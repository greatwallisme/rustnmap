//! Scan orchestrator for coordinating all scanning phases.
//!
//! This module provides the [`ScanOrchestrator`] which manages the execution
//! of all scan phases from host discovery through NSE script execution.
//!
//! The orchestrator implements the pipeline pattern, where each phase's output
//! becomes the next phase's input, allowing for efficient and modular scanning.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use rustnmap_common::ScanConfig as ScannerConfig;
use rustnmap_output::models::PortState;
use rustnmap_output::models::{HostResult, HostStatus, PortResult, ScanResult, ScanStatistics};
use rustnmap_scan::scanner::PortScanner;
use rustnmap_scan::syn_scan::TcpSynScanner;
use rustnmap_target::Target;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

use crate::error::Result;
use crate::scheduler::{ScheduledTask, TaskPriority, TaskScheduler};
use crate::session::{ScanConfig, ScanSession};
use crate::state::{HostState, PortScanState, ScanProgress};

/// Scan phase enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanPhase {
    /// Target parsing phase.
    TargetParsing,
    /// Host discovery phase.
    HostDiscovery,
    /// Port scanning phase.
    PortScanning,
    /// Service detection phase.
    ServiceDetection,
    /// OS detection phase.
    OsDetection,
    /// NSE script execution phase.
    NseExecution,
    /// Traceroute phase.
    Traceroute,
    /// Result aggregation phase.
    ResultAggregation,
}

impl ScanPhase {
    /// Returns the next phase in the pipeline.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::TargetParsing => Some(Self::HostDiscovery),
            Self::HostDiscovery => Some(Self::PortScanning),
            Self::PortScanning => Some(Self::ServiceDetection),
            Self::ServiceDetection => Some(Self::OsDetection),
            Self::OsDetection => Some(Self::NseExecution),
            Self::NseExecution => Some(Self::Traceroute),
            Self::Traceroute => Some(Self::ResultAggregation),
            Self::ResultAggregation => None,
        }
    }

    /// Returns true if this phase is enabled by default.
    #[must_use]
    pub const fn is_default(self) -> bool {
        matches!(
            self,
            Self::TargetParsing
                | Self::HostDiscovery
                | Self::PortScanning
                | Self::ResultAggregation
        )
    }

    /// Returns the display name for this phase.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TargetParsing => "Target Parsing",
            Self::HostDiscovery => "Host Discovery",
            Self::PortScanning => "Port Scanning",
            Self::ServiceDetection => "Service Detection",
            Self::OsDetection => "OS Detection",
            Self::NseExecution => "NSE Script Execution",
            Self::Traceroute => "Traceroute",
            Self::ResultAggregation => "Result Aggregation",
        }
    }
}

impl std::fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Scan pipeline configuration.
#[derive(Debug, Clone)]
pub struct ScanPipeline {
    /// Enabled phases.
    phases: Vec<ScanPhase>,
    /// Phase dependencies (phase -> required phases).
    dependencies: HashMap<ScanPhase, Vec<ScanPhase>>,
}

impl Default for ScanPipeline {
    fn default() -> Self {
        let phases = vec![
            ScanPhase::TargetParsing,
            ScanPhase::HostDiscovery,
            ScanPhase::PortScanning,
            ScanPhase::ResultAggregation,
        ];
        let mut dependencies = HashMap::new();
        dependencies.insert(ScanPhase::HostDiscovery, vec![ScanPhase::TargetParsing]);
        dependencies.insert(ScanPhase::PortScanning, vec![ScanPhase::HostDiscovery]);
        dependencies.insert(ScanPhase::ServiceDetection, vec![ScanPhase::PortScanning]);
        dependencies.insert(ScanPhase::OsDetection, vec![ScanPhase::PortScanning]);
        dependencies.insert(ScanPhase::NseExecution, vec![ScanPhase::ServiceDetection]);
        dependencies.insert(ScanPhase::Traceroute, vec![ScanPhase::PortScanning]);
        dependencies.insert(ScanPhase::ResultAggregation, vec![ScanPhase::PortScanning]);
        Self {
            phases,
            dependencies,
        }
    }
}

impl ScanPipeline {
    /// Creates a new scan pipeline from a scan configuration.
    #[must_use]
    pub fn from_config(config: &ScanConfig) -> Self {
        let mut pipeline = Self::default();

        // Add optional phases based on configuration
        if config.service_detection {
            pipeline.add_phase(ScanPhase::ServiceDetection);
        }
        if config.os_detection {
            pipeline.add_phase(ScanPhase::OsDetection);
        }
        if config.nse_scripts {
            pipeline.add_phase(ScanPhase::NseExecution);
        }
        if config.traceroute {
            pipeline.add_phase(ScanPhase::Traceroute);
        }

        pipeline
    }

    /// Adds a phase to the pipeline.
    pub fn add_phase(&mut self, phase: ScanPhase) {
        if !self.phases.contains(&phase) {
            // Insert after its dependency if possible
            if let Some(deps) = self.dependencies.get(&phase) {
                if let Some(last_dep) = deps.last() {
                    if let Some(pos) = self.phases.iter().position(|p| p == last_dep) {
                        self.phases.insert(pos + 1, phase);
                        return;
                    }
                }
            }
            self.phases.push(phase);
        }
    }

    /// Returns the enabled phases in order.
    #[must_use]
    pub fn phases(&self) -> &[ScanPhase] {
        &self.phases
    }

    /// Returns true if the given phase is enabled.
    #[must_use]
    pub fn is_enabled(&self, phase: ScanPhase) -> bool {
        self.phases.contains(&phase)
    }

    /// Returns the dependencies for a phase.
    #[must_use]
    pub fn dependencies(&self, phase: ScanPhase) -> Option<&[ScanPhase]> {
        self.dependencies.get(&phase).map(Vec::as_slice)
    }
}

/// Scan orchestrator that coordinates all scanning phases.
pub struct ScanOrchestrator {
    /// Scan session context.
    session: Arc<ScanSession>,
    /// Scan pipeline configuration.
    pipeline: ScanPipeline,
    /// Task scheduler for concurrent execution.
    scheduler: TaskScheduler,
    /// Scan state for all hosts.
    state: Arc<RwLock<ScanState>>,
    /// Current scan phase.
    current_phase: Arc<RwLock<ScanPhase>>,
}

impl fmt::Debug for ScanOrchestrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanOrchestrator")
            .field("pipeline", &self.pipeline)
            .field("scheduler", &self.scheduler)
            .finish_non_exhaustive()
    }
}

/// Scan state for tracking host and port states.
#[derive(Debug, Default)]
pub struct ScanState {
    /// Host states by IP address.
    hosts: HashMap<IpAddr, HostState>,
    /// Port states by (IP, port).
    ports: HashMap<(IpAddr, u16), PortScanState>,
    /// Overall scan progress.
    progress: ScanProgress,
}

impl ScanState {
    /// Creates a new scan state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets or creates a host state.
    pub fn host_state(&mut self, ip: IpAddr) -> &mut HostState {
        self.hosts.entry(ip).or_default()
    }

    /// Gets or creates a port state.
    pub fn port_state(&mut self, ip: IpAddr, port: u16) -> &mut PortScanState {
        self.ports.entry((ip, port)).or_default()
    }

    /// Sets the scan progress.
    pub fn set_progress(&mut self, progress: ScanProgress) {
        self.progress = progress;
    }

    /// Returns the current scan progress.
    #[must_use]
    pub const fn progress(&self) -> &ScanProgress {
        &self.progress
    }

    /// Returns the number of hosts.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Returns the number of ports.
    #[must_use]
    pub fn port_count(&self) -> usize {
        self.ports.len()
    }
}

use std::fmt;

impl ScanOrchestrator {
    /// Creates a new scan orchestrator with the given session.
    #[must_use]
    pub fn new(session: Arc<ScanSession>) -> Self {
        let pipeline = ScanPipeline::from_config(&session.config);
        let scheduler = TaskScheduler::new(session.config.max_parallel_hosts);
        let state = Arc::new(RwLock::new(ScanState::new()));
        let current_phase = Arc::new(RwLock::new(ScanPhase::TargetParsing));

        Self {
            session,
            pipeline,
            scheduler,
            state,
            current_phase,
        }
    }

    /// Creates a new orchestrator with a custom pipeline.
    #[must_use]
    pub fn with_pipeline(session: Arc<ScanSession>, pipeline: ScanPipeline) -> Self {
        let scheduler = TaskScheduler::new(session.config.max_parallel_hosts);
        let state = Arc::new(RwLock::new(ScanState::new()));
        let current_phase = Arc::new(RwLock::new(ScanPhase::TargetParsing));

        Self {
            session,
            pipeline,
            scheduler,
            state,
            current_phase,
        }
    }

    /// Runs the complete scan pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error if any phase fails to complete.
    #[instrument(skip(self), fields(targets = self.session.target_count()))]
    pub async fn run(&self) -> Result<ScanResult> {
        info!("Starting scan orchestration");

        let start_time = std::time::Instant::now();
        let mut host_results: Vec<HostResult> = Vec::new();

        // Execute each phase in order
        for phase in self.pipeline.phases().to_vec() {
            *self.current_phase.write().await = phase;
            debug!(phase = %phase, "Executing scan phase");

            match phase {
                ScanPhase::TargetParsing => {
                    // Target parsing is done before the orchestrator is created
                    debug!("Target parsing phase skipped (already completed)");
                }
                ScanPhase::HostDiscovery => {
                    if self.session.config.host_discovery {
                        self.run_host_discovery().await?;
                    }
                }
                ScanPhase::PortScanning => {
                    host_results = self.run_port_scanning().await?;
                }
                ScanPhase::ServiceDetection => {
                    if self.pipeline.is_enabled(ScanPhase::ServiceDetection) {
                        self.run_service_detection(&mut host_results)?;
                    }
                }
                ScanPhase::OsDetection => {
                    if self.pipeline.is_enabled(ScanPhase::OsDetection) {
                        self.run_os_detection(&mut host_results)?;
                    }
                }
                ScanPhase::NseExecution => {
                    if self.pipeline.is_enabled(ScanPhase::NseExecution) {
                        self.run_nse_scripts(&mut host_results)?;
                    }
                }
                ScanPhase::Traceroute => {
                    if self.pipeline.is_enabled(ScanPhase::Traceroute) {
                        self.run_traceroute(&mut host_results)?;
                    }
                }
                ScanPhase::ResultAggregation => {
                    // Results are aggregated throughout the pipeline
                    debug!("Result aggregation phase completed");
                }
            }
        }

        let elapsed = start_time.elapsed();
        info!(?elapsed, "Scan orchestration completed");

        // Build final scan result
        let scan_result = self.build_scan_result(host_results, elapsed)?;

        // Output final results
        self.session
            .output_sink
            .output_scan_result(&scan_result)
            .await?;
        self.session.output_sink.flush().await?;

        Ok(scan_result)
    }

    /// Runs the host discovery phase.
    async fn run_host_discovery(&self) -> Result<()> {
        info!("Starting host discovery phase");

        let targets: Vec<Target> = self.session.target_set.targets().to_vec();
        let mut tasks = Vec::new();

        for target in targets {
            let session = Arc::clone(&self.session);
            let state = Arc::clone(&self.state);

            let task = ScheduledTask::new(
                format!("host_discovery:{}", target.ip),
                TaskPriority::Normal,
                move || async move {
                    debug!(ip = %target.ip, "Discovering host");
                    // Host discovery implementation will be integrated with rustnmap-target discovery module
                    // Initial implementation marks hosts as up to allow scan pipeline progression
                    let mut state_guard = state.write().await;
                    let host_state = state_guard.host_state(target.ip);
                    host_state.status = HostStatus::Up;
                    host_state.discovery_method = Some("initial".to_string());
                    session.stats.mark_host_complete();
                    Ok(())
                },
            );
            tasks.push(task);
        }

        // Schedule and execute all tasks
        for task in tasks {
            self.scheduler.schedule(task).await?;
        }

        // Wait for all tasks to complete
        self.scheduler.wait_for_completion().await?;

        info!("Host discovery phase completed");
        Ok(())
    }

    /// Runs the port scanning phase.
    async fn run_port_scanning(&self) -> Result<Vec<HostResult>> {
        info!("Starting port scanning phase");

        let targets: Vec<Target> = self.session.target_set.targets().to_vec();
        let mut host_results = Vec::new();

        for target in targets {
            let ports = self.get_ports_for_scan();
            let mut port_results = Vec::new();

            for port in ports {
                let port_result = self.scan_port(&target, port).await?;
                if port_result.state != PortState::Closed {
                    port_results.push(port_result);
                    self.session.stats.record_open_port();
                }
                self.session.stats.record_packet_sent();
            }

            let host_result = HostResult {
                ip: target.ip,
                mac: None,
                hostname: target.hostname.clone(),
                status: HostStatus::Up,
                status_reason: "syn-ack".to_string(),
                latency: std::time::Duration::from_millis(1),
                ports: port_results,
                os_matches: Vec::new(),
                scripts: Vec::new(),
                traceroute: None,
                times: rustnmap_output::models::HostTimes {
                    srtt: None,
                    rttvar: None,
                    timeout: None,
                },
            };

            host_results.push(host_result);
            self.session
                .output_sink
                .output_host(host_results.last().unwrap())
                .await?;
        }

        info!(hosts = host_results.len(), "Port scanning phase completed");
        Ok(host_results)
    }

    /// Scans a single port on a target.
    async fn scan_port(&self, target: &Target, port: u16) -> Result<PortResult> {
        use rustnmap_common::Ipv4Addr;

        // Create scanner configuration from session config
        let scanner_config = ScannerConfig {
            min_rtt: std::time::Duration::from_millis(50),
            max_rtt: std::time::Duration::from_secs(10),
            initial_rtt: self.session.config.scan_delay,
            max_retries: 2,
            host_timeout: self
                .session
                .config
                .host_timeout
                .as_millis()
                .try_into()
                .unwrap_or(30000),
            scan_delay: self.session.config.scan_delay,
        };

        // Get local address for the scanner
        let local_addr = std::net::Ipv4Addr::UNSPECIFIED;

        // Try to create TCP SYN scanner (requires root)
        match TcpSynScanner::new(local_addr, scanner_config) {
            Ok(scanner) => {
                // Get target IP address
                let target_ip = match target.ip {
                    std::net::IpAddr::V4(addr) => addr,
                    std::net::IpAddr::V6(_) => {
                        // IPv6 not supported by current scanner
                        return Ok(PortResult {
                            number: port,
                            protocol: rustnmap_output::models::Protocol::Tcp,
                            state: PortState::Filtered,
                            state_reason: "ipv6-not-supported".to_string(),
                            state_ttl: None,
                            service: None,
                            scripts: Vec::new(),
                        });
                    }
                };

                // Convert to rustnmap_common types
                let common_target = rustnmap_target::Target {
                    ip: rustnmap_common::IpAddr::V4(Ipv4Addr::new(
                        target_ip.octets()[0],
                        target_ip.octets()[1],
                        target_ip.octets()[2],
                        target_ip.octets()[3],
                    )),
                    hostname: target.hostname.clone(),
                    ports: Some(vec![port]),
                    ipv6_scope: None,
                };

                // Perform the scan
                match scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp) {
                    Ok(state) => {
                        let (port_state, reason) = match state {
                            rustnmap_common::PortState::Open => {
                                (PortState::Open, "syn-ack".to_string())
                            }
                            rustnmap_common::PortState::Closed => {
                                (PortState::Closed, "rst".to_string())
                            }
                            rustnmap_common::PortState::Filtered => {
                                (PortState::Filtered, "no-response".to_string())
                            }
                            _ => (PortState::Filtered, "unknown".to_string()),
                        };

                        Ok(PortResult {
                            number: port,
                            protocol: rustnmap_output::models::Protocol::Tcp,
                            state: port_state,
                            state_reason: reason,
                            state_ttl: None,
                            service: None,
                            scripts: Vec::new(),
                        })
                    }
                    Err(_) => Ok(PortResult {
                        number: port,
                        protocol: rustnmap_output::models::Protocol::Tcp,
                        state: PortState::Filtered,
                        state_reason: "scan-error".to_string(),
                        state_ttl: None,
                        service: None,
                        scripts: Vec::new(),
                    }),
                }
            }
            Err(_) => {
                // Raw socket creation failed (not root), use TCP Connect scan fallback
                self.scan_port_connect(target, port).await
            }
        }
    }

    /// Scans a single port using TCP Connect (fallback when not root).
    async fn scan_port_connect(&self, target: &Target, port: u16) -> Result<PortResult> {
        use tokio::net::TcpSocket;
        use tokio::time::timeout;

        let addr = std::net::SocketAddr::new(target.ip, port);
        let timeout_duration = self.session.config.scan_delay;

        // Try to connect
        let result: std::io::Result<()> = async {
            let socket = TcpSocket::new_v4()?;
            timeout(timeout_duration, socket.connect(addr))
                .await
                .map_err(|_e| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timeout")
                })?
                .map(|_| ())
        }
        .await;

        let (state, reason) = match result {
            Ok(()) => (PortState::Open, "syn-ack".to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                (PortState::Closed, "conn-refused".to_string())
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                (PortState::Filtered, "timeout".to_string())
            }
            Err(_) => (PortState::Filtered, "error".to_string()),
        };

        Ok(PortResult {
            number: port,
            protocol: rustnmap_output::models::Protocol::Tcp,
            state,
            state_reason: reason,
            state_ttl: None,
            service: None,
            scripts: Vec::new(),
        })
    }

    /// Gets the list of ports to scan based on configuration.
    fn get_ports_for_scan(&self) -> Vec<u16> {
        match &self.session.config.port_spec {
            super::session::PortSpec::All => (1..=65535).collect(),
            super::session::PortSpec::Top(n) => (1..=u16::try_from(*n).unwrap_or(65535)).collect(),
            super::session::PortSpec::List(ports) => ports.clone(),
            super::session::PortSpec::Range { start, end } => (*start..=*end).collect(),
        }
    }

    /// Runs the service detection phase.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "Service detection implementation pending integration with rustnmap-fingerprint"
    )]
    fn run_service_detection(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting service detection phase");

        for host_result in host_results.iter_mut() {
            for port_result in &mut host_result.ports {
                if port_result.state == PortState::Open {
                    // Service detection will be integrated with rustnmap-fingerprint service module
                    // Current implementation logs open ports for future enhancement
                    debug!(
                        ip = %host_result.ip,
                        port = port_result.number,
                        "Service detection scheduled for open port"
                    );
                }
            }
        }

        info!("Service detection phase completed");
        Ok(())
    }

    /// Runs the OS detection phase.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "OS detection implementation pending integration with rustnmap-fingerprint"
    )]
    fn run_os_detection(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting OS detection phase");

        for host_result in host_results.iter_mut() {
            // OS detection implementation pending
            debug!(ip = %host_result.ip, "OS detection pending");
        }

        info!("OS detection phase completed");
        Ok(())
    }

    /// Runs NSE scripts on discovered services.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "NSE script execution pending integration with rustnmap-nse"
    )]
    fn run_nse_scripts(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting NSE script execution phase");

        for host_result in host_results.iter_mut() {
            for port_result in &mut host_result.ports {
                if port_result.state == PortState::Open {
                    // NSE script execution implementation pending
                    debug!(
                        ip = %host_result.ip,
                        port = port_result.number,
                        "NSE script execution pending"
                    );
                }
            }
        }

        info!("NSE script execution phase completed");
        Ok(())
    }

    /// Runs traceroute to discovered hosts.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        reason = "Traceroute implementation pending integration with rustnmap-traceroute"
    )]
    fn run_traceroute(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting traceroute phase");

        for host_result in host_results.iter_mut() {
            // Traceroute implementation pending
            debug!(ip = %host_result.ip, "Traceroute pending");
        }

        info!("Traceroute phase completed");
        Ok(())
    }

    /// Builds the final scan result.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Result return for API consistency"
    )]
    fn build_scan_result(
        &self,
        host_results: Vec<HostResult>,
        elapsed: std::time::Duration,
    ) -> Result<ScanResult> {
        let stats = ScanStatistics {
            total_hosts: host_results.len(),
            hosts_up: host_results
                .iter()
                .filter(|h| matches!(h.status, HostStatus::Up))
                .count(),
            hosts_down: host_results
                .iter()
                .filter(|h| matches!(h.status, HostStatus::Down))
                .count(),
            total_ports: host_results.iter().map(|h| h.ports.len() as u64).sum(),
            open_ports: host_results
                .iter()
                .flat_map(|h| &h.ports)
                .filter(|p| matches!(p.state, PortState::Open))
                .count() as u64,
            closed_ports: host_results
                .iter()
                .flat_map(|h| &h.ports)
                .filter(|p| matches!(p.state, PortState::Closed))
                .count() as u64,
            filtered_ports: host_results
                .iter()
                .flat_map(|h| &h.ports)
                .filter(|p| matches!(p.state, PortState::Filtered))
                .count() as u64,
            bytes_sent: self.session.stats.packets_sent() * 64, // Estimate
            bytes_received: self.session.stats.packets_received() * 64, // Estimate
            packets_sent: self.session.stats.packets_sent(),
            packets_received: self.session.stats.packets_received(),
        };

        let metadata = rustnmap_output::models::ScanMetadata {
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            command_line: String::new(), // Command line not available in core
            start_time: chrono::Utc::now()
                - chrono::TimeDelta::from_std(elapsed).unwrap_or_default(),
            end_time: chrono::Utc::now(),
            elapsed,
            scan_type: rustnmap_output::models::ScanType::TcpSyn,
            protocol: rustnmap_output::models::Protocol::Tcp,
        };

        Ok(ScanResult {
            metadata,
            hosts: host_results,
            statistics: stats,
            errors: Vec::new(),
        })
    }

    /// Returns the current scan phase.
    pub async fn current_phase(&self) -> ScanPhase {
        *self.current_phase.read().await
    }

    /// Returns the scan progress.
    pub async fn progress(&self) -> ScanProgress {
        let state = self.state.read().await;
        state.progress().clone()
    }

    /// Returns a reference to the scan session.
    #[must_use]
    pub fn session(&self) -> &ScanSession {
        &self.session
    }

    /// Returns a reference to the scan pipeline.
    #[must_use]
    pub fn pipeline(&self) -> &ScanPipeline {
        &self.pipeline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_common::Ipv4Addr;
    use rustnmap_target::TargetGroup;

    fn create_test_session() -> Arc<ScanSession> {
        let config = ScanConfig::default();
        let targets = TargetGroup::new(vec![
            Target::from(Ipv4Addr::new(192, 168, 1, 1)),
            Target::from(Ipv4Addr::new(192, 168, 1, 2)),
        ]);
        // Create a test session without async
        let target_set = Arc::new(crate::session::TargetSet::from_group(targets));
        let packet_engine: Arc<dyn crate::session::PacketEngine> =
            Arc::new(crate::session::DefaultPacketEngine::new().unwrap());
        let output_sink: Arc<dyn crate::session::OutputSink> =
            Arc::new(crate::session::DefaultOutputSink::new());
        let fingerprint_db = Arc::new(crate::session::FingerprintDatabase::new());
        let nse_registry = Arc::new(crate::session::NseRegistry::new());
        let _stats = Arc::new(crate::session::ScanStats::new());

        Arc::new(ScanSession::with_dependencies(
            config,
            target_set,
            packet_engine,
            output_sink,
            fingerprint_db,
            nse_registry,
        ))
    }

    #[test]
    fn test_scan_phase_next() {
        assert_eq!(
            ScanPhase::TargetParsing.next(),
            Some(ScanPhase::HostDiscovery)
        );
        assert_eq!(
            ScanPhase::HostDiscovery.next(),
            Some(ScanPhase::PortScanning)
        );
        assert_eq!(ScanPhase::ResultAggregation.next(), None);
    }

    #[test]
    fn test_scan_phase_display() {
        assert_eq!(ScanPhase::PortScanning.to_string(), "Port Scanning");
        assert_eq!(ScanPhase::OsDetection.to_string(), "OS Detection");
    }

    #[test]
    fn test_scan_pipeline_default() {
        let pipeline = ScanPipeline::default();
        assert!(pipeline.is_enabled(ScanPhase::TargetParsing));
        assert!(pipeline.is_enabled(ScanPhase::HostDiscovery));
        assert!(pipeline.is_enabled(ScanPhase::PortScanning));
        assert!(!pipeline.is_enabled(ScanPhase::ServiceDetection));
    }

    #[test]
    fn test_scan_pipeline_from_config() {
        let mut config = ScanConfig::default();
        config.service_detection = true;
        config.os_detection = true;

        let pipeline = ScanPipeline::from_config(&config);
        assert!(pipeline.is_enabled(ScanPhase::ServiceDetection));
        assert!(pipeline.is_enabled(ScanPhase::OsDetection));
    }

    #[test]
    fn test_scan_state() {
        let mut state = ScanState::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let host_state = state.host_state(ip);
        assert_eq!(host_state.status, HostStatus::Unknown);

        let port_state = state.port_state(ip, 80);
        assert_eq!(*port_state, PortScanState::default());

        assert_eq!(state.host_count(), 1);
        assert_eq!(state.port_count(), 1);
    }

    #[test]
    fn test_orchestrator_creation() {
        let session = create_test_session();
        let orchestrator = ScanOrchestrator::new(session);
        assert_eq!(orchestrator.session().target_count(), 2);
    }

    #[test]
    fn test_get_ports_for_scan() {
        let session = create_test_session();
        let orchestrator = ScanOrchestrator::new(session);
        let ports = orchestrator.get_ports_for_scan();
        assert!(!ports.is_empty());
    }
}
