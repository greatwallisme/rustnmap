//! Scan orchestrator for coordinating all scanning phases.
//!
//! This module provides the [`ScanOrchestrator`] which manages the execution
//! of all scan phases from host discovery through NSE script execution.
//!
//! The orchestrator implements the pipeline pattern, where each phase's output
//! becomes the next phase's input, allowing for efficient and modular scanning.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use rustnmap_common::MacAddr;
use rustnmap_common::ScanConfig as ScannerConfig;
use rustnmap_evasion::DecoyScheduler;
use rustnmap_net::raw_socket::{parse_arp_reply, ArpPacketBuilder, RawSocket};
use rustnmap_output::models::PortState;
use rustnmap_output::models::{HostResult, HostStatus, PortResult, ScanResult, ScanStatistics};
use rustnmap_scan::connect_scan::TcpConnectScanner;
use rustnmap_scan::ip_protocol_scan::IpProtocolScanner;
use rustnmap_scan::scanner::PortScanner;
use rustnmap_scan::stealth_scans::{
    TcpAckScanner, TcpFinScanner, TcpMaimonScanner, TcpNullScanner, TcpWindowScanner,
    TcpXmasScanner,
};
use rustnmap_scan::syn_scan::TcpSynScanner;
use rustnmap_scan::udp_scan::UdpScanner;
use rustnmap_scan::ultrascan::ParallelScanEngine;
use rustnmap_target::discovery::{HostDiscovery, HostState as DiscoveryHostState};
use rustnmap_target::Target;

use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, instrument, warn};

use crate::error::Result;
use crate::scheduler::{ScheduledTask, TaskPriority, TaskScheduler};
use crate::session::{ScanConfig, ScanSession, ScanType};
use crate::state::{HostState, PortScanState, ScanProgress};

/// Gets the local IPv4 address by creating a UDP socket to an external address.
///
/// This returns the source IP that would be used for packets to the internet.
/// The DNS server address is used to determine the route (no data is sent).
fn get_local_address(dns_server: &str) -> std::net::Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0");
    if let Ok(sock) = socket {
        if sock.connect(dns_server).is_ok() {
            if let Ok(local_addr) = sock.local_addr() {
                debug!(local_addr = %local_addr, "Socket local_addr after connect");
                if let IpAddr::V4(ipv4) = local_addr.ip() {
                    debug!(ipv4 = %ipv4, "Detected local IPv4 address");
                    return ipv4;
                }
            }
        }
    }
    // Fallback to localhost if detection fails
    debug!("Failed to detect local address, using LOCALHOST");
    std::net::Ipv4Addr::LOCALHOST
}

/// Creates a decoy scheduler from the session's evasion configuration.
///
/// # Arguments
///
/// * `session` - The scan session containing the evasion configuration
/// * `local_addr` - The local (real) IPv4 address
///
/// # Returns
///
/// `Some(DecoyScheduler)` if decoys are configured, `None` otherwise.
fn create_decoy_scheduler(
    session: &ScanSession,
    local_addr: std::net::Ipv4Addr,
) -> Option<DecoyScheduler> {
    session.config.evasion_config.as_ref().and_then(|evasion| {
        evasion.decoys.as_ref().map(|decoy_config| {
            DecoyScheduler::new(decoy_config.clone(), IpAddr::V4(local_addr))
                .expect("Failed to create DecoyScheduler")
        })
    })
}

/// Attempts to get the MAC address for an IPv4 target via ARP request.
///
/// # Arguments
///
/// * `target_ip` - The target IPv4 address
/// * `local_addr` - The local IPv4 address to use for the ARP request
/// * `timeout` - Timeout for the ARP request
///
/// # Returns
///
/// `Some(MacAddr)` if ARP reply is received, `None` otherwise.
fn get_mac_address_via_arp(
    target_ip: std::net::Ipv4Addr,
    local_addr: std::net::Ipv4Addr,
    timeout: std::time::Duration,
) -> Option<MacAddr> {
    // Use broadcast MAC for ARP requests
    let src_mac = MacAddr::broadcast();

    let socket = RawSocket::with_protocol(1).ok()?;

    let packet = ArpPacketBuilder::new(src_mac, local_addr, target_ip).build();

    let dst_sockaddr = SocketAddr::new(IpAddr::V4(target_ip), 0);

    socket.send_packet(&packet, &dst_sockaddr).ok()?;

    let mut recv_buf = vec![0u8; 65535];

    match socket.recv_packet(recv_buf.as_mut_slice(), Some(timeout)) {
        Ok(len) if len > 0 => {
            if let Some((mac_addr, sender_ip)) = parse_arp_reply(&recv_buf[..len]) {
                let octets = target_ip.octets();
                if sender_ip
                    == rustnmap_common::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
                {
                    return Some(mac_addr);
                }
            }
            None
        }
        _ => None,
    }
}

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
    /// Tracks when the last probe was sent for enforcing `scan_delay`.
    ///
    /// This implements nmap's `enforce_scan_delay()` from `timing.cc:172-206`.
    last_probe_send_time: Arc<Mutex<Option<Instant>>>,
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
            last_probe_send_time: Arc::new(Mutex::new(Some(Instant::now()))),
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
            last_probe_send_time: Arc::new(Mutex::new(Some(Instant::now()))),
        }
    }

    /// Enforces the `scan_delay` between probes.
    ///
    /// This implements nmap's `enforce_scan_delay()` from `timing.cc:172-206`.
    /// The scan delay is a minimum time that must elapse between sending probes,
    /// independent of rate limiting.
    ///
    /// If the time elapsed since the last probe is less than `scan_delay`,
    /// this method sleeps for the remaining time.
    ///
    /// # Behavior
    ///
    /// - First call: Returns immediately (no delay), like nmap's `init == -1` check
    /// - Subsequent calls: Enforces `scan_delay` between probes
    async fn enforce_scan_delay(&self) {
        let scan_delay = self.session.config.timing_template.scan_config().scan_delay;
        if scan_delay == Duration::ZERO {
            return;
        }

        // Calculate time since last probe
        let elapsed = {
            let last_opt = self.last_probe_send_time.lock().await;
            match *last_opt {
                None => {
                    // Should not happen since we initialize with Some(Instant::now())
                    return;
                }
                Some(last) => last.elapsed(),
            }
        };

        if elapsed < scan_delay {
            // Sleep for remaining time
            let remaining = scan_delay - elapsed;
            tokio::time::sleep(remaining).await;
        }

        // Update last probe send time to now
        *self.last_probe_send_time.lock().await = Some(Instant::now());
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
                    if self.session.config.two_phase_scan {
                        // Two-phase scanning: fast discovery + deep scan
                        host_results = self.run_two_phase_port_scanning().await?;
                    } else {
                        host_results = self.run_port_scanning().await?;
                    }
                }
                ScanPhase::ServiceDetection => {
                    if self.pipeline.is_enabled(ScanPhase::ServiceDetection) {
                        self.run_service_detection(&mut host_results).await?;
                    }
                }
                ScanPhase::OsDetection => {
                    if self.pipeline.is_enabled(ScanPhase::OsDetection) {
                        self.run_os_detection(&mut host_results).await?;
                    }
                }
                ScanPhase::NseExecution => {
                    if self.pipeline.is_enabled(ScanPhase::NseExecution) {
                        self.run_nse_scripts(&mut host_results)?;
                    }
                }
                ScanPhase::Traceroute => {
                    if self.pipeline.is_enabled(ScanPhase::Traceroute) {
                        self.run_traceroute(&mut host_results).await?;
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

        Ok(scan_result)
    }

    /// Runs the host discovery phase.
    async fn run_host_discovery(&self) -> Result<()> {
        info!("Starting host discovery phase");

        // Enforce scan_delay before first host discovery probe
        // This matches nmap's behavior where scan_delay applies to all probes
        self.enforce_scan_delay().await;

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

                    // Create host discovery engine - convert session config to common config
                    let discovery_config = rustnmap_common::ScanConfig {
                        min_rtt: std::time::Duration::from_millis(50),
                        max_rtt: std::time::Duration::from_secs(10),
                        initial_rtt: session
                            .config
                            .scan_delay
                            .max(std::time::Duration::from_millis(100)),
                        max_retries: 2,
                        host_timeout: session
                            .config
                            .host_timeout
                            .as_millis()
                            .try_into()
                            .unwrap_or(30000),
                        scan_delay: session.config.scan_delay,
                        dns_server: session.config.dns_server.clone(),
                        min_rate: None,
                        max_rate: None,
                        timing_level: 3, // Use T3 Normal for host discovery
                    };
                    let discovery = HostDiscovery::new(discovery_config);

                    // Perform host discovery using appropriate method based on IP version
                    let discovery_result = discovery.discover(&target);

                    let mut state_guard = state.write().await;
                    let host_state = state_guard.host_state(target.ip);

                    match discovery_result {
                        Ok(DiscoveryHostState::Up) => {
                            debug!(ip = %target.ip, "Host is up");
                            host_state.status = HostStatus::Up;
                            host_state.discovery_method = Some("icmp/tcp-ping".to_string());
                        }
                        Ok(DiscoveryHostState::Down) => {
                            debug!(ip = %target.ip, "Host is down");
                            host_state.status = HostStatus::Down;
                            host_state.discovery_method = Some("icmp/tcp-ping".to_string());
                        }
                        Ok(DiscoveryHostState::Unknown) | Err(_) => {
                            // Fall back to marking as up to allow scan progression
                            // In a production environment, you may want to retry or skip
                            debug!(ip = %target.ip, "Host discovery inconclusive, assuming up");
                            host_state.status = HostStatus::Up;
                            host_state.discovery_method = Some("fallback".to_string());
                        }
                    }

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

        // Initialize last_probe_send_time so the first port probe respects scan_delay
        // This matches nmap's behavior where scan_delay is enforced after host discovery
        *self.last_probe_send_time.lock().await = Some(Instant::now());

        info!("Host discovery phase completed");
        Ok(())
    }

    /// Runs the port scanning phase.
    #[expect(
        clippy::too_many_lines,
        reason = "Port scanning requires handling all scan types and parallel vs sequential logic in one function for performance"
    )]
    async fn run_port_scanning(&self) -> Result<Vec<HostResult>> {
        info!("Starting port scanning phase");

        let targets: Vec<Target> = self.session.target_set.targets().to_vec();
        let mut host_results = Vec::new();

        // Get the primary scan type from config
        let primary_scan_type = self
            .session
            .config
            .scan_types
            .first()
            .copied()
            .unwrap_or(ScanType::TcpSyn);

        // Check if we should use parallel scanning (TCP SYN or UDP scan)
        let use_parallel = matches!(primary_scan_type, ScanType::TcpSyn | ScanType::Udp);

        if use_parallel {
            // Use parallel scanning for better performance
            info!(
                "Using parallel scanning engine for {:?} scan",
                primary_scan_type
            );

            // Check for IPv6 targets or localhost targets - these require fallback
            let has_ipv6 = targets.iter().any(|t| matches!(t.ip, IpAddr::V6(_)));
            let has_localhost = targets
                .iter()
                .any(|t| matches!(t.ip, IpAddr::V4(addr) if addr.is_loopback()));

            if has_ipv6 {
                warn!("IPv6 not supported by parallel engine, falling back to sequential");
                let ports = self.get_ports_for_scan();
                return self.run_port_scanning_sequential(&targets, &ports).await;
            }

            if has_localhost {
                debug!("Localhost detected, using TCP Connect scan instead of SYN scan");
                let ports = self.get_ports_for_scan();
                return self.run_port_scanning_sequential(&targets, &ports).await;
            }

            // Create parallel scan engine (shared across all targets)
            let local_addr = get_local_address(&self.session.config.dns_server);

            // Get timing parameters from the timing template
            let timing_config = self.session.config.timing_template.scan_config();

            let scanner_config = ScannerConfig {
                min_rtt: timing_config.min_rtt,
                max_rtt: timing_config.max_rtt,
                initial_rtt: timing_config.initial_rtt,
                max_retries: timing_config.max_retries,
                host_timeout: self
                    .session
                    .config
                    .host_timeout
                    .as_millis()
                    .try_into()
                    .unwrap_or(30000),
                // Use scan_delay from timing template (T0-T5 have specific delays)
                // For T1 Sneaky, this is 15 seconds; for T0 Paranoid, 5 minutes
                // session.config.scan_delay is only set when user specifies --scan-delay
                scan_delay: timing_config.scan_delay,
                dns_server: self.session.config.dns_server.clone(),
                min_rate: self.session.config.min_rate,
                max_rate: self.session.config.max_rate,
                timing_level: timing_config.timing_level,
            };

            let engine = if let Ok(engine) = ParallelScanEngine::new(local_addr, scanner_config) {
                Arc::new(engine)
            } else {
                // Raw socket creation failed (not root), fall back to sequential
                warn!("Raw socket creation failed, falling back to TCP Connect scan");
                let ports = self.get_ports_for_scan();
                return self.run_port_scanning_sequential(&targets, &ports).await;
            };

            let ports = self.get_ports_for_scan();
            let session = Arc::clone(&self.session);

            // Get MAC addresses for IPv4 targets (only for local network targets)
            let mac_timeout = std::time::Duration::from_millis(500);

            // Spawn async tasks for each target to scan in parallel
            let scan_futures: Vec<_> = targets
                .iter()
                .map(|target| {
                    let engine = Arc::clone(&engine);
                    let ports = ports.clone();
                    let session = Arc::clone(&session);
                    let target = target.clone();
                    let target_ip_for_mac = match target.ip {
                        IpAddr::V4(addr) => Some(addr),
                        IpAddr::V6(_) => None,
                    };

                    async move {
                        let target_ip = match target.ip {
                            IpAddr::V4(addr) => addr,
                            IpAddr::V6(_) => {
                                // Should have been filtered earlier, but handle anyway
                                warn!("IPv6 target in parallel scan");
                                return None;
                            }
                        };

                        // Run parallel scan for this target (TCP SYN or UDP)
                        let scan_results = if primary_scan_type == ScanType::Udp {
                            match engine.scan_udp_ports(target_ip, &ports).await {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!(ip = %target.ip, error = %e, "UDP parallel scan failed for target");
                                    return None;
                                }
                            }
                        } else {
                            match engine.scan_ports(target_ip, &ports).await {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!(ip = %target.ip, error = %e, "Parallel scan failed for target");
                                    return None;
                                }
                            }
                        };

                        // Determine protocol for results
                        let (protocol, service_protocol) = if primary_scan_type == ScanType::Udp {
                            (
                                rustnmap_output::models::Protocol::Udp,
                                rustnmap_common::ServiceProtocol::Udp,
                            )
                        } else {
                            (
                                rustnmap_output::models::Protocol::Tcp,
                                rustnmap_common::ServiceProtocol::Tcp,
                            )
                        };

                        // Convert scan results to port results
                        let mut port_results = Vec::new();
                        for (port, common_state) in scan_results {
                            // Convert rustnmap_common::PortState to rustnmap_output::models::PortState
                            let output_state = match common_state {
                                rustnmap_common::PortState::Open => PortState::Open,
                                rustnmap_common::PortState::Closed => PortState::Closed,
                                rustnmap_common::PortState::Filtered => PortState::Filtered,
                                rustnmap_common::PortState::Unfiltered => PortState::Unfiltered,
                                rustnmap_common::PortState::OpenOrFiltered => PortState::OpenOrFiltered,
                                rustnmap_common::PortState::ClosedOrFiltered => PortState::ClosedOrFiltered,
                                rustnmap_common::PortState::OpenOrClosed => PortState::OpenOrClosed,
                            };

                            let is_open = output_state == PortState::Open;

                            let port_result = PortResult {
                                number: port,
                                protocol,
                                state: output_state,
                                state_reason: "scan".to_string(),
                                state_ttl: None,
                                service: service_info_from_db(port, service_protocol),
                                scripts: Vec::new(),
                            };

                            port_results.push(port_result);
                            if is_open {
                                session.stats.record_open_port();
                            }
                            session.stats.record_packet_sent();
                        }

                        // Get MAC address via ARP (only for IPv4 targets)
                        let mac = if let Some(target_ipv4) = target_ip_for_mac {
                            get_mac_address_via_arp(target_ipv4, local_addr, mac_timeout).map(
                                |mac_addr| {
                                    let mac_str = mac_addr.to_string();
                                    // Look up vendor from MAC prefix database
                                    let vendor = self
                                        .session
                                        .fingerprint_db
                                        .mac_db()
                                        .and_then(|db| db.lookup(&mac_str))
                                        .map(std::string::ToString::to_string);
                                    rustnmap_output::models::MacAddress {
                                        address: mac_str,
                                        vendor,
                                    }
                                },
                            )
                        } else {
                            None
                        };

                        // Determine status reason based on scan type
                        let status_reason = if primary_scan_type == ScanType::Udp {
                            "udp-response".to_string()
                        } else {
                            "syn-ack".to_string()
                        };

                        Some(HostResult {
                            ip: target.ip,
                            mac,
                            hostname: target.hostname.clone(),
                            status: HostStatus::Up,
                            status_reason,
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
                        })
                    }
                })
                .collect();

            // Execute all target scans concurrently and collect results
            let results = join_all(scan_futures).await;

            // Filter out None results (failed scans) and collect successes
            for host_result in results.into_iter().flatten() {
                host_results.push(host_result);
            }
        } else {
            // Use sequential scanning for other scan types
            info!(
                "Using sequential scanning for scan type: {:?}",
                primary_scan_type
            );
            let ports = self.get_ports_for_scan();
            return self.run_port_scanning_sequential(&targets, &ports).await;
        }

        info!(hosts = host_results.len(), "Port scanning phase completed");
        Ok(host_results)
    }

    /// Runs port scanning sequentially (fallback for non-SYN scans or when raw socket fails).
    ///
    /// For stealth scans (FIN/NULL/XMAS/Maimon), uses batch mode for improved performance.
    async fn run_port_scanning_sequential(
        &self,
        targets: &[Target],
        ports: &[u16],
    ) -> Result<Vec<HostResult>> {
        // Get the primary scan type
        let primary_scan_type = self
            .session
            .config
            .scan_types
            .first()
            .copied()
            .unwrap_or(ScanType::TcpSyn);

        // Special case for TCP Connect scan: use batch scanning for better performance
        if primary_scan_type == ScanType::TcpConnect {
            info!("Using batch scanning mode for TCP connect scan");
            return self.run_port_scanning_connect_batch(targets, ports).await;
        }

        // Check if this is a stealth scan that supports batch mode
        let use_batch = matches!(
            primary_scan_type,
            ScanType::TcpFin
                | ScanType::TcpNull
                | ScanType::TcpXmas
                | ScanType::TcpMaimon
                | ScanType::TcpAck
                | ScanType::TcpWindow
        );

        if use_batch {
            info!(
                scan_type = ?primary_scan_type,
                "Using batch scanning mode for stealth scan"
            );
            return self.run_port_scanning_batch(targets, ports, primary_scan_type);
        }

        info!("Starting sequential port scanning");

        // Get local address for MAC lookup
        let local_addr = get_local_address(&self.session.config.dns_server);
        let mut host_results = Vec::new();

        for target in targets {
            let mut port_results = Vec::new();

            for port in ports {
                // Enforce scan_delay before each probe (nmap timing.cc:172-206)
                self.enforce_scan_delay().await;
                let port_result = self.scan_port(target, *port).await?;
                let is_open = port_result.state == PortState::Open;
                port_results.push(port_result);
                if is_open {
                    self.session.stats.record_open_port();
                }
                self.session.stats.record_packet_sent();
            }

            let host_result = HostResult {
                ip: target.ip,
                mac: match target.ip {
                    IpAddr::V4(target_ipv4) => {
                        get_mac_address_via_arp(
                            target_ipv4,
                            local_addr,
                            std::time::Duration::from_millis(500),
                        )
                        .map(|mac_addr| {
                            let mac_str = mac_addr.to_string();
                            // Look up vendor from MAC prefix database
                            let vendor = self
                                .session
                                .fingerprint_db
                                .mac_db()
                                .and_then(|db| db.lookup(&mac_str))
                                .map(std::string::ToString::to_string);
                            rustnmap_output::models::MacAddress {
                                address: mac_str,
                                vendor,
                            }
                        })
                    }
                    IpAddr::V6(_) => None,
                },
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
        }

        Ok(host_results)
    }

    /// Runs port scanning in batch mode for stealth scans.
    ///
    /// This method sends all probes first, then collects responses,
    /// providing significant performance improvement over serial scanning.
    ///
    /// Note: This method is synchronous because the underlying batch scan
    /// operations in stealth scanners are synchronous (raw socket I/O).
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling all stealth scan types and result conversion in one function for clarity"
    )]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Returns Result for API consistency with other scan methods; errors are logged and skipped to process all targets"
    )]
    fn run_port_scanning_batch(
        &self,
        targets: &[Target],
        ports: &[u16],
        scan_type: ScanType,
    ) -> Result<Vec<HostResult>> {
        info!("Starting batch port scanning for stealth scan");

        let local_addr = get_local_address(&self.session.config.dns_server);
        let timing_config = self.session.config.timing_template.scan_config();

        let scanner_config = ScannerConfig {
            min_rtt: timing_config.min_rtt,
            max_rtt: timing_config.max_rtt,
            initial_rtt: timing_config.initial_rtt,
            max_retries: timing_config.max_retries,
            host_timeout: self
                .session
                .config
                .host_timeout
                .as_millis()
                .try_into()
                .unwrap_or(30000),
            // Use scan_delay from timing template (T0-T5 have specific delays)
            scan_delay: timing_config.scan_delay,
            dns_server: self.session.config.dns_server.clone(),
            min_rate: self.session.config.min_rate,
            max_rate: self.session.config.max_rate,
            timing_level: timing_config.timing_level,
        };

        // Create decoy scheduler if evasion config has decoys
        let decoy_scheduler: Option<DecoyScheduler> =
            create_decoy_scheduler(&self.session, local_addr);

        if decoy_scheduler.is_some() {
            info!("Decoy scanning enabled");
        }

        let mut host_results = Vec::new();

        for target in targets {
            // Get IPv4 address
            let target_ip = match target.ip {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => {
                    warn!(ip = %target.ip, "IPv6 not supported for stealth scans, skipping");
                    continue;
                }
            };

            // Run batch scan based on scan type
            let scan_results = match scan_type {
                ScanType::TcpFin => {
                    match TcpFinScanner::with_decoy(
                        local_addr,
                        scanner_config.clone(),
                        decoy_scheduler.clone(),
                    ) {
                        Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                        Err(e) => {
                            warn!(error = %e, "Failed to create FIN scanner");
                            continue;
                        }
                    }
                }
                ScanType::TcpNull => {
                    match TcpNullScanner::with_decoy(
                        local_addr,
                        scanner_config.clone(),
                        decoy_scheduler.clone(),
                    ) {
                        Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                        Err(e) => {
                            warn!(error = %e, "Failed to create NULL scanner");
                            continue;
                        }
                    }
                }
                ScanType::TcpXmas => {
                    match TcpXmasScanner::with_decoy(
                        local_addr,
                        scanner_config.clone(),
                        decoy_scheduler.clone(),
                    ) {
                        Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                        Err(e) => {
                            warn!(error = %e, "Failed to create XMAS scanner");
                            continue;
                        }
                    }
                }
                ScanType::TcpMaimon => {
                    match TcpMaimonScanner::with_decoy(
                        local_addr,
                        scanner_config.clone(),
                        decoy_scheduler.clone(),
                    ) {
                        Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                        Err(e) => {
                            warn!(error = %e, "Failed to create Maimon scanner");
                            continue;
                        }
                    }
                }
                ScanType::TcpAck => match TcpAckScanner::new(local_addr, scanner_config.clone()) {
                    Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                    Err(e) => {
                        warn!(error = %e, "Failed to create ACK scanner");
                        continue;
                    }
                },
                ScanType::TcpWindow => {
                    match TcpWindowScanner::new(local_addr, scanner_config.clone()) {
                        Ok(scanner) => scanner.scan_ports_batch(target_ip, ports),
                        Err(e) => {
                            warn!(error = %e, "Failed to create Window scanner");
                            continue;
                        }
                    }
                }
                ScanType::Udp => {
                    // Use ParallelScanEngine for UDP parallel scanning
                    match ParallelScanEngine::new(local_addr, scanner_config.clone()) {
                        Ok(engine) => {
                            // scan_udp_ports is async, so we need to block_on
                            // Since this method is synchronous, we use tokio runtime
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(async {
                                    engine.scan_udp_ports(target_ip, ports).await
                                })
                            })
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to create UDP parallel scanner");
                            continue;
                        }
                    }
                }
                _ => {
                    // Should not reach here, but handle gracefully
                    warn!(scan_type = ?scan_type, "Unsupported scan type for batch mode");
                    continue;
                }
            };

            // Process scan results
            let port_results = match scan_results {
                Ok(results) => results,
                Err(e) => {
                    warn!(ip = %target.ip, error = %e, "Batch scan failed");
                    continue;
                }
            };

            // Convert to PortResult format
            let mut converted_results = Vec::new();
            for (port, state) in &port_results {
                let output_state = match state {
                    rustnmap_common::PortState::Open => PortState::Open,
                    rustnmap_common::PortState::Closed => PortState::Closed,
                    rustnmap_common::PortState::Filtered => PortState::Filtered,
                    rustnmap_common::PortState::Unfiltered => PortState::Unfiltered,
                    rustnmap_common::PortState::OpenOrFiltered => PortState::OpenOrFiltered,
                    rustnmap_common::PortState::ClosedOrFiltered => PortState::ClosedOrFiltered,
                    rustnmap_common::PortState::OpenOrClosed => PortState::OpenOrClosed,
                };

                let is_open = *state == rustnmap_common::PortState::Open;
                if is_open {
                    self.session.stats.record_open_port();
                }
                self.session.stats.record_packet_sent();

                let service_info =
                    service_info_from_db(*port, rustnmap_common::ServiceProtocol::Tcp);

                converted_results.push(PortResult {
                    number: *port,
                    protocol: rustnmap_output::models::Protocol::Tcp,
                    state: output_state,
                    state_reason: "batch-scan".to_string(),
                    state_ttl: None,
                    service: service_info,
                    scripts: Vec::new(),
                });
            }

            // Add ports that weren't in results (shouldn't happen, but be safe)
            for port in ports {
                if !port_results.contains_key(port) {
                    self.session.stats.record_packet_sent();
                    converted_results.push(PortResult {
                        number: *port,
                        protocol: rustnmap_output::models::Protocol::Tcp,
                        state: PortState::OpenOrFiltered,
                        state_reason: "no-response".to_string(),
                        state_ttl: None,
                        service: service_info_from_db(*port, rustnmap_common::ServiceProtocol::Tcp),
                        scripts: Vec::new(),
                    });
                }
            }

            // Get MAC address via ARP (only for IPv4 targets)
            let mac = match target.ip {
                IpAddr::V4(target_ipv4) => {
                    get_mac_address_via_arp(
                        target_ipv4,
                        local_addr,
                        std::time::Duration::from_millis(500),
                    )
                    .map(|mac_addr| {
                        let mac_str = mac_addr.to_string();
                        // Look up vendor from MAC prefix database
                        let vendor = self
                            .session
                            .fingerprint_db
                            .mac_db()
                            .and_then(|db| db.lookup(&mac_str))
                            .map(std::string::ToString::to_string);
                        rustnmap_output::models::MacAddress {
                            address: mac_str,
                            vendor,
                        }
                    })
                }
                IpAddr::V6(_) => None,
            };

            let host_result = HostResult {
                ip: target.ip,
                mac,
                hostname: target.hostname.clone(),
                status: HostStatus::Up,
                status_reason: "batch-scan".to_string(),
                latency: std::time::Duration::from_millis(1),
                ports: converted_results,
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
        }

        info!(hosts = host_results.len(), "Batch port scanning completed");
        Ok(host_results)
    }

    /// Runs TCP Connect port scanning in batch mode for improved performance.
    ///
    /// Uses `TcpConnectScanner::scan_ports_parallel()` to scan all ports
    /// concurrently instead of sequentially, providing significant performance
    /// improvement matching nmap's behavior.
    #[expect(
        clippy::too_many_lines,
        reason = "Batch scanning requires handling all hosts and ports in one function for performance"
    )]
    async fn run_port_scanning_connect_batch(
        &self,
        targets: &[Target],
        ports: &[u16],
    ) -> Result<Vec<HostResult>> {
        info!("Starting batch port scanning for TCP connect scan");

        let local_addr = get_local_address(&self.session.config.dns_server);
        let timing_config = self.session.config.timing_template.scan_config();

        let scanner_config = ScannerConfig {
            min_rtt: timing_config.min_rtt,
            max_rtt: timing_config.max_rtt,
            initial_rtt: timing_config.initial_rtt,
            max_retries: timing_config.max_retries,
            host_timeout: self
                .session
                .config
                .host_timeout
                .as_millis()
                .try_into()
                .unwrap_or(30000),
            // Use scan_delay from timing template (T0-T5 have specific delays)
            scan_delay: timing_config.scan_delay,
            dns_server: self.session.config.dns_server.clone(),
            min_rate: self.session.config.min_rate,
            max_rate: self.session.config.max_rate,
            timing_level: timing_config.timing_level,
        };

        let mut host_results = Vec::new();

        for target in targets {
            // Create connect scanner with optimized parallel scanning
            let connect_scanner = TcpConnectScanner::new(Some(local_addr), scanner_config.clone());

            // Scan all ports in parallel using async I/O
            let port_states = connect_scanner.scan_ports_parallel(target, ports).await;

            // Convert to PortResult format
            let mut port_results = Vec::new();
            for port in ports {
                let common_state = port_states
                    .get(port)
                    .copied()
                    .unwrap_or(rustnmap_common::PortState::Filtered);
                let state = match common_state {
                    rustnmap_common::PortState::Open => PortState::Open,
                    rustnmap_common::PortState::Closed => PortState::Closed,
                    rustnmap_common::PortState::Filtered => PortState::Filtered,
                    rustnmap_common::PortState::Unfiltered => PortState::Unfiltered,
                    rustnmap_common::PortState::OpenOrFiltered => PortState::OpenOrFiltered,
                    rustnmap_common::PortState::ClosedOrFiltered => PortState::ClosedOrFiltered,
                    rustnmap_common::PortState::OpenOrClosed => PortState::OpenOrClosed,
                };
                let is_open = matches!(common_state, rustnmap_common::PortState::Open);

                if is_open {
                    self.session.stats.record_open_port();
                }
                self.session.stats.record_packet_sent();

                let service_info =
                    service_info_from_db(*port, rustnmap_common::ServiceProtocol::Tcp);

                port_results.push(PortResult {
                    number: *port,
                    protocol: rustnmap_output::models::Protocol::Tcp,
                    state,
                    state_reason: "connect-scan".to_string(),
                    state_ttl: None,
                    service: service_info,
                    scripts: Vec::new(),
                });
            }

            // Get MAC address for IPv4 targets
            let mac = match target.ip {
                IpAddr::V4(target_ipv4) => {
                    get_mac_address_via_arp(
                        target_ipv4,
                        local_addr,
                        std::time::Duration::from_millis(500),
                    )
                    .map(|mac_addr| {
                        let mac_str = mac_addr.to_string();
                        // Look up vendor from MAC prefix database
                        let vendor = self
                            .session
                            .fingerprint_db
                            .mac_db()
                            .and_then(|db| db.lookup(&mac_str))
                            .map(std::string::ToString::to_string);
                        rustnmap_output::models::MacAddress {
                            address: mac_str,
                            vendor,
                        }
                    })
                }
                IpAddr::V6(_) => None,
            };

            let host_result = HostResult {
                ip: target.ip,
                mac,
                hostname: target.hostname.clone(),
                status: HostStatus::Up,
                status_reason: "connect-scan".to_string(),
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
        }

        info!(
            hosts = host_results.len(),
            "TCP connect batch port scanning completed"
        );
        Ok(host_results)
    }

    /// Runs two-phase port scanning (fast discovery + deep scan).
    ///
    /// Phase 1: Quick scan of common ports to identify live hosts with open ports
    /// Phase 2: Full port scan only on hosts that responded in Phase 1
    #[expect(
        clippy::too_many_lines,
        reason = "Two-phase scanning requires multiple sequential operations"
    )]
    async fn run_two_phase_port_scanning(&self) -> Result<Vec<HostResult>> {
        info!("Starting two-phase port scanning");

        let targets: Vec<Target> = self.session.target_set.targets().to_vec();
        let mut host_results = Vec::new();
        let mut phase1_hosts = Vec::new();

        // Get local address for MAC lookup
        let local_addr = get_local_address(&self.session.config.dns_server);

        // ========== Phase 1: Fast Discovery ==========
        info!("Phase 1: Fast discovery with common ports");
        let first_phase_ports = if self.session.config.first_phase_ports.is_empty() {
            // Default common ports for fast discovery
            vec![22, 80, 443, 8080]
        } else {
            self.session.config.first_phase_ports.clone()
        };

        for target in &targets {
            let mut phase1_port_results = Vec::new();
            let mut has_open_port = false;

            for port in &first_phase_ports {
                // Enforce scan_delay before each probe (nmap timing.cc:172-206)
                self.enforce_scan_delay().await;
                let port_result = self.scan_port(target, *port).await?;
                if port_result.state == PortState::Open {
                    has_open_port = true;
                    phase1_port_results.push(port_result);
                    self.session.stats.record_open_port();
                }
                self.session.stats.record_packet_sent();
            }

            // Track hosts that responded with open ports in Phase 1
            if has_open_port {
                let open_port_count = phase1_port_results.len();
                phase1_hosts.push((target.clone(), phase1_port_results));
                info!("Phase 1: {} has {} open ports", target.ip, open_port_count);
            }
        }

        info!(
            "Phase 1 completed: {} hosts with open ports",
            phase1_hosts.len()
        );

        // ========== Phase 2: Deep Scan ==========
        info!("Phase 2: Deep scan on {} hosts", phase1_hosts.len());

        for (target, phase1_ports) in phase1_hosts {
            let all_ports = self.get_ports_for_scan();
            let mut phase2_port_results = phase1_ports;

            // Only scan ports that weren't already scanned in Phase 1
            for port in all_ports {
                if !first_phase_ports.contains(&port) {
                    // Enforce scan_delay before each probe (nmap timing.cc:172-206)
                    self.enforce_scan_delay().await;
                    let port_result = self.scan_port(&target, port).await?;
                    let is_open = port_result.state == PortState::Open;
                    phase2_port_results.push(port_result);
                    if is_open {
                        self.session.stats.record_open_port();
                    }
                    self.session.stats.record_packet_sent();
                }
            }

            let host_result = HostResult {
                ip: target.ip,
                mac: match target.ip {
                    IpAddr::V4(target_ipv4) => {
                        get_mac_address_via_arp(
                            target_ipv4,
                            local_addr,
                            std::time::Duration::from_millis(500),
                        )
                        .map(|mac_addr| {
                            let mac_str = mac_addr.to_string();
                            // Look up vendor from MAC prefix database
                            let vendor = self
                                .session
                                .fingerprint_db
                                .mac_db()
                                .and_then(|db| db.lookup(&mac_str))
                                .map(std::string::ToString::to_string);
                            rustnmap_output::models::MacAddress {
                                address: mac_str,
                                vendor,
                            }
                        })
                    }
                    IpAddr::V6(_) => None,
                },
                hostname: target.hostname.clone(),
                status: HostStatus::Up,
                status_reason: "syn-ack".to_string(),
                latency: std::time::Duration::from_millis(1),
                ports: phase2_port_results,
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
        }

        // Add hosts from Phase 1 that had no open ports (skip in Phase 2)
        // These hosts are alive but have no open common ports
        for target in &targets {
            if !host_results.iter().any(|h| h.ip == target.ip) {
                let mac = match target.ip {
                    IpAddr::V4(target_ipv4) => {
                        get_mac_address_via_arp(
                            target_ipv4,
                            local_addr,
                            std::time::Duration::from_millis(500),
                        )
                        .map(|mac_addr| {
                            let mac_str = mac_addr.to_string();
                            // Look up vendor from MAC prefix database
                            let vendor = self
                                .session
                                .fingerprint_db
                                .mac_db()
                                .and_then(|db| db.lookup(&mac_str))
                                .map(std::string::ToString::to_string);
                            rustnmap_output::models::MacAddress {
                                address: mac_str,
                                vendor,
                            }
                        })
                    }
                    IpAddr::V6(_) => None,
                };
                let host_result = HostResult {
                    ip: target.ip,
                    mac,
                    hostname: target.hostname.clone(),
                    status: HostStatus::Up,
                    status_reason: "host-alive".to_string(),
                    latency: std::time::Duration::from_millis(1),
                    ports: vec![],
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
            }
        }

        info!(
            hosts = host_results.len(),
            "Two-phase port scanning completed"
        );
        Ok(host_results)
    }

    /// Scans a single port on a target.
    #[allow(
        clippy::too_many_lines,
        reason = "Port scanning requires handling all scan types and protocols in one function for performance"
    )]
    async fn scan_port(&self, target: &Target, port: u16) -> Result<PortResult> {
        use rustnmap_common::Ipv4Addr;

        // Get the primary scan type from config
        let primary_scan_type = self
            .session
            .config
            .scan_types
            .first()
            .copied()
            .unwrap_or(ScanType::TcpSyn);

        // Get timing parameters from the timing template
        let timing_config = self.session.config.timing_template.scan_config();

        // Create scanner configuration from session config
        let scanner_config = ScannerConfig {
            min_rtt: timing_config.min_rtt,
            max_rtt: timing_config.max_rtt,
            initial_rtt: timing_config.initial_rtt,
            max_retries: timing_config.max_retries,
            host_timeout: self
                .session
                .config
                .host_timeout
                .as_millis()
                .try_into()
                .unwrap_or(30000),
            // Use scan_delay from timing template (T0-T5 have specific delays)
            scan_delay: timing_config.scan_delay,
            dns_server: self.session.config.dns_server.clone(),
            min_rate: self.session.config.min_rate,
            max_rate: self.session.config.max_rate,
            timing_level: timing_config.timing_level,
        };

        // Get local address for the scanner by detecting the source IP for the target
        let local_addr = get_local_address(&self.session.config.dns_server);
        debug!(local_addr = %local_addr, "Using local address for scanner");

        // Create decoy scheduler if evasion config has decoys
        let decoy_scheduler: Option<DecoyScheduler> =
            create_decoy_scheduler(&self.session, local_addr);

        // Get target IP address
        let target_ip = match target.ip {
            std::net::IpAddr::V4(addr) => addr,
            std::net::IpAddr::V6(_) => {
                // IPv6 not supported by current scanners
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

        // Route to appropriate scanner based on scan type
        let scan_result: std::result::Result<rustnmap_common::PortState, _> =
            match primary_scan_type {
                ScanType::TcpSyn => {
                    match TcpSynScanner::new(local_addr, scanner_config) {
                        Ok(scanner) => {
                            scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                        }
                        Err(_) => {
                            // Raw socket creation failed (not root), use TCP Connect fallback
                            return self.scan_port_connect(target, port).await;
                        }
                    }
                }
                ScanType::TcpConnect => {
                    // TCP Connect doesn't need root, use it directly
                    let connect_scanner = TcpConnectScanner::new(Some(local_addr), scanner_config);
                    connect_scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                }
                ScanType::TcpFin => match TcpFinScanner::with_decoy(
                    local_addr,
                    scanner_config,
                    decoy_scheduler.clone(),
                ) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::TcpNull => match TcpNullScanner::with_decoy(
                    local_addr,
                    scanner_config,
                    decoy_scheduler.clone(),
                ) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::TcpXmas => match TcpXmasScanner::with_decoy(
                    local_addr,
                    scanner_config,
                    decoy_scheduler.clone(),
                ) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::TcpAck => match TcpAckScanner::new(local_addr, scanner_config) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::TcpWindow => match TcpWindowScanner::new(local_addr, scanner_config) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::TcpMaimon => match TcpMaimonScanner::with_decoy(
                    local_addr,
                    scanner_config,
                    decoy_scheduler.clone(),
                ) {
                    Ok(scanner) => {
                        scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                    }
                    Err(_) => return self.scan_port_connect(target, port).await,
                },
                ScanType::Udp => {
                    match UdpScanner::new(local_addr, scanner_config) {
                        Ok(scanner) => {
                            scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Udp)
                        }
                        Err(_) => {
                            // UDP requires root, return filtered on error
                            return Ok(PortResult {
                                number: port,
                                protocol: rustnmap_output::models::Protocol::Udp,
                                state: PortState::Filtered,
                                state_reason: "udp-scan-error".to_string(),
                                state_ttl: None,
                                service: None,
                                scripts: Vec::new(),
                            });
                        }
                    }
                }
                ScanType::IpProtocol => {
                    match IpProtocolScanner::new(local_addr, scanner_config) {
                        Ok(scanner) => {
                            // For IP protocol scan, the 'port' is actually the protocol number
                            scanner.scan_port(&common_target, port, rustnmap_common::Protocol::Tcp)
                        }
                        Err(_) => {
                            return Ok(PortResult {
                                number: port,
                                protocol: rustnmap_output::models::Protocol::Tcp,
                                state: PortState::Filtered,
                                state_reason: "ip-protocol-scanner-init-failed".to_string(),
                                state_ttl: None,
                                service: None,
                                scripts: Vec::new(),
                            });
                        }
                    }
                }
                ScanType::SctpInit => {
                    // SCTP requires new scanner implementation (Phase 3)
                    return Ok(PortResult {
                        number: port,
                        protocol: rustnmap_output::models::Protocol::Sctp,
                        state: PortState::Filtered,
                        state_reason: "sctp-not-yet-implemented".to_string(),
                        state_ttl: None,
                        service: None,
                        scripts: Vec::new(),
                    });
                }
            };

        // Process scan result
        if let Ok(state) = scan_result {
            let (port_state, reason) = match state {
                rustnmap_common::PortState::Open => {
                    (PortState::Open, "response-received".to_string())
                }
                rustnmap_common::PortState::Closed => {
                    (PortState::Closed, "rst-received".to_string())
                }
                rustnmap_common::PortState::Filtered => {
                    (PortState::Filtered, "no-response".to_string())
                }
                rustnmap_common::PortState::Unfiltered => {
                    (PortState::Unfiltered, "no-response".to_string())
                }
                rustnmap_common::PortState::OpenOrFiltered => {
                    (PortState::OpenOrFiltered, "no-response".to_string())
                }
                rustnmap_common::PortState::ClosedOrFiltered => {
                    (PortState::ClosedOrFiltered, "no-response".to_string())
                }
                rustnmap_common::PortState::OpenOrClosed => {
                    (PortState::OpenOrClosed, "ambiguous".to_string())
                }
            };

            let protocol = match primary_scan_type {
                ScanType::Udp => rustnmap_output::models::Protocol::Udp,
                _ => rustnmap_output::models::Protocol::Tcp,
            };

            let is_udp = matches!(primary_scan_type, ScanType::Udp);
            let service_proto = if is_udp {
                rustnmap_common::ServiceProtocol::Udp
            } else {
                rustnmap_common::ServiceProtocol::Tcp
            };
            return Ok(PortResult {
                number: port,
                protocol,
                state: port_state,
                state_reason: reason,
                state_ttl: None,
                service: service_info_from_db(port, service_proto),
                scripts: Vec::new(),
            });
        }

        let protocol = match primary_scan_type {
            ScanType::Udp => rustnmap_output::models::Protocol::Udp,
            _ => rustnmap_output::models::Protocol::Tcp,
        };

        Ok(PortResult {
            number: port,
            protocol,
            state: PortState::Filtered,
            state_reason: "scan-error".to_string(),
            state_ttl: None,
            service: None,
            scripts: Vec::new(),
        })
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
            service: service_info_from_db(port, rustnmap_common::ServiceProtocol::Tcp),
            scripts: Vec::new(),
        })
    }

    /// Gets the list of ports to scan based on configuration.
    fn get_ports_for_scan(&self) -> Vec<u16> {
        match &self.session.config.port_spec {
            super::session::PortSpec::All => (1..=65535).collect(),
            super::session::PortSpec::Top(n) => {
                let db = rustnmap_common::ServiceDatabase::global();
                // Use frequency-sorted top ports from nmap-services database
                let primary_scan_type = self
                    .session
                    .config
                    .scan_types
                    .first()
                    .copied()
                    .unwrap_or(ScanType::TcpSyn);
                if matches!(primary_scan_type, ScanType::Udp) {
                    db.top_udp_ports(*n).to_vec()
                } else {
                    db.top_tcp_ports(*n).to_vec()
                }
            }
            super::session::PortSpec::List(ports) => ports.clone(),
            super::session::PortSpec::Range { start, end } => (*start..=*end).collect(),
        }
    }

    /// Runs the service detection phase.
    ///
    /// # Errors
    ///
    /// Returns an error if service detection fails for any host.
    async fn run_service_detection(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting service detection phase");

        // Check if service database is available
        let Some(service_db) = self.session.fingerprint_db.service_db() else {
            warn!("Service probe database not loaded, skipping service detection");
            return Ok(());
        };
        let service_db = service_db.clone();

        let detector = rustnmap_fingerprint::ServiceDetector::new(service_db)
            .with_timeout(std::time::Duration::from_secs(5));

        for host_result in host_results.iter_mut() {
            for port_result in &mut host_result.ports {
                if port_result.state == PortState::Open {
                    let target_addr = SocketAddr::new(host_result.ip, port_result.number);

                    // Run detection for this port using async await
                    match detector
                        .detect_service(&target_addr, port_result.number)
                        .await
                    {
                        Ok(services) => {
                            if let Some(service_info) = services.first() {
                                debug!(
                                    ip = %host_result.ip,
                                    port = port_result.number,
                                    service = %service_info.name,
                                    product = ?service_info.product,
                                    version = ?service_info.version,
                                    confidence = service_info.confidence,
                                    "Service detected"
                                );

                                // Convert fingerprint ServiceInfo to output ServiceInfo
                                port_result.service = Some(rustnmap_output::models::ServiceInfo {
                                    name: service_info.name.clone(),
                                    product: service_info.product.clone(),
                                    version: service_info.version.clone(),
                                    extrainfo: service_info.info.clone(),
                                    hostname: service_info.hostname.clone(),
                                    ostype: service_info.os_type.clone(),
                                    devicetype: service_info.device_type.clone(),
                                    method: "probed".to_string(),
                                    confidence: service_info.confidence,
                                    cpe: service_info
                                        .cpe
                                        .clone()
                                        .map(|c| vec![c])
                                        .unwrap_or_default(),
                                });

                                // Debug: print what was stored
                                debug!(
                                    "Stored service info for port {}: service={}, product={:?}, version={:?}",
                                    port_result.number,
                                    port_result.service.as_ref().map_or("None", |s| s.name.as_str()),
                                    port_result.service.as_ref().and_then(|s| s.product.as_ref()),
                                    port_result.service.as_ref().and_then(|s| s.version.as_ref())
                                );
                            }
                        }
                        Err(e) => {
                            debug!(
                                ip = %host_result.ip,
                                port = port_result.number,
                                error = %e,
                                "Service detection failed"
                            );
                        }
                    }
                }
            }
        }

        info!("Service detection phase completed");
        Ok(())
    }

    /// Runs the OS detection phase.
    ///
    /// # Errors
    ///
    /// Returns an error if OS detection fails for any host.
    async fn run_os_detection(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting OS detection phase");

        // Check if OS database is available
        let Some(os_db) = self.session.fingerprint_db.os_db() else {
            warn!("OS fingerprint database not loaded, skipping OS detection");
            return Ok(());
        };

        // Get local address for OS detection probes
        let local_addr = std::net::Ipv4Addr::UNSPECIFIED;

        for host_result in host_results.iter_mut() {
            // OS detection only works with IPv4
            let IpAddr::V4(target_ip) = host_result.ip else {
                debug!(ip = %host_result.ip, "OS detection skipped for IPv6 target");
                continue;
            };

            // Find open and closed ports for OS detection probes
            // Nmap requires both: open port for SEQ/ECN probes, closed port for T2-T7 tests
            let open_port = host_result
                .ports
                .iter()
                .find(|p| p.state == PortState::Open)
                .map_or(80, |p| p.number);

            let closed_port = host_result
                .ports
                .iter()
                .find(|p| p.state == PortState::Closed)
                .map_or(443, |p| p.number);

            // Create detector with the correct ports for this host
            let detector = rustnmap_fingerprint::OsDetector::new(os_db.clone(), local_addr)
                .with_open_port(open_port)
                .with_closed_port(closed_port)
                .with_timeout(std::time::Duration::from_secs(5));

            let target_addr = SocketAddr::new(IpAddr::V4(target_ip), open_port);

            // Run OS detection using async await
            match detector.detect_os(&target_addr).await {
                Ok(matches) => {
                    debug!(
                        ip = %host_result.ip,
                        matches_count = matches.len(),
                        "OS detection completed"
                    );

                    // Convert fingerprint OsMatch to output OsMatch
                    host_result.os_matches = matches
                        .into_iter()
                        .map(|m| rustnmap_output::models::OsMatch {
                            name: m.name,
                            accuracy: m.accuracy,
                            os_family: match m.family {
                                rustnmap_fingerprint::os::database::OsFamily::Linux => {
                                    Some("Linux".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::Windows => {
                                    Some("Windows".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::MacOS => {
                                    Some("MacOS".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::BSD => {
                                    Some("BSD".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::Solaris => {
                                    Some("Solaris".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::IOS => {
                                    Some("iOS".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::Android => {
                                    Some("Android".to_string())
                                }
                                rustnmap_fingerprint::os::database::OsFamily::Other(s) => Some(s),
                            },
                            os_generation: m.generation,
                            vendor: m.vendor,
                            device_type: m.device_type,
                            cpe: m.cpe.map(|c| vec![c]).unwrap_or_default(),
                        })
                        .collect();
                }
                Err(e) => {
                    debug!(
                        ip = %host_result.ip,
                        error = %e,
                        "OS detection failed"
                    );
                }
            }
        }

        info!("OS detection phase completed");
        Ok(())
    }

    /// Runs NSE scripts on discovered services.
    #[expect(
        clippy::unnecessary_wraps,
        clippy::too_many_lines,
        clippy::map_unwrap_or,
        reason = "NSE script execution is inherently verbose; Result return required for future extensions"
    )]
    fn run_nse_scripts(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting NSE script execution phase");

        // Check if NSE scripts are enabled and scripts are available
        if self.session.nse_registry.is_empty() {
            debug!("No NSE scripts registered, skipping NSE execution");
            return Ok(());
        }

        // Create script engine - get the database from registry
        // Since ScriptDatabase doesn't implement Clone, we need to create engine differently
        let engine = self.session.nse_registry.create_engine();

        // Get script categories to run
        let categories: Vec<rustnmap_nse::ScriptCategory> =
            if self.session.config.nse_categories.is_empty() {
                // Default to 'default' category if none specified
                vec![rustnmap_nse::ScriptCategory::Default]
            } else {
                self.session
                    .config
                    .nse_categories
                    .iter()
                    .filter_map(|c| match c.as_str() {
                        "auth" => Some(rustnmap_nse::ScriptCategory::Auth),
                        "broadcast" => Some(rustnmap_nse::ScriptCategory::Broadcast),
                        "brute" => Some(rustnmap_nse::ScriptCategory::Brute),
                        "default" => Some(rustnmap_nse::ScriptCategory::Default),
                        "discovery" => Some(rustnmap_nse::ScriptCategory::Discovery),
                        "dos" => Some(rustnmap_nse::ScriptCategory::Dos),
                        "exploit" => Some(rustnmap_nse::ScriptCategory::Exploit),
                        "external" => Some(rustnmap_nse::ScriptCategory::External),
                        "fuzzer" => Some(rustnmap_nse::ScriptCategory::Fuzzer),
                        "intrusive" => Some(rustnmap_nse::ScriptCategory::Intrusive),
                        "malware" => Some(rustnmap_nse::ScriptCategory::Malware),
                        "safe" => Some(rustnmap_nse::ScriptCategory::Safe),
                        "version" => Some(rustnmap_nse::ScriptCategory::Version),
                        "vuln" => Some(rustnmap_nse::ScriptCategory::Vuln),
                        _ => {
                            warn!("Unknown script category: {}", c);
                            None
                        }
                    })
                    .collect()
            };

        // Select scripts by category
        let scripts: Vec<&rustnmap_nse::NseScript> = engine.scheduler().select_scripts(&categories);

        if scripts.is_empty() {
            debug!("No scripts match the specified categories");
            return Ok(());
        }

        debug!("Selected {} scripts for execution", scripts.len());

        // Check if we're in a tokio runtime context
        if tokio::runtime::Handle::try_current().is_err() {
            warn!("No tokio runtime available for NSE execution");
            return Ok(());
        }

        for host_result in host_results.iter_mut() {
            for port_result in &mut host_result.ports {
                if port_result.state == PortState::Open {
                    let protocol = match port_result.protocol {
                        rustnmap_output::models::Protocol::Tcp => "tcp",
                        rustnmap_output::models::Protocol::Udp => "udp",
                        rustnmap_output::models::Protocol::Sctp => "sctp",
                    };

                    let service_name = port_result
                        .service
                        .as_ref()
                        .map(|s| s.name.as_str())
                        .unwrap_or("");

                    // Execute scripts for this port
                    for script in &scripts {
                        // Check if portrule matches
                        match engine.evaluate_portrule(
                            script,
                            host_result.ip,
                            port_result.number,
                            protocol,
                            "open",
                            Some(service_name),
                        ) {
                            Ok(true) => {
                                // Portrule matched, execute the script
                                match engine.execute_port_script(
                                    script,
                                    host_result.ip,
                                    port_result.number,
                                    protocol,
                                    "open",
                                    Some(service_name),
                                ) {
                                    Ok(result) => {
                                        if result.is_success() && !result.output.is_empty() {
                                            debug!(
                                                ip = %host_result.ip,
                                                port = port_result.number,
                                                script = %result.script_id,
                                                "NSE script executed successfully"
                                            );

                                            port_result.scripts.push(
                                                rustnmap_output::models::ScriptResult {
                                                    id: result.script_id,
                                                    output: result.output.to_display(),
                                                    elements: Vec::new(),
                                                },
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        debug!(
                                            ip = %host_result.ip,
                                            port = port_result.number,
                                            script = %script.id,
                                            error = %e,
                                            "NSE script execution failed"
                                        );
                                    }
                                }
                            }
                            Ok(false) => {
                                // Portrule didn't match, skip
                            }
                            Err(e) => {
                                debug!(
                                    ip = %host_result.ip,
                                    port = port_result.number,
                                    script = %script.id,
                                    error = %e,
                                    "NSE portrule evaluation failed"
                                );
                            }
                        }
                    }
                }
            }

            // Also execute host scripts against the host
            for script in &scripts {
                match engine.evaluate_hostrule(script, host_result.ip) {
                    Ok(true) => match engine.execute_script(script, host_result.ip) {
                        Ok(result) => {
                            if result.is_success() && !result.output.is_empty() {
                                host_result
                                    .scripts
                                    .push(rustnmap_output::models::ScriptResult {
                                        id: result.script_id,
                                        output: result.output.to_display(),
                                        elements: Vec::new(),
                                    });
                            }
                        }
                        Err(e) => {
                            debug!(
                                ip = %host_result.ip,
                                script = %script.id,
                                error = %e,
                                "Host script execution failed"
                            );
                        }
                    },
                    Ok(false) => {}
                    Err(e) => {
                        debug!(
                            ip = %host_result.ip,
                            script = %script.id,
                            error = %e,
                            "Hostrule evaluation failed"
                        );
                    }
                }
            }
        }

        info!("NSE script execution phase completed");
        Ok(())
    }

    /// Runs traceroute to discovered hosts.
    ///
    /// # Errors
    ///
    /// Returns an error if traceroute fails for any host.
    async fn run_traceroute(&self, host_results: &mut [HostResult]) -> Result<()> {
        info!("Starting traceroute phase");

        // Create traceroute configuration
        let config = rustnmap_traceroute::TracerouteConfig::new()
            .with_max_hops(30)
            .with_probes_per_hop(3)
            .with_probe_timeout(std::time::Duration::from_secs(1));

        // Get local address for traceroute
        let local_addr = rustnmap_common::Ipv4Addr::UNSPECIFIED;

        // Create traceroute instance
        let Ok(tracer) = rustnmap_traceroute::Traceroute::new(config, local_addr) else {
            warn!("Failed to create traceroute instance");
            return Ok(());
        };

        for host_result in host_results.iter_mut() {
            // Traceroute only works with IPv4
            let IpAddr::V4(addr) = host_result.ip else {
                debug!(ip = %host_result.ip, "Traceroute skipped for IPv6 target");
                continue;
            };

            // Convert std::net::Ipv4Addr to rustnmap_common::Ipv4Addr
            let target_ip = rustnmap_common::Ipv4Addr::new(
                addr.octets()[0],
                addr.octets()[1],
                addr.octets()[2],
                addr.octets()[3],
            );

            // Run traceroute using async await
            match tracer.trace(target_ip).await {
                Ok(result) => {
                    debug!(
                        ip = %host_result.ip,
                        hops = result.hop_count(),
                        completed = result.completed(),
                        "Traceroute completed"
                    );

                    // Convert traceroute hops to output format
                    let hops: Vec<rustnmap_output::models::TracerouteHop> = result
                        .hops()
                        .iter()
                        .filter_map(|hop| {
                            hop.ip().map(|ip| {
                                // Convert rustnmap_common::Ipv4Addr to std::net::IpAddr
                                let std_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                                    ip.octets()[0],
                                    ip.octets()[1],
                                    ip.octets()[2],
                                    ip.octets()[3],
                                ));
                                rustnmap_output::models::TracerouteHop {
                                    ttl: hop.ttl(),
                                    ip: std_ip,
                                    hostname: hop.hostname().map(String::from),
                                    rtt: hop.avg_rtt(),
                                }
                            })
                        })
                        .collect();

                    if !hops.is_empty() {
                        // Use the protocol from traceroute config, default to UDP
                        let protocol = match tracer.config().probe_type() {
                            rustnmap_traceroute::ProbeType::TcpSyn
                            | rustnmap_traceroute::ProbeType::TcpAck => {
                                rustnmap_output::models::Protocol::Tcp
                            }
                            rustnmap_traceroute::ProbeType::Udp => {
                                rustnmap_output::models::Protocol::Udp
                            }
                            rustnmap_traceroute::ProbeType::Icmp => {
                                // ICMP is not in Protocol enum, use UDP as fallback
                                rustnmap_output::models::Protocol::Udp
                            }
                        };
                        host_result.traceroute = Some(rustnmap_output::models::TracerouteResult {
                            protocol,
                            port: tracer.config().dest_port(),
                            hops,
                        });
                    }
                }
                Err(e) => {
                    debug!(
                        ip = %host_result.ip,
                        error = %e,
                        "Traceroute failed"
                    );
                }
            }
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

        // Derive scan type and protocol from config
        let primary_scan_type = self
            .session
            .config
            .scan_types
            .first()
            .copied()
            .unwrap_or(ScanType::TcpSyn);
        let (output_scan_type, output_protocol) = match primary_scan_type {
            ScanType::TcpSyn => (
                rustnmap_output::models::ScanType::TcpSyn,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpConnect => (
                rustnmap_output::models::ScanType::TcpConnect,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpFin => (
                rustnmap_output::models::ScanType::TcpFin,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpNull => (
                rustnmap_output::models::ScanType::TcpNull,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpXmas => (
                rustnmap_output::models::ScanType::TcpXmas,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpAck => (
                rustnmap_output::models::ScanType::TcpAck,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpWindow => (
                rustnmap_output::models::ScanType::TcpWindow,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::TcpMaimon => (
                rustnmap_output::models::ScanType::TcpMaimon,
                rustnmap_output::models::Protocol::Tcp,
            ),
            ScanType::Udp => (
                rustnmap_output::models::ScanType::Udp,
                rustnmap_output::models::Protocol::Udp,
            ),
            ScanType::SctpInit => (
                rustnmap_output::models::ScanType::SctpInit,
                rustnmap_output::models::Protocol::Sctp,
            ),
            ScanType::IpProtocol => (
                rustnmap_output::models::ScanType::IpProtocol,
                rustnmap_output::models::Protocol::Tcp,
            ), // IP protocol uses generic protocol field
        };

        let metadata = rustnmap_output::models::ScanMetadata {
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            command_line: String::new(), // Command line not available in core
            start_time: chrono::Utc::now()
                - chrono::TimeDelta::from_std(elapsed).unwrap_or_default(),
            end_time: chrono::Utc::now(),
            elapsed,
            scan_type: output_scan_type,
            protocol: output_protocol,
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

/// Looks up service info from the `nmap-services` database.
///
/// Returns a `ServiceInfo` with method "table" and confidence 3,
/// matching Nmap's behavior for non-probed service identification.
fn service_info_from_db(
    port: u16,
    protocol: rustnmap_common::ServiceProtocol,
) -> Option<rustnmap_output::models::ServiceInfo> {
    let db = rustnmap_common::ServiceDatabase::global();
    let name = db.lookup(port, protocol)?;

    Some(rustnmap_output::models::ServiceInfo {
        name: name.to_string(),
        product: None,
        version: None,
        extrainfo: None,
        ostype: None,
        hostname: None,
        devicetype: None,
        method: "table".to_string(),
        confidence: 3,
        cpe: Vec::new(),
    })
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
        let config = ScanConfig {
            service_detection: true,
            os_detection: true,
            ..ScanConfig::default()
        };

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
