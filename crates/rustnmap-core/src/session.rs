//! Scan session context and core abstractions.
//!
//! This module defines the [`ScanSession`] struct, which is the central context
//! for all scanning operations. It holds configuration, shared state, and
//! dependencies that all scan modules need access to.
//!
//! The session follows the dependency injection pattern, allowing mock
//! implementations to be substituted for testing without requiring root
//! privileges or actual network access.

use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use rustnmap_common::{MacAddr, Port};
use rustnmap_output::models::{HostResult, ScanResult};
use rustnmap_scan::scanner::TimingTemplate;
use rustnmap_target::{Target, TargetGroup};
use tokio::sync::broadcast;
use tokio_stream::Stream;

use crate::error::{CoreError, Result};

/// BPF filter program for packet filtering.
#[repr(C)]
#[derive(Debug)]
pub struct BpfProg {
    /// Length of the BPF program in instructions.
    pub bf_len: libc::c_ushort,
    /// Pointer to the BPF instructions.
    pub bf_insns: *const libc::sock_filter,
}

// SAFETY: BpfProg is only used with raw sockets and is thread-safe
// SAFETY: BpfProg contains raw pointers but is used only with raw socket operations
// and is thread-safe when properly synchronized by the kernel
unsafe impl Send for BpfProg {}
// SAFETY: BpfProg contains raw pointers but is used only with raw socket operations
// and is thread-safe when properly synchronized by the kernel
unsafe impl Sync for BpfProg {}

/// Packet buffer for zero-copy packet handling.
#[derive(Debug, Clone)]
pub struct PacketBuffer {
    /// Packet data (zero-copy reference).
    pub data: Bytes,
    /// Length of valid data.
    pub len: usize,
    /// Timestamp when packet was received.
    pub timestamp: std::time::Duration,
    /// Protocol number (e.g., 6 for TCP, 17 for UDP).
    pub protocol: u16,
}

impl PacketBuffer {
    /// Creates a new packet buffer from bytes.
    #[must_use]
    pub fn new(data: Bytes, timestamp: std::time::Duration, protocol: u16) -> Self {
        let len = data.len();
        Self {
            data,
            len,
            timestamp,
            protocol,
        }
    }

    /// Returns true if this buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Packet engine abstraction for dependency injection.
///
/// This trait abstracts the packet I/O layer, allowing different implementations
/// for production (using raw sockets) and testing (using mock implementations).
#[async_trait]
pub trait PacketEngine: Send + Sync {
    /// Sends a single packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be sent due to network issues
    /// or permission problems.
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize>;

    /// Sends multiple packets in a batch.
    ///
    /// # Errors
    ///
    /// Returns an error if any packet cannot be sent.
    async fn send_batch(&self, pkts: &[PacketBuffer]) -> Result<usize> {
        let mut total = 0;
        for pkt in pkts {
            total += self.send_packet(pkt.clone()).await?;
        }
        Ok(total)
    }

    /// Returns a stream of incoming packets.
    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>>;

    /// Sets a BPF filter for packet capture.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter is invalid or cannot be applied.
    fn set_bpf(&self, filter: &BpfProg) -> Result<()>;

    /// Returns the local MAC address if available.
    #[must_use]
    fn local_mac(&self) -> Option<MacAddr>;

    /// Returns the interface index.
    #[must_use]
    fn if_index(&self) -> libc::c_uint;
}

/// Output sink trait for receiving scan results.
///
/// This trait abstracts the output layer, allowing results to be sent to
/// different destinations (console, file, database, etc.).
#[async_trait]
pub trait OutputSink: Send + Sync {
    /// Outputs a host result.
    ///
    /// # Errors
    ///
    /// Returns an error if the output cannot be written.
    async fn output_host(&self, result: &HostResult) -> Result<()>;

    /// Outputs a complete scan result.
    ///
    /// # Errors
    ///
    /// Returns an error if the output cannot be written.
    async fn output_scan_result(&self, result: &ScanResult) -> Result<()>;

    /// Flushes any buffered output.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush operation fails.
    async fn flush(&self) -> Result<()>;
}

/// Scan configuration.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "ScanConfig mirrors Nmap's many boolean flags"
)]
pub struct ScanConfig {
    /// Timing template (T0-T5).
    pub timing_template: TimingTemplate,
    /// Scan types to perform.
    pub scan_types: Vec<ScanType>,
    /// Port specification.
    pub port_spec: PortSpec,
    /// Minimum parallel hosts.
    pub min_parallel_hosts: usize,
    /// Maximum parallel hosts.
    pub max_parallel_hosts: usize,
    /// Minimum parallel ports.
    pub min_parallel_ports: usize,
    /// Maximum parallel ports.
    pub max_parallel_ports: usize,
    /// Minimum rate in packets per second (optional).
    pub min_rate: Option<u64>,
    /// Maximum rate in packets per second (optional).
    pub max_rate: Option<u64>,
    /// Host group size for batch processing.
    pub host_group_size: usize,
    /// Enable host discovery.
    pub host_discovery: bool,
    /// Enable service detection.
    pub service_detection: bool,
    /// Enable OS detection.
    pub os_detection: bool,
    /// Enable traceroute.
    pub traceroute: bool,
    /// Enable NSE scripts.
    pub nse_scripts: bool,
    /// NSE script categories to run.
    pub nse_categories: Vec<String>,
    /// Host timeout.
    pub host_timeout: std::time::Duration,
    /// Scan delay between probes.
    pub scan_delay: std::time::Duration,
    /// Custom data payload to append to packets.
    pub data_payload: Option<Vec<u8>>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timing_template: TimingTemplate::Normal,
            scan_types: vec![ScanType::TcpSyn],
            port_spec: PortSpec::Top(1000),
            min_parallel_hosts: 1,
            max_parallel_hosts: 128,
            min_parallel_ports: 1,
            max_parallel_ports: 1024,
            min_rate: None,
            max_rate: None,
            host_group_size: 4,
            host_discovery: true,
            service_detection: false,
            os_detection: false,
            traceroute: false,
            nse_scripts: false,
            nse_categories: Vec::new(),
            host_timeout: std::time::Duration::from_secs(900),
            scan_delay: std::time::Duration::ZERO,
            data_payload: None,
        }
    }
}

/// Scan type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanType {
    /// TCP SYN scan (stealth).
    TcpSyn,
    /// TCP Connect scan.
    TcpConnect,
    /// TCP FIN scan.
    TcpFin,
    /// TCP NULL scan.
    TcpNull,
    /// TCP XMAS scan.
    TcpXmas,
    /// TCP ACK scan.
    TcpAck,
    /// TCP Window scan.
    TcpWindow,
    /// TCP Maimon scan.
    TcpMaimon,
    /// UDP scan.
    Udp,
    /// SCTP INIT scan.
    SctpInit,
    /// IP protocol scan.
    IpProtocol,
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpSyn => write!(f, "SYN"),
            Self::TcpConnect => write!(f, "Connect"),
            Self::TcpFin => write!(f, "FIN"),
            Self::TcpNull => write!(f, "NULL"),
            Self::TcpXmas => write!(f, "XMAS"),
            Self::TcpAck => write!(f, "ACK"),
            Self::TcpWindow => write!(f, "Window"),
            Self::TcpMaimon => write!(f, "Maimon"),
            Self::Udp => write!(f, "UDP"),
            Self::SctpInit => write!(f, "SCTP INIT"),
            Self::IpProtocol => write!(f, "IP Protocol"),
        }
    }
}

/// Port specification for scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSpec {
    /// All 65535 ports.
    All,
    /// Top N most common ports.
    Top(usize),
    /// Specific list of ports.
    List(Vec<Port>),
    /// Port range.
    Range {
        /// Start port (inclusive).
        start: Port,
        /// End port (inclusive).
        end: Port,
    },
}

impl Default for PortSpec {
    fn default() -> Self {
        Self::Top(1000)
    }
}

/// Scan statistics tracked during execution.
#[derive(Debug)]
pub struct ScanStats {
    /// Hosts completed.
    hosts_completed: AtomicUsize,
    /// Open ports discovered.
    open_ports: AtomicUsize,
    /// Packets sent.
    packets_sent: AtomicU64,
    /// Packets received.
    packets_received: AtomicU64,
    /// Start time of the scan.
    start_time: std::time::Instant,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            hosts_completed: AtomicUsize::new(0),
            open_ports: AtomicUsize::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }
}

impl ScanStats {
    /// Creates new scan statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a host was completed.
    pub fn mark_host_complete(&self) {
        self.hosts_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that an open port was found.
    pub fn record_open_port(&self) {
        self.open_ports.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a packet was sent.
    pub fn record_packet_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a packet was received.
    pub fn record_packet_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of hosts completed.
    #[must_use]
    pub fn hosts_completed(&self) -> usize {
        self.hosts_completed.load(Ordering::Relaxed)
    }

    /// Returns the number of open ports discovered.
    #[must_use]
    pub fn open_ports(&self) -> usize {
        self.open_ports.load(Ordering::Relaxed)
    }

    /// Returns the number of packets sent.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Returns the number of packets received.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Returns the elapsed time since scan start.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Returns the current packets per second rate.
    #[must_use]
    pub fn pps(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            #[allow(
                clippy::cast_precision_loss,
                reason = "PPS calculation allows minor precision loss"
            )]
            {
                self.packets_sent() as f64 / elapsed
            }
        } else {
            0.0
        }
    }
}

/// Target set for scanning.
#[derive(Debug, Clone)]
pub struct TargetSet {
    /// Targets to scan.
    targets: Vec<Target>,
    /// Current index for iteration.
    current: Arc<std::sync::atomic::AtomicUsize>,
}

impl TargetSet {
    /// Creates a new target set from a target group.
    #[must_use]
    pub fn from_group(group: TargetGroup) -> Self {
        Self {
            targets: group.targets,
            current: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Creates a new target set from a list of targets.
    #[must_use]
    pub fn from_targets(targets: Vec<Target>) -> Self {
        Self {
            targets,
            current: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Returns the number of targets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Returns true if the target set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Returns the next target for processing.
    #[must_use]
    pub fn next_target(&self) -> Option<&Target> {
        let idx = self.current.fetch_add(1, Ordering::Relaxed);
        self.targets.get(idx)
    }

    /// Returns all targets.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }
}

impl Default for TargetSet {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            current: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Scan session context (core abstraction).
///
/// This struct holds all the state and dependencies needed for scanning.
/// It follows the dependency injection pattern for testability.
pub struct ScanSession {
    /// Scan configuration.
    pub config: ScanConfig,
    /// Target set (thread-safe).
    pub target_set: Arc<TargetSet>,
    /// Packet engine (trait object for dependency injection).
    pub packet_engine: Arc<dyn PacketEngine>,
    /// Output sink (trait object).
    pub output_sink: Arc<dyn OutputSink>,
    /// Fingerprint database (thread-safe).
    pub fingerprint_db: Arc<FingerprintDatabase>,
    /// NSE script registry (thread-safe).
    pub nse_registry: Arc<NseRegistry>,
    /// Scan statistics (thread-safe).
    pub stats: Arc<ScanStats>,
    /// Resume store for session recovery (optional).
    pub resume_store: Option<Arc<ResumeStore>>,
}

impl fmt::Debug for ScanSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanSession")
            .field("config", &self.config)
            .field("target_set", &self.target_set)
            .field("stats", &self.stats)
            .field("resume_store", &self.resume_store.is_some())
            .finish_non_exhaustive()
    }
}

/// Fingerprint database handle.
#[derive(Debug)]
pub struct FingerprintDatabase {
    /// Service probe database.
    service_db: Option<rustnmap_fingerprint::ProbeDatabase>,
    /// OS fingerprint database.
    os_db: Option<rustnmap_fingerprint::FingerprintDatabase>,
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintDatabase {
    /// Creates a new empty fingerprint database.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            service_db: None,
            os_db: None,
        }
    }

    /// Creates a test fingerprint database with simulated loaded state.
    #[must_use]
    pub fn test_instance() -> Self {
        Self {
            service_db: Some(rustnmap_fingerprint::ProbeDatabase::empty()),
            os_db: Some(rustnmap_fingerprint::FingerprintDatabase::empty()),
        }
    }

    /// Returns true if the service database is loaded.
    #[must_use]
    pub fn is_service_db_loaded(&self) -> bool {
        self.service_db.is_some()
    }

    /// Returns true if the OS database is loaded.
    #[must_use]
    pub fn is_os_db_loaded(&self) -> bool {
        self.os_db.is_some()
    }

    /// Returns a reference to the service probe database.
    #[must_use]
    pub const fn service_db(&self) -> Option<&rustnmap_fingerprint::ProbeDatabase> {
        self.service_db.as_ref()
    }

    /// Returns a reference to the OS fingerprint database.
    #[must_use]
    pub const fn os_db(&self) -> Option<&rustnmap_fingerprint::FingerprintDatabase> {
        self.os_db.as_ref()
    }

    /// Sets the service probe database.
    pub fn set_service_db(&mut self, db: rustnmap_fingerprint::ProbeDatabase) {
        self.service_db = Some(db);
    }

    /// Sets the OS fingerprint database.
    pub fn set_os_db(&mut self, db: rustnmap_fingerprint::FingerprintDatabase) {
        self.os_db = Some(db);
    }

    /// Loads service probe database from file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database file cannot be loaded.
    pub async fn load_service_db(&mut self, path: impl AsRef<std::path::Path>) -> crate::error::Result<()> {
        match rustnmap_fingerprint::ProbeDatabase::load_from_nmap_db(path).await {
            Ok(db) => {
                self.service_db = Some(db);
                Ok(())
            }
            Err(e) => Err(crate::error::CoreError::fingerprint(format!("Failed to load service DB: {e}"))),
        }
    }

    /// Loads OS fingerprint database from file.
    ///
    /// # Errors
    ///
    /// Returns an error if the database file cannot be loaded.
    pub async fn load_os_db(&mut self, path: impl AsRef<std::path::Path>) -> crate::error::Result<()> {
        match rustnmap_fingerprint::FingerprintDatabase::load_from_nmap_db(path).await {
            Ok(db) => {
                self.os_db = Some(db);
                Ok(())
            }
            Err(e) => Err(crate::error::CoreError::fingerprint(format!("Failed to load OS DB: {e}"))),
        }
    }
}

/// NSE script registry.
#[derive(Debug)]
pub struct NseRegistry {
    /// Script database.
    script_db: rustnmap_nse::ScriptDatabase,
}

impl Default for NseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NseRegistry {
    /// Creates a new empty script registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            script_db: rustnmap_nse::ScriptDatabase::new(),
        }
    }

    /// Creates an empty registry for testing.
    #[must_use]
    pub fn empty() -> Self {
        Self::new()
    }

    /// Adds a script to the registry.
    pub fn add_script(&mut self, script: &rustnmap_nse::NseScript) {
        self.script_db.register_script(script);
    }

    /// Returns the number of scripts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.script_db.len()
    }

    /// Returns true if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.script_db.is_empty()
    }

    /// Returns a reference to the script database.
    #[must_use]
    pub const fn script_db(&self) -> &rustnmap_nse::ScriptDatabase {
        &self.script_db
    }

    /// Creates a script engine from the registry's database.
    #[must_use]
    pub fn create_engine(&self) -> rustnmap_nse::ScriptEngine {
        // Since ScriptDatabase doesn't implement Clone, we create a new empty database
        // and re-register all scripts. This is a workaround until Clone is implemented.
        let mut new_db = rustnmap_nse::ScriptDatabase::new();

        // Get all scripts from the current database and re-register them
        for script in self.script_db.all_scripts() {
            new_db.register_script(script);
        }

        rustnmap_nse::ScriptEngine::new(new_db)
    }

    /// Loads scripts from a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read.
    pub fn load_from_directory(&mut self, path: impl AsRef<std::path::Path>) -> crate::error::Result<()> {
        match rustnmap_nse::ScriptDatabase::from_directory(path.as_ref()) {
            Ok(db) => {
                self.script_db = db;
                Ok(())
            }
            Err(e) => Err(crate::error::CoreError::nse(format!("Failed to load scripts: {e}"))),
        }
    }
}

/// Resume store for session recovery.
#[derive(Debug, Default)]
pub struct ResumeStore {
    /// Resume data file path.
    #[allow(dead_code)]
    path: std::path::PathBuf,
}

impl ResumeStore {
    /// Creates a new resume store at the given path.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// Default packet engine implementation using raw sockets.
#[derive(Debug)]
pub struct DefaultPacketEngine {
    /// Interface index.
    if_index: libc::c_uint,
    /// Local MAC address.
    local_mac: Option<MacAddr>,
    /// Packet sender channel.
    tx: broadcast::Sender<PacketBuffer>,
    /// Packet receiver channel.
    #[allow(dead_code)]
    rx: broadcast::Receiver<PacketBuffer>,
}

impl DefaultPacketEngine {
    /// Creates a new default packet engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new() -> Result<Self> {
        let (tx, rx) = broadcast::channel(1024);
        Ok(Self {
            if_index: 1,
            local_mac: None,
            tx,
            rx,
        })
    }
}

#[async_trait]
impl PacketEngine for DefaultPacketEngine {
    async fn send_packet(&self, pkt: PacketBuffer) -> Result<usize> {
        self.tx
            .send(pkt)
            .map_err(|_e| CoreError::scan("failed to send packet"))?;
        Ok(0)
    }

    fn recv_stream(&self) -> Pin<Box<dyn Stream<Item = PacketBuffer> + Send>> {
        let rx = self.tx.subscribe();
        Box::pin(PacketStream { rx })
    }

    fn set_bpf(&self, _filter: &BpfProg) -> Result<()> {
        // BPF filter setting will be implemented when raw socket support is complete
        Ok(())
    }

    fn local_mac(&self) -> Option<MacAddr> {
        self.local_mac
    }

    fn if_index(&self) -> libc::c_uint {
        self.if_index
    }
}

/// Packet stream for receiving packets.
struct PacketStream {
    /// Receiver channel.
    rx: broadcast::Receiver<PacketBuffer>,
}

impl Stream for PacketStream {
    type Item = PacketBuffer;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.try_recv() {
            Ok(item) => Poll::Ready(Some(item)),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                // Register waker and return pending
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_) => Poll::Pending,
        }
    }
}

/// Default output sink implementation.
#[derive(Debug)]
pub struct DefaultOutputSink;

impl DefaultOutputSink {
    /// Creates a new default output sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DefaultOutputSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutputSink for DefaultOutputSink {
    async fn output_host(&self, _result: &HostResult) -> Result<()> {
        // Console output implementation pending integration with output formatters
        Ok(())
    }

    async fn output_scan_result(&self, _result: &ScanResult) -> Result<()> {
        // Console output implementation pending integration with output formatters
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }
}

impl ScanSession {
    /// Creates a new scan session with the given configuration and targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet engine cannot be initialized.
    pub fn new(config: ScanConfig, targets: TargetGroup) -> Result<Self> {
        let target_set = Arc::new(TargetSet::from_group(targets));
        let packet_engine: Arc<dyn PacketEngine> = Arc::new(DefaultPacketEngine::new()?);
        let output_sink: Arc<dyn OutputSink> = Arc::new(DefaultOutputSink::new());
        let fingerprint_db = Arc::new(FingerprintDatabase::new());
        let nse_registry = Arc::new(NseRegistry::new());
        let stats = Arc::new(ScanStats::new());

        Ok(Self {
            config,
            target_set,
            packet_engine,
            output_sink,
            fingerprint_db,
            nse_registry,
            stats,
            resume_store: None,
        })
    }

    /// Creates a new scan session with custom dependencies.
    ///
    /// This is useful for testing with mock implementations.
    #[must_use]
    pub fn with_dependencies(
        config: ScanConfig,
        target_set: Arc<TargetSet>,
        packet_engine: Arc<dyn PacketEngine>,
        output_sink: Arc<dyn OutputSink>,
        fingerprint_db: Arc<FingerprintDatabase>,
        nse_registry: Arc<NseRegistry>,
    ) -> Self {
        let stats = Arc::new(ScanStats::new());
        Self {
            config,
            target_set,
            packet_engine,
            output_sink,
            fingerprint_db,
            nse_registry,
            stats,
            resume_store: None,
        }
    }

    /// Returns the number of targets in this session.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.target_set.len()
    }

    /// Returns the elapsed time since scan start.
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.stats.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_common::Ipv4Addr;

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.host_group_size, 4);
        assert!(config.host_discovery);
    }

    #[test]
    fn test_scan_type_display() {
        assert_eq!(ScanType::TcpSyn.to_string(), "SYN");
        assert_eq!(ScanType::Udp.to_string(), "UDP");
    }

    #[test]
    fn test_scan_stats() {
        let stats = ScanStats::new();
        stats.record_packet_sent();
        stats.record_packet_sent();
        stats.record_packet_received();
        stats.mark_host_complete();
        stats.record_open_port();

        assert_eq!(stats.packets_sent(), 2);
        assert_eq!(stats.packets_received(), 1);
        assert_eq!(stats.hosts_completed(), 1);
        assert_eq!(stats.open_ports(), 1);
    }

    #[test]
    fn test_target_set() {
        let targets = vec![
            Target::from(Ipv4Addr::new(192, 168, 1, 1)),
            Target::from(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let set = TargetSet::from_targets(targets);
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_target_set_iteration() {
        let targets = vec![
            Target::from(Ipv4Addr::new(192, 168, 1, 1)),
            Target::from(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let set = TargetSet::from_targets(targets);
        assert!(set.next_target().is_some());
        assert!(set.next_target().is_some());
        assert!(set.next_target().is_none());
    }

    #[test]
    fn test_fingerprint_database() {
        let db = FingerprintDatabase::new();
        assert!(!db.is_service_db_loaded());
        assert!(!db.is_os_db_loaded());

        let test_db = FingerprintDatabase::test_instance();
        assert!(test_db.is_service_db_loaded());
        assert!(test_db.is_os_db_loaded());
    }

    #[test]
    fn test_nse_registry() {
        use rustnmap_nse::NseScript;
        let mut registry = NseRegistry::new();
        assert!(registry.is_empty());
        let script = NseScript::new("test-script", std::path::PathBuf::from("/test.nse"), String::new());
        registry.add_script(&script);
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_packet_buffer() {
        let data = Bytes::from_static(b"test packet");
        let buffer = PacketBuffer::new(data, std::time::Duration::from_secs(0), 6);
        assert_eq!(buffer.len, 11);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.protocol, 6);
    }

    #[test]
    fn test_port_spec_default() {
        let spec = PortSpec::default();
        assert_eq!(spec, PortSpec::Top(1000));
    }
}
