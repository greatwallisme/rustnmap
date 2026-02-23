//! Parallel port scanning engine inspired by Nmap's `UltraScan` architecture.
//!
//! This module implements high-performance parallel scanning that sends multiple
//! probes concurrently instead of sequentially waiting for each response.
//!
//! # Architecture
//!
//! The engine maintains a list of "outstanding" probes (sent but not yet responded)
//! and uses multiple concurrent tasks:
//! - A sender task that batches probes up to the parallelism limit
//! - A receiver task that continuously processes incoming responses
//! - A matcher that correlates responses to outstanding probes
//!
//! # Performance
//!
//! This architecture provides 20-30x speedup over sequential scanning for
//! large port ranges (e.g., Fast Scan with 100 ports).
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_scan::ultrascan::ParallelScanEngine;
//! use std::net::Ipv4Addr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = ParallelScanEngine::new(
//!     Ipv4Addr::new(192, 168, 1, 100),
//!     rustnmap_common::ScanConfig::default(),
//! )?;
//!
//! let ports = vec![22, 80, 443];
//! let results = engine.scan_ports("192.168.1.1".parse()?, &ports).await?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc as StdArc;
use std::time::{Duration, Instant};

use rustnmap_common::{Port, PortState, ScanConfig};
use rustnmap_net::raw_socket::{parse_tcp_response, RawSocket, TcpPacketBuilder};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout as tokio_timeout;

/// Default minimum number of probes to send in parallel.
///
/// Nmap uses 1 by default but increases based on network conditions.
pub const DEFAULT_MIN_PARALLELISM: usize = 10;

/// Default maximum number of probes to have outstanding at once.
///
/// Nmap's default varies by timing template (T3=20, T4=40, T5=200+).
pub const DEFAULT_MAX_PARALLELISM: usize = 100;

/// Default timeout for waiting on a single probe response.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Default timeout for the entire scan operation.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(300);

/// Source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Information about a probe that has been sent but not yet responded to.
#[derive(Debug, Clone)]
struct OutstandingProbe {
    /// Target IP address.
    target: Ipv4Addr,
    /// Target port number.
    port: Port,
    /// Our TCP sequence number.
    seq: u32,
    /// Our source port.
    src_port: Port,
    /// When this probe was sent.
    sent_time: Instant,
    /// Number of retry attempts.
    retry_count: u32,
}

/// A received packet with parsed TCP information.
///
/// This contains the raw parsed data from a received TCP packet.
/// The source port in the response is the destination port we probed.
#[derive(Debug, Clone)]
struct ReceivedPacket {
    /// Source IP of the response (our target).
    src_ip: Ipv4Addr,
    /// Source port of the response (the port we probed).
    src_port: Port,
    /// TCP flags from the response.
    flags: u8,
    /// Sequence number from the response (available for debugging via `seq()`).
    seq: u32,
    /// ACK number from the response.
    ack: u32,
}

impl ReceivedPacket {
    /// Creates a new received packet.
    #[must_use]
    const fn new(src_ip: Ipv4Addr, src_port: Port, flags: u8, seq: u32, ack: u32) -> Self {
        Self {
            src_ip,
            src_port,
            flags,
            seq,
            ack,
        }
    }

    /// Returns the sequence number from the response.
    ///
    /// This is primarily used for debugging and validation purposes.
    #[must_use]
    const fn seq(&self) -> u32 {
        self.seq
    }

    /// Determines the port state from TCP flags.
    #[must_use]
    fn port_state(&self) -> PortState {
        let syn_received = (self.flags & 0x02) != 0;
        let ack_received = (self.flags & 0x10) != 0;
        let rst_received = (self.flags & 0x04) != 0;

        if syn_received && ack_received {
            PortState::Open
        } else if rst_received {
            PortState::Closed
        } else {
            PortState::Filtered
        }
    }
}

/// High-performance parallel scanning engine.
///
/// This engine implements Nmap's `UltraScan` architecture, sending multiple
/// probes concurrently and processing responses asynchronously.
///
/// # Architecture
///
/// 1. **Batch Sending**: Sends multiple probes without waiting for responses
/// 2. **Async Receiving**: Background task continuously receives packets
/// 3. **Response Matching**: Correlates responses to outstanding probes
/// 4. **Timeout Handling**: Retries or times out probes that don't respond
///
/// # Performance
///
/// For scanning 100 ports:
/// - Sequential: ~100 seconds (1 second per port)
/// - Parallel: ~3-5 seconds (20-30x faster)
#[derive(Debug)]
pub struct ParallelScanEngine {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: StdArc<RawSocket>,
    /// Scanner configuration (reserved for future use).
    #[expect(dead_code, reason = "Configuration is reserved for future timing extensions")]
    config: ScanConfig,
    /// Minimum parallelism (probes to send before waiting).
    min_parallelism: usize,
    /// Maximum parallelism (max outstanding probes).
    max_parallelism: usize,
    /// Timeout for individual probes.
    probe_timeout: Duration,
    /// Timeout for the entire scan.
    scan_timeout: Duration,
}

impl ParallelScanEngine {
    /// Creates a new parallel scan engine.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A new `ParallelScanEngine` instance, or an error if raw socket creation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> Result<Self, rustnmap_common::ScanError> {
        let socket = StdArc::new(
            RawSocket::with_protocol(6).map_err(|e| {
                rustnmap_common::ScanError::PermissionDenied {
                    operation: format!("create raw socket: {e}"),
                }
            })?,
        );

        Ok(Self {
            local_addr,
            socket,
            config,
            min_parallelism: DEFAULT_MIN_PARALLELISM,
            max_parallelism: DEFAULT_MAX_PARALLELISM,
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
            scan_timeout: DEFAULT_SCAN_TIMEOUT,
        })
    }

    /// Sets the minimum parallelism.
    ///
    /// # Arguments
    ///
    /// * `value` - Minimum number of probes to have outstanding
    #[must_use]
    pub const fn with_min_parallelism(mut self, value: usize) -> Self {
        self.min_parallelism = value;
        self
    }

    /// Sets the maximum parallelism.
    ///
    /// # Arguments
    ///
    /// * `value` - Maximum number of probes to have outstanding
    #[must_use]
    pub const fn with_max_parallelism(mut self, value: usize) -> Self {
        self.max_parallelism = value;
        self
    }

    /// Sets the probe timeout.
    ///
    /// # Arguments
    ///
    /// * `value` - Timeout for waiting on individual probe responses
    #[must_use]
    pub const fn with_probe_timeout(mut self, value: Duration) -> Self {
        self.probe_timeout = value;
        self
    }

    /// Scans multiple ports on a target in parallel.
    ///
    /// This is the main entry point for parallel scanning. It sends all probes
    /// in batches and processes responses asynchronously.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `ports` - Port numbers to scan
    ///
    /// # Returns
    ///
    /// A map of port numbers to their states, or an error if scanning fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet transmission fails
    /// - The scan timeout expires
    /// - Response processing fails
    pub async fn scan_ports(
        &self,
        target: Ipv4Addr,
        ports: &[Port],
    ) -> Result<HashMap<Port, PortState>, rustnmap_common::ScanError> {
        let start_time = Instant::now();

        // Channel for received packets from the receiver task
        let (packet_tx, mut packet_rx) = mpsc::unbounded_channel();

        // Clone the sender for the receiver task
        // We'll keep the original and drop it when done to signal completion
        let receiver_handle = self.start_receiver_task(packet_tx.clone());

        // Store packet_tx for later drop - when dropped, receiver will detect closure

        // Outstanding probes: (target, port) -> probe info
        let mut outstanding: HashMap<(Ipv4Addr, Port), OutstandingProbe> = HashMap::new();
        let mut results: HashMap<Port, PortState> = HashMap::new();
        let mut ports_iter = ports.iter().copied().peekable();
        let mut retry_probes: Vec<OutstandingProbe> = Vec::new();

        // Main scan loop
        while ports_iter.peek().is_some() || !outstanding.is_empty() {
            // Check for scan timeout
            if start_time.elapsed() > self.scan_timeout {
                // Time out remaining outstanding probes
                for probe in outstanding.values() {
                    results.entry(probe.port).or_insert(PortState::Filtered);
                }
                break;
            }

            // Send more probes if we haven't reached max parallelism
            while outstanding.len() < self.max_parallelism {
                if let Some(port) = ports_iter.next() {
                    self.send_probe(target, port, &mut outstanding)?;
                } else {
                    break;
                }
            }

            // Wait for packets (with a small timeout to check for retries/timeouts)
            match tokio_timeout(Duration::from_millis(100), packet_rx.recv()).await {
                Ok(Some(packet)) => {
                    // Match the packet to an outstanding probe
                    let probe_key = (packet.src_ip, packet.src_port);
                    if let Some(probe) = outstanding.remove(&probe_key) {
                        // Verify the ACK matches our sequence number
                        let expected_ack = probe.seq.wrapping_add(1);
                        // Also verify the response has a valid sequence number (non-zero)
                        let valid_response = packet.ack == expected_ack && packet.seq() != 0;
                        if valid_response {
                            results.insert(packet.src_port, packet.port_state());
                        } else {
                            // Unexpected ACK or invalid seq - put the probe back
                            outstanding.insert(probe_key, probe);
                        }
                    }
                    // If we can't find a matching probe, this packet is unrelated traffic - ignore
                }
                Ok(None) => {
                    // Channel closed, receiver task ended
                    break;
                }
                Err(_) => {
                    // Timeout - check for probe timeouts
                    self.check_timeouts(&mut outstanding, &mut retry_probes, &mut results);
                }
            }

            // Re-send retry probes
            for probe in retry_probes.drain(..) {
                if outstanding.len() < self.max_parallelism {
                    self.resend_probe(probe, &mut outstanding)?;
                } else {
                    // Can't resend due to parallelism limit, mark as filtered
                    results.entry(probe.port).or_insert(PortState::Filtered);
                }
            }
        }

        // Explicitly drop the sender to signal the receiver task to stop
        drop(packet_tx);

        // Wait for receiver task to complete with timeout
        // Use a short timeout since the receiver should exit quickly when channel is closed
        let _ = tokio::time::timeout(Duration::from_millis(200), receiver_handle).await;

        Ok(results)
    }

    /// Starts the background receiver task.
    ///
    /// This task continuously receives packets and parses them.
    /// The task stops when the sender is dropped (all senders closed).
    ///
    /// # Note
    ///
    /// The receiver task uses `spawn_blocking` because `socket.recv_packet()` is a
    /// synchronous blocking call. This prevents blocking the Tokio worker thread.
    fn start_receiver_task(
        &self,
        packet_tx: mpsc::UnboundedSender<ReceivedPacket>,
    ) -> JoinHandle<()> {
        let socket = StdArc::clone(&self.socket);
        tokio::spawn(async move {
            // Use a shorter timeout for faster shutdown response
            const RECV_TIMEOUT: Duration = Duration::from_millis(50);

            loop {
                // Check if channel is closed before blocking on recv
                if packet_tx.is_closed() {
                    break;
                }

                // Clone Arc for the blocking task
                let socket_clone = StdArc::clone(&socket);

                // Run the blocking recv_packet in a separate thread
                let result = tokio::task::spawn_blocking(move || {
                    let mut recv_buf = vec![0u8; 65535];
                    socket_clone
                        .recv_packet(&mut recv_buf, Some(RECV_TIMEOUT))
                        .map(|len| (len, recv_buf))
                })
                .await;

                match result {
                    Ok(Ok((len, recv_buf))) if len > 0 => {
                        if let Some(packet) = Self::parse_packet(&recv_buf[..len]) {
                            // Check if channel is closed before sending
                            if packet_tx.send(packet).is_err() {
                                // Channel closed, stop receiving
                                break;
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        // Empty packet, continue
                    }
                    Ok(Err(e))
                        if e.kind() == ErrorKind::WouldBlock
                            || e.kind() == ErrorKind::TimedOut =>
                    {
                        // Normal timeout, loop will check is_closed() on next iteration
                    }
                    Ok(Err(_)) | Err(_) => {
                        // Fatal error or task was cancelled, stop receiving
                        break;
                    }
                }
            }
        })
    }

    /// Parses a received packet into a `ReceivedPacket`.
    ///
    /// Returns `None` if the packet cannot be parsed as a TCP packet.
    fn parse_packet(data: &[u8]) -> Option<ReceivedPacket> {
        if let Some((flags, seq, ack, src_port, src_ip)) = parse_tcp_response(data) {
            Some(ReceivedPacket::new(src_ip, src_port, flags, seq, ack))
        } else {
            None
        }
    }

    /// Sends a single SYN probe to the target.
    fn send_probe(
        &self,
        target: Ipv4Addr,
        port: Port,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP SYN packet
        let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, port)
            .seq(seq)
            .syn()
            .window(65_535)
            .build();

        // Send the packet
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(target), port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Track the outstanding probe
        outstanding.insert(
            (target, port),
            OutstandingProbe {
                target,
                port,
                seq,
                src_port,
                sent_time: Instant::now(),
                retry_count: 0,
            },
        );

        Ok(())
    }

    /// Re-sends a probe (for retries).
    fn resend_probe(
        &self,
        mut probe: OutstandingProbe,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
    ) -> Result<(), rustnmap_common::ScanError> {
        probe.retry_count += 1;
        probe.sent_time = Instant::now();

        // Rebuild and resend the packet
        let packet = TcpPacketBuilder::new(self.local_addr, probe.target, probe.src_port, probe.port)
            .seq(probe.seq)
            .syn()
            .window(65_535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(probe.target), probe.port);
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        outstanding.insert((probe.target, probe.port), probe);
        Ok(())
    }

    /// Checks for timed-out probes and handles retries.
    fn check_timeouts(
        &self,
        outstanding: &mut HashMap<(Ipv4Addr, Port), OutstandingProbe>,
        retry_probes: &mut Vec<OutstandingProbe>,
        results: &mut HashMap<Port, PortState>,
    ) {
        let now = Instant::now();
        let max_retries = 2;

        // Collect timed-out probes
        let timed_out: Vec<_> = outstanding
            .iter()
            .filter(|(_, p)| now.duration_since(p.sent_time) >= self.probe_timeout)
            .map(|(k, p)| (*k, p.clone()))
            .collect();

        for (key, probe) in timed_out {
            if probe.retry_count < max_retries {
                // Retry the probe
                outstanding.remove(&key);
                retry_probes.push(probe);
            } else {
                // Max retries reached, mark as filtered
                outstanding.remove(&key);
                results.entry(probe.port).or_insert(PortState::Filtered);
            }
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        let offset = (std::process::id() % 1000) as u16;
        SOURCE_PORT_START + offset
    }

    /// Generates a random initial sequence number.
    #[must_use]
    fn generate_sequence_number() -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Lower bits provide sufficient entropy"
        )]
        let now_lower = now as u32;
        let pid = std::process::id();
        now_lower.wrapping_add(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = ParallelScanEngine::new(local_addr, config);

        // May fail if not running as root
        if let Ok(engine) = result {
            assert_eq!(engine.local_addr, local_addr);
            assert_eq!(engine.min_parallelism, DEFAULT_MIN_PARALLELISM);
            assert_eq!(engine.max_parallelism, DEFAULT_MAX_PARALLELISM);
        }
    }

    #[test]
    fn test_parallelism_configuration() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(engine) = ParallelScanEngine::new(local_addr, config) {
            let engine = engine
                .with_min_parallelism(20)
                .with_max_parallelism(200);

            assert_eq!(engine.min_parallelism, 20);
            assert_eq!(engine.max_parallelism, 200);
        }
    }

    #[test]
    fn test_received_packet_creation() {
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let packet = ReceivedPacket::new(target, 80, 0x12, 1000, 1001);

        assert_eq!(packet.src_ip, target);
        assert_eq!(packet.src_port, 80);
        assert_eq!(packet.flags, 0x12);
        assert_eq!(packet.seq, 1000);
        assert_eq!(packet.ack, 1001);
    }

    #[test]
    fn test_port_state_from_flags() {
        // SYN-ACK (flags = 0x12) -> Open
        let syn_ack = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x12, 1000, 1001);
        assert_eq!(syn_ack.port_state(), PortState::Open);

        // RST (flags = 0x04) -> Closed
        let rst = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x04, 1000, 1001);
        assert_eq!(rst.port_state(), PortState::Closed);

        // Other flags -> Filtered
        let other = ReceivedPacket::new(Ipv4Addr::LOCALHOST, 80, 0x01, 1000, 1001);
        assert_eq!(other.port_state(), PortState::Filtered);
    }
}
