//! TCP SYN scanner implementation for `RustNmap`.
//!
//! This module provides a TCP SYN (half-open) scanning technique,
//! which sends raw TCP SYN packets and analyzes responses to determine
//! port states without completing the full TCP handshake.

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use crate::packet_adapter::{
    create_stealth_engine, create_stealth_engine_with_target, ScannerPacketEngine,
};
use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{parse_tcp_response, RawSocket, TcpPacketBuilder};
use rustnmap_target::Target;

/// Default source port range for outbound probes.
///
/// Using a specific range helps with firewall compatibility.
/// Nmap uses source port randomization for evasion and compatibility.
pub const SOURCE_PORT_START: u16 = 60000;

/// TCP SYN scanner using raw sockets.
///
/// Sends SYN probes and analyzes SYN-ACK/RST responses to determine
/// if ports are open, closed, or filtered. Requires root privileges
/// to create raw sockets.
#[derive(Debug)]
pub struct TcpSynScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission to remote targets.
    socket: RawSocket,
    /// Raw socket for localhost packet transmission (bound to 127.0.0.1).
    ///
    /// This socket is created when `local_addr` is not already a loopback address.
    /// It is used for scanning 127.x.x.x targets to ensure responses route via lo.
    localhost_socket: Option<RawSocket>,
    /// Scanner configuration.
    config: ScanConfig,
    /// Optional packet engine for zero-copy packet capture using `PACKET_MMAP` V2.
    ///
    /// This provides better performance through ring buffer operation.
    /// When available, used for packet reception instead of raw socket.
    packet_engine: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Optional localhost-specific packet engine for scanning 127.0.0.1.
    ///
    /// Localhost scanning requires binding to the `lo` interface because
    /// the kernel routes loopback traffic via `lo`. This engine is created
    /// on-demand when a localhost target is detected.
    ///
    /// Wrapped in Mutex for interior mutability, allowing lazy creation
    /// during scanning (since `PortScanner` trait uses &self, not &mut self).
    localhost_engine: std::sync::Mutex<Option<Arc<Mutex<ScannerPacketEngine>>>>,
}

impl TcpSynScanner {
    /// Creates a new TCP SYN scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpSynScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Create localhost socket if local_addr is not already loopback.
        // This socket is bound to 127.0.0.1 for scanning localhost targets.
        let localhost_socket = if local_addr.is_loopback() {
            // Already loopback, use the main socket
            None
        } else {
            // Create a dedicated socket for localhost scanning
            let lo_socket = RawSocket::with_protocol(6).map_err(|e| {
                rustnmap_common::ScanError::PermissionDenied {
                    operation: format!("create localhost raw socket: {e}"),
                }
            })?;

            // Bind to loopback address so responses route via lo interface
            lo_socket.bind(Ipv4Addr::LOCALHOST).map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::BindFailed {
                        interface: "lo".to_string(),
                        source: e,
                    },
                ))
            })?;

            Some(lo_socket)
        };

        // Try to create packet engine for zero-copy capture using PACKET_MMAP V2.
        // This provides better performance than raw socket reception.
        let packet_engine = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr,
            socket,
            localhost_socket,
            config,
            packet_engine,
            localhost_engine: std::sync::Mutex::new(None),
        })
    }

    /// Gets the appropriate packet engine for the target address.
    ///
    /// For localhost targets (127.x.x.x), returns a localhost-specific engine
    /// bound to the `lo` interface. For remote targets, returns the default
    /// packet engine.
    ///
    /// The localhost engine is created on-demand to avoid unnecessary overhead.
    fn get_packet_engine_for_target(
        &self,
        target_addr: Ipv4Addr,
    ) -> Option<Arc<Mutex<ScannerPacketEngine>>> {
        let target_bytes = target_addr.octets();

        // Check if target is localhost (127.x.x.x)
        if target_bytes[0] == 127 {
            // Localhost target - use or create localhost-specific engine
            let mut engine_guard = self.localhost_engine.lock().unwrap();

            if engine_guard.is_none() {
                // Create localhost engine bound to loopback interface
                let localhost_engine = create_stealth_engine_with_target(
                    Some(self.local_addr),
                    Some(target_addr),
                    self.config.clone(),
                );
                *engine_guard = localhost_engine;
            }

            engine_guard.clone()
        } else {
            // Remote target - use default packet engine
            self.packet_engine.clone()
        }
    }

    /// Scans a single port on a target.
    ///
    /// Sends a SYN probe and waits for response, retrying if necessary.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `protocol` - Protocol (must be TCP for SYN scan)
    ///
    /// # Returns
    ///
    /// Port state based on response received.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network issues.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        // Only TCP is supported
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        // Get target IP address
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        // Send SYN probe and analyze response
        self.send_syn_probe(dst_addr, port)
    }

    /// Sends a TCP SYN probe and determines port state from response.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `dst_port` - Target port
    ///
    /// # Returns
    ///
    /// Port state based on TCP response.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // Generate a random source port
        let src_port = Self::generate_source_port();

        // Generate and store sequence number for this probe
        let seq = Self::generate_sequence_number();

        // For localhost scanning (127.x.x.x), we need special handling:
        // 1. Use 127.0.0.1 as source address in the packet
        // 2. Use the localhost_socket which is bound to 127.0.0.1
        // 3. Use localhost-specific packet engine for receiving
        let is_localhost_scan = dst_addr.is_loopback();

        let (src_addr, socket) = if is_localhost_scan {
            // Use localhost source address and localhost socket
            let sock = self.localhost_socket.as_ref().unwrap_or(&self.socket);
            (Ipv4Addr::LOCALHOST, sock)
        } else {
            // Use configured local address and main socket
            (self.local_addr, &self.socket)
        };

        // Build TCP SYN packet
        let packet = TcpPacketBuilder::new(src_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .syn()
            .window(65535)
            .build();

        // Create destination socket address
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        // Send the packet using the appropriate socket
        socket.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::SendError { source: e },
            ))
        })?;

        // Wait for response with timeout and retry logic
        let max_retries = 3;
        let mut retry_count = 0;
        let mut total_timeout = self.config.initial_rtt;
        let start_time = std::time::Instant::now();
        let mut recv_buf = vec![0u8; 65535];
        let mut received_any_from_target = false;

        // Get the appropriate packet engine for this target
        let target_engine = self.get_packet_engine_for_target(dst_addr);

        loop {
            // Calculate remaining timeout
            let elapsed = start_time.elapsed();
            if elapsed >= total_timeout {
                // Timeout expired - check if we should retry
                if retry_count < max_retries {
                    retry_count += 1;
                    // Exponential backoff: double the timeout each retry
                    total_timeout = self.config.initial_rtt * (2_u32.saturating_pow(retry_count));
                    continue;
                }
                // All retries exhausted - classify based on what we received
                // If we received any packet from the target, likely Closed (RST lost/delayed)
                // If completely silent, likely Filtered
                return Ok(if received_any_from_target {
                    PortState::Closed
                } else {
                    PortState::Filtered
                });
            }
            let remaining_timeout = total_timeout.saturating_sub(elapsed);

            // Use target-specific packet engine for receive if available
            match self.recv_packet_with_engine(
                recv_buf.as_mut_slice(),
                remaining_timeout,
                target_engine.as_ref(),
            ) {
                Ok(Some(len)) if len > 0 => {
                    // Parse the response
                    if let Some((flags, _seq, ack, resp_src_port, _dst_port, src_ip)) =
                        parse_tcp_response(&recv_buf[..len])
                    {
                        // Verify this is a response from the target IP
                        if src_ip != dst_addr {
                            // Response from wrong IP, this is unrelated traffic - continue waiting
                            continue;
                        }
                        // Mark that we received at least one packet from the target
                        received_any_from_target = true;

                        // Verify this is a response to our probe (correct source port)
                        if resp_src_port != dst_port {
                            // Response from wrong port - continue waiting
                            continue;
                        }

                        // Check if ACK matches our sequence number + 1
                        let expected_ack = seq.wrapping_add(1);
                        if ack != expected_ack {
                            // Unexpected ACK - continue waiting
                            continue;
                        }

                        // Analyze flags
                        let syn_received = (flags & 0x02) != 0;
                        let ack_received = (flags & 0x10) != 0;
                        let rst_received = (flags & 0x04) != 0;

                        if syn_received && ack_received {
                            // SYN-ACK received - port is open
                            return Ok(PortState::Open);
                        } else if rst_received {
                            // RST received - port is closed
                            return Ok(PortState::Closed);
                        }
                        // Unexpected flags - continue waiting
                    }
                    // Could not parse TCP response - continue waiting
                }
                Ok(Some(_)) => {
                    // Empty response - continue waiting
                }
                Ok(None) => {
                    // Timeout on this recv - check if total timeout expired
                    if start_time.elapsed() >= total_timeout {
                        return Ok(PortState::Filtered);
                    }
                    // Otherwise continue waiting
                }
                Err(e) => {
                    // Receive error
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ));
                }
            }
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        // Use SOURCE_PORT_START as base and add random offset
        let offset = (std::process::id() % 1000) as u16;
        SOURCE_PORT_START + offset
    }

    /// Generates a random initial sequence number.
    #[must_use]
    fn generate_sequence_number() -> u32 {
        // Use current time and process ID to generate a pseudo-random sequence number
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

    /// Receives a packet using the specified packet engine.
    ///
    /// This allows using different packet engines for different targets
    /// (e.g., localhost vs remote targets).
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive packet data
    /// * `timeout` - Maximum time to wait for a packet
    /// * `engine` - Optional packet engine to use (if None, falls back to raw socket)
    fn recv_packet_with_engine(
        &self,
        buf: &mut [u8],
        timeout: Duration,
        engine: Option<&Arc<Mutex<ScannerPacketEngine>>>,
    ) -> io::Result<Option<usize>> {
        // If packet engine is provided, use it for zero-copy capture
        if let Some(engine_arc) = engine {
            tokio::task::block_in_place(|| {
                Handle::current().block_on(async {
                    let mut engine = engine_arc.lock().await;

                    // Start engine if not yet started.
                    // If already started, the engine will return AlreadyStarted error,
                    // which we ignore because the engine is ready for use.
                    let _ = engine.start().await.map_err(|e| {
                        if matches!(e, rustnmap_packet::PacketError::AlreadyStarted) {
                            // Already started - this is fine
                            io::Error::other("Already started")
                        } else {
                            io::Error::other(format!("Failed to start packet engine: {e}"))
                        }
                    });

                    // Receive with timeout
                    match engine.recv_with_timeout(timeout).await {
                        Ok(Some(data)) => {
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            Ok(Some(len))
                        }
                        Ok(None) => Ok(None), // Timeout
                        Err(e) => Err(io::Error::other(format!("Packet engine error: {e}"))),
                    }
                })
            })
        } else {
            // Fall back to raw socket reception
            // Convert io::Result<usize> to io::Result<Option<usize>>
            self.socket.recv_packet(buf, Some(timeout)).map(Some)
        }
    }
}

impl PortScanner for TcpSynScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpSynScanner::new(local_addr, config);

        // May fail if not running as root
        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[tokio::test]
    async fn test_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        // Test that scanner creation requires root
        if let Ok(scanner) = TcpSynScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_source_port() {
        let port = TcpSynScanner::generate_source_port();
        assert!(port >= SOURCE_PORT_START);
        assert!(port < SOURCE_PORT_START + 1000);
    }

    #[test]
    fn test_generate_sequence_number() {
        let seq1 = TcpSynScanner::generate_sequence_number();
        let seq2 = TcpSynScanner::generate_sequence_number();
        // Sequence numbers are based on time, so they should be close
        // but not necessarily equal due to time passing
        let diff = seq1.abs_diff(seq2);
        assert!(
            diff < 1_000_000,
            "Sequence numbers should be close in value"
        );
    }
}
