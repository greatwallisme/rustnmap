//! TCP SYN scanner implementation for `RustNmap`.
//!
//! This module provides a TCP SYN (half-open) scanning technique,
//! which sends raw TCP SYN packets and analyzes responses to determine
//! port states without completing the full TCP handshake.

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;

use crate::scanner::{PortScanner, ScanConfig, ScanResult};
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
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
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
        let socket = RawSocket::new()
            .map_err(|e| crate::scanner::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            })?;

        Ok(Self {
            local_addr,
            socket,
            config,
        })
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
    fn scan_port_impl(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
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

        // Build TCP SYN packet
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .syn()
            .window(65535)
            .build();

        // Create destination socket address
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        // Send the packet
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| crate::scanner::ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::SendError { source: e }
            )))?;

        // Wait for response with timeout
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self.socket.recv_packet(recv_buf.as_mut_slice(), Some(timeout)) {
            Ok(len) if len > 0 => {
                // Parse the response
                if let Some((flags, _seq, ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    // Verify this is a response to our probe
                    if src_port != dst_port {
                        // Response from wrong port, treat as filtered
                        return Ok(PortState::Filtered);
                    }

                    // Check if ACK matches our sequence number + 1
                    let expected_ack = seq.wrapping_add(1);
                    if ack != expected_ack {
                        // Unexpected ACK, might be a spoofed packet
                        return Ok(PortState::Filtered);
                    }

                    // Analyze flags
                    let syn_received = (flags & 0x02) != 0;
                    let ack_received = (flags & 0x10) != 0;
                    let rst_received = (flags & 0x04) != 0;

                    if syn_received && ack_received {
                        // SYN-ACK received - port is open
                        Ok(PortState::Open)
                    } else if rst_received {
                        // RST received - port is closed
                        Ok(PortState::Closed)
                    } else {
                        // Unexpected flags
                        Ok(PortState::Filtered)
                    }
                } else {
                    // Could not parse TCP response
                    Ok(PortState::Filtered)
                }
            }
            Ok(_) => {
                // Empty response (shouldn't happen)
                Ok(PortState::Filtered)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // No response received within timeout - port is filtered or host is down
                Ok(PortState::Filtered)
            }
            Err(e) => {
                // Other error
                Err(crate::scanner::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e }
                )))
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
        #[expect(clippy::cast_possible_truncation, reason = "Lower bits provide sufficient entropy")]
        let now_lower = now as u32;
        let pid = std::process::id();
        now_lower.wrapping_add(pid)
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

    #[test]
    fn test_requires_root() {
        let local_addr = Ipv4Addr::new(127, 0, 0, 1);
        let config = ScanConfig::default();

        // Test that scanner creation requires root
        match TcpSynScanner::new(local_addr, config) {
            Ok(scanner) => assert!(scanner.requires_root()),
            Err(_) => {
                // Expected if not running as root
            }
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
        let diff = if seq1 > seq2 {
            seq1 - seq2
        } else {
            seq2 - seq1
        };
        assert!(diff < 1_000_000, "Sequence numbers should be close in value");
    }
}
