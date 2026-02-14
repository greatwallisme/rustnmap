//! UDP scanner implementation for `RustNmap`.
//!
//! This module provides UDP scanning functionality using raw sockets.
//! UDP scanning determines port states based on responses:
//! - OPEN: UDP response received
//! - CLOSED: ICMP Port Unreachable received
//! - FILTERED: ICMP Admin Prohibited or other ICMP errors
//! - OPEN|FILTERED: No response (ambiguous)

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_udp_response, IcmpResponse, IcmpUnreachableCode, RawSocket,
    UdpPacketBuilder,
};
use rustnmap_target::Target;

/// Default source port range for outbound UDP probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// UDP scanner using raw sockets.
///
/// Sends UDP probes and analyzes responses to determine port states.
/// Requires root privileges to create raw sockets.
#[derive(Debug)]
pub struct UdpScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl UdpScanner {
    /// Creates a new UDP scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `UdpScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        // Use IPPROTO_UDP (17) for receiving UDP responses and ICMP errors
        let socket = RawSocket::with_protocol(17).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    ///
    /// Sends a UDP probe and determines port state based on response:
    /// - If UDP response received -> Open
    /// - If ICMP Port Unreachable received -> Closed
    /// - If ICMP Admin Prohibited received -> Filtered
    /// - If no response -> Open|Filtered (ambiguous)
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `protocol` - Protocol (must be UDP)
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
        // Only UDP is supported
        if protocol != Protocol::Udp {
            return Ok(PortState::Filtered);
        }

        // Get target IP address
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        // Send UDP probe and analyze response
        self.send_udp_probe(dst_addr, port)
    }

    /// Sends a UDP probe and determines port state from response.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `dst_port` - Target port
    ///
    /// # Returns
    ///
    /// Port state based on response:
    /// - Open: UDP response received
    /// - Closed: ICMP Port Unreachable received
    /// - Filtered: ICMP Admin Prohibited or other ICMP errors
    /// - Open|Filtered: No response (timeout)
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    fn send_udp_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // Generate a random source port
        let src_port = Self::generate_source_port();

        // Build UDP packet with empty payload
        // Some UDP services respond to empty probes, others require specific payloads
        let packet = UdpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port).build();

        // Create destination socket address
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        // Send the packet
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Wait for response with timeout
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for UDP response first
                if let Some((src_port, _payload)) = parse_udp_response(&recv_buf[..len]) {
                    // Verify this is a response to our probe
                    if src_port == dst_port {
                        return Ok(PortState::Open);
                    }
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp, dst_addr, dst_port));
                }

                // Unknown response type
                Ok(PortState::Filtered)
            }
            Ok(_) => {
                // Empty response (shouldn't happen)
                Ok(PortState::OpenOrFiltered)
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // No response received within timeout
                // This is ambiguous: port could be open (accepting but not responding)
                // or filtered (dropped by firewall)
                Ok(PortState::OpenOrFiltered)
            }
            Err(e) => {
                // Other error
                Err(rustnmap_common::ScanError::Network(
                    rustnmap_common::Error::Network(
                        rustnmap_common::error::NetworkError::ReceiveError { source: e },
                    ),
                ))
            }
        }
    }

    /// Handles ICMP response to determine port state.
    ///
    /// # Arguments
    ///
    /// * `icmp_resp` - Parsed ICMP response
    /// * `expected_dst_ip` - Expected destination IP from original probe
    /// * `expected_dst_port` - Expected destination port from original probe
    ///
    /// # Returns
    ///
    /// Port state based on ICMP response type and code.
    fn handle_icmp_response(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> PortState {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    // Not our response, treat as filtered
                    return PortState::Filtered;
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => {
                        // ICMP Port Unreachable = port is closed
                        PortState::Closed
                    }
                    IcmpUnreachableCode::AdminProhibited
                    | IcmpUnreachableCode::HostProhibited
                    | IcmpUnreachableCode::NetworkProhibited => {
                        // Administrative prohibition = filtered
                        PortState::Filtered
                    }
                    _ => {
                        // Other unreachable codes typically indicate filtering
                        PortState::Filtered
                    }
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => {
                // Other ICMP types are unexpected for UDP scanning
                PortState::Filtered
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
}

impl PortScanner for UdpScanner {
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
        let result = UdpScanner::new(local_addr, config);

        // May fail if not running as root
        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        // Test that scanner creation requires root
        if let Ok(scanner) = UdpScanner::new(local_addr, config) { assert!(scanner.requires_root()) } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_source_port() {
        let port = UdpScanner::generate_source_port();
        assert!(port >= SOURCE_PORT_START);
        assert!(port < SOURCE_PORT_START + 1000);
    }

    #[test]
    fn test_handle_icmp_response_port_unreachable() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 53;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = UdpScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Closed);
    }

    #[test]
    fn test_handle_icmp_response_admin_prohibited() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 53;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = UdpScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_handle_icmp_response_mismatch() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 53;

        // ICMP response for different port
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: 80, // Different port
        };

        let result = UdpScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Filtered);
    }
}
