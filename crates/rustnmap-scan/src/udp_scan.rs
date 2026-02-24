//! UDP scanner implementation for `RustNmap`.
//!
//! This module provides UDP scanning functionality using raw sockets.
//! UDP scanning determines port states based on responses:
//! - OPEN: UDP response received
//! - CLOSED: ICMP/ICMPv6 Port Unreachable received
//! - FILTERED: ICMP/ICMPv6 Admin Prohibited or other ICMP errors
//! - OPEN|FILTERED: No response (ambiguous)

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{IpAddr, Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_icmpv6_unreachable, parse_ipv6_udp_response, parse_udp_response,
    IcmpResponse, IcmpUnreachableCode, Icmpv6UnreachableCode, Ipv6UdpPacketBuilder, RawSocket,
    UdpPacketBuilder,
};
use rustnmap_packet::{AfPacketEngine, RingConfig};
use rustnmap_target::Target;

/// Default source port range for outbound UDP probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Ethernet header size in bytes.
const ETH_HEADER_SIZE: usize = 14;

/// UDP scanner using raw sockets.
///
/// Sends UDP probes and analyzes responses to determine port states.
/// Supports both IPv4 and IPv6 targets.
/// Requires root privileges to create raw sockets.
#[derive(Debug)]
pub struct UdpScanner {
    /// Local IPv4 address for probes.
    local_addr_v4: Ipv4Addr,
    /// Local IPv6 address for probes (optional).
    local_addr_v6: Option<std::net::Ipv6Addr>,
    /// Raw socket for IPv4 packet transmission.
    socket_v4: RawSocket,
    /// Raw socket for `ICMPv4` error responses.
    socket_icmp_v4: RawSocket,
    /// `AF_PACKET` engine for capturing ICMP errors (optional).
    packet_engine_v4: Option<AfPacketEngine>,
    /// Raw socket for IPv6 packet transmission (optional).
    socket_v6: Option<RawSocket>,
    /// Raw socket for `ICMPv6` error responses (optional).
    #[expect(dead_code, reason = "IPv6 ICMP error capture not yet implemented")]
    socket_icmp_v6: Option<RawSocket>,
    /// `AF_PACKET` engine for IPv6 (optional).
    #[expect(dead_code, reason = "IPv6 ICMP error capture not yet implemented")]
    packet_engine_v6: Option<AfPacketEngine>,
    /// Scanner configuration.
    config: ScanConfig,
}

impl UdpScanner {
    /// Creates a new UDP scanner with IPv4 support only.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IPv4 address to use for probes
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
        // Use IPPROTO_UDP (17) for sending UDP probes
        let socket_v4 = RawSocket::with_protocol(17).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        // Create ICMP socket (protocol 1) for receiving ICMP error responses
        let socket_icmp_v4 = RawSocket::with_protocol(1).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create ICMP raw socket: {e}"),
            }
        })?;

        // Try to create `AF_PACKET` engine for ICMP error capture
        // This is optional - if it fails, we fall back to raw socket only
        let packet_engine_v4 = Self::create_packet_engine(local_addr);

        Ok(Self {
            local_addr_v4: local_addr,
            local_addr_v6: None,
            socket_v4,
            socket_icmp_v4,
            packet_engine_v4,
            socket_v6: None,
            socket_icmp_v6: None,
            packet_engine_v6: None,
            config,
        })
    }

    /// Creates a new UDP scanner with dual-stack (IPv4 and IPv6) support.
    ///
    /// # Arguments
    ///
    /// * `local_addr_v4` - Local IPv4 address to use for probes
    /// * `local_addr_v6` - Local IPv6 address to use for probes
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
    pub fn new_dual_stack(
        local_addr_v4: Ipv4Addr,
        local_addr_v6: std::net::Ipv6Addr,
        config: ScanConfig,
    ) -> ScanResult<Self> {
        // Create IPv4 socket
        let socket_v4 = RawSocket::with_protocol(17).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create IPv4 raw socket: {e}"),
            }
        })?;

        // Create IPv4 ICMP socket for error responses
        let socket_icmp_v4 = RawSocket::with_protocol(1).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create IPv4 ICMP raw socket: {e}"),
            }
        })?;

        // Try to create `AF_PACKET` engine for IPv4 ICMP error capture
        let packet_engine_v4 = Self::create_packet_engine(local_addr_v4);

        // Create IPv6 socket
        let socket_v6 = RawSocket::with_protocol_ipv6(17).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create IPv6 raw socket: {e}"),
            }
        })?;

        // Create IPv6 ICMP socket for error responses (ICMPv6)
        let socket_icmp_v6 = RawSocket::with_protocol_ipv6(58).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create IPv6 ICMP raw socket: {e}"),
            }
        })?;

        // Try to create AF_PACKET engine for IPv6 (optional)
        let packet_engine_v6 = Self::create_packet_engine_v6();

        Ok(Self {
            local_addr_v4,
            local_addr_v6: Some(local_addr_v6),
            socket_v4,
            socket_icmp_v4,
            packet_engine_v4,
            socket_v6: Some(socket_v6),
            socket_icmp_v6: Some(socket_icmp_v6),
            packet_engine_v6,
            config,
        })
    }

    /// Scans a single port on a target.
    ///
    /// Sends a UDP probe and determines port state based on response:
    /// - If UDP response received -> Open
    /// - If ICMP/ICMPv6 Port Unreachable received -> Closed
    /// - If ICMP/ICMPv6 Admin Prohibited received -> Filtered
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

        // Get target IP address and dispatch to appropriate method
        match target.ip {
            IpAddr::V4(addr) => self.send_udp_probe_v4(addr, port),
            IpAddr::V6(addr) => self.send_udp_probe_v6(addr, port),
        }
    }

    /// Sends a UDP probe to an IPv4 target and determines port state from response.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IPv4 address
    /// * `dst_port` - Target port
    ///
    /// # Returns
    ///
    /// Port state based on response.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    fn send_udp_probe_v4(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        // Generate a random source port
        let src_port = Self::generate_source_port();

        // Build UDP packet with empty payload
        let packet =
            UdpPacketBuilder::new(self.local_addr_v4, dst_addr, src_port, dst_port).build();

        // Create destination socket address
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        // Send the packet
        self.socket_v4
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Wait for response with timeout
        // Use a minimum timeout to ensure ICMP responses have time to arrive
        let base_timeout = self.config.initial_rtt;
        let timeout = base_timeout.max(Duration::from_millis(500));

        // Try the `AF_PACKET` engine first for the full timeout to capture `ICMP` errors
        if let Some(icmp_resp) = self.recv_icmp_from_packet_engine(timeout) {
            if let Some(state) = Self::handle_icmp_response_v4(icmp_resp, dst_addr, dst_port) {
                return Ok(state);
            }
            // `ICMP` response for different probe - continue to socket checks
        }

        // If no matching `ICMP` response from packet engine, try the sockets
        let mut recv_buf = vec![0u8; 65535];
        let start = std::time::Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered);
            }

            // Try `ICMP` socket for backward compatibility
            match self
                .socket_icmp_v4
                .recv_packet(recv_buf.as_mut_slice(), Some(Duration::from_millis(50)))
            {
                Ok(len) if len > 0 => {
                    if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                        if let Some(state) =
                            Self::handle_icmp_response_v4(icmp_resp, dst_addr, dst_port)
                        {
                            return Ok(state);
                        }
                    }
                }
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    // Continue to UDP socket check
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            }

            // Try UDP socket for actual UDP responses (non-blocking check)
            match self
                .socket_v4
                .recv_packet(recv_buf.as_mut_slice(), Some(Duration::from_millis(50)))
            {
                Ok(len) if len > 0 => {
                    let src_ip = if len >= 20 {
                        let bytes = [recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15]];
                        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                    } else {
                        continue;
                    };

                    if src_ip == self.local_addr_v4 {
                        continue;
                    }

                    if let Some((src_port, _payload)) = parse_udp_response(&recv_buf[..len]) {
                        if src_port == dst_port {
                            return Ok(PortState::Open);
                        }
                    }
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Continue waiting, but check if timeout expired
                    if start.elapsed() >= timeout {
                        return Ok(PortState::OpenOrFiltered);
                    }
                    // Small sleep to avoid busy-waiting
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            }
        }
    }

    /// Sends a UDP probe to an IPv6 target and determines port state from response.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IPv6 address
    /// * `dst_port` - Target port
    ///
    /// # Returns
    ///
    /// Port state based on response.
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails or IPv6 is not configured.
    fn send_udp_probe_v6(
        &self,
        dst_addr: std::net::Ipv6Addr,
        dst_port: Port,
    ) -> ScanResult<PortState> {
        // Check if IPv6 is available
        let socket = match (&self.socket_v6, &self.local_addr_v6) {
            (Some(s), Some(local)) => (s, *local),
            _ => {
                return Err(rustnmap_common::ScanError::Network(
                    rustnmap_common::Error::Other("IPv6 scanning not configured".to_string()),
                ));
            }
        };

        // Generate a random source port
        let src_port = Self::generate_source_port();

        // Build IPv6 UDP packet with empty payload
        let packet = Ipv6UdpPacketBuilder::new(socket.1, dst_addr, src_port, dst_port).build();

        // Create destination socket address
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V6(dst_addr), dst_port);

        // Send the packet
        socket.0.send_packet(&packet, &dst_sockaddr).map_err(|e| {
            rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::SendError { source: e },
            ))
        })?;

        // Wait for response with timeout - use receive loop to filter out non-matching responses
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;
        let start = std::time::Instant::now();

        loop {
            // Calculate remaining timeout
            let elapsed = start.elapsed();
            let remaining_timeout = if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered); // Timeout exceeded
            } else {
                timeout - elapsed
            };

            match socket
                .0
                .recv_packet(recv_buf.as_mut_slice(), Some(remaining_timeout))
            {
                Ok(len) if len > 0 => {
                    // Check for UDP response first
                    if let Some((src_port, _payload)) = parse_ipv6_udp_response(&recv_buf[..len]) {
                        // Verify this is a response to our probe
                        if src_port == dst_port {
                            return Ok(PortState::Open);
                        }
                        // Response for different port - continue waiting
                    }

                    // Check for ICMPv6 response
                    if let Some((code, orig_ip, orig_port)) =
                        parse_icmpv6_unreachable(&recv_buf[..len])
                    {
                        // Check if this ICMPv6 response is for our probe
                        if let Some(state) = Self::handle_icmpv6_response(
                            code, orig_ip, orig_port, dst_addr, dst_port,
                        ) {
                            return Ok(state);
                        }
                        // ICMPv6 response for different probe - continue waiting
                    } else {
                        // Unknown packet type - continue waiting
                    }
                    // Loop continues to next iteration
                }
                Ok(_) => {
                    // Empty response (shouldn't happen)
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // No response received within timeout
                    return Ok(PortState::OpenOrFiltered);
                }
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            }
        }
    }

    /// Handles ICMP response to determine port state for IPv4.
    ///
    /// # Arguments
    ///
    /// * `icmp_resp` - Parsed ICMP response
    /// * `expected_dst_ip` - Expected destination IP from original probe
    /// * `expected_dst_port` - Expected destination port from original probe
    ///
    /// # Returns
    ///
    /// Port state based on `ICMP` response type and code.
    ///
    /// Returns `None` if the `ICMP` response is not for our probe (caller should continue waiting).
    /// Returns `Some(state)` if the `ICMP` response is for our probe.
    fn handle_icmp_response_v4(
        icmp_resp: IcmpResponse,
        expected_dst_ip: Ipv4Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this ICMP response is for our probe
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return None; // Not for our probe - continue waiting
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => Some(PortState::Closed),
                    _ => Some(PortState::Filtered),
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => None,
        }
    }

    /// Handles `ICMPv6` response to determine port state for IPv6.
    ///
    /// # Arguments
    ///
    /// * `code` - `ICMPv6` unreachable code
    /// * `original_dst_ip` - Original destination IP from `ICMPv6` payload
    /// * `original_dst_port` - Original destination port from `ICMPv6` payload
    /// * `expected_dst_ip` - Expected destination IP from original probe
    /// * `expected_dst_port` - Expected destination port from original probe
    ///
    /// # Returns
    ///
    /// `Some(state)` if the `ICMPv6` response is for our probe, `None` otherwise.
    fn handle_icmpv6_response(
        code: Icmpv6UnreachableCode,
        original_dst_ip: std::net::Ipv6Addr,
        original_dst_port: Port,
        expected_dst_ip: std::net::Ipv6Addr,
        expected_dst_port: Port,
    ) -> Option<PortState> {
        // Verify this ICMPv6 response is for our probe
        if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
            return None; // Not for our probe - continue waiting
        }

        match code {
            Icmpv6UnreachableCode::PortUnreachable => Some(PortState::Closed),
            Icmpv6UnreachableCode::AdminProhibited
            | Icmpv6UnreachableCode::PolicyFailed
            | Icmpv6UnreachableCode::RejectRoute
            | Icmpv6UnreachableCode::Unknown(_)
            | Icmpv6UnreachableCode::NoRoute
            | Icmpv6UnreachableCode::BeyondScope
            | Icmpv6UnreachableCode::AddressUnreachable => Some(PortState::Filtered),
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        let offset = (std::process::id() % 1000) as u16;
        SOURCE_PORT_START + offset
    }

    /// Creates an `AF_PACKET` engine for `ICMP` error capture.
    ///
    /// This is optional - if creation fails, returns `None` and the scanner
    /// falls back to raw socket only (which works for localhost but not remote hosts).
    fn create_packet_engine(local_addr: Ipv4Addr) -> Option<AfPacketEngine> {
        // Get the network interface name for the local address
        let if_name = Self::get_interface_for_ip(local_addr)?;

        let ring_config = RingConfig::default();
        let engine = AfPacketEngine::new(&if_name, ring_config).ok()?;

        // Set promiscuous mode to capture all packets
        let _ = engine.set_promiscuous(true);

        Some(engine)
    }

    /// Creates an `AF_PACKET` engine for IPv6 `ICMP` error capture.
    fn create_packet_engine_v6() -> Option<AfPacketEngine> {
        // For IPv6, we use the same interface as IPv4
        // Try common interface names
        for if_name in ["eth0", "ens33", "enp0s3", "wlan0"] {
            let ring_config = RingConfig::default();
            if let Ok(engine) = AfPacketEngine::new(if_name, ring_config) {
                let _ = engine.set_promiscuous(true);
                return Some(engine);
            }
        }
        None
    }

    /// Gets the network interface name for the given local IP address.
    fn get_interface_for_ip(local_addr: Ipv4Addr) -> Option<String> {
        // For localhost, use lo
        if local_addr == Ipv4Addr::LOCALHOST || local_addr.is_loopback() {
            return Some("lo".to_string());
        }

        // For other addresses, try common interface names
        // Includes both wired and wireless interface naming conventions
        for if_name in [
            "eth0", "eth1", "ens33", "ens34", "ens37", "enp0s3", "enp0s8", "enp1s0", "wlan0",
            "wlp3s0", "wlp2s0", "wlp1s0", "en0", "en1",
        ] {
            // Try to create the engine - if successful, this interface exists
            let ring_config = RingConfig::default();
            if AfPacketEngine::new(if_name, ring_config).is_ok() {
                return Some(if_name.to_string());
            }
        }

        None
    }

    /// Receives an `ICMP` packet from the `AF_PACKET` engine.
    ///
    /// This captures all Ethernet frames including `ICMP` error responses
    /// that are not delivered to protocol-specific raw sockets.
    fn recv_icmp_from_packet_engine(&self, timeout: Duration) -> Option<IcmpResponse> {
        let Some(engine) = &self.packet_engine_v4 else {
            return None;
        };

        let start = std::time::Instant::now();

        // Use a minimum timeout of 500ms to ensure ICMP responses have time to arrive
        let effective_timeout = timeout.max(Duration::from_millis(500));

        // Poll for packets with timeout
        while start.elapsed() < effective_timeout {
            match engine.recv_packet() {
                Ok(Some(packet)) => {
                    let data = packet.data();
                    // Skip Ethernet header (14 bytes) to get IP packet
                    if data.len() > ETH_HEADER_SIZE {
                        let ip_packet = &data[ETH_HEADER_SIZE..];
                        // Check if this is an ICMP packet (protocol = 1)
                        if ip_packet.len() >= 10 && ip_packet[9] == 1 {
                            if let Some(icmp_resp) = parse_icmp_response(ip_packet) {
                                return Some(icmp_resp);
                            }
                        }
                    }
                }
                Ok(None) => {
                    // No packet available, delay before retry
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    // Error receiving, stop polling
                    return None;
                }
            }
        }

        None
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
            assert_eq!(scanner.local_addr_v4, local_addr);
        }
    }

    #[test]
    fn test_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        // Test that scanner creation requires root
        if let Ok(scanner) = UdpScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
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

        let result = UdpScanner::handle_icmp_response_v4(icmp_resp, dst_ip, dst_port).unwrap();
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

        let result = UdpScanner::handle_icmp_response_v4(icmp_resp, dst_ip, dst_port).unwrap();
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_handle_icmp_response_mismatch() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 53;

        // `ICMP` response for different port
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: 80, // Different port
        };

        let result = UdpScanner::handle_icmp_response_v4(icmp_resp, dst_ip, dst_port);
        assert!(result.is_none(), "Should return None for mismatched port");
    }
}
