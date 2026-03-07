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
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::packet_adapter::{create_stealth_engine, ScannerPacketEngine};
use crate::scanner::{AsyncPortScanner, PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{IpAddr, Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_icmpv6_unreachable, parse_ipv6_udp_response, parse_udp_response,
    IcmpResponse, IcmpUnreachableCode, Icmpv6UnreachableCode, Ipv6UdpPacketBuilder, RawSocket,
    UdpPacketBuilder,
};
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
    /// Modern packet engine for zero-copy capture using `PACKET_MMAP` V2 (optional).
    ///
    /// This provides better performance than the old `AfPacketEngine` through
    /// ring buffer operation and async I/O.
    scanner_engine_v4: Option<Arc<Mutex<ScannerPacketEngine>>>,
    /// Raw socket for IPv6 packet transmission (optional).
    socket_v6: Option<RawSocket>,
    /// Raw socket for `ICMPv6` error responses (optional).
    #[expect(dead_code, reason = "IPv6 ICMP error capture not yet implemented")]
    socket_icmp_v6: Option<RawSocket>,
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

        // Try to create ScannerPacketEngine for zero-copy capture using PACKET_MMAP V2.
        // This provides better performance than the old AfPacketEngine through ring buffer operation.
        let scanner_engine_v4 = create_stealth_engine(Some(local_addr), config.clone());

        Ok(Self {
            local_addr_v4: local_addr,
            local_addr_v6: None,
            socket_v4,
            socket_icmp_v4,
            scanner_engine_v4,
            socket_v6: None,
            socket_icmp_v6: None,
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

        // Try to create ScannerPacketEngine for zero-copy capture
        let scanner_engine_v4 = create_stealth_engine(Some(local_addr_v4), config.clone());

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

        Ok(Self {
            local_addr_v4,
            local_addr_v6: Some(local_addr_v6),
            socket_v4,
            socket_icmp_v4,
            scanner_engine_v4,
            socket_v6: Some(socket_v6),
            socket_icmp_v6: Some(socket_icmp_v6),
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
        // Use a minimum timeout of 3000ms to ensure ICMP responses have time to arrive
        // This is based on nmap's behavior which uses adaptive RTT timing and retransmissions
        // ICMP Port Unreachable responses can be delayed due to rate limiting
        let base_timeout = self.config.initial_rtt;
        let timeout = base_timeout.max(Duration::from_millis(3000));

        let mut recv_buf = vec![0u8; 65535];
        let start = std::time::Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Ok(PortState::OpenOrFiltered);
            }

            let remaining = timeout - elapsed;

            // Note: AF_PACKET engine has been removed. The receive path now uses
            // ScannerPacketEngine in the async version. This sync version falls back
            // to raw sockets only, which works for localhost but may miss ICMP errors
            // from remote hosts. Use scan_port_async() for full ICMP error support.

            // Try ICMP socket for ICMP error responses
            let icmp_timeout = Duration::from_millis(50).min(remaining);
            match self
                .socket_icmp_v4
                .recv_packet(recv_buf.as_mut_slice(), Some(icmp_timeout))
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
                    ) => {}
                Err(e) => {
                    return Err(rustnmap_common::ScanError::Network(
                        rustnmap_common::Error::Network(
                            rustnmap_common::error::NetworkError::ReceiveError { source: e },
                        ),
                    ))
                }
            }

            // Try UDP socket for actual UDP responses
            let udp_timeout = Duration::from_millis(50).min(remaining);
            match self
                .socket_v4
                .recv_packet(recv_buf.as_mut_slice(), Some(udp_timeout))
            {
                Ok(len) if len > 0 => {
                    let src_ip = if len >= 20 {
                        let bytes = [recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15]];
                        Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                    } else {
                        continue;
                    };

                    // Skip packets from our own IP
                    if src_ip == self.local_addr_v4 {
                        continue;
                    }

                    // CRITICAL: Verify the UDP response is from the TARGET IP
                    // Without this check, any UDP packet from any host with matching
                    // source port would be incorrectly treated as "open"
                    if src_ip != dst_addr {
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
                    // Small sleep to avoid busy-waiting
                    std::thread::sleep(Duration::from_millis(10));
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

    /// Sends a UDP probe to an IPv4 target asynchronously using `ScannerPacketEngine`.
    ///
    /// This is the async version of `send_udp_probe_v4` that uses the new
    /// `ScannerPacketEngine` for zero-copy packet capture with `PACKET_MMAP` V2.
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
    #[allow(
        clippy::too_many_lines,
        reason = "UDP scan requires complex response handling"
    )]
    #[allow(
        clippy::single_match_else,
        reason = "UDP scan requires complex response handling with multiple receive sources"
    )]
    async fn scan_port_impl_async_v4(
        &self,
        dst_addr: Ipv4Addr,
        dst_port: Port,
    ) -> ScanResult<PortState> {
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
        let base_timeout = self.config.initial_rtt;
        let timeout = base_timeout.max(Duration::from_millis(3000));

        let start = std::time::Instant::now();

        // Use ScannerPacketEngine if available for ICMP error capture
        if let Some(engine_ref) = &self.scanner_engine_v4 {
            let mut engine = engine_ref.lock().await;

            loop {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Ok(PortState::OpenOrFiltered);
                }

                let remaining = timeout - elapsed;

                // Try ScannerPacketEngine for ICMP errors
                let icmp_timeout = Duration::from_millis(50).min(remaining);
                match engine.recv_with_timeout(icmp_timeout).await {
                    Ok(Some(data)) => {
                        // Skip Ethernet header (14 bytes) to get IP packet
                        if data.len() > ETH_HEADER_SIZE {
                            let ip_packet = &data[ETH_HEADER_SIZE..];
                            // Check if this is an ICMP packet (protocol = 1)
                            if ip_packet.len() >= 10 && ip_packet[9] == 1 {
                                if let Some(icmp_resp) = parse_icmp_response(ip_packet) {
                                    if let Some(state) =
                                        Self::handle_icmp_response_v4(icmp_resp, dst_addr, dst_port)
                                    {
                                        return Ok(state);
                                    }
                                    // Non-matching ICMP - continue
                                }
                            }
                        }
                    }
                    Ok(None) | Err(_) => {
                        // Timeout or error receiving - continue to check other sources
                    }
                }

                // Try ICMP socket for ICMP error responses
                let mut recv_buf = vec![0u8; 65535];
                let icmp_timeout = Duration::from_millis(50).min(remaining);
                match self
                    .socket_icmp_v4
                    .recv_packet(recv_buf.as_mut_slice(), Some(icmp_timeout))
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
                        ) => {}
                    Err(e) => {
                        return Err(rustnmap_common::ScanError::Network(
                            rustnmap_common::Error::Network(
                                rustnmap_common::error::NetworkError::ReceiveError { source: e },
                            ),
                        ))
                    }
                }

                // Try UDP socket for actual UDP responses
                let udp_timeout = Duration::from_millis(50).min(remaining);
                match self
                    .socket_v4
                    .recv_packet(recv_buf.as_mut_slice(), Some(udp_timeout))
                {
                    Ok(len) if len > 0 => {
                        let src_ip = if len >= 20 {
                            let bytes = [recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15]];
                            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                        } else {
                            continue;
                        };

                        // Skip packets from our own IP
                        if src_ip == self.local_addr_v4 {
                            continue;
                        }

                        // CRITICAL: Verify the UDP response is from the TARGET IP
                        if src_ip != dst_addr {
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
                        // Small sleep to avoid busy-waiting
                        tokio::time::sleep(Duration::from_millis(10)).await;
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
        } else {
            // Fallback to sync implementation if no ScannerPacketEngine available
            // Use the existing scan_port_impl method
            self.scan_port_impl(
                &Target {
                    ip: IpAddr::V4(dst_addr),
                    hostname: None,
                    ports: None,
                    ipv6_scope: None,
                },
                dst_port,
                Protocol::Udp,
            )
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
                    // Extract source IPv6 address from packet (bytes 8-23)
                    // IPv6 header format: version/traffic/flow (4 bytes) + payload len/next hop/hop limit (4 bytes)
                    // + source address (16 bytes at offset 8) + dest address (16 bytes at offset 24)
                    let src_ip = if len >= 24 {
                        let mut addr_bytes = [0u8; 16];
                        addr_bytes.copy_from_slice(&recv_buf[8..24]);
                        std::net::Ipv6Addr::from(addr_bytes)
                    } else {
                        continue;
                    };

                    // CRITICAL: Verify the UDP response is from the TARGET IP
                    // Without this check, any UDP packet from any host with matching
                    // source port would be incorrectly treated as "open"
                    if src_ip != dst_addr {
                        // Check for ICMPv6 response before continuing
                        if let Some((code, orig_ip, orig_port)) =
                            parse_icmpv6_unreachable(&recv_buf[..len])
                        {
                            if let Some(state) = Self::handle_icmpv6_response(
                                code, orig_ip, orig_port, dst_addr, dst_port,
                            ) {
                                return Ok(state);
                            }
                        }
                        continue;
                    }

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
}

impl PortScanner for UdpScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

#[async_trait]
impl AsyncPortScanner for UdpScanner {
    async fn scan_port_async(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        match target.ip {
            IpAddr::V4(dst_addr) if protocol == Protocol::Udp => {
                self.scan_port_impl_async_v4(dst_addr, port).await
            }
            IpAddr::V6(_dst_addr) if protocol == Protocol::Udp => {
                // IPv6 scanning not yet fully migrated to async
                // Fall back to sync implementation
                self.scan_port_impl(target, port, protocol)
            }
            _ => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Other(format!(
                    "Invalid protocol for UDP scan: {protocol:?}"
                )),
            )),
        }
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
            assert!(PortScanner::requires_root(&scanner));
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
