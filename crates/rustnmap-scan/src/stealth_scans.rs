//! Stealth TCP scanner implementations for `RustNmap`.
//!
//! This module provides alternative TCP scanning techniques that exploit
//! RFC 793 TCP behavior to perform stealthy port scanning. These scans
//! do not complete the TCP handshake, making them harder to detect.
//!
//! # Scan Types
//!
//! - **TCP FIN Scan** (`TcpFinScanner`): Sends FIN flag only
//! - **TCP NULL Scan** (`TcpNullScanner`): Sends no flags
//! - **TCP Xmas Scan** (`TcpXmasScanner`): Sends FIN+PSH+URG flags
//! - **TCP ACK Scan** (`TcpAckScanner`): Sends ACK flag only (firewall detection)
//! - **TCP Maimon Scan** (`TcpMaimonScanner`): Sends FIN+ACK flags
//! - **TCP Window Scan** (`TcpWindowScanner`): Sends ACK flag, analyzes window size in RST
//!
//! # Port State Determination
//!
//! For FIN/NULL/Xmas/Maimon scans:
//! - No response -> Port Open|Filtered
//! - RST received -> Port Closed
//! - ICMP unreachable -> Filtered
//!
//! For ACK scan:
//! - RST received -> Port Unfiltered
//! - No response/ICMP -> Port Filtered
//!
//! For Window scan:
//! - RST + Window > 0 -> Port Closed (on some systems like HP-UX)
//! - RST + Window = 0 -> Port Open (on some systems)
//! - No response/ICMP -> Port Filtered

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_tcp_response, parse_tcp_response_full, IcmpResponse,
    IcmpUnreachableCode, RawSocket, TcpPacketBuilder,
};
use rustnmap_target::Target;

/// Default source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// TCP flag constants for reference.
mod tcp_flags {
    /// RST flag (0x04).
    pub const RST: u8 = 0x04;
}

/// TCP FIN scanner using raw sockets.
///
/// Sends TCP packets with only the FIN flag set. According to RFC 793,
/// closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpFinScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpFinScanner {
    /// Creates a new TCP FIN scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpFinScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_fin_probe(dst_addr, port)
    }

    /// Sends a TCP FIN probe and determines port state from response.
    fn send_fin_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for TCP response first
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp, dst_addr, dst_port));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::OpenOrFiltered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::OpenOrFiltered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response to determine port state.
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
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return PortState::Filtered;
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                    _ => PortState::Filtered,
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => PortState::Filtered,
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

impl PortScanner for TcpFinScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP NULL scanner using raw sockets.
///
/// Sends TCP packets with no flags set. According to RFC 793,
/// closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpNullScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpNullScanner {
    /// Creates a new TCP NULL scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpNullScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_null_probe(dst_addr, port)
    }

    /// Sends a TCP NULL probe (no flags) and determines port state from response.
    fn send_null_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with NO flags set
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for TCP response first
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp, dst_addr, dst_port));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::OpenOrFiltered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::OpenOrFiltered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response to determine port state.
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
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return PortState::Filtered;
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                    _ => PortState::Filtered,
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => PortState::Filtered,
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

impl PortScanner for TcpNullScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Xmas scanner using raw sockets.
///
/// Sends TCP packets with FIN, PSH, and URG flags set ("lights up like a Christmas tree").
/// According to RFC 793, closed ports should respond with RST, while open ports should
/// ignore the packet (no response).
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpXmasScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpXmasScanner {
    /// Creates a new TCP Xmas scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpXmasScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_xmas_probe(dst_addr, port)
    }

    /// Sends a TCP Xmas probe (FIN+PSH+URG) and determines port state from response.
    fn send_xmas_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with FIN+PSH+URG flags (Xmas tree)
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .psh()
            .urg()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for TCP response first
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp, dst_addr, dst_port));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::OpenOrFiltered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::OpenOrFiltered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response to determine port state.
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
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return PortState::Filtered;
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                    _ => PortState::Filtered,
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => PortState::Filtered,
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

impl PortScanner for TcpXmasScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP ACK scanner using raw sockets.
///
/// Sends TCP packets with only the ACK flag set. This scan type is used
/// for firewall/ACL detection rather than determining port state.
///
/// # Port State Mapping
///
/// - RST received -> Unfiltered (port is reachable)
/// - No response/ICMP -> Filtered
///
/// Note: ACK scan cannot distinguish between open and closed ports.
/// It only determines if a port is filtered by a firewall.
#[derive(Debug)]
pub struct TcpAckScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpAckScanner {
    /// Creates a new TCP ACK scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpAckScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_ack_probe(dst_addr, port)
    }

    /// Sends a TCP ACK probe and determines port state from response.
    fn send_ack_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with ACK flag only
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .ack_flag()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for TCP response first
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    // For ACK scan, RST means the port is unfiltered (reachable)
                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Unfiltered);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::Filtered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::Filtered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response for ACK scan.
    fn handle_icmp_response(_icmp_resp: IcmpResponse) -> PortState {
        PortState::Filtered
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

impl PortScanner for TcpAckScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Maimon scanner using raw sockets.
///
/// Sends TCP packets with FIN and ACK flags set. Named after Uriel Maimon
/// who described this technique. Similar to FIN scan but includes ACK flag.
///
/// # Port State Mapping
///
/// - No response -> Open|Filtered
/// - RST received -> Closed
/// - ICMP unreachable -> Filtered
#[derive(Debug)]
pub struct TcpMaimonScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpMaimonScanner {
    /// Creates a new TCP Maimon scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpMaimonScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_maimon_probe(dst_addr, port)
    }

    /// Sends a TCP Maimon probe (FIN+ACK) and determines port state from response.
    fn send_maimon_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with FIN+ACK flags
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .fin()
            .ack_flag()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Check for TCP response first
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    if (flags & tcp_flags::RST) != 0 {
                        return Ok(PortState::Closed);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp, dst_addr, dst_port));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::OpenOrFiltered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::OpenOrFiltered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response to determine port state.
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
                if original_dst_ip != expected_dst_ip || original_dst_port != expected_dst_port {
                    return PortState::Filtered;
                }

                match code {
                    IcmpUnreachableCode::PortUnreachable => PortState::Closed,
                    _ => PortState::Filtered,
                }
            }
            IcmpResponse::Other { .. } | IcmpResponse::TimeExceeded { .. } => PortState::Filtered,
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

impl PortScanner for TcpMaimonScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        self.scan_port_impl(target, port, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP Window scanner using raw sockets.
///
/// Sends TCP packets with the ACK flag set and analyzes the TCP Window field
/// in RST responses. This scan type exploits differences in TCP stack
/// implementations where some systems (like HP-UX, AIX) return RST packets
/// with non-zero window sizes for closed ports.
///
/// # Port State Mapping
///
/// - RST with Window > 0 -> Port Closed (on some systems like HP-UX)
/// - RST with Window = 0 -> Port Open (on some systems)
/// - No response/ICMP -> Port Filtered
///
/// Note: Window scan behavior varies by target OS. Not all systems
/// exhibit different window sizes in RST responses.
#[derive(Debug)]
pub struct TcpWindowScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl TcpWindowScanner {
    /// Creates a new TCP Window scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `TcpWindowScanner` instance, or an error
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

        Ok(Self {
            local_addr,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_window_probe(dst_addr, port)
    }

    /// Sends a TCP Window probe (ACK) and determines port state from RST window field.
    fn send_window_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<PortState> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP packet with ACK flag only (same as ACK scan)
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .ack_flag()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Use full TCP response parser to get window field
                if let Some(tcp_resp) = parse_tcp_response_full(&recv_buf[..len]) {
                    if tcp_resp.src_port != dst_port {
                        return Ok(PortState::Filtered);
                    }

                    // Check for RST flag
                    if (tcp_resp.flags & tcp_flags::RST) != 0 {
                        // Window scan: analyze window size in RST response
                        // Some systems (HP-UX, AIX) return non-zero window for closed ports
                        if tcp_resp.window > 0 {
                            return Ok(PortState::Closed);
                        }
                        return Ok(PortState::Open);
                    }

                    return Ok(PortState::Filtered);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp));
                }

                Ok(PortState::Filtered)
            }
            Ok(_) => Ok(PortState::Filtered),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(PortState::Filtered)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Handles ICMP response for Window scan.
    fn handle_icmp_response(_icmp_resp: IcmpResponse) -> PortState {
        PortState::Filtered
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

impl PortScanner for TcpWindowScanner {
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
    fn test_fin_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpFinScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_fin_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpFinScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_null_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpNullScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_null_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpNullScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_xmas_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpXmasScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_xmas_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpXmasScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_ack_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpAckScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_ack_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpAckScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_maimon_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpMaimonScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_maimon_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpMaimonScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_source_port() {
        let port = TcpFinScanner::generate_source_port();
        assert!(port >= SOURCE_PORT_START);
        assert!(port < SOURCE_PORT_START + 1000);
    }

    #[test]
    fn test_generate_sequence_number() {
        let seq1 = TcpFinScanner::generate_sequence_number();
        let seq2 = TcpFinScanner::generate_sequence_number();
        let diff = seq1.abs_diff(seq2);
        assert!(
            diff < 1_000_000,
            "Sequence numbers should be close in value"
        );
    }

    #[test]
    fn test_fin_handle_icmp_port_unreachable() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Closed);
    }

    #[test]
    fn test_fin_handle_icmp_admin_prohibited() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: dst_ip,
            original_dst_port: dst_port,
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_fin_handle_icmp_mismatch() {
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_port = 80;

        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::PortUnreachable,
            original_dst_ip: dst_ip,
            original_dst_port: 443, // Different port
        };

        let result = TcpFinScanner::handle_icmp_response(icmp_resp, dst_ip, dst_port);
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_ack_handle_icmp() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 80,
        };

        let result = TcpAckScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Filtered);
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags::RST, 0x04);
    }

    #[test]
    fn test_window_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = TcpWindowScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_window_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = TcpWindowScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_window_handle_icmp() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 80,
        };

        let result = TcpWindowScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Filtered);
    }
}
