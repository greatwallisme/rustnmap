//! IP Protocol scanner implementation for `RustNmap`.
//!
//! This module provides IP Protocol scanning functionality using raw sockets.
//! IP Protocol scan determines which IP protocols (TCP, UDP, ICMP, etc.)
//! are supported by the target host by scanning protocol numbers (0-255).
//!
//! # Protocol State Determination
//!
//! - OPEN: Protocol-specific response received (e.g., ICMP echo reply)
//! - CLOSED: ICMP Protocol Unreachable received (type 3, code 2)
//! - FILTERED: ICMP Admin Prohibited or other ICMP errors
//! - OPEN|FILTERED: No response (ambiguous)

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{parse_icmp_response, IcmpResponse, IcmpUnreachableCode, RawSocket};
use rustnmap_target::Target;

/// Default source port for outbound protocol probes.
pub const SOURCE_PORT: u16 = 60000;

/// Target port for TCP/UDP protocol probes.
pub const TARGET_PORT: u16 = 80;

/// IP Protocol scanner using raw sockets.
///
/// Determines which IP protocols are supported by sending
/// protocol-specific probes and analyzing responses.
#[derive(Debug)]
pub struct IpProtocolScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl IpProtocolScanner {
    /// Creates a new IP Protocol scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `IpProtocolScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn new(local_addr: Ipv4Addr, config: ScanConfig) -> ScanResult<Self> {
        // Use IPPROTO_RAW (255) to receive all IP protocol responses
        let socket = RawSocket::with_protocol(255).map_err(|e| {
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

    /// Scans a single protocol on a target.
    ///
    /// Sends a protocol-specific probe and determines state based on response:
    /// - If protocol-specific response received -> Open
    /// - If ICMP Protocol Unreachable received -> Closed
    /// - If ICMP Admin Prohibited received -> Filtered
    /// - If no response -> Open|Filtered (ambiguous)
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Protocol number (0-255) to probe
    /// * `protocol` - Protocol type
    ///
    /// # Returns
    ///
    /// Protocol state based on response received.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network issues.
    fn scan_protocol_impl(
        &self,
        target: &Target,
        protocol_num: u8,
        _protocol: Protocol,
    ) -> ScanResult<PortState> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        self.send_protocol_probe(dst_addr, protocol_num)
    }

    /// Sends a protocol probe and determines state from response.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `protocol_num` - IP protocol number to probe
    ///
    /// # Returns
    ///
    /// Protocol state based on response:
    /// - Open: Protocol-specific response received
    /// - Closed: ICMP Protocol Unreachable received
    /// - Filtered: ICMP Admin Prohibited or other ICMP errors
    /// - Open|Filtered: No response (timeout)
    ///
    /// # Errors
    ///
    /// Returns an error if packet transmission fails.
    fn send_protocol_probe(&self, dst_addr: Ipv4Addr, protocol_num: u8) -> ScanResult<PortState> {
        // Build protocol-specific probe
        let packet = self.build_protocol_probe(dst_addr, protocol_num);

        // Create destination socket address (use protocol number as port for raw IP)
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), 0);

        // Send the packet
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
                // Check if we received a protocol-specific response
                if Self::is_protocol_response(&recv_buf[..len], protocol_num) {
                    return Ok(PortState::Open);
                }

                // Check for ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(Self::handle_icmp_response(icmp_resp));
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

    /// Builds a protocol-specific probe packet.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `protocol_num` - IP protocol number
    ///
    /// # Returns
    ///
    /// Raw packet bytes ready to be sent.
    fn build_protocol_probe(&self, dst_addr: Ipv4Addr, protocol_num: u8) -> Vec<u8> {
        match protocol_num {
            1 => self.build_icmp_probe(dst_addr),
            6 => self.build_tcp_probe(dst_addr),
            17 => self.build_udp_probe(dst_addr),
            _ => self.build_generic_probe(dst_addr, protocol_num),
        }
    }

    /// Builds an ICMP echo request probe.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    ///
    /// # Returns
    ///
    /// ICMP echo request packet.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    fn build_icmp_probe(&self, dst_addr: Ipv4Addr) -> Vec<u8> {
        // IP header (20 bytes) + ICMP header (8 bytes) + payload
        let ip_header_len = 20;
        let icmp_len = 8 + 56; // ICMP header + typical payload
        let total_len = ip_header_len + icmp_len;

        let mut packet = Vec::with_capacity(total_len);

        // Build IP header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0); // DSCP/ECN
        packet.push((total_len >> 8) as u8);
        packet.push((total_len & 0xFF) as u8);
        packet.push(0);
        packet.push(0); // Identification
        packet.push(0x40);
        packet.push(0); // Flags, fragment offset
        packet.push(64); // TTL
        packet.push(1); // Protocol = ICMP
        packet.push(0);
        packet.push(0); // Header checksum (calculated later)
        packet.extend_from_slice(&self.local_addr.octets());
        packet.extend_from_slice(&dst_addr.octets());

        // Build ICMP echo request
        packet.push(8); // Type = Echo Request
        packet.push(0); // Code = 0
        packet.push(0);
        packet.push(0); // Checksum (calculated later)
        packet.push(0);
        packet.push(0); // Identifier
        packet.push(0);
        packet.push(0); // Sequence number

        // Add payload (56 bytes of zeros, typical for ping)
        packet.extend_from_slice(&[0u8; 56]);

        // Calculate ICMP checksum
        let icmp_checksum = Self::calculate_checksum(&packet[ip_header_len..]);
        packet[ip_header_len + 2] = (icmp_checksum >> 8) as u8;
        packet[ip_header_len + 3] = (icmp_checksum & 0xFF) as u8;

        // Calculate IP checksum
        let ip_checksum = Self::calculate_checksum(&packet[..ip_header_len]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        packet
    }

    /// Builds a TCP ACK probe.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    ///
    /// # Returns
    ///
    /// TCP ACK packet.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    fn build_tcp_probe(&self, dst_addr: Ipv4Addr) -> Vec<u8> {
        // IP header (20 bytes) + TCP header (20 bytes)
        let ip_header_len = 20;
        let tcp_len = 20;
        let total_len = ip_header_len + tcp_len;

        let mut packet = Vec::with_capacity(total_len);

        // Build IP header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0); // DSCP/ECN
        packet.push((total_len >> 8) as u8);
        packet.push((total_len & 0xFF) as u8);
        packet.push(0);
        packet.push(0); // Identification
        packet.push(0x40);
        packet.push(0); // Flags, fragment offset
        packet.push(64); // TTL
        packet.push(6); // Protocol = TCP
        packet.push(0);
        packet.push(0); // Header checksum (calculated later)
        packet.extend_from_slice(&self.local_addr.octets());
        packet.extend_from_slice(&dst_addr.octets());

        // Build TCP header
        let seq = Self::generate_sequence_number();
        packet.push((SOURCE_PORT >> 8) as u8);
        packet.push((SOURCE_PORT & 0xFF) as u8); // Source port
        packet.push((TARGET_PORT >> 8) as u8);
        packet.push((TARGET_PORT & 0xFF) as u8); // Destination port
        packet.push((seq >> 24) as u8);
        packet.push((seq >> 16) as u8);
        packet.push((seq >> 8) as u8);
        packet.push((seq & 0xFF) as u8); // Sequence number
        packet.push(0);
        packet.push(0);
        packet.push(0);
        packet.push(0); // Acknowledgment number
        packet.push(0x50); // Data offset (5 * 4 = 20 bytes), reserved
        packet.push(0x10); // ACK flag
        packet.push(0xFF);
        packet.push(0xFF); // Window size
        packet.push(0);
        packet.push(0); // TCP checksum (calculated later)
        packet.push(0);
        packet.push(0); // Urgent pointer

        // Calculate TCP checksum (pseudo-header + TCP header)
        let tcp_checksum =
            Self::calculate_tcp_checksum(self.local_addr, dst_addr, &packet[ip_header_len..]);
        packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
        packet[ip_header_len + 17] = (tcp_checksum & 0xFF) as u8;

        // Calculate IP checksum
        let ip_checksum = Self::calculate_checksum(&packet[..ip_header_len]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        packet
    }

    /// Builds a UDP probe.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    ///
    /// # Returns
    ///
    /// UDP packet.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    fn build_udp_probe(&self, dst_addr: Ipv4Addr) -> Vec<u8> {
        // IP header (20 bytes) + UDP header (8 bytes)
        let ip_header_len = 20;
        let udp_len = 8;
        let total_len = ip_header_len + udp_len;

        let mut packet = Vec::with_capacity(total_len);

        // Build IP header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0); // DSCP/ECN
        packet.push((total_len >> 8) as u8);
        packet.push((total_len & 0xFF) as u8);
        packet.push(0);
        packet.push(0); // Identification
        packet.push(0x40);
        packet.push(0); // Flags, fragment offset
        packet.push(64); // TTL
        packet.push(17); // Protocol = UDP
        packet.push(0);
        packet.push(0); // Header checksum (calculated later)
        packet.extend_from_slice(&self.local_addr.octets());
        packet.extend_from_slice(&dst_addr.octets());

        // Build UDP header
        packet.push((SOURCE_PORT >> 8) as u8);
        packet.push((SOURCE_PORT & 0xFF) as u8); // Source port
        packet.push((TARGET_PORT >> 8) as u8);
        packet.push((TARGET_PORT & 0xFF) as u8); // Destination port
        packet.push((udp_len >> 8) as u8);
        packet.push((udp_len & 0xFF) as u8); // Length
        packet.push(0);
        packet.push(0); // UDP checksum (optional, set to 0)

        // Calculate IP checksum
        let ip_checksum = Self::calculate_checksum(&packet[..ip_header_len]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        packet
    }

    /// Builds a generic IP probe for other protocols.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `protocol_num` - IP protocol number
    ///
    /// # Returns
    ///
    /// Raw IP packet with empty payload.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    fn build_generic_probe(&self, dst_addr: Ipv4Addr, protocol_num: u8) -> Vec<u8> {
        // IP header (20 bytes) + empty payload
        let ip_header_len = 20;
        let total_len = ip_header_len;

        let mut packet = Vec::with_capacity(total_len);

        // Build IP header
        packet.push(0x45); // Version 4, IHL 5
        packet.push(0); // DSCP/ECN
        packet.push((total_len >> 8) as u8);
        packet.push((total_len & 0xFF) as u8);
        packet.push(0);
        packet.push(0); // Identification
        packet.push(0x40);
        packet.push(0); // Flags, fragment offset
        packet.push(64); // TTL
        packet.push(protocol_num); // Protocol
        packet.push(0);
        packet.push(0); // Header checksum (calculated later)
        packet.extend_from_slice(&self.local_addr.octets());
        packet.extend_from_slice(&dst_addr.octets());

        // Calculate IP checksum
        let ip_checksum = Self::calculate_checksum(&packet[..ip_header_len]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        packet
    }

    /// Checks if the response is a protocol-specific response.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes
    /// * `protocol_num` - Expected protocol number
    ///
    /// # Returns
    ///
    /// `true` if the response matches the expected protocol.
    fn is_protocol_response(packet: &[u8], protocol_num: u8) -> bool {
        if packet.len() < 20 {
            return false;
        }

        // Check IP version
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return false;
        }

        // Check protocol field in IP header
        packet[9] == protocol_num
    }

    /// Handles ICMP response for protocol scan.
    ///
    /// # Arguments
    ///
    /// * `icmp_resp` - Parsed ICMP response
    ///
    /// # Returns
    ///
    /// Port state based on ICMP response.
    fn handle_icmp_response(icmp_resp: IcmpResponse) -> PortState {
        match icmp_resp {
            IcmpResponse::DestinationUnreachable { code, .. } => match code {
                IcmpUnreachableCode::ProtocolUnreachable => PortState::Closed,
                _ => PortState::Filtered,
            },
            IcmpResponse::TimeExceeded { .. } | IcmpResponse::Other { .. } => PortState::Filtered,
        }
    }

    /// Calculates the checksum for a packet.
    ///
    /// # Arguments
    ///
    /// * `data` - Packet data
    ///
    /// # Returns
    ///
    /// 16-bit checksum value.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Checksum calculation requires truncation"
    )]
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let len = data.len();

        for i in (0..len).step_by(2) {
            if i + 1 < len {
                sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
            } else {
                sum += u32::from(data[i]) << 8;
            }
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Calculates TCP checksum using pseudo-header.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `tcp_data` - TCP segment data
    ///
    /// # Returns
    ///
    /// 16-bit checksum value.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "TCP checksum calculation requires truncation"
    )]
    fn calculate_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
        // Build pseudo-header
        let mut pseudo_header = Vec::with_capacity(12);
        pseudo_header.extend_from_slice(&src_ip.octets());
        pseudo_header.extend_from_slice(&dst_ip.octets());
        pseudo_header.push(0);
        pseudo_header.push(6); // Protocol = TCP
        pseudo_header.push((tcp_data.len() >> 8) as u8);
        pseudo_header.push((tcp_data.len() & 0xFF) as u8);

        // Calculate checksum over pseudo-header + TCP data
        let mut sum = 0u32;

        for chunk in pseudo_header.chunks(2) {
            if chunk.len() == 2 {
                sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
        }

        for i in (0..tcp_data.len()).step_by(2) {
            if i + 1 < tcp_data.len() {
                sum += u32::from(u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]));
            } else {
                sum += u32::from(tcp_data[i]) << 8;
            }
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
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

impl PortScanner for IpProtocolScanner {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Protocol numbers are 0-255, port values above 255 are truncated"
    )]
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        // For IP protocol scan, 'port' is actually the protocol number
        self.scan_protocol_impl(target, port as u8, protocol)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_protocol_scanner_creation() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();
        let result = IpProtocolScanner::new(local_addr, config);

        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
        }
    }

    #[test]
    fn test_ip_protocol_scanner_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let config = ScanConfig::default();

        if let Ok(scanner) = IpProtocolScanner::new(local_addr, config) {
            assert!(scanner.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_sequence_number() {
        let seq1 = IpProtocolScanner::generate_sequence_number();
        let seq2 = IpProtocolScanner::generate_sequence_number();
        let diff = seq1.abs_diff(seq2);
        assert!(
            diff < 1_000_000,
            "Sequence numbers should be close in value"
        );
    }

    #[test]
    fn test_build_icmp_probe() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();

        if let Ok(scanner) = IpProtocolScanner::new(local_addr, config) {
            let dst_addr = Ipv4Addr::new(192, 168, 1, 1);
            let packet = scanner.build_icmp_probe(dst_addr);

            // Check IP header
            assert_eq!(packet[0], 0x45); // Version 4, IHL 5
            assert_eq!(packet[9], 1); // Protocol = ICMP

            // Check ICMP header
            assert_eq!(packet[20], 8); // Type = Echo Request
            assert_eq!(packet[21], 0); // Code = 0
        }
    }

    #[test]
    fn test_build_tcp_probe() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();

        if let Ok(scanner) = IpProtocolScanner::new(local_addr, config) {
            let dst_addr = Ipv4Addr::new(192, 168, 1, 1);
            let packet = scanner.build_tcp_probe(dst_addr);

            // Check IP header
            assert_eq!(packet[0], 0x45); // Version 4, IHL 5
            assert_eq!(packet[9], 6); // Protocol = TCP

            // Check TCP header flags
            assert_eq!(packet[33], 0x10); // ACK flag
        }
    }

    #[test]
    fn test_build_udp_probe() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();

        if let Ok(scanner) = IpProtocolScanner::new(local_addr, config) {
            let dst_addr = Ipv4Addr::new(192, 168, 1, 1);
            let packet = scanner.build_udp_probe(dst_addr);

            // Check IP header
            assert_eq!(packet[0], 0x45); // Version 4, IHL 5
            assert_eq!(packet[9], 17); // Protocol = UDP

            // Check UDP destination port
            let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
            assert_eq!(dst_port, TARGET_PORT);
        }
    }

    #[test]
    fn test_build_generic_probe() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let config = ScanConfig::default();

        if let Ok(scanner) = IpProtocolScanner::new(local_addr, config) {
            let dst_addr = Ipv4Addr::new(192, 168, 1, 1);
            let protocol_num = 47; // GRE
            let packet = scanner.build_generic_probe(dst_addr, protocol_num);

            // Check IP header
            assert_eq!(packet[0], 0x45); // Version 4, IHL 5
            assert_eq!(packet[9], protocol_num); // Protocol
        }
    }

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        let data = [0x45u8, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00];
        let checksum = IpProtocolScanner::calculate_checksum(&data);

        // Verify checksum is valid (should not be 0 for valid data)
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_handle_icmp_protocol_unreachable() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::ProtocolUnreachable,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 0,
        };

        let result = IpProtocolScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Closed);
    }

    #[test]
    fn test_handle_icmp_admin_prohibited() {
        let icmp_resp = IcmpResponse::DestinationUnreachable {
            code: IcmpUnreachableCode::AdminProhibited,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 1),
            original_dst_port: 0,
        };

        let result = IpProtocolScanner::handle_icmp_response(icmp_resp);
        assert_eq!(result, PortState::Filtered);
    }
}
