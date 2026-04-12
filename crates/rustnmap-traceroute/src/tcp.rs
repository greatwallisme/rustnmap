//! TCP traceroute implementations (SYN and ACK).

use crate::{
    error::{Result, TracerouteError},
    probe::ProbeResponse,
    TracerouteConfig,
};
use rustnmap_common::Ipv4Addr;
use rustnmap_net::raw_socket::{
    parse_icmp_response, parse_tcp_response, IcmpResponse, RawSocket, TcpPacketBuilder,
};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// TCP SYN-based traceroute implementation.
#[derive(Debug)]
pub struct TcpSynTraceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
    /// Socket for sending TCP probes and receiving TCP responses.
    socket: RawSocket,
    /// Socket for receiving ICMP responses (Time Exceeded).
    icmp_socket: RawSocket,
    /// Sequence number for probes.
    sequence: u32,
}

/// TCP ACK-based traceroute implementation.
#[derive(Debug)]
pub struct TcpAckTraceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
    /// Socket for sending TCP probes and receiving TCP responses.
    socket: RawSocket,
    /// Socket for receiving ICMP responses (Time Exceeded).
    icmp_socket: RawSocket,
    /// Sequence number for probes.
    sequence: u32,
}

impl TcpSynTraceroute {
    /// Creates a new TCP SYN traceroute instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Traceroute configuration
    /// * `local_addr` - Local IP address to use for probes
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid or socket creation fails.
    pub fn new(config: TracerouteConfig, local_addr: Ipv4Addr) -> Result<Self> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;
        // Use IPPROTO_ICMP (1) for receiving ICMP Time Exceeded responses
        let icmp_socket = RawSocket::with_protocol(1).map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;

        Ok(Self {
            config,
            local_addr,
            socket,
            icmp_socket,
            sequence: 0,
        })
    }

    /// Sends a TCP SYN probe with the specified TTL.
    ///
    /// # Arguments
    ///
    /// * `target` - Target IP address
    /// * `ttl` - Time-to-live value for this probe
    /// * `dest_port` - Destination port to probe
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a response was received,
    /// `Ok(None)` if the probe timed out, or an error if sending failed.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub fn send_probe(
        &mut self,
        target: Ipv4Addr,
        ttl: u8,
        dest_port: u16,
    ) -> Result<Option<ProbeResponse>> {
        self.sequence = self.sequence.wrapping_add(1);

        // Generate source port
        let src_port = self.generate_source_port();

        // Build TCP SYN packet
        let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, dest_port)
            .seq(self.sequence)
            .syn()
            .window(65535)
            .build();

        // Set TTL on socket
        self.socket
            .set_ttl(u32::from(ttl))
            .map_err(|e| TracerouteError::Network(format!("Failed to set TTL: {e}")))?;

        // Create destination socket address
        let dst_sockaddr = SocketAddr::V4(SocketAddrV4::new(target, dest_port));

        // Send the packet
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| TracerouteError::SendFailed { source: e })?;

        // Wait for response
        self.receive_response(target, dest_port)
    }

    /// Receives and parses response to TCP SYN probe.
    ///
    /// # Arguments
    ///
    /// * `target` - Expected target IP
    /// * `dest_port` - Destination port used in probe
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a valid response was received,
    /// `Ok(None)` if timed out, or an error.
    fn receive_response(&self, target: Ipv4Addr, dest_port: u16) -> Result<Option<ProbeResponse>> {
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.probe_timeout;

        // First check TCP socket for SYN-ACK/RST responses
        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                if let Some(response) =
                    self.handle_tcp_response(&recv_buf[..len], target, dest_port)
                {
                    return Ok(Some(response));
                }

                // Also check for ICMP on TCP socket (Linux may deliver some)
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &recv_buf[..len],
                    ));
                }

                // Fall through to check ICMP socket
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {}
            Err(e) => return Err(TracerouteError::ReceiveFailed { source: e }),
        }

        // Check ICMP socket for Time Exceeded / Port Unreachable
        let mut icmp_buf = vec![0u8; 65535];
        let icmp_timeout = self.config.probe_timeout;
        match self
            .icmp_socket
            .recv_packet(icmp_buf.as_mut_slice(), Some(icmp_timeout))
        {
            Ok(len) if len > 0 => {
                if let Some(icmp_resp) = parse_icmp_response(&icmp_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &icmp_buf[..len],
                    ));
                }
                Ok(None)
            }
            Ok(_) => Ok(None),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(TracerouteError::ReceiveFailed { source: e }),
        }
    }

    /// Handles TCP response (SYN-ACK or RST from target).
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes
    /// * `_expected_target` - Expected target IP
    /// * `expected_port` - Expected destination port
    ///
    /// # Returns
    ///
    /// `Some(ProbeResponse)` if valid TCP response from target, `None` otherwise.
    fn handle_tcp_response(
        &self,
        packet: &[u8],
        _expected_target: Ipv4Addr,
        expected_port: u16,
    ) -> Option<ProbeResponse> {
        if let Some((flags, _seq, ack, src_port, _dst_port, _src_ip)) = parse_tcp_response(packet) {
            // Verify this is a response to our probe
            if src_port != expected_port {
                return None;
            }

            // Check if ACK matches our sequence number + 1
            let expected_ack = self.sequence.wrapping_add(1);
            if ack != expected_ack {
                return None;
            }

            // Extract source IP from IP header
            if packet.len() < 20 {
                return None;
            }
            let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

            // Analyze flags
            let syn_received = (flags & 0x02) != 0;
            let ack_received = (flags & 0x10) != 0;
            let rst_received = (flags & 0x04) != 0;

            if syn_received && ack_received {
                // SYN-ACK received - we reached the target and port is open
                Some(ProbeResponse::new(source_ip, 6, 0, true)) // Type 6 = TCP
            } else if rst_received {
                // RST received - we reached the target but port is closed
                Some(ProbeResponse::new(source_ip, 6, 1, true)) // Type 6 = TCP, Code 1 = RST
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Handles ICMP response and creates appropriate `ProbeResponse`.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn handle_icmp_response(
        &self,
        icmp_resp: IcmpResponse,
        expected_target: Ipv4Addr,
        _expected_port: u16,
        packet: &[u8],
    ) -> Option<ProbeResponse> {
        // Extract source IP from the IP header (bytes 12-15)
        if packet.len() < 20 {
            return None;
        }
        let responder_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        match icmp_resp {
            IcmpResponse::TimeExceeded {
                original_dst_ip, ..
            } => {
                // Verify this response is for our probe
                (original_dst_ip == expected_target)
                    .then(|| ProbeResponse::time_exceeded(responder_ip))
            }
            IcmpResponse::DestinationUnreachable { code, .. } => {
                // For TCP traceroute, destination unreachable typically means
                // we can't reach the target
                Some(ProbeResponse::new(
                    responder_ip,
                    3, // ICMP Destination Unreachable
                    u8::from(code),
                    responder_ip == expected_target,
                ))
            }
            IcmpResponse::Other { .. } => None,
        }
    }

    /// Generates a source port for the probe.
    ///
    /// Uses the configured source port if non-zero, otherwise generates
    /// a random port in the high range to avoid conflicts.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn generate_source_port(&self) -> u16 {
        let configured = self.config.source_port();
        if configured != 0 {
            return configured;
        }
        // Use a high port range to avoid conflicts
        let offset = (std::process::id() % 1000) as u16;
        50000 + offset
    }
}

impl TcpAckTraceroute {
    /// Creates a new TCP ACK traceroute instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Traceroute configuration
    /// * `local_addr` - Local IP address to use for probes
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid or socket creation fails.
    pub fn new(config: TracerouteConfig, local_addr: Ipv4Addr) -> Result<Self> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;
        // Use IPPROTO_ICMP (1) for receiving ICMP Time Exceeded responses
        let icmp_socket = RawSocket::with_protocol(1).map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;

        Ok(Self {
            config,
            local_addr,
            socket,
            icmp_socket,
            sequence: 0,
        })
    }

    /// Sends a TCP ACK probe with the specified TTL.
    ///
    /// # Arguments
    ///
    /// * `target` - Target IP address
    /// * `ttl` - Time-to-live value for this probe
    /// * `dest_port` - Destination port to probe
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a response was received,
    /// `Ok(None)` if the probe timed out, or an error if sending failed.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub fn send_probe(
        &mut self,
        target: Ipv4Addr,
        ttl: u8,
        dest_port: u16,
    ) -> Result<Option<ProbeResponse>> {
        self.sequence = self.sequence.wrapping_add(1);

        // Generate source port
        let src_port = self.generate_source_port();

        // Build TCP ACK packet (useful for bypassing stateless firewalls)
        let packet = TcpPacketBuilder::new(self.local_addr, target, src_port, dest_port)
            .seq(self.sequence)
            .ack_flag()
            .window(65535)
            .build();

        // Set TTL on socket
        self.socket
            .set_ttl(u32::from(ttl))
            .map_err(|e| TracerouteError::Network(format!("Failed to set TTL: {e}")))?;

        // Create destination socket address
        let dst_sockaddr = SocketAddr::V4(SocketAddrV4::new(target, dest_port));

        // Send the packet
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| TracerouteError::SendFailed { source: e })?;

        // Wait for response
        self.receive_response(target, dest_port)
    }

    /// Receives and parses response to TCP ACK probe.
    fn receive_response(&self, target: Ipv4Addr, dest_port: u16) -> Result<Option<ProbeResponse>> {
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.probe_timeout;

        // First check TCP socket for RST responses
        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                if let Some(response) =
                    self.handle_tcp_response(&recv_buf[..len], target, dest_port)
                {
                    return Ok(Some(response));
                }

                // Also check for ICMP on TCP socket
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &recv_buf[..len],
                    ));
                }

                // Fall through to check ICMP socket
            }
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {}
            Err(e) => return Err(TracerouteError::ReceiveFailed { source: e }),
        }

        // Check ICMP socket for Time Exceeded / Port Unreachable
        let mut icmp_buf = vec![0u8; 65535];
        let icmp_timeout = self.config.probe_timeout;
        match self
            .icmp_socket
            .recv_packet(icmp_buf.as_mut_slice(), Some(icmp_timeout))
        {
            Ok(len) if len > 0 => {
                if let Some(icmp_resp) = parse_icmp_response(&icmp_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &icmp_buf[..len],
                    ));
                }
                Ok(None)
            }
            Ok(_) => Ok(None),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(TracerouteError::ReceiveFailed { source: e }),
        }
    }

    /// Handles TCP response to ACK probe.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn handle_tcp_response(
        &self,
        packet: &[u8],
        expected_target: Ipv4Addr,
        expected_port: u16,
    ) -> Option<ProbeResponse> {
        if let Some((flags, _seq, _ack, src_port, _dst_port, src_ip)) = parse_tcp_response(packet) {
            // Verify this is a response to our probe
            if src_port != expected_port {
                return None;
            }

            // Use the parsed source IP from the response
            let source_ip = src_ip;

            // For ACK probe, RST typically means we reached the target
            // (target has no matching connection and sends RST)
            let rst_received = (flags & 0x04) != 0;

            rst_received.then(|| ProbeResponse::new(source_ip, 6, 1, source_ip == expected_target))
        } else {
            None
        }
    }

    /// Handles ICMP response and creates appropriate `ProbeResponse`.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn handle_icmp_response(
        &self,
        icmp_resp: IcmpResponse,
        expected_target: Ipv4Addr,
        _expected_port: u16,
        packet: &[u8],
    ) -> Option<ProbeResponse> {
        if packet.len() < 20 {
            return None;
        }
        let responder_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        match icmp_resp {
            IcmpResponse::TimeExceeded {
                original_dst_ip, ..
            } => (original_dst_ip == expected_target)
                .then(|| ProbeResponse::time_exceeded(responder_ip)),
            IcmpResponse::DestinationUnreachable { code, .. } => Some(ProbeResponse::new(
                responder_ip,
                3,
                u8::from(code),
                responder_ip == expected_target,
            )),
            IcmpResponse::Other { .. } => None,
        }
    }

    /// Generates a source port for the probe.
    ///
    /// Uses the configured source port if non-zero, otherwise generates
    /// a random port in the high range to avoid conflicts.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn generate_source_port(&self) -> u16 {
        let configured = self.config.source_port();
        if configured != 0 {
            return configured;
        }
        // Use a high port range to avoid conflicts
        let offset = (std::process::id() % 1000) as u16;
        50000 + offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnmap_net::raw_socket::IcmpUnreachableCode;

    // Helper function to build a minimal valid TCP response packet (40+ bytes)
    // IP header (20 bytes) + TCP header (20 bytes)
    fn build_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];

        // IP header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[1] = 0x00; // DSCP, ECN
        packet[2] = 0x00; // Total length (high byte)
        packet[3] = 40; // Total length (low byte) - 40 bytes
        packet[4] = 0x00; // Identification
        packet[5] = 0x00; // Identification
        packet[6] = 0x00; // Flags, Fragment offset
        packet[7] = 0x00; // Fragment offset
        packet[8] = 64; // TTL
        packet[9] = 6; // Protocol: TCP
        packet[10] = 0x00; // Header checksum (zero for test packet)
        packet[11] = 0x00; // Header checksum
        packet[12..16].copy_from_slice(&src_ip.octets()); // Source IP
        packet[16..20].copy_from_slice(&dst_ip.octets()); // Destination IP

        // TCP header (20 bytes)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes()); // Source port
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes()); // Destination port
        packet[24..28].copy_from_slice(&seq.to_be_bytes()); // Sequence number
        packet[28..32].copy_from_slice(&ack.to_be_bytes()); // Acknowledgment number
        packet[32] = 0x50; // Data offset (5 * 4 = 20 bytes) + reserved
        packet[33] = flags; // Flags
        packet[34] = 0xff; // Window size (high byte)
        packet[35] = 0xff; // Window size (low byte)
        packet[36] = 0x00; // TCP checksum (zero for test packet)
        packet[37] = 0x00; // TCP checksum
        packet[38] = 0x00; // Urgent pointer
        packet[39] = 0x00; // Urgent pointer

        packet
    }

    // Helper function to build an ICMP Time Exceeded packet
    // IP header (20 bytes) + ICMP header (8 bytes) + original packet payload (28 bytes) = 56 bytes
    fn build_icmp_time_exceeded_packet(
        responder_ip: Ipv4Addr,
        original_dst_ip: Ipv4Addr,
        original_dst_port: u16,
        code: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 56];

        // Outer IP header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00;
        packet[2] = 0x00; // Total length = 56
        packet[3] = 56;
        packet[4] = 0x00;
        packet[5] = 0x00;
        packet[6] = 0x00;
        packet[7] = 0x00;
        packet[8] = 64; // TTL
        packet[9] = 1; // Protocol: ICMP
        packet[10] = 0x00;
        packet[11] = 0x00;
        packet[12..16].copy_from_slice(&responder_ip.octets()); // Source IP (responder)
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]); // Destination IP (us)

        // ICMP header (8 bytes)
        packet[20] = 11; // Type: Time Exceeded
        packet[21] = code; // Code: 0 = TTL expired in transit, 1 = Fragment reassembly
        packet[22] = 0x00; // Checksum
        packet[23] = 0x00;
        packet[24] = 0x00; // Unused
        packet[25] = 0x00;
        packet[26] = 0x00;
        packet[27] = 0x00;

        // Original IP header (20 bytes) - embedded in ICMP payload
        packet[28] = 0x45; // Version 4, IHL 5
        packet[29] = 0x00;
        packet[30] = 0x00; // Total length
        packet[31] = 40;
        packet[32] = 0x00;
        packet[33] = 0x00;
        packet[34] = 0x00;
        packet[35] = 0x00;
        packet[36] = 64; // TTL
        packet[37] = 6; // Protocol: TCP
        packet[38] = 0x00;
        packet[39] = 0x00;
        packet[40..44].copy_from_slice(&[127, 0, 0, 1]); // Original source IP
        packet[44..48].copy_from_slice(&original_dst_ip.octets()); // Original destination IP

        // Original TCP header (8 bytes) - only first 8 bytes needed
        packet[48] = 0xc0; // Original source port (high byte) - 49152
        packet[49] = 0x00; // Original source port (low byte)
        packet[50..52].copy_from_slice(&original_dst_port.to_be_bytes()); // Original destination port
        packet[52] = 0x00;
        packet[53] = 0x00;
        packet[54] = 0x00;
        packet[55] = 0x00;

        packet
    }

    // Helper function to build an ICMP Destination Unreachable packet
    fn build_icmp_destination_unreachable_packet(
        responder_ip: Ipv4Addr,
        original_dst_ip: Ipv4Addr,
        original_dst_port: u16,
        code: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 56];

        // Outer IP header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00;
        packet[2] = 0x00; // Total length = 56
        packet[3] = 56;
        packet[4] = 0x00;
        packet[5] = 0x00;
        packet[6] = 0x00;
        packet[7] = 0x00;
        packet[8] = 64; // TTL
        packet[9] = 1; // Protocol: ICMP
        packet[10] = 0x00;
        packet[11] = 0x00;
        packet[12..16].copy_from_slice(&responder_ip.octets()); // Source IP (responder)
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]); // Destination IP (us)

        // ICMP header (8 bytes)
        packet[20] = 3; // Type: Destination Unreachable
        packet[21] = code; // Code
        packet[22] = 0x00; // Checksum
        packet[23] = 0x00;
        packet[24] = 0x00; // Unused
        packet[25] = 0x00;
        packet[26] = 0x00;
        packet[27] = 0x00;

        // Original IP header (20 bytes) - embedded in ICMP payload
        packet[28] = 0x45; // Version 4, IHL 5
        packet[29] = 0x00;
        packet[30] = 0x00;
        packet[31] = 40;
        packet[32] = 0x00;
        packet[33] = 0x00;
        packet[34] = 0x00;
        packet[35] = 0x00;
        packet[36] = 64; // TTL
        packet[37] = 6; // Protocol: TCP
        packet[38] = 0x00;
        packet[39] = 0x00;
        packet[40..44].copy_from_slice(&[127, 0, 0, 1]); // Original source IP
        packet[44..48].copy_from_slice(&original_dst_ip.octets()); // Original destination IP

        // Original TCP header (8 bytes)
        packet[48] = 0xc0;
        packet[49] = 0x00;
        packet[50..52].copy_from_slice(&original_dst_port.to_be_bytes());
        packet[52] = 0x00;
        packet[53] = 0x00;
        packet[54] = 0x00;
        packet[55] = 0x00;

        packet
    }

    // Helper function to build an ICMP Echo Reply packet (Type 8)
    fn build_icmp_other_packet(responder_ip: Ipv4Addr, icmp_type: u8, icmp_code: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 28];

        // IP header (20 bytes)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00;
        packet[2] = 0x00;
        packet[3] = 28;
        packet[4] = 0x00;
        packet[5] = 0x00;
        packet[6] = 0x00;
        packet[7] = 0x00;
        packet[8] = 64; // TTL
        packet[9] = 1; // Protocol: ICMP
        packet[10] = 0x00;
        packet[11] = 0x00;
        packet[12..16].copy_from_slice(&responder_ip.octets()); // Source IP
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]); // Destination IP

        // ICMP header (8 bytes)
        packet[20] = icmp_type;
        packet[21] = icmp_code;
        packet[22] = 0x00;
        packet[23] = 0x00;
        packet[24] = 0x00;
        packet[25] = 0x00;
        packet[26] = 0x00;
        packet[27] = 0x00;

        packet
    }

    #[test]
    fn test_tcp_syn_traceroute_new() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        let result = TcpSynTraceroute::new(config, local_addr);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_tcp_ack_traceroute_new() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        let result = TcpAckTraceroute::new(config, local_addr);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_generate_source_port() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let port = traceroute.generate_source_port();
            assert!(port >= 50000);
            assert!(port < 51000);
        }
    }

    #[test]
    fn test_source_port_configured_syn() {
        let config = TracerouteConfig::new().with_source_port(12345);
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let port = traceroute.generate_source_port();
            assert_eq!(port, 12345);
        }
    }

    #[test]
    fn test_source_port_configured_ack() {
        let config = TracerouteConfig::new().with_source_port(12345);
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let port = traceroute.generate_source_port();
            assert_eq!(port, 12345);
        }
    }

    // Tests for TcpSynTraceroute::handle_tcp_response

    #[test]
    fn test_syn_traceroute_handle_tcp_response_syn_ack() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) {
            traceroute.sequence = 1000; // Set known sequence number
            let expected_ack = 1001; // sequence + 1

            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build SYN-ACK response (flags 0x12 = SYN + ACK)
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                5000,         // seq
                expected_ack, // ack = our sequence + 1
                0x12,         // SYN + ACK flags
            );

            let response = traceroute
                .handle_tcp_response(&packet, target_ip, dest_port)
                .expect("should parse SYN-ACK response");

            assert_eq!(response.ip(), target_ip);
            assert_eq!(response.icmp_type(), 6); // TCP type
            assert_eq!(response.icmp_code(), 0);
            assert!(response.is_destination());
        }
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_rst() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) {
            traceroute.sequence = 2000;
            let expected_ack = 2001;

            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 443;

            // Build RST response (flags 0x04 = RST)
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                0,            // seq doesn't matter for RST
                expected_ack, // ack = our sequence + 1
                0x04,         // RST flag
            );

            let response = traceroute
                .handle_tcp_response(&packet, target_ip, dest_port)
                .expect("should parse RST response");

            assert_eq!(response.ip(), target_ip);
            assert_eq!(response.icmp_type(), 6); // TCP type
            assert_eq!(response.icmp_code(), 1); // RST code
            assert!(response.is_destination());
        }
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_wrong_source_port() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) {
            traceroute.sequence = 3000;
            let expected_ack = 3001;

            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let expected_port = 80;
            let wrong_port = 8080;

            // Build packet with wrong source port
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                wrong_port, // Wrong source port
                traceroute.generate_source_port(),
                5000,
                expected_ack,
                0x12, // SYN + ACK
            );

            let response = traceroute.handle_tcp_response(&packet, target_ip, expected_port);
            assert!(
                response.is_none(),
                "should reject packet with wrong source port"
            );
        }
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_wrong_ack_number() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) {
            traceroute.sequence = 4000;
            let wrong_ack = 9999; // Not sequence + 1

            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build packet with wrong ACK number
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                5000,
                wrong_ack, // Wrong ACK
                0x12,      // SYN + ACK
            );

            let response = traceroute.handle_tcp_response(&packet, target_ip, dest_port);
            assert!(
                response.is_none(),
                "should reject packet with wrong ACK number"
            );
        }
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_packet_too_short() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Packet with only 19 bytes (less than 20 needed for IP header)
            let short_packet = vec![0u8; 19];
            let response = traceroute.handle_tcp_response(&short_packet, target_ip, dest_port);
            assert!(
                response.is_none(),
                "should reject packet too short for IP header"
            );
        }
    }

    // Tests for TcpAckTraceroute::handle_tcp_response

    #[test]
    fn test_ack_traceroute_handle_tcp_response_rst() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build RST response
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                0,
                0,    // ACK doesn't matter for ACK traceroute
                0x04, // RST flag
            );

            let response = traceroute
                .handle_tcp_response(&packet, target_ip, dest_port)
                .expect("should parse RST response");

            assert_eq!(response.ip(), target_ip);
            assert_eq!(response.icmp_type(), 6); // TCP type
            assert_eq!(response.icmp_code(), 1); // RST code
            assert!(response.is_destination());
        }
    }

    #[test]
    fn test_ack_traceroute_handle_tcp_response_wrong_source_port() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let expected_port = 80;
            let wrong_port = 8080;

            // Build packet with wrong source port
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                wrong_port, // Wrong source port
                traceroute.generate_source_port(),
                0,
                0,
                0x04, // RST
            );

            let response = traceroute.handle_tcp_response(&packet, target_ip, expected_port);
            assert!(
                response.is_none(),
                "should reject packet with wrong source port"
            );
        }
    }

    #[test]
    fn test_ack_traceroute_handle_tcp_response_no_rst_flag() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build SYN-ACK packet (no RST flag)
            let packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                5000,
                0,
                0x12, // SYN + ACK (no RST)
            );

            let response = traceroute.handle_tcp_response(&packet, target_ip, dest_port);
            assert!(
                response.is_none(),
                "should return None for non-RST response to ACK probe"
            );
        }
    }

    // Tests for handle_icmp_response - TcpSynTraceroute

    #[test]
    fn test_syn_traceroute_handle_icmp_response_time_exceeded_matching() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Build ICMP Time Exceeded with matching original destination
            let packet = build_icmp_time_exceeded_packet(router_ip, target_ip, dest_port, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Time Exceeded");

            assert_eq!(response.ip(), router_ip);
            assert_eq!(response.icmp_type(), 11); // Time Exceeded
            assert_eq!(response.icmp_code(), 0);
            assert!(!response.is_destination());
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_time_exceeded_non_matching() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let expected_target = Ipv4Addr::new(8, 8, 8, 8);
            let other_target = Ipv4Addr::new(1, 1, 1, 1);
            let dest_port = 80;

            // Build ICMP Time Exceeded with different original destination
            let packet = build_icmp_time_exceeded_packet(router_ip, other_target, dest_port, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response =
                traceroute.handle_icmp_response(icmp_resp, expected_target, dest_port, &packet);
            assert!(
                response.is_none(),
                "should return None for non-matching target"
            );
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_destination_unreachable() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Build ICMP Destination Unreachable (code 1 = Host Unreachable)
            let packet =
                build_icmp_destination_unreachable_packet(router_ip, target_ip, dest_port, 1);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Destination Unreachable");

            assert_eq!(response.ip(), router_ip);
            assert_eq!(response.icmp_type(), 3); // Destination Unreachable
            assert_eq!(response.icmp_code(), 1); // Host Unreachable
            assert!(!response.is_destination()); // router_ip != target_ip
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_other_type() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let responder_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Build ICMP Echo Reply (type 0) - not relevant for traceroute
            let packet = build_icmp_other_packet(responder_ip, 0, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response =
                traceroute.handle_icmp_response(icmp_resp, target_ip, dest_port, &packet);
            assert!(
                response.is_none(),
                "should return None for other ICMP types"
            );
        }
    }

    // Tests for handle_icmp_response - TcpAckTraceroute

    #[test]
    fn test_ack_traceroute_handle_icmp_response_time_exceeded_matching() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 443;

            let packet = build_icmp_time_exceeded_packet(router_ip, target_ip, dest_port, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Time Exceeded");

            assert_eq!(response.ip(), router_ip);
            assert_eq!(response.icmp_type(), 11);
            assert_eq!(response.icmp_code(), 0);
            assert!(!response.is_destination());
        }
    }

    #[test]
    fn test_ack_traceroute_handle_icmp_response_time_exceeded_non_matching() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let expected_target = Ipv4Addr::new(8, 8, 8, 8);
            let other_target = Ipv4Addr::new(1, 1, 1, 1);
            let dest_port = 443;

            let packet = build_icmp_time_exceeded_packet(router_ip, other_target, dest_port, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response =
                traceroute.handle_icmp_response(icmp_resp, expected_target, dest_port, &packet);
            assert!(response.is_none());
        }
    }

    #[test]
    fn test_ack_traceroute_handle_icmp_response_destination_unreachable() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 443;

            // Build ICMP Destination Unreachable (code 3 = Port Unreachable)
            let packet =
                build_icmp_destination_unreachable_packet(router_ip, target_ip, dest_port, 3);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Destination Unreachable");

            assert_eq!(response.ip(), router_ip);
            assert_eq!(response.icmp_type(), 3);
            assert_eq!(response.icmp_code(), 3); // Port Unreachable
        }
    }

    #[test]
    fn test_ack_traceroute_handle_icmp_response_other_type() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let responder_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 443;

            // Build ICMP Redirect (type 5)
            let packet = build_icmp_other_packet(responder_ip, 5, 0);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response =
                traceroute.handle_icmp_response(icmp_resp, target_ip, dest_port, &packet);
            assert!(response.is_none());
        }
    }

    // Packet boundary condition tests

    #[test]
    fn test_parse_tcp_response_empty_packet() {
        let empty_packet: Vec<u8> = vec![];
        let result = parse_tcp_response(&empty_packet);
        assert!(result.is_none(), "should return None for empty packet");
    }

    #[test]
    fn test_parse_tcp_response_packet_less_than_40_bytes() {
        // Packet with 39 bytes (less than minimum 40 for IP + TCP headers)
        let short_packet = vec![0u8; 39];
        let result = parse_tcp_response(&short_packet);
        assert!(result.is_none(), "should return None for packet < 40 bytes");
    }

    #[test]
    fn test_parse_tcp_response_packet_20_bytes() {
        // Exactly 20 bytes (IP header only, no TCP)
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 6; // TCP protocol

        let result = parse_tcp_response(&packet);
        assert!(
            result.is_none(),
            "should return None for packet with only IP header"
        );
    }

    #[test]
    fn test_parse_icmp_response_empty_packet() {
        let empty_packet: Vec<u8> = vec![];
        let result = parse_icmp_response(&empty_packet);
        assert!(result.is_none(), "should return None for empty ICMP packet");
    }

    #[test]
    fn test_parse_icmp_response_packet_less_than_28_bytes() {
        // Packet with 27 bytes (less than minimum 28 for IP + ICMP headers)
        let short_packet = vec![0u8; 27];
        let result = parse_icmp_response(&short_packet);
        assert!(
            result.is_none(),
            "should return None for ICMP packet < 28 bytes"
        );
    }

    #[test]
    fn test_parse_icmp_response_packet_20_bytes() {
        // Exactly 20 bytes (IP header only, no ICMP)
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 1; // ICMP protocol

        let result = parse_icmp_response(&packet);
        assert!(
            result.is_none(),
            "should return None for packet with only IP header"
        );
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_invalid_ip_version() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build packet with IP version 6 instead of 4
            let mut packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                5000,
                traceroute.sequence.wrapping_add(1),
                0x12,
            );
            packet[0] = 0x65; // Version 6, IHL 5

            let response = traceroute.handle_tcp_response(&packet, target_ip, dest_port);
            assert!(
                response.is_none(),
                "should reject packet with wrong IP version"
            );
        }
    }

    #[test]
    fn test_ack_traceroute_handle_tcp_response_packet_too_short() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Packet with only 19 bytes
            let short_packet = vec![0u8; 19];
            let response = traceroute.handle_tcp_response(&short_packet, target_ip, dest_port);
            assert!(response.is_none(), "should reject packet too short");
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_packet_too_short() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Packet with only 19 bytes
            let short_packet = vec![0u8; 19];
            let icmp_resp = IcmpResponse::TimeExceeded {
                code: 0,
                original_dst_ip: target_ip,
                original_dst_port: dest_port,
            };

            let response =
                traceroute.handle_icmp_response(icmp_resp, target_ip, dest_port, &short_packet);
            assert!(
                response.is_none(),
                "should return None for packet too short to extract responder IP"
            );
        }
    }

    #[test]
    fn test_ack_traceroute_handle_icmp_response_packet_too_short() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpAckTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 443;

            // Packet with only 19 bytes
            let short_packet = vec![0u8; 19];
            let icmp_resp = IcmpResponse::DestinationUnreachable {
                code: IcmpUnreachableCode::PortUnreachable,
                original_dst_ip: target_ip,
                original_dst_port: dest_port,
            };

            let response =
                traceroute.handle_icmp_response(icmp_resp, target_ip, dest_port, &short_packet);
            assert!(
                response.is_none(),
                "should return None for packet too short"
            );
        }
    }

    #[test]
    fn test_syn_traceroute_handle_tcp_response_non_tcp_protocol() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) {
            traceroute.sequence = 5000;
            let expected_ack = 5001;

            let target_ip = Ipv4Addr::new(192, 168, 1, 100);
            let dest_port = 80;

            // Build packet with UDP protocol instead of TCP
            let mut packet = build_tcp_packet(
                target_ip,
                local_addr,
                dest_port,
                traceroute.generate_source_port(),
                5000,
                expected_ack,
                0x12,
            );
            packet[9] = 17; // UDP protocol instead of TCP

            let response = traceroute.handle_tcp_response(&packet, target_ip, dest_port);
            assert!(
                response.is_none(),
                "should reject packet with non-TCP protocol"
            );
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_fragment_reassembly() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let router_ip = Ipv4Addr::new(192, 168, 1, 1);
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Build ICMP Time Exceeded with code 1 (Fragment reassembly time exceeded)
            let packet = build_icmp_time_exceeded_packet(router_ip, target_ip, dest_port, 1);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Time Exceeded");

            assert_eq!(response.ip(), router_ip);
            assert_eq!(response.icmp_type(), 11);
            // Note: ProbeResponse::time_exceeded hardcodes code to 0
            assert_eq!(response.icmp_code(), 0);
            assert!(!response.is_destination());
        }
    }

    #[test]
    fn test_syn_traceroute_handle_icmp_response_destination_unreachable_from_target() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        if let Ok(traceroute) = TcpSynTraceroute::new(config, local_addr) {
            let target_ip = Ipv4Addr::new(8, 8, 8, 8);
            let dest_port = 80;

            // Build ICMP Destination Unreachable from the target itself
            let packet =
                build_icmp_destination_unreachable_packet(target_ip, target_ip, dest_port, 3);

            let icmp_resp = parse_icmp_response(&packet).expect("should parse ICMP");
            let response = traceroute
                .handle_icmp_response(icmp_resp, target_ip, dest_port, &packet)
                .expect("should handle Destination Unreachable");

            assert_eq!(response.ip(), target_ip);
            assert_eq!(response.icmp_type(), 3);
            assert_eq!(response.icmp_code(), 3);
            assert!(response.is_destination()); // responder_ip == target_ip
        }
    }
}
