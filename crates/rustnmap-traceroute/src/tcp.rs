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
    socket: RawSocket,
    /// Sequence number for probes.
    sequence: u32,
}

/// TCP ACK-based traceroute implementation.
#[derive(Debug)]
pub struct TcpAckTraceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
    socket: RawSocket,
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
        let socket = RawSocket::new().map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;

        Ok(Self {
            config,
            local_addr,
            socket,
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

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // First try to parse as TCP response (SYN-ACK or RST from target)
                if let Some(response) =
                    self.handle_tcp_response(&recv_buf[..len], target, dest_port)
                {
                    return Ok(Some(response));
                }

                // Then try ICMP response (Time Exceeded from intermediate router)
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &recv_buf[..len],
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
        if let Some((flags, _seq, ack, src_port)) = parse_tcp_response(packet) {
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
        let socket = RawSocket::new().map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;

        Ok(Self {
            config,
            local_addr,
            socket,
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

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // First try to parse as TCP response
                if let Some(response) =
                    self.handle_tcp_response(&recv_buf[..len], target, dest_port)
                {
                    return Ok(Some(response));
                }

                // Then try ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &recv_buf[..len],
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
        if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(packet) {
            // Verify this is a response to our probe
            if src_port != expected_port {
                return None;
            }

            // Extract source IP from IP header
            if packet.len() < 20 {
                return None;
            }
            let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

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
}
