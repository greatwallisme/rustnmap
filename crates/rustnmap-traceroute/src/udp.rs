// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! UDP traceroute implementation.

use crate::{
    error::{Result, TracerouteError},
    probe::ProbeResponse,
    TracerouteConfig,
};
use rustnmap_common::Ipv4Addr;
use rustnmap_net::raw_socket::{parse_icmp_response, IcmpResponse, RawSocket, UdpPacketBuilder};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// UDP-based traceroute implementation.
#[derive(Debug)]
pub struct UdpTraceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
    /// Socket for sending UDP probes.
    send_socket: RawSocket,
    /// Socket for receiving ICMP responses (Time Exceeded, Port Unreachable).
    recv_socket: RawSocket,
    /// Base destination port (incremented per probe).
    base_dest_port: u16,
    /// Sequence number for probes.
    sequence: u16,
}

impl UdpTraceroute {
    /// Creates a new UDP traceroute instance.
    ///
    /// # Arguments
    ///
    /// * `config` - Traceroute configuration
    /// * `local_addr` - Local IP address to use for probes
    ///
    /// # Errors
    ///
    /// Returns an error if socket creation fails.
    pub fn new(config: TracerouteConfig, local_addr: Ipv4Addr) -> Result<Self> {
        // Use IPPROTO_UDP (17) for sending probes
        let send_socket =
            RawSocket::with_protocol(17).map_err(|e| TracerouteError::SocketCreation {
                source: io::Error::other(e),
            })?;
        // Use IPPROTO_ICMP (1) for receiving ICMP responses (Time Exceeded, Port Unreachable)
        let recv_socket =
            RawSocket::with_protocol(1).map_err(|e| TracerouteError::SocketCreation {
                source: io::Error::other(e),
            })?;

        Ok(Self {
            config,
            local_addr,
            send_socket,
            recv_socket,
            base_dest_port: 33434,
            sequence: 0,
        })
    }

    /// Sets the base destination port.
    ///
    /// The default `base_port` is 33434. Each probe will use `base_port` + sequence.
    #[must_use]
    pub const fn with_base_port(mut self, port: u16) -> Self {
        self.base_dest_port = port;
        self
    }

    /// Sends a single UDP probe with the specified TTL and waits for response.
    ///
    /// # Arguments
    ///
    /// * `target` - Target IP address
    /// * `ttl` - Time-to-live value for this probe
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a response was received,
    /// `Ok(None)` if the probe timed out, or an error if sending failed.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub fn send_probe(&mut self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        self.sequence = self.sequence.wrapping_add(1);

        // Calculate destination port (base + sequence)
        let dest_port = self.base_dest_port.wrapping_add(self.sequence);

        // Generate source port
        let src_port = self.generate_source_port();

        // Build UDP packet with traceroute payload
        let payload = Self::build_payload(ttl, self.sequence);
        let packet = UdpPacketBuilder::new(self.local_addr, target, src_port, dest_port)
            .payload(&payload)
            .build();

        // Set TTL on send socket
        self.send_socket
            .set_ttl(u32::from(ttl))
            .map_err(|e| TracerouteError::Network(format!("Failed to set TTL: {e}")))?;

        // Create destination socket address
        let dst_sockaddr = SocketAddr::V4(SocketAddrV4::new(target, dest_port));

        // Send the packet via UDP socket
        self.send_socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| TracerouteError::SendFailed { source: e })?;

        // Wait for response on ICMP socket
        self.receive_response(target, dest_port)
    }

    /// Receives and parses ICMP response to UDP probe.
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
            .recv_socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Try to parse ICMP response
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(
                        icmp_resp,
                        target,
                        dest_port,
                        &recv_buf[..len],
                    ));
                }

                // No recognizable ICMP response
                Ok(None)
            }
            Ok(_) => Ok(None),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout - no response
                Ok(None)
            }
            Err(e) => Err(TracerouteError::ReceiveFailed { source: e }),
        }
    }

    /// Handles ICMP response and creates appropriate `ProbeResponse`.
    ///
    /// # Arguments
    ///
    /// * `icmp_resp` - Parsed ICMP response
    /// * `expected_target` - Expected target IP
    /// * `expected_port` - Expected destination port
    /// * `packet` - Raw packet bytes for extracting source IP
    ///
    /// # Returns
    ///
    /// `Some(ProbeResponse)` if valid response for our probe, `None` otherwise.
    #[allow(clippy::unused_self, reason = "Instance method for API consistency")]
    fn handle_icmp_response(
        &self,
        icmp_resp: IcmpResponse,
        expected_target: Ipv4Addr,
        expected_port: u16,
        packet: &[u8],
    ) -> Option<ProbeResponse> {
        // Extract source IP from the IP header (bytes 12-15)
        if packet.len() < 20 {
            return None;
        }
        let responder_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

        match icmp_resp {
            IcmpResponse::TimeExceeded {
                original_dst_ip,
                original_dst_port,
                ..
            } => {
                // Verify this response is for our probe
                (original_dst_ip == expected_target
                    && (original_dst_port == expected_port || original_dst_port == 0))
                    .then(|| ProbeResponse::time_exceeded(responder_ip))
            }
            IcmpResponse::DestinationUnreachable {
                code,
                original_dst_ip,
                original_dst_port,
            } => {
                // Verify this response is for our probe
                (original_dst_ip == expected_target && original_dst_port == expected_port).then(
                    || {
                        // Port unreachable means we reached the destination
                        let is_destination = matches!(
                            code,
                            rustnmap_net::raw_socket::IcmpUnreachableCode::PortUnreachable
                        );
                        ProbeResponse::new(
                            responder_ip,
                            3, // ICMP Destination Unreachable
                            u8::from(code),
                            is_destination,
                        )
                    },
                )
            }
            IcmpResponse::Other {
                icmp_type,
                icmp_code,
            } => {
                // For traceroute, we only care about Time Exceeded (11) and Destination Unreachable (3)
                // Echo Reply (0) would indicate the target responded directly (unlikely for UDP)
                // Echo reply - this would be unusual for UDP traceroute
                (icmp_type == 0 && icmp_code == 0).then(|| {
                    ProbeResponse::new(
                        responder_ip,
                        icmp_type,
                        icmp_code,
                        responder_ip == expected_target,
                    )
                })
            }
        }
    }

    /// Builds traceroute payload.
    ///
    /// Traditional traceroute uses a payload that can help identify
    /// the probe. We include TTL and sequence for correlation.
    fn build_payload(ttl: u8, sequence: u16) -> Vec<u8> {
        // Simple payload with TTL and sequence
        vec![ttl, 0, (sequence >> 8) as u8, (sequence & 0xFF) as u8]
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
    fn test_udp_traceroute_new() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        let result = UdpTraceroute::new(config, local_addr);
        if let Ok(traceroute) = result {
            assert_eq!(traceroute.local_addr, local_addr);
            assert_eq!(traceroute.base_dest_port, 33434);
        }
    }

    #[test]
    fn test_udp_traceroute_with_base_port() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        let result = UdpTraceroute::new(config, local_addr);
        if let Ok(traceroute) = result {
            let traceroute = traceroute.with_base_port(40125);
            assert_eq!(traceroute.base_dest_port, 40125);
        }
    }

    #[test]
    fn test_build_payload() {
        let payload = UdpTraceroute::build_payload(5, 100);
        assert_eq!(payload.len(), 4);
        assert_eq!(payload[0], 5); // TTL
        assert_eq!(payload[1], 0);
        assert_eq!(payload[2], 0); // sequence high byte
        assert_eq!(payload[3], 100); // sequence low byte
    }

    #[test]
    fn test_generate_source_port() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(traceroute) = UdpTraceroute::new(config, local_addr) {
            let port = traceroute.generate_source_port();
            assert!(port >= 50000);
            assert!(port < 51000);
        }
    }

    #[test]
    fn test_source_port_configured() {
        let config = TracerouteConfig::new().with_source_port(12345);
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(traceroute) = UdpTraceroute::new(config, local_addr) {
            let port = traceroute.generate_source_port();
            assert_eq!(port, 12345);
        }
    }

    #[test]
    fn test_probe_response_creation() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let resp = ProbeResponse::time_exceeded(ip);
        assert_eq!(resp.ip(), ip);
        assert_eq!(resp.icmp_type(), 11);
        assert!(!resp.is_destination());
    }
}
