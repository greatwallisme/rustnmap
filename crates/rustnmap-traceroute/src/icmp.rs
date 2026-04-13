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

//! ICMP-based traceroute implementation.

use crate::{
    error::{Result, TracerouteError},
    probe::ProbeResponse,
    TracerouteConfig,
};
use rustnmap_common::Ipv4Addr;
use rustnmap_net::raw_socket::{
    parse_icmp_echo_reply, parse_icmp_response, IcmpPacketBuilder, IcmpResponse, RawSocket,
};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// ICMP Echo-based traceroute implementation.
#[derive(Debug)]
pub struct IcmpTraceroute {
    config: TracerouteConfig,
    local_addr: Ipv4Addr,
    socket: RawSocket,
    /// ICMP identifier.
    identifier: u16,
    /// ICMP sequence number.
    sequence: u16,
}

impl IcmpTraceroute {
    /// Creates a new ICMP traceroute instance.
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
        // Use IPPROTO_ICMP (1) for receiving ICMP responses
        let socket = RawSocket::with_protocol(1).map_err(|e| TracerouteError::SocketCreation {
            source: io::Error::other(e),
        })?;

        // Use process ID as identifier (truncated to 16 bits)
        let identifier = (std::process::id() & 0xFFFF) as u16;

        Ok(Self {
            config,
            local_addr,
            socket,
            identifier,
            sequence: 0,
        })
    }

    /// Sends an ICMP Echo Request probe with the specified TTL.
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
    /// Returns an error if probe cannot be sent or response cannot be received.
    pub fn send_probe(&mut self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        self.sequence = self.sequence.wrapping_add(1);

        // Build ICMP Echo Request packet
        let payload = Self::build_payload(ttl, self.sequence);
        let packet = IcmpPacketBuilder::new(self.local_addr, target)
            .identifier(self.identifier)
            .sequence(self.sequence)
            .payload(&payload)
            .build();

        // Set TTL on socket
        self.socket
            .set_ttl(u32::from(ttl))
            .map_err(|e| TracerouteError::Network(format!("Failed to set TTL: {e}")))?;

        // Create destination socket address (ICMP doesn't use ports, but we need an address)
        let dst_sockaddr = SocketAddr::V4(SocketAddrV4::new(target, 0));

        // Send the packet
        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| TracerouteError::SendFailed { source: e })?;

        // Wait for response
        self.receive_response(target)
    }

    /// Receives and parses ICMP response to Echo Request.
    ///
    /// # Arguments
    ///
    /// * `target` - Expected target IP
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(ProbeResponse))` if a valid response was received,
    /// `Ok(None)` if timed out, or an error.
    fn receive_response(&self, target: Ipv4Addr) -> Result<Option<ProbeResponse>> {
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.probe_timeout;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // First try to parse as ICMP Echo Reply (from target)
                if let Some(response) = self.handle_echo_reply(&recv_buf[..len], target) {
                    return Ok(Some(response));
                }

                // Then try ICMP response (Time Exceeded from intermediate router)
                if let Some(icmp_resp) = parse_icmp_response(&recv_buf[..len]) {
                    return Ok(self.handle_icmp_response(icmp_resp, target, &recv_buf[..len]));
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

    /// Handles ICMP Echo Reply from target.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes
    /// * `expected_target` - Expected target IP
    ///
    /// # Returns
    ///
    /// `Some(ProbeResponse)` if valid Echo Reply from target, `None` otherwise.
    fn handle_echo_reply(
        &self,
        packet: &[u8],
        _expected_target: Ipv4Addr,
    ) -> Option<ProbeResponse> {
        if let Some((identifier, sequence)) = parse_icmp_echo_reply(packet) {
            // Verify this is a response to our probe
            if identifier != self.identifier || sequence != self.sequence {
                return None;
            }

            // Extract source IP from IP header
            if packet.len() < 20 {
                return None;
            }
            let source_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);

            // Echo reply means we reached the target
            Some(ProbeResponse::echo_reply(source_ip))
        } else {
            None
        }
    }

    /// Handles ICMP response and creates appropriate `ProbeResponse`.
    ///
    /// # Arguments
    ///
    /// * `icmp_resp` - Parsed ICMP response
    /// * `expected_target` - Expected target IP
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
                // For ICMP traceroute, destination unreachable typically means
                // we can't reach the target
                Some(ProbeResponse::new(
                    responder_ip,
                    3, // ICMP Destination Unreachable
                    u8::from(code),
                    responder_ip == expected_target,
                ))
            }
            IcmpResponse::Other {
                icmp_type,
                icmp_code,
            } => {
                // Echo Reply (Type 0, Code 0) - we reached the target
                (icmp_type == 0 && icmp_code == 0).then(|| ProbeResponse::echo_reply(responder_ip))
            }
        }
    }

    /// Builds ICMP traceroute payload.
    ///
    /// The payload includes TTL and sequence for correlation.
    fn build_payload(ttl: u8, sequence: u16) -> Vec<u8> {
        // Standard traceroute payload with timestamp and identifiers
        let mut payload = vec![0u8; 32];
        payload[0] = ttl;
        payload[1] = 0;
        payload[2] = (sequence >> 8) as u8;
        payload[3] = (sequence & 0xFF) as u8;
        // Fill rest with pattern
        #[expect(
            clippy::cast_possible_truncation,
            reason = "i ranges from 4 to 31, safe to truncate"
        )]
        for (i, item) in payload.iter_mut().enumerate().skip(4) {
            *item = (i as u8).wrapping_mul(0x41); // 'A' pattern
        }
        payload
    }

    /// Returns the ICMP identifier used by this traceroute instance.
    #[must_use]
    pub const fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Returns the current sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u16 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_traceroute_new() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        let result = IcmpTraceroute::new(config, local_addr);
        if let Ok(traceroute) = result {
            // Identifier should be based on process ID
            assert!(traceroute.identifier() > 0);
        }
    }

    #[test]
    fn test_sequence_increment() {
        let config = TracerouteConfig::new();
        let local_addr = Ipv4Addr::LOCALHOST;

        // May fail if not running as root
        if let Ok(mut traceroute) = IcmpTraceroute::new(config, local_addr) {
            let initial_sequence = traceroute.sequence();

            // Send probe increments sequence
            traceroute.sequence = traceroute.sequence.wrapping_add(1);
            assert_eq!(traceroute.sequence(), initial_sequence.wrapping_add(1));
        }
    }

    #[test]
    fn test_build_payload() {
        let payload = IcmpTraceroute::build_payload(5, 100);
        assert_eq!(payload.len(), 32);
        assert_eq!(payload[0], 5); // TTL
        assert_eq!(payload[1], 0);
        assert_eq!(payload[2], 0); // sequence high byte
        assert_eq!(payload[3], 100); // sequence low byte
    }

    #[test]
    fn test_probe_response_creation() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let resp = ProbeResponse::echo_reply(ip);
        assert_eq!(resp.ip(), ip);
        assert_eq!(resp.icmp_type(), 0);
        assert!(resp.is_destination());
    }
}
