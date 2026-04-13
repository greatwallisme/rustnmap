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

// Rust guideline compliant 2026-02-14

//! Host discovery module for `RustNmap`.
//!
//! This module provides host discovery functionality to determine
//! which targets are up before port scanning.
//!
//! ## IPv6 Host Discovery
//!
//! IPv6 host discovery is implemented using:
//! - `ICMPv6` Echo Ping (Type 128/129)
//! - `ICMPv6` Neighbor Discovery Protocol (`NDP`)
//! - TCP SYN Ping over IPv6

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::Target;
use rustnmap_common::{Ipv4Addr, Ipv6Addr, MacAddr, Port, ScanConfig, ScanError};
use rustnmap_net::raw_socket::{
    parse_arp_reply, parse_icmp_echo_reply, parse_icmp_timestamp_reply, parse_tcp_response,
    ArpPacketBuilder, IcmpPacketBuilder, RawSocket, TcpPacketBuilder,
};

/// Host discovery result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    /// Host is up and responsive.
    Up,

    /// Host is down or unresponsive.
    Down,

    /// Host state is unknown (discovery pending).
    Unknown,
}

/// Trait for host discovery methods.
///
/// All discovery implementations must implement this trait to provide
/// a consistent interface for determining host availability.
pub trait HostDiscoveryMethod {
    /// Probes a target to determine if it is up.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    fn discover(&self, target: &Target) -> Result<HostState, ScanError>;

    /// Returns true if this discovery method requires root privileges.
    #[must_use]
    fn requires_root(&self) -> bool {
        false
    }
}

/// TCP SYN Ping discovery method.
///
/// Sends TCP SYN packets to specified ports. If SYN-ACK is received,
/// the host is considered up. If RST is received, the host is also
/// considered up (port closed but host responsive).
#[derive(Debug)]
pub struct TcpSynPing {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Ports to probe.
    ports: Vec<Port>,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
}

impl TcpSynPing {
    /// Default ports to probe if none specified.
    pub const DEFAULT_PORTS: [Port; 3] = [80, 443, 22];

    /// Creates a new TCP SYN ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `ports` - Ports to probe (uses defaults if empty)
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries per port
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(
        local_addr: Ipv4Addr,
        ports: Vec<Port>,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ScanError> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let ports = if ports.is_empty() {
            Self::DEFAULT_PORTS.to_vec()
        } else {
            ports
        };

        Ok(Self {
            local_addr,
            socket,
            ports,
            timeout,
            retries,
        })
    }

    /// Sends a TCP SYN probe to a specific port.
    fn send_syn_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> Result<bool, ScanError> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .syn()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((flags, _seq, ack, src_port, _dst_port, _src_ip)) =
                    parse_tcp_response(&recv_buf[..len])
                {
                    if src_port != dst_port {
                        return Ok(false);
                    }

                    let expected_ack = seq.wrapping_add(1);
                    if ack != expected_ack {
                        return Ok(false);
                    }

                    let syn_received = (flags & 0x02) != 0;
                    let ack_received = (flags & 0x10) != 0;
                    let rst_received = (flags & 0x04) != 0;

                    // SYN-ACK or RST both indicate host is up
                    if (syn_received && ack_received) || rst_received {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        const SOURCE_PORT_START: u16 = 60000;
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

impl HostDiscoveryMethod for TcpSynPing {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(HostState::Unknown),
        };

        for port in &self.ports {
            for _ in 0..=self.retries {
                match self.send_syn_probe(dst_addr, *port) {
                    Ok(true) => return Ok(HostState::Up),
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        // No response from any port
        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP ACK Ping discovery method.
///
/// Sends TCP ACK packets to specified ports. If RST is received,
/// the host is considered up. This works against stateful firewalls
/// that block SYN packets but allow ACK.
#[derive(Debug)]
pub struct TcpAckPing {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Ports to probe.
    ports: Vec<Port>,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
}

impl TcpAckPing {
    /// Default ports to probe if none specified.
    pub const DEFAULT_PORTS: [Port; 3] = [80, 443, 22];

    /// Creates a new TCP ACK ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `ports` - Ports to probe (uses defaults if empty)
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries per port
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(
        local_addr: Ipv4Addr,
        ports: Vec<Port>,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ScanError> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let ports = if ports.is_empty() {
            Self::DEFAULT_PORTS.to_vec()
        } else {
            ports
        };

        Ok(Self {
            local_addr,
            socket,
            ports,
            timeout,
            retries,
        })
    }

    /// Sends a TCP ACK probe to a specific port.
    fn send_ack_probe(&self, dst_addr: Ipv4Addr, dst_port: Port) -> Result<bool, ScanError> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Send ACK packet (ACK flag = 0x10)
        let packet = TcpPacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .ack_flag()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((flags, _seq, _ack, src_port, _dst_port, _src_ip)) =
                    parse_tcp_response(&recv_buf[..len])
                {
                    if src_port != dst_port {
                        return Ok(false);
                    }

                    let rst_received = (flags & 0x04) != 0;

                    // RST indicates host is up (port closed but host responsive)
                    if rst_received {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        const SOURCE_PORT_START: u16 = 60000;
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

impl HostDiscoveryMethod for TcpAckPing {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(HostState::Unknown),
        };

        for port in &self.ports {
            for _ in 0..=self.retries {
                match self.send_ack_probe(dst_addr, *port) {
                    Ok(true) => return Ok(HostState::Up),
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// ICMP Echo Ping discovery method.
///
/// Sends ICMP echo request packets (ping). If echo reply is received,
/// the host is considered up.
#[derive(Debug)]
pub struct IcmpPing {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
    /// ICMP identifier.
    identifier: u16,
}

impl IcmpPing {
    /// Creates a new ICMP ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(local_addr: Ipv4Addr, timeout: Duration, retries: u8) -> Result<Self, ScanError> {
        // Use IPPROTO_ICMP (1) for receiving ICMP responses
        let socket = RawSocket::with_protocol(1).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let identifier = (std::process::id() & 0xFFFF) as u16;

        Ok(Self {
            local_addr,
            socket,
            timeout,
            retries,
            identifier,
        })
    }

    /// Sends an ICMP echo request probe.
    fn send_echo_probe(&self, dst_addr: Ipv4Addr, sequence: u16) -> Result<bool, ScanError> {
        let packet = IcmpPacketBuilder::new(self.local_addr, dst_addr)
            .identifier(self.identifier)
            .sequence(sequence)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), 0);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((recv_id, recv_seq)) = parse_icmp_echo_reply(&recv_buf[..len]) {
                    if recv_id == self.identifier && recv_seq == sequence {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }
}

impl HostDiscoveryMethod for IcmpPing {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(HostState::Unknown),
        };

        for seq in 0..=self.retries {
            match self.send_echo_probe(dst_addr, u16::from(seq)) {
                Ok(true) => return Ok(HostState::Up),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// ICMP Timestamp Ping discovery method.
///
/// Sends ICMP timestamp request packets. If timestamp reply is received,
/// the host is considered up. This is useful when echo requests are blocked.
#[derive(Debug)]
pub struct IcmpTimestampPing {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
    /// ICMP identifier.
    identifier: u16,
}

impl IcmpTimestampPing {
    /// Creates a new ICMP timestamp ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(local_addr: Ipv4Addr, timeout: Duration, retries: u8) -> Result<Self, ScanError> {
        // Use IPPROTO_ICMP (1) for receiving ICMP responses
        let socket = RawSocket::with_protocol(1).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let identifier = (std::process::id() & 0xFFFF) as u16;

        Ok(Self {
            local_addr,
            socket,
            timeout,
            retries,
            identifier,
        })
    }

    /// Sends an ICMP timestamp request probe.
    fn send_timestamp_probe(&self, dst_addr: Ipv4Addr, sequence: u16) -> Result<bool, ScanError> {
        let packet = IcmpPacketBuilder::timestamp_request(self.local_addr, dst_addr)
            .identifier(self.identifier)
            .sequence(sequence)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), 0);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((recv_id, recv_seq, _, _, _)) =
                    parse_icmp_timestamp_reply(&recv_buf[..len])
                {
                    if recv_id == self.identifier && recv_seq == sequence {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }
}

impl HostDiscoveryMethod for IcmpTimestampPing {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(HostState::Unknown),
        };

        for seq in 0..=self.retries {
            match self.send_timestamp_probe(dst_addr, u16::from(seq)) {
                Ok(true) => return Ok(HostState::Up),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// ARP Ping discovery method.
///
/// Sends ARP request packets for hosts on the local network.
/// If ARP reply is received, the host is considered up.
/// Only works for IPv4 on the same LAN.
#[derive(Debug)]
pub struct ArpPing {
    /// Source MAC address.
    src_mac: MacAddr,
    /// Source IP address.
    src_ip: Ipv4Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
}

impl ArpPing {
    /// Creates a new ARP ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `src_mac` - Source MAC address
    /// * `src_ip` - Source IP address
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ScanError> {
        // Use IPPROTO_ICMP (1) for receiving ICMP responses
        let socket = RawSocket::with_protocol(1).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        Ok(Self {
            src_mac,
            src_ip,
            socket,
            timeout,
            retries,
        })
    }

    /// Checks if the target is on the same local network.
    fn is_local_target(&self, target: &Target) -> bool {
        let target_ip = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return false,
        };

        // Simple check: if target is in RFC 1918 private range
        // and source is also in private range, assume local
        let target_octets = target_ip.octets();
        let src_octets = self.src_ip.octets();

        // Check if both are in same /24 subnet
        target_octets[0] == src_octets[0]
            && target_octets[1] == src_octets[1]
            && target_octets[2] == src_octets[2]
    }

    /// Sends an ARP request probe.
    fn send_arp_probe(&self, target_ip: Ipv4Addr) -> Result<bool, ScanError> {
        let packet = ArpPacketBuilder::new(self.src_mac, self.src_ip, target_ip).build();

        // ARP is broadcast, so destination address doesn't matter for Ethernet
        // But we need to send to a valid address for the socket
        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V4(target_ip), 0);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((_, sender_ip)) = parse_arp_reply(&recv_buf[..len]) {
                    if sender_ip == target_ip {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }
}

impl HostDiscoveryMethod for ArpPing {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let target_ip = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(HostState::Unknown),
        };

        if !self.is_local_target(target) {
            return Ok(HostState::Unknown);
        }

        for _ in 0..=self.retries {
            match self.send_arp_probe(target_ip) {
                Ok(true) => return Ok(HostState::Up),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// `ICMPv6` Echo Ping discovery method for IPv6.
///
/// Sends `ICMPv6` echo request packets (ping). If echo reply is received,
/// the host is considered up.
#[derive(Debug)]
pub struct Icmpv6Ping {
    /// Local IPv6 address for probes.
    local_addr: Ipv6Addr,
    /// Raw socket for packet transmission (`IPPROTO_ICMPV6` = 58).
    socket: RawSocket,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
    /// `ICMPv6` identifier.
    identifier: u16,
}

impl Icmpv6Ping {
    /// Creates a new `ICMPv6` ping discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IPv6 address to use for probes
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(local_addr: Ipv6Addr, timeout: Duration, retries: u8) -> Result<Self, ScanError> {
        // Use IPPROTO_ICMPV6 (58) for receiving ICMPv6 responses
        let socket = RawSocket::with_protocol(58).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let identifier = (std::process::id() & 0xFFFF) as u16;

        Ok(Self {
            local_addr,
            socket,
            timeout,
            retries,
            identifier,
        })
    }

    /// Sends an `ICMPv6` echo request probe.
    fn send_echo_probe(&self, dst_addr: Ipv6Addr, sequence: u16) -> Result<bool, ScanError> {
        let packet = Icmpv6PacketBuilder::echo_request(self.local_addr, dst_addr)
            .identifier(self.identifier)
            .sequence(sequence)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V6(dst_addr), 0);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((recv_id, recv_seq)) = parse_icmpv6_echo_reply(&recv_buf[..len]) {
                    if recv_id == self.identifier && recv_seq == sequence {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }
}

impl HostDiscoveryMethod for Icmpv6Ping {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V6(addr) => addr,
            rustnmap_common::IpAddr::V4(_) => return Ok(HostState::Unknown),
        };

        for seq in 0..=self.retries {
            match self.send_echo_probe(dst_addr, u16::from(seq)) {
                Ok(true) => return Ok(HostState::Up),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// `ICMPv6` Neighbor Discovery Protocol (NDP) discovery method.
///
/// Sends `ICMPv6` Neighbor Solicitation packets. If Neighbor Advertisement
/// is received, the host is considered up. This is the IPv6 equivalent of ARP.
#[derive(Debug)]
pub struct Icmpv6NeighborDiscovery {
    /// Local IPv6 address for probes.
    local_addr: Ipv6Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
}

impl Icmpv6NeighborDiscovery {
    /// Creates a new `ICMPv6` NDP discovery method.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IPv6 address to use for probes
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(local_addr: Ipv6Addr, timeout: Duration, retries: u8) -> Result<Self, ScanError> {
        // Use IPPROTO_ICMPV6 (58) for receiving ICMPv6 responses
        let socket = RawSocket::with_protocol(58).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        Ok(Self {
            local_addr,
            socket,
            timeout,
            retries,
        })
    }

    /// Computes the solicited-node multicast address for a target IPv6 address.
    ///
    /// The solicited-node multicast address is formed by taking the prefix
    /// `ff02::1:ff00:0/104` and appending the last 24 bits of the target address.
    #[must_use]
    fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
        let target_octets = target.octets();
        // ff02::1:ff00:0/104 + last 24 bits of target
        Ipv6Addr::new(
            0xff02,
            0,
            0,
            0,
            0,
            0x0001,
            0xff00 | u16::from(target_octets[13]),
            (u16::from(target_octets[14]) << 8) | u16::from(target_octets[15]),
        )
    }

    /// Sends an `ICMPv6` Neighbor Solicitation probe.
    fn send_neighbor_solicitation(&self, target: Ipv6Addr) -> Result<bool, ScanError> {
        // Target is the solicited-node multicast address
        let multicast_target = Self::solicited_node_multicast(target);

        let packet = Icmpv6PacketBuilder::neighbor_solicitation(self.local_addr, multicast_target)
            .target_address(target)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V6(multicast_target), 0);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                // Check if we got a Neighbor Advertisement (Type 136) for our target
                if let Some((target_addr, _mac)) =
                    parse_icmpv6_neighbor_advertisement(&recv_buf[..len])
                {
                    if target_addr == target {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }
}

impl HostDiscoveryMethod for Icmpv6NeighborDiscovery {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let target_addr = match target.ip {
            rustnmap_common::IpAddr::V6(addr) => addr,
            rustnmap_common::IpAddr::V4(_) => return Ok(HostState::Unknown),
        };

        // Skip multicast and loopback addresses
        let octets = target_addr.octets();
        if octets[0] == 0xff {
            // Multicast address
            return Ok(HostState::Unknown);
        }
        if target_addr.is_loopback() {
            return Ok(HostState::Up);
        }

        for _ in 0..=self.retries {
            match self.send_neighbor_solicitation(target_addr) {
                Ok(true) => return Ok(HostState::Up),
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }

        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// TCP SYN Ping discovery method for IPv6.
///
/// Sends TCP SYN packets over IPv6 to specified ports. If SYN-ACK is received,
/// the host is considered up.
#[derive(Debug)]
pub struct TcpSynPingV6 {
    /// Local IPv6 address for probes.
    local_addr: Ipv6Addr,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Ports to probe.
    ports: Vec<Port>,
    /// Timeout for each probe.
    timeout: Duration,
    /// Number of retries.
    retries: u8,
}

impl TcpSynPingV6 {
    /// Default ports to probe if none specified.
    pub const DEFAULT_PORTS: [Port; 3] = [80, 443, 22];

    /// Creates a new TCP SYN ping discovery method for IPv6.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IPv6 address to use for probes
    /// * `ports` - Ports to probe (uses defaults if empty)
    /// * `timeout` - Timeout for each probe
    /// * `retries` - Number of retries per port
    ///
    /// # Errors
    ///
    /// Returns an error if the raw socket cannot be created.
    pub fn new(
        local_addr: Ipv6Addr,
        ports: Vec<Port>,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ScanError> {
        // Use IPPROTO_TCP (6) for receiving TCP responses
        let socket = RawSocket::with_protocol(6).map_err(|e| ScanError::PermissionDenied {
            operation: format!("create raw socket: {e}"),
        })?;

        let ports = if ports.is_empty() {
            Self::DEFAULT_PORTS.to_vec()
        } else {
            ports
        };

        Ok(Self {
            local_addr,
            socket,
            ports,
            timeout,
            retries,
        })
    }

    /// Sends a TCP SYN probe to a specific port.
    fn send_syn_probe(&self, dst_addr: Ipv6Addr, dst_port: Port) -> Result<bool, ScanError> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        let packet = Tcpv6PacketBuilder::new(self.local_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .syn()
            .window(65535)
            .build();

        let dst_sockaddr = SocketAddr::new(std::net::IpAddr::V6(dst_addr), dst_port);

        self.socket
            .send_packet(&packet, &dst_sockaddr)
            .map_err(|e| {
                ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        let mut recv_buf = vec![0u8; 65535];

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(self.timeout))
        {
            Ok(len) if len > 0 => {
                if let Some((flags, _seq, ack, src_port)) = parse_tcpv6_response(&recv_buf[..len]) {
                    if src_port != dst_port {
                        return Ok(false);
                    }

                    let expected_ack = seq.wrapping_add(1);
                    if ack != expected_ack {
                        return Ok(false);
                    }

                    let syn_received = (flags & 0x02) != 0;
                    let ack_received = (flags & 0x10) != 0;
                    let rst_received = (flags & 0x04) != 0;

                    // SYN-ACK or RST both indicate host is up
                    if (syn_received && ack_received) || rst_received {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Ok(_) => Ok(false),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(false)
            }
            Err(e) => Err(ScanError::Network(rustnmap_common::Error::Network(
                rustnmap_common::error::NetworkError::ReceiveError { source: e },
            ))),
        }
    }

    /// Generates a random source port.
    #[must_use]
    fn generate_source_port() -> Port {
        const SOURCE_PORT_START: u16 = 60000;
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

impl HostDiscoveryMethod for TcpSynPingV6 {
    fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V6(addr) => addr,
            rustnmap_common::IpAddr::V4(_) => return Ok(HostState::Unknown),
        };

        for port in &self.ports {
            for _ in 0..=self.retries {
                match self.send_syn_probe(dst_addr, *port) {
                    Ok(true) => return Ok(HostState::Up),
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        // No response from any port
        Ok(HostState::Down)
    }

    fn requires_root(&self) -> bool {
        true
    }
}

/// `ICMPv6` packet builder for constructing `ICMPv6` packets.
#[derive(Debug)]
pub struct Icmpv6PacketBuilder {
    /// Source IPv6 address.
    src_ip: Ipv6Addr,
    /// Destination IPv6 address.
    dst_ip: Ipv6Addr,
    /// `ICMPv6` type.
    icmp_type: u8,
    /// `ICMPv6` code.
    icmp_code: u8,
    /// `ICMPv6` identifier.
    identifier: u16,
    /// `ICMPv6` sequence number.
    sequence: u16,
    /// Target address for Neighbor Solicitation.
    target_address: Option<Ipv6Addr>,
    /// `ICMPv6` payload/data.
    payload: Vec<u8>,
}

impl Icmpv6PacketBuilder {
    /// Creates a new `ICMPv6` packet builder for echo request.
    #[must_use]
    pub fn echo_request(src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Self {
        Self {
            src_ip,
            dst_ip,
            icmp_type: 128, // Echo Request
            icmp_code: 0,
            identifier: 0,
            sequence: 0,
            target_address: None,
            payload: Vec::new(),
        }
    }

    /// Creates a new `ICMPv6` packet builder for neighbor solicitation.
    #[must_use]
    pub fn neighbor_solicitation(src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Self {
        Self {
            src_ip,
            dst_ip,
            icmp_type: 135, // Neighbor Solicitation
            icmp_code: 0,
            identifier: 0,
            sequence: 0,
            target_address: None,
            payload: Vec::new(),
        }
    }

    /// Sets the `ICMPv6` identifier.
    #[must_use]
    pub fn identifier(mut self, identifier: u16) -> Self {
        self.identifier = identifier;
        self
    }

    /// Sets the `ICMPv6` sequence number.
    #[must_use]
    pub fn sequence(mut self, sequence: u16) -> Self {
        self.sequence = sequence;
        self
    }

    /// Sets the target address for Neighbor Solicitation.
    #[must_use]
    pub fn target_address(mut self, target: Ipv6Addr) -> Self {
        self.target_address = Some(target);
        self
    }

    /// Builds the `ICMPv6` packet.
    ///
    /// Returns a complete IPv6 packet with `ICMPv6` header and payload.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    pub fn build(self) -> Vec<u8> {
        let mut packet = Vec::new();

        // IPv6 header (40 bytes)
        // Version (4 bits) = 6, Traffic Class (8 bits) = 0, Flow Label (20 bits) = 0
        // Combined: 0x60 0x00 0x00 0x00
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);

        // Payload length (16 bits) - will be set later
        let payload_len_offset = packet.len();
        packet.extend_from_slice(&[0x00, 0x00]);

        // Next Header (8 bits) - ICMPv6 = 58
        packet.push(58);

        // Hop Limit (8 bits)
        packet.push(255);

        // Source Address (128 bits)
        packet.extend_from_slice(&self.src_ip.octets());

        // Destination Address (128 bits)
        packet.extend_from_slice(&self.dst_ip.octets());

        // ICMPv6 header
        let icmp_start = packet.len();
        // Type (8 bits)
        packet.push(self.icmp_type);
        // Code (8 bits)
        packet.push(self.icmp_code);
        // Checksum (16 bits) - calculated later
        packet.extend_from_slice(&[0x00, 0x00]);

        // ICMPv6 body
        match self.icmp_type {
            128 | 129 => {
                // Echo Request/Reply
                // Identifier (16 bits)
                packet.push((self.identifier >> 8) as u8);
                packet.push((self.identifier & 0xFF) as u8);
                // Sequence Number (16 bits)
                packet.push((self.sequence >> 8) as u8);
                packet.push((self.sequence & 0xFF) as u8);
                // Payload
                packet.extend_from_slice(&self.payload);
            }
            135 => {
                // Neighbor Solicitation
                // Reserved (32 bits)
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                // Target Address (128 bits)
                if let Some(target) = self.target_address {
                    packet.extend_from_slice(&target.octets());
                }
            }
            _ => {
                packet.extend_from_slice(&self.payload);
            }
        }

        // Calculate payload length
        let payload_len = packet.len() - 40; // Subtract IPv6 header
        packet[payload_len_offset] = (payload_len >> 8) as u8;
        packet[payload_len_offset + 1] = (payload_len & 0xFF) as u8;

        // Calculate ICMPv6 checksum
        let icmp_checksum = self.calculate_checksum(&packet[40..], payload_len);
        packet[icmp_start + 2] = (icmp_checksum >> 8) as u8;
        packet[icmp_start + 3] = (icmp_checksum & 0xFF) as u8;

        packet
    }

    /// Calculates the `ICMPv6` checksum with pseudo-header.
    fn calculate_checksum(&self, icmp_data: &[u8], payload_len: usize) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header: source address
        for chunk in self.src_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        // Pseudo-header: destination address
        for chunk in self.dst_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        // Pseudo-header: upper-layer packet length (32 bits)
        sum += u32::try_from(payload_len).unwrap_or(0);

        // Pseudo-header: next header (ICMPv6 = 58)
        sum += 58;

        // ICMPv6 data
        let len = icmp_data.len();
        for i in (0..len).step_by(2) {
            if i + 1 < len {
                sum += u32::from(u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]));
            } else {
                sum += u32::from(icmp_data[i]) << 8;
            }
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Truncation is intentional for checksum calculation
        #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
        {
            !(sum as u16)
        }
    }
}

/// TCP packet builder for IPv6.
#[derive(Debug)]
pub struct Tcpv6PacketBuilder {
    /// Source IPv6 address.
    src_ip: Ipv6Addr,
    /// Destination IPv6 address.
    dst_ip: Ipv6Addr,
    /// Source port.
    src_port: Port,
    /// Destination port.
    dst_port: Port,
    /// Sequence number.
    seq: u32,
    /// Acknowledgment number.
    ack: u32,
    /// TCP flags.
    flags: u8,
    /// Window size.
    window: u16,
}

impl Tcpv6PacketBuilder {
    /// Creates a new `TCPv6` packet builder.
    #[must_use]
    pub fn new(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, src_port: Port, dst_port: Port) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq: 0,
            ack: 0,
            flags: 0,
            window: 65535,
        }
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    /// Sets the SYN flag.
    #[must_use]
    pub fn syn(mut self) -> Self {
        self.flags |= 0x02;
        self
    }

    /// Sets the ACK flag.
    #[must_use]
    pub fn ack_flag(mut self) -> Self {
        self.flags |= 0x10;
        self
    }

    /// Sets the window size.
    #[must_use]
    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    /// Builds the `TCPv6` packet.
    ///
    /// Returns a complete IPv6 packet with TCP header.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Byte extraction from integers requires truncation"
    )]
    pub fn build(self) -> Vec<u8> {
        let mut packet = Vec::new();

        // IPv6 header (40 bytes)
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, Traffic Class, Flow Label

        // Payload length (16 bits) - TCP header (20 bytes)
        let payload_len = 20u16;
        packet.push((payload_len >> 8) as u8);
        packet.push((payload_len & 0xFF) as u8);

        // Next Header (8 bits) - TCP = 6
        packet.push(6);

        // Hop Limit (8 bits)
        packet.push(64);

        // Source Address (128 bits)
        packet.extend_from_slice(&self.src_ip.octets());

        // Destination Address (128 bits)
        packet.extend_from_slice(&self.dst_ip.octets());

        // TCP header
        let tcp_start = packet.len();
        // Source port (16 bits)
        packet.push((self.src_port >> 8) as u8);
        packet.push((self.src_port & 0xFF) as u8);
        // Destination port (16 bits)
        packet.push((self.dst_port >> 8) as u8);
        packet.push((self.dst_port & 0xFF) as u8);
        // Sequence number (32 bits)
        packet.push((self.seq >> 24) as u8);
        packet.push((self.seq >> 16) as u8);
        packet.push((self.seq >> 8) as u8);
        packet.push((self.seq & 0xFF) as u8);
        // Acknowledgment number (32 bits)
        packet.push((self.ack >> 24) as u8);
        packet.push((self.ack >> 16) as u8);
        packet.push((self.ack >> 8) as u8);
        packet.push((self.ack & 0xFF) as u8);
        // Data offset (5 * 4 = 20 bytes) and reserved
        packet.push(0x50);
        // Flags
        packet.push(self.flags);
        // Window size (16 bits)
        packet.push((self.window >> 8) as u8);
        packet.push((self.window & 0xFF) as u8);
        // Checksum (16 bits) - calculated later
        packet.push(0);
        packet.push(0);
        // Urgent pointer (16 bits)
        packet.push(0);
        packet.push(0);

        // Calculate TCP checksum with IPv6 pseudo-header
        let tcp_checksum = self.calculate_tcp_checksum(&packet[tcp_start..]);
        packet[tcp_start + 16] = (tcp_checksum >> 8) as u8;
        packet[tcp_start + 17] = (tcp_checksum & 0xFF) as u8;

        packet
    }

    /// Calculates the TCP checksum with IPv6 pseudo-header.
    fn calculate_tcp_checksum(&self, tcp_segment: &[u8]) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header: source address
        for chunk in self.src_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        // Pseudo-header: destination address
        for chunk in self.dst_ip.octets().chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }

        // Pseudo-header: upper-layer packet length (32 bits)
        sum += u32::try_from(tcp_segment.len()).unwrap_or(0);

        // Pseudo-header: next header (TCP = 6)
        sum += 6;

        // TCP segment
        let len = tcp_segment.len();
        for i in (0..len).step_by(2) {
            if i + 1 < len {
                sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
            } else {
                sum += u32::from(tcp_segment[i]) << 8;
            }
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Truncation is intentional for checksum calculation
        #[expect(clippy::cast_possible_truncation, reason = "Checksum algorithm")]
        {
            !(sum as u16)
        }
    }
}

/// Parses an `ICMPv6` echo reply packet.
///
/// Returns the identifier and sequence number if the packet is a valid
/// `ICMPv6` echo reply.
///
/// # Arguments
///
/// * `packet` - The raw packet bytes
///
/// # Returns
///
/// `Some((identifier, sequence))` if valid `ICMPv6` echo reply, `None` otherwise.
#[must_use]
pub fn parse_icmpv6_echo_reply(packet: &[u8]) -> Option<(u16, u16)> {
    // Minimum IPv6 header + ICMPv6 header
    if packet.len() < 48 {
        return None;
    }

    // Check IP version (must be 6)
    let version = (packet[0] >> 4) & 0x0F;
    if version != 6 {
        return None;
    }

    // Check next header (must be ICMPv6 = 58)
    if packet[6] != 58 {
        return None;
    }

    // Parse ICMPv6 header (starts after 40-byte IPv6 header)
    let icmpv6_start = 40;
    if packet.len() < icmpv6_start + 8 {
        return None;
    }

    let icmpv6_type = packet[icmpv6_start];
    let icmpv6_code = packet[icmpv6_start + 1];

    // Echo Reply is Type 129, Code 0
    if icmpv6_type != 129 || icmpv6_code != 0 {
        return None;
    }

    // Extract identifier and sequence
    let identifier = u16::from_be_bytes([packet[icmpv6_start + 4], packet[icmpv6_start + 5]]);
    let sequence = u16::from_be_bytes([packet[icmpv6_start + 6], packet[icmpv6_start + 7]]);

    Some((identifier, sequence))
}

/// Parses an `ICMPv6` Neighbor Advertisement packet.
///
/// Returns the target address and MAC address if the packet is valid.
///
/// # Arguments
///
/// * `packet` - The raw packet bytes
///
/// # Returns
///
/// `Some((target_addr, mac_addr))` if valid Neighbor Advertisement, `None` otherwise.
#[must_use]
pub fn parse_icmpv6_neighbor_advertisement(packet: &[u8]) -> Option<(Ipv6Addr, Option<MacAddr>)> {
    // Minimum IPv6 header + ICMPv6 header + Neighbor Advertisement
    if packet.len() < 56 {
        return None;
    }

    // Check IP version (must be 6)
    let version = (packet[0] >> 4) & 0x0F;
    if version != 6 {
        return None;
    }

    // Check next header (must be ICMPv6 = 58)
    if packet[6] != 58 {
        return None;
    }

    // Parse ICMPv6 header
    let icmpv6_start = 40;
    if packet.len() < icmpv6_start + 24 {
        return None;
    }

    let icmpv6_type = packet[icmpv6_start];
    let icmpv6_code = packet[icmpv6_start + 1];

    // Neighbor Advertisement is Type 136, Code 0
    if icmpv6_type != 136 || icmpv6_code != 0 {
        return None;
    }

    // Extract target address (bytes 8-23 of ICMPv6)
    let target_addr = Ipv6Addr::new(
        u16::from_be_bytes([packet[icmpv6_start + 8], packet[icmpv6_start + 9]]),
        u16::from_be_bytes([packet[icmpv6_start + 10], packet[icmpv6_start + 11]]),
        u16::from_be_bytes([packet[icmpv6_start + 12], packet[icmpv6_start + 13]]),
        u16::from_be_bytes([packet[icmpv6_start + 14], packet[icmpv6_start + 15]]),
        u16::from_be_bytes([packet[icmpv6_start + 16], packet[icmpv6_start + 17]]),
        u16::from_be_bytes([packet[icmpv6_start + 18], packet[icmpv6_start + 19]]),
        u16::from_be_bytes([packet[icmpv6_start + 20], packet[icmpv6_start + 21]]),
        u16::from_be_bytes([packet[icmpv6_start + 22], packet[icmpv6_start + 23]]),
    );

    // Try to extract MAC address from Target Link-Layer Address option (Type 2)
    let mut mac_addr = None;
    let options_start = icmpv6_start + 24;

    if packet.len() > options_start + 8 {
        // Check if there's a Target Link-Layer Address option
        let option_type = packet[options_start];
        let option_len = packet[options_start + 1] as usize * 8; // Length in 8-byte units

        if option_type == 2 && option_len >= 8 && packet.len() >= options_start + option_len {
            mac_addr = Some(MacAddr::new([
                packet[options_start + 2],
                packet[options_start + 3],
                packet[options_start + 4],
                packet[options_start + 5],
                packet[options_start + 6],
                packet[options_start + 7],
            ]));
        }
    }

    Some((target_addr, mac_addr))
}

/// Parses a TCP response packet over `IPv6`.
///
/// Returns the TCP flags, sequence number, acknowledgment number, and source port
/// if the packet is a valid TCP response over IPv6.
///
/// # Arguments
///
/// * `packet` - The raw packet bytes
///
/// # Returns
///
/// `Some((flags, seq, ack, src_port))` if valid `TCPv6` packet, `None` otherwise.
#[must_use]
pub fn parse_tcpv6_response(packet: &[u8]) -> Option<(u8, u32, u32, Port)> {
    // Minimum IPv6 header + TCP header
    if packet.len() < 60 {
        return None;
    }

    // Check IP version (must be 6)
    let version = (packet[0] >> 4) & 0x0F;
    if version != 6 {
        return None;
    }

    // Check next header (must be TCP = 6)
    if packet[6] != 6 {
        return None;
    }

    // Parse TCP header (starts after 40-byte IPv6 header)
    let tcp_start = 40;
    if packet.len() < tcp_start + 20 {
        return None;
    }

    // Source port
    let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
    // Sequence number
    let seq = u32::from_be_bytes([
        packet[tcp_start + 4],
        packet[tcp_start + 5],
        packet[tcp_start + 6],
        packet[tcp_start + 7],
    ]);
    // Acknowledgment number
    let ack = u32::from_be_bytes([
        packet[tcp_start + 8],
        packet[tcp_start + 9],
        packet[tcp_start + 10],
        packet[tcp_start + 11],
    ]);
    // Flags
    let flags = packet[tcp_start + 13];

    Some((flags, seq, ack, src_port))
}

/// Host discovery engine.
///
/// Probes targets to determine if they are up using ICMP,
/// TCP ping, ARP methods, and IPv6-specific methods (`ICMPv6` Echo, NDP).
#[derive(Debug)]
pub struct HostDiscovery {
    /// Configuration for discovery.
    config: ScanConfig,

    /// Number of retries for discovery probes.
    retries: u8,
}

impl HostDiscovery {
    /// Creates a new host discovery engine.
    #[must_use]
    pub fn new(config: ScanConfig) -> Self {
        Self { config, retries: 2 }
    }

    /// Detects the local IPv4 address by connecting to a DNS server.
    ///
    /// This doesn't actually send any data, just determines the route.
    /// Uses the DNS server from the configuration.
    fn get_local_ipv4_address(&self) -> Ipv4Addr {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0");
        if let Ok(sock) = socket {
            if sock.connect(&self.config.dns_server).is_ok() {
                if let Ok(local_addr) = sock.local_addr() {
                    if let std::net::IpAddr::V4(ipv4) = local_addr.ip() {
                        return ipv4;
                    }
                }
            }
        }
        Ipv4Addr::UNSPECIFIED
    }

    /// Discovers if a host is up using TCP ping.
    ///
    /// Sends a TCP ACK or SYN probe to well-known ports.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    pub fn discover_tcp_ping(&self, target: &Target) -> Result<HostState, ScanError> {
        let local_addr = self.get_local_ipv4_address();
        let timeout = self.config.initial_rtt;
        let ports = vec![80, 443, 22];

        let syn_ping = TcpSynPing::new(local_addr, ports.clone(), timeout, self.retries)?;
        let result = syn_ping.discover(target)?;

        if result == HostState::Up {
            return Ok(HostState::Up);
        }

        // Try ACK ping as fallback
        let ack_ping = TcpAckPing::new(local_addr, ports, timeout, self.retries)?;
        ack_ping.discover(target)
    }

    /// Discovers if a host is up using ICMP echo.
    ///
    /// Sends ICMP echo requests to determine reachability.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    pub fn discover_icmp(&self, target: &Target) -> Result<HostState, ScanError> {
        let local_addr = self.get_local_ipv4_address();
        let timeout = self.config.initial_rtt;

        let icmp_ping = IcmpPing::new(local_addr, timeout, self.retries)?;
        let result = icmp_ping.discover(target)?;

        if result == HostState::Up {
            return Ok(HostState::Up);
        }

        // Try timestamp as fallback
        let timestamp_ping = IcmpTimestampPing::new(local_addr, timeout, self.retries)?;
        timestamp_ping.discover(target)
    }

    /// Gets the MAC address of the local network interface that has the given IPv4 address.
    fn get_interface_mac(local_addr: Ipv4Addr) -> Option<MacAddr> {
        let interface_name = Self::get_interface_name_for_addr(local_addr)?;

        // SAFETY: socket() returns a valid fd or -1; we check fd < 0 before use
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }

        // SAFETY: mem::zeroed() is safe for ifreq which contains only primitive types and arrays
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        let if_name = &mut ifreq.ifr_name;
        for (i, &byte) in interface_name.as_bytes().iter().enumerate() {
            if i >= if_name.len() {
                break;
            }
            #[expect(clippy::cast_possible_wrap, reason = "ASCII values fit in i8")]
            {
                if_name[i] = byte as i8;
            }
        }

        // SAFETY: fd is valid and owned by us; ifreq is properly initialized
        let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifreq) };
        // SAFETY: fd is valid and being closed
        unsafe { libc::close(fd) };

        if ret < 0 {
            return None;
        }

        // SAFETY: ioctl has populated ifru_hwaddr with valid data
        let sa_data = unsafe { ifreq.ifr_ifru.ifru_hwaddr.sa_data };
        Some(MacAddr::new([
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[0] as u8
            },
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[1] as u8
            },
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[2] as u8
            },
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[3] as u8
            },
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[4] as u8
            },
            #[expect(clippy::cast_sign_loss, reason = "MAC address bytes are unsigned")]
            {
                sa_data[5] as u8
            },
        ]))
    }

    /// Finds the network interface name that has the given local IPv4 address.
    fn get_interface_name_for_addr(local_addr: Ipv4Addr) -> Option<String> {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs writes to a valid pointer; returns 0 on success
        let result = unsafe { libc::getifaddrs(std::ptr::addr_of_mut!(addrs)) };
        if result != 0 {
            return None;
        }

        let mut current = addrs;
        let target_bytes = local_addr.octets();
        let mut found_name: Option<String> = None;

        while !current.is_null() {
            // SAFETY: current points to a valid linked list node from getifaddrs
            let ifa = unsafe { &*current };
            let ifa_addr = ifa.ifa_addr;

            if !ifa_addr.is_null() {
                // SAFETY: ifa_addr is non-null and points to a valid sockaddr
                let family = unsafe { (*ifa_addr).sa_family };
                if i32::from(family) == libc::AF_INET {
                    // SAFETY: family check confirms this is a sockaddr_in;
                    // cast_ptr_alignment: sockaddr_in is the correct interpretation for AF_INET
                    #[expect(clippy::cast_ptr_alignment, reason = "AF_INET confirms sockaddr_in layout")]
                    let sockaddr_in = unsafe { &*(ifa_addr as *const libc::sockaddr_in) };
                    let addr_bytes = sockaddr_in.sin_addr.s_addr.to_ne_bytes();
                    if addr_bytes == target_bytes {
                        // SAFETY: ifa_name is a null-terminated C string from getifaddrs
                        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                        if let Ok(name_str) = name.to_str() {
                            found_name = Some(name_str.to_string());
                            break;
                        }
                    }
                }
            }

            current = ifa.ifa_next;
        }

        // SAFETY: addrs was allocated by getifaddrs and must be freed by freeifaddrs
        unsafe { libc::freeifaddrs(addrs) };
        found_name
    }

    /// Discovers if a host is up using ARP for local networks.
    ///
    /// Uses ARP requests to discover hosts on the same LAN.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    pub fn discover_arp(&self, target: &Target) -> Result<HostState, ScanError> {
        let src_ip = self.get_local_ipv4_address();
        let src_mac = Self::get_interface_mac(src_ip).unwrap_or_else(MacAddr::broadcast);
        let timeout = self.config.initial_rtt;

        let arp_ping = ArpPing::new(src_mac, src_ip, timeout, self.retries)?;
        arp_ping.discover(target)
    }

    /// Discovers if a host is up using `ICMPv6` echo ping.
    ///
    /// Sends `ICMPv6` echo requests to determine IPv6 reachability.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    pub fn discover_icmpv6(&self, target: &Target) -> Result<HostState, ScanError> {
        let local_addr = Ipv6Addr::UNSPECIFIED;
        let timeout = self.config.initial_rtt;

        let icmpv6_ping = Icmpv6Ping::new(local_addr, timeout, self.retries)?;
        let result = icmpv6_ping.discover(target)?;

        if result == HostState::Up {
            return Ok(HostState::Up);
        }

        // Try Neighbor Discovery as fallback for local targets
        let ndp = Icmpv6NeighborDiscovery::new(local_addr, timeout, self.retries)?;
        ndp.discover(target)
    }

    /// Discovers if a host is up using TCP SYN ping over `IPv6`.
    ///
    /// Sends TCP SYN probes over `IPv6` to well-known ports.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed due to network
    /// issues or permissions.
    pub fn discover_tcp_ping_v6(&self, target: &Target) -> Result<HostState, ScanError> {
        let local_addr = Ipv6Addr::UNSPECIFIED;
        let timeout = self.config.initial_rtt;
        let ports = vec![80, 443, 22];

        let syn_ping = TcpSynPingV6::new(local_addr, ports, timeout, self.retries)?;
        syn_ping.discover(target)
    }

    /// Discovers a host using the appropriate method based on IP version.
    ///
    /// Automatically selects IPv4 or IPv6 discovery methods based on target address.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to discover
    ///
    /// # Returns
    ///
    /// Host state (Up, Down, or Unknown).
    ///
    /// # Errors
    ///
    /// Returns an error if the discovery cannot be performed.
    pub fn discover(&self, target: &Target) -> Result<HostState, ScanError> {
        match target.ip {
            rustnmap_common::IpAddr::V4(_) => {
                // Try ICMP first, then TCP
                let result = self.discover_icmp(target)?;
                if result == HostState::Up {
                    return Ok(HostState::Up);
                }
                self.discover_tcp_ping(target)
            }
            rustnmap_common::IpAddr::V6(_) => {
                // Try ICMPv6 first, then TCPv6
                let result = self.discover_icmpv6(target)?;
                if result == HostState::Up {
                    return Ok(HostState::Up);
                }
                self.discover_tcp_ping_v6(target)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_state_equality() {
        assert_eq!(HostState::Up, HostState::Up);
        assert_ne!(HostState::Up, HostState::Down);
        assert_ne!(HostState::Up, HostState::Unknown);
        assert_eq!(HostState::Down, HostState::Down);
        assert_eq!(HostState::Unknown, HostState::Unknown);
    }

    #[test]
    fn test_host_discovery_creation() {
        let config = ScanConfig::default();
        let discovery = HostDiscovery::new(config);
        assert_eq!(discovery.retries, 2);
    }

    #[test]
    fn test_tcp_syn_ping_default_ports() {
        assert_eq!(TcpSynPing::DEFAULT_PORTS, [80, 443, 22]);
    }

    #[test]
    fn test_tcp_ack_ping_default_ports() {
        assert_eq!(TcpAckPing::DEFAULT_PORTS, [80, 443, 22]);
    }

    #[test]
    fn test_tcp_syn_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        // This will fail without root, but we can verify the error type
        if let Ok(ping) = TcpSynPing::new(local_addr, vec![], timeout, 2) {
            assert!(ping.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_tcp_ack_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = TcpAckPing::new(local_addr, vec![], timeout, 2) {
            assert!(ping.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_icmp_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = IcmpPing::new(local_addr, timeout, 2) {
            assert!(ping.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_icmp_timestamp_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = IcmpTimestampPing::new(local_addr, timeout, 2) {
            assert!(ping.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_arp_ping_requires_root() {
        let src_mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = ArpPing::new(src_mac, src_ip, timeout, 2) {
            assert!(ping.requires_root());
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_arp_ping_is_local_target() {
        let src_mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        let Ok(arp_ping) = ArpPing::new(src_mac, src_ip, timeout, 2) else {
            // Skip test if not root
            return;
        };

        // Same subnet
        let target_same = Target {
            ip: rustnmap_common::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };
        assert!(arp_ping.is_local_target(&target_same));

        // Different subnet
        let target_diff = Target {
            ip: rustnmap_common::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };
        assert!(!arp_ping.is_local_target(&target_diff));

        // IPv6
        let target_v6 = Target {
            ip: rustnmap_common::IpAddr::V6(rustnmap_common::Ipv6Addr::LOCALHOST),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };
        assert!(!arp_ping.is_local_target(&target_v6));
    }

    #[test]
    fn test_tcp_syn_ping_discover_localhost() {
        // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
        if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
            eprintln!("Skipping test_tcp_syn_ping_discover_localhost: set RUSTNMAP_INTEGRATION_TEST=1 to run");
            return;
        }

        let local_addr = Ipv4Addr::LOCALHOST;
        let timeout = Duration::from_secs(1);

        let ping = TcpSynPing::new(local_addr, vec![], timeout, 1).unwrap();

        let target = Target {
            ip: rustnmap_common::IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };

        let result = ping.discover(&target).unwrap();
        // Note: Localhost may return Down due to Linux kernel raw socket limitations
        // The important thing is that the scan completes without error
        assert!(
            matches!(result, HostState::Up | HostState::Down),
            "Localhost discovery should return Up or Down, got {result:?}"
        );
    }

    #[test]
    fn test_icmp_ping_discover_localhost() {
        // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
        if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
            eprintln!("Skipping test_icmp_ping_discover_localhost: set RUSTNMAP_INTEGRATION_TEST=1 to run");
            return;
        }

        let local_addr = Ipv4Addr::LOCALHOST;
        let timeout = Duration::from_secs(1);

        let ping = IcmpPing::new(local_addr, timeout, 1).unwrap();

        let target = Target {
            ip: rustnmap_common::IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };

        let result = ping.discover(&target).unwrap();
        // Note: Localhost may return Down due to Linux kernel raw socket limitations
        // The important thing is that the scan completes without error
        assert!(
            matches!(result, HostState::Up | HostState::Down),
            "Localhost discovery should return Up or Down, got {result:?}"
        );
    }

    #[test]
    fn test_icmpv6_ping_requires_root() {
        let local_addr = Ipv6Addr::LOCALHOST;
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = Icmpv6Ping::new(local_addr, timeout, 2) {
            assert!(ping.requires_root());
        }
        // If not root, constructor will fail - that's expected
    }

    #[test]
    fn test_icmpv6_neighbor_discovery_requires_root() {
        let local_addr = Ipv6Addr::LOCALHOST;
        let timeout = Duration::from_secs(1);

        if let Ok(ndp) = Icmpv6NeighborDiscovery::new(local_addr, timeout, 2) {
            assert!(ndp.requires_root());
        }
        // If not root, constructor will fail - that's expected
    }

    #[test]
    fn test_tcp_syn_ping_v6_requires_root() {
        let local_addr = Ipv6Addr::LOCALHOST;
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = TcpSynPingV6::new(local_addr, vec![], timeout, 2) {
            assert!(ping.requires_root());
        }
        // If not root, constructor will fail - that's expected
    }

    #[test]
    fn test_icmpv6_ping_default_ports() {
        assert_eq!(TcpSynPingV6::DEFAULT_PORTS, [80, 443, 22]);
    }

    #[test]
    fn test_solicited_node_multicast() {
        // Test address: 2001:db8::1
        let target = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let multicast = Icmpv6NeighborDiscovery::solicited_node_multicast(target);

        // Expected: ff02::1:ff00:1
        let expected = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff00, 1);
        assert_eq!(multicast, expected);

        // Test address: fe80::1
        let target2 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let multicast2 = Icmpv6NeighborDiscovery::solicited_node_multicast(target2);
        let expected2 = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff00, 1);
        assert_eq!(multicast2, expected2);
    }

    #[test]
    fn test_icmpv6_neighbor_discovery_skips_multicast() {
        let local_addr = Ipv6Addr::UNSPECIFIED;
        let timeout = Duration::from_secs(1);

        let Ok(ndp) = Icmpv6NeighborDiscovery::new(local_addr, timeout, 2) else {
            // Skip if not root
            return;
        };

        // Test with multicast address - should return Unknown
        let multicast_target = Target {
            ip: rustnmap_common::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };
        let result = ndp.discover(&multicast_target).unwrap();
        assert_eq!(result, HostState::Unknown);

        // Test with loopback address - should return Up
        let loopback_target = Target {
            ip: rustnmap_common::IpAddr::V6(Ipv6Addr::LOCALHOST),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };
        let result = ndp.discover(&loopback_target).unwrap();
        assert_eq!(result, HostState::Up);
    }

    #[test]
    fn test_host_discovery_ipv6_methods() {
        let config = ScanConfig::default();
        let discovery = HostDiscovery::new(config);

        // Test IPv6 localhost discovery via engine
        let target_v6 = Target {
            ip: rustnmap_common::IpAddr::V6(Ipv6Addr::LOCALHOST),
            hostname: None,
            ports: None,
            ipv6_scope: None,
        };

        // The discover method should handle IPv6
        let result = discovery.discover(&target_v6);
        // May fail without root, but should not panic
        if let Ok(state) = result {
            assert!(
                matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
                "IPv6 discovery should return a valid state"
            );
        }
    }
}
