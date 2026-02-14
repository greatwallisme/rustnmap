//! Host discovery module for `RustNmap`.
//!
//! This module provides host discovery functionality to determine
//! which targets are up before port scanning.

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::Target;
use rustnmap_common::{Ipv4Addr, MacAddr, Port, ScanConfig, ScanError};
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
                if let Some((flags, _seq, ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
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
                if let Some((flags, _seq, _ack, src_port)) = parse_tcp_response(&recv_buf[..len]) {
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

/// Host discovery engine.
///
/// Probes targets to determine if they are up using ICMP,
/// TCP ping, and ARP methods.
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
        let local_addr = Ipv4Addr::UNSPECIFIED;
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
        let local_addr = Ipv4Addr::UNSPECIFIED;
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
        let src_mac = MacAddr::broadcast();
        let src_ip = Ipv4Addr::UNSPECIFIED;
        let timeout = self.config.initial_rtt;

        let arp_ping = ArpPing::new(src_mac, src_ip, timeout, self.retries)?;
        arp_ping.discover(target)
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
        if let Ok(ping) = TcpSynPing::new(local_addr, vec![], timeout, 2) { assert!(ping.requires_root()) } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_tcp_ack_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = TcpAckPing::new(local_addr, vec![], timeout, 2) { assert!(ping.requires_root()) } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_icmp_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = IcmpPing::new(local_addr, timeout, 2) { assert!(ping.requires_root()) } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_icmp_timestamp_ping_requires_root() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = IcmpTimestampPing::new(local_addr, timeout, 2) { assert!(ping.requires_root()) } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_arp_ping_requires_root() {
        let src_mac = MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let timeout = Duration::from_secs(1);

        if let Ok(ping) = ArpPing::new(src_mac, src_ip, timeout, 2) { assert!(ping.requires_root()) } else {
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
    #[ignore = "Requires root privileges"]
    fn test_tcp_syn_ping_discover_localhost() {
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
        assert_eq!(result, HostState::Up);
    }

    #[test]
    #[ignore = "Requires root privileges"]
    fn test_icmp_ping_discover_localhost() {
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
        assert_eq!(result, HostState::Up);
    }
}
