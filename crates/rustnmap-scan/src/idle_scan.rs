//! TCP Idle scanner implementation for `RustNmap`.
//!
//! This module provides an advanced stealth scanning technique that uses
//! a third-party "zombie" host to scan target ports. No packets are sent
//! from the scanner's IP address to the target, making this the stealthiest
//! scan type available.
//!
//! # Idle Scan Principles
//!
//! 1. **Probe Zombie for IP ID**: Send a SYN/ACK packet to the zombie and
//!    record the IP ID from its RST response.
//! 2. **Spoof SYN to Target**: Send a SYN packet to the target with the
//!    zombie's IP as the source address.
//! 3. **Probe Zombie Again**: Send another SYN/ACK to the zombie and
//!    record the new IP ID.
//!
//! # Port State Determination
//!
//! | IP ID Change | Port State | Reasoning |
//! |--------------|------------|-----------|
//! | +2 | Open | Target SYN-ACK caused zombie to send RST (+1), probe RST (+1) |
//! | +1 | Closed | Target RST, zombie did nothing, probe RST (+1) |
//! | 0/erratic | Filtered | Zombie unreliable or port filtered |
//!
//! # Zombie Host Requirements
//!
//! - Predictable IP ID sequence (incremental, not random)
//! - Low traffic during scan period
//! - Standard TCP stack that sends RST on unexpected SYN-ACK
//!
//! # Example
//!
//! ```rust,no_run
//! use rustnmap_scan::IdleScanner;
//! use rustnmap_common::{Ipv4Addr, ScanConfig};
//!
//! let local_addr = Ipv4Addr::new(192, 168, 1, 100);
//! let zombie_addr = Ipv4Addr::new(192, 168, 1, 50);
//! let config = ScanConfig::default();
//!
//! let scanner = IdleScanner::new(local_addr, zombie_addr, config).unwrap();
//! ```

#![warn(missing_docs)]

use std::io;
use std::net::SocketAddr;

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::ScanConfig;
use rustnmap_common::{Ipv4Addr, Port, PortState, Protocol};
use rustnmap_net::raw_socket::{RawSocket, TcpPacketBuilder};
use rustnmap_target::Target;

/// Default port on zombie to probe for IP ID.
///
/// Port 80 is commonly used because most hosts have predictable
/// IP ID sequences on well-known ports.
pub const DEFAULT_ZOMBIE_PORT: Port = 80;

/// Default source port range for outbound probes.
pub const SOURCE_PORT_START: u16 = 60000;

/// Idle scanner using IP ID sequence exploitation.
///
/// This scanner performs completely blind port scanning by using
/// a zombie host as an intermediary. No packets are sent from the
/// scanner's IP to the target.
///
/// The scan works by:
/// 1. Probing the zombie to get its current IP ID
/// 2. Sending a spoofed SYN packet to the target (source = zombie)
/// 3. Probing the zombie again to see how much the IP ID incremented
///
/// # Port State Mapping
///
/// - IP ID +2 = Port Open (target sent SYN-ACK to zombie, zombie RST'd back)
/// - IP ID +1 = Port Closed (target sent RST, zombie did nothing)
/// - IP ID 0/erratic = Filtered or unreliable zombie
#[derive(Debug)]
pub struct IdleScanner {
    /// Local IP address for probes.
    local_addr: Ipv4Addr,
    /// Zombie host IP address (the "idle" host).
    zombie_addr: Ipv4Addr,
    /// Zombie probe port (port on zombie to probe).
    zombie_port: Port,
    /// Raw socket for packet transmission.
    socket: RawSocket,
    /// Scanner configuration.
    config: ScanConfig,
}

impl IdleScanner {
    /// Creates a new Idle scanner.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes to zombie
    /// * `zombie_addr` - Zombie host IP address (will be spoofed as source)
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `IdleScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rustnmap_scan::IdleScanner;
    /// use rustnmap_common::{Ipv4Addr, ScanConfig};
    ///
    /// let local_addr = Ipv4Addr::new(192, 168, 1, 100);
    /// let zombie_addr = Ipv4Addr::new(192, 168, 1, 50);
    /// let config = ScanConfig::default();
    ///
    /// let scanner = IdleScanner::new(local_addr, zombie_addr, config).unwrap();
    /// ```
    pub fn new(
        local_addr: Ipv4Addr,
        zombie_addr: Ipv4Addr,
        config: ScanConfig,
    ) -> ScanResult<Self> {
        // Use IPPROTO_TCP (6) for receiving TCP responses from zombie
        let socket = RawSocket::with_protocol(6).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        Ok(Self {
            local_addr,
            zombie_addr,
            zombie_port: DEFAULT_ZOMBIE_PORT,
            socket,
            config,
        })
    }

    /// Creates a new Idle scanner with a specific zombie probe port.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local IP address to use for probes to zombie
    /// * `zombie_addr` - Zombie host IP address (will be spoofed as source)
    /// * `zombie_port` - Port on zombie to probe for IP ID
    /// * `config` - Scanner configuration
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the new `IdleScanner` instance, or an error
    /// if the raw socket cannot be created.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process lacks `CAP_NET_RAW` capability (requires root)
    /// - The system runs out of file descriptors
    pub fn with_zombie_port(
        local_addr: Ipv4Addr,
        zombie_addr: Ipv4Addr,
        zombie_port: Port,
        config: ScanConfig,
    ) -> ScanResult<Self> {
        // Use IPPROTO_TCP (6) for receiving TCP responses from zombie
        let socket = RawSocket::with_protocol(6).map_err(|e| {
            rustnmap_common::ScanError::PermissionDenied {
                operation: format!("create raw socket: {e}"),
            }
        })?;

        Ok(Self {
            local_addr,
            zombie_addr,
            zombie_port,
            socket,
            config,
        })
    }

    /// Scans a single port on a target.
    ///
    /// Performs the complete idle scan sequence:
    /// 1. Probe zombie for initial IP ID
    /// 2. Send spoofed SYN to target
    /// 3. Probe zombie for final IP ID
    /// 4. Determine port state from IP ID change
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `protocol` - Protocol (must be TCP for idle scan)
    ///
    /// # Returns
    ///
    /// Port state based on IP ID sequence analysis.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network issues
    /// or zombie communication failure.
    fn scan_port_impl(
        &self,
        target: &Target,
        port: Port,
        protocol: Protocol,
    ) -> ScanResult<PortState> {
        // Only TCP is supported for idle scan
        if protocol != Protocol::Tcp {
            return Ok(PortState::Filtered);
        }

        // Get target IP address
        let dst_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => addr,
            rustnmap_common::IpAddr::V6(_) => return Ok(PortState::Filtered),
        };

        // Step 1: Probe zombie for initial IP ID
        let Some(ipid_before) = self.probe_zombie_ip_id()? else {
            return Ok(PortState::Filtered); // Zombie not responding
        };

        // Step 2: Send spoofed SYN to target (appears to come from zombie)
        self.send_spoofed_syn(dst_addr, port)?;

        // Small delay to allow target to respond to zombie
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Step 3: Probe zombie for final IP ID
        let Some(ipid_after) = self.probe_zombie_ip_id()? else {
            return Ok(PortState::Filtered); // Zombie not responding
        };

        // Step 4: Determine port state from IP ID change
        Ok(Self::determine_port_state(ipid_before, ipid_after))
    }

    /// Probes the zombie host to get its current IP ID.
    ///
    /// Sends a SYN-ACK packet to the zombie on the configured probe port.
    /// The zombie should respond with an RST packet containing its current IP ID.
    ///
    /// # Returns
    ///
    /// `Ok(Some(ip_id))` if successful, `Ok(None)` if no response received,
    /// or an error if the probe could not be sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be sent.
    fn probe_zombie_ip_id(&self) -> ScanResult<Option<u16>> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP SYN-ACK packet to probe zombie
        // SYN-ACK is used because it elicits an RST response from a closed port
        // which includes the IP ID we need
        let packet = TcpPacketBuilder::new(
            self.local_addr,
            self.zombie_addr,
            src_port,
            self.zombie_port,
        )
        .seq(seq)
        .ack_flag() // Set ACK flag
        .syn() // Set SYN flag
        .window(65535)
        .build();

        let zombie_sockaddr =
            SocketAddr::new(std::net::IpAddr::V4(self.zombie_addr), self.zombie_port);

        // Send the probe
        self.socket
            .send_packet(&packet, &zombie_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        // Wait for RST response with IP ID
        let mut recv_buf = vec![0u8; 65535];
        let timeout = self.config.initial_rtt;

        match self
            .socket
            .recv_packet(recv_buf.as_mut_slice(), Some(timeout))
        {
            Ok(len) if len > 0 => {
                // Extract IP ID from the response
                if let Some(ip_id) = Self::extract_ip_id(&recv_buf[..len]) {
                    Ok(Some(ip_id))
                } else {
                    Ok(None)
                }
            }
            Ok(_) => Ok(None),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(rustnmap_common::ScanError::Network(
                rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::ReceiveError { source: e },
                ),
            )),
        }
    }

    /// Sends a spoofed SYN packet to the target.
    ///
    /// The packet appears to come from the zombie host, not from this scanner.
    /// This is the key to the idle scan's stealth - the target sees the zombie
    /// as the source of the scan.
    ///
    /// # Arguments
    ///
    /// * `dst_addr` - Target IP address
    /// * `dst_port` - Target port
    ///
    /// # Errors
    ///
    /// Returns an error if the packet cannot be sent.
    fn send_spoofed_syn(&self, dst_addr: Ipv4Addr, dst_port: Port) -> ScanResult<()> {
        let src_port = Self::generate_source_port();
        let seq = Self::generate_sequence_number();

        // Build TCP SYN packet with ZOMBIE as source (spoofing)
        // This is the key to idle scan - the target thinks the zombie is scanning it
        let packet = TcpPacketBuilder::new(self.zombie_addr, dst_addr, src_port, dst_port)
            .seq(seq)
            .syn()
            .window(65535)
            .build();

        let target_sockaddr = SocketAddr::new(std::net::IpAddr::V4(dst_addr), dst_port);

        // Send the spoofed packet
        self.socket
            .send_packet(&packet, &target_sockaddr)
            .map_err(|e| {
                rustnmap_common::ScanError::Network(rustnmap_common::Error::Network(
                    rustnmap_common::error::NetworkError::SendError { source: e },
                ))
            })?;

        Ok(())
    }

    /// Determines port state from IP ID change.
    ///
    /// Analyzes the difference between the initial and final IP IDs
    /// to determine if the target port is open, closed, or filtered.
    ///
    /// # Arguments
    ///
    /// * `ipid_before` - IP ID before sending spoofed SYN
    /// * `ipid_after` - IP ID after sending spoofed SYN
    ///
    /// # Returns
    ///
    /// Port state based on IP ID sequence analysis:
    /// - `Open` if IP ID increased by 2
    /// - `Closed` if IP ID increased by 1
    /// - `Filtered` if IP ID did not change or changed unpredictably
    #[must_use]
    fn determine_port_state(ipid_before: u16, ipid_after: u16) -> PortState {
        // Calculate the difference, handling 16-bit wraparound
        let diff = ipid_after.wrapping_sub(ipid_before);

        match diff {
            2 => {
                // IP ID increased by 2:
                // 1. Our probe to zombie (zombie sent RST, IP ID +1)
                // 2. Target sent SYN-ACK to zombie, zombie sent RST back (IP ID +1)
                // Total: +2 = Port is Open
                PortState::Open
            }
            1 => {
                // IP ID increased by 1:
                // 1. Our probe to zombie (zombie sent RST, IP ID +1)
                // Target sent RST to zombie (zombie did nothing)
                // Total: +1 = Port is Closed
                PortState::Closed
            }
            0 => {
                // No change - zombie may be down or not responding
                PortState::Filtered
            }
            _ => {
                // Unexpected change - zombie traffic or unreliable IP ID sequence
                PortState::Filtered
            }
        }
    }

    /// Extracts the IP ID field from an IP packet.
    ///
    /// The IP ID field is a 16-bit value at bytes 4-5 of the IP header.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes
    ///
    /// # Returns
    ///
    /// `Some(ip_id)` if the packet is valid and contains an IP ID,
    /// `None` otherwise.
    #[must_use]
    fn extract_ip_id(packet: &[u8]) -> Option<u16> {
        // Minimum IP header size
        if packet.len() < 20 {
            return None;
        }

        // Check IP version (must be 4)
        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        // Get IP header length
        let ip_header_len = (packet[0] & 0x0F) as usize * 4;
        if packet.len() < ip_header_len {
            return None;
        }

        // IP ID is at bytes 4-5 of the IP header
        let ip_id = u16::from_be_bytes([packet[4], packet[5]]);
        Some(ip_id)
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

impl PortScanner for IdleScanner {
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
        let zombie_addr = Ipv4Addr::new(192, 168, 1, 50);
        let config = ScanConfig::default();
        let result = IdleScanner::new(local_addr, zombie_addr, config);

        // May fail if not running as root
        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
            assert_eq!(scanner.zombie_addr, zombie_addr);
            assert_eq!(scanner.zombie_port, DEFAULT_ZOMBIE_PORT);
        }
    }

    #[test]
    fn test_scanner_with_custom_port() {
        let local_addr = Ipv4Addr::new(192, 168, 1, 100);
        let zombie_addr = Ipv4Addr::new(192, 168, 1, 50);
        let config = ScanConfig::default();
        let result = IdleScanner::with_zombie_port(local_addr, zombie_addr, 443, config);

        // May fail if not running as root
        if let Ok(scanner) = result {
            assert_eq!(scanner.local_addr, local_addr);
            assert_eq!(scanner.zombie_addr, zombie_addr);
            assert_eq!(scanner.zombie_port, 443);
        }
    }

    #[test]
    fn test_requires_root() {
        let local_addr = Ipv4Addr::LOCALHOST;
        let zombie_addr = Ipv4Addr::new(192, 168, 1, 50);
        let config = ScanConfig::default();

        // Test that scanner creation requires root
        if let Ok(scanner) = IdleScanner::new(local_addr, zombie_addr, config) {
            assert!(scanner.requires_root())
        } else {
            // Expected if not running as root
        }
    }

    #[test]
    fn test_generate_source_port() {
        let port = IdleScanner::generate_source_port();
        assert!(port >= SOURCE_PORT_START);
        assert!(port < SOURCE_PORT_START + 1000);
    }

    #[test]
    fn test_generate_sequence_number() {
        let seq1 = IdleScanner::generate_sequence_number();
        let seq2 = IdleScanner::generate_sequence_number();
        // Sequence numbers are based on time, so they should be close
        let diff = seq1.abs_diff(seq2);
        assert!(
            diff < 1_000_000,
            "Sequence numbers should be close in value"
        );
    }

    #[test]
    fn test_extract_ip_id_valid() {
        // Create a valid IPv4 packet header
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[4] = 0x12; // IP ID high byte
        packet[5] = 0x34; // IP ID low byte

        let ip_id = IdleScanner::extract_ip_id(&packet);
        assert_eq!(ip_id, Some(0x1234));
    }

    #[test]
    fn test_extract_ip_id_too_short() {
        let packet = vec![0u8; 10];
        let ip_id = IdleScanner::extract_ip_id(&packet);
        assert_eq!(ip_id, None);
    }

    #[test]
    fn test_extract_ip_id_wrong_version() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x65; // Version 6, IHL 5

        let ip_id = IdleScanner::extract_ip_id(&packet);
        assert_eq!(ip_id, None);
    }

    #[test]
    fn test_determine_port_state_open() {
        // IP ID increased by 2 = Open
        let state = IdleScanner::determine_port_state(1000, 1002);
        assert_eq!(state, PortState::Open);
    }

    #[test]
    fn test_determine_port_state_closed() {
        // IP ID increased by 1 = Closed
        let state = IdleScanner::determine_port_state(1000, 1001);
        assert_eq!(state, PortState::Closed);
    }

    #[test]
    fn test_determine_port_state_filtered_no_change() {
        // No change = Filtered
        let state = IdleScanner::determine_port_state(1000, 1000);
        assert_eq!(state, PortState::Filtered);
    }

    #[test]
    fn test_determine_port_state_filtered_unexpected() {
        // Unexpected change = Filtered
        let state = IdleScanner::determine_port_state(1000, 1005);
        assert_eq!(state, PortState::Filtered);
    }

    #[test]
    fn test_determine_port_state_wraparound() {
        // Test 16-bit wraparound for open port
        let state = IdleScanner::determine_port_state(65535, 1); // 65535 + 2 = 1 (wraparound)
        assert_eq!(state, PortState::Open);

        // Test 16-bit wraparound for closed port
        let state = IdleScanner::determine_port_state(65535, 0); // 65535 + 1 = 0 (wraparound)
        assert_eq!(state, PortState::Closed);
    }
}
// Rust guideline compliant 2026-02-14
