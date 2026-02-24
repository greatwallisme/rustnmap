//! Core types for network scanning.
//!
//! This module defines the fundamental types used throughout `RustNmap`,
//! including port states, protocols, addresses, and scan statistics.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::{Error, TargetError};

/// A MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Creates a new MAC address from bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Creates a broadcast MAC address (ff:ff:ff:ff:ff:ff).
    #[must_use]
    pub const fn broadcast() -> Self {
        Self([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Deprecated: Use `broadcast()` instead.
    #[deprecated(since = "0.1.0", note = "Use broadcast() instead")]
    #[expect(non_snake_case, reason = "Nmap compatibility")]
    #[must_use]
    pub const fn BROADCAST() -> Self {
        Self::broadcast()
    }

    /// Returns the underlying bytes.
    #[must_use]
    pub const fn bytes(&self) -> [u8; 6] {
        self.0
    }

    /// Parses a MAC address from a string.
    ///
    /// # Errors
    ///
    /// Returns `None` if the string is not a valid MAC address format.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut bytes = [0u8; 6];
        let mut parts = s.split([':', '-']);

        for (i, part) in (0..6).zip(&mut parts) {
            let byte = u8::from_str_radix(part, 16).ok()?;
            bytes[i] = byte;
        }

        if parts.next().is_some() {
            return None;
        }

        Some(Self(bytes))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Port number (1-65535).
///
/// Port 0 is reserved and should not be used for scanning.
pub type Port = u16;

/// Network protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Stream Control Transmission Protocol.
    Sctp,
    /// IP protocol (raw IP scanning).
    IpProto(u8),
}

impl Protocol {
    /// Returns the IP protocol number for this protocol.
    #[must_use]
    pub const fn protocol_number(&self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
            Self::IpProto(n) => *n,
        }
    }

    /// Creates a protocol from its IP protocol number.
    #[must_use]
    pub const fn from_protocol_number(n: u8) -> Self {
        match n {
            6 => Self::Tcp,
            17 => Self::Udp,
            132 => Self::Sctp,
            n => Self::IpProto(n),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Sctp => write!(f, "sctp"),
            Self::IpProto(n) => write!(f, "ipproto:{n}"),
        }
    }
}

/// Port state as determined by scanning.
///
/// These states correspond exactly to Nmap's port states to ensure
/// behavioral compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PortState {
    /// Port accepts connections.
    Open,
    /// Port responds but is closed.
    Closed,
    /// No response, firewall likely blocking.
    Filtered,
    /// Responds but open/closed cannot be determined.
    Unfiltered,
    /// Port is open or filtered (no response).
    OpenOrFiltered,
    /// Port is closed or filtered.
    ClosedOrFiltered,
    /// Port shows both open and closed responses.
    OpenOrClosed,
}

impl PortState {
    /// Returns true if the port is definitely open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns true if the port is definitely closed.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Returns true if the port state is filtered or may be filtered.
    #[must_use]
    pub const fn is_filtered(&self) -> bool {
        matches!(
            self,
            Self::Filtered | Self::OpenOrFiltered | Self::ClosedOrFiltered
        )
    }

    /// Returns the Nmap-style string representation.
    ///
    /// Nmap uses these strings to represent port states in its output:
    /// - `open` for [`Self::Open`]
    /// - `closed` for [`Self::Closed`]
    /// - `filtered` for [`Self::Filtered`]
    /// - `unfiltered` for [`Self::Unfiltered`]
    /// - `open|filtered` for [`Self::OpenOrFiltered`]
    /// - `closed|filtered` for [`Self::ClosedOrFiltered`]
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Unfiltered => "unfiltered",
            Self::OpenOrFiltered => "open|filtered",
            Self::ClosedOrFiltered => "closed|filtered",
            Self::OpenOrClosed => "open|closed",
        }
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Filtered => write!(f, "filtered"),
            Self::Unfiltered => write!(f, "unfiltered"),
            Self::OpenOrFiltered => write!(f, "open|filtered"),
            Self::ClosedOrFiltered => write!(f, "closed|filtered"),
            Self::OpenOrClosed => write!(f, "open|closed"),
        }
    }
}

/// A range of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    /// Start of the range (inclusive).
    pub start: Port,
    /// End of the range (inclusive).
    pub end: Port,
}

impl PortRange {
    /// Creates a new port range.
    ///
    /// # Errors
    ///
    /// Returns an error if start > end or if either is 0.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "cannot be const: returns Result and constructs Error variants"
    )]
    pub fn new(start: Port, end: Port) -> crate::Result<Self> {
        if start == 0 || end == 0 {
            return Err(Error::Target(TargetError::PortOutOfRange {
                port: if start == 0 { start } else { end },
            }));
        }
        if start > end {
            return Err(Error::Target(TargetError::InvalidPortRange { start, end }));
        }
        Ok(Self { start, end })
    }

    /// Creates a port range without validation.
    ///
    /// # Safety
    ///
    /// Caller must ensure start <= end and neither is 0.
    #[must_use]
    pub const unsafe fn new_unchecked(start: Port, end: Port) -> Self {
        Self { start, end }
    }

    /// Returns true if this range contains the given port.
    #[must_use]
    pub const fn contains(&self, port: Port) -> bool {
        port >= self.start && port <= self.end
    }

    /// Returns the number of ports in this range.
    #[must_use]
    pub const fn len(&self) -> usize {
        (self.end - self.start + 1) as usize
    }

    /// Returns true if this range is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start > self.end
    }

    /// Returns an iterator over ports in this range.
    pub fn iter(&self) -> impl Iterator<Item = Port> {
        self.start..=self.end
    }
}

/// Port selection for scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSelector {
    /// Scan specific ports.
    Specific(PortList),
    /// Scan top N most common ports.
    Top(usize),
    /// Scan all 65535 ports.
    All,
    /// Scan a range of ports.
    Range(PortRange),
}

impl PortSelector {
    /// Scan the default top 1000 ports.
    #[must_use]
    pub const fn top_1000() -> Self {
        Self::Top(1000)
    }

    /// Returns the estimated number of ports to scan.
    #[must_use]
    pub const fn estimated_count(&self) -> usize {
        match self {
            Self::Specific(list) => list.len(),
            Self::Top(n) => *n,
            Self::All => 65535,
            Self::Range(range) => range.len(),
        }
    }
}

/// A list of ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList {
    /// Sorted list of unique ports.
    ports: Vec<Port>,
}

impl PortList {
    /// Creates a new port list from a slice of ports.
    #[must_use]
    pub fn from_slice(ports: &[Port]) -> Self {
        let mut vec: Vec<Port> = ports.to_vec();
        vec.sort_unstable();
        vec.dedup();
        Self { ports: vec }
    }
}

impl FromIterator<Port> for PortList {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Port>,
    {
        let mut ports: Vec<Port> = iter.into_iter().filter(|&p| p != 0).collect();
        ports.sort_unstable();
        ports.dedup();
        Self { ports }
    }
}

impl PortList {
    /// Returns the number of ports in this list.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ports.len()
    }

    /// Returns true if this list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }

    /// Returns true if this list contains the given port.
    #[must_use]
    pub fn contains(&self, port: Port) -> bool {
        self.ports.binary_search(&port).is_ok()
    }

    /// Returns an iterator over the ports.
    pub fn iter(&self) -> impl Iterator<Item = Port> + '_ {
        self.ports.iter().copied()
    }

    /// Creates a new port list from a vector of ports.
    #[must_use]
    pub const fn from_ports(ports: Vec<Port>) -> Self {
        Self { ports }
    }
}

impl IntoIterator for PortList {
    type Item = Port;
    type IntoIter = std::vec::IntoIter<Port>;

    fn into_iter(self) -> Self::IntoIter {
        self.ports.into_iter()
    }
}

/// Scan statistics tracked during execution.
#[derive(Debug, Default)]
pub struct ScanStats {
    /// Total packets sent.
    packets_sent: AtomicU64,
    /// Total packets received.
    packets_received: AtomicU64,
    /// Hosts up.
    hosts_up: AtomicUsize,
    /// Hosts down.
    hosts_down: AtomicUsize,
}

impl ScanStats {
    /// Creates new scan statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a packet was sent.
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a packet was received.
    pub fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a host is up.
    pub fn record_host_up(&self) {
        self.hosts_up.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a host is down.
    pub fn record_host_down(&self) {
        self.hosts_down.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of packets sent.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Returns the number of packets received.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Returns the number of hosts up.
    #[must_use]
    pub fn hosts_up(&self) -> usize {
        self.hosts_up.load(Ordering::Relaxed)
    }

    /// Returns the number of hosts down.
    #[must_use]
    pub fn hosts_down(&self) -> usize {
        self.hosts_down.load(Ordering::Relaxed)
    }
}

/// A shareable scan statistics reference.
pub type SharedScanStats = Arc<ScanStats>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr_display() {
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_mac_addr_broadcast() {
        assert_eq!(MacAddr::broadcast().to_string(), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn test_mac_addr_parse() {
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.bytes(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let mac = MacAddr::parse("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac.bytes(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_protocol_numbers() {
        assert_eq!(Protocol::Tcp.protocol_number(), 6);
        assert_eq!(Protocol::Udp.protocol_number(), 17);
        assert_eq!(Protocol::Sctp.protocol_number(), 132);
    }

    #[test]
    fn test_port_state_methods() {
        assert!(PortState::Open.is_open());
        assert!(!PortState::Open.is_closed());
        assert!(!PortState::Open.is_filtered());

        assert!(PortState::Closed.is_closed());
        assert!(!PortState::Closed.is_open());

        assert!(PortState::Filtered.is_filtered());
        assert!(PortState::OpenOrFiltered.is_filtered());
    }

    #[test]
    fn test_port_range_valid() {
        let range = PortRange::new(80, 443).unwrap();
        assert_eq!(range.start, 80);
        assert_eq!(range.end, 443);
        assert_eq!(range.len(), 364);
        assert!(range.contains(80));
        assert!(range.contains(443));
        assert!(!range.contains(79));
    }

    #[test]
    fn test_port_range_invalid() {
        PortRange::new(443, 80).unwrap_err();
        PortRange::new(0, 80).unwrap_err();
    }

    #[test]
    fn test_scan_stats() {
        let stats = ScanStats::new();
        stats.record_sent();
        stats.record_sent();
        stats.record_received();
        stats.record_host_up();

        assert_eq!(stats.packets_sent(), 2);
        assert_eq!(stats.packets_received(), 1);
        assert_eq!(stats.hosts_up(), 1);
        assert_eq!(stats.hosts_down(), 0);
    }
}
