//! Probe types and response handling for traceroute.

use rustnmap_common::Ipv4Addr;
use std::fmt;

/// Type of traceroute probe to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    /// UDP probe (standard traceroute).
    Udp,

    /// TCP SYN probe.
    TcpSyn,

    /// TCP ACK probe.
    TcpAck,

    /// ICMP Echo probe.
    Icmp,
}

impl Default for ProbeType {
    fn default() -> Self {
        Self::Udp
    }
}

impl fmt::Display for ProbeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::TcpSyn => write!(f, "TCP-SYN"),
            Self::TcpAck => write!(f, "TCP-ACK"),
            Self::Icmp => write!(f, "ICMP"),
        }
    }
}

/// Configuration for individual probe packets.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Source port to use (0 for automatic).
    pub source_port: u16,

    /// Destination port.
    pub dest_port: u16,

    /// TTL for this probe.
    pub ttl: u8,

    /// Payload data to include.
    pub payload: Vec<u8>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            source_port: 0,
            dest_port: 33434,
            ttl: 1,
            payload: vec![],
        }
    }
}

impl ProbeConfig {
    /// Creates a new probe configuration.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            source_port: 0,
            dest_port: 33434,
            ttl: 1,
            payload: vec![],
        }
    }

    /// Sets the source port.
    #[must_use]
    pub const fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = port;
        self
    }

    /// Sets the destination port.
    #[must_use]
    pub const fn with_dest_port(mut self, port: u16) -> Self {
        self.dest_port = port;
        self
    }

    /// Sets the TTL.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the payload data.
    #[must_use]
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }
}

/// Response received from a traceroute probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResponse {
    /// IP address of the responder.
    ip: Ipv4Addr,

    /// ICMP type code.
    icmp_type: u8,

    /// ICMP code.
    icmp_code: u8,

    /// Whether this is the final destination.
    is_destination: bool,
}

impl ProbeResponse {
    /// Creates a new probe response.
    #[must_use]
    pub const fn new(ip: Ipv4Addr, icmp_type: u8, icmp_code: u8, is_destination: bool) -> Self {
        Self {
            ip,
            icmp_type,
            icmp_code,
            is_destination,
        }
    }

    /// Returns the IP address of the responder.
    #[must_use]
    pub const fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Returns the ICMP type.
    #[must_use]
    pub const fn icmp_type(&self) -> u8 {
        self.icmp_type
    }

    /// Returns the ICMP code.
    #[must_use]
    pub const fn icmp_code(&self) -> u8 {
        self.icmp_code
    }

    /// Returns whether this response is from the final destination.
    #[must_use]
    pub const fn is_destination(&self) -> bool {
        self.is_destination
    }

    /// Creates a time-exceeded response (TTL expired).
    #[must_use]
    pub const fn time_exceeded(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            icmp_type: 11, // ICMP Time Exceeded
            icmp_code: 0,  // TTL expired
            is_destination: false,
        }
    }

    /// Creates a destination-unreachable response.
    #[must_use]
    pub const fn unreachable(ip: Ipv4Addr, code: u8) -> Self {
        Self {
            ip,
            icmp_type: 3, // ICMP Destination Unreachable
            icmp_code: code,
            is_destination: true,
        }
    }

    /// Creates an echo-reply response.
    #[must_use]
    pub const fn echo_reply(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            icmp_type: 0, // ICMP Echo Reply
            icmp_code: 0,
            is_destination: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_type_display() {
        assert_eq!(format!("{}", ProbeType::Udp), "UDP");
        assert_eq!(format!("{}", ProbeType::TcpSyn), "TCP-SYN");
        assert_eq!(format!("{}", ProbeType::TcpAck), "TCP-ACK");
        assert_eq!(format!("{}", ProbeType::Icmp), "ICMP");
    }

    #[test]
    fn test_probe_config_default() {
        let config = ProbeConfig::new();
        assert_eq!(config.source_port, 0);
        assert_eq!(config.dest_port, 33434);
        assert_eq!(config.ttl, 1);
        assert!(config.payload.is_empty());
    }

    #[test]
    fn test_probe_config_builder() {
        let config = ProbeConfig::new()
            .with_source_port(12345)
            .with_dest_port(80)
            .with_ttl(5);

        assert_eq!(config.source_port, 12345);
        assert_eq!(config.dest_port, 80);
        assert_eq!(config.ttl, 5);
    }

    #[test]
    fn test_probe_response_new() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let response = ProbeResponse::new(ip, 11, 0, false);

        assert_eq!(response.ip(), ip);
        assert_eq!(response.icmp_type(), 11);
        assert_eq!(response.icmp_code(), 0);
        assert!(!response.is_destination());
    }

    #[test]
    fn test_time_exceeded_response() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let response = ProbeResponse::time_exceeded(ip);

        assert_eq!(response.ip(), ip);
        assert_eq!(response.icmp_type(), 11);
        assert!(!response.is_destination());
    }

    #[test]
    fn test_unreachable_response() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let response = ProbeResponse::unreachable(ip, 3);

        assert_eq!(response.ip(), ip);
        assert_eq!(response.icmp_type(), 3);
        assert_eq!(response.icmp_code(), 3);
        assert!(response.is_destination());
    }

    #[test]
    fn test_echo_reply_response() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let response = ProbeResponse::echo_reply(ip);

        assert_eq!(response.ip(), ip);
        assert_eq!(response.icmp_type(), 0);
        assert!(response.is_destination());
    }
}
