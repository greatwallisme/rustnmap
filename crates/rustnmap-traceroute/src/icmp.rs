//! ICMP-based traceroute implementation.

use crate::{error::Result, probe::ProbeResponse, TracerouteConfig};
use std::net::Ipv4Addr;

/// ICMP Echo-based traceroute implementation.
#[derive(Debug)]
pub struct IcmpTraceroute {
    #[expect(dead_code, reason = "Feature not yet implemented")]
    config: TracerouteConfig,
    sequence: u16,
}

impl IcmpTraceroute {
    /// Creates a new ICMP traceroute instance.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid.
    pub fn new(config: &TracerouteConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            sequence: 0,
        })
    }

    /// Sends an ICMP Echo Request probe with the specified TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent or response cannot be received.
    // TODO: This is a placeholder implementation. Actual sending and receiving of ICMP packets
    pub fn send_probe(&mut self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        let _ = (target, ttl);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_traceroute_new() {
        let config = TracerouteConfig::new();
        let result = IcmpTraceroute::new(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sequence_increment() {
        let config = TracerouteConfig::new();
        let mut traceroute = IcmpTraceroute::new(&config).unwrap();
        assert_eq!(traceroute.sequence, 0);

        traceroute.sequence = traceroute.sequence.wrapping_add(1);
        assert_eq!(traceroute.sequence, 1);
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
