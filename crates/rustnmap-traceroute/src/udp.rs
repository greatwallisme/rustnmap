//! UDP traceroute implementation.

use crate::{error::Result, probe::ProbeResponse, TracerouteConfig};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

/// UDP-based traceroute implementation.
#[derive(Debug)]
pub struct UdpTraceroute {
    config: TracerouteConfig,
}

impl UdpTraceroute {
    /// Creates a new UDP traceroute instance.
    ///
    /// # Errors
    ///
    /// Returns an error if socket binding fails.
    pub fn new(config: &TracerouteConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Sends a single UDP probe with the specified TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub async fn send_probe(&self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| crate::error::TracerouteError::Network(format!("bind failed: {}", e)))?;

        // Set TTL using socket option
        socket.set_ttl(u32::from(ttl))
            .map_err(|e| crate::error::TracerouteError::Network(format!("set_ttl failed: {}", e)))?;

        // Build UDP probe payload containing TTL value
        let payload = [ttl, 0, 0, 0];

        // Send UDP probe
        let dest_addr = SocketAddr::V4(SocketAddrV4::new(target, self.config.dest_port));
        socket.send_to(&payload, dest_addr)
            .map_err(|e| crate::error::TracerouteError::Network(format!("send failed: {}", e)))?;

        // Return None indicating timeout (no immediate response)
        // Full implementation would use a separate ICMP socket to receive responses
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_traceroute_new() {
        let config = TracerouteConfig::new();
        let result = UdpTraceroute::new(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_probe_response_creation() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let resp = ProbeResponse::time_exceeded(ip);
        assert_eq!(resp.ip(), ip);
        assert_eq!(resp.icmp_type(), 11);
    }
}
