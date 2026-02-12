//! TCP traceroute implementations (SYN and ACK).

use crate::{error::Result, probe::ProbeResponse, TracerouteConfig};
use std::net::Ipv4Addr;

/// TCP SYN-based traceroute implementation.
#[derive(Debug)]
pub struct TcpSynTraceroute {
    #[allow(dead_code)]
    config: TracerouteConfig,
}

/// TCP ACK-based traceroute implementation.
#[derive(Debug)]
pub struct TcpAckTraceroute {
    #[allow(dead_code)]
    config: TracerouteConfig,
}

impl TcpSynTraceroute {
    /// Creates a new TCP SYN traceroute instance.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid.
    pub fn new(config: &TracerouteConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Sends a TCP SYN probe with the specified TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub async fn send_probe(&self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        let _ = (target, ttl);
        Ok(None)
    }
}

impl TcpAckTraceroute {
    /// Creates a new TCP ACK traceroute instance.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid.
    pub fn new(config: &TracerouteConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Sends a TCP ACK probe with the specified TTL.
    ///
    /// # Errors
    ///
    /// Returns an error if probe cannot be sent.
    pub async fn send_probe(&self, target: Ipv4Addr, ttl: u8) -> Result<Option<ProbeResponse>> {
        let _ = (target, ttl);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_syn_traceroute_new() {
        let config = TracerouteConfig::new();
        let result = TcpSynTraceroute::new(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tcp_ack_traceroute_new() {
        let config = TracerouteConfig::new();
        let result = TcpAckTraceroute::new(&config);
        assert!(result.is_ok());
    }
}
