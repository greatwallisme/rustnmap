// Rust guideline compliant 2026-02-12

//! Source address spoofing implementation.
//!
//! This module provides functionality for spoofing source IP addresses,
//! ports, and MAC addresses in outgoing packets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::SourceConfig;

/// Spoofer for manipulating source addresses in packets.
#[derive(Debug, Clone)]
pub struct SourceSpoofer {
    config: SourceConfig,
    real_ip: IpAddr,
    real_port: Option<u16>,
}

impl SourceSpoofer {
    /// Creates a new source spoofer.
    ///
    /// # Arguments
    ///
    /// * `config` - The source configuration.
    /// * `real_ip` - The actual source IP address.
    pub fn new(config: SourceConfig, real_ip: IpAddr) -> Self {
        Self {
            config,
            real_ip,
            real_port: None,
        }
    }

    /// Sets the real source port.
    pub fn with_real_port(mut self, port: u16) -> Self {
        self.real_port = Some(port);
        self
    }

    /// Returns the source IP to use for outgoing packets.
    ///
    /// If `source_ip` is configured, returns the spoofed IP.
    /// Otherwise, returns the real IP.
    pub fn source_ip(&self) -> IpAddr {
        self.config.source_ip.unwrap_or(self.real_ip)
    }

    /// Returns the source port to use for outgoing packets.
    ///
    /// If `source_port` is configured, returns the spoofed port.
    /// Otherwise, returns the real port if set, or None.
    pub fn source_port(&self) -> Option<u16> {
        self.config.source_port.or(self.real_port)
    }

    /// Returns the complete source socket address.
    pub fn source_addr(&self) -> Option<SocketAddr> {
        let port = match self.source_port() {
            Some(p) => p,
            None => return None,
        };
        Some(SocketAddr::new(self.source_ip(), port))
    }

    /// Returns the real source IP (unspoofed).
    pub fn real_ip(&self) -> IpAddr {
        self.real_ip
    }

    /// Returns the real source port (unspoofed).
    pub fn real_port(&self) -> Option<u16> {
        self.real_port
    }

    /// Returns true if source IP spoofing is enabled.
    pub fn is_ip_spoofed(&self) -> bool {
        self.config.source_ip.is_some()
    }

    /// Returns true if source port spoofing is enabled.
    pub fn is_port_spoofed(&self) -> bool {
        self.config.source_port.is_some()
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &SourceConfig {
        &self.config
    }

    /// Validates that the spoofed address is not the real address.
    ///
    /// This can be used to detect misconfigurations where the spoofed
    /// address is the same as the real address.
    pub fn validate(&self) -> std::result::Result<(), crate::Error> {
        if let Some(spoofed_ip) = self.config.source_ip {
            if spoofed_ip == self.real_ip {
                return Err(crate::Error::InvalidIpAddress(
                    "spoofed IP is the same as real IP".to_string(),
                ));
            }
        }

        if let Some(port) = self.config.source_port {
            if port == 0 {
                return Err(crate::Error::InvalidPort { port });
            }
        }

        Ok(())
    }
}

/// Builder for constructing SourceSpoofer.
#[derive(Debug, Clone)]
pub struct SourceSpooferBuilder {
    real_ip: IpAddr,
    real_port: Option<u16>,
    source_ip: Option<IpAddr>,
    source_port: Option<u16>,
    source_mac: Option<[u8; 6]>,
    interface: Option<String>,
}

impl SourceSpooferBuilder {
    /// Creates a new builder with the real source IP.
    pub fn new(real_ip: IpAddr) -> Self {
        Self {
            real_ip,
            real_port: None,
            source_ip: None,
            source_port: None,
            source_mac: None,
            interface: None,
        }
    }

    /// Sets the real source port.
    pub fn real_port(mut self, port: u16) -> Self {
        self.real_port = Some(port);
        self
    }

    /// Sets the spoofed source IP.
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Sets the spoofed source port.
    pub fn source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Sets the spoofed source MAC address.
    pub fn source_mac(mut self, mac: [u8; 6]) -> Self {
        self.source_mac = Some(mac);
        self
    }

    /// Sets the network interface.
    pub fn interface(mut self, iface: String) -> Self {
        self.interface = Some(iface);
        self
    }

    /// Builds the SourceSpoofer.
    pub fn build(self) -> std::result::Result<SourceSpoofer, crate::Error> {
        let config = SourceConfig {
            source_ip: self.source_ip,
            source_port: self.source_port,
            source_mac: self.source_mac,
            interface: self.interface,
        };

        let spoofer = SourceSpoofer::new(config, self.real_ip).with_real_port(
            self.real_port.unwrap_or(0),
        );

        spoofer.validate()?;
        Ok(spoofer as SourceSpoofer)
    }
}

/// Commonly used spoofed source addresses for specific purposes.
pub mod common {
    use super::*;

    /// Returns the NULL source address (0.0.0.0).
    ///
    /// This is sometimes used for host discovery.
    pub fn null_source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }

    /// Returns a random-looking source IP in the 192.0.2.0/24 range.
    ///
    /// The 192.0.2.0/24 range is reserved for documentation (RFC 5737).
    pub fn doc_source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    /// Returns a source IP commonly used for DNS (port 53).
    pub fn dns_source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::common::*;

    #[test]
    fn test_source_spoofer_new() {
        let config = SourceConfig::default();
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert_eq!(spoofer.real_ip(), real_ip);
        assert_eq!(spoofer.source_ip(), real_ip);
        assert!(!spoofer.is_ip_spoofed());
    }

    #[test]
    fn test_source_spoofer_with_real_port() {
        let config = SourceConfig::default();
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip).with_real_port(8080);

        assert_eq!(spoofer.real_ip(), real_ip);
        assert_eq!(spoofer.real_port(), Some(8080));
        assert_eq!(spoofer.source_port(), Some(8080));
    }

    #[test]
    fn test_source_spoofer_spoofed_ip() {
        let config = SourceConfig {
            source_ip: Some("192.0.2.1".parse().unwrap()),
            source_port: None,
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert_eq!(spoofer.source_ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(spoofer.real_ip(), real_ip);
        assert!(spoofer.is_ip_spoofed());
    }

    #[test]
    fn test_source_spoofer_spoofed_port() {
        let config = SourceConfig {
            source_ip: None,
            source_port: Some(80),
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert_eq!(spoofer.source_port(), Some(80));
        assert_eq!(spoofer.real_port(), None);
        assert!(spoofer.is_port_spoofed());
    }

    #[test]
    fn test_source_spoofer_source_addr() {
        let config = SourceConfig {
            source_ip: Some("192.0.2.1".parse().unwrap()),
            source_port: Some(80),
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert_eq!(
            spoofer.source_addr(),
            Some("192.0.2.1:80".parse().unwrap())
        );
    }

    #[test]
    fn test_source_spoofer_validate_same_ip() {
        let config = SourceConfig {
            source_ip: Some("192.168.1.100".parse().unwrap()),
            source_port: None,
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert!(spoofer.validate().is_err());
    }

    #[test]
    fn test_source_spoofer_validate_zero_port() {
        let config = SourceConfig {
            source_ip: None,
            source_port: Some(0),
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip);

        assert!(spoofer.validate().is_err());
    }

    #[test]
    fn test_source_spoofer_builder() {
        let builder = SourceSpooferBuilder::new("192.168.1.100".parse().unwrap())
            .real_port(8080)
            .source_ip("192.0.2.1".parse().unwrap())
            .source_port(53);

        let spoofer = builder.build().unwrap();

        assert_eq!(spoofer.real_ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(spoofer.real_port(), Some(8080));
        assert_eq!(spoofer.source_ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(spoofer.source_port(), Some(53));
    }

    #[test]
    fn test_common_null_source() {
        let ip = null_source();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn test_common_doc_source() {
        let ip = doc_source();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn test_common_dns_source() {
        let ip = dns_source();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)));
    }

    #[test]
    fn test_source_spoofing_property() {
        let config = SourceConfig {
            source_ip: Some("192.0.2.1".parse().unwrap()),
            source_port: Some(53),
            source_mac: None,
            interface: None,
        };
        let real_ip = "192.168.1.100".parse().unwrap();
        let spoofer = SourceSpoofer::new(config, real_ip).with_real_port(8080);

        assert!(spoofer.is_ip_spoofed());
        assert!(spoofer.is_port_spoofed());

        assert_eq!(spoofer.source_port(), Some(53));
        assert_eq!(spoofer.real_port(), Some(8080));
    }
}
