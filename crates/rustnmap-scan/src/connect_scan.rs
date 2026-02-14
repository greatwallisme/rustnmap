//! TCP Connect scanner implementation for `RustNmap`.
//!
//! This module provides TCP Connect scanning, which uses the operating
//! system's `connect()` syscall to determine port state. This technique
//! does not require root privileges but is more easily detected than
//! TCP SYN scanning.

#![warn(missing_docs)]
#![allow(
    clippy::used_underscore_binding,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps,
    reason = "Required for PortScanner trait compatibility"
)]

use crate::scanner::{PortScanner, ScanResult};
use rustnmap_common::{Port, PortState, Protocol, ScanConfig};
use rustnmap_target::Target;
use std::net::SocketAddr;
use std::time::Duration;

/// TCP Connect scanner.
///
/// Uses the system TCP stack to attempt full connections to target ports.
/// Does not require root privileges but is noisier than SYN scan.
#[derive(Debug)]
pub struct TcpConnectScanner {
    /// Connection timeout for individual port probes.
    connect_timeout: Duration,
}

impl TcpConnectScanner {
    /// Creates a new TCP Connect scanner.
    ///
    /// # Arguments
    ///
    /// * `_local_addr` - Local address (reserved for future use)
    /// * `_config` - Scanner configuration (reserved for future use)
    ///
    /// # Returns
    ///
    /// A new `TcpConnectScanner` instance with default timeout.
    #[must_use]
    pub fn new(_local_addr: Option<rustnmap_common::Ipv4Addr>, _config: ScanConfig) -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
        }
    }

    /// Scans a single port on a target using TCP connect.
    ///
    /// Attempts to establish a TCP connection to determine port state.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `protocol` - Protocol (must be TCP for Connect scan)
    ///
    /// # Returns
    ///
    /// Port state based on connection result.
    fn scan_port_impl(&self, target: &Target, port: Port, protocol: Protocol) -> PortState {
        // Only TCP is supported
        if protocol != Protocol::Tcp {
            return PortState::Filtered;
        }

        // Get target socket address
        let socket_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => SocketAddr::new(std::net::IpAddr::V4(addr), port),
            rustnmap_common::IpAddr::V6(_) => return PortState::Filtered,
        };

        // Attempt connection with timeout
        let result = std::net::TcpStream::connect_timeout(&socket_addr, self.connect_timeout);

        match result {
            Ok(_stream) => {
                // Connection succeeded: port is open
                // We close the stream immediately since we only wanted to check if it's open
                PortState::Open
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                // Connection refused/reset: port is closed
                PortState::Closed
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Connection timed out: port is likely filtered
                PortState::Filtered
            }
            Err(_e) => {
                // Other errors: treat as filtered
                PortState::Filtered
            }
        }
    }
}

impl PortScanner for TcpConnectScanner {
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState> {
        Ok(self.scan_port_impl(target, port, protocol))
    }

    fn requires_root(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScanConfig::default();
        let scanner = TcpConnectScanner::new(None, config);

        assert_eq!(scanner.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_requires_root_false() {
        let scanner = TcpConnectScanner::new(None, ScanConfig::default());
        assert!(!scanner.requires_root());
    }

    #[test]
    fn test_scanner_default_timeout() {
        let scanner = TcpConnectScanner::new(None, ScanConfig::default());
        assert_eq!(scanner.connect_timeout, Duration::from_secs(5));
    }
}
