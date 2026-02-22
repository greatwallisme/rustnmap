//! TCP Connect scanner implementation for `RustNmap`.
//!
//! This module provides TCP Connect scanning, which uses the operating
//! system's `connect()` syscall to determine port state. This technique
//! does not require root privileges but is more easily detected than
//! TCP SYN scanning.

#![warn(missing_docs)]

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

        // Try to use spawn_blocking if in a multi-threaded tokio runtime context
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                // Clone data needed for the blocking operation
                let target_clone = target.clone();
                match tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        tokio::task::spawn_blocking(move || {
                            Self::scan_port_impl_blocking_static(&target_clone, port, protocol)
                        })
                        .await
                    })
                }) {
                    Ok(state) => return state,
                    Err(_) => return PortState::Filtered,
                }
            }
        }

        // No multi-threaded runtime, do blocking operation directly
        self.scan_port_impl_blocking(target, port, protocol)
    }

    /// Blocking implementation of TCP connect scan.
    ///
    /// This function performs the actual blocking TCP connection.
    /// It is called within `block_in_place` to avoid blocking the async runtime.
    fn scan_port_impl_blocking(
        &self,
        target: &Target,
        port: Port,
        _protocol: Protocol,
    ) -> PortState {
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

    /// Static version of blocking TCP connect scan for use with `spawn_blocking`.
    ///
    /// This is a standalone function that doesn't require `self`,
    /// making it suitable for use with `spawn_blocking` which requires `Send + 'static` closures.
    fn scan_port_impl_blocking_static(
        target: &Target,
        port: Port,
        _protocol: Protocol,
    ) -> PortState {
        // Get target socket address
        let socket_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => SocketAddr::new(std::net::IpAddr::V4(addr), port),
            rustnmap_common::IpAddr::V6(_) => return PortState::Filtered,
        };

        // Use default timeout for static version
        let timeout = Duration::from_secs(10);

        // Attempt connection with timeout
        let result = std::net::TcpStream::connect_timeout(&socket_addr, timeout);

        match result {
            Ok(_stream) => PortState::Open,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                PortState::Closed
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => PortState::Filtered,
            Err(_e) => PortState::Filtered,
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
