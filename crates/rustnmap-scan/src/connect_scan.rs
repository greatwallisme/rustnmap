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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default maximum parallel connections.
const DEFAULT_MAX_PARALLELISM: usize = 100;

/// TCP Connect scanner.
///
/// Uses the system TCP stack to attempt full connections to target ports.
/// Does not require root privileges but is noisier than SYN scan.
#[derive(Debug)]
pub struct TcpConnectScanner {
    /// Connection timeout for individual port probes.
    connect_timeout: Duration,
    /// Maximum number of parallel connections.
    max_parallelism: usize,
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
            max_parallelism: DEFAULT_MAX_PARALLELISM,
        }
    }

    /// Sets the maximum parallelism for batch scanning.
    ///
    /// # Arguments
    ///
    /// * `value` - Maximum number of concurrent connections
    #[must_use]
    pub const fn with_max_parallelism(mut self, value: usize) -> Self {
        self.max_parallelism = value;
        self
    }

    /// Scans multiple ports on a target in parallel.
    ///
    /// This is significantly faster than scanning ports sequentially,
    /// especially when many ports are closed or filtered.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `ports` - Slice of port numbers to probe
    ///
    /// # Returns
    ///
    /// A map of port numbers to their states.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustnmap_scan::connect_scan::TcpConnectScanner;
    /// use rustnmap_target::Target;
    /// use rustnmap_common::ScanConfig;
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let scanner = TcpConnectScanner::new(None, ScanConfig::default());
    /// let target = Target::from(Ipv4Addr::new(192, 168, 1, 1));
    /// let ports = vec![22, 80, 443];
    /// let results = scanner.scan_ports_parallel(&target, &ports).await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn scan_ports_parallel(
        &self,
        target: &Target,
        ports: &[Port],
    ) -> HashMap<Port, PortState> {
        let target = Arc::new(target.clone());
        let timeout = self.connect_timeout;
        let max_parallel = self.max_parallelism;

        let mut results = HashMap::new();

        // Process ports in batches to limit concurrency
        for chunk in ports.chunks(max_parallel) {
            let mut handles = Vec::new();

            for &port in chunk {
                let target_clone = Arc::clone(&target);
                let handle = tokio::task::spawn_blocking(move || {
                    let state = Self::scan_single_port(&target_clone, port, timeout);
                    (port, state)
                });
                handles.push(handle);
            }

            // Wait for all connections in this batch
            for handle in handles {
                if let Ok((port, state)) = handle.await {
                    results.insert(port, state);
                }
            }
        }

        results
    }

    /// Scans a single port synchronously.
    fn scan_single_port(target: &Target, port: Port, timeout: Duration) -> PortState {
        // Get target socket address
        let socket_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => SocketAddr::new(std::net::IpAddr::V4(addr), port),
            rustnmap_common::IpAddr::V6(_) => return PortState::Filtered,
        };

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
                let timeout = self.connect_timeout;
                match tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        tokio::task::spawn_blocking(move || {
                            Self::scan_single_port(&target_clone, port, timeout)
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
        Self::scan_single_port(target, port, self.connect_timeout)
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

    #[test]
    fn test_scanner_default_parallelism() {
        let scanner = TcpConnectScanner::new(None, ScanConfig::default());
        assert_eq!(scanner.max_parallelism, DEFAULT_MAX_PARALLELISM);
    }

    #[test]
    fn test_scanner_custom_parallelism() {
        let scanner = TcpConnectScanner::new(None, ScanConfig::default()).with_max_parallelism(50);
        assert_eq!(scanner.max_parallelism, 50);
    }
}
