// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026  greatwallisme
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

/// Default connect timeout in milliseconds.
///
/// Matches nmap's `DEFAULT_CONNECT_TIMEOUT` from `service_scan.h:86`.
/// nmap uses adaptive timeouts, but starts with this value.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5_000;

/// TCP Connect scanner.
///
/// Uses the system TCP stack to attempt full connections to target ports.
/// Does not require root privileges but is noisier than SYN scan.
///
/// # Performance
///
/// This implementation uses async I/O with tokio for efficient concurrent
/// connections, matching nmap's approach of using non-blocking sockets with
/// `select()` for multiplexing.
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
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
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
    /// Uses async I/O for efficient concurrency, avoiding the overhead of
    /// `spawn_blocking` and blocking system calls.
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

                // Spawn each connection as a separate task for true parallelism
                handles.push(tokio::spawn(async move {
                    let state = Self::scan_single_port_async(&target_clone, port, timeout).await;
                    (port, state)
                }));
            }

            // Wait for all tasks to complete concurrently
            for handle in handles {
                if let Ok((port, state)) = handle.await {
                    results.insert(port, state);
                }
                // Task failed: no need to record, port not in results = filtered
            }
        }

        results
    }

    /// Scans a single port asynchronously.
    ///
    /// Uses tokio's async TCP stream with timeout for efficient non-blocking
    /// connection attempts.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `timeout` - Connection timeout duration
    ///
    /// # Returns
    ///
    /// Port state based on connection result.
    async fn scan_single_port_async(target: &Target, port: Port, timeout: Duration) -> PortState {
        // Get target socket address
        let socket_addr = match target.ip {
            rustnmap_common::IpAddr::V4(addr) => SocketAddr::new(std::net::IpAddr::V4(addr), port),
            rustnmap_common::IpAddr::V6(_) => return PortState::Filtered,
        };

        // Attempt async connection with timeout
        let connect_future = tokio::net::TcpStream::connect(&socket_addr);
        let timeout_future = tokio::time::timeout(timeout, connect_future);

        match timeout_future.await {
            Ok(Ok(_stream)) => PortState::Open,
            Ok(Err(e))
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                PortState::Closed
            }
            // Connection error or timeout: filtered
            Ok(Err(_)) | Err(_) => PortState::Filtered,
        }
    }

    /// Scans a single port synchronously.
    ///
    /// This is a fallback for non-async contexts. Uses blocking I/O.
    ///
    /// # Arguments
    ///
    /// * `target` - Target host to scan
    /// * `port` - Port number to probe
    /// * `timeout` - Connection timeout duration
    ///
    /// # Returns
    ///
    /// Port state based on connection result.
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
    /// Uses async I/O when in a tokio runtime for better performance.
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

        // Try to use async I/O if in a tokio runtime context
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let target_clone = target.clone();
            let timeout = self.connect_timeout;

            return tokio::task::block_in_place(|| {
                handle.block_on(Self::scan_single_port_async(&target_clone, port, timeout))
            });
        }

        // No tokio runtime, do blocking operation directly
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
