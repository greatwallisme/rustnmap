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

//! Common utilities for integration tests.
//!
//! This module provides shared functionality for integration tests including:
//! - Test target configuration (loaded from `.env` file)
//! - Privilege detection
//! - Result validation helpers
//!
//! # Configuration
//!
//! Tests can be configured via environment variables or a `.env` file in the
//! project root. See `.env.example` for available options.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use rustnmap_core::session::{PortSpec, ScanType};
use rustnmap_core::Result;
use rustnmap_core::{ScanConfig, ScanOrchestrator, ScanSession};
use rustnmap_output::models::{PortState, ScanResult};
use rustnmap_scan::scanner::TimingTemplate;
use rustnmap_target::{Target, TargetGroup};

// Load environment variables from `.env` file if present.
// This is called automatically when the module is first used.
fn init_env() {
    // dotenvy::dotenv() is idempotent - safe to call multiple times
    let _ = dotenvy::dotenv();
}

/// Default localhost IP address for testing.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
pub const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Gets the external test target IP address from environment or returns localhost.
///
/// Uses `TEST_TARGET_IP` environment variable. Defaults to `127.0.0.1`.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn test_target_ip() -> Ipv4Addr {
    init_env();
    std::env::var("TEST_TARGET_IP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

/// Gets the list of known open ports on localhost for testing.
///
/// Uses `TEST_LOCAL_OPEN_PORTS` environment variable (comma-separated).
/// Defaults to `[22, 8501]`.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn test_open_ports() -> Vec<u16> {
    init_env();
    parse_port_list(
        &std::env::var("TEST_LOCAL_OPEN_PORTS").unwrap_or_else(|_| "22,8501".to_string()),
    )
}

/// Gets the list of known closed ports on localhost for testing.
///
/// Uses `TEST_LOCAL_CLOSED_PORTS` environment variable (comma-separated).
/// Defaults to `[54321, 65432]`.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn test_closed_ports() -> Vec<u16> {
    init_env();
    parse_port_list(
        &std::env::var("TEST_LOCAL_CLOSED_PORTS").unwrap_or_else(|_| "54321,65432".to_string()),
    )
}

/// Parses a comma-separated list of port numbers.
fn parse_port_list(s: &str) -> Vec<u16> {
    s.split(',')
        .map(str::trim)
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Detects if the current process has `root/CAP_NET_RAW` privileges.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "API consistency with other test utilities"
)]
pub fn has_raw_socket_privileges() -> Result<bool> {
    // Try to create a raw socket to test privileges
    // SAFETY: Creating a raw socket to test privileges; fd is checked before use
    match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) } {
        -1 => Ok(false),
        fd => {
            // SAFETY: fd is valid (not -1) and was just created by socket()
            unsafe { libc::close(fd) };
            Ok(true)
        }
    }
}

/// Gets the current user name.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

/// Creates a target group for localhost testing.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn localhost_target() -> TargetGroup {
    let target = Target::from(LOCALHOST);
    TargetGroup::new(vec![target])
}

/// Creates a target group for the configured external test target.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn external_target() -> TargetGroup {
    let target = Target::from(test_target_ip());
    TargetGroup::new(vec![target])
}

/// Creates a scan configuration for TCP SYN scanning.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn syn_scan_config(ports: Vec<u16>) -> ScanConfig {
    ScanConfig {
        scan_types: vec![ScanType::TcpSyn],
        port_spec: PortSpec::List(ports),
        timing_template: TimingTemplate::Normal,
        ..ScanConfig::default()
    }
}

/// Creates a scan configuration for TCP Connect scanning.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn connect_scan_config(ports: Vec<u16>) -> ScanConfig {
    ScanConfig {
        scan_types: vec![ScanType::TcpConnect],
        port_spec: PortSpec::List(ports),
        timing_template: TimingTemplate::Normal,
        ..ScanConfig::default()
    }
}

/// Gets the scan timeout from environment or returns default.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn test_scan_timeout() -> Duration {
    init_env();
    std::env::var("TEST_SCAN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or_else(|| Duration::from_secs(30), Duration::from_secs)
}

/// Runs a scan and returns the results.
///
/// # Errors
///
/// Returns an error if the scan fails to execute.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
pub async fn run_scan(config: ScanConfig, targets: TargetGroup) -> Result<ScanResult> {
    let session = ScanSession::new(config, targets)?;
    let session = Arc::new(session);
    let orchestrator = ScanOrchestrator::new(session);
    orchestrator.run().await
}

/// Validates that a scan result contains expected port states.
///
/// # Panics
///
/// Panics if validation fails.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
pub fn assert_port_state(result: &ScanResult, expected_port: u16, expected_state: PortState) {
    let host = result
        .hosts
        .first()
        .expect("Expected at least one host in results");

    let port_found = host.ports.iter().find(|p| {
        p.number == expected_port && p.protocol == rustnmap_output::models::Protocol::Tcp
    });

    match port_found {
        Some(port) => {
            assert_eq!(
                port.state, expected_state,
                "Port {expected_port} expected {expected_state:?}, found {:?}",
                port.state
            );
        }
        None => {
            panic!("Port {expected_port} not found in scan results");
        }
    }
}

/// Checks if a service is listening on the specified port.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn is_port_open(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).is_err()
}

/// Gets the list of actually open ports on localhost for testing.
///
/// Filters `TEST_LOCAL_OPEN_PORTS` to only include ports that are
/// actually listening on localhost.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn get_available_test_ports() -> Vec<u16> {
    test_open_ports()
        .iter()
        .copied()
        .filter(|&port| is_port_open(SocketAddr::new(LOCALHOST, port)))
        .collect()
}

/// Gets the list of ports to scan on the external test target.
///
/// Uses `TEST_TARGET_PORTS` environment variable (comma-separated).
/// Defaults to `[22, 80, 443, 3389, 8080]`.
#[allow(
    dead_code,
    reason = "shared test utilities may be unused by some test modules"
)]
#[must_use]
pub fn test_target_ports() -> Vec<u16> {
    init_env();
    parse_port_list(
        &std::env::var("TEST_TARGET_PORTS").unwrap_or_else(|_| "22,80,443,3389,8080".to_string()),
    )
}

/// Backward compatibility: returns `TEST_CLOSED_PORTS` via `test_closed_ports()`.
///
/// This constant is deprecated; use `test_closed_ports()` function instead.
#[allow(
    dead_code,
    reason = "backward compatibility - use test_closed_ports() function instead"
)]
pub const TEST_CLOSED_PORTS: &[u16] = &[54321, 65432];

/// Backward compatibility: returns `TEST_OPEN_PORTS` slice.
///
/// This constant is deprecated; use `test_open_ports()` function instead.
#[allow(
    dead_code,
    reason = "backward compatibility - use test_open_ports() function instead"
)]
pub const TEST_OPEN_PORTS: &[u16] = &[22, 8501];
