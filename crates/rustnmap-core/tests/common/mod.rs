// Integration test utilities for RustNmap
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Common utilities for integration tests.
//!
//! This module provides shared functionality for integration tests including:
//! - Test target configuration
//! - Privilege detection
//! - Result validation helpers

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;

use rustnmap_core::session::{PortSpec, ScanType};
use rustnmap_core::Result;
use rustnmap_core::{ScanConfig, ScanOrchestrator, ScanSession};
use rustnmap_output::models::{PortState, ScanResult};
use rustnmap_scan::scanner::TimingTemplate;
use rustnmap_target::{Target, TargetGroup};

/// Localhost IP address for testing.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Known open ports on localhost for testing.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub const TEST_OPEN_PORTS: &[u16] = &[22, 8501];

/// Known closed ports on localhost for testing.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub const TEST_CLOSED_PORTS: &[u16] = &[54321, 65432];

/// Detects if the current process has `root/CAP_NET_RAW` privileges.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
#[allow(clippy::unnecessary_wraps, reason = "API consistency with other test utilities")]
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
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
}

/// Creates a target group for localhost testing.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn localhost_target() -> TargetGroup {
    let target = Target::from(LOCALHOST);
    TargetGroup::new(vec![target])
}

/// Creates a scan configuration for TCP SYN scanning.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn syn_scan_config(ports: Vec<u16>) -> ScanConfig {
    ScanConfig {
        scan_types: vec![ScanType::TcpSyn],
        port_spec: PortSpec::List(ports),
        timing_template: TimingTemplate::Normal,
        ..ScanConfig::default()
    }
}

/// Creates a scan configuration for TCP Connect scanning.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn connect_scan_config(ports: Vec<u16>) -> ScanConfig {
    ScanConfig {
        scan_types: vec![ScanType::TcpConnect],
        port_spec: PortSpec::List(ports),
        timing_template: TimingTemplate::Normal,
        ..ScanConfig::default()
    }
}

/// Runs a scan and returns the results.
///
/// # Errors
///
/// Returns an error if the scan fails to execute.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
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
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
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
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn is_port_open(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).is_err()
}

/// Gets the list of actually open ports on localhost for testing.
#[allow(dead_code, reason = "shared test utilities may be unused by some test modules")]
pub fn get_available_test_ports() -> Vec<u16> {
    TEST_OPEN_PORTS
        .iter()
        .copied()
        .filter(|&port| is_port_open(SocketAddr::new(LOCALHOST, port)))
        .collect()
}
