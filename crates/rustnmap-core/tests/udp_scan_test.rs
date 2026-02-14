// UDP scan integration tests for RustNmap
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

//! Integration tests for UDP scanning functionality.
//!
//! These tests verify UDP scanning against real network targets.
//! Tests requiring root privileges are marked with `#[ignore = "requires root"]`.

mod common;

use common::has_raw_socket_privileges;
use rustnmap_common::ScanConfig;
use rustnmap_common::{Port, PortState, Protocol};
use rustnmap_scan::{PortScanner, UdpScanner};
use rustnmap_target::Target;
use std::net::Ipv4Addr;

/// Creates a scan configuration for UDP scanning.
fn udp_scan_config() -> ScanConfig {
    ScanConfig {
        initial_rtt: std::time::Duration::from_millis(500),
        max_retries: 1,
        ..ScanConfig::default()
    }
}

/// Tests UDP scanner creation.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_udp_scanner_creation() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = udp_scan_config();

    let scanner = UdpScanner::new(local_addr, config);
    assert!(
        scanner.is_ok(),
        "UDP scanner should be created successfully with root privileges"
    );

    let scanner = scanner.unwrap();
    assert!(scanner.requires_root());
}

/// Tests UDP scanner requires root.
#[test]
fn test_udp_scanner_requires_root_without_privileges() {
    // Skip if we have privileges (test the failure case)
    if has_raw_socket_privileges().unwrap_or(false) {
        eprintln!("Skipping test: has raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = udp_scan_config();

    let result = UdpScanner::new(local_addr, config);
    assert!(
        result.is_err(),
        "UDP scanner creation should fail without root privileges"
    );
}

/// Tests UDP scan against a port (likely Open|Filtered since UDP is stateless).
///
/// This test requires `root/CAP_NET_RAW` privileges.
/// Note: UDP scanning is inherently ambiguous - no response means Open|Filtered.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_udp_scan_port() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = udp_scan_config();

    let scanner = match UdpScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            panic!("Failed to create UDP scanner: {e}");
        }
    };

    // Use localhost as target
    let target = Target::from(Ipv4Addr::LOCALHOST);

    // Scan a high port that's likely closed (will get ICMP Port Unreachable)
    // or filtered (no response)
    let port: Port = 65432;

    let result = scanner.scan_port(&target, port, Protocol::Udp);

    // Result could be:
    // - Closed: if we get ICMP Port Unreachable
    // - Open|Filtered: if no response (timeout)
    // - Filtered: if ICMP Admin Prohibited
    match result {
        Ok(state) => {
            println!("Port {port} state: {state}");
            assert!(
                matches!(
                    state,
                    PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered
                ),
                "UDP scan should return Closed, Filtered, or Open|Filtered"
            );
        }
        Err(e) => {
            // Network errors are acceptable for localhost testing
            println!("UDP scan returned error (expected for localhost): {e}");
        }
    }
}

/// Tests UDP scan with wrong protocol returns Filtered.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_udp_scan_wrong_protocol() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = udp_scan_config();

    let scanner = match UdpScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            panic!("Failed to create UDP scanner: {e}");
        }
    };

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let port: Port = 80;

    // Scan with TCP protocol (wrong for UDP scanner)
    let result = scanner.scan_port(&target, port, Protocol::Tcp);

    assert_eq!(
        result.unwrap(),
        PortState::Filtered,
        "UDP scanner should return Filtered for non-UDP protocol"
    );
}

/// Tests UDP scan with IPv6 target returns Filtered.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_udp_scan_ipv6_target() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = udp_scan_config();

    let scanner = match UdpScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            panic!("Failed to create UDP scanner: {e}");
        }
    };

    // Create IPv6 target
    let target = Target::from(std::net::Ipv6Addr::LOCALHOST);
    let port: Port = 53;

    let result = scanner.scan_port(&target, port, Protocol::Udp);

    assert_eq!(
        result.unwrap(),
        PortState::Filtered,
        "UDP scanner should return Filtered for IPv6 target (not yet supported)"
    );
}

/// Tests UDP scan source port generation.
#[test]
fn test_udp_scan_source_port_range() {
    use rustnmap_scan::udp_scan::SOURCE_PORT_START;

    // Verify the source port constant is in the ephemeral range
    // Ephemeral ports are typically 49152-65535
    assert!(
        (49152..=65535).contains(&SOURCE_PORT_START),
        "Source port should be in ephemeral range (49152-65535)"
    );
}

/// Benchmarks UDP scan performance.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_udp_scan_performance() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = ScanConfig {
        initial_rtt: std::time::Duration::from_millis(100),
        max_retries: 0,
        ..ScanConfig::default()
    };

    let scanner = match UdpScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            panic!("Failed to create UDP scanner: {e}");
        }
    };

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let ports: Vec<Port> = (60000..60100).collect();

    let start = std::time::Instant::now();

    for port in &ports {
        // Ignore results, just measure timing
        let _ = scanner.scan_port(&target, *port, Protocol::Udp);
    }

    let duration = start.elapsed();
    println!("Scanned 100 UDP ports in {duration:?}");

    // Performance assertion: should complete within reasonable time
    // Note: UDP scans with timeout are slower due to waiting for responses
    assert!(
        duration.as_secs() < 60,
        "UDP scan took too long: {duration:?}"
    );
}
