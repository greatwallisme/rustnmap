// TCP scan integration tests for RustNmap
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

//! Integration tests for TCP scanning functionality.
//!
//! These tests verify TCP SYN and Connect scanning against real network targets.
//! Tests requiring root privileges are marked with `#[ignore = "requires root"]`.

mod common;

use common::{
    assert_port_state, connect_scan_config, get_available_test_ports, has_raw_socket_privileges,
    localhost_target, run_scan, syn_scan_config, TEST_CLOSED_PORTS,
};
use rustnmap_output::models::PortState;

/// Tests TCP SYN scan against open ports on localhost.
///
/// This test requires root/CAP_NET_RAW privileges.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
async fn test_syn_scan_open_ports() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let open_ports = get_available_test_ports();
    if open_ports.is_empty() {
        eprintln!("Skipping test: no open ports available on localhost");
        return;
    }

    let config = syn_scan_config(open_ports.clone());
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify we have results for localhost
    assert!(
        !result.hosts.is_empty(),
        "Should have at least one host result"
    );

    // Verify each open port is detected as Open
    for port in &open_ports {
        assert_port_state(&result, *port, PortState::Open);
    }

    println!("SYN scan detected {} open ports", open_ports.len());
}

/// Tests TCP SYN scan filters out closed ports from results.
///
/// This test requires root/CAP_NET_RAW privileges.
/// Note: Closed ports are filtered from results by design (like Nmap).
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
async fn test_syn_scan_closed_ports_filtered() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let closed_ports: Vec<u16> = TEST_CLOSED_PORTS.to_vec();
    let config = syn_scan_config(closed_ports.clone());
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify closed ports are NOT in results (filtered by design)
    if let Some(host) = result.hosts.first() {
        for port in &closed_ports {
            let port_found = host
                .ports
                .iter()
                .any(|p| p.number == *port);
            assert!(!port_found, "Closed port {} should not be in results", port);
        }
    }

    println!("SYN scan correctly filtered {} closed ports from results", closed_ports.len());
}

/// Tests TCP Connect scan against open ports.
///
/// This test does NOT require root privileges.
#[tokio::test]
async fn test_connect_scan_open_ports() {
    let open_ports = get_available_test_ports();
    if open_ports.is_empty() {
        eprintln!("Skipping test: no open ports available on localhost");
        return;
    }

    let config = connect_scan_config(open_ports.clone());
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify each open port is detected as Open
    for port in &open_ports {
        assert_port_state(&result, *port, PortState::Open);
    }

    println!("Connect scan detected {} open ports", open_ports.len());
}

/// Tests TCP Connect scan filters out closed ports from results.
///
/// This test does NOT require root privileges.
/// Note: Closed ports are filtered from results by design (like Nmap).
#[tokio::test]
async fn test_connect_scan_closed_ports_filtered() {
    let closed_ports: Vec<u16> = TEST_CLOSED_PORTS.to_vec();
    let config = connect_scan_config(closed_ports.clone());
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify closed ports are NOT in results (filtered by design)
    if let Some(host) = result.hosts.first() {
        for port in &closed_ports {
            let port_found = host
                .ports
                .iter()
                .any(|p| p.number == *port);
            assert!(!port_found, "Closed port {} should not be in results", port);
        }
    }

    println!("Connect scan correctly filtered {} closed ports from results", closed_ports.len());
}

/// Tests TCP SYN scan with mixed open and closed ports.
///
/// This test requires root/CAP_NET_RAW privileges.
/// Note: Only open ports appear in results; closed ports are filtered.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
async fn test_syn_scan_mixed_ports() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let open_ports = get_available_test_ports();
    let closed_ports: Vec<u16> = TEST_CLOSED_PORTS.iter().copied().take(2).collect();

    let mut all_ports = open_ports.clone();
    all_ports.extend(&closed_ports);

    let config = syn_scan_config(all_ports);
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify open ports are detected
    for port in &open_ports {
        assert_port_state(&result, *port, PortState::Open);
    }

    // Verify closed ports are NOT in results (filtered by design)
    if let Some(host) = result.hosts.first() {
        for port in &closed_ports {
            let port_found = host.ports.iter().any(|p| p.number == *port);
            assert!(!port_found, "Closed port {} should not be in results", port);
        }
    }

    println!(
        "Mixed SYN scan: {} open ports detected, {} closed ports filtered",
        open_ports.len(),
        closed_ports.len()
    );
}

/// Tests TCP Connect scan with mixed open and closed ports.
///
/// This test does NOT require root privileges.
/// Note: Only open ports appear in results; closed ports are filtered.
#[tokio::test]
async fn test_connect_scan_mixed_ports() {
    let open_ports = get_available_test_ports();
    let closed_ports: Vec<u16> = TEST_CLOSED_PORTS.iter().copied().take(2).collect();

    let mut all_ports = open_ports.clone();
    all_ports.extend(&closed_ports);

    let config = connect_scan_config(all_ports);
    let targets = localhost_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify open ports are detected
    for port in &open_ports {
        assert_port_state(&result, *port, PortState::Open);
    }

    // Verify closed ports are NOT in results (filtered by design)
    if let Some(host) = result.hosts.first() {
        for port in &closed_ports {
            let port_found = host.ports.iter().any(|p| p.number == *port);
            assert!(!port_found, "Closed port {} should not be in results", port);
        }
    }

    println!(
        "Mixed Connect scan: {} open ports detected, {} closed ports filtered",
        open_ports.len(),
        closed_ports.len()
    );
}

/// Benchmarks TCP SYN scan performance.
///
/// This test requires root/CAP_NET_RAW privileges.
#[tokio::test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
async fn test_syn_scan_performance() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let ports: Vec<u16> = (8000..8100).collect();
    let config = syn_scan_config(ports);
    let targets = localhost_target();

    let start = std::time::Instant::now();
    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");
    let duration = start.elapsed();

    println!("Scanned 100 ports in {:?}", duration);
    println!("Found {} hosts with results", result.hosts.len());

    // Performance assertion: should complete within 10 seconds
    assert!(
        duration.as_secs() < 10,
        "Scan took too long: {:?}",
        duration
    );
}

/// Benchmarks TCP Connect scan performance.
///
/// This test does NOT require root privileges.
#[tokio::test]
async fn test_connect_scan_performance() {
    let ports: Vec<u16> = (8000..8050).collect();
    let config = connect_scan_config(ports);
    let targets = localhost_target();

    let start = std::time::Instant::now();
    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");
    let duration = start.elapsed();

    println!("Scanned 50 ports in {:?}", duration);
    println!("Found {} hosts with results", result.hosts.len());

    // Performance assertion: should complete within 30 seconds (connect scan is slower)
    assert!(
        duration.as_secs() < 30,
        "Scan took too long: {:?}",
        duration
    );
}
