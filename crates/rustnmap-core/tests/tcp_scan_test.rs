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
//! SYN scan tests require `root/CAP_NET_RAW` privileges to run.
//!
//! # Configuration
//!
//! Tests can be configured via environment variables or a `.env` file:
//! - `TEST_TARGET_IP`: Target IP address for scanning (default: 127.0.0.1)
//! - `TEST_TARGET_PORTS`: Comma-separated list of ports to scan (default: 22,80,443,3389,8080)

mod common;

use common::{
    connect_scan_config, has_raw_socket_privileges, run_scan, syn_scan_config, test_target_ip,
    test_target_ports,
};
use rustnmap_target::{Target, TargetGroup};

/// Creates a target group for the configured test target.
fn test_target() -> TargetGroup {
    let target = Target::from(test_target_ip());
    TargetGroup::new(vec![target])
}

/// Tests TCP SYN scan against configured target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[tokio::test]
async fn test_syn_scan_target() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let ports = test_target_ports();
    let config = syn_scan_config(ports.clone());
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify we have results for the target
    assert!(
        !result.hosts.is_empty(),
        "Should have at least one host result"
    );

    // Verify results contain expected host
    let target_ip = test_target_ip();
    let host_found = result.hosts.iter().any(|h| h.ip.to_string() == target_ip.to_string());
    assert!(host_found, "Target host {target_ip} should be in results");

    println!("SYN scan completed against {target_ip}, found {} hosts", result.hosts.len());
    if let Some(host) = result.hosts.first() {
        println!("Open ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Tests TCP SYN scan completes successfully against high ports.
///
/// This test requires `root/CAP_NET_RAW` privileges.
/// Note: Port state depends on target configuration.
#[tokio::test]
async fn test_syn_scan_high_ports() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    // Use high ports that are likely closed
    let high_ports: Vec<u16> = vec![54321, 65432];
    let config = syn_scan_config(high_ports.clone());
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Just verify scan completed - port states depend on target
    println!(
        "SYN scan completed against high ports, found {} hosts",
        result.hosts.len()
    );
    if let Some(host) = result.hosts.first() {
        println!("Ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Tests TCP Connect scan against configured target.
///
/// This test does NOT require root privileges.
#[tokio::test]
async fn test_connect_scan_target() {
    let ports = test_target_ports();
    let config = connect_scan_config(ports.clone());
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Verify results contain expected host
    let target_ip = test_target_ip();
    let host_found = result.hosts.iter().any(|h| h.ip.to_string() == target_ip.to_string());
    assert!(host_found, "Target host {target_ip} should be in results");

    println!("Connect scan completed against {target_ip}, found {} hosts", result.hosts.len());
    if let Some(host) = result.hosts.first() {
        println!("Open ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Tests TCP Connect scan completes successfully against high ports.
///
/// This test does NOT require root privileges.
/// Note: Port state depends on target configuration.
#[tokio::test]
async fn test_connect_scan_high_ports() {
    // Use high ports that are likely closed
    let high_ports: Vec<u16> = vec![54321, 65432];
    let config = connect_scan_config(high_ports.clone());
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Just verify scan completed - port states depend on target
    println!(
        "Connect scan completed against high ports, found {} hosts",
        result.hosts.len()
    );
    if let Some(host) = result.hosts.first() {
        println!("Ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Tests TCP SYN scan with mixed ports on configured target.
///
/// This test requires `root/CAP_NET_RAW` privileges.
/// Note: Port states depend on target configuration.
#[tokio::test]
async fn test_syn_scan_mixed_ports() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let target_ports = test_target_ports();
    let high_ports: Vec<u16> = vec![54321, 65432];

    let mut all_ports = target_ports.clone();
    all_ports.extend(&high_ports);

    let config = syn_scan_config(all_ports);
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Just verify scan completed - port states depend on target
    println!(
        "Mixed SYN scan: {} ports scanned, {} hosts found",
        target_ports.len() + high_ports.len(),
        result.hosts.len()
    );
    if let Some(host) = result.hosts.first() {
        println!("Ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Tests TCP Connect scan with mixed ports on configured target.
///
/// This test does NOT require root privileges.
/// Note: Port states depend on target configuration.
#[tokio::test]
async fn test_connect_scan_mixed_ports() {
    let target_ports = test_target_ports();
    let high_ports: Vec<u16> = vec![54321, 65432];

    let mut all_ports = target_ports.clone();
    all_ports.extend(&high_ports);

    let config = connect_scan_config(all_ports);
    let targets = test_target();

    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");

    // Just verify scan completed - port states depend on target
    println!(
        "Mixed Connect scan: {} ports scanned, {} hosts found",
        target_ports.len() + high_ports.len(),
        result.hosts.len()
    );
    if let Some(host) = result.hosts.first() {
        println!("Ports found: {}", host.ports.len());
        for port in &host.ports {
            println!("  Port {}: {:?}", port.number, port.state);
        }
    }
}

/// Benchmarks TCP SYN scan performance.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[tokio::test]
async fn test_syn_scan_performance() {
    // Skip if no privileges
    if !has_raw_socket_privileges().expect("Failed to check privileges") {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let ports: Vec<u16> = (8000..8100).collect();
    let config = syn_scan_config(ports);
    let targets = test_target();

    let start = std::time::Instant::now();
    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");
    let duration = start.elapsed();

    println!("Scanned 100 ports in {duration:?}");
    println!("Found {} hosts with results", result.hosts.len());

    // Performance assertion: should complete within 10 seconds
    assert!(
        duration.as_secs() < 10,
        "Scan took too long: {duration:?}"
    );
}

/// Benchmarks TCP Connect scan performance.
///
/// This test does NOT require root privileges.
#[tokio::test]
async fn test_connect_scan_performance() {
    let ports: Vec<u16> = (8000..8050).collect();
    let config = connect_scan_config(ports);
    let targets = test_target();

    let start = std::time::Instant::now();
    let result = run_scan(config, targets)
        .await
        .expect("Scan should complete successfully");
    let duration = start.elapsed();

    println!("Scanned 50 ports in {duration:?}");
    println!("Found {} hosts with results", result.hosts.len());

    // Performance assertion: should complete within 30 seconds (connect scan is slower)
    assert!(
        duration.as_secs() < 30,
        "Scan took too long: {duration:?}"
    );
}
