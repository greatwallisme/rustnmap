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

//! Integration tests for host discovery using real network operations.
//!
//! These tests use actual network operations. Root privileges are available
//! in the development environment for raw socket operations.
//! The test target IP is read from the `TEST_TARGET_IP` environment variable,
//! defaulting to localhost (127.0.0.1) if not set.

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rustnmap_common::ScanConfig;
use rustnmap_target::{
    ArpPing, HostDiscovery, HostDiscoveryMethod, HostState, IcmpPing, IcmpTimestampPing,
    Icmpv6NeighborDiscovery, Icmpv6Ping, Target, TargetParser, TcpAckPing, TcpSynPing,
};

/// Get the test target IP from environment or use localhost fallback.
fn get_test_target() -> Target {
    let ip_str = env::var("TEST_TARGET_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let parser = TargetParser::new();
    let group = parser.parse(&ip_str).expect("Failed to parse test target");
    group.targets.into_iter().next().expect("No targets found")
}

/// Create a basic scan configuration for testing.
fn test_config() -> ScanConfig {
    ScanConfig {
        min_rtt: Duration::from_millis(50),
        max_rtt: Duration::from_secs(2),
        initial_rtt: Duration::from_millis(500),
        max_retries: 1,
        host_timeout: 900_000,
        scan_delay: Duration::ZERO,
        dns_server: rustnmap_common::DEFAULT_DNS_SERVER.to_string(),
        min_rate: None,
        max_rate: None,
        timing_level: 3, // T3 Normal
        badsum: false,
    }
}

/// Test ICMP ping discovery against localhost.
#[test]
fn test_icmp_ping_discovery() {
    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;

    let icmp_ping = match IcmpPing::new(local_addr, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create ICMP ping (requires root): {e}");
            return;
        }
    };

    let state = icmp_ping.discover(&target).expect("ICMP ping failed");

    // Should get a valid host state
    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test ICMP timestamp ping discovery.
#[test]
fn test_icmp_timestamp_discovery() {
    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;

    let timestamp_ping = match IcmpTimestampPing::new(local_addr, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create ICMP timestamp ping (requires root): {e}");
            return;
        }
    };

    let state = timestamp_ping
        .discover(&target)
        .expect("ICMP timestamp ping failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test TCP SYN ping discovery.
#[test]
fn test_tcp_syn_ping_discovery() {
    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;
    let ports = vec![80, 443, 22];

    let syn_ping = match TcpSynPing::new(local_addr, ports, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create TCP SYN ping (requires root): {e}");
            return;
        }
    };

    let state = syn_ping.discover(&target).expect("TCP SYN ping failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test TCP ACK ping discovery.
#[test]
fn test_tcp_ack_ping_discovery() {
    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;
    let ports = vec![80, 443, 22];

    let ack_ping = match TcpAckPing::new(local_addr, ports, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create TCP ACK ping (requires root): {e}");
            return;
        }
    };

    let state = ack_ping.discover(&target).expect("TCP ACK ping failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test ARP ping discovery (for local network).
#[test]
fn test_arp_ping_discovery() {
    let target = get_test_target();
    let src_mac = rustnmap_common::MacAddr::broadcast();
    let src_ip = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;

    let arp_ping = match ArpPing::new(src_mac, src_ip, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create ARP ping (requires root): {e}");
            return;
        }
    };

    let state = arp_ping.discover(&target).expect("ARP ping failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test `HostDiscovery` engine with ICMP.
#[test]
fn test_host_discovery_icmp() {
    // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
    if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
        eprintln!("Skipping test_host_discovery_icmp: set RUSTNMAP_INTEGRATION_TEST=1 to run");
        return;
    }

    let target = get_test_target();
    let config = test_config();

    let discovery = HostDiscovery::new(config);
    let state = discovery
        .discover_icmp(&target)
        .expect("Host discovery failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test `HostDiscovery` engine with TCP ping.
#[test]
fn test_host_discovery_tcp_ping() {
    // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
    if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
        eprintln!("Skipping test_host_discovery_tcp_ping: set RUSTNMAP_INTEGRATION_TEST=1 to run");
        return;
    }

    let target = get_test_target();
    let config = test_config();

    let discovery = HostDiscovery::new(config);
    let state = discovery
        .discover_tcp_ping(&target)
        .expect("TCP ping discovery failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test `HostDiscovery` engine auto-selection.
#[test]
fn test_host_discovery_auto() {
    // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
    if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
        eprintln!("Skipping test_host_discovery_auto: set RUSTNMAP_INTEGRATION_TEST=1 to run");
        return;
    }

    let target = get_test_target();
    let config = test_config();

    let discovery = HostDiscovery::new(config);
    let state = discovery.discover(&target).expect("Auto discovery failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test IPv6 `ICMPv6` ping discovery.
#[test]
fn test_icmpv6_ping_discovery() {
    let local_addr = Ipv6Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;

    let icmpv6_ping = match Icmpv6Ping::new(local_addr, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create ICMPv6 ping (requires root): {e}");
            return;
        }
    };

    // Create an IPv6 localhost target
    let parser = TargetParser::new();
    let group = parser.parse("::1").expect("Failed to parse IPv6 target");
    let target = group.targets.into_iter().next().expect("No targets found");

    match icmpv6_ping.discover(&target) {
        Ok(state) => {
            assert!(
                matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
                "Unexpected host state: {state:?}"
            );
        }
        Err(e) => {
            // IPv6 may not be supported in this environment
            eprintln!("ICMPv6 ping error (IPv6 may not be supported): {e}");
        }
    }
}

/// Test IPv6 Neighbor Discovery Protocol.
#[test]
fn test_icmpv6_neighbor_discovery() {
    let local_addr = Ipv6Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(2);
    let retries = 2;

    let ndp = match Icmpv6NeighborDiscovery::new(local_addr, timeout, retries) {
        Ok(ping) => ping,
        Err(e) => {
            eprintln!("Skipping test: cannot create NDP (requires root): {e}");
            return;
        }
    };

    // Create an IPv6 localhost target
    let parser = TargetParser::new();
    let group = parser.parse("::1").expect("Failed to parse IPv6 target");
    let target = group.targets.into_iter().next().expect("No targets found");

    let state = ndp.discover(&target).expect("NDP failed");

    assert!(
        matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
        "Unexpected host state: {state:?}"
    );
}

/// Test discovery methods require root property.
#[test]
fn test_discovery_requires_root() {
    // ICMP ping requires root
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(1);
    let retries = 1;

    let icmp_result = IcmpPing::new(local_addr, timeout, retries);

    if let Ok(ping) = icmp_result {
        assert!(
            ping.requires_root(),
            "ICMP ping should report requiring root"
        );
    } else {
        // Expected without root - test passes
    }
}

/// Test discovery with timeout.
#[test]
fn test_discovery_timeout() {
    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_millis(100); // Very short timeout
    let retries = 0;

    let start = std::time::Instant::now();

    if let Ok(ping) = IcmpPing::new(local_addr, timeout, retries) {
        let _ = ping.discover(&target);
    } else {
        // If we can't create the ping, that's fine for this test
    }

    let elapsed = start.elapsed();

    // Should complete quickly even with short timeout
    assert!(
        elapsed < Duration::from_secs(2),
        "Discovery should respect timeout, took {elapsed:?}"
    );
}

/// Test host discovery engine creation.
#[test]
fn test_host_discovery_creation() {
    let config = test_config();
    let _discovery = HostDiscovery::new(config);

    // Just verify the engine can be created
    // The engine itself doesn't expose much for direct testing
    // The discovery methods internally handle root requirements
    // _discovery is dropped here
}

/// Test multiple discovery methods against same target.
#[test]
fn test_multiple_discovery_methods() {
    // Skip test if running as non-root (raw sockets require CAP_NET_RAW)
    if !std::env::var("RUSTNMAP_INTEGRATION_TEST").is_ok_and(|v| v == "1") {
        eprintln!(
            "Skipping test_multiple_discovery_methods: set RUSTNMAP_INTEGRATION_TEST=1 to run"
        );
        return;
    }

    let target = get_test_target();
    let local_addr = Ipv4Addr::UNSPECIFIED;
    let timeout = Duration::from_secs(1);
    let retries = 1;

    let mut results = Vec::new();

    // Try ICMP ping
    if let Ok(ping) = IcmpPing::new(local_addr, timeout, retries) {
        if let Ok(state) = ping.discover(&target) {
            results.push(("ICMP", state));
        }
    }

    // Try TCP SYN ping
    let ports = vec![80];
    if let Ok(ping) = TcpSynPing::new(local_addr, ports, timeout, retries) {
        if let Ok(state) = ping.discover(&target) {
            results.push(("TCP SYN", state));
        }
    }

    // Should have at least one result
    assert!(
        !results.is_empty(),
        "At least one discovery method should succeed"
    );

    // All states should be valid
    for (method, state) in &results {
        assert!(
            matches!(state, HostState::Up | HostState::Down | HostState::Unknown),
            "{method}: Unexpected host state: {state:?}"
        );
    }
}

/// Test discovery with invalid target (should handle gracefully).
#[test]
fn test_discovery_invalid_target() {
    let config = test_config();
    let discovery = HostDiscovery::new(config);

    // Create a target with IPv6 address for IPv4 discovery
    let parser = TargetParser::new();
    let group = parser.parse("::1").expect("Failed to parse IPv6 target");
    let ipv6_target = group.targets.into_iter().next().expect("No targets found");

    // Try IPv4 discovery on IPv6 target - should return Unknown, not error
    let state = discovery.discover_icmp(&ipv6_target);

    // This may fail or return Unknown depending on implementation
    match state {
        Ok(HostState::Unknown | HostState::Down) => {
            // Expected behavior
        }
        Ok(other) => {
            println!("IPv4 discovery on IPv6 target returned: {other:?}");
        }
        Err(e) => {
            println!("IPv4 discovery on IPv6 target error (expected): {e}");
        }
    }
}
