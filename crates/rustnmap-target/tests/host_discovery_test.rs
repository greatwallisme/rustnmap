// Host discovery integration tests for RustNmap
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

//! Integration tests for host discovery functionality.
//!
//! These tests verify host discovery methods against real network targets.
//! Tests requiring root privileges are marked with `#[ignore]`.

use std::net::Ipv4Addr;
use std::time::Duration;

use rustnmap_common::ScanConfig;
use rustnmap_target::Target;
use rustnmap_target::{
    ArpPing, HostDiscovery, HostDiscoveryMethod, HostState, IcmpPing, IcmpTimestampPing,
    TcpAckPing, TcpSynPing,
};

/// Detects if the current process has `root/CAP_NET_RAW` privileges.
fn has_raw_socket_privileges() -> bool {
    // SAFETY: Creating a raw socket to test privileges; fd is checked before use
    match unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) } {
        -1 => false,
        fd => {
            // SAFETY: fd is valid (not -1) and was just created by socket()
            unsafe { libc::close(fd) };
            true
        }
    }
}

/// Creates a scan configuration for discovery tests.
fn discovery_config() -> ScanConfig {
    ScanConfig {
        initial_rtt: Duration::from_secs(1),
        max_retries: 1,
        ..ScanConfig::default()
    }
}

/// Tests TCP SYN ping discovery against localhost.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_tcp_syn_ping_localhost() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = discovery_config();

    let ping = TcpSynPing::new(
        local_addr,
        vec![80, 443],
        config.initial_rtt,
        config.max_retries,
    )
    .expect("Failed to create TCP SYN ping");

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = ping.discover(&target).expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests TCP ACK ping discovery against localhost.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_tcp_ack_ping_localhost() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = discovery_config();

    let ping = TcpAckPing::new(
        local_addr,
        vec![80, 443],
        config.initial_rtt,
        config.max_retries,
    )
    .expect("Failed to create TCP ACK ping");

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = ping.discover(&target).expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests ICMP echo ping discovery against localhost.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_icmp_ping_localhost() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = discovery_config();

    let ping = IcmpPing::new(local_addr, config.initial_rtt, config.max_retries)
        .expect("Failed to create ICMP ping");

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = ping.discover(&target).expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests ICMP timestamp ping discovery against localhost.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_icmp_timestamp_ping_localhost() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let config = discovery_config();

    let ping = IcmpTimestampPing::new(local_addr, config.initial_rtt, config.max_retries)
        .expect("Failed to create ICMP timestamp ping");

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = ping.discover(&target).expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests ARP ping discovery against localhost.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_arp_ping_localhost() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let src_mac = rustnmap_common::MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let src_ip = Ipv4Addr::LOCALHOST;
    let config = discovery_config();

    let ping = ArpPing::new(src_mac, src_ip, config.initial_rtt, config.max_retries)
        .expect("Failed to create ARP ping");

    let target = Target::from(Ipv4Addr::LOCALHOST);

    // ARP only works for local network, localhost may not respond to ARP
    // so we just verify the method doesn't panic
    let _result = ping.discover(&target);
}

/// Tests `HostDiscovery` engine with TCP ping.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_host_discovery_tcp_ping() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let config = discovery_config();
    let discovery = HostDiscovery::new(config);

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = discovery
        .discover_tcp_ping(&target)
        .expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests `HostDiscovery` engine with ICMP.
///
/// This test requires `root/CAP_NET_RAW` privileges.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_host_discovery_icmp() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let config = discovery_config();
    let discovery = HostDiscovery::new(config);

    let target = Target::from(Ipv4Addr::LOCALHOST);
    let result = discovery.discover_icmp(&target).expect("Discovery failed");

    assert_eq!(result, HostState::Up, "Localhost should be up");
}

/// Tests that discovery methods require root.
#[test]
fn test_discovery_requires_root_without_privileges() {
    // Skip if we have privileges (test the failure case)
    if has_raw_socket_privileges() {
        eprintln!("Skipping test: has raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let timeout = Duration::from_secs(1);

    // TCP SYN ping should fail without root
    let result = TcpSynPing::new(local_addr, vec![], timeout, 2);
    assert!(
        result.is_err(),
        "TCP SYN ping should fail without root privileges"
    );

    // TCP ACK ping should fail without root
    let result = TcpAckPing::new(local_addr, vec![], timeout, 2);
    assert!(
        result.is_err(),
        "TCP ACK ping should fail without root privileges"
    );

    // ICMP ping should fail without root
    let result = IcmpPing::new(local_addr, timeout, 2);
    assert!(
        result.is_err(),
        "ICMP ping should fail without root privileges"
    );

    // ICMP timestamp ping should fail without root
    let result = IcmpTimestampPing::new(local_addr, timeout, 2);
    assert!(
        result.is_err(),
        "ICMP timestamp ping should fail without root privileges"
    );

    // ARP ping should fail without root
    let src_mac = rustnmap_common::MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let result = ArpPing::new(src_mac, src_ip, timeout, 2);
    assert!(
        result.is_err(),
        "ARP ping should fail without root privileges"
    );
}

/// Tests discovery against IPv6 target returns Unknown.
#[test]
#[ignore = "requires root/CAP_NET_RAW privileges"]
fn test_discovery_ipv6_returns_unknown() {
    if !has_raw_socket_privileges() {
        eprintln!("Skipping test: no raw socket privileges");
        return;
    }

    let local_addr = Ipv4Addr::LOCALHOST;
    let timeout = Duration::from_secs(1);

    let ping =
        TcpSynPing::new(local_addr, vec![80], timeout, 1).expect("Failed to create TCP SYN ping");

    // Create IPv6 target
    let target = Target::from(std::net::Ipv6Addr::LOCALHOST);
    let result = ping.discover(&target).expect("Discovery failed");

    assert_eq!(
        result,
        HostState::Unknown,
        "IPv6 targets should return Unknown for IPv4 discovery methods"
    );
}

/// Tests `HostState` equality and variants.
#[test]
fn test_host_state_variants() {
    assert_eq!(HostState::Up, HostState::Up);
    assert_eq!(HostState::Down, HostState::Down);
    assert_eq!(HostState::Unknown, HostState::Unknown);

    assert_ne!(HostState::Up, HostState::Down);
    assert_ne!(HostState::Up, HostState::Unknown);
    assert_ne!(HostState::Down, HostState::Unknown);
}

/// Tests default ports for TCP discovery methods.
#[test]
fn test_default_ports() {
    assert_eq!(TcpSynPing::DEFAULT_PORTS, [80, 443, 22]);
    assert_eq!(TcpAckPing::DEFAULT_PORTS, [80, 443, 22]);
}
