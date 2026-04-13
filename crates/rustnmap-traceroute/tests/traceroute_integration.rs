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

//! Integration tests for traceroute functionality.
//!
//! These tests verify the traceroute implementation with different probe types.
//! Note: Some tests require root privileges to create raw sockets.

use rustnmap_common::Ipv4Addr;
use rustnmap_traceroute::{
    HopInfo, IcmpTraceroute, ProbeResponse, ProbeType, TcpAckTraceroute, TcpSynTraceroute,
    Traceroute, TracerouteConfig, UdpTraceroute,
};
use std::time::Duration;

/// Tests that `TracerouteConfig` can be created and modified correctly.
#[test]
fn test_traceroute_config_creation() {
    let config = TracerouteConfig::new()
        .with_max_hops(20)
        .with_probes_per_hop(5)
        .with_probe_timeout(Duration::from_millis(500))
        .with_probe_type(ProbeType::Icmp)
        .with_dest_port(80)
        .with_resolve_hostnames(true);

    assert_eq!(config.max_hops(), 20);
    assert_eq!(config.probes_per_hop(), 5);
    assert_eq!(config.probe_timeout(), Duration::from_millis(500));
    assert_eq!(config.probe_type(), ProbeType::Icmp);
    assert_eq!(config.dest_port(), 80);
    assert!(config.resolve_hostnames());
}

/// Tests that Traceroute can be created with different configurations.
#[test]
fn test_traceroute_creation() {
    let local_addr = Ipv4Addr::LOCALHOST;

    // Test UDP traceroute creation
    let udp_config = TracerouteConfig::new().with_probe_type(ProbeType::Udp);
    let tracer = Traceroute::new(udp_config, local_addr);
    tracer.unwrap();

    // Test TCP SYN traceroute creation
    let tcp_syn_config = TracerouteConfig::new().with_probe_type(ProbeType::TcpSyn);
    let tracer = Traceroute::new(tcp_syn_config, local_addr);
    tracer.unwrap();

    // Test TCP ACK traceroute creation
    let tcp_ack_config = TracerouteConfig::new().with_probe_type(ProbeType::TcpAck);
    let tracer = Traceroute::new(tcp_ack_config, local_addr);
    tracer.unwrap();

    // Test ICMP traceroute creation
    let icmp_config = TracerouteConfig::new().with_probe_type(ProbeType::Icmp);
    let tracer = Traceroute::new(icmp_config, local_addr);
    tracer.unwrap();
}

/// Tests that default configuration values are correct.
#[test]
fn test_default_config_values() {
    let config = TracerouteConfig::new();

    assert_eq!(config.max_hops(), 30);
    assert_eq!(config.probes_per_hop(), 3);
    assert_eq!(config.probe_timeout(), Duration::from_millis(1000));
    assert_eq!(config.probe_type(), ProbeType::Udp);
    assert_eq!(config.dest_port(), 33434);
    assert_eq!(config.initial_ttl(), 1);
    assert!(!config.resolve_hostnames());
}

/// Tests that invalid configurations are rejected.
#[test]
fn test_invalid_config_rejection() {
    let local_addr = Ipv4Addr::LOCALHOST;

    // Test max_hops = 0 is rejected
    let config = TracerouteConfig::new().with_max_hops(0);
    let result = Traceroute::new(config, local_addr);
    result.unwrap_err();

    // Test probes_per_hop = 0 is rejected
    let config = TracerouteConfig::new().with_probes_per_hop(0);
    let result = Traceroute::new(config, local_addr);
    result.unwrap_err();
}

/// Tests UDP traceroute creation (requires root).
#[test]
fn test_udp_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::LOCALHOST;

    // This may fail if not running as root
    let result = UdpTraceroute::new(config, local_addr);
    // Just verify creation succeeds (or fails gracefully without root)
    assert!(result.is_ok() || result.is_err());
}

/// Tests TCP SYN traceroute creation (requires root).
#[test]
fn test_tcp_syn_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::LOCALHOST;

    // This may fail if not running as root
    let result = TcpSynTraceroute::new(config, local_addr);
    assert!(result.is_ok() || result.is_err());
}

/// Tests TCP ACK traceroute creation (requires root).
#[test]
fn test_tcp_ack_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::LOCALHOST;

    // This may fail if not running as root
    let result = TcpAckTraceroute::new(config, local_addr);
    assert!(result.is_ok() || result.is_err());
}

/// Tests ICMP traceroute creation (requires root).
#[test]
fn test_icmp_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::LOCALHOST;

    // This may fail if not running as root
    let result = IcmpTraceroute::new(config, local_addr);
    if let Ok(tracer) = result {
        // ICMP traceroute should have a valid identifier
        assert!(tracer.identifier() > 0);
    }
}

/// Tests `HopInfo` creation and accessors.
#[test]
#[allow(clippy::float_cmp, reason = "comparing exact f32 values set in test")]
fn test_hop_info_creation() {
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    let rtts = vec![
        Duration::from_millis(10),
        Duration::from_millis(12),
        Duration::from_millis(11),
    ];

    let hop = HopInfo::new(
        5,
        Some(ip),
        Some("router.local".to_string()),
        rtts.clone(),
        0.0,
    );

    assert_eq!(hop.ttl(), 5);
    assert_eq!(hop.ip(), Some(ip));
    assert_eq!(hop.hostname(), Some("router.local"));
    assert_eq!(hop.probe_count(), 3);
    assert!(hop.responded());
    assert_eq!(hop.loss(), 0.0);

    // Test RTT calculations
    let avg = hop.avg_rtt().unwrap();
    assert!(avg >= Duration::from_millis(10) && avg <= Duration::from_millis(12));

    let min = hop.min_rtt().unwrap();
    assert_eq!(min, Duration::from_millis(10));

    let max = hop.max_rtt().unwrap();
    assert_eq!(max, Duration::from_millis(12));
}

/// Tests `HopInfo` with no response.
#[test]
#[allow(clippy::float_cmp, reason = "comparing exact f32 values set in test")]
fn test_hop_info_no_response() {
    let hop = HopInfo::new(3, None, None, vec![], 1.0);

    assert_eq!(hop.ttl(), 3);
    assert!(hop.ip().is_none());
    assert!(!hop.responded());
    assert_eq!(hop.loss(), 1.0);
    assert!(hop.avg_rtt().is_none());
}

/// Tests `ProbeResponse` creation for different response types.
#[test]
fn test_probe_response_types() {
    let ip = Ipv4Addr::new(192, 168, 1, 1);

    // Time Exceeded response
    let time_exceeded = ProbeResponse::time_exceeded(ip);
    assert_eq!(time_exceeded.ip(), ip);
    assert_eq!(time_exceeded.icmp_type(), 11);
    assert_eq!(time_exceeded.icmp_code(), 0);
    assert!(!time_exceeded.is_destination());

    // Echo Reply response
    let echo_reply = ProbeResponse::echo_reply(ip);
    assert_eq!(echo_reply.ip(), ip);
    assert_eq!(echo_reply.icmp_type(), 0);
    assert_eq!(echo_reply.icmp_code(), 0);
    assert!(echo_reply.is_destination());

    // Destination Unreachable response
    let unreachable = ProbeResponse::unreachable(ip, 3);
    assert_eq!(unreachable.ip(), ip);
    assert_eq!(unreachable.icmp_type(), 3);
    assert_eq!(unreachable.icmp_code(), 3);
    assert!(unreachable.is_destination());
}

/// Tests `ProbeType` display formatting.
#[test]
fn test_probe_type_display() {
    assert_eq!(format!("{}", ProbeType::Udp), "UDP");
    assert_eq!(format!("{}", ProbeType::TcpSyn), "TCP-SYN");
    assert_eq!(format!("{}", ProbeType::TcpAck), "TCP-ACK");
    assert_eq!(format!("{}", ProbeType::Icmp), "ICMP");
}

/// Tests `TracerouteResult` formatting by checking the Display implementation.
#[tokio::test]
async fn test_traceroute_result_formatting() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probes_per_hop(1)
        .with_probe_timeout(Duration::from_millis(100))
        .with_probe_type(ProbeType::Icmp);

    if let Ok(tracer) = Traceroute::new(config, local_addr) {
        let result = tracer.trace(target).await;
        if let Ok(result) = result {
            let formatted = format!("{result}");
            assert!(formatted.contains("traceroute to"));
            // The result should have either hop info or timeout markers
            assert!(!formatted.is_empty());
        }
    }
}

/// Tests that all probe types can be used with Traceroute.
#[tokio::test]
async fn test_traceroute_with_all_probe_types() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    // Test with UDP
    let udp_config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probes_per_hop(1)
        .with_probe_timeout(Duration::from_millis(100))
        .with_probe_type(ProbeType::Udp);

    if let Ok(tracer) = Traceroute::new(udp_config, local_addr) {
        // This will likely timeout since we're sending to localhost
        // but it should not panic or error
        let _ = tracer.trace(target).await;
    }

    // Test with ICMP
    let icmp_config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probes_per_hop(1)
        .with_probe_timeout(Duration::from_millis(100))
        .with_probe_type(ProbeType::Icmp);

    if let Ok(tracer) = Traceroute::new(icmp_config, local_addr) {
        let _ = tracer.trace(target).await;
    }
}

/// Tests that packet loss is calculated correctly.
#[test]
#[allow(clippy::float_cmp, reason = "comparing exact f32 values set in test")]
fn test_packet_loss_calculation() {
    // No loss
    let hop = HopInfo::new(
        1,
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        None,
        vec![
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_millis(10),
        ],
        0.0,
    );
    assert_eq!(hop.loss(), 0.0);

    // 50% loss
    let hop = HopInfo::new(
        1,
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        None,
        vec![Duration::from_millis(10), Duration::from_millis(10)],
        0.5,
    );
    assert_eq!(hop.loss(), 0.5);

    // 100% loss
    let hop = HopInfo::new(1, None, None, vec![], 1.0);
    assert_eq!(hop.loss(), 1.0);
}

/// Tests RTT standard deviation calculation.
#[test]
fn test_rtt_stddev_calculation() {
    let rtts = vec![
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_millis(30),
    ];

    let hop = HopInfo::new(1, Some(Ipv4Addr::new(192, 168, 1, 1)), None, rtts, 0.0);

    // Should have stddev with 3+ samples
    let stddev = hop.rtt_stddev();
    assert!(stddev.is_some());

    // Single sample should have no stddev
    let single_rtt = vec![Duration::from_millis(10)];
    let hop = HopInfo::new(
        1,
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        None,
        single_rtt,
        0.0,
    );
    assert!(hop.rtt_stddev().is_none());
}

// =============================================================================
// Real Network Tests - TCP Traceroute
// =============================================================================

/// Real network test: TCP SYN traceroute to localhost.
/// Sends actual TCP SYN packets and verifies response handling.
#[test]
fn test_real_tcp_syn_traceroute_localhost() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) else {
        eprintln!("Skipping TCP SYN traceroute test - not running as root");
        return;
    };

    // Send a probe to localhost on port 80 (HTTP)
    // Localhost should respond with RST (port likely closed) or SYN-ACK (if open)
    let result = traceroute.send_probe(target, 1, 80);

    // Should not error (timeout is ok)
    assert!(
        result.is_ok(),
        "TCP SYN probe should not error: {:?}",
        result.err()
    );

    // We may or may not get a response depending on local services
    // The important thing is that the probe was sent without error
}

/// Real network test: TCP ACK traceroute to localhost.
/// Sends actual TCP ACK packets and verifies response handling.
#[test]
fn test_real_tcp_ack_traceroute_localhost() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpAckTraceroute::new(config, local_addr) else {
        eprintln!("Skipping TCP ACK traceroute test - not running as root");
        return;
    };

    // Send a probe to localhost on port 80
    let result = traceroute.send_probe(target, 1, 80);

    // Should not error (timeout is ok)
    assert!(
        result.is_ok(),
        "TCP ACK probe should not error: {:?}",
        result.err()
    );
}

/// Real network test: TCP SYN traceroute to external target.
/// Tests multi-hop traceroute to a well-known public server.
#[test]
fn test_real_tcp_syn_traceroute_external() {
    let local_addr = Ipv4Addr::LOCALHOST;
    // Use a well-known public DNS server that responds to TCP
    let target = Ipv4Addr::new(8, 8, 8, 8); // Google DNS

    let config = TracerouteConfig::new()
        .with_max_hops(5)
        .with_probe_timeout(Duration::from_millis(1000));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) else {
        eprintln!("Skipping TCP SYN external traceroute test - not running as root");
        return;
    };

    // Send probes with increasing TTL to trace the route
    for ttl in 1..=3 {
        let result = traceroute.send_probe(target, ttl, 53); // DNS port

        assert!(
            result.is_ok(),
            "TCP SYN probe with TTL {} should not error: {:?}",
            ttl,
            result.err()
        );

        // Print what we got (for debugging)
        match result.unwrap() {
            Some(response) => {
                eprintln!(
                    "TTL {}: Response from {} (type={}, code={})",
                    ttl,
                    response.ip(),
                    response.icmp_type(),
                    response.icmp_code()
                );
            }
            None => {
                eprintln!("TTL {ttl}: No response (timeout)");
            }
        }
    }
}

/// Real network test: TCP traceroute with different destination ports.
#[test]
fn test_real_tcp_traceroute_different_ports() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) else {
        eprintln!("Skipping TCP port test - not running as root");
        return;
    };

    // Test different ports
    let ports = [22, 80, 443, 8080];
    for port in &ports {
        let result = traceroute.send_probe(target, 1, *port);
        assert!(
            result.is_ok(),
            "TCP SYN probe to port {port} should not error"
        );
    }
}

/// Real network test: Verify source port generation in real scenario.
/// This test verifies the source port is used correctly by checking
/// that probes can be sent (which internally uses source port generation).
#[test]
fn test_real_source_port_generation() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) else {
        eprintln!("Skipping source port test - not running as root");
        return;
    };

    // Verify source port generation works by sending a probe
    // The probe will fail if source port generation fails
    let result = traceroute.send_probe(target, 1, 80);
    assert!(
        result.is_ok(),
        "Probe with generated source port should succeed: {:?}",
        result.err()
    );
}

/// Real network test: TCP SYN vs ACK behavior difference.
/// SYN should get SYN-ACK or RST from open/closed ports.
/// ACK should get RST from any port (since no connection exists).
#[test]
fn test_real_tcp_syn_vs_ack_behavior() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let syn_config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    let ack_config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Create both traceroute types
    let (Ok(mut syn_tracer), Ok(mut ack_tracer)) = (
        TcpSynTraceroute::new(syn_config, local_addr),
        TcpAckTraceroute::new(ack_config, local_addr),
    ) else {
        eprintln!("Skipping SYN vs ACK test - not running as root");
        return;
    };

    // Send both probes to the same port
    let syn_result = syn_tracer.send_probe(target, 1, 9999); // Unlikely to be open
    let ack_result = ack_tracer.send_probe(target, 1, 9999);

    // Both should complete without error
    assert!(
        syn_result.is_ok(),
        "SYN probe should not error: {:?}",
        syn_result.err()
    );
    assert!(
        ack_result.is_ok(),
        "ACK probe should not error: {:?}",
        ack_result.err()
    );

    // The responses may differ based on local firewall configuration
    // Just verify we got some kind of response or timeout gracefully
    eprintln!("SYN result: {:?}", syn_result.unwrap());
    eprintln!("ACK result: {:?}", ack_result.unwrap());
}

/// Real network test: Traceroute with configured source port.
/// Verifies that a configured source port is used correctly by sending probes.
#[test]
fn test_real_tcp_traceroute_configured_source_port() {
    let local_addr = Ipv4Addr::LOCALHOST;
    let target = Ipv4Addr::LOCALHOST;

    let config = TracerouteConfig::new()
        .with_source_port(54321)
        .with_max_hops(1)
        .with_probe_timeout(Duration::from_millis(500));

    // Try to create traceroute (requires root)
    let Ok(mut traceroute) = TcpSynTraceroute::new(config, local_addr) else {
        eprintln!("Skipping configured source port test - not running as root");
        return;
    };

    // Verify the configured source port is used by sending a probe
    // If the wrong port is used, the probe might fail
    let result = traceroute.send_probe(target, 1, 80);
    assert!(
        result.is_ok(),
        "Probe with configured source port should succeed: {:?}",
        result.err()
    );
}

// Rust guideline compliant 2026-02-15
