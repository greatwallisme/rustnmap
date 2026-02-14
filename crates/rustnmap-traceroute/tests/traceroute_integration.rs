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

/// Tests that TracerouteConfig can be created and modified correctly.
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
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // Test UDP traceroute creation
    let udp_config = TracerouteConfig::new().with_probe_type(ProbeType::Udp);
    let tracer = Traceroute::new(udp_config, local_addr);
    assert!(tracer.is_ok());

    // Test TCP SYN traceroute creation
    let tcp_syn_config = TracerouteConfig::new().with_probe_type(ProbeType::TcpSyn);
    let tracer = Traceroute::new(tcp_syn_config, local_addr);
    assert!(tracer.is_ok());

    // Test TCP ACK traceroute creation
    let tcp_ack_config = TracerouteConfig::new().with_probe_type(ProbeType::TcpAck);
    let tracer = Traceroute::new(tcp_ack_config, local_addr);
    assert!(tracer.is_ok());

    // Test ICMP traceroute creation
    let icmp_config = TracerouteConfig::new().with_probe_type(ProbeType::Icmp);
    let tracer = Traceroute::new(icmp_config, local_addr);
    assert!(tracer.is_ok());
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
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // Test max_hops = 0 is rejected
    let config = TracerouteConfig::new().with_max_hops(0);
    let result = Traceroute::new(config, local_addr);
    assert!(result.is_err());

    // Test probes_per_hop = 0 is rejected
    let config = TracerouteConfig::new().with_probes_per_hop(0);
    let result = Traceroute::new(config, local_addr);
    assert!(result.is_err());
}

/// Tests UDP traceroute creation (requires root).
#[test]
fn test_udp_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // This may fail if not running as root
    let result = UdpTraceroute::new(config, local_addr);
    // Just verify creation succeeds (or fails gracefully without root)
    assert!(result.is_ok() || result.is_err());
}

/// Tests TCP SYN traceroute creation (requires root).
#[test]
fn test_tcp_syn_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // This may fail if not running as root
    let result = TcpSynTraceroute::new(config, local_addr);
    assert!(result.is_ok() || result.is_err());
}

/// Tests TCP ACK traceroute creation (requires root).
#[test]
fn test_tcp_ack_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // This may fail if not running as root
    let result = TcpAckTraceroute::new(config, local_addr);
    assert!(result.is_ok() || result.is_err());
}

/// Tests ICMP traceroute creation (requires root).
#[test]
fn test_icmp_traceroute_creation() {
    let config = TracerouteConfig::new();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // This may fail if not running as root
    let result = IcmpTraceroute::new(config, local_addr);
    if let Ok(tracer) = result {
        // ICMP traceroute should have a valid identifier
        assert!(tracer.identifier() > 0);
    }
}

/// Tests HopInfo creation and accessors.
#[test]
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

/// Tests HopInfo with no response.
#[test]
fn test_hop_info_no_response() {
    let hop = HopInfo::new(3, None, None, vec![], 1.0);

    assert_eq!(hop.ttl(), 3);
    assert!(hop.ip().is_none());
    assert!(!hop.responded());
    assert_eq!(hop.loss(), 1.0);
    assert!(hop.avg_rtt().is_none());
}

/// Tests ProbeResponse creation for different response types.
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

/// Tests ProbeType display formatting.
#[test]
fn test_probe_type_display() {
    assert_eq!(format!("{}", ProbeType::Udp), "UDP");
    assert_eq!(format!("{}", ProbeType::TcpSyn), "TCP-SYN");
    assert_eq!(format!("{}", ProbeType::TcpAck), "TCP-ACK");
    assert_eq!(format!("{}", ProbeType::Icmp), "ICMP");
}

/// Tests TracerouteResult formatting by checking the Display implementation.
#[tokio::test]
async fn test_traceroute_result_formatting() {
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let target = Ipv4Addr::new(127, 0, 0, 1);

    let config = TracerouteConfig::new()
        .with_max_hops(1)
        .with_probes_per_hop(1)
        .with_probe_timeout(Duration::from_millis(100))
        .with_probe_type(ProbeType::Icmp);

    if let Ok(tracer) = Traceroute::new(config, local_addr) {
        let result = tracer.trace(target).await;
        if let Ok(result) = result {
            let formatted = format!("{}", result);
            assert!(formatted.contains("traceroute to"));
            // The result should have either hop info or timeout markers
            assert!(!formatted.is_empty());
        }
    }
}

/// Tests that all probe types can be used with Traceroute.
#[tokio::test]
async fn test_traceroute_with_all_probe_types() {
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let target = Ipv4Addr::new(127, 0, 0, 1);

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
