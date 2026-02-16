//! Integration tests for evasion techniques.
//!
//! These tests verify the evasion functionality including fragmentation,
//! decoy scanning, source spoofing, packet modification, and timing templates.

use std::net::IpAddr;
use std::time::Duration;

use rustnmap_evasion::{
    config::{
        DecoyConfig, FragmentConfig, FragmentMode, PacketModConfig, SourceConfig, TimingTemplate,
    },
    decoy::DecoyScheduler,
    fragment::Fragmenter,
    modify::PacketModifier,
    source::SourceSpoofer,
    timing::TimingController,
    EvasionConfig,
};

// =============================================================================
// EvasionConfig Tests
// =============================================================================

/// Test that `EvasionConfig` can be created with builder pattern.
#[test]
fn test_evasion_config_builder_complete() {
    let config = EvasionConfig::builder()
        .fragmentation_mtu(1000)
        .decoys(vec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ])
        .source_ip("10.0.0.1".parse().unwrap())
        .source_port(53)
        .ttl(128)
        .bad_checksum()
        .data_length(100)
        .timing_template(TimingTemplate::Aggressive)
        .build()
        .unwrap();

    assert!(config.is_enabled());
    assert!(config.fragmentation.is_some());
    assert!(config.decoys.is_some());
    assert_eq!(config.source.source_ip, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(config.source.source_port, Some(53));
    assert_eq!(config.packet_modification.ttl, Some(128));
    assert!(config.packet_modification.bad_checksum);
    assert_eq!(config.packet_modification.data_length, Some(100));
    assert_eq!(config.timing.template, TimingTemplate::Aggressive);
}

/// Test that empty config reports not enabled.
#[test]
fn test_evasion_config_not_enabled() {
    let config = EvasionConfig::builder().build().unwrap();
    assert!(!config.is_enabled());
}

/// Test fragmentation validation.
#[test]
fn test_evasion_config_fragmentation_validation() {
    // Too small
    let result = EvasionConfig::builder().fragmentation_mtu(5).build();
    result.unwrap_err();

    // Too large
    let result = EvasionConfig::builder().fragmentation_mtu(2000).build();
    result.unwrap_err();

    // Valid
    let result = EvasionConfig::builder().fragmentation_mtu(1000).build();
    result.unwrap();
}

/// Test decoy validation.
#[test]
fn test_evasion_config_decoy_validation() {
    // Empty decoys
    let result = EvasionConfig::builder().decoys(vec![]).build();
    result.unwrap_err();

    // Valid
    let result = EvasionConfig::builder()
        .decoys(vec!["192.0.2.1".parse().unwrap()])
        .build();
    result.unwrap();
}

/// Test source port validation.
#[test]
fn test_evasion_config_source_port_validation() {
    // Port 0 is invalid
    let result = EvasionConfig::builder().source_port(0).build();
    result.unwrap_err();

    // Valid port
    let result = EvasionConfig::builder().source_port(80).build();
    result.unwrap();
}

/// Test TTL validation.
#[test]
fn test_evasion_config_ttl_validation() {
    // TTL 0 is invalid
    let result = EvasionConfig::builder().ttl(0).build();
    result.unwrap_err();

    // Valid TTL
    let result = EvasionConfig::builder().ttl(64).build();
    result.unwrap();
}

// =============================================================================
// Fragmenter Tests
// =============================================================================

/// Test fragmenter creation with default mode.
#[test]
fn test_fragmenter_default_mode() {
    let fragmenter = Fragmenter::default_mode();
    let packet = vec![0u8; 100]; // 100-byte packet
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();

    // With default 8-byte fragments, should produce multiple fragments
    assert!(fragments.len() > 1);
}

/// Test fragmenter with custom MTU.
#[test]
fn test_fragmenter_custom_mtu() {
    let config = FragmentConfig {
        enabled: true,
        mode: FragmentMode::CustomMTU(100),
        overlap: false,
        timeout: Duration::from_secs(30),
    };
    let fragmenter = Fragmenter::new(config);

    // Create a packet larger than 100 bytes
    let packet = vec![0u8; 200];
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();

    // Should be fragmented
    assert!(fragments.len() > 1);
}

/// Test fragmenter with disabled configuration.
#[test]
fn test_fragmenter_disabled() {
    let config = FragmentConfig {
        enabled: false,
        mode: FragmentMode::Default,
        overlap: false,
        timeout: Duration::from_secs(30),
    };
    let fragmenter = Fragmenter::new(config);

    let packet = vec![0u8; 1000];
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();

    // When disabled, should return single fragment
    assert_eq!(fragments.len(), 1);
}

/// Test fragmenter with disabled fragmentation (no fragmentation).
#[test]
fn test_fragmenter_disabled_small_packet() {
    let config = FragmentConfig {
        enabled: false,
        mode: FragmentMode::Default,
        overlap: false,
        timeout: Duration::from_secs(30),
    };
    let fragmenter = Fragmenter::new(config);
    let packet = vec![0u8; 50]; // Small packet
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();

    // When disabled, packet should not be fragmented
    assert_eq!(fragments.len(), 1);
}

/// Test fragmenter with random mode.
#[test]
fn test_fragmenter_random_mode() {
    let config = FragmentConfig {
        enabled: true,
        mode: FragmentMode::Random { min: 16, max: 32 },
        overlap: false,
        timeout: Duration::from_secs(30),
    };
    let fragmenter = Fragmenter::new(config);

    let packet = vec![0u8; 200];
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();

    // Should produce fragments
    assert!(!fragments.is_empty());
}

// =============================================================================
// DecoyScheduler Tests
// =============================================================================

/// Test decoy scheduler creation and basic operation.
#[test]
fn test_decoy_scheduler_basic() {
    let decoys = vec![
        "192.0.2.1".parse::<IpAddr>().unwrap(),
        "192.0.2.2".parse::<IpAddr>().unwrap(),
        "192.0.2.3".parse::<IpAddr>().unwrap(),
    ];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 0,
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

    // Should have 4 sources (3 decoys + 1 real)
    assert_eq!(scheduler.total_sources(), 4);

    // First source should be real IP (position 0)
    assert_eq!(scheduler.next_source(), Some(real_ip));

    // Then decoys
    assert_eq!(scheduler.next_source(), Some("192.0.2.1".parse().unwrap()));
    assert_eq!(scheduler.next_source(), Some("192.0.2.2".parse().unwrap()));
    assert_eq!(scheduler.next_source(), Some("192.0.2.3".parse().unwrap()));

    // No more sources
    assert_eq!(scheduler.next_source(), None);
}

/// Test decoy scheduler with real IP in middle position.
#[test]
fn test_decoy_scheduler_middle_position() {
    let decoys = vec![
        "192.0.2.1".parse::<IpAddr>().unwrap(),
        "192.0.2.2".parse::<IpAddr>().unwrap(),
    ];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 1, // Real IP in middle
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

    // First decoy, then real, then second decoy
    assert_eq!(scheduler.next_source(), Some("192.0.2.1".parse().unwrap()));
    assert_eq!(scheduler.next_source(), Some(real_ip));
    assert_eq!(scheduler.next_source(), Some("192.0.2.2".parse().unwrap()));
}

/// Test decoy scheduler with real IP at end.
#[test]
fn test_decoy_scheduler_end_position() {
    let decoys = vec![
        "192.0.2.1".parse::<IpAddr>().unwrap(),
        "192.0.2.2".parse::<IpAddr>().unwrap(),
    ];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 2, // Real IP at end
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

    // Both decoys first, then real
    assert_eq!(scheduler.next_source(), Some("192.0.2.1".parse().unwrap()));
    assert_eq!(scheduler.next_source(), Some("192.0.2.2".parse().unwrap()));
    assert_eq!(scheduler.next_source(), Some(real_ip));
}

/// Test decoy scheduler reset.
#[test]
fn test_decoy_scheduler_reset() {
    let decoys = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 0,
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let mut scheduler = DecoyScheduler::new(config, real_ip).unwrap();

    // Consume all sources
    let _ = scheduler.next_source();
    let _ = scheduler.next_source();
    assert!(scheduler.next_source().is_none());

    // Reset and try again
    scheduler.reset();
    assert_eq!(scheduler.next_source(), Some(real_ip));
}

/// Test decoy scheduler validation - empty decoys.
#[test]
fn test_decoy_scheduler_empty_decoys() {
    let config = DecoyConfig {
        decoys: vec![],
        real_ip_position: 0,
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let result = DecoyScheduler::new(config, real_ip);
    result.unwrap_err();
}

/// Test decoy scheduler validation - invalid position.
#[test]
fn test_decoy_scheduler_invalid_position() {
    let decoys = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 5, // Invalid - exceeds decoy count
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let result = DecoyScheduler::new(config, real_ip);
    result.unwrap_err();
}

/// Test decoy scheduler `is_real_ip` check.
#[test]
fn test_decoy_scheduler_is_real_ip() {
    let decoys = vec!["192.0.2.1".parse::<IpAddr>().unwrap()];
    let config = DecoyConfig {
        decoys,
        real_ip_position: 0,
        random_order: false,
    };
    let real_ip = "192.0.2.100".parse::<IpAddr>().unwrap();

    let scheduler = DecoyScheduler::new(config, real_ip).unwrap();

    assert!(scheduler.is_real_ip(&real_ip));
    assert!(!scheduler.is_real_ip(&"192.0.2.1".parse().unwrap()));
}

// =============================================================================
// SourceSpoofer Tests
// =============================================================================

/// Test source spoofer without spoofing (default).
#[test]
fn test_source_spoofer_no_spoofing() {
    let config = SourceConfig::default();
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let spoofer = SourceSpoofer::new(config, real_ip);

    assert_eq!(spoofer.source_ip(), real_ip);
    assert!(!spoofer.is_ip_spoofed());
    assert!(!spoofer.is_port_spoofed());
}

/// Test source spoofer with IP spoofing.
#[test]
fn test_source_spoofer_ip_spoofing() {
    let config = SourceConfig {
        source_ip: Some("10.0.0.1".parse().unwrap()),
        source_port: None,
        source_mac: None,
        interface: None,
    };
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let spoofer = SourceSpoofer::new(config, real_ip);

    assert_eq!(spoofer.source_ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
    assert!(spoofer.is_ip_spoofed());
    assert_eq!(spoofer.real_ip(), real_ip);
}

/// Test source spoofer with port spoofing.
#[test]
fn test_source_spoofer_port_spoofing() {
    let config = SourceConfig {
        source_ip: None,
        source_port: Some(53),
        source_mac: None,
        interface: None,
    };
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let spoofer = SourceSpoofer::new(config, real_ip);

    assert_eq!(spoofer.source_port(), Some(53));
    assert!(spoofer.is_port_spoofed());
}

/// Test source spoofer with real port.
#[test]
fn test_source_spoofer_with_real_port() {
    let config = SourceConfig::default();
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let spoofer = SourceSpoofer::new(config, real_ip).with_real_port(12345);

    assert_eq!(spoofer.real_port(), Some(12345));
    assert_eq!(spoofer.source_port(), Some(12345));
}

/// Test source spoofer complete address.
#[test]
fn test_source_spoofer_complete_address() {
    let config = SourceConfig {
        source_ip: Some("10.0.0.1".parse().unwrap()),
        source_port: Some(80),
        source_mac: None,
        interface: None,
    };
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let spoofer = SourceSpoofer::new(config, real_ip);
    let addr = spoofer.source_addr().unwrap();

    assert_eq!(addr.ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(addr.port(), 80);
}

// =============================================================================
// PacketModifier Tests
// =============================================================================

/// Test packet modifier with no modifications.
#[test]
fn test_packet_modifier_none() {
    let modifier = PacketModifier::none();
    let packet = vec![0u8; 100];
    let result = modifier.apply(packet.clone()).unwrap();

    assert_eq!(result, packet);
}

/// Test packet modifier with data padding.
#[test]
fn test_packet_modifier_padding() {
    let config = PacketModConfig {
        data_length: Some(50),
        bad_checksum: false,
        ip_options: None,
        ttl: None,
        tos: None,
        no_flags: false,
    };
    let modifier = PacketModifier::new(config);

    let packet = vec![0u8; 100];
    let result = modifier.apply(packet).unwrap();

    // Original + 50 bytes padding
    assert_eq!(result.len(), 150);
}

/// Test packet modifier with zero padding.
#[test]
fn test_packet_modifier_zero_padding() {
    let config = PacketModConfig {
        data_length: Some(0),
        bad_checksum: false,
        ip_options: None,
        ttl: None,
        tos: None,
        no_flags: false,
    };
    let modifier = PacketModifier::new(config);

    let packet = vec![0u8; 100];
    let result = modifier.apply(packet.clone()).unwrap();

    // No change
    assert_eq!(result.len(), packet.len());
}

/// Test packet modifier with bad checksum.
#[test]
fn test_packet_modifier_bad_checksum() {
    let config = PacketModConfig {
        data_length: None,
        bad_checksum: true,
        ip_options: None,
        ttl: None,
        tos: None,
        no_flags: false,
    };
    let modifier = PacketModifier::new(config);

    // Create a packet with at least 12 bytes
    let packet = vec![
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    ];
    let result = modifier.apply(packet.clone()).unwrap();

    // Checksum bytes should be modified
    assert_ne!(result[10..12], packet[10..12]);
}

/// Test packet modifier with small packet and bad checksum.
#[test]
fn test_packet_modifier_bad_checksum_small_packet() {
    let config = PacketModConfig {
        data_length: None,
        bad_checksum: true,
        ip_options: None,
        ttl: None,
        tos: None,
        no_flags: false,
    };
    let modifier = PacketModifier::new(config);

    // Small packet - checksum modification should be skipped
    let packet = vec![0u8; 5];
    let result = modifier.apply(packet.clone()).unwrap();

    // Should remain unchanged
    assert_eq!(result, packet);
}

/// Test packet modifier with combined modifications.
#[test]
fn test_packet_modifier_combined() {
    let config = PacketModConfig {
        data_length: Some(20),
        bad_checksum: true,
        ip_options: None,
        ttl: None,
        tos: None,
        no_flags: false,
    };
    let modifier = PacketModifier::new(config);

    let packet = vec![
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    ];
    let result = modifier.apply(packet).unwrap();

    // Should have padding
    assert_eq!(result.len(), 32); // 12 + 20
}

// =============================================================================
// TimingController Tests
// =============================================================================

/// Test timing controller creation for all templates.
#[test]
fn test_timing_controller_all_templates() {
    let templates = [
        TimingTemplate::Paranoid,
        TimingTemplate::Sneaky,
        TimingTemplate::Polite,
        TimingTemplate::Normal,
        TimingTemplate::Aggressive,
        TimingTemplate::Insane,
    ];

    for template in &templates {
        let controller = TimingController::new(*template);
        assert_eq!(controller.template(), *template);
    }
}

/// Test timing controller default creation.
#[test]
fn test_timing_controller_default() {
    let controller = TimingController::new_default();
    assert_eq!(controller.template(), TimingTemplate::Normal);
}

/// Test timing values for paranoid template.
#[test]
fn test_timing_controller_paranoid_values() {
    let controller = TimingController::new(TimingTemplate::Paranoid);
    let values = controller.values();

    assert!(controller.is_stealthy());
    assert!(!controller.is_aggressive());

    // Paranoid should have long timeouts and delays
    assert_eq!(values.scan_delay_ms, 300);
    assert_eq!(values.max_parallel, 1);
}

/// Test timing values for insane template.
#[test]
fn test_timing_controller_insane_values() {
    let controller = TimingController::new(TimingTemplate::Insane);
    let values = controller.values();

    assert!(!controller.is_stealthy());
    assert!(controller.is_aggressive());

    // Insane should have minimal delays
    assert_eq!(values.scan_delay_ms, 0);
    assert_eq!(values.max_parallel, 1000);
}

/// Test timing controller timeout accessors.
#[test]
fn test_timing_controller_timeouts() {
    let controller = TimingController::new(TimingTemplate::Normal);

    assert_eq!(
        controller.initial_rtt_timeout(),
        Duration::from_millis(1000)
    );
    assert_eq!(controller.min_rtt_timeout(), Duration::from_millis(100));
    assert_eq!(controller.max_rtt_timeout(), Duration::from_millis(10_000));
}

/// Test timing controller scan delay.
#[test]
fn test_timing_controller_scan_delay() {
    let polite = TimingController::new(TimingTemplate::Polite);
    assert_eq!(polite.scan_delay(), Duration::from_millis(10));

    let normal = TimingController::new(TimingTemplate::Normal);
    assert_eq!(normal.scan_delay(), Duration::from_millis(0));

    let paranoid = TimingController::new(TimingTemplate::Paranoid);
    assert_eq!(paranoid.scan_delay(), Duration::from_millis(300));
}

/// Test timing controller max retries.
#[test]
fn test_timing_controller_max_retries() {
    let paranoid = TimingController::new(TimingTemplate::Paranoid);
    assert_eq!(paranoid.max_retries(), 10);

    let normal = TimingController::new(TimingTemplate::Normal);
    assert_eq!(normal.max_retries(), 2);

    let insane = TimingController::new(TimingTemplate::Insane);
    assert_eq!(insane.max_retries(), 0);
}

/// Test timing controller max parallel.
#[test]
fn test_timing_controller_max_parallel() {
    let paranoid = TimingController::new(TimingTemplate::Paranoid);
    assert_eq!(paranoid.max_parallel(), 1);

    let normal = TimingController::new(TimingTemplate::Normal);
    assert_eq!(normal.max_parallel(), 100);

    let insane = TimingController::new(TimingTemplate::Insane);
    assert_eq!(insane.max_parallel(), 1000);
}

/// Test timing template config method.
#[test]
fn test_timing_template_config() {
    let config = TimingTemplate::Normal.config();
    assert_eq!(config.initial_rtt_timeout_ms, 1000);
    assert_eq!(config.scan_delay_ms, 0);
}

// =============================================================================
// Integration Tests - Combined Evasion Techniques
// =============================================================================

/// Test combining multiple evasion techniques.
#[test]
fn test_combined_evasion_techniques() {
    // Create a complex evasion config
    let config = EvasionConfig::builder()
        .fragmentation_mtu(500)
        .decoys(vec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ])
        .source_ip("10.0.0.1".parse().unwrap())
        .source_port(53)
        .ttl(255)
        .bad_checksum()
        .data_length(50)
        .timing_template(TimingTemplate::Sneaky)
        .build()
        .unwrap();

    // Verify all techniques are enabled
    assert!(config.is_enabled());
    assert!(config.fragmentation.is_some());
    assert!(config.decoys.is_some());
    assert!(config.source.source_ip.is_some());
    assert!(config.source.source_port.is_some());
    assert!(config.packet_modification.bad_checksum);
    assert!(config.packet_modification.data_length.is_some());
    assert!(config.packet_modification.ttl.is_some());

    // Test fragmentation
    let fragmenter = Fragmenter::new(config.fragmentation.clone().unwrap());
    let packet = vec![0u8; 1000];
    let fragments = fragmenter.fragment(&packet, 1500).unwrap();
    assert!(fragments.len() > 1);

    // Test decoy scheduler
    let decoy_config = config.decoys.clone().unwrap();
    let real_ip = "192.168.1.100".parse::<IpAddr>().unwrap();
    let scheduler = DecoyScheduler::new(decoy_config, real_ip).unwrap();
    assert_eq!(scheduler.total_sources(), 3);

    // Test source spoofer
    let spoofer = SourceSpoofer::new(config.source.clone(), real_ip);
    assert!(spoofer.is_ip_spoofed());
    assert!(spoofer.is_port_spoofed());

    // Test packet modifier
    let modifier = PacketModifier::new(config.packet_modification.clone());
    let modified_pkt = modifier.apply(packet).unwrap();
    assert_eq!(modified_pkt.len(), 1050); // 1000 + 50 padding

    // Test timing controller
    let timing = TimingController::new(config.timing.template);
    assert!(timing.is_stealthy());
}

/// Test error types.
#[test]
fn test_error_types() {
    use rustnmap_evasion::Error;

    let err = Error::InvalidFragmentSize { size: 5 };
    assert!(err.to_string().contains("invalid fragment size"));

    let err = Error::InvalidDecoyConfig("test error".into());
    assert!(err.to_string().contains("invalid decoy configuration"));

    let err = Error::InvalidIpAddress("bad ip".into());
    assert!(err.to_string().contains("invalid IP address"));

    let err = Error::InvalidPort { port: 0 };
    assert!(err.to_string().contains("invalid port"));

    let err = Error::InvalidTtl { ttl: 0 };
    assert!(err.to_string().contains("invalid TTL"));

    let err = Error::InvalidTimingTemplate("bad".into());
    assert!(err.to_string().contains("invalid timing template"));

    let err = Error::Configuration("config error".into());
    assert!(err.to_string().contains("configuration error"));
}
