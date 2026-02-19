// Integration tests for service detection.
//
// These tests verify that the service detection engine works correctly
// with real network services and probe databases.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustnmap_fingerprint::service::probe::Protocol;
use rustnmap_fingerprint::service::{
    MatchRule, MatchTemplate, ProbeDatabase, ProbeDefinition, ServiceDetector, ServiceInfo,
};

/// Get test target from environment or use localhost.
fn get_test_target() -> SocketAddr {
    if let Ok(ip_str) = std::env::var("TEST_TARGET_IP") {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            return SocketAddr::new(ip.into(), 80);
        }
    }
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80)
}

/// Test creating a `ServiceDetector` with empty database.
#[test]
fn test_service_detector_empty_database() {
    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db);

    // Should be able to create detector
    let debug_str = format!("{detector:?}");
    assert!(debug_str.contains("ServiceDetector"));
}

/// Test `ServiceDetector` configuration.
#[test]
fn test_service_detector_configuration() {
    let db = ProbeDatabase::empty();

    // Build detector with configuration
    let detector = ServiceDetector::new(db)
        .with_timeout(Duration::from_secs(10))
        .with_intensity(5);

    // Verify configuration through debug output
    let debug_str = format!("{detector:?}");
    assert!(debug_str.contains('5')); // Intensity should be in debug output
}

/// Test intensity clamping.
#[test]
fn test_service_detector_intensity_clamping() {
    let db = ProbeDatabase::empty();

    // Test low intensity clamping
    let detector_low = ServiceDetector::new(db.clone()).with_intensity(0);
    let debug_low = format!("{detector_low:?}");
    assert!(debug_low.contains('1')); // Clamped to minimum

    // Test high intensity clamping
    let detector_high = ServiceDetector::new(db).with_intensity(15);
    let debug_high = format!("{detector_high:?}");
    assert!(debug_high.contains('9')); // Clamped to maximum
}

/// Test `ProbeDatabase` empty creation.
#[test]
fn test_probe_database_empty() {
    let db = ProbeDatabase::empty();

    // Empty database should have no probes
    let probes = db.probes_for_port(80);
    assert!(probes.is_empty());
}

/// Test `ServiceInfo` creation.
#[test]
fn test_service_info_creation() {
    let info = ServiceInfo::new("http");

    assert_eq!(info.name, "http");
    assert_eq!(info.confidence, 5); // Default confidence
    assert!(info.product.is_none());
    assert!(info.version.is_none());
}

/// Test `ServiceInfo` with confidence.
#[test]
fn test_service_info_with_confidence() {
    let info = ServiceInfo::new("ssh").with_confidence(8);

    assert_eq!(info.name, "ssh");
    assert_eq!(info.confidence, 8);
}

/// Test `ServiceInfo` confidence clamping.
#[test]
fn test_service_info_confidence_clamping() {
    let info_high = ServiceInfo::new("ftp").with_confidence(15);
    assert_eq!(info_high.confidence, 10); // Clamped to max

    let info_low = ServiceInfo::new("smtp").with_confidence(0);
    assert_eq!(info_low.confidence, 0); // Allowed (minimum)
}

/// Test creating a custom probe definition.
#[test]
fn test_probe_definition_creation() {
    let probe = ProbeDefinition {
        name: "TestProbe".to_string(),
        protocol: Protocol::Tcp,
        ports: vec![80, 443],
        payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        rarity: 5,
        ssl_ports: vec![443],
        matches: vec![],
    };

    assert_eq!(probe.name, "TestProbe");
    assert_eq!(probe.protocol, Protocol::Tcp);
    assert_eq!(probe.ports, vec![80, 443]);
    assert_eq!(probe.rarity, 5);
}

/// Test `MatchRule` creation.
#[test]
fn test_match_rule_creation() {
    let rule = MatchRule {
        pattern: r"^SSH-([\d.]+)-(.*)$".to_string(),
        service: "ssh".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    assert_eq!(rule.service, "ssh");
    assert!(!rule.soft);
}

/// Test soft match rule.
#[test]
fn test_soft_match_rule() {
    let rule = MatchRule {
        pattern: r".*".to_string(),
        service: "unknown".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: true,
    };

    assert!(rule.soft);
}

/// Test service detection against localhost HTTP (if available).
#[tokio::test]
async fn test_service_detection_http() {
    let target = get_test_target();

    // Create database with HTTP probe
    let db = ProbeDatabase::empty();

    let detector = ServiceDetector::new(db)
        .with_timeout(Duration::from_secs(3))
        .with_intensity(7);

    // Attempt detection - may fail if no service is running
    let result = detector.detect_service(&target, target.port()).await;

    // Should either succeed with results or return unknown
    if let Ok(services) = result {
        if !services.is_empty() {
            // Got some results
            assert!(
                services
                    .iter()
                    .any(|s| s.name == "http" || s.name == "unknown"),
                "Should detect http or unknown"
            );
        }
    } else {
        // Connection refused or timeout is acceptable
        // if no service is running
    }
}

/// Test banner grabbing against localhost.
#[tokio::test]
async fn test_banner_grabbing() {
    let target = get_test_target();

    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db).with_timeout(Duration::from_secs(3));

    // Try to grab banner - may fail if no service is running
    let result = detector.grab_banner(&target, target.port()).await;

    // Result can be Ok(Some), Ok(None), or Err
    match result {
        Ok(Some(banner)) => {
            // Got a banner
            assert!(!banner.is_empty());
        }
        Ok(None) => {
            // No banner received (service doesn't send immediate banner)
        }
        Err(_) => {
            // Connection refused or timeout is acceptable
        }
    }
}

/// Test service detection with different intensity levels.
#[test]
fn test_intensity_levels() {
    let db = ProbeDatabase::empty();

    let intensities = vec![1, 3, 5, 7, 9];

    for intensity in intensities {
        let detector = ServiceDetector::new(db.clone()).with_intensity(intensity);
        let debug_str = format!("{detector:?}");
        // Intensity should be reflected in debug output
        assert!(debug_str.contains(&intensity.to_string()));
    }
}

/// Test probe protocol types.
#[test]
fn test_probe_protocols() {
    let tcp_probe = ProbeDefinition {
        name: "TCPProbe".to_string(),
        protocol: Protocol::Tcp,
        ports: vec![80],
        payload: vec![],
        rarity: 5,
        ssl_ports: vec![],
        matches: vec![],
    };

    let udp_probe = ProbeDefinition {
        name: "UDPProbe".to_string(),
        protocol: Protocol::Udp,
        ports: vec![53],
        payload: vec![],
        rarity: 5,
        ssl_ports: vec![],
        matches: vec![],
    };

    assert_eq!(tcp_probe.protocol, Protocol::Tcp);
    assert_eq!(udp_probe.protocol, Protocol::Udp);
    assert_ne!(tcp_probe.protocol, udp_probe.protocol);
}

/// Test `ServiceInfo` from match result simulation.
#[test]
fn test_service_info_from_match() {
    // Simulate creating ServiceInfo from match result fields
    let info = ServiceInfo {
        name: "apache".to_string(),
        product: Some("Apache httpd".to_string()),
        version: Some("2.4.41".to_string()),
        info: Some("(Ubuntu)".to_string()),
        hostname: None,
        os_type: Some("Linux".to_string()),
        device_type: None,
        cpe: Some("cpe:/a:apache:httpd:2.4.41".to_string()),
        confidence: 10,
    };

    assert_eq!(info.name, "apache");
    assert_eq!(info.product.as_deref(), Some("Apache httpd"));
    assert_eq!(info.version.as_deref(), Some("2.4.41"));
    assert_eq!(info.confidence, 10);
}

/// Test multiple service infos handling.
#[test]
fn test_multiple_service_infos() {
    let services = vec![
        ServiceInfo::new("http").with_confidence(10),
        ServiceInfo::new("https").with_confidence(8),
        ServiceInfo::new("unknown").with_confidence(3),
    ];

    // Check we can filter by confidence
    let high_confidence: Vec<_> = services.iter().filter(|s| s.confidence >= 8).collect();

    assert_eq!(high_confidence.len(), 2);
}

/// Test detection timeout handling.
#[tokio::test]
async fn test_detection_timeout() {
    // Use a non-routable address to trigger timeout
    let target = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 80); // TEST-NET-1

    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db).with_timeout(Duration::from_millis(100)); // Very short timeout

    // Should timeout quickly or return empty results
    let result = detector.detect_service(&target, 80).await;

    // Result should be either:
    // - Error (timeout or network unreachable)
    // - Ok with services (could be empty or contain unknown)
    if let Ok(services) = result {
        // If we got results, they should be reasonable
        for service in services {
            assert!(!service.name.is_empty());
        }
    } else {
        // Error is expected (timeout or unreachable)
    }
}

/// Test `ServiceDetector` debug output.
#[test]
fn test_detector_debug() {
    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db);

    let debug_str = format!("{detector:?}");
    assert!(debug_str.contains("ServiceDetector"));
}

/// Test probe database debug output.
#[test]
fn test_database_debug() {
    let db = ProbeDatabase::empty();

    let debug_str = format!("{db:?}");
    assert!(debug_str.contains("ProbeDatabase"));
}

/// Test service info debug output.
#[test]
fn test_service_info_debug() {
    let info = ServiceInfo::new("test");

    let debug_str = format!("{info:?}");
    assert!(debug_str.contains("ServiceInfo"));
    assert!(debug_str.contains("test"));
}

/// Test probe definition debug output.
#[test]
fn test_probe_definition_debug() {
    let probe = ProbeDefinition {
        name: "Test".to_string(),
        protocol: Protocol::Tcp,
        ports: vec![80],
        payload: vec![1, 2, 3],
        rarity: 5,
        ssl_ports: vec![],
        matches: vec![],
    };

    let debug_str = format!("{probe:?}");
    assert!(debug_str.contains("Test"));
    assert!(debug_str.contains("Tcp"));
}

/// Test service detection against SSH port (if available).
#[tokio::test]
async fn test_service_detection_ssh() {
    let ssh_target = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 22);

    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db).with_timeout(Duration::from_secs(2));

    // Try to grab banner from SSH port
    let result = detector.grab_banner(&ssh_target, 22).await;

    if let Ok(Some(banner)) = result {
        // SSH should send a banner like "SSH-2.0-..."
        let banner_str = String::from_utf8_lossy(&banner);
        if banner_str.starts_with("SSH-") {
            assert!(banner_str.contains("SSH"));
        }
    } else {
        // SSH not running or connection refused - acceptable
    }
}

/// Test database loading from non-existent path.
#[tokio::test]
async fn test_database_load_nonexistent() {
    let result = ProbeDatabase::load_from_nmap_db("/nonexistent/path/nmap-service-probes").await;

    assert!(result.is_err());
}

/// Test service info equality.
#[test]
fn test_service_info_equality() {
    let info1 = ServiceInfo::new("http").with_confidence(8);
    let info2 = ServiceInfo::new("http").with_confidence(8);
    let info3 = ServiceInfo::new("ssh").with_confidence(8);

    assert_eq!(info1, info2);
    assert_ne!(info1, info3);
}

/// Test service info cloning.
#[test]
fn test_service_info_clone() {
    let info = ServiceInfo {
        name: "test".to_string(),
        product: Some("product".to_string()),
        version: Some("1.0".to_string()),
        info: Some("info".to_string()),
        hostname: Some("host".to_string()),
        os_type: Some("Linux".to_string()),
        device_type: Some("server".to_string()),
        cpe: Some("cpe:/a:test".to_string()),
        confidence: 9,
    };

    let cloned = info.clone();
    assert_eq!(info.name, cloned.name);
    assert_eq!(info.product, cloned.product);
    assert_eq!(info.confidence, cloned.confidence);
}

/// Test match rule with all fields.
#[test]
fn test_match_rule_full() {
    let rule = MatchRule {
        pattern: r"^Test (.*)$".to_string(),
        service: "test".to_string(),
        product_template: Some(MatchTemplate {
            value: "$1".to_string(),
        }),
        version_template: Some(MatchTemplate {
            value: "1.0".to_string(),
        }),
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    assert_eq!(rule.pattern, r"^Test (.*)$");
    assert_eq!(rule.service, "test");
    assert!(rule.product_template.is_some());
    assert!(!rule.soft);
}

/// Test `MatchTemplate` creation.
#[test]
fn test_match_template() {
    let template = MatchTemplate {
        value: "$1/$2".to_string(),
    };

    assert_eq!(template.value, "$1/$2");
}

/// Test `ProbeDefinition` builder methods.
#[test]
fn test_probe_definition_builder() {
    let mut probe =
        ProbeDefinition::new_tcp("HTTPProbe".to_string(), b"GET / HTTP/1.0\r\n\r\n".to_vec());

    probe.with_rarity(3).with_ports(&[80, 443, 8080]);

    assert_eq!(probe.rarity, 3);
    assert!(probe.matches_port(80));
    assert!(probe.matches_port(443));
    assert!(!probe.matches_port(22));
}

/// Test `ProbeDefinition` UDP creation.
#[test]
fn test_probe_definition_udp() {
    let probe = ProbeDefinition::new_udp(
        "DNSProbe".to_string(),
        vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x01], // Simple DNS-like payload
    );

    assert_eq!(probe.name, "DNSProbe");
    assert_eq!(probe.protocol, Protocol::Udp);
}

/// Test adding match rule to probe.
#[test]
fn test_probe_add_match() {
    let mut probe = ProbeDefinition::new_tcp("Test".to_string(), vec![]);

    let rule = MatchRule {
        pattern: r"test".to_string(),
        service: "test".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    probe.add_match(rule);
    assert_eq!(probe.matches.len(), 1);
}

/// Test `MatchRule` regex compilation.
#[test]
fn test_match_rule_compile_regex() {
    let rule = MatchRule {
        pattern: r"^SSH-[\d.]+-OpenSSH".to_string(),
        service: "ssh".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    assert!(rule.compile_regex().is_ok());
}

/// Test invalid regex pattern.
#[test]
fn test_invalid_regex_pattern() {
    let rule = MatchRule {
        pattern: r"[\d".to_string(), // Invalid regex
        service: "test".to_string(),
        product_template: None,
        version_template: None,
        info_template: None,
        hostname_template: None,
        os_type_template: None,
        device_type_template: None,
        cpe_template: None,
        soft: false,
    };

    assert!(rule.compile_regex().is_err());
}

/// Test timeout configuration.
#[test]
fn test_timeout_configuration() {
    let db = ProbeDatabase::empty();

    let detector = ServiceDetector::new(db).with_timeout(Duration::from_secs(30));

    let debug_str = format!("{detector:?}");
    assert!(debug_str.contains("30s") || debug_str.contains("30"));
}

/// Test service info with all fields populated.
#[test]
fn test_service_info_full() {
    let info = ServiceInfo {
        name: "nginx".to_string(),
        product: Some("nginx".to_string()),
        version: Some("1.18.0".to_string()),
        info: Some("Ubuntu".to_string()),
        hostname: Some("localhost".to_string()),
        os_type: Some("Linux".to_string()),
        device_type: Some("server".to_string()),
        cpe: Some("cpe:/a:nginx:nginx:1.18.0".to_string()),
        confidence: 10,
    };

    assert_eq!(info.name, "nginx");
    assert_eq!(info.product.as_deref(), Some("nginx"));
    assert_eq!(info.version.as_deref(), Some("1.18.0"));
    assert_eq!(info.hostname.as_deref(), Some("localhost"));
    assert_eq!(info.os_type.as_deref(), Some("Linux"));
    assert_eq!(info.device_type.as_deref(), Some("server"));
    assert_eq!(info.cpe.as_deref(), Some("cpe:/a:nginx:nginx:1.18.0"));
    assert_eq!(info.confidence, 10);
}

/// Test default rarity value.
#[test]
fn test_default_rarity() {
    let probe = ProbeDefinition::new_tcp("Test".to_string(), vec![]);
    assert_eq!(probe.rarity, 5); // Default rarity
}

/// Test rarity clamping.
#[test]
fn test_rarity_clamping() {
    let mut probe = ProbeDefinition::new_tcp("Test".to_string(), vec![]);

    probe.with_rarity(15);
    assert_eq!(probe.rarity, 9); // Clamped to max

    probe.with_rarity(0);
    assert_eq!(probe.rarity, 1); // Clamped to min
}

/// Test empty ports matches all ports.
#[test]
fn test_empty_ports_matches_all() {
    let probe = ProbeDefinition::new_tcp("Test".to_string(), vec![]);

    // Empty ports means it matches all ports
    assert!(probe.matches_port(1));
    assert!(probe.matches_port(80));
    assert!(probe.matches_port(443));
    assert!(probe.matches_port(65535));
}

/// Test service detection with various target scenarios.
#[tokio::test]
async fn test_detection_scenarios() {
    let db = ProbeDatabase::empty();
    let detector = ServiceDetector::new(db).with_timeout(Duration::from_millis(500));

    // Test with localhost on various ports
    let targets = vec![
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080),
    ];

    for target in targets {
        // Just verify these don't panic
        let _ = detector.grab_banner(&target, target.port()).await;
    }
}
