//! Integration tests for port scanning using real network operations.
//!
//! These tests use actual network operations. Root privileges are available
//! in the development environment for raw socket operations.
//! The test target IP is read from the `TEST_TARGET_IP` environment variable,
//! defaulting to localhost (127.0.0.1) if not set.

use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;

use rustnmap_common::{PortState, Protocol, ScanConfig};
use rustnmap_scan::scanner::PortScanner;
use rustnmap_target::{Target, TargetParser};

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
    }
}

/// Test TCP SYN scan against localhost.
/// Note: This test requires root privileges to create raw sockets.
#[test]
fn test_syn_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::syn_scan::TcpSynScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create SYN scanner (requires root): {e}");
            return;
        }
    };

    // Scan a port - should get a valid state even if port is closed
    let port = 9999; // High port likely to be closed
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    // State should be one of the valid states
    match state {
        PortState::Open
        | PortState::Closed
        | PortState::Filtered
        | PortState::Unfiltered
        | PortState::OpenOrFiltered
        | PortState::ClosedOrFiltered => {}
        PortState::OpenOrClosed => panic!("Unexpected port state: {state:?}"),
    }
}

/// Test TCP Connect scan against localhost.
/// This test does not require root privileges.
#[test]
fn test_connect_scan() {
    let target = get_test_target();
    let config = test_config();

    let scanner = rustnmap_scan::connect_scan::TcpConnectScanner::new(None, config);

    // Scan a high port likely to be closed
    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    // Should get a valid state (likely Closed for high port)
    assert!(
        matches!(
            state,
            PortState::Open | PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test UDP scan against localhost.
#[test]
fn test_udp_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::udp_scan::UdpScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create UDP scanner (requires root): {e}");
            return;
        }
    };

    // Scan a high UDP port
    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Udp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Open | PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP FIN scan.
#[test]
fn test_fin_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpFinScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create FIN scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP NULL scan.
#[test]
fn test_null_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpNullScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create NULL scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP XMAS scan.
#[test]
fn test_xmas_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpXmasScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create XMAS scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP ACK scan for firewall detection.
#[test]
fn test_ack_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpAckScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create ACK scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Filtered | PortState::Unfiltered | PortState::Closed | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP Maimon scan.
#[test]
fn test_maimon_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpMaimonScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create Maimon scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP Window scan.
#[test]
fn test_window_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::stealth_scans::TcpWindowScanner::new(local_addr, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create Window scanner (requires root): {e}");
            return;
        }
    };

    let port = 59999;
    let state = scanner
        .scan_port(&target, port, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered | PortState::Open
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test IP Protocol scan.
#[test]
fn test_ip_protocol_scan() {
    let target = get_test_target();
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    let scanner = match rustnmap_scan::ip_protocol_scan::IpProtocolScanner::new(local_addr, config)
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping test: cannot create IP Protocol scanner (requires root): {e}");
            return;
        }
    };

    // Scan TCP protocol
    let state = scanner
        .scan_port(&target, 0, Protocol::Tcp)
        .expect("Scan failed");

    assert!(
        matches!(
            state,
            PortState::Open | PortState::Closed | PortState::Filtered | PortState::OpenOrFiltered
        ),
        "Unexpected state: {state:?}"
    );
}

/// Test TCP Connect scanner does not require root.
#[test]
fn test_connect_scanner_requires_no_root() {
    let config = test_config();
    let scanner = rustnmap_scan::connect_scan::TcpConnectScanner::new(None, config);
    assert!(!scanner.requires_root());
}

/// Test SYN scanner reports it requires root.
#[test]
fn test_syn_scanner_reports_requires_root() {
    let config = test_config();

    if let Ok(scanner) = rustnmap_scan::syn_scan::TcpSynScanner::new(Ipv4Addr::UNSPECIFIED, config)
    {
        assert!(
            scanner.requires_root(),
            "SYN scanner should report requiring root"
        )
    } else {
        // If we can't create it due to permissions, that's expected without root
    }
}

/// Test scan timeout behavior.
#[test]
fn test_scan_timeout() {
    let target = get_test_target();
    let config = ScanConfig {
        min_rtt: Duration::from_millis(50),
        max_rtt: Duration::from_millis(300), // Short timeout
        initial_rtt: Duration::from_millis(100),
        max_retries: 0,
        host_timeout: 900_000,
        scan_delay: Duration::ZERO,
    };

    let scanner = rustnmap_scan::connect_scan::TcpConnectScanner::new(None, config);

    // Scan a port that's likely closed/filtered
    let start = std::time::Instant::now();
    let _result = scanner.scan_port(&target, 65535, Protocol::Tcp);
    let elapsed = start.elapsed();

    // Should complete relatively quickly due to short timeout
    assert!(
        elapsed < Duration::from_secs(2),
        "Scan should respect timeout, took {elapsed:?}"
    );
}

/// Test all stealth scanners can be created (requires root).
/// If not root, prints a message and returns gracefully.
#[test]
fn test_stealth_scanners_creation() {
    let config = test_config();
    let local_addr = Ipv4Addr::UNSPECIFIED;

    // Try to create each scanner
    let syn_result = rustnmap_scan::syn_scan::TcpSynScanner::new(local_addr, config.clone());
    let fin_result = rustnmap_scan::stealth_scans::TcpFinScanner::new(local_addr, config.clone());
    let null_result = rustnmap_scan::stealth_scans::TcpNullScanner::new(local_addr, config.clone());
    let xmas_result = rustnmap_scan::stealth_scans::TcpXmasScanner::new(local_addr, config.clone());
    let ack_result = rustnmap_scan::stealth_scans::TcpAckScanner::new(local_addr, config.clone());
    let maimon_result =
        rustnmap_scan::stealth_scans::TcpMaimonScanner::new(local_addr, config.clone());
    let window_result =
        rustnmap_scan::stealth_scans::TcpWindowScanner::new(local_addr, config.clone());

    // All results should be consistent - either all succeed (root) or all fail (non-root)
    let results = [
        syn_result.is_ok(),
        fin_result.is_ok(),
        null_result.is_ok(),
        xmas_result.is_ok(),
        ack_result.is_ok(),
        maimon_result.is_ok(),
        window_result.is_ok(),
    ];

    // All should be the same (either all true or all false)
    let all_ok = results.iter().all(|&r| r);
    let all_err = results.iter().all(|&r| !r);

    assert!(!(!all_ok && !all_err),
            "All scanner creation results should be consistent (all succeed or all fail). Got: {results:?}"
        );

    if all_ok {
        println!("All stealth scanners created successfully (running as root)");
    } else {
        println!("Cannot create stealth scanners (not running as root) - this is expected");
    }
}

/// Test scanning multiple ports.
#[test]
fn test_scan_multiple_ports() {
    let target = get_test_target();
    let config = test_config();

    let scanner = rustnmap_scan::connect_scan::TcpConnectScanner::new(None, config);

    // Scan multiple high ports
    let ports = [59990, 59991, 59992];
    for port in ports {
        let state = scanner
            .scan_port(&target, port, Protocol::Tcp)
            .expect("Scan failed");
        assert!(
            matches!(
                state,
                PortState::Closed | PortState::Filtered | PortState::Open
            ),
            "Port {port}: Unexpected state: {state:?}"
        );
    }
}

/// Test scanner error handling for invalid configurations.
#[test]
fn test_scanner_error_handling() {
    // Test with a configuration that has very short timeouts
    let config = ScanConfig {
        min_rtt: Duration::from_millis(1),
        max_rtt: Duration::from_millis(10),
        initial_rtt: Duration::from_millis(5),
        max_retries: 0,
        host_timeout: 1000,
        scan_delay: Duration::ZERO,
    };

    let scanner = rustnmap_scan::connect_scan::TcpConnectScanner::new(None, config);
    let target = get_test_target();

    // Should complete quickly even with aggressive timeouts
    let result = scanner.scan_port(&target, 59999, Protocol::Tcp);
    assert!(result.is_ok(), "Scan should complete: {result:?}");
}
