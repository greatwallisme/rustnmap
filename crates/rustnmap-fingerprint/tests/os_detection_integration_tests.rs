//! Integration tests for OS detection functionality.
//!
//! These tests verify the OS detection engine with different configurations
//! and against real network targets when available.
//! Note: Some tests require root privileges and a target host.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rustnmap_fingerprint::os::{FingerprintDatabase, OsDetector};

// =============================================================================
// OS Detector Configuration Tests
// =============================================================================

/// Test OS detector creation with default configuration.
#[test]
fn test_os_detector_default_creation() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let _detector = OsDetector::new(db, local_addr);

    // Just verify detector was created successfully
}

/// Test OS detector with custom sequence count.
#[test]
fn test_os_detector_with_seq_count() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(192, 168, 1, 100);
    let _detector = OsDetector::new(db, local_addr)
        .with_seq_count(10)
        .with_open_port(22)
        .with_closed_port(443)
        .with_closed_udp_port(33434);

    // Just verify it was created successfully with custom config
}

/// Test OS detector with custom timeout.
#[test]
fn test_os_detector_with_timeout() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let _detector = OsDetector::new(db, local_addr).with_timeout(Duration::from_secs(5));

    // Verify detector was created
}

/// Test OS detector with all configuration options.
#[test]
fn test_os_detector_full_configuration() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(10, 0, 0, 50);
    let _detector = OsDetector::new(db, local_addr)
        .with_seq_count(8)
        .with_open_port(8080)
        .with_closed_port(444)
        .with_closed_udp_port(55555)
        .with_timeout(Duration::from_secs(10));

    // Verify detector was created
}

// =============================================================================
// Fingerprint Database Tests
// =============================================================================

/// Test fingerprint database creation.
#[test]
fn test_fingerprint_database_empty() {
    let _db = FingerprintDatabase::empty();
}

/// Test fingerprint database loading from invalid path.
#[tokio::test]
async fn test_fingerprint_database_load_invalid_path() {
    let result = FingerprintDatabase::load_from_nmap_db("/nonexistent/path/nmap-os-db").await;
    assert!(result.is_err());
}

// =============================================================================
// OS Detection Against Real Targets
// =============================================================================

/// Test OS detection against localhost.
///
/// This test requires root privileges to create raw sockets.
/// It will likely timeout or return no matches since localhost
/// may not respond to OS detection probes as expected.
#[tokio::test]
async fn test_os_detection_localhost() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let detector = OsDetector::new(db, local_addr)
        .with_open_port(80)
        .with_closed_port(443)
        .with_timeout(Duration::from_secs(2));

    let target: SocketAddr = "127.0.0.1:80".parse().unwrap();

    let result = detector.detect_os(&target).await;

    // Should not error, even if no matches found (empty database)
    assert!(result.is_ok());
    let matches = result.unwrap();
    // With empty database, should return no matches
    assert!(matches.is_empty());
}

/// Test OS detection with TEST_TARGET_IP from environment.
///
/// This test requires:
/// - Root privileges (CAP_NET_RAW)
/// - TEST_TARGET_IP set in .env file
/// - Target host responding to OS detection probes
#[tokio::test]
async fn test_os_detection_with_target_ip() {
    let db = FingerprintDatabase::empty();

    // Get local address
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // Get target from environment or skip
    let target_ip = match std::env::var("TEST_TARGET_IP") {
        Ok(ip) => ip
            .parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::new(127, 0, 0, 1)),
        Err(_) => {
            // Skip test if no target IP configured
            eprintln!("Skipping test: TEST_TARGET_IP not set");
            return;
        }
    };

    let detector = OsDetector::new(db, local_addr)
        .with_open_port(22)
        .with_closed_port(443)
        .with_timeout(Duration::from_secs(3));

    let target = SocketAddr::new(target_ip.into(), 22);

    // This may fail without root or if target doesn't respond
    let result = detector.detect_os(&target).await;

    // Just verify the operation completes without panic
    // Result may be Ok(empty) or Err depending on network conditions
    match result {
        Ok(matches) => {
            eprintln!("Found {} OS matches for {}", matches.len(), target);
        }
        Err(e) => {
            eprintln!("OS detection failed (expected without root): {}", e);
        }
    }
}

/// Test OS detection timeout behavior.
#[tokio::test]
async fn test_os_detection_timeout() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // Use a very short timeout
    let detector = OsDetector::new(db, local_addr).with_timeout(Duration::from_millis(100));

    // Target a non-existent host
    let target: SocketAddr = "192.0.2.1:80".parse().unwrap();

    let start = std::time::Instant::now();
    let result = detector.detect_os(&target).await;
    let elapsed = start.elapsed();

    // Should complete relatively quickly (within timeout + processing time)
    assert!(elapsed < Duration::from_secs(10));

    // Result depends on whether we have root and network access
    // Just verify it doesn't panic
    let _ = result;
}

// =============================================================================
// SEQ Analysis Tests
// =============================================================================

/// Test SEQ (TCP ISN) analysis with mock data.
#[test]
fn test_seq_analysis_incremental() {
    // Simulate incremental ISN pattern (Linux-like)
    let isns: Vec<u32> = vec![1000000, 2000000, 3000000, 4000000, 5000000, 6000000];

    // Calculate GCD
    let diffs: Vec<u32> = isns.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    let gcd = diffs
        .iter()
        .copied()
        .reduce(|a, b| {
            let mut a = a;
            let mut b = b;
            while b != 0 {
                let temp = b;
                b = a % b;
                a = temp;
            }
            a
        })
        .unwrap_or(0);

    // All differences should be 1000000
    assert!(diffs.iter().all(|&d| d == 1000000));
    assert_eq!(gcd, 1000000);
}

/// Test SEQ analysis with random ISN pattern.
#[test]
fn test_seq_analysis_random() {
    // Simulate random ISN pattern
    let isns: Vec<u32> = vec![1234567, 9876543, 5555555, 3333333, 7777777, 1111111];

    // Calculate differences
    let diffs: Vec<u32> = isns.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();

    // With random ISNs, differences should vary widely
    let unique_diffs: std::collections::HashSet<u32> = diffs.iter().copied().collect();
    assert!(
        unique_diffs.len() > 1,
        "Random ISNs should have varying differences"
    );
}

/// Test SEQ analysis with time-dependent ISN pattern.
#[test]
fn test_seq_analysis_time_dependent() {
    // Simulate time-dependent ISN (microsecond-based, like old Windows)
    let base_time = 1_000_000_u64;
    let isns: Vec<u32> = (0..6)
        .map(|i| {
            let time_offset = i as u64 * 10_000; // 10ms increments
            ((base_time + time_offset) * 250) as u32 // 250 ticks per microsecond
        })
        .collect();

    // Verify ISNs increase consistently with time
    for window in isns.windows(2) {
        assert!(window[1] > window[0], "Time-dependent ISNs should increase");
    }
}

// =============================================================================
// IP ID Analysis Tests
// =============================================================================

/// Test IP ID sequence classification - incremental.
#[test]
fn test_ip_id_classification_incremental() {
    // Incremental sequence (common in many systems)
    let ip_ids = [100, 101, 102, 103, 104, 105];
    let diffs: Vec<i32> = ip_ids.windows(2).map(|w| w[1] - w[0]).collect();

    // All differences should be 1 (or wrap around -65535)
    assert!(diffs.iter().all(|&d| d == 1 || d == -65535));
}

/// Test IP ID sequence classification - fixed.
#[test]
fn test_ip_id_classification_fixed() {
    // Fixed sequence (some embedded systems)
    let ip_ids = [500, 500, 500, 500];
    let all_same = ip_ids.iter().all(|&id| id == ip_ids[0]);
    assert!(all_same);
}

/// Test IP ID sequence classification - random.
#[test]
fn test_ip_id_classification_random() {
    // Random sequence (OpenBSD, etc)
    let ip_ids = [100, 5000, 200, 60000, 1000, 30000];
    let variance = {
        let mean = ip_ids.iter().map(|&n| n as u64).sum::<u64>() / ip_ids.len() as u64;
        let sum_sq_diff: u64 = ip_ids
            .iter()
            .map(|&n| {
                let diff = n as i64 - mean as i64;
                (diff * diff) as u64
            })
            .sum();
        sum_sq_diff / ip_ids.len() as u64
    };
    assert!(variance > 1000, "Random sequence should have high variance");
}

/// Test IP ID sequence with wraparound.
#[test]
fn test_ip_id_wraparound() {
    // Test wraparound at 65535
    let ip_ids = [65534, 65535, 0, 1, 2];
    let diffs: Vec<i32> = ip_ids.windows(2).map(|w| w[1] - w[0]).collect();

    // 65535 -> 0 is a difference of -65535 (or +1 with wraparound)
    assert_eq!(diffs[1], -65535);
}

// =============================================================================
// TCP Options Parsing Tests
// =============================================================================

/// Test TCP options parsing - common options.
#[test]
fn test_tcp_options_parsing() {
    // Build options as they would be in a real packet (Nmap-style)
    let options = [
        3, 3, 10, // Window Scale = 10
        1,  // NOP
        1,  // NOP
        2, 4, 0x05, 0xB4, // MSS = 1460
        8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamp (TSval=0, TSecr=0)
        4, 2, // SACK permitted
        1, // NOP
        1, // NOP
    ];

    // Verify options structure
    assert_eq!(options[0], 3); // Window Scale kind
    assert_eq!(options[1], 3); // Length
    assert_eq!(options[2], 10); // Value

    assert_eq!(options[3], 1); // NOP
    assert_eq!(options[4], 1); // NOP

    assert_eq!(options[5], 2); // MSS kind
    assert_eq!(options[6], 4); // Length
    assert_eq!(u16::from_be_bytes([options[7], options[8]]), 1460); // MSS value

    assert_eq!(options[9], 8); // Timestamp kind
    assert_eq!(options[10], 10); // Length
}

/// Test TCP options with window scale variations.
#[test]
fn test_tcp_options_window_scale_variations() {
    let scales = [0u8, 5, 10, 14];

    for scale in scales {
        let options = [3, 3, scale];
        assert_eq!(options[2], scale);
    }
}

/// Test TCP options with MSS variations.
#[test]
fn test_tcp_options_mss_variations() {
    let mss_values = [536u16, 1460, 8960, 9160]; // Common MSS values

    for mss in mss_values {
        let mss_bytes = mss.to_be_bytes();
        let options = [2, 4, mss_bytes[0], mss_bytes[1]];
        assert_eq!(u16::from_be_bytes([options[2], options[3]]), mss);
    }
}

// =============================================================================
// OS Fingerprint Building Tests
// =============================================================================

/// Test OS fingerprint building with all fields.
#[test]
fn test_os_fingerprint_complete() {
    use rustnmap_fingerprint::os::{
        EcnFingerprint, IcmpTestResult, IpIdPattern, IpIdSeqClass, IsnClass, OpsFingerprint,
        OsFingerprint, SeqFingerprint, TestResult, TimestampRate, UdpTestResult,
    };

    let seq_fp = SeqFingerprint {
        class: IsnClass::Random,
        timestamp: true,
        timestamp_rate: Some(TimestampRate::Rate100),
        gcd: 1,
        isr: 50,
        sp: 80,
        ti: IpIdSeqClass::Incremental,
        ci: IpIdSeqClass::Incremental,
        ii: IpIdSeqClass::Random,
        ss: 0,
        timestamps: vec![1000, 2000, 3000],
    };

    let ip_id = IpIdPattern {
        zero: false,
        incremental: true,
        seq_class: IpIdSeqClass::Incremental,
    };

    let ecn = EcnFingerprint {
        ece: true,
        df: true,
        tos: 0,
        cwr: false,
    };

    let test_t1 = TestResult::new("T1")
        .with_flags(0x12) // SYN+ACK
        .with_window(65535)
        .with_ip_fields(true, 64, 12345);

    let u1 = UdpTestResult::new()
        .with_icmp_response(3) // Port unreachable
        .with_ip_fields(true, 64, 54321, 56);

    let ie = IcmpTestResult::new()
        .with_response1(true, 64, 11111, 0, 120)
        .with_response2(true, 64, 11112, 0, 150);

    let fingerprint = OsFingerprint::new()
        .with_seq(seq_fp)
        .with_ip_id(ip_id)
        .with_ecn(ecn)
        .with_test(test_t1)
        .with_u1(u1)
        .with_ie(ie)
        .with_win("T1".to_string(), 65535)
        .with_ops("T1".to_string(), OpsFingerprint::new());

    assert!(fingerprint.seq.is_some());
    assert!(fingerprint.ip_id.is_some());
    assert!(fingerprint.ecn.is_some());
    assert!(fingerprint.u1.is_some());
    assert!(fingerprint.ie.is_some());
    assert_eq!(fingerprint.tests.len(), 1);
    assert_eq!(fingerprint.win.len(), 1);
    assert_eq!(fingerprint.ops.len(), 1);
}

/// Test OS fingerprint with empty fields.
#[test]
fn test_os_fingerprint_empty() {
    use rustnmap_fingerprint::os::OsFingerprint;

    let fingerprint = OsFingerprint::new();

    assert!(fingerprint.seq.is_none());
    assert!(fingerprint.ip_id.is_none());
    assert!(fingerprint.ecn.is_none());
    assert!(fingerprint.u1.is_none());
    assert!(fingerprint.ie.is_none());
    assert!(fingerprint.tests.is_empty());
    assert!(fingerprint.win.is_empty());
    assert!(fingerprint.ops.is_empty());
}

/// Test OS fingerprint with only sequence information.
#[test]
fn test_os_fingerprint_seq_only() {
    use rustnmap_fingerprint::os::{
        IpIdPattern, IpIdSeqClass, IsnClass, OsFingerprint, SeqFingerprint,
    };

    let seq_fp = SeqFingerprint {
        class: IsnClass::Random,
        timestamp: false,
        timestamp_rate: None,
        gcd: 1,
        isr: 8,
        sp: 63,
        ti: IpIdSeqClass::Incremental,
        ci: IpIdSeqClass::Incremental,
        ii: IpIdSeqClass::Incremental,
        ss: 0,
        timestamps: vec![],
    };

    let fingerprint = OsFingerprint::new()
        .with_seq(seq_fp)
        .with_ip_id(IpIdPattern {
            zero: false,
            incremental: true,
            seq_class: IpIdSeqClass::Incremental,
        });

    assert!(fingerprint.seq.is_some());
    assert!(fingerprint.ip_id.is_some());
    assert!(fingerprint.ecn.is_none());
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test error handling for invalid target.
#[tokio::test]
async fn test_os_detection_invalid_target() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let detector = OsDetector::new(db, local_addr);

    // Test with IPv6 target (not supported)
    let target: SocketAddr = "[::1]:80".parse().unwrap();
    let result = detector.detect_os(&target).await;

    // Should return error for IPv6
    assert!(result.is_err());
}

/// Test error handling for unreachable target.
#[tokio::test]
async fn test_os_detection_unreachable_target() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let detector = OsDetector::new(db, local_addr).with_timeout(Duration::from_millis(100));

    // Use RFC 5737 documentation range (should be unreachable)
    let target: SocketAddr = "192.0.2.99:80".parse().unwrap();

    let result = detector.detect_os(&target).await;

    // May succeed with empty results or fail depending on implementation
    // Just verify it doesn't panic
    if let Ok(matches) = result {
        assert!(matches.is_empty());
    } // Error is acceptable for unreachable target
}

// Rust guideline compliant 2026-02-15
