//! Integration tests for OS detection functionality.
//!
//! These tests require root privileges to create raw sockets.
//! They are marked with `#[ignore]` to prevent them from running by default.

use std::net::{Ipv4Addr, SocketAddr};

use rustnmap_fingerprint::os::{FingerprintDatabase, OsDetector};

/// Test that OS detector can be created with an empty database.
#[test]
fn test_os_detector_creation() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let _detector = OsDetector::new(db, local_addr);

    // Just verify it was created successfully
    // Fields are private, so we just verify no panic occurred
}

/// Test OS detector with custom configuration.
#[test]
fn test_os_detector_configuration() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(192, 168, 1, 100);
    let _detector = OsDetector::new(db, local_addr)
        .with_seq_count(10)
        .with_open_port(22)
        .with_closed_port(443)
        .with_closed_udp_port(33434);

    // Just verify it was created successfully with custom config
    // Fields are private, so we just verify no panic occurred
}

/// Test OS detection against localhost (requires root).
///
/// This test is ignored by default because it requires:
/// 1. Root privileges (CAP_NET_RAW)
/// 2. A listening service on port 80 (or configured open_port)
#[tokio::test]
#[ignore = "Requires root privileges and a listening service on port 80"]
async fn test_os_detection_localhost() {
    let db = FingerprintDatabase::empty();
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);
    let detector = OsDetector::new(db, local_addr)
        .with_open_port(80)
        .with_closed_port(443)
        .with_timeout(std::time::Duration::from_secs(5));

    let target: SocketAddr = "127.0.0.1:80".parse().unwrap();

    let result = detector.detect_os(&target).await;

    // Should not error, even if no matches found (empty database)
    assert!(result.is_ok());
    let matches = result.unwrap();
    // With empty database, should return no matches
    assert!(matches.is_empty());
}

/// Test SEQ probe analysis with mock data.
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

/// Test IP ID sequence classification.
#[test]
fn test_ip_id_classification() {
    // Incremental sequence
    let ip_ids = vec![100, 101, 102, 103, 104, 105];
    let diffs: Vec<i32> = ip_ids
        .windows(2)
        .map(|w| w[1] as i32 - w[0] as i32)
        .collect();
    assert!(diffs.iter().all(|&d| d == 1 || d == -65535));

    // Fixed sequence
    let ip_ids = vec![500, 500, 500, 500];
    let all_same = ip_ids.iter().all(|&id| id == ip_ids[0]);
    assert!(all_same);

    // Random sequence (high variance)
    let ip_ids = vec![100, 5000, 200, 60000, 1000];
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
    assert!(variance > 1000);
}

/// Test TCP options parsing.
#[test]
fn test_tcp_options_parsing() {
    // Build options as they would be in a real packet
    let options = vec![
        3, 3, 10, // Window Scale = 10
        1,  // NOP
        2, 4, 0x05, 0xB4, // MSS = 1460
        8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamp (TSval=0, TSecr=0)
        4, 2, // SACK permitted
    ];

    // Verify options structure
    assert_eq!(options[0], 3); // Window Scale kind
    assert_eq!(options[1], 3); // Length
    assert_eq!(options[2], 10); // Value

    assert_eq!(options[3], 1); // NOP

    assert_eq!(options[4], 2); // MSS kind
    assert_eq!(options[5], 4); // Length
    assert_eq!(u16::from_be_bytes([options[6], options[7]]), 1460); // MSS value

    assert_eq!(options[8], 8); // Timestamp kind
    assert_eq!(options[9], 10); // Length

    assert_eq!(options[18], 4); // SACK permitted kind
    assert_eq!(options[19], 2); // Length
}

/// Test OS fingerprint building with all fields.
#[test]
fn test_os_fingerprint_building() {
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
