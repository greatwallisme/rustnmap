//! OS fingerprint data structures.
//!
//! Types representing TCP/IP stack fingerprints for OS detection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Complete OS fingerprint for a target host.
///
/// Contains all characteristics extracted from TCP/IP behavior
/// that can be matched against known OS fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsFingerprint {
    /// TCP Initial Sequence Number analysis.
    pub seq: Option<SeqFingerprint>,

    /// IP ID generation patterns.
    pub ip_id: Option<IpIdPattern>,

    /// TCP options per test (T1-T7).
    pub ops: HashMap<String, OpsFingerprint>,

    /// TCP window sizes per test.
    pub win: HashMap<String, u16>,

    /// ECN (Explicit Congestion Notification) response.
    pub ecn: Option<EcnFingerprint>,

    /// Individual test results (T1-T7, U1, IE).
    pub tests: HashMap<String, TestResult>,
}

/// TCP ISN (Initial Sequence Number) fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeqFingerprint {
    /// ISN generation class.
    pub class: IsnClass,

    /// TCP Timestamp option presence.
    pub timestamp: bool,

    /// Timestamp increment rate (if timestamps enabled).
    pub timestamp_rate: Option<TimestampRate>,
}

/// ISN generation algorithm classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IsnClass {
    /// Random ISN generation (cryptographically secure).
    Random,

    /// ISN increments by constant value.
    Incremental {
        /// Increment between consecutive ISNs.
        increment: u32,
    },

    /// ISN uses GCD-based generation.
    Gcd {
        /// Greatest common divisor of ISN differences.
        gcd: u32,
    },

    /// ISN uses time-based generation.
    Time,

    /// Unknown ISN pattern.
    Unknown,
}

/// TCP timestamp rate class.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TimestampRate {
    /// No timestamp option present.
    None,

    /// Timestamp increments by 2 per second.
    Rate2,

    /// Timestamp increments by 100 per second.
    Rate100,

    /// Unknown timestamp rate.
    Unknown,
}

/// IP ID generation pattern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpIdPattern {
    /// Zero IP ID (all zeros).
    pub zero: bool,

    /// Incremental IP IDs.
    pub incremental: bool,

    /// IP ID sequence class.
    pub seq_class: IpIdSeqClass,
}

/// IP ID sequence generation classification.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum IpIdSeqClass {
    /// Random IP IDs.
    Random,

    /// Incremental by 1.
    Incremental,

    /// Incremental by 257.
    Incremental257,

    /// Fixed IP ID.
    Fixed,

    /// Unknown pattern.
    Unknown,
}

/// TCP options fingerprint for a single test.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpsFingerprint {
    /// Maximum Segment Size option value.
    pub mss: Option<u16>,

    /// Window scale option value.
    pub wscale: Option<u8>,

    /// Selective ACK supported.
    pub sack: bool,

    /// Timestamp option present.
    pub timestamp: bool,

    /// Number of NOP options.
    pub nop_count: u8,

    /// End of Options List present.
    pub eol: bool,
}

/// ECN (Explicit Congestion Notification) fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EcnFingerprint {
    /// ECE (ECN-Echo) flag received.
    pub ece: bool,

    /// Don't Fragment bit set.
    pub df: bool,

    /// Type of Service value.
    pub tos: u8,

    /// CWR flag received.
    pub cwr: bool,
}

/// Result of a single OS detection test.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestResult {
    /// Test name (T1, T2, etc.).
    pub name: String,

    /// Response flags received.
    pub flags: u8,

    /// Window size from response.
    pub window: Option<u16>,

    /// MSS option value if present.
    pub mss: Option<u16>,

    /// Window scale option if present.
    pub wscale: Option<u8>,

    /// Selective ACK present.
    pub sack: bool,

    /// Timestamp option present.
    pub timestamp: bool,
}

impl OsFingerprint {
    /// Create empty fingerprint.
    pub fn new() -> Self {
        Self {
            seq: None,
            ip_id: None,
            ops: HashMap::new(),
            win: HashMap::new(),
            ecn: None,
            tests: HashMap::new(),
        }
    }

    /// Set SEQ fingerprint.
    pub fn with_seq(mut self, seq: SeqFingerprint) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set IP ID pattern.
    pub fn with_ip_id(mut self, ip_id: IpIdPattern) -> Self {
        self.ip_id = Some(ip_id);
        self
    }

    /// Add TCP options for a test.
    pub fn with_ops(mut self, test: String, ops: OpsFingerprint) -> Self {
        self.ops.insert(test, ops);
        self
    }

    /// Set window size for a test.
    pub fn with_win(mut self, test: String, window: u16) -> Self {
        self.win.insert(test, window);
        self
    }

    /// Set ECN fingerprint.
    pub fn with_ecn(mut self, ecn: EcnFingerprint) -> Self {
        self.ecn = Some(ecn);
        self
    }

    /// Add test result.
    pub fn with_test(mut self, result: TestResult) -> Self {
        self.tests.insert(result.name.clone(), result);
        self
    }
}

impl Default for OsFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for OpsFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

impl OpsFingerprint {
    /// Create empty TCP options fingerprint.
    pub fn new() -> Self {
        Self {
            mss: None,
            wscale: None,
            sack: false,
            timestamp: false,
            nop_count: 0,
            eol: false,
        }
    }
}

impl Default for EcnFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

impl EcnFingerprint {
    /// Create empty ECN fingerprint.
    pub fn new() -> Self {
        Self {
            ece: false,
            df: false,
            tos: 0,
            cwr: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_new() {
        let fp = OsFingerprint::new();
        assert!(fp.seq.is_none());
        assert!(fp.ip_id.is_none());
        assert!(fp.ops.is_empty());
    }

    #[test]
    fn test_fingerprint_with_seq() {
        let fp = OsFingerprint::new()
            .with_seq(SeqFingerprint {
                class: IsnClass::Random,
                timestamp: false,
                timestamp_rate: None,
            });

        assert!(fp.seq.is_some());
        assert_eq!(fp.seq.as_ref().unwrap().class, IsnClass::Random);
    }

    #[test]
    fn test_fingerprint_with_win() {
        let fp = OsFingerprint::new()
            .with_win("T1".to_string(), 1234);

        assert_eq!(fp.win.get("T1"), Some(&1234));
    }

    #[test]
    fn test_ops_fingerprint_new() {
        let ops = OpsFingerprint::new();
        assert!(ops.mss.is_none());
        assert_eq!(ops.nop_count, 0);
        assert!(!ops.sack);
    }

    #[test]
    fn test_ecn_fingerprint_new() {
        let ecn = EcnFingerprint::new();
        assert!(!ecn.ece);
        assert!(!ecn.df);
        assert_eq!(ecn.tos, 0);
    }
}
