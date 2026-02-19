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

    /// U1 (UDP) test result.
    pub u1: Option<UdpTestResult>,

    /// IE (ICMP Echo) test results.
    pub ie: Option<IcmpTestResult>,
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

    /// GCD (Greatest Common Divisor) of ISN differences.
    pub gcd: u32,

    /// ISR (ISN Rate) - rate of ISN generation.
    pub isr: u8,

    /// SP (Sequence Predictability) - difficulty of predicting sequence numbers.
    pub sp: u8,

    /// TI (IP ID sequence) - IP ID generation class.
    pub ti: IpIdSeqClass,

    /// CI (IP ID sequence for continuous probes).
    pub ci: IpIdSeqClass,

    /// II (IP ID sequence for ICMP probes).
    pub ii: IpIdSeqClass,

    /// SS (Shared IP ID sequence flag).
    pub ss: u8,

    /// Timestamp counter values from SEQ probes.
    pub timestamps: Vec<u32>,
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
#[allow(clippy::struct_excessive_bools, reason = "TestResult is a data structure with independent boolean flags for OS fingerprinting")]
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

    /// Response received (R flag in Nmap fingerprint).
    pub responded: bool,

    /// Don't Fragment bit set.
    pub df: bool,

    /// Time To Live.
    pub ttl: Option<u8>,

    /// IP ID value.
    pub ip_id: Option<u16>,
}

/// U1 (UDP) test result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UdpTestResult {
    /// Response received (R flag).
    pub responded: bool,

    /// Don't Fragment bit set in response.
    pub df: bool,

    /// Time To Live.
    pub ttl: Option<u8>,

    /// IP ID value.
    pub ip_id: Option<u16>,

    /// Total length of response IP packet.
    pub ip_len: Option<u16>,

    /// Length of unused data in ICMP response.
    pub unused: Option<u8>,

    /// ICMP unreachable code received.
    pub icmp_code: Option<u8>,
}

/// IE (ICMP Echo) test result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools, reason = "IcmpTestResult is a data structure with independent boolean flags for OS fingerprinting")]
pub struct IcmpTestResult {
    /// Response to first ICMP echo (R flag).
    pub responded1: bool,

    /// Response to second ICMP echo (R flag).
    pub responded2: bool,

    /// Don't Fragment bit in first response.
    pub df1: bool,

    /// Don't Fragment bit in second response.
    pub df2: bool,

    /// Time To Live in first response.
    pub ttl1: Option<u8>,

    /// Time To Live in second response.
    pub ttl2: Option<u8>,

    /// IP ID sequence class.
    pub ipll: Option<u16>,

    /// IP ID value in first response.
    pub ip_id1: Option<u16>,

    /// IP ID value in second response.
    pub ip_id2: Option<u16>,

    /// Type of Service in first response.
    pub tos1: Option<u8>,

    /// Type of Service in second response.
    pub tos2: Option<u8>,

    /// Data bytes returned in first response.
    pub data1: Option<u16>,

    /// Data bytes returned in second response.
    pub data2: Option<u16>,
}

impl OsFingerprint {
    /// Create empty fingerprint.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seq: None,
            ip_id: None,
            ops: HashMap::new(),
            win: HashMap::new(),
            ecn: None,
            tests: HashMap::new(),
            u1: None,
            ie: None,
        }
    }

    /// Set SEQ fingerprint.
    #[must_use]
    pub fn with_seq(mut self, seq: SeqFingerprint) -> Self {
        self.seq = Some(seq);
        self
    }

    /// Set IP ID pattern.
    #[must_use]
    pub fn with_ip_id(mut self, ip_id: IpIdPattern) -> Self {
        self.ip_id = Some(ip_id);
        self
    }

    /// Add TCP options for a test.
    #[must_use]
    pub fn with_ops(mut self, test: String, ops: OpsFingerprint) -> Self {
        self.ops.insert(test, ops);
        self
    }

    /// Set window size for a test.
    #[must_use]
    pub fn with_win(mut self, test: String, window: u16) -> Self {
        self.win.insert(test, window);
        self
    }

    /// Set ECN fingerprint.
    #[must_use]
    pub fn with_ecn(mut self, ecn: EcnFingerprint) -> Self {
        self.ecn = Some(ecn);
        self
    }

    /// Add test result.
    #[must_use]
    pub fn with_test(mut self, result: TestResult) -> Self {
        self.tests.insert(result.name.clone(), result);
        self
    }

    /// Set U1 (UDP) test result.
    #[must_use]
    pub fn with_u1(mut self, u1: UdpTestResult) -> Self {
        self.u1 = Some(u1);
        self
    }

    /// Set IE (ICMP Echo) test result.
    #[must_use]
    pub fn with_ie(mut self, ie: IcmpTestResult) -> Self {
        self.ie = Some(ie);
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
    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            ece: false,
            df: false,
            tos: 0,
            cwr: false,
        }
    }
}

impl SeqFingerprint {
    /// Create a new SEQ fingerprint with unknown class.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: IsnClass::Unknown,
            timestamp: false,
            timestamp_rate: None,
            gcd: 0,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Unknown,
            ci: IpIdSeqClass::Unknown,
            ii: IpIdSeqClass::Unknown,
            ss: 0,
            timestamps: Vec::new(),
        }
    }
}

impl Default for SeqFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

impl TestResult {
    /// Create a new test result with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            flags: 0,
            window: None,
            mss: None,
            wscale: None,
            sack: false,
            timestamp: false,
            responded: false,
            df: false,
            ttl: None,
            ip_id: None,
        }
    }

    /// Set the response flags.
    #[must_use]
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self.responded = true;
        self
    }

    /// Set the window size.
    #[must_use]
    pub fn with_window(mut self, window: u16) -> Self {
        self.window = Some(window);
        self
    }

    /// Set TCP options.
    #[must_use]
    pub fn with_options(mut self, options: &OpsFingerprint) -> Self {
        self.mss = options.mss;
        self.wscale = options.wscale;
        self.sack = options.sack;
        self.timestamp = options.timestamp;
        self
    }

    /// Set IP header fields.
    #[must_use]
    pub fn with_ip_fields(mut self, df: bool, ttl: u8, ip_id: u16) -> Self {
        self.df = df;
        self.ttl = Some(ttl);
        self.ip_id = Some(ip_id);
        self
    }
}

impl Default for TestResult {
    fn default() -> Self {
        Self::new("T1")
    }
}

impl UdpTestResult {
    /// Create a new empty U1 test result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responded: false,
            df: false,
            ttl: None,
            ip_id: None,
            ip_len: None,
            unused: None,
            icmp_code: None,
        }
    }

    /// Mark as responded with ICMP unreachable.
    #[must_use]
    pub fn with_icmp_response(mut self, code: u8) -> Self {
        self.responded = true;
        self.icmp_code = Some(code);
        self
    }

    /// Set IP header fields.
    #[must_use]
    pub fn with_ip_fields(mut self, df: bool, ttl: u8, ip_id: u16, ip_len: u16) -> Self {
        self.df = df;
        self.ttl = Some(ttl);
        self.ip_id = Some(ip_id);
        self.ip_len = Some(ip_len);
        self
    }
}

impl Default for UdpTestResult {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpTestResult {
    /// Create a new empty IE test result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            responded1: false,
            responded2: false,
            df1: false,
            df2: false,
            ttl1: None,
            ttl2: None,
            ipll: None,
            ip_id1: None,
            ip_id2: None,
            tos1: None,
            tos2: None,
            data1: None,
            data2: None,
        }
    }

    /// Set first response fields.
    #[must_use]
    pub fn with_response1(mut self, df: bool, ttl: u8, ip_id: u16, tos: u8, data: u16) -> Self {
        self.responded1 = true;
        self.df1 = df;
        self.ttl1 = Some(ttl);
        self.ip_id1 = Some(ip_id);
        self.tos1 = Some(tos);
        self.data1 = Some(data);
        self
    }

    /// Set second response fields.
    #[must_use]
    pub fn with_response2(mut self, df: bool, ttl: u8, ip_id: u16, tos: u8, data: u16) -> Self {
        self.responded2 = true;
        self.df2 = df;
        self.ttl2 = Some(ttl);
        self.ip_id2 = Some(ip_id);
        self.tos2 = Some(tos);
        self.data2 = Some(data);
        self
    }
}

impl Default for IcmpTestResult {
    fn default() -> Self {
        Self::new()
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
        let fp = OsFingerprint::new().with_seq(SeqFingerprint {
            class: IsnClass::Random,
            timestamp: false,
            timestamp_rate: None,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Random,
            ci: IpIdSeqClass::Random,
            ii: IpIdSeqClass::Random,
            ss: 0,
            timestamps: Vec::new(),
        });

        assert!(fp.seq.is_some());
        assert_eq!(fp.seq.as_ref().unwrap().class, IsnClass::Random);
    }

    #[test]
    fn test_fingerprint_with_win() {
        let fp = OsFingerprint::new().with_win("T1".to_string(), 1234);

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
