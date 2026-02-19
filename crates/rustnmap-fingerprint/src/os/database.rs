//! OS fingerprint database loader.
//!
//! Parses nmap-os-db files containing reference fingerprints
//! for OS matching.

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use tracing::info;

use super::fingerprint::{
    EcnFingerprint, IpIdSeqClass, IsnClass, OpsFingerprint, OsFingerprint, SeqFingerprint,
    TimestampRate,
};
use crate::{FingerprintError, Result};

/// Database of OS fingerprints for matching.
///
/// Contains parsed fingerprints from nmap-os-db with
/// metadata for OS family and vendor.
#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    /// All known OS fingerprints indexed by name.
    fingerprints: HashMap<String, OsReference>,
}

/// Reference OS fingerprint from database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsReference {
    /// OS name (e.g., "Linux 5.4", "Windows 10").
    pub name: String,

    /// OS family classification.
    pub family: OsFamily,

    /// Vendor/organization.
    pub vendor: Option<String>,

    /// OS generation (e.g., "10", "5.4").
    pub generation: Option<String>,

    /// Device type.
    pub device_type: Option<String>,

    /// CPE identifier.
    pub cpe: Option<String>,

    /// Reference fingerprint.
    pub fingerprint: OsFingerprint,
}

/// Operating system family classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OsFamily {
    /// Linux operating systems.
    Linux,
    /// Windows operating systems.
    Windows,
    /// macOS operating systems.
    MacOS,
    /// BSD-based operating systems.
    BSD,
    /// Solaris operating systems.
    Solaris,
    /// iOS operating systems.
    IOS,
    /// Android operating systems.
    Android,
    /// Other operating systems.
    Other(String),
}

impl FingerprintDatabase {
    /// Create empty database.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    /// Load database from nmap-os-db file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid OS fingerprint data.
    pub async fn load_from_nmap_db(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        let content = fs::read_to_string(path).map_err(|e| FingerprintError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        Self::parse(&content)
    }

    /// Parse database content from nmap-os-db format.
    ///
    /// The nmap-os-db file format consists of:
    /// - Comment lines starting with #
    /// - Fingerprint lines starting with "Fingerprint "
    /// - Class lines starting with "Class " following a fingerprint
    /// - Test result lines (SEQ, OPS, WIN, ECN, T1-T7, U1, IE, etc.)
    fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();
        let mut current_fp: Option<NmapOsFingerprint> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // New fingerprint entry
            if let Some(name) = line.strip_prefix("Fingerprint ") {
                // Save previous fingerprint if exists
                if let Some(fp) = current_fp.take() {
                    let reference = fp.into_os_reference()?;
                    db.fingerprints.insert(reference.name.clone(), reference);
                }

                // Start new fingerprint
                current_fp = Some(NmapOsFingerprint::new(name.to_string()));
            }
            // Class line - belongs to current fingerprint
            else if let Some(class_str) = line.strip_prefix("Class ") {
                if let Some(ref mut fp) = current_fp {
                    fp.parse_class_line(class_str)?;
                }
            }
            // Test result line - belongs to current fingerprint
            // Test lines start with test name followed by '(' (e.g., "SEQ(...)", "OPS(...)")
            else if line.contains('(')
                && !line.starts_with("Fingerprint ")
                && !line.starts_with("Class ")
                && !line.starts_with("CPE ")
            {
                if let Some(ref mut fp) = current_fp {
                    fp.parse_test_line(line)?;
                }
            }
            // CPE line
            else if let Some(cpe_str) = line.strip_prefix("CPE ") {
                if let Some(ref mut fp) = current_fp {
                    fp.cpe = Some(cpe_str.trim().to_string());
                }
            }
        }

        // Don't forget the last fingerprint
        if let Some(fp) = current_fp {
            let reference = fp.into_os_reference()?;
            db.fingerprints.insert(reference.name.clone(), reference);
        }

        info!(
            "Loaded {} OS fingerprints from database",
            db.fingerprints.len()
        );
        Ok(db)
    }

    /// Find best matching OS fingerprints.
    #[must_use]
    pub fn find_matches(&self, fp: &OsFingerprint) -> Vec<OsMatch> {
        let mut matches: Vec<OsMatch> = Vec::new();

        for reference in self.fingerprints.values() {
            let score = self.calculate_match_score(fp, &reference.fingerprint);

            // Score threshold: lower is better
            // FP_NOVELTY_THRESHOLD = 15.0 from Nmap
            if score < 15.0 {
                matches.push(OsMatch {
                    name: reference.name.clone(),
                    family: reference.family.clone(),
                    vendor: reference.vendor.clone(),
                    generation: reference.generation.clone(),
                    device_type: reference.device_type.clone(),
                    cpe: reference.cpe.clone(),
                    accuracy: self.score_to_accuracy(score),
                });
            }
        }

        // Sort by accuracy (highest first)
        matches.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));

        matches
    }

    /// Calculate difference score between two fingerprints.
    #[allow(clippy::unused_self, reason = "API consistency with potential future instance-based scoring")]
    fn calculate_match_score(&self, fp1: &OsFingerprint, fp2: &OsFingerprint) -> f64 {
        let mut diff = 0.0;

        // Compare SEQ
        diff += Self::compare_seq(fp1.seq.as_ref(), fp2.seq.as_ref());

        // Compare OPS
        for (test, ops1) in &fp1.ops {
            if let Some(ops2) = fp2.ops.get(test) {
                diff += Self::compare_ops(ops1, ops2);
            }
        }

        // Compare WIN
        for (test, win1) in &fp1.win {
            if let Some(win2) = fp2.win.get(test) {
                diff += if win1 == win2 { 0.0 } else { 5.0 };
            }
        }

        // Compare ECN
        diff += Self::compare_ecn(fp1.ecn.as_ref(), fp2.ecn.as_ref());

        diff
    }

    /// Compare SEQ fingerprints.
    fn compare_seq(
        seq1: Option<&crate::os::fingerprint::SeqFingerprint>,
        seq2: Option<&crate::os::fingerprint::SeqFingerprint>,
    ) -> f64 {
        match (seq1, seq2) {
            (Some(s1), Some(s2)) => {
                if s1.class == s2.class {
                    0.0
                } else {
                    10.0
                }
            }
            (None, None) => 0.0,
            _ => 5.0,
        }
    }

    /// Compare TCP options fingerprints.
    fn compare_ops(
        ops1: &crate::os::fingerprint::OpsFingerprint,
        ops2: &crate::os::fingerprint::OpsFingerprint,
    ) -> f64 {
        let mut diff = 0.0;

        diff += if ops1.mss == ops2.mss { 0.0 } else { 2.0 };
        diff += if ops1.wscale == ops2.wscale { 0.0 } else { 1.0 };
        diff += if ops1.sack == ops2.sack { 0.0 } else { 1.0 };
        diff += if ops1.timestamp == ops2.timestamp {
            0.0
        } else {
            1.0
        };
        diff += (f64::from(ops1.nop_count) - f64::from(ops2.nop_count)).abs() / 2.0;
        diff += if ops1.eol == ops2.eol { 0.0 } else { 1.0 };

        diff
    }

    /// Compare ECN fingerprints.
    fn compare_ecn(
        ecn1: Option<&crate::os::fingerprint::EcnFingerprint>,
        ecn2: Option<&crate::os::fingerprint::EcnFingerprint>,
    ) -> f64 {
        match (ecn1, ecn2) {
            (Some(e1), Some(e2)) => {
                let mut diff = 0.0;
                diff += if e1.ece == e2.ece { 0.0 } else { 2.0 };
                diff += if e1.df == e2.df { 0.0 } else { 1.0 };
                diff += if e1.cwr == e2.cwr { 0.0 } else { 2.0 };
                diff += (f64::from(e1.tos) - f64::from(e2.tos)).abs() / 10.0;
                diff
            }
            (None, None) => 0.0,
            _ => 3.0,
        }
    }

    /// Convert difference score to accuracy percentage.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::unused_self, reason = "score is clamped to 0-100 range, u8 is appropriate")]
    fn score_to_accuracy(&self, score: f64) -> u8 {
        // Lower score = higher accuracy
        // Score of 0 = 100% accuracy
        // Score of 15 = 0% accuracy (at threshold)
        (100.0 - score.max(0.0)).clamp(0.0, 100.0) as u8
    }
}

impl Default for FingerprintDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

/// OS match result with accuracy score.
#[derive(Debug, Clone, PartialEq)]
pub struct OsMatch {
    /// OS name.
    pub name: String,

    /// OS family.
    pub family: OsFamily,

    /// Vendor/organization.
    pub vendor: Option<String>,

    /// OS generation.
    pub generation: Option<String>,

    /// Device type.
    pub device_type: Option<String>,

    /// CPE identifier.
    pub cpe: Option<String>,

    /// Match accuracy (0-100).
    pub accuracy: u8,
}

/// Internal structure for parsing nmap-os-db fingerprint entries.
#[derive(Debug, Default)]
struct NmapOsFingerprint {
    /// OS name from fingerprint line.
    name: String,
    /// OS family (e.g., Linux, Windows).
    family: Option<String>,
    /// OS vendor/organization.
    vendor: Option<String>,
    /// OS version/generation.
    generation: Option<String>,
    /// Device type.
    device_type: Option<String>,
    /// CPE identifier.
    cpe: Option<String>,
    /// Raw test results.
    tests: HashMap<String, String>,
}

impl NmapOsFingerprint {
    /// Create new fingerprint parser.
    fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    /// Parse Class line format: "Class vendor | family | gen | type"
    #[allow(clippy::unnecessary_wraps, reason = "Internal API matches signature pattern")]
    fn parse_class_line(&mut self, line: &str) -> Result<()> {
        // Format: "Class Microsoft | Windows | 10 | general purpose"
        // or: "Class Linux | Linux | 5.X | general purpose"
        let parts: Vec<&str> = line.split('|').map(str::trim).collect();

        if parts.len() >= 2 {
            self.vendor = Some(parts[0].to_string());
            self.family = Some(parts[1].to_string());
        }
        if parts.len() >= 3 {
            self.generation = Some(parts[2].to_string());
        }
        if parts.len() >= 4 {
            self.device_type = Some(parts[3].to_string());
        }

        Ok(())
    }

    /// Parse test line format: "TEST(values)"
    #[allow(clippy::unnecessary_wraps, reason = "Internal API matches signature pattern")]
    fn parse_test_line(&mut self, line: &str) -> Result<()> {
        // Test lines look like: "SEQ(SP=101-105%GCD=1%ISR=107)"
        // or: "OPS(O1=M5B4ST11NW2%O2=M5B4ST11NW2)"
        if let Some((test_name, values)) = line.split_once('(') {
            let values = values.trim_end_matches(')');
            self.tests.insert(test_name.to_string(), values.to_string());
        }
        Ok(())
    }

    /// Convert parsed fingerprint to `OsReference`.
    #[allow(clippy::unnecessary_wraps, reason = "API consistency for potential future error cases")]
    fn into_os_reference(self) -> Result<OsReference> {
        let family = self.family.as_deref().unwrap_or("Unknown");
        let family_lower = family.to_lowercase();
        let os_family = match family_lower.as_str() {
            "linux" => OsFamily::Linux,
            "windows" => OsFamily::Windows,
            "macos" | "mac os x" | "osx" => OsFamily::MacOS,
            "freebsd" | "openbsd" | "netbsd" | "bsd" => OsFamily::BSD,
            "solaris" => OsFamily::Solaris,
            "ios" => OsFamily::IOS,
            "android" => OsFamily::Android,
            _ => OsFamily::Other(family.to_string()),
        };

        // Build fingerprint from test results
        let fingerprint = self.parse_fingerprint();

        Ok(OsReference {
            name: self.name,
            family: os_family,
            vendor: self.vendor,
            generation: self.generation,
            device_type: self.device_type,
            cpe: self.cpe,
            fingerprint,
        })
    }

    /// Parse test results into `OsFingerprint` structure.
    fn parse_fingerprint(&self) -> OsFingerprint {
        let mut fingerprint = OsFingerprint::new();

        for (test_name, values) in &self.tests {
            match test_name.as_str() {
                "SEQ" => {
                    if let Some(seq) = Self::parse_seq(values) {
                        fingerprint.seq = Some(seq);
                    }
                }
                "OPS" => {
                    let ops_map = Self::parse_ops(values);
                    for (test, ops) in ops_map {
                        fingerprint.ops.insert(test, ops);
                    }
                }
                "WIN" => {
                    let win_map = Self::parse_win(values);
                    for (test, window) in win_map {
                        fingerprint.win.insert(test, window);
                    }
                }
                "ECN" => {
                    if let Some(ecn) = Self::parse_ecn(values) {
                        fingerprint.ecn = Some(ecn);
                    }
                }
                "T1" | "T2" | "T3" | "T4" | "T5" | "T6" | "T7" => {
                    if let Some(test_result) = Self::parse_test(test_name, values) {
                        fingerprint.tests.insert(test_name.to_string(), test_result);
                    }
                }
                "U1" => {
                    if let Some(u1) = Self::parse_u1(values) {
                        fingerprint.u1 = Some(u1);
                    }
                }
                "IE" => {
                    if let Some(ie) = Self::parse_ie(values) {
                        fingerprint.ie = Some(ie);
                    }
                }
                _ => {}
            }
        }

        fingerprint
    }

    /// Parse SEQ test values into `SeqFingerprint`.
    ///
    /// Format: SEQ(SP=101-105%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S)
    fn parse_seq(values: &str) -> Option<SeqFingerprint> {
        let mut seq = SeqFingerprint::new();
        let params = Self::parse_params(values);

        for (key, value) in &params {
            match *key {
                "SP" => {
                    // Parse SP value (can be range like "101-105" or single value)
                    if let Some(dash_pos) = value.find('-') {
                        let start: u8 = value[..dash_pos].parse().ok()?;
                        seq.sp = start;
                    } else {
                        seq.sp = value.parse().ok()?;
                    }
                }
                "GCD" => {
                    seq.gcd = value.parse().ok()?;
                }
                "ISR" => {
                    seq.isr = value.parse().ok()?;
                }
                "TI" => {
                    seq.ti = Self::parse_ip_id_class(value);
                }
                "CI" => {
                    seq.ci = Self::parse_ip_id_class(value);
                }
                "II" => {
                    seq.ii = Self::parse_ip_id_class(value);
                }
                "SS" => {
                    seq.ss = u8::from(*value == "S");
                }
                "TS" => {
                    seq.timestamp = *value != "U" && *value != "0";
                    if *value == "2" {
                        seq.timestamp_rate = Some(TimestampRate::Rate2);
                    } else if *value == "100" || value.starts_with("100Hz") {
                        seq.timestamp_rate = Some(TimestampRate::Rate100);
                    }
                }
                _ => {}
            }
        }

        // Determine ISN class based on parsed values
        seq.class = Self::determine_isn_class(seq.gcd, seq.isr, seq.sp);

        Some(seq)
    }

    /// Parse IP ID class from string.
    #[allow(clippy::match_same_arms, reason = "Intentional: RI and I both map to Incremental per Nmap spec")]
    fn parse_ip_id_class(value: &str) -> IpIdSeqClass {
        match value {
            "Z" => IpIdSeqClass::Fixed,
            "RD" | "R" => IpIdSeqClass::Random,
            "RI" => IpIdSeqClass::Incremental,
            "BI" => IpIdSeqClass::Incremental257,
            "I" => IpIdSeqClass::Incremental,
            _ => IpIdSeqClass::Unknown,
        }
    }

    /// Determine ISN class from parsed values.
    fn determine_isn_class(gcd: u32, isr: u8, sp: u8) -> IsnClass {
        if gcd == 0 && isr == 0 && sp == 0 {
            return IsnClass::Unknown;
        }

        if sp == 0 && gcd > 1 {
            return IsnClass::Gcd { gcd };
        }

        if isr > 0 && gcd == 1 {
            return IsnClass::Incremental {
                increment: u32::from(isr),
            };
        }

        if sp >= 80 {
            return IsnClass::Random;
        }

        if isr == 0 && sp > 0 {
            return IsnClass::Time;
        }

        IsnClass::Unknown
    }

    /// Parse OPS test values into map of test names to `OpsFingerprint`.
    ///
    /// Format: OPS(O1=M5B4ST11NW2%O2=M5B4ST11NW2%O3=M5B4ST11NW2...)
    fn parse_ops(values: &str) -> HashMap<String, OpsFingerprint> {
        let mut ops_map = HashMap::new();
        let params = Self::parse_params(values);

        for (key, value) in &params {
            if let Some(test_num) = key.strip_prefix('O') {
                if let Ok(num) = test_num.parse::<u8>() {
                    if (1..=7).contains(&num) {
                        let test_name = format!("T{num}");
                        if let Some(ops) = Self::parse_ops_value(value) {
                            ops_map.insert(test_name, ops);
                        }
                    }
                }
            }
        }

        ops_map
    }

    /// Parse a single OPS value string.
    ///
    /// Format: M5B4ST11NW2 (MSS=1460, Window Scale, Timestamp, NOP, Window)
    #[allow(clippy::unnecessary_wraps, reason = "Intentional: returns None for empty/invalid input")]
    fn parse_ops_value(value: &str) -> Option<OpsFingerprint> {
        let mut ops = OpsFingerprint::new();

        // Parse the compact OPS format
        // M = MSS, W = Window scale, S = SACK, T = Timestamp, N = NOP, E = EOL
        let mut chars = value.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                'M' => {
                    // MSS value follows (hex)
                    let mut hex_val = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_hexdigit() {
                            hex_val.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if let Ok(mss_hex) = u16::from_str_radix(&hex_val, 16) {
                        ops.mss = Some(mss_hex);
                    }
                }
                'W' => {
                    // Window scale follows
                    let mut val = String::new();
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_digit() {
                            val.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    if let Ok(wscale) = val.parse() {
                        ops.wscale = Some(wscale);
                    }
                }
                'S' => {
                    // SACK permitted
                    if chars.peek() == Some(&'A') {
                        chars.next(); // consume 'A'
                    }
                    ops.sack = true;
                }
                'T' => {
                    // Timestamp
                    ops.timestamp = true;
                    // Skip timestamp values if present
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_digit() {
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                'N' => {
                    // NOP
                    ops.nop_count += 1;
                }
                'E' => {
                    // EOL
                    ops.eol = true;
                }
                _ => {}
            }
        }

        Some(ops)
    }

    /// Parse WIN test values into map of test names to window sizes.
    ///
    /// Format: WIN(W1=FFFF%W2=FFFF%W3=FFFF...)
    fn parse_win(values: &str) -> HashMap<String, u16> {
        let mut win_map = HashMap::new();
        let params = Self::parse_params(values);

        for (key, value) in params {
            if let Some(test_num) = key.strip_prefix('W') {
                if let Ok(num) = test_num.parse::<u8>() {
                    if (1..=7).contains(&num) {
                        let test_name = format!("T{num}");
                        if let Ok(window) = u16::from_str_radix(value, 16) {
                            win_map.insert(test_name, window);
                        }
                    }
                }
            }
        }

        win_map
    }

    /// Parse ECN test values into `EcnFingerprint`.
    ///
    /// Format: ECN(R=Y%DF=Y%T=FA%TG=FF%W=FFFF%O=M5B4NNSW2%CC=N%Q=)
    #[allow(clippy::unnecessary_wraps, reason = "Intentional: returns None for empty/invalid input")]
    fn parse_ecn(values: &str) -> Option<EcnFingerprint> {
        let mut ecn = EcnFingerprint::new();
        let params = Self::parse_params(values);

        for (key, value) in params {
            match key {
                "DF" => {
                    ecn.df = value == "Y";
                }
                "T" | "TG" => {
                    if let Ok(tos) = u8::from_str_radix(value, 16) {
                        ecn.tos = tos;
                    }
                }
                "CC" => {
                    // Congestion control response
                    ecn.ece = value == "Y" || value == "S";
                    ecn.cwr = value == "Y";
                }
                _ => {}
            }
        }

        Some(ecn)
    }

    /// Parse T1-T7 test values into `TestResult`.
    ///
    /// Format: T1(R=Y%DF=Y%T=FA%TG=FF%S=O%A=S+%F=AS%RD=0%Q=)
    #[allow(clippy::match_same_arms, clippy::unnecessary_wraps, reason = "Intentional: empty arms for fields handled elsewhere, None for empty input")]
    fn parse_test(name: &str, values: &str) -> Option<super::fingerprint::TestResult> {
        let mut test = super::fingerprint::TestResult::new(name);
        let params = Self::parse_params(values);

        for (key, value) in params {
            match key {
                "R" => {
                    test.responded = value == "Y";
                }
                "DF" => {
                    test.df = value == "Y";
                }
                "T" => {
                    if let Ok(ttl) = u8::from_str_radix(value, 16) {
                        test.ttl = Some(ttl);
                    }
                }
                "S" => {
                    // Response sequence number handling
                }
                "A" => {
                    // ACK number handling
                }
                "F" => {
                    // Parse flags
                    test.flags = Self::parse_flags(value);
                }
                "W" => {
                    if let Ok(window) = u16::from_str_radix(value, 16) {
                        test.window = Some(window);
                    }
                }
                "O" => {
                    // TCP options in test response
                    if let Some(ops) = Self::parse_ops_value(value) {
                        test.mss = ops.mss;
                        test.wscale = ops.wscale;
                        test.sack = ops.sack;
                        test.timestamp = ops.timestamp;
                    }
                }
                _ => {}
            }
        }

        Some(test)
    }

    /// Parse TCP flags from string.
    fn parse_flags(value: &str) -> u8 {
        let mut flags = 0u8;
        for ch in value.chars() {
            match ch {
                'F' => flags |= 0x01, // FIN
                'S' => flags |= 0x02, // SYN
                'R' => flags |= 0x04, // RST
                'P' => flags |= 0x08, // PSH
                'A' => flags |= 0x10, // ACK
                'U' => flags |= 0x20, // URG
                'E' => flags |= 0x40, // ECE
                'C' => flags |= 0x80, // CWR
                _ => {}
            }
        }
        flags
    }

    /// Parse U1 (UDP) test values into `UdpTestResult`.
    ///
    /// Format: U1(DF=N%T=FA%TG=FF%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
    #[allow(clippy::unnecessary_wraps, reason = "Intentional: returns None for empty/invalid input")]
    fn parse_u1(values: &str) -> Option<super::fingerprint::UdpTestResult> {
        let mut u1 = super::fingerprint::UdpTestResult::new();
        let params = Self::parse_params(values);

        for (key, value) in &params {
            match *key {
                "DF" => {
                    u1.df = *value == "Y";
                }
                "T" => {
                    if let Ok(ttl) = u8::from_str_radix(value, 16) {
                        u1.ttl = Some(ttl);
                    }
                }
                "IPL" => {
                    if let Ok(len) = value.parse() {
                        u1.ip_len = Some(len);
                    }
                }
                "UN" => {
                    if let Ok(unused) = value.parse() {
                        u1.unused = Some(unused);
                    }
                }
                _ => {}
            }
        }

        // R= usually indicates if we got any response
        if let Some(r_val) = params.get("R") {
            u1.responded = r_val == &"Y";
        }

        Some(u1)
    }

    /// Parse IE (ICMP Echo) test values into `IcmpTestResult`.
    ///
    /// Format: IE(DFI=N%T=FA%TG=FF%CD=S)
    #[allow(clippy::unnecessary_wraps, reason = "Intentional: returns None for empty/invalid input")]
    fn parse_ie(values: &str) -> Option<super::fingerprint::IcmpTestResult> {
        let mut ie = super::fingerprint::IcmpTestResult::new();
        let params = Self::parse_params(values);

        // Parse DFI (Don't Fragment bit behavior)
        if let Some(dfi) = params.get("DFI") {
            ie.df1 = dfi == &"Y" || dfi == &"S";
            ie.df2 = dfi == &"Y" || dfi == &"S";
        }

        // Parse T/TG (TTL)
        if let Some(t) = params.get("T") {
            if let Ok(ttl) = u8::from_str_radix(t, 16) {
                ie.ttl1 = Some(ttl);
                ie.ttl2 = Some(ttl);
            }
        }

        // Parse CD (Code) - indicates if both probes responded
        if let Some(cd) = params.get("CD") {
            ie.responded1 = cd == &"S" || cd == &"Z" || cd == &"O";
            ie.responded2 = cd == &"S" || cd == &"Z" || cd == &"O";
        }

        Some(ie)
    }

    /// Parse key=value pairs from test string.
    ///
    /// Input: "SP=101-105%GCD=1%ISR=108"
    /// Returns: `HashMap` with ("SP", "101-105"), ("GCD", "1"), ("ISR", "108")
    fn parse_params(values: &str) -> HashMap<&str, &str> {
        let mut params = HashMap::new();

        for part in values.split('%') {
            if let Some((key, value)) = part.split_once('=') {
                params.insert(key, value);
            }
        }

        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::fingerprint::{IsnClass, SeqFingerprint};

    #[test]
    fn test_database_empty() {
        let db = FingerprintDatabase::empty();
        assert!(db.fingerprints.is_empty());
    }

    #[test]
    fn test_score_to_accuracy() {
        let db = FingerprintDatabase::empty();

        assert_eq!(db.score_to_accuracy(0.0), 100);
        assert_eq!(db.score_to_accuracy(5.0), 95);
        assert_eq!(db.score_to_accuracy(15.0), 85);
        assert_eq!(db.score_to_accuracy(100.0), 0);
    }

    #[test]
    fn test_compare_seq() {
        let _db = FingerprintDatabase::empty();
        let seq1 = SeqFingerprint {
            class: IsnClass::Random,
            timestamp: false,
            timestamp_rate: None,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: crate::os::fingerprint::IpIdSeqClass::Random,
            ci: crate::os::fingerprint::IpIdSeqClass::Random,
            ii: crate::os::fingerprint::IpIdSeqClass::Random,
            ss: 0,
            timestamps: Vec::new(),
        };
        let seq2 = SeqFingerprint {
            class: IsnClass::Incremental { increment: 1 },
            timestamp: false,
            timestamp_rate: None,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: crate::os::fingerprint::IpIdSeqClass::Incremental,
            ci: crate::os::fingerprint::IpIdSeqClass::Incremental,
            ii: crate::os::fingerprint::IpIdSeqClass::Incremental,
            ss: 0,
            timestamps: Vec::new(),
        };

        // Different classes = 10.0 diff
        assert!(FingerprintDatabase::compare_seq(Some(&seq1), Some(&seq2)) > 5.0);

        // Same class = 0.0 diff
        let diff = FingerprintDatabase::compare_seq(Some(&seq1), Some(&seq1));
        assert_eq!(diff, 0.0);
    }

    #[test]
    fn test_parse_simple_db() {
        let db_content = r"
# Nmap OS detection database
# This is a test database

Fingerprint Test OS 1
Class TestVendor | TestOS | 1.0 | general purpose
SEQ(SP=100-105%GCD=1%ISR=108)
OPS(O1=M5B4ST11NW2%O2=M5B4ST11NW2)
WIN(W1=FFFF)

Fingerprint Test OS 2
Class AnotherVendor | AnotherOS | 2.0 | specialized
SEQ(SP=200-205%GCD=1%ISR=208)
";

        let db = FingerprintDatabase::parse(db_content).unwrap();
        assert_eq!(db.fingerprints.len(), 2);

        let fp1 = db.fingerprints.get("Test OS 1").unwrap();
        assert_eq!(fp1.name, "Test OS 1");
        assert_eq!(fp1.vendor, Some("TestVendor".to_string()));
        assert_eq!(fp1.family, OsFamily::Other("TestOS".to_string()));
        assert_eq!(fp1.generation, Some("1.0".to_string()));
        assert_eq!(fp1.device_type, Some("general purpose".to_string()));

        let fp2 = db.fingerprints.get("Test OS 2").unwrap();
        assert_eq!(fp2.name, "Test OS 2");
        assert_eq!(fp2.vendor, Some("AnotherVendor".to_string()));
    }

    #[test]
    fn test_parse_class_line_variations() {
        let db_content = r"
Fingerprint Linux Test
Class Linux | Linux | 5.X | general purpose

Fingerprint Windows Test
Class Microsoft | Windows | 10 | general purpose

Fingerprint Unknown Test
Class Unknown | UnknownOS
";

        let db = FingerprintDatabase::parse(db_content).unwrap();
        assert_eq!(db.fingerprints.len(), 3);

        let linux = db.fingerprints.get("Linux Test").unwrap();
        assert!(matches!(linux.family, OsFamily::Linux));
        assert_eq!(linux.vendor, Some("Linux".to_string()));

        let windows = db.fingerprints.get("Windows Test").unwrap();
        assert!(matches!(windows.family, OsFamily::Windows));
        assert_eq!(windows.vendor, Some("Microsoft".to_string()));

        let unknown = db.fingerprints.get("Unknown Test").unwrap();
        assert!(matches!(unknown.family, OsFamily::Other(_)));
    }

    #[test]
    fn test_parse_with_cpe() {
        let db_content = r"
Fingerprint Test With CPE
Class Test | TestOS | 1.0 | general purpose
CPE cpe:/o:test:os:1.0
SEQ(SP=100)
";

        let db = FingerprintDatabase::parse(db_content).unwrap();
        let fp = db.fingerprints.get("Test With CPE").unwrap();
        assert_eq!(fp.cpe, Some("cpe:/o:test:os:1.0".to_string()));
    }

    #[test]
    fn test_empty_db() {
        let db = FingerprintDatabase::parse("").unwrap();
        assert!(db.fingerprints.is_empty());
    }

    #[test]
    fn test_db_with_only_comments() {
        let db_content = r"
# This is a comment
# Another comment
";
        let db = FingerprintDatabase::parse(db_content).unwrap();
        assert!(db.fingerprints.is_empty());
    }
}
