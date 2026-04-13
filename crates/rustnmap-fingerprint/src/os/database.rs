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

//! OS fingerprint database loader.
//!
//! Parses nmap-os-db files containing reference fingerprints
//! for OS matching using nmap's expression-based weighted scoring.

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use tracing::info;

use super::fingerprint::{EcnFingerprint, IpIdSeqClass, OpsFingerprint, OsFingerprint};
use super::matching::{
    self, AttrKey, CompactFingerprint, CompiledMatchPoints, MatchPointsDef, RawFingerprint, Section,
};
use crate::{FingerprintError, Result};

/// Database of OS fingerprints for matching.
///
/// Contains parsed fingerprints from nmap-os-db with
/// metadata for OS family and vendor. Uses nmap's weighted
/// MatchPoints scoring for accurate fingerprint comparison.
#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    /// All known OS fingerprints indexed by name.
    fingerprints: HashMap<String, OsReference>,

    /// Weighted scoring definition from MatchPoints section.
    match_points: MatchPointsDef,

    /// Pre-compiled match points with enum keys for fast matching.
    compiled_match_points: CompiledMatchPoints,
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

    /// Compact fingerprint with expression strings for matching.
    /// Uses enum keys and Box<str> values to reduce memory from
    /// ~20KB to ~3.5KB per fingerprint (6036 fingerprints total).
    #[serde(skip)]
    pub compact_fp: CompactFingerprint,
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
        let mp = default_match_points();
        let compiled = CompiledMatchPoints::from_match_points(&mp);
        Self {
            fingerprints: HashMap::new(),
            match_points: mp,
            compiled_match_points: compiled,
        }
    }

    /// Load database from nmap-os-db file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid OS fingerprint data.
    pub fn load_from_nmap_db(path: impl AsRef<Path>) -> Result<Self> {
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
    /// - MatchPoints section defining weighted scoring
    /// - Fingerprint lines starting with "Fingerprint "
    /// - Class lines starting with "Class " following a fingerprint
    /// - CPE lines starting with "CPE "
    /// - Test result lines (SEQ, OPS, WIN, ECN, T1-T7, U1, IE)
    fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();
        let mut current_fp: Option<NmapOsFingerprint> = None;
        let mut parsing_match_points = false;
        let mut match_points = MatchPointsDef::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                if parsing_match_points && line.is_empty() {
                    parsing_match_points = false;
                }
                continue;
            }

            // MatchPoints section
            if line == "MatchPoints" {
                parsing_match_points = true;
                continue;
            }

            if parsing_match_points {
                // Parse MatchPoints test line: TEST(ATTR=POINTS%ATTR=POINTS...)
                if line.starts_with("Fingerprint ") || line.starts_with("Class ") {
                    parsing_match_points = false;
                    // Fall through to process this line below
                } else if let Some((test_name, values)) = line.split_once('(') {
                    let values = values.trim_end_matches(')');
                    let mut attrs = HashMap::new();
                    for part in values.split('%') {
                        if let Some((key, val)) = part.split_once('=') {
                            if let Ok(points) = val.parse::<u32>() {
                                attrs.insert(key.to_string(), points);
                            }
                        }
                    }
                    if !attrs.is_empty() {
                        match_points.insert(test_name.to_string(), attrs);
                    }
                    continue;
                } else {
                    continue;
                }
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
            // CPE line
            else if let Some(cpe_str) = line.strip_prefix("CPE ") {
                if let Some(ref mut fp) = current_fp {
                    fp.cpe = Some(cpe_str.trim().to_string());
                }
            }
            // Test result line - belongs to current fingerprint
            else if line.contains('(')
                && !line.starts_with("Fingerprint ")
                && !line.starts_with("Class ")
                && !line.starts_with("CPE ")
            {
                if let Some(ref mut fp) = current_fp {
                    fp.parse_test_line(line)?;
                }
            }
        }

        // Save the last fingerprint
        if let Some(fp) = current_fp {
            let reference = fp.into_os_reference()?;
            db.fingerprints.insert(reference.name.clone(), reference);
        }

        // Use parsed MatchPoints or defaults
        if !match_points.is_empty() {
            db.match_points = match_points;
        }
        db.compiled_match_points = CompiledMatchPoints::from_match_points(&db.match_points);

        info!(
            "Loaded {} OS fingerprints with {} match point tests from database",
            db.fingerprints.len(),
            db.match_points.len()
        );
        Ok(db)
    }

    /// Find best matching OS fingerprints.
    ///
    /// Converts the observed fingerprint to raw string format,
    /// then uses nmap's weighted MatchPoints scoring to find matches.
    /// Uses pre-filtering to skip fingerprints that cannot possibly match.
    #[must_use]
    pub fn find_matches(&self, fp: &OsFingerprint) -> Vec<OsMatch> {
        let observed_raw = fingerprint_to_raw(fp);
        let mut matches: Vec<OsMatch> = Vec::new();

        // nmap uses 0.85 as default accuracy threshold
        // (OSSCAN_GUESS_THRESHOLD in nmap.h)
        let accuracy_threshold = 0.85;

        // Pre-extract R (responded) fields for cheap pre-filter.
        // R fields carry 50-100 points each. If observed says R=Y for a test
        // but reference says R=N, or vice versa, the reference cannot match.
        // Checking multiple test R fields eliminates 50-80% of fingerprints.
        let obs_r_values: Vec<(Section, &str)> = [
            Section::T1,
            Section::T2,
            Section::T3,
            Section::T4,
            Section::T5,
            Section::T6,
            Section::T7,
        ]
        .into_iter()
        .filter_map(|section| {
            observed_raw
                .get(section.name())
                .and_then(|t| t.get("R"))
                .map(|v| (section, v.as_str()))
        })
        .collect();

        for reference in self.fingerprints.values() {
            // Pre-filter: check all observed R fields against reference.
            let mut skip = false;
            for &(section, obs_r) in &obs_r_values {
                if let Some(ref_r) = reference.compact_fp.get(section, AttrKey::R) {
                    if obs_r != ref_r {
                        skip = true;
                        break;
                    }
                }
            }
            if skip {
                continue;
            }

            let accuracy = matching::compare_compact(
                &observed_raw,
                &reference.compact_fp,
                &self.compiled_match_points,
                accuracy_threshold,
            );

            if accuracy >= accuracy_threshold {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "accuracy is clamped to 0.0-1.0, percentage fits u8"
                )]
                let pct = (accuracy * 100.0).round() as u8;
                matches.push(OsMatch {
                    name: reference.name.clone(),
                    family: reference.family.clone(),
                    vendor: reference.vendor.clone(),
                    generation: reference.generation.clone(),
                    device_type: reference.device_type.clone(),
                    cpe: reference.cpe.clone(),
                    accuracy: pct,
                });
            }
        }

        // Sort by accuracy (highest first)
        matches.sort_by(|a, b| b.accuracy.cmp(&a.accuracy));

        matches
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

/// Default MatchPoints matching nmap's nmap-os-db.
///
/// Used as fallback when the database file does not contain a MatchPoints section.
fn default_match_points() -> MatchPointsDef {
    let mut mp = MatchPointsDef::new();

    let mut seq = HashMap::new();
    seq.insert("SP".to_string(), 25);
    seq.insert("GCD".to_string(), 75);
    seq.insert("ISR".to_string(), 25);
    seq.insert("TI".to_string(), 100);
    seq.insert("CI".to_string(), 50);
    seq.insert("II".to_string(), 100);
    seq.insert("SS".to_string(), 80);
    seq.insert("TS".to_string(), 100);
    mp.insert("SEQ".to_string(), seq);

    let mut ops = HashMap::new();
    for i in 1..=6 {
        ops.insert(format!("O{i}"), 20);
    }
    mp.insert("OPS".to_string(), ops);

    let mut win = HashMap::new();
    for i in 1..=6 {
        win.insert(format!("W{i}"), 15);
    }
    mp.insert("WIN".to_string(), win);

    let mut ecn = HashMap::new();
    ecn.insert("R".to_string(), 100);
    ecn.insert("DF".to_string(), 20);
    ecn.insert("T".to_string(), 15);
    ecn.insert("TG".to_string(), 15);
    ecn.insert("W".to_string(), 15);
    ecn.insert("O".to_string(), 15);
    ecn.insert("CC".to_string(), 100);
    ecn.insert("Q".to_string(), 20);
    mp.insert("ECN".to_string(), ecn);

    // T1 has different weights than T2-T7
    let mut t1 = HashMap::new();
    t1.insert("R".to_string(), 100);
    t1.insert("DF".to_string(), 20);
    t1.insert("T".to_string(), 15);
    t1.insert("TG".to_string(), 15);
    t1.insert("S".to_string(), 20);
    t1.insert("A".to_string(), 20);
    t1.insert("F".to_string(), 30);
    t1.insert("RD".to_string(), 20);
    t1.insert("Q".to_string(), 20);
    mp.insert("T1".to_string(), t1);

    // T2-T7 share same structure
    for name in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        let mut t = HashMap::new();
        let r_pts = if name == "T2" || name == "T3" || name == "T7" {
            80
        } else {
            100
        };
        t.insert("R".to_string(), r_pts);
        t.insert("DF".to_string(), 20);
        t.insert("T".to_string(), 15);
        t.insert("TG".to_string(), 15);
        t.insert("W".to_string(), 25);
        t.insert("S".to_string(), 20);
        t.insert("A".to_string(), 20);
        t.insert("F".to_string(), 30);
        t.insert("O".to_string(), 10);
        t.insert("RD".to_string(), 20);
        t.insert("Q".to_string(), 20);
        mp.insert(name.to_string(), t);
    }

    let mut u1 = HashMap::new();
    u1.insert("R".to_string(), 50);
    u1.insert("DF".to_string(), 20);
    u1.insert("T".to_string(), 15);
    u1.insert("TG".to_string(), 15);
    u1.insert("IPL".to_string(), 100);
    u1.insert("UN".to_string(), 100);
    u1.insert("RIPL".to_string(), 100);
    u1.insert("RID".to_string(), 100);
    u1.insert("RIPCK".to_string(), 100);
    u1.insert("RUCK".to_string(), 50);
    u1.insert("RUD".to_string(), 100);
    mp.insert("U1".to_string(), u1);

    let mut ie = HashMap::new();
    ie.insert("R".to_string(), 50);
    ie.insert("DFI".to_string(), 40);
    ie.insert("T".to_string(), 15);
    ie.insert("TG".to_string(), 15);
    ie.insert("CD".to_string(), 100);
    mp.insert("IE".to_string(), ie);

    mp
}

/// Convert an observed `OsFingerprint` to `RawFingerprint` for matching.
///
/// Formats each field as nmap would output it (hex values, flag strings, etc.)
/// so it can be compared against reference expressions using `expr_match`.
#[must_use]
pub fn fingerprint_to_raw(fp: &OsFingerprint) -> RawFingerprint {
    let mut raw = RawFingerprint::new();

    // SEQ test
    if let Some(ref seq) = fp.seq {
        let mut seq_raw = HashMap::new();
        seq_raw.insert("SP".to_string(), format!("{:X}", seq.sp));
        seq_raw.insert("GCD".to_string(), format!("{:X}", seq.gcd));
        seq_raw.insert("ISR".to_string(), format!("{:X}", seq.isr));
        seq_raw.insert("TI".to_string(), ip_id_class_to_str(&seq.ti));
        seq_raw.insert("CI".to_string(), ip_id_class_to_str(&seq.ci));
        seq_raw.insert("II".to_string(), ip_id_class_to_str(&seq.ii));
        seq_raw.insert(
            "SS".to_string(),
            if seq.ss != 0 { "S" } else { "O" }.to_string(),
        );
        let ts_val = if !seq.timestamp || seq.ts_val == 0 {
            "U".to_string()
        } else {
            format!("{:X}", seq.ts_val)
        };
        seq_raw.insert("TS".to_string(), ts_val);
        raw.insert("SEQ".to_string(), seq_raw);
    }

    // OPS test - TCP options from SEQ probe responses (O1-O6).
    // Nmap collects OPS from the 6 SYN-ACK responses to SEQ probes,
    // using raw_options_to_nmap_string for accurate formatting.
    let mut ops_raw = HashMap::new();
    for (i, raw_opts) in fp.seq_raw_options.iter().enumerate() {
        let i1 = i + 1; // 1-indexed
        let opts_str = if !raw_opts.is_empty() {
            raw_options_to_nmap_string(raw_opts)
        } else if let Some(ops) = fp.ops.get(&format!("T{i1}")) {
            ops_to_string(ops)
        } else {
            String::new()
        };
        ops_raw.insert(format!("O{i1}"), opts_str);
    }
    // Also include any OPS from T1-T6 that don't have seq_raw_options
    for i in 1..=6 {
        let key = format!("O{i}");
        if let std::collections::hash_map::Entry::Vacant(e) = ops_raw.entry(key) {
            let test_name = format!("T{i}");
            if let Some(ops) = fp.ops.get(&test_name) {
                e.insert(ops_to_string(ops));
            }
        }
    }
    if !ops_raw.is_empty() {
        raw.insert("OPS".to_string(), ops_raw);
    }

    // WIN test - window sizes for each test T1-T6
    let mut win_raw = HashMap::new();
    for i in 1..=6 {
        let test_name = format!("T{i}");
        if let Some(&window) = fp.win.get(&test_name) {
            win_raw.insert(format!("W{i}"), format!("{window:X}"));
        }
    }
    if !win_raw.is_empty() {
        raw.insert("WIN".to_string(), win_raw);
    }

    // ECN test
    if let Some(ref ecn) = fp.ecn {
        raw.insert("ECN".to_string(), ecn_to_raw(ecn));
    }

    // T1-T7 tests
    for i in 1..=7 {
        let test_name = format!("T{i}");
        if let Some(test) = fp.tests.get(&test_name) {
            raw.insert(test_name, test_result_to_raw(test));
        }
    }

    // U1 (UDP) test
    if let Some(ref u1) = fp.u1 {
        raw.insert("U1".to_string(), udp_test_to_raw(u1));
    }

    // IE (ICMP Echo) test
    if let Some(ref ie) = fp.ie {
        raw.insert("IE".to_string(), icmp_test_to_raw(ie));
    }

    raw
}

/// Convert `IpIdSeqClass` to nmap string representation.
fn ip_id_class_to_str(class: &IpIdSeqClass) -> String {
    match class {
        IpIdSeqClass::Fixed => "Z".to_string(),
        IpIdSeqClass::Random => "RD".to_string(),
        IpIdSeqClass::Incremental => "I".to_string(),
        IpIdSeqClass::Incremental257 => "BI".to_string(),
        IpIdSeqClass::Unknown => "O".to_string(),
    }
}

/// Convert `OpsFingerprint` to nmap compact string (e.g., "M5B4ST11NW2").
fn ops_to_string(ops: &OpsFingerprint) -> String {
    let mut s = String::new();
    if let Some(mss) = ops.mss {
        s.push_str(&format!("M{mss:X}"));
    }
    if ops.sack {
        s.push('S');
    }
    if ops.timestamp {
        s.push_str("T11");
    }
    for _ in 0..ops.nop_count {
        s.push('N');
    }
    if let Some(wscale) = ops.wscale {
        s.push_str(&format!("W{wscale}"));
    }
    if ops.eol {
        s.push('E');
    }
    s
}

/// Convert `EcnFingerprint` to raw attribute map.
fn ecn_to_raw(ecn: &EcnFingerprint) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("R".to_string(), "Y".to_string());
    m.insert("DF".to_string(), if ecn.df { "Y" } else { "N" }.to_string());
    // T field uses TTL guess (initial TTL estimate), not raw TTL
    if let Some(ttl) = ecn.ttl {
        let tg = get_initial_ttl_guess(ttl);
        m.insert("T".to_string(), format!("{tg:X}"));
        m.insert("TG".to_string(), format!("{tg:X}"));
    }
    // W (window size)
    if let Some(window) = ecn.window {
        m.insert("W".to_string(), format!("{window:X}"));
    }
    // O (TCP options)
    let opts_str = if !ecn.raw_options.is_empty() {
        raw_options_to_nmap_string(&ecn.raw_options)
    } else {
        String::new()
    };
    m.insert("O".to_string(), opts_str);
    // CC field encoding
    let cc = if ecn.ece && ecn.cwr {
        "Y"
    } else if ecn.ece {
        "S"
    } else {
        "N"
    };
    m.insert("CC".to_string(), cc.to_string());
    m.insert("Q".to_string(), String::new());
    m
}

/// Convert `TestResult` to raw attribute map.
fn test_result_to_raw(test: &super::fingerprint::TestResult) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "R".to_string(),
        if test.responded { "Y" } else { "N" }.to_string(),
    );

    if test.responded {
        m.insert(
            "DF".to_string(),
            if test.df { "Y" } else { "N" }.to_string(),
        );

        if let Some(ttl) = test.ttl {
            // T is actual TTL in hex, TG is TTL guess (initial TTL estimate)
            let tg = get_initial_ttl_guess(ttl);
            m.insert("T".to_string(), format!("{tg:X}"));
            m.insert("TG".to_string(), format!("{tg:X}"));
        }

        if let Some(window) = test.window {
            m.insert("W".to_string(), format!("{window:X}"));
        }

        // F (flags)
        let flags_str = flags_to_string(test.flags);
        m.insert("F".to_string(), flags_str);

        // O (TCP options) - use raw options for nmap-format string
        let opts_str = if !test.raw_options.is_empty() {
            raw_options_to_nmap_string(&test.raw_options)
        } else {
            ops_to_string(&OpsFingerprint {
                mss: test.mss,
                wscale: test.wscale,
                sack: test.sack,
                timestamp: test.timestamp,
                nop_count: 0,
                eol: false,
            })
        };
        m.insert("O".to_string(), opts_str);

        // RD (TCP data CRC32) - "0" when no payload data
        m.insert("RD".to_string(), "0".to_string());

        // Q (quirks) - empty for now
        m.insert("Q".to_string(), String::new());

        // S (sequence number relationship)
        let s = compute_seq_relationship(test.resp_seq, test.sent_seq, test.sent_ack);
        m.insert("S".to_string(), s);

        // A (ACK number relationship)
        let a = compute_ack_relationship(test.resp_ack, test.sent_seq);
        m.insert("A".to_string(), a);
    }

    m
}

/// Compute S (sequence number relationship) for nmap fingerprint.
///
/// Encoding from nmap osscan2.cc `get_fingerprint_by_resp`:
/// - Z: response seq == 0
/// - A: response seq == sent ack
/// - A+: response seq == sent ack + 1
/// - O: anything else (the host chose its own ISN)
fn compute_seq_relationship(resp_seq: u32, _sent_seq: u32, sent_ack: u32) -> String {
    if resp_seq == 0 {
        "Z".to_string()
    } else if resp_seq == sent_ack {
        "A".to_string()
    } else if resp_seq == sent_ack.wrapping_add(1) {
        "A+".to_string()
    } else {
        "O".to_string()
    }
}

/// Compute A (ACK number relationship) for nmap fingerprint.
///
/// Encoding from nmap osscan2.cc:
/// - Z: response ack == 0
/// - S: response ack == sent seq
/// - S+: response ack == sent seq + 1
/// - O: anything else
fn compute_ack_relationship(resp_ack: u32, sent_seq: u32) -> String {
    if resp_ack == 0 {
        "Z".to_string()
    } else if resp_ack == sent_seq {
        "S".to_string()
    } else if resp_ack == sent_seq.wrapping_add(1) {
        "S+".to_string()
    } else {
        "O".to_string()
    }
}

/// Convert raw TCP options bytes to nmap format string.
///
/// Nmap format: each option represented by a letter code followed by hex value.
/// E.g., `M5B4ST11NW7` = MSS(0x5B4) SACK Timestamp(1,1) NOP WScale(7)
fn raw_options_to_nmap_string(opts: &[u8]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => {
                // EOL
                s.push('L');
                break;
            }
            1 => {
                // NOP
                s.push('N');
                i += 1;
            }
            2 => {
                // MSS
                if i + 3 < opts.len() {
                    let mss = u16::from_be_bytes([opts[i + 2], opts[i + 3]]);
                    s.push_str(&format!("M{mss:X}"));
                    i += 4;
                } else {
                    break;
                }
            }
            3 => {
                // Window Scale
                if i + 2 < opts.len() {
                    let ws = opts[i + 2];
                    s.push_str(&format!("W{ws:X}"));
                    i += 3;
                } else {
                    break;
                }
            }
            4 => {
                // SACK Permitted
                s.push('S');
                i += 2;
            }
            8 => {
                // Timestamp
                if i + 9 < opts.len() {
                    let tsval =
                        u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                    let tsecr =
                        u32::from_be_bytes([opts[i + 6], opts[i + 7], opts[i + 8], opts[i + 9]]);
                    // Nmap encodes as Thexval where hex is nonzero indicator
                    let ts_ind = if tsval != 0 { 1 } else { 0 };
                    let te_ind = if tsecr != 0 { 1 } else { 0 };
                    s.push_str(&format!("T{ts_ind}{te_ind}"));
                    i += 10;
                } else {
                    break;
                }
            }
            _ => {
                // Unknown option, skip by length
                if i + 1 < opts.len() && opts[i + 1] > 1 {
                    i += opts[i + 1] as usize;
                } else {
                    break;
                }
            }
        }
    }
    s
}

/// Convert `UdpTestResult` to raw attribute map.
fn udp_test_to_raw(u1: &super::fingerprint::UdpTestResult) -> HashMap<String, String> {
    let mut m = HashMap::new();

    if u1.responded {
        m.insert("R".to_string(), "Y".to_string());
        m.insert("DF".to_string(), if u1.df { "Y" } else { "N" }.to_string());
        if let Some(ttl) = u1.ttl {
            m.insert("T".to_string(), format!("{ttl:X}"));
            let tg = get_initial_ttl_guess(ttl);
            m.insert("TG".to_string(), format!("{tg:X}"));
        }
        if let Some(len) = u1.ip_len {
            m.insert("IPL".to_string(), format!("{len:X}"));
        }
        if let Some(unused) = u1.unused {
            m.insert("UN".to_string(), format!("{unused:X}"));
        }
        // RIPL, RID, RIPCK, RUCK, RUD default to "G" (good)
        m.insert("RIPL".to_string(), "G".to_string());
        m.insert("RID".to_string(), "G".to_string());
        m.insert("RIPCK".to_string(), "G".to_string());
        m.insert("RUCK".to_string(), "G".to_string());
        m.insert("RUD".to_string(), "G".to_string());
    } else {
        m.insert("R".to_string(), "N".to_string());
    }

    m
}

/// Convert `IcmpTestResult` to raw attribute map.
fn icmp_test_to_raw(ie: &super::fingerprint::IcmpTestResult) -> HashMap<String, String> {
    let mut m = HashMap::new();

    if ie.responded1 || ie.responded2 {
        m.insert("R".to_string(), "Y".to_string());

        // DFI encoding
        let dfi = if ie.df1 && ie.df2 {
            "Y"
        } else if !ie.df1 && !ie.df2 {
            "N"
        } else {
            "S"
        };
        m.insert("DFI".to_string(), dfi.to_string());

        if let Some(ttl) = ie.ttl1 {
            m.insert("T".to_string(), format!("{ttl:X}"));
            let tg = get_initial_ttl_guess(ttl);
            m.insert("TG".to_string(), format!("{tg:X}"));
        }

        // CD encoding
        m.insert("CD".to_string(), "S".to_string());
    } else {
        m.insert("R".to_string(), "N".to_string());
    }

    m
}

/// Guess the initial TTL based on observed TTL.
///
/// Common initial TTL values: 32, 64, 128, 255.
/// Returns the smallest standard value >= observed TTL.
fn get_initial_ttl_guess(ttl: u8) -> u8 {
    if ttl <= 32 {
        32
    } else if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    }
}

/// Convert TCP flags byte to nmap string representation.
fn flags_to_string(flags: u8) -> String {
    let mut s = String::new();
    if flags & 0x40 != 0 {
        s.push('E');
    } // ECE
    if flags & 0x80 != 0 {
        s.push('C');
    } // CWR
    if flags & 0x20 != 0 {
        s.push('U');
    } // URG
    if flags & 0x10 != 0 {
        s.push('A');
    } // ACK
    if flags & 0x08 != 0 {
        s.push('P');
    } // PSH
    if flags & 0x04 != 0 {
        s.push('R');
    } // RST
    if flags & 0x02 != 0 {
        s.push('S');
    } // SYN
    if flags & 0x01 != 0 {
        s.push('F');
    } // FIN
    s
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
    /// Raw test results preserving expression strings.
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
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Internal API matches signature pattern for consistent error handling"
    )]
    fn parse_class_line(&mut self, line: &str) -> Result<()> {
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
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Internal API matches signature pattern for consistent error handling"
    )]
    fn parse_test_line(&mut self, line: &str) -> Result<()> {
        if let Some((test_name, values)) = line.split_once('(') {
            let values = values.trim_end_matches(')');
            self.tests.insert(test_name.to_string(), values.to_string());
        }
        Ok(())
    }

    /// Convert parsed fingerprint to `OsReference`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "API consistency for potential future error cases"
    )]
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

        // Build compact fingerprint using enum keys and Box<str> values
        let compact_fp = self.build_compact_fingerprint();

        Ok(OsReference {
            name: self.name,
            family: os_family,
            vendor: self.vendor,
            generation: self.generation,
            device_type: self.device_type,
            cpe: self.cpe,
            compact_fp,
        })
    }

    /// Build compact fingerprint from test strings, preserving expressions.
    ///
    /// Uses `Section` and `AttrKey` enums instead of String keys,
    /// and `Box<str>` instead of `String` for values.
    /// Reduces per-fingerprint memory from ~20KB to ~3.5KB.
    fn build_compact_fingerprint(&self) -> CompactFingerprint {
        let mut fp = CompactFingerprint::new();

        for (test_name, values) in &self.tests {
            let Some(section) = Section::from_name(test_name) else {
                continue;
            };
            let mut attrs = Vec::new();
            for part in values.split('%') {
                if let Some((key, val)) = part.split_once('=') {
                    if let Some(attr) = AttrKey::from_name(key) {
                        attrs.push((attr, val.to_string().into_boxed_str()));
                    }
                } else if !part.is_empty() {
                    if let Some(attr) = AttrKey::from_name(part) {
                        attrs.push((attr, String::new().into_boxed_str()));
                    }
                }
            }
            if !attrs.is_empty() {
                fp.set_section(section, attrs);
            }
        }

        fp
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
        assert!(!db.match_points.is_empty());
    }

    #[test]
    fn test_compare_seq() {
        let _db = FingerprintDatabase::empty();
        let seq1 = SeqFingerprint {
            class: IsnClass::Random,
            timestamp: false,
            ts_val: 0,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Random,
            ci: IpIdSeqClass::Random,
            ii: IpIdSeqClass::Random,
            ss: 0,
            timestamps: Vec::new(),
        };
        let seq2 = SeqFingerprint {
            class: IsnClass::Incremental { increment: 1 },
            timestamp: false,
            ts_val: 0,
            gcd: 1,
            isr: 0,
            sp: 0,
            ti: IpIdSeqClass::Incremental,
            ci: IpIdSeqClass::Incremental,
            ii: IpIdSeqClass::Incremental,
            ss: 0,
            timestamps: Vec::new(),
        };

        // Different TI values should produce different raw output
        let fp1 = OsFingerprint::new().with_seq(seq1);
        let fp2 = OsFingerprint::new().with_seq(seq2);
        let raw1 = fingerprint_to_raw(&fp1);
        let raw2 = fingerprint_to_raw(&fp2);
        assert_ne!(
            raw1.get("SEQ").and_then(|s| s.get("TI")),
            raw2.get("SEQ").and_then(|s| s.get("TI"))
        );
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

        let db = FingerprintDatabase::parse(db_content).expect("parse failed");
        assert_eq!(db.fingerprints.len(), 2);

        let fp1 = db.fingerprints.get("Test OS 1").expect("missing fp1");
        assert_eq!(fp1.name, "Test OS 1");
        assert_eq!(fp1.vendor, Some("TestVendor".to_string()));
        assert_eq!(fp1.family, OsFamily::Other("TestOS".to_string()));
        assert_eq!(fp1.generation, Some("1.0".to_string()));
        assert_eq!(fp1.device_type, Some("general purpose".to_string()));

        // Verify compact fingerprint preserves expressions
        let raw_seq = fp1.compact_fp.get_str("SEQ", "SP").expect("missing SEQ SP");
        assert_eq!(raw_seq, "100-105");

        let fp2 = db.fingerprints.get("Test OS 2").expect("missing fp2");
        assert_eq!(fp2.name, "Test OS 2");
        assert_eq!(fp2.vendor, Some("AnotherVendor".to_string()));
    }

    #[test]
    fn test_parse_match_points() {
        let db_content = r"
MatchPoints
SEQ(SP=25%GCD=75%ISR=25%TI=100)
T1(R=100%DF=20)

Fingerprint Test OS
Class Test | Linux | 5.X | general purpose
SEQ(SP=80-A0%GCD=1%ISR=108%TI=I)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS)
";

        let db = FingerprintDatabase::parse(db_content).expect("parse failed");

        // Verify MatchPoints were parsed
        let seq_pts = db.match_points.get("SEQ").expect("missing SEQ points");
        assert_eq!(seq_pts.get("SP"), Some(&25));
        assert_eq!(seq_pts.get("TI"), Some(&100));

        let t1_pts = db.match_points.get("T1").expect("missing T1 points");
        assert_eq!(t1_pts.get("R"), Some(&100));
        assert_eq!(t1_pts.get("DF"), Some(&20));
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

        let db = FingerprintDatabase::parse(db_content).expect("parse failed");
        assert_eq!(db.fingerprints.len(), 3);

        let linux = db.fingerprints.get("Linux Test").expect("missing linux");
        assert!(matches!(linux.family, OsFamily::Linux));

        let windows = db
            .fingerprints
            .get("Windows Test")
            .expect("missing windows");
        assert!(matches!(windows.family, OsFamily::Windows));

        let unknown = db
            .fingerprints
            .get("Unknown Test")
            .expect("missing unknown");
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

        let db = FingerprintDatabase::parse(db_content).expect("parse failed");
        let fp = db.fingerprints.get("Test With CPE").expect("missing fp");
        assert_eq!(fp.cpe, Some("cpe:/o:test:os:1.0".to_string()));
    }

    #[test]
    fn test_empty_db() {
        let db = FingerprintDatabase::parse("").expect("parse failed");
        assert!(db.fingerprints.is_empty());
    }

    #[test]
    fn test_db_with_only_comments() {
        let db_content = r"
# This is a comment
# Another comment
";
        let db = FingerprintDatabase::parse(db_content).expect("parse failed");
        assert!(db.fingerprints.is_empty());
    }

    #[test]
    fn test_flags_to_string() {
        assert_eq!(flags_to_string(0x12), "AS"); // ACK + SYN
        assert_eq!(flags_to_string(0x14), "AR"); // ACK + RST
        assert_eq!(flags_to_string(0x02), "S"); // SYN only
        assert_eq!(flags_to_string(0x04), "R"); // RST only
    }

    #[test]
    fn test_get_initial_ttl_guess() {
        assert_eq!(get_initial_ttl_guess(30), 32);
        assert_eq!(get_initial_ttl_guess(60), 64);
        assert_eq!(get_initial_ttl_guess(64), 64);
        assert_eq!(get_initial_ttl_guess(100), 128);
        assert_eq!(get_initial_ttl_guess(200), 255);
    }

    #[test]
    fn test_fingerprint_to_raw_basic() {
        let fp = OsFingerprint::new().with_seq(SeqFingerprint {
            class: IsnClass::Incremental { increment: 1 },
            timestamp: true,
            ts_val: 0xA, // nmap TS=A means ~1000 Hz
            gcd: 1,
            isr: 0x9A,
            sp: 0xFE,
            ti: IpIdSeqClass::Incremental,
            ci: IpIdSeqClass::Incremental,
            ii: IpIdSeqClass::Incremental,
            ss: 1,
            timestamps: Vec::new(),
        });

        let raw = fingerprint_to_raw(&fp);
        let seq = raw.get("SEQ").expect("missing SEQ");
        assert_eq!(seq.get("TI"), Some(&"I".to_string()));
        assert_eq!(seq.get("SS"), Some(&"S".to_string()));
        assert_eq!(seq.get("SP"), Some(&"FE".to_string()));
        assert_eq!(seq.get("ISR"), Some(&"9A".to_string()));
        assert_eq!(seq.get("TS"), Some(&"A".to_string()));
    }
}

// Rust guideline compliant 2026-04-09
