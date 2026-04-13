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

//! OS fingerprint expression matching engine.
//!
//! Implements nmap's `expr_match` algorithm for comparing observed
//! fingerprint values against reference expressions from nmap-os-db.
//!
//! Supports:
//! - Exact string match: `"Y"` matches `"Y"`
//! - Hex range: `"FA-104"` matches hex values in `[0xFA, 0x104]`
//! - Alternatives: `"Y|N"` matches either `"Y"` or `"N"`
//! - Greater/less than: `">10"` or `"<FF"`
//! - Nested expressions: `"M[>500]ST11W[1-5]"` for TCP options

use std::collections::HashMap;

/// Raw OS fingerprint storing test attributes as strings.
///
/// Used for observed fingerprints (created once per target, short-lived).
/// Reference fingerprints use `CompactFingerprint` for memory efficiency.
pub type RawFingerprint = HashMap<String, HashMap<String, String>>;

/// Match point weights for each test attribute.
///
/// Maps test name -> attribute name -> point value.
/// Parsed from the MatchPoints section of nmap-os-db.
pub type MatchPointsDef = HashMap<String, HashMap<String, u32>>;

/// Section names in nmap-os-db (13 total).
///
/// Using an enum instead of String keys eliminates ~20MB of heap allocations
/// across 6036 reference fingerprints (each section name repeated 6036 times).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[expect(missing_docs, reason = "Self-explanatory nmap section name variants")]
pub enum Section {
    SEQ = 0,
    OPS = 1,
    WIN = 2,
    ECN = 3,
    T1 = 4,
    T2 = 5,
    T3 = 6,
    T4 = 7,
    T5 = 8,
    T6 = 9,
    T7 = 10,
    U1 = 11,
    IE = 12,
}

impl Section {
    /// Total number of fingerprint sections.
    pub const COUNT: usize = 13;

    /// All section variants in order.
    pub const ALL: [Section; Self::COUNT] = [
        Section::SEQ,
        Section::OPS,
        Section::WIN,
        Section::ECN,
        Section::T1,
        Section::T2,
        Section::T3,
        Section::T4,
        Section::T5,
        Section::T6,
        Section::T7,
        Section::U1,
        Section::IE,
    ];

    /// Parse a section name string to enum.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SEQ" => Some(Self::SEQ),
            "OPS" => Some(Self::OPS),
            "WIN" => Some(Self::WIN),
            "ECN" => Some(Self::ECN),
            "T1" => Some(Self::T1),
            "T2" => Some(Self::T2),
            "T3" => Some(Self::T3),
            "T4" => Some(Self::T4),
            "T5" => Some(Self::T5),
            "T6" => Some(Self::T6),
            "T7" => Some(Self::T7),
            "U1" => Some(Self::U1),
            "IE" => Some(Self::IE),
            _ => None,
        }
    }

    /// Get the nmap-os-db section name string.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SEQ => "SEQ",
            Self::OPS => "OPS",
            Self::WIN => "WIN",
            Self::ECN => "ECN",
            Self::T1 => "T1",
            Self::T2 => "T2",
            Self::T3 => "T3",
            Self::T4 => "T4",
            Self::T5 => "T5",
            Self::T6 => "T6",
            Self::T7 => "T7",
            Self::U1 => "U1",
            Self::IE => "IE",
        }
    }

    /// Get the section index (0-based).
    #[must_use]
    pub fn idx(self) -> usize {
        self as usize
    }
}

/// Attribute keys within fingerprint sections.
///
/// 41 unique keys across all sections. Using enum instead of String
/// eliminates ~23MB of String allocations in 6036 reference fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[expect(missing_docs, reason = "Self-explanatory nmap attribute key variants")]
pub enum AttrKey {
    // Common across multiple sections
    R,
    DF,
    T,
    TG,
    W,
    S,
    A,
    F,
    O,
    Q,
    RD,
    CC,
    // SEQ-specific
    SP,
    GCD,
    ISR,
    TI,
    CI,
    II,
    SS,
    TS,
    // OPS (O1-O6)
    O1,
    O2,
    O3,
    O4,
    O5,
    O6,
    // WIN (W1-W6)
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    // U1-specific
    IPL,
    UN,
    RIPL,
    RID,
    RIPCK,
    RUCK,
    RUD,
    // IE-specific
    DFI,
    CD,
}

impl AttrKey {
    /// Parse an attribute name string to enum.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "R" => Some(Self::R),
            "DF" => Some(Self::DF),
            "T" => Some(Self::T),
            "TG" => Some(Self::TG),
            "W" => Some(Self::W),
            "S" => Some(Self::S),
            "A" => Some(Self::A),
            "F" => Some(Self::F),
            "O" => Some(Self::O),
            "Q" => Some(Self::Q),
            "RD" => Some(Self::RD),
            "CC" => Some(Self::CC),
            "SP" => Some(Self::SP),
            "GCD" => Some(Self::GCD),
            "ISR" => Some(Self::ISR),
            "TI" => Some(Self::TI),
            "CI" => Some(Self::CI),
            "II" => Some(Self::II),
            "SS" => Some(Self::SS),
            "TS" => Some(Self::TS),
            "O1" => Some(Self::O1),
            "O2" => Some(Self::O2),
            "O3" => Some(Self::O3),
            "O4" => Some(Self::O4),
            "O5" => Some(Self::O5),
            "O6" => Some(Self::O6),
            "W1" => Some(Self::W1),
            "W2" => Some(Self::W2),
            "W3" => Some(Self::W3),
            "W4" => Some(Self::W4),
            "W5" => Some(Self::W5),
            "W6" => Some(Self::W6),
            "IPL" => Some(Self::IPL),
            "UN" => Some(Self::UN),
            "RIPL" => Some(Self::RIPL),
            "RID" => Some(Self::RID),
            "RIPCK" => Some(Self::RIPCK),
            "RUCK" => Some(Self::RUCK),
            "RUD" => Some(Self::RUD),
            "DFI" => Some(Self::DFI),
            "CD" => Some(Self::CD),
            _ => None,
        }
    }

    /// Get the nmap-os-db attribute name string.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::R => "R",
            Self::DF => "DF",
            Self::T => "T",
            Self::TG => "TG",
            Self::W => "W",
            Self::S => "S",
            Self::A => "A",
            Self::F => "F",
            Self::O => "O",
            Self::Q => "Q",
            Self::RD => "RD",
            Self::CC => "CC",
            Self::SP => "SP",
            Self::GCD => "GCD",
            Self::ISR => "ISR",
            Self::TI => "TI",
            Self::CI => "CI",
            Self::II => "II",
            Self::SS => "SS",
            Self::TS => "TS",
            Self::O1 => "O1",
            Self::O2 => "O2",
            Self::O3 => "O3",
            Self::O4 => "O4",
            Self::O5 => "O5",
            Self::O6 => "O6",
            Self::W1 => "W1",
            Self::W2 => "W2",
            Self::W3 => "W3",
            Self::W4 => "W4",
            Self::W5 => "W5",
            Self::W6 => "W6",
            Self::IPL => "IPL",
            Self::UN => "UN",
            Self::RIPL => "RIPL",
            Self::RID => "RID",
            Self::RIPCK => "RIPCK",
            Self::RUCK => "RUCK",
            Self::RUD => "RUD",
            Self::DFI => "DFI",
            Self::CD => "CD",
        }
    }
}

/// Attribute key-value pair in a compact fingerprint section.
type AttrPair = (AttrKey, Box<str>);

/// Section data: ordered list of attribute key-value pairs.
type SectionData = Vec<AttrPair>;

/// Compact fingerprint storage for reference fingerprints.
///
/// Uses enum keys (`AttrKey`) and `Box<str>` values instead of
/// `HashMap<String, String>`, reducing per-fingerprint memory from
/// ~20KB to ~3.5KB (5.7x reduction).
///
/// Memory layout per fingerprint:
/// - 13 section slots (Option<Vec<...>>): ~208 bytes
/// - ~10 attributes per section, ~14 sections: ~4.7KB values
/// - Total: ~3.5KB vs ~20KB with HashMap<String, HashMap<String, String>>
///
/// For 6036 reference fingerprints: ~21MB vs ~120MB.
#[derive(Debug, Clone, Default)]
pub struct CompactFingerprint {
    /// One slot per section (SEQ, OPS, WIN, ECN, T1-T7, U1, IE).
    /// Each slot contains optional attribute key-value pairs.
    sections: [Option<SectionData>; Section::COUNT],
}

impl CompactFingerprint {
    /// Create an empty compact fingerprint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set attributes for a section.
    pub fn set_section(&mut self, section: Section, attrs: Vec<(AttrKey, Box<str>)>) {
        self.sections[section.idx()] = Some(attrs);
    }

    /// Get a value by section and attribute enum (fast, no string parsing).
    #[must_use]
    pub fn get(&self, section: Section, attr: AttrKey) -> Option<&str> {
        self.sections[section.idx()].as_ref().and_then(|attrs| {
            attrs
                .iter()
                .find(|(k, _)| *k == attr)
                .map(|(_, v)| v.as_ref())
        })
    }

    /// Get a value by section name and attribute name strings.
    ///
    /// Used for bridging with `MatchPointsDef` (HashMap-based) during matching.
    #[must_use]
    pub fn get_str(&self, section_name: &str, attr_name: &str) -> Option<&str> {
        let section = Section::from_name(section_name)?;
        let attr = AttrKey::from_name(attr_name)?;
        self.get(section, attr)
    }

    /// Get all attributes for a section by name.
    #[must_use]
    pub fn get_section_str(&self, section_name: &str) -> Option<&[(AttrKey, Box<str>)]> {
        Section::from_name(section_name).and_then(|s| self.sections[s.idx()].as_deref())
    }
}

/// Match point entry: attribute key with its point value.
type PointEntry = (AttrKey, u32);

/// Pre-compiled match points with enum keys for fast matching.
///
/// Compiled once from `MatchPointsDef` at database load time.
/// Avoids string-to-enum conversion on every fingerprint comparison.
#[derive(Debug, Clone)]
pub struct CompiledMatchPoints {
    /// Per-section match points, indexed by `Section` enum.
    points: [Option<Vec<PointEntry>>; Section::COUNT],
    /// Pre-computed total of all point values.
    total: u32,
}

impl CompiledMatchPoints {
    /// Compile match points from HashMap-based definition.
    #[must_use]
    pub fn from_match_points(mp: &MatchPointsDef) -> Self {
        let mut points: [Option<Vec<PointEntry>>; Section::COUNT] = Default::default();
        let mut total = 0u32;

        for (section_name, attrs) in mp {
            let Some(section) = Section::from_name(section_name) else {
                continue;
            };
            let mut compiled = Vec::new();
            for (attr_name, &pts) in attrs {
                let Some(attr) = AttrKey::from_name(attr_name) else {
                    continue;
                };
                compiled.push((attr, pts));
                total += pts;
            }
            if !compiled.is_empty() {
                points[section.idx()] = Some(compiled);
            }
        }

        Self { points, total }
    }

    /// Total match points across all sections and attributes.
    #[must_use]
    pub fn total(&self) -> u32 {
        self.total
    }
}

/// Compare an observed fingerprint against a compact reference fingerprint.
///
/// Optimized version that uses pre-compiled match points with enum keys,
/// avoiding string-to-enum conversion on every attribute lookup.
/// Returns accuracy as a value between 0.0 and 1.0.
/// Uses early termination when accuracy cannot reach `threshold`.
#[must_use]
pub fn compare_compact(
    observed: &RawFingerprint,
    reference: &CompactFingerprint,
    match_points: &CompiledMatchPoints,
    threshold: f64,
) -> f64 {
    let mut total_pts: u32 = 0;
    let mut matched_pts: u32 = 0;
    let max_mismatch = ((1.0 - threshold) * f64::from(match_points.total)) as u32;

    for (section_idx, section_points) in match_points.points.iter().enumerate() {
        let Some(pts) = section_points else { continue };
        let section = Section::ALL[section_idx];
        let section_name = section.name();
        let obs_section = observed.get(section_name);

        for &(attr, points) in pts {
            let attr_name = attr.name();
            let ref_val = reference.get(section, attr);
            let obs_val = obs_section.and_then(|s| s.get(attr_name));

            if let (Some(ref_expr), Some(obs_value)) = (ref_val, obs_val) {
                total_pts += points;

                let is_opts = attr == AttrKey::O
                    || (section == Section::OPS
                        && matches!(
                            attr,
                            AttrKey::O1
                                | AttrKey::O2
                                | AttrKey::O3
                                | AttrKey::O4
                                | AttrKey::O5
                                | AttrKey::O6
                        ));

                if expr_match(obs_value, ref_expr, is_opts) {
                    matched_pts += points;
                }

                if total_pts - matched_pts > max_mismatch {
                    return f64::from(matched_pts) / f64::from(total_pts.max(1));
                }
            }
        }
    }

    f64::from(matched_pts) / f64::from(total_pts.max(1))
}

/// Total number of points across all match point attributes.
///
/// Pre-computed from `MatchPointsDef` to avoid repeated summation.
#[must_use]
pub fn total_match_points(mp: &MatchPointsDef) -> u32 {
    mp.values().map(|attrs| attrs.values().sum::<u32>()).sum()
}

/// Compare an observed fingerprint against a reference using weighted scoring.
///
/// Returns accuracy as a value between 0.0 and 1.0.
/// Uses early termination when accuracy cannot reach `threshold`.
#[must_use]
pub fn compare_fingerprints(
    observed: &RawFingerprint,
    reference: &RawFingerprint,
    match_points: &MatchPointsDef,
    total_points: u32,
    threshold: f64,
) -> f64 {
    let mut total_pts: u32 = 0;
    let mut matched_pts: u32 = 0;

    // Pre-compute max possible mismatch for early termination
    let max_mismatch = ((1.0 - threshold) * f64::from(total_points)) as u32;

    for (test_name, attr_points) in match_points {
        let ref_test = reference.get(test_name);
        let obs_test = observed.get(test_name);

        for (attr_name, &points) in attr_points {
            let ref_val = ref_test.and_then(|t| t.get(attr_name));
            let obs_val = obs_test.and_then(|t| t.get(attr_name));

            if let (Some(ref_expr), Some(obs_value)) = (ref_val, obs_val) {
                total_pts += points;

                // TCP options fields use nested matching
                let is_opts_field =
                    attr_name == "O" || (test_name == "OPS" && attr_name.starts_with('O'));

                if expr_match(obs_value, ref_expr, is_opts_field) {
                    matched_pts += points;
                }

                // Early termination check
                if total_pts - matched_pts > max_mismatch {
                    return if total_pts > 0 {
                        f64::from(matched_pts) / f64::from(total_pts)
                    } else {
                        0.0
                    };
                }
            }
        }
    }

    if total_pts > 0 {
        f64::from(matched_pts) / f64::from(total_pts)
    } else {
        0.0
    }
}

/// Match an observed value against a reference expression.
///
/// Expression syntax from nmap-os-db:
/// - Exact: `"Y"` matches `"Y"`
/// - Range: `"FA-104"` matches hex values in `[0xFA, 0x104]`
/// - Alternatives: `"Y|N"` matches `"Y"` or `"N"`
/// - Greater than: `">10"` matches hex values > 0x10
/// - Less than: `"<FF"` matches hex values < 0xFF
/// - Nested: `"M[>500]ST11W[1-5]"` for structured option strings
///
/// When `do_nested` is true, bracket expressions are evaluated
/// recursively (used for TCP options fields like O= values).
#[must_use]
pub fn expr_match(value: &str, expression: &str, do_nested: bool) -> bool {
    if expression.is_empty() {
        return value.is_empty();
    }

    // Split on '|' (alternatives) at top level
    for alt in TopLevelSplit::new(expression, b'|') {
        if match_single_alternative(value, alt, do_nested) {
            return true;
        }
    }

    false
}

/// Match a single alternative (no top-level '|' present).
fn match_single_alternative(value: &str, expr: &str, do_nested: bool) -> bool {
    if do_nested && expr.contains('[') {
        return match_nested(value, expr);
    }

    // Empty expression matches empty value
    if expr.is_empty() {
        return value.is_empty();
    }

    // Strip leading zeros from hex values for comparison
    let val = strip_leading_zeros(value);

    // Greater than
    if let Some(rest) = expr.strip_prefix('>') {
        let rest = strip_leading_zeros(rest);
        return hex_compare(val, rest) == std::cmp::Ordering::Greater;
    }

    // Less than
    if let Some(rest) = expr.strip_prefix('<') {
        let rest = strip_leading_zeros(rest);
        return hex_compare(val, rest) == std::cmp::Ordering::Less;
    }

    // Range (hex): e.g., "FA-104"
    if val.bytes().next().is_some_and(|b| b.is_ascii_hexdigit())
        && expr.bytes().next().is_some_and(|b| b.is_ascii_hexdigit())
    {
        if let Some(dash_pos) = find_range_dash(expr) {
            let lo = strip_leading_zeros(&expr[..dash_pos]);
            let hi = strip_leading_zeros(&expr[dash_pos + 1..]);
            return hex_compare(val, lo) != std::cmp::Ordering::Less
                && hex_compare(val, hi) != std::cmp::Ordering::Greater;
        }
    }

    // Exact match
    val == strip_leading_zeros(expr)
}

/// Match a value against a nested expression like `"M[>500]ST11W[1-5]"`.
///
/// The expression has literal segments interspersed with `[expr]` blocks.
/// Each `[expr]` matches hex digits from the value using `expr_match`.
fn match_nested(value: &str, expr: &str) -> bool {
    let mut val_pos = 0;
    let mut expr_pos = 0;
    let expr_bytes = expr.as_bytes();
    let val_bytes = value.as_bytes();

    while expr_pos < expr_bytes.len() {
        if let Some(bracket_start) = find_bracket(expr_bytes, expr_pos) {
            // Match literal segment before the bracket
            let literal_len = bracket_start - expr_pos;
            if val_pos + literal_len > val_bytes.len() {
                return false;
            }
            if val_bytes[val_pos..val_pos + literal_len] != expr_bytes[expr_pos..bracket_start] {
                return false;
            }
            val_pos += literal_len;

            // Find closing bracket
            let close = match find_closing_bracket(expr_bytes, bracket_start + 1) {
                Some(pos) => pos,
                None => return false,
            };

            let inner_expr = &expr[bracket_start + 1..close];

            // Extract hex digits from value at current position
            let hex_end = consume_hex_digits(val_bytes, val_pos);
            if hex_end == val_pos {
                return false;
            }

            let hex_val = &value[val_pos..hex_end];
            if !expr_match(hex_val, inner_expr, false) {
                return false;
            }

            val_pos = hex_end;
            expr_pos = close + 1;
        } else {
            // No more brackets: rest must match literally
            let remaining_expr = &expr[expr_pos..];
            let remaining_val = &value[val_pos..];
            return remaining_val == remaining_expr;
        }
    }

    val_pos == val_bytes.len()
}

/// Find the position of a `[` in the expression starting from `start`.
fn find_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == b'[')
        .map(|p| p + start)
}

/// Find matching `]` for a `[` expression.
fn find_closing_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == b']')
        .map(|p| p + start)
}

/// Consume consecutive hex digits from a byte slice.
fn consume_hex_digits(bytes: &[u8], start: usize) -> usize {
    let mut pos = start;
    while pos < bytes.len() && bytes[pos].is_ascii_hexdigit() {
        pos += 1;
    }
    pos
}

/// Compare two hex strings numerically.
///
/// Both inputs should have leading zeros stripped.
/// Longer string is larger; equal length compared lexicographically
/// (case-insensitive since hex digits are A-F).
fn hex_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_upper = a.to_ascii_uppercase();
    let b_upper = b.to_ascii_uppercase();
    a_upper
        .len()
        .cmp(&b_upper.len())
        .then_with(|| a_upper.cmp(&b_upper))
}

/// Strip leading zeros from a hex string, keeping at least one character.
fn strip_leading_zeros(s: &str) -> &str {
    let stripped = s.trim_start_matches('0');
    if stripped.is_empty() && !s.is_empty() {
        // Keep one zero for "0" or "00"
        &s[s.len() - 1..]
    } else {
        stripped
    }
}

/// Find the dash that represents a range separator in a hex expression.
///
/// A dash at position 0 is not a range separator (it would be a literal).
/// Returns `None` if no range dash is found.
fn find_range_dash(expr: &str) -> Option<usize> {
    // Skip position 0 (could be negative sign, not applicable for hex ranges)
    expr[1..].find('-').map(|p| p + 1)
}

/// Iterator that splits on a delimiter while respecting brackets.
///
/// Splits `"A|B[C|D]E|F"` on `|` into `["A", "B[C|D]E", "F"]`,
/// skipping delimiters inside `[...]`.
struct TopLevelSplit<'a> {
    data: &'a str,
    delim: u8,
    pos: usize,
}

impl<'a> TopLevelSplit<'a> {
    fn new(data: &'a str, delim: u8) -> Self {
        Self {
            data,
            delim,
            pos: 0,
        }
    }
}

impl<'a> Iterator for TopLevelSplit<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos > self.data.len() {
            return None;
        }

        let bytes = self.data.as_bytes();
        let start = self.pos;
        let mut depth = 0u32;
        let mut i = start;

        while i < bytes.len() {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => depth = depth.saturating_sub(1),
                b if b == self.delim && depth == 0 => {
                    self.pos = i + 1;
                    return Some(&self.data[start..i]);
                }
                _ => {}
            }
            i += 1;
        }

        self.pos = self.data.len() + 1;
        Some(&self.data[start..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(expr_match("Y", "Y", false));
        assert!(expr_match("N", "N", false));
        assert!(!expr_match("Y", "N", false));
        assert!(expr_match("", "", false));
        assert!(!expr_match("Y", "", false));
        assert!(!expr_match("", "Y", false));
    }

    #[test]
    fn test_alternatives() {
        assert!(expr_match("Y", "Y|N", false));
        assert!(expr_match("N", "Y|N", false));
        assert!(!expr_match("X", "Y|N", false));
        assert!(expr_match("S", "S|O", false));
    }

    #[test]
    fn test_hex_range() {
        // FA-104 means 0xFA to 0x104
        assert!(expr_match("FA", "FA-104", false));
        assert!(expr_match("FF", "FA-104", false));
        assert!(expr_match("100", "FA-104", false));
        assert!(expr_match("104", "FA-104", false));
        assert!(!expr_match("F9", "FA-104", false));
        assert!(!expr_match("105", "FA-104", false));
    }

    #[test]
    fn test_greater_than() {
        assert!(expr_match("11", ">10", false));
        assert!(expr_match("FF", ">10", false));
        assert!(!expr_match("10", ">10", false));
        assert!(!expr_match("F", ">10", false));
    }

    #[test]
    fn test_less_than() {
        assert!(expr_match("F", "<10", false));
        assert!(expr_match("9", "<10", false));
        assert!(!expr_match("10", "<10", false));
        assert!(!expr_match("FF", "<10", false));
    }

    #[test]
    fn test_leading_zeros() {
        assert!(expr_match("0", "0", false));
        assert!(expr_match("00", "0", false));
        assert!(expr_match("0", "00", false));
        assert!(expr_match("0FA", "FA", false));
    }

    #[test]
    fn test_nested_match() {
        // M5B4ST11NW2 against M[>500]ST11NW[1-5]
        assert!(expr_match("M5B4ST11NW2", "M[>500]ST11NW[1-5]", true));
        assert!(expr_match("M5B4ST11NW5", "M[>500]ST11NW[1-5]", true));
        assert!(!expr_match("M5B4ST11NW6", "M[>500]ST11NW[1-5]", true));
        assert!(!expr_match("M400ST11NW2", "M[>500]ST11NW[1-5]", true));
    }

    #[test]
    fn test_nested_exact() {
        assert!(expr_match("M5B4", "M5B4", true));
        assert!(!expr_match("M5B4", "M5B5", true));
    }

    #[test]
    fn test_string_match() {
        assert!(expr_match("S", "S", false));
        assert!(expr_match("O", "O", false));
        assert!(expr_match("A+", "A+", false));
        assert!(expr_match("S+", "S+", false));
        assert!(expr_match("AS", "AS", false));
    }

    #[test]
    fn test_alternatives_with_strings() {
        assert!(expr_match("O", "O|S+", false));
        assert!(expr_match("S+", "O|S+", false));
        assert!(expr_match("A", "A|S+|O", false));
    }

    #[test]
    fn test_top_level_split() {
        let parts: Vec<&str> = TopLevelSplit::new("A|B|C", b'|').collect();
        assert_eq!(parts, vec!["A", "B", "C"]);

        let parts: Vec<&str> = TopLevelSplit::new("A|B[C|D]E|F", b'|').collect();
        assert_eq!(parts, vec!["A", "B[C|D]E", "F"]);

        let parts: Vec<&str> = TopLevelSplit::new("single", b'|').collect();
        assert_eq!(parts, vec!["single"]);
    }

    #[test]
    fn test_compare_fingerprints_basic() {
        let mut mp = MatchPointsDef::new();
        let mut seq_pts = HashMap::new();
        seq_pts.insert("TI".to_string(), 100);
        seq_pts.insert("SP".to_string(), 25);
        mp.insert("SEQ".to_string(), seq_pts);

        let mut reference = RawFingerprint::new();
        let mut seq_ref = HashMap::new();
        seq_ref.insert("TI".to_string(), "I".to_string());
        seq_ref.insert("SP".to_string(), "80-A0".to_string());
        reference.insert("SEQ".to_string(), seq_ref);

        let mut observed = RawFingerprint::new();
        let mut seq_obs = HashMap::new();
        seq_obs.insert("TI".to_string(), "I".to_string());
        seq_obs.insert("SP".to_string(), "90".to_string());
        observed.insert("SEQ".to_string(), seq_obs);

        let total = total_match_points(&mp);
        let acc = compare_fingerprints(&observed, &reference, &mp, total, 0.0);
        assert!((acc - 1.0).abs() < f64::EPSILON, "Expected 1.0 got {acc}");
    }

    #[test]
    fn test_compare_partial_match() {
        let mut mp = MatchPointsDef::new();
        let mut t1_pts = HashMap::new();
        t1_pts.insert("R".to_string(), 100);
        t1_pts.insert("DF".to_string(), 20);
        mp.insert("T1".to_string(), t1_pts);

        let mut reference = RawFingerprint::new();
        let mut t1_ref = HashMap::new();
        t1_ref.insert("R".to_string(), "Y".to_string());
        t1_ref.insert("DF".to_string(), "Y".to_string());
        reference.insert("T1".to_string(), t1_ref);

        let mut observed = RawFingerprint::new();
        let mut t1_obs = HashMap::new();
        t1_obs.insert("R".to_string(), "Y".to_string());
        t1_obs.insert("DF".to_string(), "N".to_string()); // Mismatch
        observed.insert("T1".to_string(), t1_obs);

        let total = total_match_points(&mp);
        let acc = compare_fingerprints(&observed, &reference, &mp, total, 0.0);
        // 100 matched out of 120 = 0.8333...
        let expected = 100.0 / 120.0;
        assert!(
            (acc - expected).abs() < 0.001,
            "Expected {expected} got {acc}"
        );
    }
}

// Rust guideline compliant 2026-04-09
