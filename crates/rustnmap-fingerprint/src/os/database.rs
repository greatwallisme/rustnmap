//! OS fingerprint database loader.
//!
//! Parses nmap-os-db files containing reference fingerprints
//! for OS matching.

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use tracing::info;

use super::fingerprint::OsFingerprint;
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
    pub fn empty() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    /// Load database from nmap-os-db file.
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
            else if line.contains('(') && !line.starts_with("Fingerprint ") && !line.starts_with("Class ") && !line.starts_with("CPE ") {
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
    fn calculate_match_score(&self, fp1: &OsFingerprint, fp2: &OsFingerprint) -> f64 {
        let mut diff = 0.0;

        // Compare SEQ
        diff += self.compare_seq(fp1.seq.as_ref(), fp2.seq.as_ref());

        // Compare OPS
        for (test, ops1) in &fp1.ops {
            if let Some(ops2) = fp2.ops.get(test) {
                diff += self.compare_ops(ops1, ops2);
            }
        }

        // Compare WIN
        for (test, win1) in &fp1.win {
            if let Some(win2) = fp2.win.get(test) {
                diff += if win1 == win2 { 0.0 } else { 5.0 };
            }
        }

        // Compare ECN
        diff += self.compare_ecn(fp1.ecn.as_ref(), fp2.ecn.as_ref());

        diff
    }

    /// Compare SEQ fingerprints.
    fn compare_seq(
        &self,
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
        &self,
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
        diff += (ops1.nop_count as f64 - ops2.nop_count as f64).abs() / 2.0;
        diff += if ops1.eol == ops2.eol { 0.0 } else { 1.0 };

        diff
    }

    /// Compare ECN fingerprints.
    fn compare_ecn(
        &self,
        ecn1: Option<&crate::os::fingerprint::EcnFingerprint>,
        ecn2: Option<&crate::os::fingerprint::EcnFingerprint>,
    ) -> f64 {
        match (ecn1, ecn2) {
            (Some(e1), Some(e2)) => {
                let mut diff = 0.0;
                diff += if e1.ece == e2.ece { 0.0 } else { 2.0 };
                diff += if e1.df == e2.df { 0.0 } else { 1.0 };
                diff += if e1.cwr == e2.cwr { 0.0 } else { 2.0 };
                diff += (e1.tos as f64 - e2.tos as f64).abs() / 10.0;
                diff
            }
            (None, None) => 0.0,
            _ => 3.0,
        }
    }

    /// Convert difference score to accuracy percentage.
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
    fn parse_class_line(&mut self, line: &str) -> Result<()> {
        // Format: "Class Microsoft | Windows | 10 | general purpose"
        // or: "Class Linux | Linux | 5.X | general purpose"
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();

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
    fn parse_test_line(&mut self, line: &str) -> Result<()> {
        // Test lines look like: "SEQ(SP=101-105%GCD=1%ISR=107)"
        // or: "OPS(O1=M5B4ST11NW2%O2=M5B4ST11NW2)"
        if let Some((test_name, values)) = line.split_once('(') {
            let values = values.trim_end_matches(')');
            self.tests.insert(test_name.to_string(), values.to_string());
        }
        Ok(())
    }

    /// Convert parsed fingerprint to OsReference.
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
        let fingerprint = OsFingerprint::new();
        // TODO: Parse test results into fingerprint structure
        // This requires parsing complex test value strings

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
        let db = FingerprintDatabase::empty();
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
        assert!(db.compare_seq(Some(&seq1), Some(&seq2)) > 5.0);

        // Same class = 0.0 diff
        let diff = db.compare_seq(Some(&seq1), Some(&seq1));
        assert_eq!(diff, 0.0);
    }

    #[test]
    fn test_parse_simple_db() {
        let db_content = r#"
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
"#;

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
        let db_content = r#"
Fingerprint Linux Test
Class Linux | Linux | 5.X | general purpose

Fingerprint Windows Test
Class Microsoft | Windows | 10 | general purpose

Fingerprint Unknown Test
Class Unknown | UnknownOS
"#;

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
        let db_content = r#"
Fingerprint Test With CPE
Class Test | TestOS | 1.0 | general purpose
CPE cpe:/o:test:os:1.0
SEQ(SP=100)
"#;

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
        let db_content = r#"
# This is a comment
# Another comment
"#;
        let db = FingerprintDatabase::parse(db_content).unwrap();
        assert!(db.fingerprints.is_empty());
    }
}
