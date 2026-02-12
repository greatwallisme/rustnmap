//! OS fingerprint database loader.
//!
//! Parses nmap-os-db files containing reference fingerprints
//! for OS matching.

use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{FingerprintError, Result};
use super::fingerprint::{OsFingerprint};

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

    /// Parse database content.
    fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();

        // Fingerprint entries start with "Fingerprint "
        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("Fingerprint ") {
                // TODO: Implement full nmap-os-db parsing with proper line-based state machine
                // This requires multi-line parsing to extract:
                // - OS class and vendor information
                // - SEQ, OPS, WIN, ECN test results
                // - T1-T7, U1, IE test fingerprints
                let fp_name = "Unknown".to_string();
                db.fingerprints.insert(fp_name.clone(), OsReference {
                    name: fp_name,
                    family: OsFamily::Other("Unknown".to_string()).clone(),
                    vendor: None,
                    generation: None,
                    device_type: None,
                    cpe: None,
                    fingerprint: OsFingerprint::new(),
                });
            }
        }

        info!("Loaded {} OS fingerprints from database", db.fingerprints.len());
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
                if s1.class == s2.class { 0.0 } else { 10.0 }
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
        diff += if ops1.timestamp == ops2.timestamp { 0.0 } else { 1.0 };
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
        };
        let seq2 = SeqFingerprint {
            class: IsnClass::Incremental { increment: 1 },
            timestamp: false,
            timestamp_rate: None,
        };

        // Different classes = 10.0 diff
        assert!(db.compare_seq(Some(&seq1), Some(&seq2)) > 5.0);

        // Same class = 0.0 diff
        let diff = db.compare_seq(Some(&seq1), Some(&seq1));
        assert_eq!(diff, 0.0);
    }
}
