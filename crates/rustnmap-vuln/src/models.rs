//! Vulnerability data models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Vulnerability information.
///
/// Contains all relevant data about a vulnerability including
/// CVSS score, EPSS probability, and CISA KEV status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInfo {
    /// CVE identifier (e.g., "CVE-2024-1234").
    pub cve_id: String,

    /// CVSS 3.1 base score (0.0 - 10.0).
    pub cvss_v3: f32,

    /// CVSS 3.1 vector string.
    pub cvss_vector: Option<String>,

    /// EPSS exploit probability score (0.0 - 1.0).
    pub epss_score: f32,

    /// EPSS percentile ranking.
    pub epss_percentile: Option<f32>,

    /// Whether this vulnerability is in CISA KEV catalog.
    pub is_kev: bool,

    /// Matching CPE that triggered this vulnerability match.
    pub affected_cpe: String,

    /// Vulnerability description.
    pub description: String,

    /// Publication date.
    pub published_date: DateTime<Utc>,

    /// Last modification date.
    pub modified_date: Option<DateTime<Utc>>,

    /// Reference URLs.
    pub references: Vec<String>,

    /// Vendor name (from KEV data).
    pub vendor_project: Option<String>,

    /// Product name (from KEV data).
    pub product: Option<String>,

    /// CISA required action (from KEV data).
    pub kev_required_action: Option<String>,

    /// CISA due date (from KEV data).
    pub kev_due_date: Option<String>,
}

impl VulnInfo {
    /// Calculate risk priority score (0-100).
    ///
    /// Scoring formula:
    /// - CVSS contribution: `cvss_v3` * 5.0 (max 50 points)
    /// - EPSS contribution: `epss_score` * 30.0 (max 30 points)
    /// - KEV bonus: 20 points if in KEV catalog
    ///
    /// # Returns
    ///
    /// Risk priority score from 0 (lowest) to 100 (highest).
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Score is clamped to 0-100 range, u8 is sufficient"
    )]
    pub fn risk_priority(&self) -> u8 {
        let cvss_weight = self.cvss_v3 * 5.0; // Max 50
        let epss_weight = self.epss_score * 30.0; // Max 30
        let kev_bonus = if self.is_kev { 20.0 } else { 0.0 };

        (cvss_weight + epss_weight + kev_bonus).min(100.0) as u8
    }

    /// Check if this is a critical vulnerability.
    ///
    /// Critical is defined as:
    /// - CVSS >= 9.0, or
    /// - In CISA KEV catalog, or
    /// - Risk priority >= 80
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.cvss_v3 >= 9.0 || self.is_kev || self.risk_priority() >= 80
    }

    /// Check if this is a high severity vulnerability.
    ///
    /// High is defined as CVSS >= 7.0 and < 9.0.
    #[must_use]
    pub fn is_high(&self) -> bool {
        self.cvss_v3 >= 7.0 && self.cvss_v3 < 9.0
    }

    /// Check if this is a medium severity vulnerability.
    ///
    /// Medium is defined as CVSS >= 4.0 and < 7.0.
    #[must_use]
    pub fn is_medium(&self) -> bool {
        self.cvss_v3 >= 4.0 && self.cvss_v3 < 7.0
    }

    /// Get severity label.
    #[must_use]
    pub fn severity(&self) -> &'static str {
        if self.cvss_v3 >= 9.0 {
            "CRITICAL"
        } else if self.cvss_v3 >= 7.0 {
            "HIGH"
        } else if self.cvss_v3 >= 4.0 {
            "MEDIUM"
        } else if self.cvss_v3 > 0.0 {
            "LOW"
        } else {
            "UNKNOWN"
        }
    }
}

/// CVE entry from NVD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    /// CVE identifier.
    pub id: String,

    /// Vulnerability description.
    pub description: String,

    /// CVSS v3 base score.
    pub cvss_v3_base: Option<f32>,

    /// CVSS v3 vector string.
    pub cvss_v3_vector: Option<String>,

    /// Publication date.
    pub published_at: DateTime<Utc>,

    /// Last modified date.
    pub modified_at: Option<DateTime<Utc>>,

    /// Reference URLs.
    pub references: Vec<String>,
}

/// CPE match record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpeMatch {
    /// Associated CVE ID.
    pub cve_id: String,

    /// CPE 2.3 URI.
    pub cpe_23_uri: String,

    /// Version start excluding.
    pub version_start_excluding: Option<String>,

    /// Version end excluding.
    pub version_end_excluding: Option<String>,

    /// Version start including.
    pub version_start_including: Option<String>,

    /// Version end including.
    pub version_end_including: Option<String>,

    /// Whether this is a vulnerable match.
    pub vulnerable: bool,
}

/// EPSS score record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssRecord {
    /// CVE identifier.
    pub cve_id: String,

    /// EPSS score (0.0 - 1.0).
    pub epss_score: f32,

    /// EPSS percentile.
    pub percentile: f32,

    /// Date of score.
    pub date: String,
}

/// KEV catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    /// CVE identifier.
    pub cve_id: String,

    /// Vendor/project name.
    pub vendor_project: String,

    /// Product name.
    pub product: String,

    /// Date added to KEV catalog.
    pub date_added: String,

    /// Required action.
    pub required_action: String,

    /// Due date for remediation.
    pub due_date: String,

    /// Additional notes.
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_vuln() -> VulnInfo {
        VulnInfo {
            cve_id: "CVE-2024-1234".to_string(),
            cvss_v3: 9.8,
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            epss_score: 0.85,
            epss_percentile: Some(0.95),
            is_kev: true,
            affected_cpe: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*".to_string(),
            description: "Test vulnerability".to_string(),
            published_date: Utc::now() - Duration::days(30),
            modified_date: Some(Utc::now() - Duration::days(10)),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()],
            vendor_project: Some("Apache".to_string()),
            product: Some("HTTP Server".to_string()),
            kev_required_action: Some("Apply vendor update".to_string()),
            kev_due_date: Some("2024-12-31".to_string()),
        }
    }

    #[test]
    fn test_risk_priority_critical() {
        let vuln = create_test_vuln();
        let priority = vuln.risk_priority();
        assert!(priority >= 80);
    }

    #[test]
    fn test_is_critical() {
        let vuln = create_test_vuln();
        assert!(vuln.is_critical());
    }

    #[test]
    fn test_severity_critical() {
        let vuln = create_test_vuln();
        assert_eq!(vuln.severity(), "CRITICAL");
    }

    #[test]
    fn test_is_high() {
        let mut vuln = create_test_vuln();
        vuln.cvss_v3 = 7.5;
        assert!(vuln.is_high());
        assert_eq!(vuln.severity(), "HIGH");
    }

    #[test]
    fn test_is_medium() {
        let mut vuln = create_test_vuln();
        vuln.cvss_v3 = 5.5;
        assert!(vuln.is_medium());
        assert_eq!(vuln.severity(), "MEDIUM");
    }
}
