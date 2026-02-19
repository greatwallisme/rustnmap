//! EPSS (Exploit Prediction Scoring System) integration.
//!
//! This module provides EPSS score lookup and management.

use crate::database::VulnDatabase;
use crate::error::Result;
use crate::models::EpssRecord;

/// EPSS scoring utilities.
#[derive(Debug, Clone)]
pub struct EpssEngine;

impl EpssEngine {
    /// Create a new EPSS engine.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Get EPSS score for a CVE from the database.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_score(db: &VulnDatabase, cve_id: &str) -> Result<Option<EpssRecord>> {
        db.get_epss(cve_id)
    }

    /// Get EPSS score with default fallback.
    ///
    /// If no score is found, returns 0.0.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn get_score_or_default(db: &VulnDatabase, cve_id: &str) -> Result<f32> {
        Ok(Self::get_score(db, cve_id)?.map_or(0.0, |r| r.epss_score))
    }

    /// Check if EPSS score is above a threshold.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    /// * `threshold` - Score threshold (0.0 - 1.0).
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub fn is_above_threshold(db: &VulnDatabase, cve_id: &str, threshold: f32) -> Result<bool> {
        let score = Self::get_score_or_default(db, cve_id)?;
        Ok(score >= threshold)
    }
}

impl Default for EpssEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CveEntry;
    use chrono::Utc;

    #[test]
    fn test_epss_engine_get_score() {
        let db = VulnDatabase::open_in_memory().unwrap();

        // Insert CVE first (foreign key requirement)
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test vulnerability".to_string(),
            cvss_v3_base: Some(9.8),
            cvss_v3_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).unwrap();

        let epss = EpssRecord {
            cve_id: "CVE-2024-1234".to_string(),
            epss_score: 0.85,
            percentile: 0.95,
            date: "2024-01-15".to_string(),
        };
        db.insert_epss(&epss).unwrap();

        let result = EpssEngine::get_score(&db, "CVE-2024-1234")
            .unwrap()
            .unwrap();
        assert!((result.epss_score - 0.85).abs() < f32::EPSILON);
    }

    #[test]
    fn test_epss_engine_not_found() {
        let db = VulnDatabase::open_in_memory().unwrap();
        let result = EpssEngine::get_score(&db, "CVE-2024-9999").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_epss_above_threshold() {
        let db = VulnDatabase::open_in_memory().unwrap();

        // Insert CVE first
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test".to_string(),
            cvss_v3_base: Some(9.8),
            cvss_v3_vector: None,
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).unwrap();

        let epss = EpssRecord {
            cve_id: "CVE-2024-1234".to_string(),
            epss_score: 0.85,
            percentile: 0.95,
            date: "2024-01-15".to_string(),
        };
        db.insert_epss(&epss).unwrap();

        assert!(EpssEngine::is_above_threshold(&db, "CVE-2024-1234", 0.5).unwrap());
        assert!(!EpssEngine::is_above_threshold(&db, "CVE-2024-1234", 0.9).unwrap());
    }
}
