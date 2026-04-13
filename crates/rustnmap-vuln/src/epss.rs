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
    pub const fn new() -> Self {
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
    pub async fn get_score(db: &VulnDatabase, cve_id: &str) -> Result<Option<EpssRecord>> {
        db.get_epss(cve_id).await
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
    pub async fn get_score_or_default(db: &VulnDatabase, cve_id: &str) -> Result<f32> {
        Ok(Self::get_score(db, cve_id)
            .await?
            .map_or(0.0, |r| r.epss_score))
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
    pub async fn is_above_threshold(
        db: &VulnDatabase,
        cve_id: &str,
        threshold: f32,
    ) -> Result<bool> {
        let score = Self::get_score_or_default(db, cve_id).await?;
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

    #[tokio::test]
    async fn test_epss_engine_get_score() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

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
        db.insert_cve(&cve).await.unwrap();

        let epss = EpssRecord {
            cve_id: "CVE-2024-1234".to_string(),
            epss_score: 0.85,
            percentile: 0.95,
            date: "2024-01-15".to_string(),
        };
        db.insert_epss(&epss).await.unwrap();

        let result = db.get_epss("CVE-2024-1234").await.unwrap().unwrap();
        assert!((result.epss_score - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn test_epss_engine_not_found() {
        let db = VulnDatabase::open_in_memory().await.unwrap();
        let result = db.get_epss("CVE-2024-9999").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_epss_above_threshold() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

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
        db.insert_cve(&cve).await.unwrap();

        let epss = EpssRecord {
            cve_id: "CVE-2024-1234".to_string(),
            epss_score: 0.85,
            percentile: 0.95,
            date: "2024-01-15".to_string(),
        };
        db.insert_epss(&epss).await.unwrap();

        assert!(EpssEngine::is_above_threshold(&db, "CVE-2024-1234", 0.5)
            .await
            .unwrap());
        assert!(!EpssEngine::is_above_threshold(&db, "CVE-2024-1234", 0.9)
            .await
            .unwrap());
    }
}
