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

//! CISA KEV (Known Exploited Vulnerabilities) catalog integration.
//!
//! This module provides KEV lookup and management.

use crate::database::VulnDatabase;
use crate::error::Result;
use crate::models::KevEntry;

/// CISA KEV catalog utilities.
#[derive(Debug, Clone)]
pub struct KevEngine;

impl KevEngine {
    /// Create a new KEV engine.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Check if a CVE is in the KEV catalog.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn is_kev(db: &VulnDatabase, cve_id: &str) -> Result<bool> {
        Ok(db.get_kev(cve_id).await?.is_some())
    }

    /// Get KEV entry for a CVE.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_entry(db: &VulnDatabase, cve_id: &str) -> Result<Option<KevEntry>> {
        db.get_kev(cve_id).await
    }

    /// Get KEV required action for a CVE.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_required_action(db: &VulnDatabase, cve_id: &str) -> Result<Option<String>> {
        Ok(db.get_kev(cve_id).await?.map(|k| k.required_action))
    }

    /// Get KEV due date for a CVE.
    ///
    /// # Arguments
    ///
    /// * `db` - Database reference.
    /// * `cve_id` - CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_due_date(db: &VulnDatabase, cve_id: &str) -> Result<Option<String>> {
        Ok(db.get_kev(cve_id).await?.map(|k| k.due_date))
    }
}

impl Default for KevEngine {
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
    async fn test_kev_engine_is_kev() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

        // Insert CVE first (foreign key requirement)
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test".to_string(),
            cvss_v3_base: None,
            cvss_v3_vector: None,
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).await.unwrap();

        let kev = KevEntry {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Apache".to_string(),
            product: "HTTP Server".to_string(),
            date_added: "2024-01-15".to_string(),
            required_action: "Apply update".to_string(),
            due_date: "2024-02-15".to_string(),
            notes: None,
        };
        db.insert_kev(&kev).await.unwrap();

        assert!(KevEngine::is_kev(&db, "CVE-2024-1234").await.unwrap());
        assert!(!KevEngine::is_kev(&db, "CVE-2024-9999").await.unwrap());
    }

    #[tokio::test]
    async fn test_kev_engine_get_entry() {
        let db = VulnDatabase::open_in_memory().await.unwrap();

        // Insert CVE first
        let cve = CveEntry {
            id: "CVE-2024-1234".to_string(),
            description: "Test".to_string(),
            cvss_v3_base: None,
            cvss_v3_vector: None,
            published_at: Utc::now(),
            modified_at: None,
            references: vec![],
        };
        db.insert_cve(&cve).await.unwrap();

        let kev = KevEntry {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Apache".to_string(),
            product: "HTTP Server".to_string(),
            date_added: "2024-01-15".to_string(),
            required_action: "Apply update".to_string(),
            due_date: "2024-02-15".to_string(),
            notes: Some("Critical update".to_string()),
        };
        db.insert_kev(&kev).await.unwrap();

        let entry = KevEngine::get_entry(&db, "CVE-2024-1234")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.vendor_project, "Apache");
        assert_eq!(entry.product, "HTTP Server");
        assert!(entry.notes.is_some());
    }
}
