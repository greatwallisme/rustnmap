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

//! Scan history management.

use crate::database::ScanDatabase;
use crate::error::Result;
use crate::models::{ScanStatus, ScanSummary, StoredScan};
use chrono::{DateTime, Utc};
use rustnmap_output::models::ScanType;
use rustnmap_output::ScanResult;

/// Scan history manager for querying and managing historical scans.
#[derive(Debug)]
pub struct ScanHistory {
    db: ScanDatabase,
}

impl ScanHistory {
    /// Open or create the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or created.
    pub fn open(db_path: &str) -> Result<Self> {
        let config = crate::database::DbConfig {
            path: db_path.to_string(),
            ..Default::default()
        };
        let db = ScanDatabase::open(&config)?;
        Ok(Self { db })
    }

    /// Create from existing database.
    #[must_use]
    pub fn from_database(db: ScanDatabase) -> Self {
        Self { db }
    }

    /// Save scan result to history.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be saved to the database.
    pub async fn save_scan(
        &self,
        result: &ScanResult,
        target_spec: &str,
        created_by: Option<&str>,
    ) -> Result<String> {
        self.db.save_scan(result, target_spec, created_by).await
    }

    /// List scans with optional filtering.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn list_scans(&self, filter: ScanFilter) -> Result<Vec<ScanSummary>> {
        self.db.list_scans(&filter).await
    }

    /// Get scan details by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_scan(&self, id: &str) -> Result<Option<StoredScan>> {
        self.db.get_scan(id).await
    }

    /// Get target's scan history.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_target_history(&self, target: &str) -> Result<Vec<ScanSummary>> {
        let filter = ScanFilter {
            target: Some(target.to_string()),
            ..Default::default()
        };
        self.db.list_scans(&filter).await
    }

    /// Delete old scans beyond retention period.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub async fn prune_old_scans(&self, retention_days: u32) -> Result<usize> {
        self.db.prune_old_scans(retention_days).await
    }

    /// Get the most recent scan for a target.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_latest_scan(&self, target: &str) -> Result<Option<StoredScan>> {
        let filter = ScanFilter {
            target: Some(target.to_string()),
            limit: Some(1),
            ..Default::default()
        };
        let summaries = self.db.list_scans(&filter).await?;
        if let Some(summary) = summaries.first() {
            self.db.get_scan(&summary.id).await
        } else {
            Ok(None)
        }
    }

    /// Get scans by status.
    ///
    /// Uses database-level filtering for efficient queries.
    ///
    /// # Errors
    ///
    /// Returns an error if the database query fails.
    pub async fn get_scans_by_status(&self, status: ScanStatus) -> Result<Vec<ScanSummary>> {
        let filter = ScanFilter {
            status: Some(status),
            ..Default::default()
        };
        self.db.list_scans(&filter).await
    }
}

/// Filter for querying scans.
#[derive(Debug, Clone, Default)]
pub struct ScanFilter {
    /// Start of time range.
    pub since: Option<DateTime<Utc>>,
    /// End of time range.
    pub until: Option<DateTime<Utc>>,
    /// Filter by target.
    pub target: Option<String>,
    /// Filter by scan type.
    pub scan_type: Option<ScanType>,
    /// Filter by status.
    pub status: Option<ScanStatus>,
    /// Limit results.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

impl ScanFilter {
    /// Create a new filter with time range.
    #[must_use]
    pub fn with_time_range(since: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        Self {
            since: Some(since),
            until: Some(until),
            ..Default::default()
        }
    }

    /// Create a filter for a specific target.
    #[must_use]
    pub fn for_target(target: &str) -> Self {
        Self {
            target: Some(target.to_string()),
            ..Default::default()
        }
    }

    /// Set the limit.
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_temp_db() -> (ScanHistory, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_scans.db");
        let db_path_str = db_path.to_string_lossy().to_string();
        let history = ScanHistory::open(&db_path_str).unwrap();
        (history, db_path)
    }

    #[test]
    fn test_open_database() {
        let (_history, _db_path) = create_temp_db();
        // Successfully opening the database is enough for this test
    }
}
