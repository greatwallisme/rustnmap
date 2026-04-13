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

//! Scan task manager for in-memory scan orchestration

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;

use crate::config::ApiConfig;
use crate::error::{ApiError, ApiResult};
use crate::{ScanProgress, ScanResultsResponse, ScanStatus};

/// In-memory scan task
#[derive(Debug, Clone)]
pub struct ScanTask {
    pub id: String,
    pub status: ScanStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub targets: Vec<String>,
    pub scan_type: String,
    pub progress: ScanProgress,
}

impl ScanTask {
    #[must_use]
    pub fn new(id: String, targets: Vec<String>, scan_type: String) -> Self {
        Self {
            id,
            status: ScanStatus::Queued,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            targets,
            scan_type,
            progress: ScanProgress {
                total_hosts: 0,
                completed_hosts: 0,
                percentage: 0.0,
                current_phase: None,
                pps: None,
                eta_seconds: None,
            },
        }
    }
}

/// Scan task manager
#[derive(Debug)]
pub struct ScanManager {
    tasks: Arc<DashMap<String, ScanTask>>,
    results: Arc<DashMap<String, ScanResultsResponse>>,
    config: ApiConfig,
}

impl ScanManager {
    /// Create a new scan manager
    #[must_use]
    pub fn new(config: ApiConfig) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            results: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Create a scan task
    ///
    /// # Errors
    ///
    /// Returns `ApiError::ScanAlreadyExists` if a scan with the given ID already exists.
    pub fn create_scan(&self, id: &str, targets: Vec<String>, scan_type: String) -> ApiResult<()> {
        if self.tasks.contains_key(id) {
            return Err(ApiError::ScanAlreadyExists(id.to_string()));
        }

        let task = ScanTask::new(id.to_string(), targets, scan_type);
        self.tasks.insert(id.to_string(), task);
        Ok(())
    }

    /// Get scan summary
    #[must_use]
    pub fn get_scan_summary(&self, id: &str) -> Option<ScanTask> {
        self.tasks.get(id).map(|r| r.clone())
    }

    #[allow(
        clippy::missing_errors_doc,
        reason = "Internal API, errors are self-explanatory"
    )]
    /// Update scan status
    pub fn update_status(&self, id: &str, status: ScanStatus) -> ApiResult<()> {
        let mut task = self
            .tasks
            .get_mut(id)
            .ok_or_else(|| ApiError::ScanNotFound(id.to_string()))?;
        task.status = status;
        if matches!(task.status, ScanStatus::Running) && task.started_at.is_none() {
            task.started_at = Some(Utc::now());
        }
        if matches!(
            task.status,
            ScanStatus::Completed | ScanStatus::Cancelled | ScanStatus::Failed
        ) {
            task.completed_at = Some(Utc::now());
        }
        Ok(())
    }

    #[allow(
        clippy::missing_errors_doc,
        reason = "Internal API, errors are self-explanatory"
    )]
    /// Update scan progress
    pub fn update_progress(&self, id: &str, progress: ScanProgress) -> ApiResult<()> {
        let mut task = self
            .tasks
            .get_mut(id)
            .ok_or_else(|| ApiError::ScanNotFound(id.to_string()))?;
        task.progress = progress;
        Ok(())
    }

    /// Cancel a scan
    ///
    /// # Errors
    ///
    /// Returns `ApiError::ScanNotFound` if no scan with the given ID exists.
    pub fn cancel_scan(&self, id: &str) -> ApiResult<()> {
        self.update_status(id, ScanStatus::Cancelled)
    }

    /// List all scans
    #[must_use]
    pub fn list_scans(&self) -> Vec<ScanTask> {
        self.tasks.iter().map(|r| r.clone()).collect()
    }

    /// Get active scan count
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|r| matches!(r.status, ScanStatus::Running))
            .count()
    }

    /// Get queued scan count
    #[must_use]
    pub fn queued_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|r| matches!(r.status, ScanStatus::Queued))
            .count()
    }

    /// Check if a new scan can be started based on max concurrent limit.
    /// Counts both queued and running scans against the limit.
    #[must_use]
    pub fn can_start_scan(&self) -> bool {
        let active_and_queued = self
            .tasks
            .iter()
            .filter(|r| matches!(r.status, ScanStatus::Queued | ScanStatus::Running))
            .count();
        active_and_queued < self.config.max_concurrent_scans
    }

    /// Validate an API key against the configured keys.
    #[must_use]
    pub fn validate_api_key(&self, key: &str) -> bool {
        self.config.is_valid_key(key)
    }

    /// Get a reference to the API configuration.
    #[must_use]
    pub const fn config(&self) -> &ApiConfig {
        &self.config
    }

    /// Check if there are available scan slots.
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.config
            .max_concurrent_scans
            .saturating_sub(self.active_count())
    }

    /// Get the maximum concurrent scans limit.
    #[must_use]
    pub fn max_concurrent_scans(&self) -> usize {
        self.config.max_concurrent_scans
    }

    /// Check if result retention is enabled.
    #[must_use]
    pub fn is_sse_enabled(&self) -> bool {
        self.config.enable_sse
    }

    /// Get the result retention duration.
    #[must_use]
    pub fn result_retention(&self) -> std::time::Duration {
        self.config.result_retention
    }

    /// Create a scan if under concurrency limit.
    ///
    /// # Errors
    ///
    /// Returns `ApiError::ScanLimitReached` if the maximum concurrent scans limit is reached.
    /// Returns `ApiError::ScanAlreadyExists` if a scan with the given ID already exists.
    pub fn create_scan_if_allowed(
        &self,
        id: &str,
        targets: Vec<String>,
        scan_type: String,
    ) -> ApiResult<()> {
        if !self.can_start_scan() {
            return Err(ApiError::ScanLimitReached(self.config.max_concurrent_scans));
        }
        self.create_scan(id, targets, scan_type)
    }

    /// Get scan results
    ///
    /// Returns the complete scan results if available.
    #[must_use]
    pub fn get_scan_results(&self, id: &str) -> Option<ScanResultsResponse> {
        self.results.get(id).map(|r| r.clone())
    }

    /// Store scan results
    ///
    /// # Errors
    ///
    /// Returns `ApiError::ScanNotFound` if no scan with the given ID exists.
    pub fn store_results(&self, id: &str, results: ScanResultsResponse) -> ApiResult<()> {
        if !self.tasks.contains_key(id) {
            return Err(ApiError::ScanNotFound(id.to_string()));
        }
        self.results.insert(id.to_string(), results);
        Ok(())
    }

    /// Check if results are available for a scan
    #[must_use]
    pub fn has_results(&self, id: &str) -> bool {
        self.results.contains_key(id)
    }
}

impl Default for ScanManager {
    fn default() -> Self {
        Self::new(ApiConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> ScanManager {
        let config = ApiConfig::new()
            .with_api_keys(vec!["test-api-key".to_string()])
            .with_max_concurrent_scans(3);
        ScanManager::new(config)
    }

    // ==================== create_scan tests ====================

    #[test]
    fn test_create_scan_success() {
        let manager = create_test_manager();
        let result = manager.create_scan(
            "scan_001",
            vec!["192.168.1.1".to_string()],
            "syn".to_string(),
        );
        result.unwrap();

        let task = manager.get_scan_summary("scan_001");
        assert!(task.is_some());
        let task = task.unwrap();
        assert_eq!(task.id, "scan_001");
        assert_eq!(task.status, ScanStatus::Queued);
        assert_eq!(task.targets, vec!["192.168.1.1"]);
        assert_eq!(task.scan_type, "syn");
    }

    #[test]
    fn test_create_scan_duplicate_id() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        let result = manager.create_scan(
            "scan_001",
            vec!["192.168.1.2".to_string()],
            "connect".to_string(),
        );
        assert!(result.is_err());
        if let ApiError::ScanAlreadyExists(id) = result.unwrap_err() {
            assert_eq!(id, "scan_001");
        } else {
            panic!("Expected ScanAlreadyExists error");
        }
    }

    // ==================== update_status tests ====================

    #[test]
    fn test_update_status_to_running() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        let result = manager.update_status("scan_001", ScanStatus::Running);
        result.unwrap();

        let task = manager.get_scan_summary("scan_001").unwrap();
        assert_eq!(task.status, ScanStatus::Running);
        assert!(task.started_at.is_some());
    }

    #[test]
    fn test_update_status_to_completed() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .update_status("scan_001", ScanStatus::Running)
            .unwrap();

        let result = manager.update_status("scan_001", ScanStatus::Completed);
        result.unwrap();

        let task = manager.get_scan_summary("scan_001").unwrap();
        assert_eq!(task.status, ScanStatus::Completed);
        assert!(task.completed_at.is_some());
    }

    #[test]
    fn test_update_status_nonexistent_scan() {
        let manager = create_test_manager();
        let result = manager.update_status("nonexistent", ScanStatus::Running);
        assert!(result.is_err());
        if let ApiError::ScanNotFound(id) = result.unwrap_err() {
            assert_eq!(id, "nonexistent");
        } else {
            panic!("Expected ScanNotFound error");
        }
    }

    // ==================== update_progress tests ====================

    #[test]
    fn test_update_progress() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        let progress = ScanProgress {
            total_hosts: 10,
            completed_hosts: 5,
            percentage: 50.0,
            current_phase: Some("port_scanning".to_string()),
            pps: Some(1000),
            eta_seconds: Some(30),
        };

        let result = manager.update_progress("scan_001", progress.clone());
        result.unwrap();

        let task = manager.get_scan_summary("scan_001").unwrap();
        assert_eq!(task.progress.total_hosts, 10);
        assert_eq!(task.progress.completed_hosts, 5);
        assert!((task.progress.percentage - 50.0).abs() < f64::EPSILON);
    }

    // ==================== cancel_scan tests ====================

    #[test]
    fn test_cancel_scan() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        let result = manager.cancel_scan("scan_001");
        result.unwrap();

        let task = manager.get_scan_summary("scan_001").unwrap();
        assert_eq!(task.status, ScanStatus::Cancelled);
        assert!(task.completed_at.is_some());
    }

    #[test]
    fn test_cancel_scan_nonexistent() {
        let manager = create_test_manager();
        let result = manager.cancel_scan("nonexistent");
        assert!(result.is_err());
    }

    // ==================== list_scans tests ====================

    #[test]
    fn test_list_scans_empty() {
        let manager = create_test_manager();
        let scans = manager.list_scans();
        assert!(scans.is_empty());
    }

    #[test]
    fn test_list_scans_multiple() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .create_scan(
                "scan_002",
                vec!["192.168.1.2".to_string()],
                "udp".to_string(),
            )
            .unwrap();
        manager
            .update_status("scan_001", ScanStatus::Running)
            .unwrap();

        let scans = manager.list_scans();
        assert_eq!(scans.len(), 2);
    }

    // ==================== active_count/queued_count tests ====================

    #[test]
    fn test_active_count() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .create_scan(
                "scan_002",
                vec!["192.168.1.2".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .update_status("scan_001", ScanStatus::Running)
            .unwrap();

        assert_eq!(manager.active_count(), 1);
        assert_eq!(manager.queued_count(), 1);
    }

    // ==================== can_start_scan tests ====================

    #[test]
    fn test_can_start_scan_under_limit() {
        let manager = create_test_manager(); // max 3
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .update_status("scan_001", ScanStatus::Running)
            .unwrap();

        assert!(manager.can_start_scan());
    }

    #[test]
    fn test_can_start_scan_at_limit() {
        let manager = create_test_manager(); // max 3
        for i in 0..3 {
            let id = format!("scan_{i:03}");
            manager
                .create_scan(&id, vec!["192.168.1.1".to_string()], "syn".to_string())
                .unwrap();
            manager.update_status(&id, ScanStatus::Running).unwrap();
        }

        assert!(!manager.can_start_scan());
    }

    // ==================== create_scan_if_allowed tests ====================

    #[test]
    fn test_create_scan_if_allowed_under_limit() {
        let manager = create_test_manager();
        let result = manager.create_scan_if_allowed(
            "scan_001",
            vec!["192.168.1.1".to_string()],
            "syn".to_string(),
        );
        result.unwrap();
    }

    #[test]
    fn test_create_scan_if_allowed_at_limit() {
        let manager = create_test_manager(); // max 3
        for i in 0..3 {
            let id = format!("scan_{i:03}");
            manager
                .create_scan(&id, vec!["192.168.1.1".to_string()], "syn".to_string())
                .unwrap();
            manager.update_status(&id, ScanStatus::Running).unwrap();
        }

        let result = manager.create_scan_if_allowed(
            "scan_003",
            vec!["192.168.1.1".to_string()],
            "syn".to_string(),
        );
        assert!(result.is_err());
        if let ApiError::ScanLimitReached(max) = result.unwrap_err() {
            assert_eq!(max, 3);
        } else {
            panic!("Expected ScanLimitReached error");
        }
    }

    // ==================== results storage tests ====================

    #[test]
    fn test_store_and_get_results() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        let results = ScanResultsResponse {
            scan_id: "scan_001".to_string(),
            status: ScanStatus::Completed,
            completed_at: Some(Utc::now()),
            hosts: vec![],
            statistics: rustnmap_output::models::ScanStatistics::default(),
        };

        let store_result = manager.store_results("scan_001", results.clone());
        store_result.unwrap();

        let retrieved = manager.get_scan_results("scan_001");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.scan_id, "scan_001");
        assert_eq!(retrieved.status, ScanStatus::Completed);
    }

    #[test]
    fn test_store_results_nonexistent_scan() {
        let manager = create_test_manager();

        let results = ScanResultsResponse {
            scan_id: "nonexistent".to_string(),
            status: ScanStatus::Completed,
            completed_at: Some(Utc::now()),
            hosts: vec![],
            statistics: rustnmap_output::models::ScanStatistics::default(),
        };

        let store_result = manager.store_results("nonexistent", results);
        assert!(store_result.is_err());
        if let ApiError::ScanNotFound(id) = store_result.unwrap_err() {
            assert_eq!(id, "nonexistent");
        } else {
            panic!("Expected ScanNotFound error");
        }
    }

    #[test]
    fn test_has_results() {
        let manager = create_test_manager();
        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();

        assert!(!manager.has_results("scan_001"));

        let results = ScanResultsResponse {
            scan_id: "scan_001".to_string(),
            status: ScanStatus::Completed,
            completed_at: Some(Utc::now()),
            hosts: vec![],
            statistics: rustnmap_output::models::ScanStatistics::default(),
        };
        manager.store_results("scan_001", results).unwrap();

        assert!(manager.has_results("scan_001"));
    }

    // ==================== api key validation tests ====================

    #[test]
    fn test_validate_api_key_valid() {
        let manager = create_test_manager();
        assert!(manager.validate_api_key("test-api-key"));
    }

    #[test]
    fn test_validate_api_key_invalid() {
        let manager = create_test_manager();
        assert!(!manager.validate_api_key("wrong-key"));
    }

    // ==================== available_slots tests ====================

    #[test]
    fn test_available_slots() {
        let manager = create_test_manager(); // max 3
        assert_eq!(manager.available_slots(), 3);

        manager
            .create_scan(
                "scan_001",
                vec!["192.168.1.1".to_string()],
                "syn".to_string(),
            )
            .unwrap();
        manager
            .update_status("scan_001", ScanStatus::Running)
            .unwrap();

        assert_eq!(manager.available_slots(), 2);
    }
}
