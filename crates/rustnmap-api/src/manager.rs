//! Scan task manager for in-memory scan orchestration

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;

use crate::config::ApiConfig;
use crate::error::{ApiError, ApiResult};
use crate::{ScanProgress, ScanStatus};

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
    #[allow(dead_code, reason = "Config field reserved for future use")]
    config: ApiConfig,
}

impl ScanManager {
    /// Create a new scan manager
    #[must_use]
    pub fn new(config: ApiConfig) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
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
}

impl Default for ScanManager {
    fn default() -> Self {
        Self::new(ApiConfig::default())
    }
}
