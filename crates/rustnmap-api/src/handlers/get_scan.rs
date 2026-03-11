//! Get scan handler

use axum::extract::{Path, State};

use crate::{error::ApiResult, ScanDetail};

/// Handler for GET /api/v1/scans/{id}
///
/// # Errors
///
/// Returns an error if the scan is not found.
pub async fn get_scan(
    State(state): State<crate::server::ApiState>,
    Path(scan_id): Path<String>,
) -> ApiResult<axum::Json<crate::ApiResponse<ScanDetail>>> {
    // Get scan status from manager
    let task = state
        .scan_manager
        .get_scan_summary(&scan_id)
        .ok_or_else(|| crate::error::ApiError::ScanNotFound(scan_id.clone()))?;

    let detail = ScanDetail {
        id: scan_id.clone(),
        status: task.status,
        created_at: task.created_at,
        started_at: task.started_at,
        completed_at: task.completed_at,
        targets: task.targets,
        scan_type: task.scan_type,
        progress: task.progress,
    };

    Ok(axum::Json(crate::ApiResponse::success(detail)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiResponse, ScanProgress, ScanStatus};
    use chrono::Utc;

    fn create_test_detail() -> ScanDetail {
        ScanDetail {
            id: "scan_test_001".to_string(),
            status: ScanStatus::Running,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: None,
            targets: vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
            scan_type: "syn".to_string(),
            progress: ScanProgress {
                total_hosts: 2,
                completed_hosts: 1,
                percentage: 50.0,
                current_phase: Some("port_scanning".to_string()),
                pps: Some(1000),
                eta_seconds: Some(30),
            },
        }
    }

    #[test]
    fn test_scan_detail_serialization() {
        let detail = create_test_detail();
        let json = serde_json::to_string(&detail).unwrap();

        assert!(json.contains("scan_test_001"));
        assert!(json.contains("running"));
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("syn"));
        assert!(json.contains("port_scanning"));
        assert!(json.contains("1000"));
        assert!(json.contains("50.0"));
    }

    #[test]
    fn test_scan_detail_deserialization() {
        let json = r#"{
            "id": "scan_002",
            "status": "completed",
            "created_at": "2024-01-01T00:00:00Z",
            "started_at": "2024-01-01T00:00:01Z",
            "completed_at": "2024-01-01T00:00:10Z",
            "targets": ["10.0.0.1"],
            "scan_type": "connect",
            "progress": {
                "total_hosts": 1,
                "completed_hosts": 1,
                "percentage": 100.0
            }
        }"#;

        let detail: ScanDetail = serde_json::from_str(json).unwrap();
        assert_eq!(detail.id, "scan_002");
        assert_eq!(detail.status, ScanStatus::Completed);
        assert_eq!(detail.targets, vec!["10.0.0.1"]);
        assert_eq!(detail.scan_type, "connect");
        assert!((detail.progress.percentage - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_api_response_with_scan_detail() {
        let detail = create_test_detail();
        let response = ApiResponse::success(detail);

        assert!(response.success);
        assert!(response.data.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_scan_progress_default() {
        let progress = ScanProgress {
            total_hosts: 0,
            completed_hosts: 0,
            percentage: 0.0,
            current_phase: None,
            pps: None,
            eta_seconds: None,
        };

        let json = serde_json::to_string(&progress).unwrap();
        assert!(json.contains("total_hosts"));
        assert!(json.contains("completed_hosts"));
        // Optional fields should not appear when None
        assert!(!json.contains("current_phase"));
        assert!(!json.contains("pps"));
        assert!(!json.contains("eta_seconds"));
    }

    #[test]
    fn test_scan_status_display() {
        assert_eq!(ScanStatus::Queued.to_string(), "queued");
        assert_eq!(ScanStatus::Running.to_string(), "running");
        assert_eq!(ScanStatus::Completed.to_string(), "completed");
        assert_eq!(ScanStatus::Cancelled.to_string(), "cancelled");
        assert_eq!(ScanStatus::Failed.to_string(), "failed");
    }
}
