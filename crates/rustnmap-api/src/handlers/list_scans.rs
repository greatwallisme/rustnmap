//! List scans handler

use axum::extract::Query;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{error::ApiResult, ScanProgress, ScanStatus};

/// Query parameters for list scans
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListScansQuery {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanSummaryItem>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummaryItem {
    pub id: String,
    pub status: ScanStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub targets: Vec<String>,
    pub progress: ScanProgress,
}

/// Handler for GET /api/v1/scans
///
/// # Errors
///
/// Returns `ApiError` if the request fails or scan manager encounters an error.
pub async fn list_scans(
    State(state): State<crate::server::ApiState>,
    Query(query): Query<ListScansQuery>,
) -> ApiResult<Json<crate::ApiResponse<ListScansResponse>>> {
    let limit = query.limit.unwrap_or(20);
    let offset = query.offset.unwrap_or(0);

    // Get all scans from manager
    let all_scans = state.scan_manager.list_scans();

    // Filter by status if provided
    let filtered: Vec<_> = if let Some(status_filter) = &query.status {
        all_scans
            .into_iter()
            .filter(|s| s.status.to_string() == *status_filter)
            .collect()
    } else {
        all_scans
    };

    let total = filtered.len();

    // Apply pagination
    let paginated: Vec<_> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|s| ScanSummaryItem {
            id: s.id,
            status: s.status,
            created_at: s.created_at,
            targets: s.targets,
            progress: s.progress,
        })
        .collect();

    let response = ListScansResponse {
        scans: paginated,
        total,
        limit,
        offset,
    };

    Ok(Json(crate::ApiResponse::success(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_scans_query_default() {
        let query = ListScansQuery::default();
        assert!(query.status.is_none());
        assert!(query.limit.is_none());
        assert!(query.offset.is_none());
    }

    #[test]
    fn test_list_scans_query_deserialize() {
        let query: ListScansQuery =
            serde_urlencoded::from_str("status=running&limit=10&offset=5").unwrap();
        assert_eq!(query.status, Some("running".to_string()));
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(5));
    }

    #[test]
    fn test_list_scans_query_partial() {
        let query: ListScansQuery = serde_urlencoded::from_str("limit=50").unwrap();
        assert!(query.status.is_none());
        assert_eq!(query.limit, Some(50));
        assert!(query.offset.is_none());
    }

    #[test]
    fn test_scan_summary_item_serialization() {
        let item = ScanSummaryItem {
            id: "scan_001".to_string(),
            status: ScanStatus::Running,
            created_at: chrono::Utc::now(),
            targets: vec!["192.168.1.1".to_string()],
            progress: ScanProgress {
                total_hosts: 10,
                completed_hosts: 5,
                percentage: 50.0,
                current_phase: Some("port_scanning".to_string()),
                pps: Some(1000),
                eta_seconds: Some(30),
            },
        };

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("scan_001"));
        assert!(json.contains("running"));
        assert!(json.contains("port_scanning"));
    }

    #[test]
    fn test_list_scans_response_serialization() {
        let response = ListScansResponse {
            scans: vec![],
            total: 0,
            limit: 20,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"scans\":[]"));
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"limit\":20"));
        assert!(json.contains("\"offset\":0"));
    }

    #[test]
    fn test_list_scans_response_with_items() {
        let item = ScanSummaryItem {
            id: "scan_001".to_string(),
            status: ScanStatus::Completed,
            created_at: chrono::Utc::now(),
            targets: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            progress: ScanProgress {
                total_hosts: 2,
                completed_hosts: 2,
                percentage: 100.0,
                current_phase: None,
                pps: None,
                eta_seconds: None,
            },
        };

        let response = ListScansResponse {
            scans: vec![item],
            total: 1,
            limit: 10,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("scan_001"));
        assert!(json.contains("completed"));
        assert!(json.contains("10.0.0.1"));
        assert!(json.contains("100.0"));
    }
}
