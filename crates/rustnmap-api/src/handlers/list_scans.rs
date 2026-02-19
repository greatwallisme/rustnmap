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
