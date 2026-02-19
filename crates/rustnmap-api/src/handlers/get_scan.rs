//! Get scan handler

use axum::extract::{Path, State};

use crate::{
    error::ApiResult,
    ScanDetail,
};

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
