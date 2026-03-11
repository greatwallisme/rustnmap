//! Get scan results handler

use axum::extract::{Path, State};

use crate::error::{ApiError, ApiResult};
use crate::server::ApiState;
use crate::{ApiResponse, ScanResultsResponse};

/// Handler for GET /api/v1/scans/{id}/results
///
/// Returns the complete scan results including all hosts, ports, and statistics.
///
/// # Errors
///
/// Returns `ApiError::ScanNotFound` if the scan does not exist.
/// Returns `ApiError::ScanFailed` if the scan has not completed successfully.
pub async fn get_scan_results(
    State(state): State<ApiState>,
    Path(scan_id): Path<String>,
) -> ApiResult<axum::Json<ApiResponse<ScanResultsResponse>>> {
    // Get scan results from manager
    let results = state
        .scan_manager
        .get_scan_results(&scan_id)
        .ok_or_else(|| ApiError::ScanNotFound(scan_id.clone()))?;

    Ok(axum::Json(ApiResponse::success(results)))
}
