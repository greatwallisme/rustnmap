//! Cancel scan handler

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiResult;

/// Handler for DELETE /api/v1/scans/{id}
///
/// # Errors
///
/// Returns an error if the scan is not found or cannot be cancelled.
pub async fn cancel_scan(
    State(state): State<crate::server::ApiState>,
    Path(scan_id): Path<String>,
) -> ApiResult<(axum::http::StatusCode, Json<CancelScanResponse>)> {
    // Cancel the scan
    state
        .scan_manager
        .cancel_scan(&scan_id)
        .map_err(|e| crate::error::ApiError::InternalError(e.into()))?;

    let response = CancelScanResponse {
        id: scan_id.clone(),
        status: "cancelled".to_string(),
        message: "Scan cancelled by user".to_string(),
    };

    Ok((axum::http::StatusCode::OK, Json(response)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelScanResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}
