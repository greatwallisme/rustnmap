//! Create scan handler

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

/// Handler for POST /api/v1/scans
///
/// # Errors
///
/// Returns an error if the request is invalid or the scan cannot be created.
pub async fn create_scan(
    State(state): State<crate::server::ApiState>,
    Json(request): Json<crate::CreateScanRequest>,
) -> ApiResult<(StatusCode, Json<crate::ApiResponse<CreateScanResponse>>)> {
    // Validate targets
    if request.targets.is_empty() {
        return Err(ApiError::InvalidRequest("No targets specified".to_string()));
    }

    // Create scan task
    let scan_id = format!("scan_{}", Uuid::new_v4().as_simple());

    // Submit scan to manager
    state
        .scan_manager
        .create_scan(&scan_id, request.targets.clone(), request.scan_type.clone())
        .map_err(|e| ApiError::InternalError(e.into()))?;

    let response = CreateScanResponse {
        id: scan_id.clone(),
        status: crate::ScanStatus::Queued,
        created_at: chrono::Utc::now(),
        targets: request.targets,
        progress: crate::ScanProgress {
            total_hosts: 0,
            completed_hosts: 0,
            percentage: 0.0,
            current_phase: None,
            pps: None,
            eta_seconds: None,
        },
    };

    Ok((
        StatusCode::CREATED,
        Json(crate::ApiResponse::success(response)),
    ))
}

/// Create scan response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateScanResponse {
    pub id: String,
    pub status: crate::ScanStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub targets: Vec<String>,
    pub progress: crate::ScanProgress,
}
