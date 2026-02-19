//! Health check handler

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::time::Instant;

use crate::{error::ApiResult, HealthResponse};

static START_TIME: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

/// Handler for GET /api/v1/health
///
/// # Errors
///
/// Returns `ApiError` if the health check fails.
pub async fn health_check(
    State(state): State<crate::server::ApiState>,
) -> ApiResult<(StatusCode, Json<HealthResponse>)> {
    let uptime = START_TIME.elapsed().as_secs();

    // Get scan counts
    let active_scans = state.scan_manager.active_count();
    let queued_scans = state.scan_manager.queued_count();

    let response = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        active_scans,
        queued_scans,
    };

    Ok((StatusCode::OK, Json(response)))
}
