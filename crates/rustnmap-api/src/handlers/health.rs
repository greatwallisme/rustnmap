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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_default() {
        let response = HealthResponse::default();
        assert_eq!(response.status, "healthy");
        assert_eq!(response.active_scans, 0);
        assert_eq!(response.queued_scans, 0);
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            uptime_seconds: 3600,
            active_scans: 5,
            queued_scans: 2,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("3600"));
        assert!(json.contains('5'));
        assert!(json.contains('2'));
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{"status":"degraded","version":"2.0.0","uptime_seconds":100,"active_scans":3,"queued_scans":7}"#;
        let response: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "degraded");
        assert_eq!(response.version, "2.0.0");
        assert_eq!(response.uptime_seconds, 100);
        assert_eq!(response.active_scans, 3);
        assert_eq!(response.queued_scans, 7);
    }

    #[test]
    fn test_start_time_initialized() {
        // Force START_TIME initialization
        let start = *START_TIME;
        // Sleep briefly to ensure time passes
        std::thread::sleep(std::time::Duration::from_millis(10));
        let now = Instant::now();
        // Start time should be before now
        assert!(start < now);
    }
}
