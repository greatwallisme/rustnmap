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
) -> ApiResult<(
    axum::http::StatusCode,
    Json<crate::ApiResponse<CancelScanResponse>>,
)> {
    // Cancel the scan
    state.scan_manager.cancel_scan(&scan_id)?;

    let response = CancelScanResponse {
        id: scan_id,
        status: "cancelled".to_string(),
        message: "Scan cancelled by user".to_string(),
    };

    Ok((
        axum::http::StatusCode::OK,
        Json(crate::ApiResponse::success(response)),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelScanResponse {
    pub id: String,
    pub status: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancel_scan_response_serialization() {
        let response = CancelScanResponse {
            id: "scan_001".to_string(),
            status: "cancelled".to_string(),
            message: "Scan cancelled by user".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("scan_001"));
        assert!(json.contains("cancelled"));
        assert!(json.contains("Scan cancelled by user"));
    }

    #[test]
    fn test_cancel_scan_response_deserialization() {
        let json = r#"{"id":"scan_002","status":"cancelled","message":"User requested"}"#;
        let response: CancelScanResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.id, "scan_002");
        assert_eq!(response.status, "cancelled");
        assert_eq!(response.message, "User requested");
    }

    #[test]
    fn test_cancel_scan_response_clone() {
        let response = CancelScanResponse {
            id: "scan_001".to_string(),
            status: "cancelled".to_string(),
            message: "Test".to_string(),
        };
        let cloned = response.clone();
        assert_eq!(cloned.id, response.id);
        assert_eq!(cloned.status, response.status);
        assert_eq!(cloned.message, response.message);
    }

    #[test]
    fn test_cancel_scan_response_debug() {
        let response = CancelScanResponse {
            id: "scan_001".to_string(),
            status: "cancelled".to_string(),
            message: "Test".to_string(),
        };
        let debug_str = format!("{response:?}");
        assert!(debug_str.contains("CancelScanResponse"));
        assert!(debug_str.contains("scan_001"));
    }
}
