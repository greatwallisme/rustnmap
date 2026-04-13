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

//! Get scan results handler

use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::error::{ApiError, ApiResult};
use crate::server::ApiState;
use crate::{ApiResponse, ScanResultsResponse, ScanStatus};

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
) -> ApiResult<(StatusCode, axum::Json<ApiResponse<ScanResultsResponse>>)> {
    // Check if scan exists first
    let task = state
        .scan_manager
        .get_scan_summary(&scan_id)
        .ok_or_else(|| ApiError::ScanNotFound(scan_id.clone()))?;

    // If scan is not yet completed, return 202 Accepted
    if !matches!(
        task.status,
        ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled
    ) {
        return Err(ApiError::ScanPending(format!(
            "Scan '{scan_id}' has status '{}', results not yet available",
            task.status
        )));
    }

    // Get scan results from manager
    let results = state
        .scan_manager
        .get_scan_results(&scan_id)
        .ok_or_else(|| {
            ApiError::ScanFailed(format!(
                "Scan '{scan_id}' completed but results are unavailable"
            ))
        })?;

    Ok((StatusCode::OK, axum::Json(ApiResponse::success(results))))
}
