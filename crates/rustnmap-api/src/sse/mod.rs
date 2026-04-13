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

//! SSE (Server-Sent Events) streaming

use axum::extract::Path;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use std::{convert::Infallible, time::Duration};

use crate::error::{ApiError, ApiResult};

/// Maximum time to wait for a scan to reach terminal state (30 minutes).
const SSE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Handler for GET /api/v1/scans/{id}/stream
///
/// # Errors
///
/// Returns `ApiError::ScanNotFound` if the scan ID does not exist.
pub async fn scan_stream(
    State(state): State<crate::server::ApiState>,
    Path(scan_id): Path<String>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Check if scan exists
    let _task = state
        .scan_manager
        .get_scan_summary(&scan_id)
        .ok_or_else(|| ApiError::ScanNotFound(scan_id.clone()))?;

    // Create SSE stream with timeout
    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let deadline = tokio::time::Instant::now() + SSE_TIMEOUT;

        loop {
            // Check timeout
            if tokio::time::Instant::now() >= deadline {
                let timeout_event = serde_json::json!({
                    "type": "timeout",
                    "scan_id": scan_id,
                    "message": "SSE stream timed out waiting for scan completion"
                });
                yield Ok(Event::default().event("timeout").data(timeout_event.to_string()));
                break;
            }

            interval.tick().await;

            // Get current scan status
            if let Some(task) = state.scan_manager.get_scan_summary(&scan_id).clone() {
                let progress = serde_json::json!({
                    "type": "progress",
                    "scan_id": scan_id,
                    "status": task.status.to_string(),
                    "completed_hosts": task.progress.completed_hosts,
                    "total_hosts": task.progress.total_hosts,
                    "percentage": task.progress.percentage,
                });

                yield Ok(Event::default().data(progress.to_string()));

                // Check if scan is complete
                if matches!(task.status, crate::ScanStatus::Completed | crate::ScanStatus::Cancelled | crate::ScanStatus::Failed) {
                    let done = serde_json::json!({
                        "type": "done",
                        "scan_id": scan_id,
                        "status": task.status.to_string(),
                    });

                    yield Ok(Event::default().event("done").data(done.to_string()));
                    break;
                }
            } else {
                // Scan no longer exists
                break;
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(3))
            .text("keep-alive"),
    ))
}

use axum::extract::State;
