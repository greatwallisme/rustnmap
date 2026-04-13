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

//! Routes module

use axum::{
    routing::{delete, get, post},
    Router,
};

use crate::server::ApiState;

/// Create API router with all routes
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        // Health check (no auth required)
        .route("/api/v1/health", get(crate::handlers::health_check))
        // Scan management routes
        .route("/api/v1/scans", post(crate::handlers::create_scan))
        .route("/api/v1/scans", get(crate::handlers::list_scans))
        .route("/api/v1/scans/:id", get(crate::handlers::get_scan))
        .route(
            "/api/v1/scans/:id/results",
            get(crate::handlers::get_scan_results),
        )
        .route("/api/v1/scans/:id", delete(crate::handlers::cancel_scan))
        // SSE streaming
        .route("/api/v1/scans/:id/stream", get(crate::sse::scan_stream))
        // Apply authentication middleware to all routes except health
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::auth::auth_middleware,
        ))
        .with_state(state)
}
