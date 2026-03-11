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
