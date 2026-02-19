//! API error types

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// API error types
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Scan not found: {0}")]
    ScanNotFound(String),

    #[error("Scan already exists: {0}")]
    ScanAlreadyExists(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Scan cancelled: {0}")]
    ScanCancelled(String),

    #[error("Scan failed: {0}")]
    ScanFailed(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::ScanNotFound(id) => {
                (StatusCode::NOT_FOUND, format!("Scan not found: {id}"))
            }
            ApiError::ScanAlreadyExists(id) => {
                (StatusCode::CONFLICT, format!("Scan already exists: {id}"))
            }
            ApiError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid request: {msg}"))
            }
            ApiError::AuthenticationFailed(msg) => {
                (StatusCode::UNAUTHORIZED, format!("Authentication failed: {msg}"))
            }
            ApiError::ScanCancelled(id) => {
                (StatusCode::OK, format!("Scan cancelled: {id}"))
            }
            ApiError::ScanFailed(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Scan failed: {msg}")),
            ApiError::InternalError(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Internal error: {err}"))
            }
            ApiError::IoError(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("IO error: {err}"))
            }
        };

        let body = Json(json!({
            "success": false,
            "error": message,
        }));

        (status, body).into_response()
    }
}

/// API result type alias
pub type ApiResult<T> = Result<T, ApiError>;
