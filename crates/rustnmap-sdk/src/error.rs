//! SDK error types

/// Scan error types
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Scan timeout: {0:?}")]
    Timeout(std::time::Duration),

    #[error("Scan cancelled: {0}")]
    Cancelled(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Formatting error: {0}")]
    FormatError(#[from] std::fmt::Error),
}

/// Scan result type alias
pub type ScanResult<T> = Result<T, ScanError>;
