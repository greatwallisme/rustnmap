//! Error types for traceroute operations.

use rustnmap_common::Error as CommonError;

/// Errors that can occur during traceroute operations.
#[derive(Debug, thiserror::Error)]
pub enum TracerouteError {
    /// Invalid configuration provided.
    #[error("Invalid configuration: {reason}")]
    InvalidConfig {
        /// Reason for the configuration being invalid.
        reason: String,
    },

    /// Socket creation failed.
    #[error("Failed to create socket: {source}")]
    SocketCreation {
        /// The underlying error.
        source: std::io::Error,
    },

    /// Failed to send probe.
    #[error("Failed to send probe: {source}")]
    SendFailed {
        /// The underlying error.
        source: std::io::Error,
    },

    /// Failed to receive probe response.
    #[error("Failed to receive response: {source}")]
    ReceiveFailed {
        /// The underlying error.
        source: std::io::Error,
    },

    /// Probe timed out.
    #[error("Probe timed out")]
    Timeout,

    /// Permission denied (requires `root`/`CAP_NET_RAW`).
    #[error("Permission denied: traceroute requires CAP_NET_RAW capability")]
    PermissionDenied,

    /// Invalid IP address.
    #[error("Invalid IP address: {address}")]
    InvalidAddress {
        /// The invalid address that was provided.
        address: String,
    },

    /// Network error.
    #[error("Network error: {0}")]
    Network(String),

    /// Other error.
    #[error("Traceroute error: {0}")]
    Other(String),
}

/// Result type for traceroute operations.
pub type Result<T> = std::result::Result<T, TracerouteError>;

impl From<CommonError> for TracerouteError {
    fn from(err: CommonError) -> Self {
        Self::Other(err.to_string())
    }
}

impl From<std::io::Error> for TracerouteError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Network(err.to_string()),
        }
    }
}

impl From<std::num::TryFromIntError> for TracerouteError {
    fn from(err: std::num::TryFromIntError) -> Self {
        Self::Other(format!("Integer conversion error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TracerouteError::InvalidConfig {
            reason: "test".to_string(),
        };
        assert_eq!(format!("{}", err), "Invalid configuration: test");
    }

    #[test]
    fn test_timeout_error() {
        let err = TracerouteError::Timeout;
        assert_eq!(format!("{}", err), "Probe timed out");
    }

    #[test]
    fn test_permission_denied_error() {
        let err = TracerouteError::PermissionDenied;
        assert!(format!("{}", err).contains("Permission denied"));
    }
}
