//! Error types for fingerprinting operations.

use std::{io, path::PathBuf};

/// Errors that can occur during service and OS fingerprinting.
#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    /// I/O error reading fingerprint database.
    #[error("I/O error reading fingerprint database: {path}")]
    Io {
        /// Database file path that failed to read.
        path: PathBuf,

        /// Underlying I/O error.
        source: io::Error,
    },

    /// Failed to parse fingerprint database entry.
    #[error("Failed to parse fingerprint database at line {line}")]
    ParseError {
        /// Line number where parsing failed.
        line: usize,

        /// Raw content that failed to parse.
        content: String,
    },

    /// Invalid regular expression in fingerprint pattern.
    #[error("Invalid regex pattern '{pattern}': {reason}")]
    InvalidRegex {
        /// Pattern string that failed to compile.
        pattern: String,

        /// Error reason from regex engine.
        reason: String,
    },

    /// Network error during probe transmission.
    #[error("Network error during probe transmission: {operation}")]
    Network {
        /// Operation that failed.
        operation: String,

        /// Error description.
        reason: String,
    },

    /// Timeout waiting for probe response.
    #[error("Timeout waiting for probe response on {address}:{port}")]
    Timeout {
        /// Target address.
        address: String,

        /// Target port.
        port: u16,
    },

    /// No matching fingerprint found.
    #[error("No matching fingerprint found for probe response")]
    NoMatch,

    /// Invalid probe definition.
    #[error("Invalid probe definition: {reason}")]
    InvalidProbe {
        /// Description of what makes the probe invalid.
        reason: String,
    },

    /// Database not found at specified path.
    #[error("Fingerprint database not found: {path}")]
    DatabaseNotFound {
        /// Path that was not found.
        path: PathBuf,
    },

    /// TLS/SSL error.
    #[error("TLS error: {context}")]
    Tls {
        /// Context of the TLS error.
        context: String,
    },
}

impl From<io::Error> for FingerprintError {
    fn from(err: io::Error) -> Self {
        FingerprintError::Io {
            path: PathBuf::new(),
            source: err,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = FingerprintError::InvalidRegex {
            pattern: r"[\d".to_string(),
            reason: "unclosed bracket".to_string(),
        };
        assert!(err.to_string().contains("Invalid regex pattern"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let fingerprint_err = FingerprintError::from(io_err);
        assert!(matches!(fingerprint_err, FingerprintError::Io { .. }));
    }
}
