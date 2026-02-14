//! Error types for `RustNmap`.
//!
//! This module defines the error types used throughout the `RustNmap` project.
//! All errors implement `std::error::Error` and provide context for debugging.

use std::fmt;

// Re-export ScanError from scan module for backward compatibility
pub use crate::scan::ScanError;

/// Result type alias for `RustNmap` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Core error type for `RustNmap`.
///
/// Errors are categorized by component to allow targeted handling in different
/// parts of the system. Each error variant includes relevant context for
/// debugging and user reporting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network-related errors.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    /// Target parsing or resolution errors.
    #[error("target error: {0}")]
    Target(#[from] TargetError),

    /// Packet construction or parsing errors.
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),

    /// I/O operation errors.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration or validation errors.
    #[error("configuration error: {message}")]
    Config {
        /// Error message describing the configuration issue.
        message: String,
    },

    /// Permission-related errors (e.g., missing `CAP_NET_RAW`).
    #[error("permission denied: {operation} requires {required}")]
    Permission {
        /// The operation that was attempted.
        operation: String,
        /// The required permission or capability.
        required: String,
    },

    /// Timeout waiting for a response.
    #[error("timeout after {timeout:?} waiting for {operation}")]
    Timeout {
        /// The operation that timed out.
        operation: String,
        /// The duration that elapsed.
        timeout: std::time::Duration,
    },

    /// Generic error with context.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a configuration error.
    #[must_use]
    pub const fn config(message: String) -> Self {
        Self::Config { message }
    }

    /// Create a permission error.
    #[must_use]
    pub fn permission(operation: impl Into<String>, required: impl Into<String>) -> Self {
        Self::Permission {
            operation: operation.into(),
            required: required.into(),
        }
    }
}

/// Network-specific errors.
#[derive(Debug)]
pub enum NetworkError {
    /// Failed to create raw socket.
    RawSocketCreation {
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Failed to bind to interface.
    BindFailed {
        /// The interface name.
        interface: String,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Failed to set socket option.
    SocketOptionFailed {
        /// The option name.
        option_name: String,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Invalid network interface.
    InvalidInterface {
        /// The interface name.
        name: String,
    },

    /// Packet send failed.
    SendFailed {
        /// Number of bytes attempted.
        attempted: usize,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Packet send error.
    SendError {
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Packet receive failed.
    ReceiveFailed {
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// Packet receive error.
    ReceiveError {
        /// The underlying OS error.
        source: std::io::Error,
    },
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawSocketCreation { .. } => write!(f, "failed to create raw socket"),
            Self::BindFailed { interface, .. } => {
                write!(f, "failed to bind to interface '{interface}'")
            }
            Self::SocketOptionFailed { option_name, .. } => {
                write!(f, "failed to set socket option '{option_name}'")
            }
            Self::InvalidInterface { name } => write!(f, "invalid network interface '{name}'"),
            Self::SendFailed { attempted, .. } => {
                write!(f, "failed to send {attempted} bytes")
            }
            Self::SendError { .. } => write!(f, "failed to send packet"),
            Self::ReceiveFailed { .. } | Self::ReceiveError { .. } => {
                write!(f, "failed to receive packet")
            }
        }
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RawSocketCreation { source }
            | Self::BindFailed { source, .. }
            | Self::SocketOptionFailed { source, .. }
            | Self::SendFailed { source, .. }
            | Self::SendError { source }
            | Self::ReceiveFailed { source }
            | Self::ReceiveError { source } => Some(source),
            Self::InvalidInterface { .. } => None,
        }
    }
}

/// Target parsing and resolution errors.
#[derive(Debug)]
pub enum TargetError {
    /// Invalid IP address format.
    InvalidIpAddress {
        /// The invalid address string.
        address: String,
    },

    /// Invalid CIDR notation.
    InvalidCidr {
        /// The invalid CIDR string.
        cidr: String,
        /// Reason for failure.
        reason: String,
    },

    /// Invalid port range.
    InvalidPortRange {
        /// The start of the range.
        start: u16,
        /// The end of the range.
        end: u16,
    },

    /// Port number out of valid range.
    PortOutOfRange {
        /// The invalid port number.
        port: u16,
    },

    /// Empty target specification.
    EmptySpecification,

    /// Hostname resolution failed.
    ResolutionFailed {
        /// The hostname that failed to resolve.
        hostname: String,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIpAddress { address } => {
                write!(f, "invalid IP address: '{address}'")
            }
            Self::InvalidCidr { cidr, reason } => {
                write!(f, "invalid CIDR '{cidr}': {reason}")
            }
            Self::InvalidPortRange { start, end } => {
                write!(f, "invalid port range: {start}-{end}")
            }
            Self::PortOutOfRange { port } => {
                write!(f, "port {port} out of range (1-65535)")
            }
            Self::EmptySpecification => write!(f, "empty target specification"),
            Self::ResolutionFailed { hostname } => {
                write!(f, "failed to resolve hostname: '{hostname}'")
            }
        }
    }
}

impl std::error::Error for TargetError {}

/// Packet construction and parsing errors.
#[derive(Debug)]
pub enum PacketError {
    /// Packet too small to contain expected header.
    TooShort {
        /// Expected minimum size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// Invalid checksum.
    InvalidChecksum {
        /// Expected checksum.
        expected: u16,
        /// Actual checksum.
        actual: u16,
    },

    /// Unknown protocol.
    UnknownProtocol {
        /// The protocol number.
        number: u8,
    },

    /// Malformed packet data.
    MalformedData {
        /// Description of the malformed portion.
        portion: String,
    },

    /// Buffer too small for packet construction.
    BufferTooSmall {
        /// Required size.
        required: usize,
        /// Available size.
        available: usize,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, actual } => {
                write!(
                    f,
                    "packet too short: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidChecksum { expected, actual } => {
                write!(
                    f,
                    "invalid checksum: expected {expected:#06x}, got {actual:#06x}"
                )
            }
            Self::UnknownProtocol { number } => {
                write!(f, "unknown protocol number: {number}")
            }
            Self::MalformedData { portion } => {
                write!(f, "malformed packet data in {portion}")
            }
            Self::BufferTooSmall {
                required,
                available,
            } => {
                write!(
                    f,
                    "buffer too small: need {required} bytes, have {available}"
                )
            }
        }
    }
}

impl std::error::Error for PacketError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Network(NetworkError::InvalidInterface {
            name: "eth0".to_string(),
        });
        assert_eq!(
            err.to_string(),
            "network error: invalid network interface 'eth0'"
        );
    }

    #[test]
    fn test_config_error() {
        let err = Error::config("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_permission_error() {
        let err = Error::permission("raw socket", "CAP_NET_RAW");
        assert!(err.to_string().contains("raw socket"));
        assert!(err.to_string().contains("CAP_NET_RAW"));
    }
}
