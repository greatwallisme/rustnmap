//! Error types for the core orchestrator.
//!
//! This module defines errors that can occur during scan orchestration,
//! including configuration errors, scheduling errors, and pipeline failures.

use std::fmt;

/// Result type alias for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Core error type for scan orchestration failures.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Configuration error.
    #[error("configuration error: {message}")]
    Config {
        /// Error message describing the configuration issue.
        message: String,
    },

    /// Target parsing or resolution error.
    #[error("target error: {0}")]
    Target(#[from] rustnmap_common::error::TargetError),

    /// Network-related error.
    #[error("network error: {0}")]
    Network(#[from] rustnmap_common::error::NetworkError),

    /// Packet processing error.
    #[error("packet error: {0}")]
    Packet(#[from] rustnmap_common::error::PacketError),

    /// Scanning error.
    #[error("scan error: {0}")]
    Scan(String),

    /// Scheduler error.
    #[error("scheduler error: {message}")]
    Scheduler {
        /// Error message.
        message: String,
    },

    /// State management error.
    #[error("state error: {message}")]
    State {
        /// Error message.
        message: String,
    },

    /// I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Output formatting error.
    #[error("output error: {0}")]
    Output(String),

    /// NSE script execution error.
    #[error("nse error: {0}")]
    Nse(String),

    /// Fingerprint database error.
    #[error("fingerprint error: {0}")]
    Fingerprint(String),

    /// Timeout error.
    #[error("timeout after {duration:?} waiting for {operation}")]
    Timeout {
        /// The operation that timed out.
        operation: String,
        /// The duration that elapsed.
        duration: std::time::Duration,
    },

    /// Pipeline execution error.
    #[error("pipeline error in phase {phase}: {message}")]
    Pipeline {
        /// The phase that failed.
        phase: String,
        /// Error message.
        message: String,
    },

    /// Session initialization error.
    #[error("session initialization error: {message}")]
    SessionInit {
        /// Error message.
        message: String,
    },
}

impl CoreError {
    /// Creates a new configuration error.
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Creates a new scheduler error.
    #[must_use]
    pub fn scheduler(message: impl Into<String>) -> Self {
        Self::Scheduler {
            message: message.into(),
        }
    }

    /// Creates a new state error.
    #[must_use]
    pub fn state(message: impl Into<String>) -> Self {
        Self::State {
            message: message.into(),
        }
    }

    /// Creates a new scan error.
    #[must_use]
    pub fn scan(message: impl Into<String>) -> Self {
        Self::Scan(message.into())
    }

    /// Creates a new output error.
    #[must_use]
    pub fn output(message: impl Into<String>) -> Self {
        Self::Output(message.into())
    }

    /// Creates a new NSE error.
    #[must_use]
    pub fn nse(message: impl Into<String>) -> Self {
        Self::Nse(message.into())
    }

    /// Creates a new fingerprint error.
    #[must_use]
    pub fn fingerprint(message: impl Into<String>) -> Self {
        Self::Fingerprint(message.into())
    }

    /// Creates a new timeout error.
    #[must_use]
    pub fn timeout(operation: impl Into<String>, duration: std::time::Duration) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration,
        }
    }

    /// Creates a new pipeline error.
    #[must_use]
    pub fn pipeline(phase: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Pipeline {
            phase: phase.into(),
            message: message.into(),
        }
    }

    /// Creates a new session initialization error.
    #[must_use]
    pub fn session_init(message: impl Into<String>) -> Self {
        Self::SessionInit {
            message: message.into(),
        }
    }
}

/// Error type for task scheduling failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    /// Task queue is full.
    QueueFull,
    /// Task was cancelled.
    Cancelled,
    /// Task timeout.
    Timeout,
    /// Invalid task priority.
    InvalidPriority,
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => write!(f, "task queue is full"),
            Self::Cancelled => write!(f, "task was cancelled"),
            Self::Timeout => write!(f, "task timed out"),
            Self::InvalidPriority => write!(f, "invalid task priority"),
        }
    }
}

impl std::error::Error for SchedulerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error() {
        let err = CoreError::config("invalid port range");
        assert!(err.to_string().contains("invalid port range"));
    }

    #[test]
    fn test_scheduler_error() {
        let err = CoreError::scheduler("worker thread panicked");
        assert!(err.to_string().contains("worker thread panicked"));
    }

    #[test]
    fn test_timeout_error() {
        let duration = std::time::Duration::from_secs(30);
        let err = CoreError::timeout("host discovery", duration);
        assert!(err.to_string().contains("host discovery"));
        assert!(err.to_string().contains("30s"));
    }

    #[test]
    fn test_pipeline_error() {
        let err = CoreError::pipeline("port_scan", "connection refused");
        assert!(err.to_string().contains("port_scan"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_scheduler_error_enum() {
        assert_eq!(SchedulerError::QueueFull.to_string(), "task queue is full");
        assert_eq!(SchedulerError::Cancelled.to_string(), "task was cancelled");
    }
}
