//! NSE engine error types.
//!
//! This module defines all error types that can occur during NSE script
//! loading, parsing, and execution.

use thiserror::Error;

/// Result type alias for NSE operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the NSE engine.
#[derive(Error, Debug)]
pub enum Error {
    /// Error loading a script file.
    #[error("failed to load script '{0}': {1}")]
    ScriptLoadError(String, #[source] std::io::Error),

    /// Error parsing script metadata.
    #[error("failed to parse script metadata in '{0}': {1}")]
    MetadataParseError(String, String),

    /// Script has no rule function.
    #[error("script '{0}' has no hostrule or portrule")]
    NoRuleError(String),

    /// Script has no action function.
    #[error("script '{0}' has no action function")]
    NoActionError(String),

    /// Lua runtime error.
    #[error("lua runtime error in '{script}': {message}")]
    LuaError {
        /// Script ID where the error occurred.
        script: String,
        /// Error message from Lua.
        message: String,
    },

    /// Script execution timeout.
    #[error("script '{0}' timed out after {1:?}")]
    Timeout(String, std::time::Duration),

    /// Script exceeded memory limit.
    #[error("script '{0}' exceeded memory limit of {1} bytes")]
    MemoryLimitExceeded(String, usize),

    /// Circular dependency detected.
    #[error("circular dependency detected: {0}")]
    CircularDependency(String),

    /// Missing dependency.
    #[error("missing required library '{0}' for script '{1}'")]
    MissingDependency(String, String),

    /// Invalid script category.
    #[error("invalid script category '{0}' in '{1}'")]
    InvalidCategory(String, String),

    /// Incompatible NSE version.
    #[error("script '{script}' requires NSE version {required}, but we have {current}")]
    IncompatibleVersion {
        /// Script ID.
        script: String,
        /// Required version.
        required: String,
        /// Current version.
        current: String,
    },

    /// Socket error.
    #[error("socket error: {0}")]
    SocketError(#[from] std::io::Error),

    /// Network error.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Registry error.
    #[error("registry error: {0}")]
    RegistryError(String),

    /// Database error.
    #[error("database error: {0}")]
    DatabaseError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

impl Error {
    /// Create a Lua error with context.
    #[must_use]
    pub fn lua(script: impl Into<String>, message: impl Into<String>) -> Self {
        Self::LuaError {
            script: script.into(),
            message: message.into(),
        }
    }

    /// Create a timeout error.
    #[must_use]
    pub fn timeout(script: impl Into<String>, duration: std::time::Duration) -> Self {
        Self::Timeout(script.into(), duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::lua("test-script", "test error");
        assert_eq!(
            err.to_string(),
            "lua runtime error in 'test-script': test error"
        );
    }

    #[test]
    fn test_timeout_error() {
        let err = Error::timeout("test-script", std::time::Duration::from_secs(5));
        assert_eq!(err.to_string(), "script 'test-script' timed out after 5s");
    }
}
