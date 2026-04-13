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

    /// Script execution error.
    #[error("script execution error in '{script_id}': {message}")]
    ExecutionError {
        /// Script ID where the error occurred.
        script_id: String,
        /// Error message.
        message: String,
    },

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

    /// Lua library error.
    #[error("lua error: {0}")]
    LuaLibError(String),
}

impl From<mlua::Error> for Error {
    fn from(err: mlua::Error) -> Self {
        Self::LuaLibError(err.to_string())
    }
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
