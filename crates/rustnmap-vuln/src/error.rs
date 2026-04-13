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

//! Error types for vulnerability intelligence operations.

use thiserror::Error;

/// Result type alias for vulnerability operations.
pub type Result<T> = std::result::Result<T, VulnError>;

/// Vulnerability intelligence error type.
#[derive(Debug, Error)]
pub enum VulnError {
    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(String),

    /// CPE parsing error.
    #[error("CPE parsing error: {0}")]
    Cpe(String),

    /// API error.
    #[error("API error: {message}")]
    Api {
        /// Error message from API.
        message: String,
        /// HTTP status code if available.
        status: Option<u16>,
    },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded, retry after {retry_after} seconds")]
    RateLimit {
        /// Seconds to wait before retry.
        retry_after: u64,
    },

    /// Data not found.
    #[error("data not found: {0}")]
    NotFound(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl VulnError {
    /// Create a database error.
    #[must_use]
    pub fn database(message: impl Into<String>) -> Self {
        Self::Database(message.into())
    }

    /// Create an HTTP error.
    #[must_use]
    pub fn http(message: impl Into<String>) -> Self {
        Self::Http(message.into())
    }

    /// Create a JSON error.
    #[must_use]
    pub fn json(message: impl Into<String>) -> Self {
        Self::Json(message.into())
    }

    /// Create a CPE error.
    #[must_use]
    pub fn cpe(message: impl Into<String>) -> Self {
        Self::Cpe(message.into())
    }

    /// Create an API error.
    #[must_use]
    pub fn api(message: impl Into<String>, status: Option<u16>) -> Self {
        Self::Api {
            message: message.into(),
            status,
        }
    }

    /// Create a configuration error.
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Create a rate limit error.
    #[must_use]
    pub fn rate_limit(retry_after: u64) -> Self {
        Self::RateLimit { retry_after }
    }

    /// Create a not found error.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }
}

impl From<rusqlite::Error> for VulnError {
    fn from(err: rusqlite::Error) -> Self {
        Self::database(err.to_string())
    }
}

impl From<tokio_rusqlite::Error> for VulnError {
    fn from(err: tokio_rusqlite::Error) -> Self {
        Self::database(err.to_string())
    }
}

impl From<serde_json::Error> for VulnError {
    fn from(err: serde_json::Error) -> Self {
        Self::json(err.to_string())
    }
}

impl From<reqwest::Error> for VulnError {
    fn from(err: reqwest::Error) -> Self {
        Self::http(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_error_display() {
        let err = VulnError::database("connection failed");
        assert!(err.to_string().contains("database error"));
        assert!(err.to_string().contains("connection failed"));
    }

    #[test]
    fn test_vuln_error_api() {
        let err = VulnError::api("rate limited", Some(429));
        assert!(err.to_string().contains("API error"));
        assert!(err.to_string().contains("rate limited"));
    }

    #[test]
    fn test_vuln_error_rate_limit() {
        let err = VulnError::rate_limit(60);
        assert!(err.to_string().contains("rate limit exceeded"));
        assert!(err.to_string().contains("60 seconds"));
    }
}
