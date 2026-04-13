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

//! Error types for output formatters.

/// Error type for output operations.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// I/O error occurred while writing output.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error serializing to JSON format.
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// Error serializing to XML format.
    #[error("XML serialization error: {0}")]
    XmlSerialization(#[from] quick_xml::Error),

    /// Error writing to file.
    #[error("Failed to write to file '{path}': {message}")]
    FileWrite { path: String, message: String },

    /// Invalid output format specified.
    #[error("Invalid output format: '{0}'")]
    InvalidFormat(String),

    /// Missing required field for formatting.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Time conversion error.
    #[error("Time conversion error: {0}")]
    TimeConversion(String),

    /// Invalid scan result data.
    #[error("Invalid scan result: {0}")]
    InvalidData(String),
}

impl From<std::string::FromUtf8Error> for OutputError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::InvalidData(err.to_string())
    }
}

/// Result type for output operations.
pub type Result<T> = std::result::Result<T, OutputError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = OutputError::InvalidFormat("json".to_string());
        assert!(err.to_string().contains("json"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let out_err: OutputError = io_err.into();
        assert!(matches!(out_err, OutputError::Io(_)));
    }
}
