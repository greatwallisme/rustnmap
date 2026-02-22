// rustnmap-output
// Copyright (C) 2026  greatwallisme
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
