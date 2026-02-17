// rustnmap-scan-management
// Copyright (C) 2026  greatwallisme

//! Error types for scan management.

use thiserror::Error;

/// Result type alias for scan management operations.
pub type Result<T> = std::result::Result<T, ScanManagementError>;

/// Scan management error types.
#[derive(Debug, Error)]
pub enum ScanManagementError {
    /// Database operation failed.
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Serialization failed.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YAML parsing failed.
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// I/O operation failed.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Scan not found.
    #[error("Scan not found: {0}")]
    ScanNotFound(String),

    /// Invalid scan status.
    #[error("Invalid scan status: {0}")]
    InvalidStatus(String),

    /// Profile validation failed.
    #[error("Profile validation failed: {0}")]
    ProfileValidation(String),

    /// Profile not found.
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    /// Diff operation requires two scans.
    #[error("Diff requires two scans, got {0}")]
    DiffRequiresTwoScans(usize),
}
