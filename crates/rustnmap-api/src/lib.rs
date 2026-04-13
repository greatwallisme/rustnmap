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

//! `RustNmap` REST API - HTTP API server for remote scan management
//!
//! This crate provides a `RESTful` API for creating, managing, and monitoring
//! network scan tasks. It supports:
//!
//! - Creating scan tasks via POST /api/v1/scans
//! - Querying scan status via GET /api/v1/scans/{id}
//! - Retrieving scan results via GET /api/v1/scans/{id}/results
//! - Cancelling scans via DELETE /api/v1/scans/{id}
//! - SSE streaming for real-time progress updates
//! - API Key authentication
//!
//! # Example
//!
//! ```rust,no_run
//! use rustnmap_api::{ApiServer, ApiConfig};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = ApiConfig::default();
//!     let server = ApiServer::new(&config)?;
//!
//!     let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//!     server.run(addr).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod error;
pub mod handlers;
pub mod manager;
pub mod middleware;
pub mod routes;
pub mod server;
pub mod sse;

pub use config::ApiConfig;
pub use error::{ApiError, ApiResult};
pub use manager::ScanManager;
pub use server::ApiServer;
pub use server::ApiState;

use serde::{Deserialize, Serialize};

/// API response wrapper for consistent response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Create a success response
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_scans: usize,
    pub queued_scans: usize,
}

impl Default for HealthResponse {
    fn default() -> Self {
        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 0,
            active_scans: 0,
            queued_scans: 0,
        }
    }
}

/// Scan status enum matching scan-management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

impl From<rustnmap_scan_management::ScanStatus> for ScanStatus {
    fn from(status: rustnmap_scan_management::ScanStatus) -> Self {
        match status {
            rustnmap_scan_management::ScanStatus::Running => Self::Running,
            rustnmap_scan_management::ScanStatus::Completed => Self::Completed,
            rustnmap_scan_management::ScanStatus::Failed => Self::Failed,
            rustnmap_scan_management::ScanStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total_hosts: usize,
    pub completed_hosts: usize,
    pub percentage: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,
}

/// Create scan request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub targets: Vec<String>,
    #[serde(default = "default_scan_type")]
    pub scan_type: String,
    #[serde(default)]
    pub options: ScanOptions,
}

fn default_scan_type() -> String {
    "syn".to_string()
}

/// Scan options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanOptions {
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default)]
    pub service_detection: bool,
    #[serde(default)]
    pub os_detection: bool,
    #[serde(default)]
    pub vulnerability_scan: bool,
    #[serde(default)]
    pub timing: Option<String>,
}

/// Scan summary for list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub id: String,
    pub status: ScanStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub targets: Vec<String>,
    pub progress: ScanProgress,
}

/// Scan detail response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetail {
    pub id: String,
    pub status: ScanStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub targets: Vec<String>,
    pub scan_type: String,
    pub progress: ScanProgress,
}

/// Scan results response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultsResponse {
    pub scan_id: String,
    pub status: ScanStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub hosts: Vec<rustnmap_output::models::HostResult>,
    pub statistics: rustnmap_output::models::ScanStatistics,
}
