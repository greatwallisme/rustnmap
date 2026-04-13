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

//! SDK error types

/// Scan error types
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),

    #[error("Scan timeout: {0:?}")]
    Timeout(std::time::Duration),

    #[error("Scan cancelled: {0}")]
    Cancelled(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),

    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Formatting error: {0}")]
    FormatError(#[from] std::fmt::Error),
}

/// Scan result type alias
pub type ScanResult<T> = Result<T, ScanError>;
