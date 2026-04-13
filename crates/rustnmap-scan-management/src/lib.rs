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

//! Scan management module for `RustNmap` 2.0.
//!
//! Provides scan result persistence, historical queries, result comparison (Diff),
//! and configuration profile management.

mod database;
mod diff;
mod error;
mod history;
mod models;
mod profile;

pub use database::{DbConfig, ScanDatabase};
pub use diff::{DiffFormat, DiffReport, HostChanges, PortChanges, ScanDiff, VulnerabilityChanges};
pub use error::{Result, ScanManagementError};
pub use history::{ScanFilter, ScanHistory};
pub use models::{
    ScanStatus, ScanSummary, StoredHost, StoredPort, StoredScan, StoredVulnerability,
};
pub use profile::{OutputConfig, ProfileManager, ScanProfile};
