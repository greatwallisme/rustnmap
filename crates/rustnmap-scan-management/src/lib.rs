// rustnmap-scan-management
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
