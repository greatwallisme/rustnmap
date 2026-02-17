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

// Allow pedantic lints with reasons
#![allow(clippy::missing_errors_doc, reason = "Internal API, errors are self-explanatory")]
#![allow(clippy::missing_panics_doc, reason = "Internal API, panics are not part of public contract")]
#![allow(clippy::must_use_candidate, reason = "Methods are used for side effects in internal flows")]
#![allow(clippy::module_name_repetitions, reason = "Module names are part of public API clarity")]
#![allow(clippy::return_self_not_must_use, reason = "Builder pattern returns self for chaining")]
#![allow(clippy::uninlined_format_args, reason = "Consistent format across codebase")]
#![allow(clippy::manual_range_contains, reason = "Explicit comparison is clearer")]
#![allow(clippy::similar_names, reason = "Variable names follow domain conventions")]
#![allow(clippy::too_many_lines, reason = "Complex report generation requires longer functions")]
#![allow(clippy::cast_possible_wrap, reason = "Statistics values are within i64 range")]
#![allow(clippy::cast_possible_truncation, reason = "Values are validated before casting")]
#![allow(clippy::redundant_closure_for_method_calls, reason = "Explicit closures improve readability")]
#![allow(clippy::unnecessary_cast, reason = "Casts document intent")]
#![allow(clippy::unnecessary_map_or, reason = "map_or is clearer in context")]
#![allow(clippy::unused_self, reason = "Self is required for API consistency")]
#![allow(clippy::items_after_statements, reason = "Helper items defined after use")]
#![allow(clippy::format_push_string, reason = "Pushing formatted strings is standard pattern")]
#![warn(clippy::allow_attributes_without_reason)]

mod database;
mod diff;
mod error;
mod history;
mod models;
mod profile;

pub use database::{ScanDatabase, DbConfig};
pub use diff::{ScanDiff, DiffFormat, DiffReport, HostChanges, PortChanges, VulnerabilityChanges};
pub use error::{ScanManagementError, Result};
pub use history::{ScanHistory, ScanFilter};
pub use models::{ScanSummary, ScanStatus, StoredScan, StoredHost, StoredPort, StoredVulnerability};
pub use profile::{ScanProfile, ProfileManager, OutputConfig};
