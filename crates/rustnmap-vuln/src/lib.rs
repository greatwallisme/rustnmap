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

//! Vulnerability intelligence for `RustNmap`.
//!
//! This crate provides CVE/CPE correlation, EPSS scoring, and CISA KEV marking
//! for vulnerability assessment and prioritization.
//!
//! # Features
//!
//! - **CVE/CPE Correlation**: Match CPE strings to known CVEs
//! - **EPSS Scoring**: Exploit Prediction Scoring System integration
//! - **CISA KEV**: Known Exploited Vulnerabilities catalog
//! - **Multiple Modes**: Offline, online, and hybrid operation
//!
//! # Example
//!
//! ```no_run
//! use rustnmap_vuln::VulnClient;
//! use std::path::Path;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create offline client
//! let client = VulnClient::offline_async(Path::new("/var/lib/rustnmap/vuln.db")).await?;
//!
//! // Query vulnerabilities for a CPE
//! let vulns = client.query_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").await?;
//!
//! // Process vulnerabilities
//! for vuln in vulns {
//!     let _ = format!("CVE: {} (CVSS: {}, EPSS: {}, KEV: {})",
//!         vuln.cve_id, vuln.cvss_v3, vuln.epss_score, vuln.is_kev);
//! }
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod cpe;
pub mod cve;
pub mod database;
pub mod epss;
pub mod error;
pub mod kev;
pub mod models;

pub use client::VulnClient;
pub use database::VulnDatabase;
pub use error::{Result, VulnError};
pub use models::VulnInfo;
