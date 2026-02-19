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
//! use rustnmap_vuln::{VulnClient, VulnDatabase};
//! use std::path::Path;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create offline client
//! let client = VulnClient::offline(Path::new("/var/lib/rustnmap/vuln.db"))?;
//!
//! // Query vulnerabilities for a CPE
//! let vulns = client.query_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")?;
//!
//! for vuln in vulns {
//!     println!("CVE: {} (CVSS: {}, EPSS: {})", vuln.cve_id, vuln.cvss_v3, vuln.epss_score);
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
