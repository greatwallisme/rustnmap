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

//! `RustNmap` SDK - High-level Rust API for network scanning
//!
//! This crate provides a fluent Builder pattern API for programmatically
//! using `RustNmap`'s scanning capabilities in your Rust applications.
//!
//! # Example
//!
//! ```rust,no_run
//! use rustnmap_sdk::{Scanner, ScanOutput};
//! use anyhow::Result;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Create scanner with targets
//!     let scanner = Scanner::new()?.with_targets("192.168.1.1");
//!
//!     // Run a scan
//!     let result = scanner.run().await?;
//!
//!     // Process results
//!     for host in &result.hosts {
//!         let _ = format!("{}: {} open ports", host.ip, host.ports.len());
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod builder;
pub mod error;
pub mod models;
pub mod profile;
pub mod remote;

pub use builder::{Scanner, ScannerBuilder};
pub use error::{ScanError, ScanResult};
pub use models::{HostResult, PortResult, ScanOutput, ScanStatus, ServiceInfo};
pub use profile::ScanProfile;
pub use remote::{ApiConfig, RemoteScanner};
