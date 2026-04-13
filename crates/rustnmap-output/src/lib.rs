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

//! Output formatters for `RustNmap` network scanner.
//!
//! This crate provides multiple output format implementations compatible with Nmap:
//! - Normal format (human-readable text output)
//! - XML format (machine-readable, for tools like Ndiff)
//! - JSON format (structured data output)
//! - Grepable format (simple line-based output)
//! # Example
//!
//! ```no_run
//! use rustnmap_output::{OutputManager, NormalFormatter, ScanResult};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manager = OutputManager::new();
//! manager.add_formatter(Box::new(NormalFormatter::new()));
//! manager.add_file_output(PathBuf::from("scan.nmap"));
//!
//! let scan_result = ScanResult::default();
//! manager.output_scan_result(&scan_result)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod formatter;
pub mod models;
pub mod writer;
pub mod xml_parser;

pub use error::{OutputError, Result};
pub use formatter::{
    GrepableFormatter, JsonFormatter, MarkdownFormatter, NdjsonFormatter, NormalFormatter,
    OutputFormatter, ScriptKiddieFormatter, XmlFormatter,
};
pub use models::{
    HostResult, MacAddress, OsMatch, PortResult, Protocol, ScanMetadata, ScanResult,
    ScanStatistics, ScriptResult, ServiceInfo,
};
pub use writer::OutputManager;
pub use xml_parser::parse_nmap_xml;
