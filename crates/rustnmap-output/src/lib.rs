// rustnmap-output
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

//! Output formatters for RustNmap network scanner.
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
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut manager = OutputManager::new();
//! manager.add_formatter(Box::new(NormalFormatter::new()));
//! manager.add_file_output(PathBuf::from("scan.nmap"));
//!
//! let scan_result = ScanResult::default();
//! manager.output_scan_result(&scan_result).await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod formatter;
pub mod models;
pub mod writer;

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
