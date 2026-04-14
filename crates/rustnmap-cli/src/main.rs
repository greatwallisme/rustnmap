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

//! Main entry point for `RustNmap` CLI.
//!
//! This is the binary entry point that parses command-line arguments
//! and coordinates the scanning workflow using the orchestrator library.

use std::io::Write;

use rustnmap_cli::args::Args;
use rustnmap_common::Result;
use tracing::info;

use rustnmap_cli::cli::run_scan;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse().unwrap_or_else(|e| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Failed to parse arguments: {e}");
        std::process::exit(1);
    });

    // Suggest running `init` if ~/.rustnmap/ does not exist and user
    // is not already running init or a management command.
    if !args.init
        && !args.history
        && !args.if_list
        && !args.list_profiles
        && args.validate_profile.is_none()
        && !args.generate_profile
        && !args.script_updatedb
        && args.script_help.is_none()
    {
        if let Some(home) = dirs::home_dir() {
            if !home.join(".rustnmap").exists() {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "Note: Data directory ~/.rustnmap/ not found. \
                     Run `rustnmap init` to extract embedded data files."
                );
            }
        }
    }

    // Run the scan using the orchestrator library
    let result = run_scan(args).await;

    // Handle result
    match result {
        Ok(()) => {
            info!("Scan completed successfully");
        }
        Err(e) => {
            tracing::error!("Scan failed: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
