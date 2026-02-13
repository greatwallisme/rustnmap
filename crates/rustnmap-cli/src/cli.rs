// rustnmap-cli
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

//! Minimal CLI implementation for RustNmap.
//!
//! This will be expanded with full scanning functionality in
//! subsequent commits. For now, it provides argument parsing
//! and basic validation.

use rustnmap_common::Result;
use tracing::{error, info};

use crate::args::Args;

/// Runs the main RustNmap scan workflow.
///
/// # Errors
///
/// Returns an error if the scan fails to complete.
pub async fn run_scan(args: Args) -> Result<()> {
    // Setup logging
    setup_logging(&args);

    info!("RustNmap v{} starting...", env!("CARGO_PKG_VERSION"));

    // Validate arguments and show scan configuration
    if args.targets.is_empty() {
        error!("No targets specified");
        std::process::exit(1);
    }

    info!("Targets: {:?}", args.targets);
    info!("Scan type: {:?}", args.scan_type());
    info!("Timing level: {:?}", args.timing);

    // TODO: Full scan implementation pending
    // This includes:
    // - Target parsing and expansion
    // - Host discovery
    // - Port scanning with actual scanners
    // - Service detection
    // - OS detection
    // - NSE script execution
    // - Output formatting and file writing

    Ok(())
}

/// Sets up tracing based on verbosity and debug levels.
fn setup_logging(args: &Args) {
    let filter_level = if args.debug > 0 {
        match args.debug {
            1 => "debug",
            2 => "debug",
            _ => "trace",
        }
    } else if args.verbose > 0 {
        match args.verbose {
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    } else if args.quiet {
        "warn"
    } else {
        "warn"
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rustnmap", filter_level));

    match env_filter.add_directive("rustnmap_cli=info") {
        Ok(_) => {},
        Err(e) => {
            tracing::warn!("Failed to set log directive: {e}");
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}
