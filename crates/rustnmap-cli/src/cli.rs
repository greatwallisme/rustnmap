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

//! CLI implementation for `RustNmap`.
//!
//! This module provides the main scan execution logic, integrating all
//! `RustNmap` components into a unified command-line interface.

use std::sync::Arc;
use std::{fs::File, io::Write};
use rustnmap_common::Result;
use rustnmap_core::session::ScanType as CoreScanType;
use rustnmap_core::session::{
    DefaultOutputSink, DefaultPacketEngine, FingerprintDatabase, NseRegistry, OutputSink,
    PacketEngine, PortSpec, TargetSet,
};
use rustnmap_core::{ScanConfig, ScanOrchestrator, ScanSession};
use rustnmap_output::formatter::OutputFormatter;
use rustnmap_output::{DatabaseContext, NdjsonFormatter, MarkdownFormatter, JsonFormatter};
use rustnmap_output::models::{HostResult, PortResult, PortState, Protocol, ScanResult, ScanType};
use rustnmap_scan::scanner::TimingTemplate;
use rustnmap_target::{Target, TargetGroup, TargetParser};
use rustnmap_scan_management::{ScanFilter, ScanHistory, ScanProfile};
use tracing::{debug, error, info, warn};
use crate::args::Args;

/// Runs the main `RustNmap` scan workflow.
///
/// # Errors
///
/// Returns an error if the scan fails to complete.
pub async fn run_scan(args: Args) -> Result<()> {
    // Setup logging
    setup_logging(&args);

    info!("RustNmap v{} starting...", env!("CARGO_PKG_VERSION"));

    // Initialize service database with custom data directory
    let datadir = shellexpand::tilde(&args.datadir);
    rustnmap_common::ServiceDatabase::set_data_dir(datadir.as_ref());

    // Validate arguments
    if let Err(e) = args.validate() {
        error!("Argument validation failed: {e}");
        return Err(rustnmap_common::Error::Other(format!(
            "Invalid arguments: {e}"
        )));
    }

    // Handle scan management commands first
    if args.history {
        return handle_history_command(&args).await;
    }

    if args.list_profiles {
        return handle_list_profiles_command(&args);
    }

    if let Some(ref profile_path) = args.validate_profile {
        return handle_validate_profile_command(profile_path);
    }

    if args.generate_profile {
        handle_generate_profile_command();
        return Ok(());
    }

    if let Some(ref diff_files) = args.diff {
        return handle_diff_command(&args, diff_files).await;
    }

    // Handle profile-based scanning
    if let Some(ref profile_path) = args.profile {
        return handle_profile_scan(&args, profile_path).await;
    }

    // Normal scan flow
    run_normal_scan(&args).await
}

/// Handle --history command
async fn handle_history_command(args: &Args) -> Result<()> {
    let db_path = shellexpand::tilde(&args.db_path);
    let history = ScanHistory::open(&db_path).map_err(|e| {
        rustnmap_common::Error::Other(format!("Failed to open history database: {e}"))
    })?;

    // Build filter
    let mut filter = ScanFilter::default();

    if let Some(ref since) = args.since {
        // Parse since date with multiple format support
        filter.since = parse_date_flexible(since);
    }

    if let Some(ref until) = args.until {
        // Parse until date with multiple format support
        filter.until = parse_date_flexible(until).map(|dt| {
            // Set to end of day for until dates
            dt.date_naive()
                .and_hms_opt(23, 59, 59)
                .map(|t| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(t, chrono::Utc))
                .unwrap_or(dt)
        });
    }

    if let Some(ref target) = args.target {
        filter.target = Some(target.clone());
    }

    if let Some(ref scan_type_str) = args.scan_type_filter {
        filter.scan_type = Some(match scan_type_str.as_str() {
            "connect" | "TcpConnect" => ScanType::TcpConnect,
            "udp" | "Udp" => ScanType::Udp,
            "fin" | "TcpFin" => ScanType::TcpFin,
            "null" | "TcpNull" => ScanType::TcpNull,
            "xmas" | "TcpXmas" => ScanType::TcpXmas,
            "maimon" | "TcpMaimon" => ScanType::TcpMaimon,
            _ => ScanType::TcpSyn,
        });
    }

    if let Some(limit) = args.limit {
        filter.limit = Some(limit);
    }

    // Show specific scan details if --scan-id provided
    if let Some(ref scan_id) = args.scan_id {
        let scan_opt = history.get_scan(scan_id).await.map_err(|e| {
            rustnmap_common::Error::Other(format!("Failed to get scan details: {e}"))
        })?;
        if let Some(scan) = scan_opt {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "Scan ID: {}", scan.id)?;
            writeln!(stdout, "  Target: {}", scan.target_spec)?;
            writeln!(stdout, "  Type: {:?}", scan.scan_type)?;
            writeln!(stdout, "  Status: {:?}", scan.status)?;
            writeln!(stdout, "  Started: {}", scan.started_at)?;
            writeln!(stdout, "  Completed: {:?}", scan.completed_at)?;
        }
        return Ok(());
    }

    // List scans
    let scans = history
        .list_scans(filter)
        .await
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to list scans: {e}")))?;

    if scans.is_empty() {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "No scans found in history database.")?;
        return Ok(());
    }

    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "Scan History:")?;
        writeln!(stdout, "{:-<80}", "")?;
        for scan in scans {
            writeln!(
                stdout,
                "ID: {:<36}  Status: {:<10}  Type: {:<8}",
                scan.id,
                format!("{:?}", scan.status),
                format!("{:?}", scan.scan_type)
            )?;
            writeln!(stdout, "  Target: {}", scan.target_spec)?;
            writeln!(
                stdout,
                "  Started: {}  Hosts: {}",
                scan.started_at, scan.hosts_count
            )?;
            writeln!(stdout, "{:-<80}", "")?;
        }
    }

    Ok(())
}

/// Handle --list-profiles command
fn handle_list_profiles_command(args: &Args) -> Result<()> {
    use rustnmap_scan_management::ProfileManager;

    let db_path = shellexpand::tilde(&args.db_path);
    let db_dir = std::path::Path::new(db_path.as_ref())
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let profiles_dir = db_dir.join("profiles");

    let manager = ProfileManager::from_directory(profiles_dir.to_str().unwrap_or("."))
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to load profiles: {e}")))?;

    let profiles = manager.list_profiles();

    {
        let mut stdout = std::io::stdout().lock();
        if profiles.is_empty() {
            writeln!(
                stdout,
                "No profiles found. Use --generate-profile to create one."
            )?;
            return Ok(());
        }

        writeln!(stdout, "Available Profiles:")?;
        writeln!(stdout, "{:-<60}", "")?;
        for profile in profiles {
            writeln!(stdout, "  {profile}")?;
        }
    }

    Ok(())
}

/// Handle --validate-profile command
fn handle_validate_profile_command(profile_path: &std::path::Path) -> Result<()> {
    let profile = ScanProfile::from_file(profile_path)
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to load profile: {e}")))?;

    profile
        .validate()
        .map_err(|e| rustnmap_common::Error::Other(format!("Profile validation failed: {e}")))?;

    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "Profile '{}' is valid.", profile.name)?;
        writeln!(stdout, "  Description: {:?}", profile.description)?;
        writeln!(stdout, "  Targets: {} specified", profile.targets.len())?;
        writeln!(stdout, "  Scan Type: {:?}", profile.scan.scan_type)?;
        writeln!(stdout, "  Ports: {:?}", profile.scan.ports)?;
    }

    Ok(())
}

/// Handle --generate-profile command
fn handle_generate_profile_command() {
    let profile_template = r#"# RustNmap Scan Profile
name: "custom-scan"
description: "Custom scan profile template"
targets: []  # Specify targets here or via command line
exclude: []  # Targets to exclude
scan:
  type: "syn"           # syn, connect, udp, fin, null, xmas, maimon
  ports: "1-1000"       # Port range or comma-separated list
  service_detection: true
  os_detection: true
  scripts: ["default"]  # NSE script categories
  timing: "T3"          # T0 (slowest) to T5 (fastest)
output:
  formats: ["json", "normal"]  # Output formats
  directory: "./reports"       # Output directory
  save_to_history: true
"#;

    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{profile_template}");
}

/// Handle --diff command
async fn handle_diff_command(args: &Args, diff_files: &[String]) -> Result<()> {
    use rustnmap_scan_management::{DiffFormat, ScanDiff};

    // If --from-history is specified, load from database
    if args.from_history.is_some() {
        let db_path = shellexpand::tilde(&args.db_path);

        let history = ScanHistory::open(&db_path).map_err(|e| {
            rustnmap_common::Error::Other(format!("Failed to open history database: {e}"))
        })?;

        let scan_ids = args.from_history.as_ref().unwrap();

        // Use from_history method which handles the conversion
        let diff = ScanDiff::from_history(&history, &scan_ids[0], &scan_ids[1])
            .await
            .map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to create diff from history: {e}"))
            })?;

        let format = match args.diff_format.as_str() {
            "markdown" | "md" => DiffFormat::Markdown,
            "json" => DiffFormat::Json,
            "html" => DiffFormat::Html,
            _ => DiffFormat::Text,
        };

        let report = diff.generate_report(format);
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{report}")?;
        return Ok(());
    }

    // Load from files
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(
            stdout,
            "Comparing scans from files: {} vs {}",
            diff_files[0], diff_files[1]
        )?;
    }

    // Detect format from file extension
    let (before_result, after_result) =
        if diff_files[0].ends_with(".json") && diff_files[1].ends_with(".json") {
            let before_content = std::fs::read_to_string(&diff_files[0]).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to read {}: {e}", diff_files[0]))
            })?;
            let after_content = std::fs::read_to_string(&diff_files[1]).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to read {}: {e}", diff_files[1]))
            })?;

            let before: rustnmap_output::ScanResult = serde_json::from_str(&before_content)
                .map_err(|e| {
                    rustnmap_common::Error::Other(format!("Failed to parse {}: {e}", diff_files[0]))
                })?;
            let after: rustnmap_output::ScanResult =
                serde_json::from_str(&after_content).map_err(|e| {
                    rustnmap_common::Error::Other(format!("Failed to parse {}: {e}", diff_files[1]))
                })?;

            (before, after)
        } else if diff_files[0].ends_with(".xml") && diff_files[1].ends_with(".xml") {
            let before_content = std::fs::read_to_string(&diff_files[0]).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to read {}: {e}", diff_files[0]))
            })?;
            let after_content = std::fs::read_to_string(&diff_files[1]).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to read {}: {e}", diff_files[1]))
            })?;

            let before = rustnmap_output::parse_nmap_xml(&before_content).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to parse {}: {e}", diff_files[0]))
            })?;
            let after = rustnmap_output::parse_nmap_xml(&after_content).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to parse {}: {e}", diff_files[1]))
            })?;

            (before, after)
        } else {
            return Err(rustnmap_common::Error::Other(format!(
                "Unsupported file format. Supported: JSON (.json), XML (.xml). Got: {} and {}",
                diff_files[0], diff_files[1]
            )));
        };

    let diff = ScanDiff::new(before_result, after_result);

    let format = match args.diff_format.as_str() {
        "markdown" | "md" => DiffFormat::Markdown,
        "json" => DiffFormat::Json,
        "html" => DiffFormat::Html,
        _ => DiffFormat::Text,
    };

    let report = diff.generate_report(format);
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{report}")?;
    }

    Ok(())
}

/// Handle profile-based scanning
async fn handle_profile_scan(args: &Args, profile_path: &std::path::Path) -> Result<()> {
    let profile = ScanProfile::from_file(profile_path)
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to load profile: {e}")))?;

    profile
        .validate()
        .map_err(|e| rustnmap_common::Error::Other(format!("Profile validation failed: {e}")))?;

    info!("Loaded profile: {}", profile.name);

    // Merge profile settings with command-line args
    // Use targets from command line (priority) or profile
    let targets = if args.targets.is_empty() && !profile.targets.is_empty() {
        Ok(parse_targets_from_list(&profile.targets))
    } else {
        parse_targets(args)
    }?;

    // Build scan config from profile
    let config = build_scan_config_from_profile(&profile, args);

    info!("Scan type: {:?}", config.scan_types);
    info!("Timing template: {:?}", config.timing_template);

    // Load fingerprint databases (service and/or OS detection)
    let mut fp_db = FingerprintDatabase::new();
    let datadir = shellexpand::tilde(&args.datadir);
    let db_dir = std::path::PathBuf::from(datadir.as_ref()).join("db");

    // Load service probe database if service detection is enabled
    if config.service_detection {
        let service_db_path = db_dir.join("nmap-service-probes");

        if service_db_path.exists() {
            info!(
                "Loading service probe database from: {}",
                service_db_path.display()
            );
            match rustnmap_fingerprint::ProbeDatabase::load_from_nmap_db(&service_db_path).await {
                Ok(db) => {
                    info!("Service probe database loaded successfully");
                    fp_db.set_service_db(db);
                }
                Err(e) => {
                    warn!("Failed to load service probe database: {e}");
                    warn!("Service detection will be skipped");
                }
            }
        } else {
            warn!(
                "Service probe database not found at: {}",
                service_db_path.display()
            );
            warn!("Service detection will be skipped");
        }
    }

    // Load OS fingerprint database if OS detection is enabled
    if config.os_detection {
        let os_db_path = db_dir.join("nmap-os-db");

        if os_db_path.exists() {
            info!(
                "Loading OS fingerprint database from: {}",
                os_db_path.display()
            );
            match tokio::task::block_in_place(|| {
                rustnmap_fingerprint::FingerprintDatabase::load_from_nmap_db(&os_db_path)
            }) {
                Ok(db) => {
                    info!("OS fingerprint database loaded successfully");
                    fp_db.set_os_db(db);
                }
                Err(e) => {
                    warn!("Failed to load OS fingerprint database: {e}");
                    warn!("OS detection will be skipped");
                }
            }
        } else {
            warn!(
                "OS fingerprint database not found at: {}",
                os_db_path.display()
            );
            warn!("OS detection will be skipped");
        }
    }

    // Load MAC prefix database for vendor lookups
    let mac_db_path = db_dir.join("nmap-mac-prefixes");
    if mac_db_path.exists() {
        info!(
            "Loading MAC prefix database from: {}",
            mac_db_path.display()
        );
        match rustnmap_fingerprint::MacPrefixDatabase::load_from_file(&mac_db_path).await {
            Ok(db) => {
                info!(
                    "MAC prefix database loaded successfully ({} entries)",
                    db.len()
                );
                fp_db.set_mac_db(db);
            }
            Err(e) => {
                warn!("Failed to load MAC prefix database: {e}");
            }
        }
    } else {
        debug!(
            "MAC prefix database not found at: {}",
            mac_db_path.display()
        );
    }

    // Create database context for output
    let mut db_context = DatabaseContext::new();

    // Load service database for port-to-service name mappings
    let services_db_path = db_dir.join("nmap-services");
    if services_db_path.exists() {
        info!(
            "Loading services database from: {}",
            services_db_path.display()
        );
        match rustnmap_fingerprint::ServiceDatabase::load_from_file(&services_db_path).await {
            Ok(db) => {
                info!("Services database loaded successfully");
                db_context.services = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load services database: {e}");
            }
        }
    } else {
        debug!(
            "Services database not found at: {}",
            services_db_path.display()
        );
    }

    // Load protocols database for protocol number-to-name mappings
    let protocols_db_path = db_dir.join("nmap-protocols");
    if protocols_db_path.exists() {
        info!(
            "Loading protocols database from: {}",
            protocols_db_path.display()
        );
        match rustnmap_fingerprint::ProtocolDatabase::load_from_file(&protocols_db_path).await {
            Ok(db) => {
                info!("Protocols database loaded successfully");
                db_context.protocols = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load protocols database: {e}");
            }
        }
    } else {
        debug!(
            "Protocols database not found at: {}",
            protocols_db_path.display()
        );
    }

    // Load RPC database for RPC program number mappings
    let rpc_db_path = db_dir.join("nmap-rpc");
    if rpc_db_path.exists() {
        info!("Loading RPC database from: {}", rpc_db_path.display());
        match rustnmap_fingerprint::RpcDatabase::load_from_file(&rpc_db_path).await {
            Ok(db) => {
                info!("RPC database loaded successfully");
                db_context.rpc = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load RPC database: {e}");
            }
        }
    } else {
        debug!("RPC database not found at: {}", rpc_db_path.display());
    }

    let fingerprint_db = Arc::new(fp_db);

    // Create scan session and run
    let target_set = Arc::new(TargetSet::from_group(targets));
    let packet_engine: Arc<dyn PacketEngine> =
        Arc::new(DefaultPacketEngine::new().map_err(|e| {
            rustnmap_common::Error::Other(format!("Failed to create packet engine: {e}"))
        })?);
    let output_sink: Arc<dyn OutputSink> = Arc::new(DefaultOutputSink::new());
    let nse_registry = Arc::new(NseRegistry::new());

    let session = ScanSession::with_dependencies(
        config,
        target_set,
        packet_engine,
        output_sink,
        fingerprint_db,
        nse_registry,
    );

    let session = Arc::new(session);

    let orchestrator = ScanOrchestrator::new(session);

    info!("Starting scan...");
    let scan_result = orchestrator
        .run()
        .await
        .map_err(|e| rustnmap_common::Error::Other(format!("Scan failed: {e}")))?;

    // Build command line string for output
    let command_line = build_command_line_string(args);

    // Output results
    output_results(args, &scan_result, &command_line, &db_context)?;

    info!("Scan completed successfully");
    Ok(())
}

/// Parse date string with multiple format support.
///
/// Supports the following formats:
/// - `YYYY-MM-DD` (ISO date)
/// - `YYYY-MM-DD HH:MM:SS` (ISO datetime)
/// - `YYYY-MM-DDTHH:MM:SS` (ISO 8601)
/// - Relative expressions: `today`, `yesterday`, `-Nd` (N days ago)
///
/// Returns `None` if the date string cannot be parsed.
fn parse_date_flexible(date_str: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let date_str = date_str.trim();
    let now = chrono::Utc::now();

    // Handle relative date expressions
    match date_str.to_lowercase().as_str() {
        "today" => {
            return now.date_naive().and_hms_opt(0, 0, 0).map(|t| {
                chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(t, chrono::Utc)
            });
        }
        "yesterday" => {
            return (now - chrono::Duration::days(1))
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .map(|t| {
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(t, chrono::Utc)
                });
        }
        "now" => return Some(now),
        _ => {}
    }

    // Handle relative days (e.g., "-7d", "-30d")
    if date_str.starts_with('-') && date_str.ends_with('d') {
        if let Ok(days) = date_str[1..date_str.len() - 1].parse::<i64>() {
            return Some(now - chrono::Duration::days(days));
        }
    }

    // Try multiple date formats
    let formats = [
        "%Y-%m-%d",             // 2026-02-20
        "%Y-%m-%d %H:%M:%S",    // 2026-02-20 10:30:00
        "%Y-%m-%dT%H:%M:%S",    // 2026-02-20T10:30:00
        "%Y-%m-%dT%H:%M:%SZ",   // 2026-02-20T10:30:00Z
        "%Y-%m-%dT%H:%M:%S%:z", // 2026-02-20T10:30:00+00:00
        "%d/%m/%Y",             // 20/02/2026
        "%m/%d/%Y",             // 02/20/2026
        "%b %d, %Y",            // Feb 20, 2026
        "%B %d, %Y",            // February 20, 2026
    ];

    for fmt in &formats {
        // Try parsing as datetime with timezone
        if let Ok(dt) = chrono::DateTime::parse_from_str(date_str, fmt) {
            return Some(dt.with_timezone(&chrono::Utc));
        }

        // Try parsing as naive datetime
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(date_str, fmt) {
            return Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                dt,
                chrono::Utc,
            ));
        }

        // Try parsing as naive date
        if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, fmt) {
            if let Some(time) = date.and_hms_opt(0, 0, 0) {
                return Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                    time,
                    chrono::Utc,
                ));
            }
        }
    }

    None
}

/// Parse targets from a string list
fn parse_targets_from_list(target_list: &[String]) -> TargetGroup {
    // Try to use DNS resolver, fall back to no DNS if it fails
    let parser = TargetParser::with_dns()
        .unwrap_or_else(|_| TargetParser::new());
    let mut all_targets = Vec::new();

    for target_spec in target_list {
        match parser.parse(target_spec) {
            Ok(group) => {
                for target in group.targets {
                    if !all_targets.iter().any(|t: &Target| t.ip == target.ip) {
                        all_targets.push(target);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse target '{}': {}", target_spec, e);
            }
        }
    }

    TargetGroup::new(all_targets)
}

/// Build scan config from profile
fn build_scan_config_from_profile(
    profile: &rustnmap_scan_management::ScanProfile,
    args: &Args,
) -> ScanConfig {
    let scan_types = vec![match profile.scan.scan_type.as_str() {
        "connect" => rustnmap_core::session::ScanType::TcpConnect,
        "udp" => rustnmap_core::session::ScanType::Udp,
        "fin" => rustnmap_core::session::ScanType::TcpFin,
        "null" => rustnmap_core::session::ScanType::TcpNull,
        "xmas" => rustnmap_core::session::ScanType::TcpXmas,
        "maimon" => rustnmap_core::session::ScanType::TcpMaimon,
        _ => rustnmap_core::session::ScanType::TcpSyn,
    }];

    let port_spec = if let Some(ref ports) = profile.scan.ports {
        parse_port_string(ports).unwrap_or(rustnmap_core::session::PortSpec::Range {
            start: 1,
            end: 1000,
        })
    } else {
        rustnmap_core::session::PortSpec::Range {
            start: 1,
            end: 1000,
        }
    };

    let mut config = ScanConfig {
        scan_types,
        port_spec,
        service_detection: profile.scan.service_detection,
        os_detection: profile.scan.os_detection,
        nse_scripts: !profile.scan.scripts.is_empty(),
        nse_categories: profile.scan.scripts.clone(),
        ..ScanConfig::default()
    };

    // Timing template from profile
    config.timing_template = match profile.scan.timing.as_str() {
        "T0" => TimingTemplate::Paranoid,
        "T1" => TimingTemplate::Sneaky,
        "T2" => TimingTemplate::Polite,
        "T4" => TimingTemplate::Aggressive,
        "T5" => TimingTemplate::Insane,
        _ => TimingTemplate::Normal,
    };

    // Override with command-line args if specified
    if args.service_detection {
        config.service_detection = true;
    }
    if args.os_detection {
        config.os_detection = true;
    }
    if let Some(timing) = args.timing {
        config.timing_template = match timing {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => config.timing_template,
        };
    }

    // DNS server from CLI args
    config.dns_server = args.dns_server.clone();

    config
}

/// Normal scan flow (original `run_scan` logic)
async fn run_normal_scan(args: &Args) -> Result<()> {
    #[cfg(feature = "diagnostic")]
    let cli_start = std::time::Instant::now();

    // Parse targets
    #[cfg(feature = "diagnostic")]
    let before_parse = std::time::Instant::now();

    let targets = parse_targets(args)?;

    #[cfg(feature = "diagnostic")]
    let after_parse = std::time::Instant::now();

    if targets.is_empty() {
        error!("No valid targets specified");
        return Err(rustnmap_common::Error::Other(
            "No valid targets".to_string(),
        ));
    }

    info!("Targets: {}", targets.len());
    debug!(
        "Target list: {:?}",
        targets
            .targets
            .iter()
            .map(|t| t.ip.to_string())
            .collect::<Vec<_>>()
    );

    // Build scan configuration from arguments
    #[cfg(feature = "diagnostic")]
    let before_config = std::time::Instant::now();

    let config = build_scan_config(args)?;

    #[cfg(feature = "diagnostic")]
    let after_config = std::time::Instant::now();

    // Auto-disable host discovery for single host targets (matching nmap behavior)
    // When scanning a single IP address (not a network range), host discovery is unnecessary
    let mut config = config;
    if !args.disable_ping && targets.targets.len() == 1 {
        config.host_discovery = false;
        debug!("Auto-disabled host discovery for single host target");
    }

    info!("Scan type: {:?}", config.scan_types);
    info!("Timing template: {:?}", config.timing_template);

    // Load fingerprint databases (service and/or OS detection)
    let mut fp_db = FingerprintDatabase::new();
    let datadir = shellexpand::tilde(&args.datadir);
    let db_dir = std::path::PathBuf::from(datadir.as_ref()).join("db");

    // Load service probe database if service detection is enabled
    if config.service_detection {
        let service_db_path = db_dir.join("nmap-service-probes");

        if service_db_path.exists() {
            info!(
                "Loading service probe database from: {}",
                service_db_path.display()
            );
            match rustnmap_fingerprint::ProbeDatabase::load_from_nmap_db(&service_db_path).await {
                Ok(db) => {
                    info!("Service probe database loaded successfully");
                    fp_db.set_service_db(db);
                }
                Err(e) => {
                    warn!("Failed to load service probe database: {e}");
                    warn!("Service detection will be skipped");
                }
            }
        } else {
            warn!(
                "Service probe database not found at: {}",
                service_db_path.display()
            );
            warn!("Service detection will be skipped");
        }
    }

    // Load OS fingerprint database if OS detection is enabled
    if config.os_detection {
        let os_db_path = db_dir.join("nmap-os-db");

        if os_db_path.exists() {
            info!(
                "Loading OS fingerprint database from: {}",
                os_db_path.display()
            );
            match tokio::task::block_in_place(|| {
                rustnmap_fingerprint::FingerprintDatabase::load_from_nmap_db(&os_db_path)
            }) {
                Ok(db) => {
                    info!("OS fingerprint database loaded successfully");
                    fp_db.set_os_db(db);
                }
                Err(e) => {
                    warn!("Failed to load OS fingerprint database: {e}");
                    warn!("OS detection will be skipped");
                }
            }
        } else {
            warn!(
                "OS fingerprint database not found at: {}",
                os_db_path.display()
            );
            warn!("OS detection will be skipped");
        }
    }

    // Load MAC prefix database for vendor lookups
    let mac_db_path = db_dir.join("nmap-mac-prefixes");
    if mac_db_path.exists() {
        info!(
            "Loading MAC prefix database from: {}",
            mac_db_path.display()
        );
        match rustnmap_fingerprint::MacPrefixDatabase::load_from_file(&mac_db_path).await {
            Ok(db) => {
                info!(
                    "MAC prefix database loaded successfully ({} entries)",
                    db.len()
                );
                fp_db.set_mac_db(db);
            }
            Err(e) => {
                warn!("Failed to load MAC prefix database: {e}");
            }
        }
    } else {
        debug!(
            "MAC prefix database not found at: {}",
            mac_db_path.display()
        );
    }

    // Create database context for output
    let mut db_context = DatabaseContext::new();

    // Load service database for port-to-service name mappings
    let services_db_path = db_dir.join("nmap-services");
    if services_db_path.exists() {
        info!(
            "Loading services database from: {}",
            services_db_path.display()
        );
        match rustnmap_fingerprint::ServiceDatabase::load_from_file(&services_db_path).await {
            Ok(db) => {
                info!("Services database loaded successfully");
                db_context.services = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load services database: {e}");
            }
        }
    } else {
        debug!(
            "Services database not found at: {}",
            services_db_path.display()
        );
    }

    // Load protocols database for protocol number-to-name mappings
    let protocols_db_path = db_dir.join("nmap-protocols");
    if protocols_db_path.exists() {
        info!(
            "Loading protocols database from: {}",
            protocols_db_path.display()
        );
        match rustnmap_fingerprint::ProtocolDatabase::load_from_file(&protocols_db_path).await {
            Ok(db) => {
                info!("Protocols database loaded successfully");
                db_context.protocols = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load protocols database: {e}");
            }
        }
    } else {
        debug!(
            "Protocols database not found at: {}",
            protocols_db_path.display()
        );
    }

    // Load RPC database for RPC program number mappings
    let rpc_db_path = db_dir.join("nmap-rpc");
    if rpc_db_path.exists() {
        info!("Loading RPC database from: {}", rpc_db_path.display());
        match rustnmap_fingerprint::RpcDatabase::load_from_file(&rpc_db_path).await {
            Ok(db) => {
                info!("RPC database loaded successfully");
                db_context.rpc = Some(Arc::new(db));
            }
            Err(e) => {
                warn!("Failed to load RPC database: {e}");
            }
        }
    } else {
        debug!("RPC database not found at: {}", rpc_db_path.display());
    }

    let fingerprint_db = Arc::new(fp_db);

    // Create scan session with dependencies
    let target_set = Arc::new(TargetSet::from_group(targets));
    let packet_engine: Arc<dyn PacketEngine> =
        Arc::new(DefaultPacketEngine::new().map_err(|e| {
            rustnmap_common::Error::Other(format!("Failed to create packet engine: {e}"))
        })?);
    let output_sink: Arc<dyn OutputSink> = Arc::new(DefaultOutputSink::new());
    let nse_registry = Arc::new(NseRegistry::new());

    let session = ScanSession::with_dependencies(
        config,
        target_set,
        packet_engine,
        output_sink,
        fingerprint_db,
        nse_registry,
    );

    let session = Arc::new(session);

    // Create and run orchestrator
    let orchestrator = ScanOrchestrator::new(session);

    info!("Starting scan...");

    #[cfg(feature = "diagnostic")]
    let before_orch = std::time::Instant::now();

    let scan_result = orchestrator
        .run()
        .await
        .map_err(|e| rustnmap_common::Error::Other(format!("Scan failed: {e}")))?;

    #[cfg(feature = "diagnostic")]
    let after_orch = std::time::Instant::now();

    // Build command line string for output
    let command_line = build_command_line_string(args);

    // Output results
    output_results(args, &scan_result, &command_line, &db_context)?;

    #[cfg(feature = "diagnostic")]
    {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/rustnmap_diagnostic.txt")
        {
            let _ = writeln!(file, "\n=== CLI Timing ===");
            let _ = writeln!(file, "Total CLI: {:?}", cli_start.elapsed());
            let _ = writeln!(file, "Parse targets: {:?}", after_parse.duration_since(before_parse));
            let _ = writeln!(file, "Build config: {:?}", after_config.duration_since(before_config));
            let _ = writeln!(file, "Orchestrator.run(): {:?}", after_orch.duration_since(before_orch));
            let _ = writeln!(file, "Other CLI overhead: {:?}",
                cli_start.elapsed() - after_parse.duration_since(before_parse)
                - after_config.duration_since(before_config) - after_orch.duration_since(before_orch));
        }
    }

    info!("Scan completed successfully");
    Ok(())
}

/// Parses target specifications from command-line arguments.
async fn parse_targets_async(args: &Args) -> Result<TargetGroup> {
    // Use with_dns() to enable hostname resolution (e.g., scanme.nmap.org)
    let parser = TargetParser::with_dns().map_err(|e| {
        rustnmap_common::Error::Other(format!("Failed to create DNS resolver: {e}"))
    })?;
    let mut all_targets = Vec::new();

    for target_spec in &args.targets {
        match parser.parse_async(target_spec).await {
            Ok(group) => {
                for target in group.targets {
                    if !all_targets.iter().any(|t: &Target| t.ip == target.ip) {
                        all_targets.push(target);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse target '{}': {}", target_spec, e);
            }
        }
    }

    // Handle input file if specified
    if let Some(input_file) = &args.input_file {
        let content = tokio::fs::read_to_string(input_file).await.map_err(|e| {
            rustnmap_common::Error::Other(format!("Failed to read input file: {e}"))
        })?;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parser.parse_async(line).await {
                Ok(group) => {
                    for target in group.targets {
                        if !all_targets.iter().any(|t: &Target| t.ip == target.ip) {
                            all_targets.push(target);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse target from file '{}': {}", line, e);
                }
            }
        }
    }

    Ok(TargetGroup::new(all_targets))
}

/// Parses target specifications from command-line arguments (synchronous wrapper).
fn parse_targets(args: &Args) -> Result<TargetGroup> {
    // Use tokio runtime to run async parsing
    tokio::task::block_in_place(|| {
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| tokio::runtime::Handle::try_current())
            .unwrap_or_else(|_| {
                // Create new runtime if none exists (shouldn't happen in normal flow)
                std::panic::panic_any("Tokio runtime not found")
            });

        rt.block_on(parse_targets_async(args))
    })
}

/// Builds scan configuration from command-line arguments.
fn build_scan_config(args: &Args) -> Result<ScanConfig> {
    let scan_types = vec![map_scan_type(args.scan_type())];
    let port_spec = parse_port_spec(args)?;

    let mut config = ScanConfig {
        scan_types,
        port_spec,
        ..ScanConfig::default()
    };

    // Timing template
    if let Some(timing) = args.timing {
        config.timing_template = match timing {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            _ => TimingTemplate::Normal,
        };
    }

    // Parallelism settings
    if let Some(min) = args.min_parallelism {
        config.min_parallel_hosts = min;
    }
    if let Some(max) = args.max_parallelism {
        config.max_parallel_hosts = max;
    }

    // Rate limiting
    config.min_rate = args.min_rate;
    config.max_rate = args.max_rate;

    // Host discovery
    config.host_discovery = !args.disable_ping;

    // Aggressive scan (-A) enables: OS detection, service detection, vuln scripts, T4 timing
    if args.aggressive_scan {
        config.service_detection = true;
        config.os_detection = true;
        config.nse_scripts = true;
        config.nse_categories = vec!["vuln".to_string()];
        config.timing_template = TimingTemplate::Aggressive;
    }

    // Service detection (explicit -sV overrides aggressive default)
    if args.service_detection {
        config.service_detection = true;
    }

    // OS detection (explicit -O overrides aggressive default)
    if args.os_detection {
        config.os_detection = true;
    }

    // Traceroute
    config.traceroute = args.traceroute;

    // NSE scripts
    config.nse_scripts = args.script.is_some();
    if let Some(script) = &args.script {
        config.nse_categories = script.split(',').map(String::from).collect();
    }

    // Script timeout
    if let Some(timeout) = &args.script_timeout {
        match parse_time_duration(timeout) {
            Ok(duration) => config.script_timeout = duration,
            Err(e) => {
                warn!("Invalid script timeout '{timeout}': {e}. Using default.");
            }
        }
    }

    // Scan delay
    if let Some(delay) = args.scan_delay {
        config.scan_delay = std::time::Duration::from_millis(delay);
    }

    // Host timeout
    if let Some(timeout) = args.host_timeout {
        config.host_timeout = std::time::Duration::from_millis(timeout);
    }

    // Data payload (--data-hex or --data-string)
    config.data_payload = parse_data_payload(args)?;

    // Evasion configuration (--decoys, --spoof-ip, --fragment-mtu, --source-port)
    config.evasion_config = build_evasion_config(args)?;

    // DNS server for local IP detection
    config.dns_server = args.dns_server.clone();

    Ok(config)
}

/// Builds evasion configuration from CLI arguments.
///
/// Parses --decoys, --spoof-ip, --fragment-mtu, and --source-port options
/// into an `EvasionConfig` structure.
///
/// # Errors
///
/// Returns an error if any evasion argument is invalid.
fn build_evasion_config(args: &Args) -> Result<Option<rustnmap_evasion::EvasionConfig>> {
    use rustnmap_evasion::EvasionConfig;

    let mut builder = EvasionConfig::builder();
    let mut has_evasion = false;

    // Handle fragmentation (-f flag)
    if let Some(mtu) = args.fragment_mtu {
        builder = builder.fragmentation_mtu(mtu);
        has_evasion = true;
    }

    // Handle decoys (-D flag)
    if let Some(ref decoy_str) = args.decoys {
        let decoy_ips = parse_decoy_ips(decoy_str)?;
        if !decoy_ips.is_empty() {
            builder = builder.decoys(decoy_ips);
            has_evasion = true;
        }
    }

    // Handle source IP spoofing (-S flag)
    if let Some(ref spoof_ip) = args.spoof_ip {
        let ip: std::net::IpAddr = spoof_ip.parse().map_err(|_| {
            rustnmap_common::Error::Other(format!("Invalid spoof IP address: {spoof_ip}"))
        })?;
        builder = builder.source_ip(ip);
        has_evasion = true;
    }

    // Handle source port (-g flag)
    if let Some(port) = args.source_port {
        builder = builder.source_port(port);
        has_evasion = true;
    }

    if has_evasion {
        Ok(Some(builder.build().map_err(|e| {
            rustnmap_common::Error::Other(format!("Evasion config error: {e}"))
        })?))
    } else {
        Ok(None)
    }
}

/// Parses decoy IP list from comma-separated string.
///
/// Supports:
/// - Explicit IP addresses (e.g., "192.168.1.1,10.0.0.1")
/// - `RND:number` syntax to generate random decoys (e.g., "RND:10")
/// - Mixed syntax (e.g., "192.168.1.1,RND:5,10.0.0.1")
///
/// # Errors
///
/// Returns an error if any IP address is invalid or RND number is out of range.
fn parse_decoy_ips(s: &str) -> Result<Vec<std::net::IpAddr>> {
    let mut ips = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Check for RND:number syntax (nmap-compatible random decoys)
        if let Some(number_str) = part.strip_prefix("RND:") {
            let count: usize = number_str.parse().map_err(|_| {
                rustnmap_common::Error::Other(format!(
                    "Invalid RND number: {number_str} (expected RND:<number>)"
                ))
            })?;

            // nmap limits RND to reasonable values (typically 1-100)
            if count == 0 {
                return Err(rustnmap_common::Error::Other(
                    "RND count must be at least 1".to_string(),
                ));
            }
            if count > 100 {
                return Err(rustnmap_common::Error::Other(
                    "RND count exceeds maximum of 100".to_string(),
                ));
            }

            // Generate random IP addresses for decoys
            // Use current time and process ID as seed sources
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let pid = std::process::id();

            for i in 0..count {
                // Simple deterministic random generation based on seed
                // This is sufficient for decoy generation (not cryptographic)
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "Truncation is acceptable for decoy IP generation"
                )]
                let hash = {
                    let base = (seed as u64).wrapping_add((pid as u64).wrapping_mul(0x5851_f42d));
                    let offset = (i as u64).wrapping_mul(0x0001_4057_b7ef);
                    base.wrapping_add(offset)
                };

                // Generate random IP in public IP space (avoid reserved ranges)
                // Use the hash to create a public IP address
                let octets: [u8; 4] = [
                    // First octet: avoid 0, 10, 127, 172.16-31, 192.168 (private/reserved)
                    // Prefer common public ranges: 1-9, 11-126, 128-171, 173-191, 193-255
                    {
                        let first = ((hash >> 24) & 0xFF) as u8;
                        // Map to valid public IP first octet
                        match first {
                            0..=9 => first.saturating_add(1),
                            10 => 11,
                            127 => 128,
                            172..=191 => {
                                if first == 172 {
                                    173
                                } else {
                                    first
                                }
                            }
                            192..=223 => {
                                if (190..=223).contains(&first) {
                                    first
                                } else {
                                    first.saturating_add(30)
                                }
                            }
                            _ => first,
                        }
                    },
                    ((hash >> 16) & 0xFF) as u8,
                    ((hash >> 8) & 0xFF) as u8,
                    (hash & 0xFF) as u8,
                ];

                ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            }
        } else {
            // Parse as explicit IP address
            let ip: std::net::IpAddr = part.parse().map_err(|_| {
                rustnmap_common::Error::Other(format!("Invalid decoy IP address: {part}"))
            })?;
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// Parses nmap-style time specification into Duration.
///
/// # Supported Formats
///
/// - Plain number: `60` -> 60 seconds
/// - Milliseconds: `500ms` -> 500ms
/// - Seconds: `30s` -> 30 seconds
/// - Minutes: `5m` -> 5 minutes
/// - Hours: `1h` -> 1 hour
/// - Zero: `0` -> no timeout (Duration::MAX)
///
/// # Errors
///
/// Returns an error if the string cannot be parsed.
fn parse_time_duration(input: &str) -> Result<std::time::Duration> {
    let input = input.trim();

    // Handle special case: 0 means no timeout
    if input == "0" {
        return Ok(std::time::Duration::MAX);
    }

    // Check for "ms" suffix (milliseconds)
    if input.len() > 2 {
        let suffix = &input[input.len() - 2..];
        if suffix == "ms" {
            let num_str = &input[..input.len() - 2];
            let ms: u64 = num_str.parse().map_err(|_| {
                rustnmap_common::Error::Other(format!("Invalid milliseconds value: {num_str}"))
            })?;
            return Ok(std::time::Duration::from_millis(ms));
        }
    }

    // Check for single-char suffix (s, m, h)
    if let Some(c) = input.chars().last() {
        match c {
            's' | 'm' | 'h' => {
                let num_str = &input[..input.len() - 1];
                let num: u64 = num_str.parse().map_err(|_| {
                    rustnmap_common::Error::Other(format!("Invalid time value: {num_str}"))
                })?;
                return Ok(match c {
                    's' => std::time::Duration::from_secs(num),
                    'm' => std::time::Duration::from_secs(num * 60),
                    'h' => std::time::Duration::from_secs(num * 3600),
                    _ => unreachable!(),
                });
            }
            _ => {}
        }
    }

    // No recognized suffix, try parsing as plain seconds
    let secs: u64 = input.parse().map_err(|_| {
        rustnmap_common::Error::Other(format!("Invalid time format: {input}"))
    })?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Parses data payload from CLI arguments.
///
/// Supports --data-hex for hex-encoded data and --data-string for plain text.
///
/// # Errors
///
/// Returns an error if the hex data is malformed.
fn parse_data_payload(args: &Args) -> Result<Option<Vec<u8>>> {
    if let Some(hex_data) = &args.data_hex {
        // Parse hex string (e.g., "48656c6c6f" -> "Hello")
        // Remove spaces and colons from hex string efficiently
        let hex_clean: String = hex_data
            .chars()
            .filter(|c| *c != ' ' && *c != ':')
            .collect();
        if !hex_clean.len().is_multiple_of(2) {
            return Err(rustnmap_common::Error::Other(
                "Hex data must have an even number of characters".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(hex_clean.len() / 2);
        for i in (0..hex_clean.len()).step_by(2) {
            let byte_str = &hex_clean[i..i + 2];
            match u8::from_str_radix(byte_str, 16) {
                Ok(byte) => bytes.push(byte),
                Err(_) => {
                    return Err(rustnmap_common::Error::Other(format!(
                        "Invalid hex byte: {byte_str}"
                    )));
                }
            }
        }
        Ok(Some(bytes))
    } else if let Some(string_data) = &args.data_string {
        // Use string data as-is (UTF-8 bytes)
        Ok(Some(string_data.as_bytes().to_vec()))
    } else if let Some(length) = args.data_length {
        // Generate random padding of specified length
        #[allow(clippy::cast_possible_truncation)]
        let padding: Vec<u8> = (0..length).map(|i| (i % 256) as u8).collect();
        Ok(Some(padding))
    } else {
        Ok(None)
    }
}

/// Parses port specification from arguments.
fn parse_port_spec(args: &Args) -> Result<PortSpec> {
    if args.port_range_all {
        Ok(PortSpec::All)
    } else if let Some(top) = args.top_ports {
        // top_ports takes precedence over fast_scan
        Ok(PortSpec::Top(top as usize))
    } else if args.fast_scan {
        Ok(PortSpec::Top(100))
    } else if let Some(ports) = &args.ports {
        parse_port_string(ports)
    } else {
        // Default: top 1000 ports
        Ok(PortSpec::Top(1000))
    }
}

/// Parses a port string (e.g., "22,80,443" or "1-1000").
fn parse_port_string(s: &str) -> Result<PortSpec> {
    let mut ports = Vec::new();

    for segment in s.split(',') {
        let segment = segment.trim();
        if segment.contains('-') {
            // Range
            let range_parts: Vec<&str> = segment.split('-').collect();
            if range_parts.len() != 2 {
                return Err(rustnmap_common::Error::Other(format!(
                    "Invalid port range: {segment}"
                )));
            }
            let start: u16 = range_parts[0].parse().map_err(|_| {
                rustnmap_common::Error::Other(format!("Invalid port number: {}", range_parts[0]))
            })?;
            let end: u16 = range_parts[1].parse().map_err(|_| {
                rustnmap_common::Error::Other(format!("Invalid port number: {}", range_parts[1]))
            })?;
            return Ok(PortSpec::Range { start, end });
        }
        // Single port
        let port_num: u16 = segment.parse().map_err(|_| {
            rustnmap_common::Error::Other(format!("Invalid port number: {segment}"))
        })?;
        ports.push(port_num);
    }

    Ok(PortSpec::List(ports))
}

/// Maps CLI scan type to core scan type.
const fn map_scan_type(scan_type: crate::args::ScanType) -> CoreScanType {
    match scan_type {
        crate::args::ScanType::Syn => CoreScanType::TcpSyn,
        crate::args::ScanType::Connect => CoreScanType::TcpConnect,
        crate::args::ScanType::Udp => CoreScanType::Udp,
        crate::args::ScanType::Fin => CoreScanType::TcpFin,
        crate::args::ScanType::Null => CoreScanType::TcpNull,
        crate::args::ScanType::Xmas => CoreScanType::TcpXmas,
        crate::args::ScanType::Maimon => CoreScanType::TcpMaimon,
        crate::args::ScanType::Ack => CoreScanType::TcpAck,
        crate::args::ScanType::Window => CoreScanType::TcpWindow,
    }
}

/// Builds command line string from arguments for output.
fn build_command_line_string(args: &Args) -> String {
    use std::fmt::Write;

    let mut cmd = String::from("rustnmap");

    // Add scan type
    match args.scan_type() {
        crate::args::ScanType::Syn => cmd.push_str(" -sS"),
        crate::args::ScanType::Connect => cmd.push_str(" -sT"),
        crate::args::ScanType::Udp => cmd.push_str(" -sU"),
        crate::args::ScanType::Fin => cmd.push_str(" -sF"),
        crate::args::ScanType::Null => cmd.push_str(" -sN"),
        crate::args::ScanType::Xmas => cmd.push_str(" -sX"),
        crate::args::ScanType::Maimon => cmd.push_str(" -sM"),
        crate::args::ScanType::Ack => cmd.push_str(" -sA"),
        crate::args::ScanType::Window => cmd.push_str(" -sW"),
    }

    // Add ports
    if let Some(ports) = &args.ports {
        let _ = write!(cmd, " -p{ports}");
    } else if args.port_range_all {
        cmd.push_str(" -p-");
    } else if args.fast_scan {
        cmd.push_str(" -F");
    } else if let Some(top) = args.top_ports {
        let _ = write!(cmd, " --top-ports {top}");
    }

    // Add targets
    for target in &args.targets {
        let _ = write!(cmd, " {target}");
    }

    cmd
}

/// Outputs scan results based on command-line arguments.
fn output_results(args: &Args, result: &ScanResult, command_line: &str, db_context: &DatabaseContext) -> Result<()> {
    // Handle quiet mode
    if args.quiet || args.no_output {
        return Ok(());
    }

    // Generate output based on format
    if args.output_script_kiddie {
        print_script_kiddie_output(result);
    } else {
        print_normal_output(args, result, command_line, db_context);
    }

    // Write to output files if specified
    if let Some(basename) = &args.output_all {
        write_all_formats(result, basename, args.append_output, db_context)?;
    } else {
        if let Some(path) = &args.output_normal {
            write_normal_output(result, path, args.append_output, db_context)?;
        }
        if let Some(path) = &args.output_xml {
            write_xml_output(result, path, args.append_output, db_context)?;
        }
        if let Some(path) = &args.output_json {
            write_json_output(result, path, args.append_output)?;
        }
        if let Some(path) = &args.output_ndjson {
            write_ndjson_output(result, path, args.append_output)?;
        }
        if let Some(path) = &args.output_grepable {
            write_grepable_output(result, path, args.append_output, db_context)?;
        }
        if let Some(path) = &args.output_markdown {
            write_markdown_output(result, path, args.append_output)?;
        }
    }

    Ok(())
}

/// Prints normal formatted output to console.
fn print_normal_output(args: &Args, result: &ScanResult, command_line: &str, _db_context: &DatabaseContext) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    // Header
    let local_time = result.metadata.start_time.with_timezone(&chrono::Local);
    let _ = writeln!(
        &mut handle,
        "# RustNmap {} scan initiated {}",
        result.metadata.scanner_version,
        local_time.format("%a %b %d %H:%M:%S %Y")
    );
    let _ = writeln!(&mut handle, "# {command_line}");
    let _ = writeln!(&mut handle);

    // Host results
    for host in &result.hosts {
        print_host_normal(&mut handle, args, host);
    }

    // Footer
    let _ = writeln!(
        &mut handle,
        "RustNmap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        result.statistics.total_hosts,
        if result.statistics.total_hosts == 1 {
            ""
        } else {
            "es"
        },
        result.statistics.hosts_up,
        if result.statistics.hosts_up == 1 {
            ""
        } else {
            "s"
        },
        result.metadata.elapsed.as_secs_f64()
    );
}

/// Prints a single host in normal format.
fn print_host_normal<W: Write>(handle: &mut W, args: &Args, host: &HostResult) {
    let _ = writeln!(handle, "RustNmap scan report for {}", host.ip);

    if let Some(ref hostname) = host.hostname {
        let _ = writeln!(handle, "rDNS record for {}: {}", host.ip, hostname);
    }

    let status_str = match host.status {
        rustnmap_output::models::HostStatus::Up => "up",
        rustnmap_output::models::HostStatus::Down => "down",
        rustnmap_output::models::HostStatus::Unknown => "unknown",
    };

    let latency_ms = host.latency.as_secs_f64() * 1000.0;
    let _ = writeln!(
        handle,
        "Host is {} ({:.4}s latency).",
        status_str,
        latency_ms / 1000.0
    );

    if let Some(ref mac) = host.mac {
        let _ = writeln!(handle, "MAC Address: {mac:?}");
    }

    // Port information
    if !host.ports.is_empty() {
        let _ = writeln!(handle, "PORT     STATE SERVICE");
        for port in &host.ports {
            print_port_normal(handle, args, port);
        }
    }

    // OS detection results
    if !host.os_matches.is_empty() {
        let _ = writeln!(handle, "OS detection:");
        for os_match in &host.os_matches {
            let _ = writeln!(handle, "{} ({}%)", os_match.name, os_match.accuracy);
        }
    }

    let _ = writeln!(handle);
}

/// Prints a single port in normal format.
fn print_port_normal<W: Write>(handle: &mut W, _args: &Args, port: &PortResult) {
    use rustnmap_output::NormalFormatter;

    let formatter = NormalFormatter::new();
    if let Ok(output) = formatter.format_port(port) {
        let _ = write!(handle, "{}", output);
    } else {
        // Fallback to simple format if formatter fails
        let protocol = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        let state_str = match port.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::Unfiltered => "unfiltered",
            PortState::OpenOrFiltered => "open|filtered",
            PortState::ClosedOrFiltered => "closed|filtered",
            PortState::OpenOrClosed => "open|closed",
            PortState::FilteredOrClosed => "filtered|closed",
            PortState::Unknown => "unknown",
        };

        if let Some(ref service) = port.service {
            let _ = writeln!(
                handle,
                "{}/{:<5} {:<8} {}",
                port.number, protocol, state_str, service.name
            );
        } else {
            let _ = writeln!(
                handle,
                "{}/{:<5} {:<8} unknown",
                port.number, protocol, state_str
            );
        }
    }
}

/// Prints output in script kiddie format.
fn print_script_kiddie_output(result: &ScanResult) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    let _ = writeln!(
        &mut handle,
        "RuStNmAp {} ScAn InItIaTeD",
        result.metadata.scanner_version
    );
    let _ = writeln!(&mut handle);

    for host in &result.hosts {
        let _ = writeln!(&mut handle, "== HoSt: {} ==", host.ip);

        for port in &host.ports {
            if matches!(port.state, PortState::Open) {
                let _ = writeln!(&mut handle, "  [+] PoRt {} iS oPeN!", port.number);
            }
        }
        let _ = writeln!(&mut handle);
    }

    let _ = writeln!(
        &mut handle,
        "ScAn CoMpLeTe! {} HoStS fOuNd",
        result.statistics.hosts_up
    );
}

/// Writes output in all formats.
fn write_all_formats(result: &ScanResult, basename: &std::path::Path, append: bool, db_context: &DatabaseContext) -> Result<()> {
    let normal_path = basename.with_extension("nmap");
    let xml_path = basename.with_extension("xml");
    let grepable_path = basename.with_extension("gnmap");
    let json_path = basename.with_extension("json");
    let ndjson_path = basename.with_extension("ndjson");
    let md_path = basename.with_extension("md");

    write_normal_output(result, &normal_path, append, db_context)?;
    write_xml_output(result, &xml_path, append, db_context)?;
    write_grepable_output(result, &grepable_path, append, db_context)?;
    write_json_output(result, &json_path, append)?;
    write_ndjson_output(result, &ndjson_path, append)?;
    write_markdown_output(result, &md_path, append)?;

    Ok(())
}

/// Opens a file for writing with async-friendly blocking I/O.
///
/// Uses `block_in_place` to avoid blocking the async runtime during file operations.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or created.
fn open_output_file(path: &std::path::Path, append: bool) -> Result<std::fs::File> {
    tokio::task::block_in_place(|| {
        if append {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| {
                    rustnmap_common::Error::Other(format!("Failed to open output file: {e}"))
                })
        } else {
            File::create(path).map_err(|e| {
                rustnmap_common::Error::Other(format!("Failed to create output file: {e}"))
            })
        }
    })
}

/// Writes normal format output to file.
fn write_normal_output(result: &ScanResult, path: &std::path::Path, append: bool, _db_context: &DatabaseContext) -> Result<()> {
    let mut file = open_output_file(path, append)?;
    // Write header
    writeln!(
        file,
        "# RustNmap {} scan initiated {}",
        result.metadata.scanner_version,
        result.metadata.start_time.format("%c")
    )
    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(file, "# rustnmap <targets>")
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(file).map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    // Write host results
    for host in &result.hosts {
        writeln!(file, "RustNmap scan report for {}", host.ip)
            .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

        let status_str = match host.status {
            rustnmap_output::models::HostStatus::Up => "up",
            rustnmap_output::models::HostStatus::Down => "down",
            rustnmap_output::models::HostStatus::Unknown => "unknown",
        };

        let latency_ms = host.latency.as_secs_f64() * 1000.0;
        writeln!(
            file,
            "Host is {} ({:.4}s latency).",
            status_str,
            latency_ms / 1000.0
        )
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

        for port in &host.ports {
            if matches!(port.state, PortState::Open) {
                let protocol_str = match port.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Sctp => "sctp",
                };
                let service_name = _db_context.lookup_service(port.number, protocol_str);
                if let Some(name) = service_name {
                    writeln!(file, "Port {}: open {}", port.number, name)
                        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
                } else {
                    writeln!(file, "Port {}: open", port.number)
                        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
                }
            }
        }
        writeln!(file).map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    }

    // Write footer
    writeln!(
        file,
        "RustNmap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        result.statistics.total_hosts,
        if result.statistics.total_hosts == 1 {
            ""
        } else {
            "es"
        },
        result.statistics.hosts_up,
        if result.statistics.hosts_up == 1 {
            ""
        } else {
            "s"
        },
        result.metadata.elapsed.as_secs_f64()
    )
    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    Ok(())
}

/// Writes XML format output to file.
fn write_xml_output(result: &ScanResult, path: &std::path::Path, append: bool, _db_context: &DatabaseContext) -> Result<()> {
    let mut file = open_output_file(path, append)?;
    writeln!(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(
        file,
        "<nmaprun scanner=\"rustnmap\" version=\"{}\" xmloutputversion=\"1.05\">",
        result.metadata.scanner_version
    )
    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    for host in &result.hosts {
        writeln!(file, "  <host>")
            .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
        writeln!(
            file,
            "    <address addr=\"{}\" addrtype=\"ipv4\"/>",
            host.ip
        )
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

        if !host.ports.is_empty() {
            writeln!(file, "    <ports>")
                .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
            for port in &host.ports {
                let state_str = match port.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                    PortState::Filtered => "filtered",
                    _ => "unknown",
                };
                writeln!(
                    file,
                    "      <port protocol=\"tcp\" portid=\"{}\">",
                    port.number
                )
                .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
                writeln!(file, "        <state state=\"{state_str}\"/>")
                    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
                writeln!(file, "      </port>")
                    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
            }
            writeln!(file, "    </ports>")
                .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
        }

        writeln!(file, "  </host>")
            .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    }

    writeln!(file, "  <runstats>")
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(
        file,
        "    <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
        result.statistics.hosts_up, result.statistics.hosts_down, result.statistics.total_hosts
    )
    .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(file, "  </runstats>")
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
    writeln!(file, "</nmaprun>")
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    Ok(())
}

/// Writes grepable format output to file.
fn write_grepable_output(result: &ScanResult, path: &std::path::Path, append: bool, _db_context: &DatabaseContext) -> Result<()> {
    let mut file = open_output_file(path, append)?;

    for host in &result.hosts {
        let status = match host.status {
            rustnmap_output::models::HostStatus::Up => "Up",
            _ => "Down",
        };

        let ports: Vec<String> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open))
            .map(|p| {
                let protocol_str = match p.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                    Protocol::Sctp => "sctp",
                };
                let service_name = _db_context.lookup_service(p.number, protocol_str).unwrap_or("");
                format!("{}/open/{}/{}/", p.number, protocol_str, service_name)
            })
            .collect();

        writeln!(
            file,
            "Host: {} ({})	Status: {}",
            host.ip,
            host.hostname.as_deref().unwrap_or(""),
            status
        )
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

        if !ports.is_empty() {
            writeln!(file, "Ports: {}", ports.join(", "))
                .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;
        }
    }

    Ok(())
}

/// Writes NDJSON format output to file.
fn write_ndjson_output(result: &ScanResult, path: &std::path::Path, append: bool) -> Result<()> {
    let formatter = NdjsonFormatter::new();
    let output = formatter
        .format_scan_result(result)
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to format NDJSON: {e}")))?;

    let mut file = open_output_file(path, append)?;

    file.write_all(output.as_bytes())
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    Ok(())
}

/// Writes Markdown format output to file.
fn write_markdown_output(result: &ScanResult, path: &std::path::Path, append: bool) -> Result<()> {
    let formatter = MarkdownFormatter::new();
    let output = formatter
        .format_scan_result(result)
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to format Markdown: {e}")))?;

    let mut file = open_output_file(path, append)?;

    file.write_all(output.as_bytes())
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    Ok(())
}

/// Writes JSON format output to file.
fn write_json_output(result: &ScanResult, path: &std::path::Path, append: bool) -> Result<()> {
    let formatter = JsonFormatter::new();
    let output = formatter
        .format_scan_result(result)
        .map_err(|e| rustnmap_common::Error::Other(format!("Failed to format JSON: {e}")))?;

    let mut file = open_output_file(path, append)?;
    file.write_all(output.as_bytes())
        .map_err(|e| rustnmap_common::Error::Other(format!("Write error: {e}")))?;

    Ok(())
}

/// Sets up logging based on verbosity and debug levels.
fn setup_logging(args: &Args) {
    let filter_level = if args.debug > 0 {
        match args.debug {
            1 | 2 => "debug",
            _ => "trace",
        }
    } else if args.verbose > 0 {
        match args.verbose {
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    } else {
        "warn"
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter_level));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_string_single() {
        let result = parse_port_string("80");
        assert!(result.is_ok());
        let ports = match result {
            Ok(PortSpec::List(p)) => p,
            Ok(_) => {
                panic!("Expected PortSpec::List");
            }
            Err(ref e) => {
                panic!("Parse failed: {e}");
            }
        };
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_port_string_multiple() {
        let result = parse_port_string("22,80,443");
        assert!(result.is_ok());
        let ports = match result {
            Ok(PortSpec::List(p)) => p,
            Ok(_) => {
                panic!("Expected PortSpec::List");
            }
            Err(ref e) => {
                panic!("Parse failed: {e}");
            }
        };
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_port_string_range() {
        let result = parse_port_string("1-100");
        assert!(result.is_ok());
        let (start, end) = match result {
            Ok(PortSpec::Range { start, end }) => (start, end),
            Ok(_) => {
                panic!("Expected PortSpec::Range");
            }
            Err(ref e) => {
                panic!("Parse failed: {e}");
            }
        };
        assert_eq!(start, 1);
        assert_eq!(end, 100);
    }

    #[test]
    fn test_map_scan_type() {
        assert!(matches!(
            map_scan_type(crate::args::ScanType::Syn),
            CoreScanType::TcpSyn
        ));
        assert!(matches!(
            map_scan_type(crate::args::ScanType::Connect),
            CoreScanType::TcpConnect
        ));
        assert!(matches!(
            map_scan_type(crate::args::ScanType::Udp),
            CoreScanType::Udp
        ));
    }

    #[test]
    fn test_parse_decoy_ips_valid() {
        let result = parse_decoy_ips("192.168.1.1,192.168.1.2,10.0.0.1");
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn test_parse_decoy_ips_with_spaces() {
        let result = parse_decoy_ips("192.168.1.1, 192.168.1.2 , 10.0.0.1");
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn test_parse_decoy_ips_invalid() {
        let result = parse_decoy_ips("192.168.1.1,invalid_ip,10.0.0.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_evasion_config_none() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn test_build_evasion_config_fragmentation() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            fragment_mtu: Some(100),
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert!(cfg.fragmentation.is_some());
    }

    #[test]
    fn test_build_evasion_config_spoof_ip() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            spoof_ip: Some("10.0.0.1".to_string()),
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert!(cfg.source.source_ip.is_some());
    }

    #[test]
    fn test_build_evasion_config_source_port() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            source_port: Some(53),
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert_eq!(cfg.source.source_port, Some(53));
    }

    #[test]
    fn test_build_evasion_config_decoys() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            decoys: Some("192.168.1.2,192.168.1.3".to_string()),
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert!(cfg.decoys.is_some());
        let decoy_cfg = cfg.decoys.unwrap();
        assert_eq!(decoy_cfg.decoys.len(), 2);
    }

    #[test]
    fn test_build_evasion_config_multiple() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            fragment_mtu: Some(64),
            spoof_ip: Some("10.0.0.1".to_string()),
            source_port: Some(443),
            ..Default::default()
        };
        let config = build_evasion_config(&args).unwrap();
        assert!(config.is_some());
        let cfg = config.unwrap();
        assert!(cfg.fragmentation.is_some());
        assert!(cfg.source.source_ip.is_some());
        assert_eq!(cfg.source.source_port, Some(443));
    }

    #[test]
    fn test_parse_time_duration_seconds() {
        let result = parse_time_duration("30s").unwrap();
        assert_eq!(result, std::time::Duration::from_secs(30));
    }

    #[test]
    fn test_parse_time_duration_minutes() {
        let result = parse_time_duration("5m").unwrap();
        assert_eq!(result, std::time::Duration::from_secs(300));
    }

    #[test]
    fn test_parse_time_duration_hours() {
        let result = parse_time_duration("1h").unwrap();
        assert_eq!(result, std::time::Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_time_duration_milliseconds() {
        let result = parse_time_duration("500ms").unwrap();
        assert_eq!(result, std::time::Duration::from_millis(500));
    }

    #[test]
    fn test_parse_time_duration_plain_number() {
        let result = parse_time_duration("60").unwrap();
        assert_eq!(result, std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_parse_time_duration_zero() {
        let result = parse_time_duration("0").unwrap();
        assert_eq!(result, std::time::Duration::MAX);
    }

    #[test]
    fn test_parse_time_duration_invalid() {
        let result = parse_time_duration("invalid");
        assert!(result.is_err());
    }
}
