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

//! Command-line argument parsing for `RustNmap`.
//!
//! This module provides comprehensive Nmap-compatible argument parsing
//! using clap's derive API.

use clap::Parser;
use std::path::PathBuf;

/// `RustNmap` - Modern, high-performance network scanner written in Rust.
///
/// `RustNmap` provides 100% functional parity with Nmap while leveraging
/// Rust's safety guarantees and asynchronous capabilities for improved performance.
///
/// # Target Specification
///
/// Targets can be specified as:
/// - IP addresses: `192.168.1.1`
/// - Hostnames: `example.com`
/// - CIDR notation: `192.168.1.0/24`
/// - Ranges: `192.168.1.1-100`
/// - Octet ranges: `192.168.1-10.*`
///
/// # Examples
///
/// Basic TCP SYN scan:
/// ```bash
/// rustnmap -sS 192.168.1.1
/// ```
///
/// Service detection and OS fingerprinting:
/// ```bash
/// rustnmap -sS -sV -O 192.168.1.1
/// ```
///
/// Scan with NSE scripts:
/// ```bash
/// rustnmap -sS --script=default 192.168.1.1
/// ```
///
/// Output to multiple formats:
/// ```bash
/// rustnmap -sS -oA scan_results 192.168.1.1
/// ```
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "rustnmap",
    author = "greatwallisme <greatwallisme@gmail.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "Network Mapper, modern high-performance network scanner",
    long_about = "RustNmap provides 100% functional parity with Nmap while leveraging Rust's \
                  safety guarantees and asynchronous capabilities for improved performance.",
    after_help = "See https://github.com/greatwalllisme/rustnmap for more information.",
    max_term_width = 100,
    args_override_self = true
)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Args is a CLI argument struct with independent boolean flags"
)]
pub struct Args {
    /// Target hosts to scan
    #[arg(
        required = true,
        num_args = 1..,
        help_heading = "Target Specification",
        value_name = "TARGET"
    )]
    pub targets: Vec<String>,

    // ============================================
    // Scan Types
    // ============================================
    /// TCP SYN scan (default with root)
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_connect", "scan_udp", "scan_fin",
                             "scan_null", "scan_xmas", "scan_maimon"]
    )]
    pub scan_syn: bool,

    /// TCP Connect scan (default without root)
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_udp", "scan_fin",
                             "scan_null", "scan_xmas", "scan_maimon"]
    )]
    pub scan_connect: bool,

    /// UDP scan
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_connect", "scan_fin",
                             "scan_null", "scan_xmas", "scan_maimon"]
    )]
    pub scan_udp: bool,

    /// TCP FIN scan
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_connect", "scan_udp",
                             "scan_null", "scan_xmas", "scan_maimon"]
    )]
    pub scan_fin: bool,

    /// TCP NULL scan
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_connect", "scan_udp",
                             "scan_fin", "scan_xmas", "scan_maimon"]
    )]
    pub scan_null: bool,

    /// TCP XMAS scan
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_connect", "scan_udp",
                             "scan_fin", "scan_null", "scan_maimon"]
    )]
    pub scan_xmas: bool,

    /// TCP MAIMON scan
    #[arg(
        short = 's',
        long,
        help_heading = "Scan Types",
        conflicts_with_all = ["scan_syn", "scan_connect", "scan_udp",
                             "scan_fin", "scan_null", "scan_xmas"]
    )]
    pub scan_maimon: bool,

    // ============================================
    // Port Specification
    // ============================================
    /// Ports to scan (e.g., -p 22,80,443 or -p 1-1000)
    #[arg(
        short = 'p',
        long,
        help_heading = "Port Specification",
        value_name = "PORTS",
        conflicts_with_all = ["port_range_all", "top_ports", "fast_scan"]
    )]
    pub ports: Option<String>,

    /// Scan all 65535 ports
    #[arg(
        short = 'p',
        long,
        help_heading = "Port Specification",
        conflicts_with_all = ["ports", "top_ports", "fast_scan"]
    )]
    pub port_range_all: bool,

    /// Top `<N>` most common ports
    #[arg(
        long,
        help_heading = "Port Specification",
        value_name = "N",
        conflicts_with_all = ["ports", "port_range_all"]
    )]
    pub top_ports: Option<u16>,

    /// Scan fewer ports than the default scan (top 100)
    #[arg(
        short = 'F',
        long,
        help_heading = "Port Specification",
        conflicts_with_all = ["ports", "port_range_all", "top_ports"]
    )]
    pub fast_scan: bool,

    /// Scan the specified protocol
    #[arg(
        short = 's',
        long,
        help_heading = "Port Specification",
        value_name = "PROTOCOL"
    )]
    pub protocol: Option<String>,

    // ============================================
    // Service/OS Detection
    // ============================================
    /// Probe open ports to determine service/version info
    #[arg(short = 's', long, help_heading = "Service/OS Detection")]
    pub service_detection: bool,

    /// Intensity level of service detection (0-9)
    #[arg(
        long,
        help_heading = "Service/OS Detection",
        value_name = "LEVEL",
        requires = "service_detection"
    )]
    pub version_intensity: Option<u8>,

    /// Detect operating system
    #[arg(short = 'O', long, help_heading = "Service/OS Detection")]
    pub os_detection: bool,

    /// Limit OS detection to promising targets
    #[arg(long, help_heading = "Service/OS Detection", requires = "os_detection")]
    pub osscan_limit: bool,

    /// Guess OS more aggressively
    #[arg(long, help_heading = "Service/OS Detection", requires = "os_detection")]
    pub osscan_guess: bool,

    // ============================================
    // Timing and Performance
    // ============================================
    /// Timing template (0-5, higher is faster)
    #[arg(
        short = 'T',
        long,
        help_heading = "Timing and Performance",
        value_name = "LEVEL"
    )]
    pub timing: Option<u8>,

    /// Minimum milliseconds between probes
    #[arg(long, help_heading = "Timing and Performance", value_name = "MS")]
    pub scan_delay: Option<u64>,

    /// Maximum milliseconds overall probe timeout
    #[arg(long, help_heading = "Timing and Performance", value_name = "MS")]
    pub min_parallelism: Option<usize>,

    /// Maximum number of parallel probes
    #[arg(long, help_heading = "Timing and Performance", value_name = "NUM")]
    pub max_parallelism: Option<usize>,

    /// Minimum rate (packets per second)
    #[arg(long, help_heading = "Timing and Performance", value_name = "NUM")]
    pub min_rate: Option<u64>,

    /// Maximum rate (packets per second)
    #[arg(long, help_heading = "Timing and Performance", value_name = "NUM")]
    pub max_rate: Option<u64>,

    // ============================================
    // Firewall/IDS Evasion
    // ============================================
    /// Decoy scan with multiple hosts
    #[arg(
        short = 'D',
        long,
        help_heading = "Firewall/IDS Evasion",
        value_name = "DECOYS"
    )]
    pub decoys: Option<String>,

    /// Spoof source address
    #[arg(
        short = 'S',
        long,
        help_heading = "Firewall/IDS Evasion",
        value_name = "IP"
    )]
    pub spoof_ip: Option<String>,

    /// Use specified interface
    #[arg(
        short = 'e',
        long,
        help_heading = "Firewall/IDS Evasion",
        value_name = "IFACE"
    )]
    pub interface: Option<String>,

    /// Fragment packets (MTU)
    #[arg(
        short = 'f',
        long,
        help_heading = "Firewall/IDS Evasion",
        value_name = "MTU"
    )]
    pub fragment_mtu: Option<u16>,

    /// Specify source port number
    #[arg(
        short = 'g',
        long,
        help_heading = "Firewall/IDS Evasion",
        value_name = "PORT"
    )]
    pub source_port: Option<u16>,

    /// Use specific data length
    #[arg(long, help_heading = "Firewall/IDS Evasion", value_name = "LEN")]
    pub data_length: Option<usize>,

    /// Append custom binary data to packets
    #[arg(long, help_heading = "Firewall/IDS Evasion", value_name = "HEX")]
    pub data_hex: Option<String>,

    /// Append custom string data to packets
    #[arg(long, help_heading = "Firewall/IDS Evasion", value_name = "STRING")]
    pub data_string: Option<String>,

    // ============================================
    // Output Formats
    // ============================================
    /// Normal output to file
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_normal: Option<PathBuf>,

    /// XML output to file
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_xml: Option<PathBuf>,

    /// Grepable output to file
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_grepable: Option<PathBuf>,

    /// JSON output to file
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_json: Option<PathBuf>,

    /// NDJSON output to file (newline-delimited JSON for pipelines)
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_ndjson: Option<PathBuf>,

    /// Markdown output to file
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "FILE",
        conflicts_with = "output_all"
    )]
    pub output_markdown: Option<PathBuf>,

    /// Output all formats to basename
    #[arg(
        short = 'o',
        long,
        help_heading = "Output",
        value_name = "BASENAME",
        conflicts_with_all = ["output_normal", "output_xml",
                             "output_grepable", "output_json",
                             "output_ndjson", "output_markdown"]
    )]
    pub output_all: Option<PathBuf>,

    /// Script Kiddie output
    #[arg(short = 'o', long, help_heading = "Output")]
    pub output_script_kiddie: bool,

    /// No output (suppress default output)
    #[arg(long, help_heading = "Output")]
    pub no_output: bool,

    /// Enable streaming output (output hosts as they are discovered)
    #[arg(long, help_heading = "Output")]
    pub stream: bool,

    /// Append to output files (don't overwrite)
    #[arg(long, help_heading = "Output")]
    pub append_output: bool,

    /// Increase verbosity level (use -v, -vv, -vvv)
    #[arg(
        short = 'v',
        long,
        help_heading = "Output",
        action = clap::ArgAction::Count
    )]
    pub verbose: u8,

    /// Decrease verbosity level (quiet mode)
    #[arg(short = 'q', long, help_heading = "Output")]
    pub quiet: bool,

    /// Increase debugging level (use -d, -dd, -ddd...)
    #[arg(
        short = 'd',
        long,
        help_heading = "Output",
        action = clap::ArgAction::Count
    )]
    pub debug: u8,

    /// Display reason codes for port status
    #[arg(long, help_heading = "Output")]
    pub reasons: bool,

    /// Show open ports in summary
    #[arg(long, help_heading = "Output")]
    pub open: bool,

    /// Show packet trace of scan
    #[arg(long, help_heading = "Output")]
    pub packet_trace: bool,

    /// Show interface list and routes
    #[arg(long, help_heading = "Output")]
    pub if_list: bool,

    // ============================================
    // Misc
    // ============================================
    /// NSE scripts to run
    #[arg(long, help_heading = "Scripting", value_name = "SCRIPTS")]
    pub script: Option<String>,

    /// Script arguments
    #[arg(long, help_heading = "Scripting", value_name = "ARGS")]
    pub script_args: Option<String>,

    /// Script update database
    #[arg(long, help_heading = "Scripting")]
    pub script_updatedb: bool,

    /// Script help for specified script
    #[arg(long, help_heading = "Scripting", value_name = "SCRIPT")]
    pub script_help: Option<String>,

    /// Trace hop path to host
    #[arg(long, help_heading = "Misc")]
    pub traceroute: bool,

    /// Number of traceroute probes
    #[arg(long, help_heading = "Misc", value_name = "NUM")]
    pub traceroute_hops: Option<u8>,

    /// Read target specifications from file
    #[arg(short = 'i', long, help_heading = "Misc", value_name = "FILE")]
    pub input_file: Option<PathBuf>,

    /// Randomize target host order
    #[arg(long, help_heading = "Misc")]
    pub randomize_hosts: bool,

    /// Host group size
    #[arg(long, help_heading = "Misc", value_name = "NUM")]
    pub host_group_size: Option<usize>,

    /// Ping type for host discovery
    #[arg(long, help_heading = "Misc", value_name = "TYPE")]
    pub ping_type: Option<String>,

    /// Disable ping (skip host discovery)
    #[arg(long, help_heading = "Misc")]
    pub disable_ping: bool,

    /// Retry ratio for host discovery
    #[arg(long, help_heading = "Misc", value_name = "RATIO")]
    pub host_timeout: Option<u64>,

    /// Print the interacted URLs
    #[arg(long, help_heading = "Misc")]
    pub print_urls: bool,

    // ============================================
    // Scan Management (Phase 3)
    // ============================================
    /// Query scan history
    #[arg(long, help_heading = "Scan Management", conflicts_with_all = ["targets", "diff", "profile"])]
    pub history: bool,

    /// List available profiles
    #[arg(long, help_heading = "Scan Management", conflicts_with_all = ["targets", "history", "diff"])]
    pub list_profiles: bool,

    /// Validate a profile file
    #[arg(long, help_heading = "Scan Management", value_name = "FILE", conflicts_with_all = ["targets", "history", "list_profiles", "diff"])]
    pub validate_profile: Option<PathBuf>,

    /// Generate a profile template
    #[arg(long, help_heading = "Scan Management", conflicts_with_all = ["targets", "history", "list_profiles", "validate_profile", "diff"])]
    pub generate_profile: bool,

    /// Use a scan profile
    #[arg(long, help_heading = "Scan Management", value_name = "FILE", conflicts_with_all = ["history", "list_profiles", "validate_profile", "generate_profile", "diff"])]
    pub profile: Option<PathBuf>,

    /// Compare two scans
    #[arg(long, help_heading = "Scan Management", value_name = "FILES", num_args = 2, conflicts_with_all = ["history", "list_profiles", "validate_profile", "generate_profile", "profile"])]
    pub diff: Option<Vec<String>>,

    /// Compare scans from history database
    #[arg(long, help_heading = "Scan Management", value_name = "SCAN_IDS", num_args = 2, requires = "diff", conflicts_with_all = ["history", "list_profiles", "validate_profile", "generate_profile", "profile"])]
    pub from_history: Option<Vec<String>>,

    /// Diff output format
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "FORMAT",
        default_value = "text",
        requires = "diff"
    )]
    pub diff_format: String,

    /// Show only vulnerability changes in diff
    #[arg(long, help_heading = "Scan Management", requires = "diff")]
    pub vulns_only: bool,

    /// Filter history by time range (since)
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "DATE",
        requires = "history"
    )]
    pub since: Option<String>,

    /// Filter history by time range (until)
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "DATE",
        requires = "history"
    )]
    pub until: Option<String>,

    /// Filter history by target
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "TARGET",
        requires = "history"
    )]
    pub target: Option<String>,

    /// Filter history by scan type
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "TYPE",
        requires = "history"
    )]
    pub scan_type_filter: Option<String>,

    /// Limit history results
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "NUM",
        requires = "history"
    )]
    pub limit: Option<usize>,

    /// Show scan details by ID
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "SCAN_ID",
        requires = "history"
    )]
    pub scan_id: Option<String>,

    /// Database path for scan history
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "PATH",
        default_value = "~/.rustnmap/scans.db"
    )]
    pub db_path: String,

    /// Data directory for Nmap databases (nmap-services, nmap-os-db, etc.)
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "DIR",
        default_value = "~/.rustnmap"
    )]
    pub datadir: String,

    /// DNS server for local IP detection (default: 8.8.8.8:53)
    #[arg(
        long,
        help_heading = "Scan Management",
        value_name = "ADDRESS",
        default_value = "8.8.8.8:53"
    )]
    pub dns_server: String,
}

impl Args {
    /// Validate arguments and check for conflicts.
    ///
    /// # Errors
    ///
    /// Returns an error if arguments are invalid or mutually exclusive options
    /// were provided.
    pub fn validate(&self) -> Result<(), String> {
        // Validate timing level
        if let Some(timing) = self.timing {
            if timing > 5 {
                return Err(format!(
                    "Timing level must be between 0 and 5, got {timing}"
                ));
            }
        }

        // Validate version intensity
        if let Some(intensity) = self.version_intensity {
            if intensity > 9 {
                return Err(format!(
                    "Version intensity must be between 0 and 9, got {intensity}"
                ));
            }
        }

        // Validate spoof IP address
        if let Some(ref ip) = self.spoof_ip {
            ip.parse::<std::net::IpAddr>()
                .map_err(|_| format!("Invalid spoof IP address: {ip}"))?;
        }

        // Validate decoy IP addresses
        if let Some(ref decoys) = self.decoys {
            for ip_str in decoys.split(',') {
                let ip_str = ip_str.trim();
                if !ip_str.is_empty() {
                    ip_str
                        .parse::<std::net::IpAddr>()
                        .map_err(|_| format!("Invalid decoy IP address: {ip_str}"))?;
                }
            }
        }

        // Validate fragment MTU (must be between 8 and 1500)
        if let Some(mtu) = self.fragment_mtu {
            if !(8..=1500).contains(&mtu) {
                return Err(format!(
                    "Fragment MTU must be between 8 and 1500, got {mtu}"
                ));
            }
        }

        // Validate source port
        if let Some(port) = self.source_port {
            if port == 0 {
                return Err("Source port must be between 1 and 65535".to_string());
            }
        }

        Ok(())
    }

    /// Returns the scan type based on provided flags.
    #[must_use]
    pub const fn scan_type(&self) -> ScanType {
        if self.scan_udp {
            ScanType::Udp
        } else if self.scan_fin {
            ScanType::Fin
        } else if self.scan_null {
            ScanType::Null
        } else if self.scan_xmas {
            ScanType::Xmas
        } else if self.scan_maimon {
            ScanType::Maimon
        } else if self.scan_connect {
            ScanType::Connect
        } else {
            ScanType::Syn
        }
    }
}

/// Scan type enumeration derived from command-line flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// TCP SYN scan (requires root)
    Syn,
    /// TCP Connect scan (no root required)
    Connect,
    /// UDP scan
    Udp,
    /// TCP FIN scan
    Fin,
    /// TCP NULL scan
    Null,
    /// TCP XMAS scan
    Xmas,
    /// TCP MAIMON scan
    Maimon,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_validation_timing() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            timing: Some(6),
            ..Default::default()
        };
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_args_validation_valid() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            timing: Some(3),
            ..Default::default()
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_scan_type_default() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            ..Default::default()
        };
        assert_eq!(args.scan_type(), ScanType::Syn);
    }

    #[test]
    fn test_scan_type_udp() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            scan_udp: true,
            ..Default::default()
        };
        assert_eq!(args.scan_type(), ScanType::Udp);
    }

    #[test]
    fn test_scan_type_connect() {
        let args = Args {
            targets: vec!["192.168.1.1".to_string()],
            scan_connect: true,
            ..Default::default()
        };
        assert_eq!(args.scan_type(), ScanType::Connect);
    }
}
