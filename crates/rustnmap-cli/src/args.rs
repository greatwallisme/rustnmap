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

//! Command-line argument parsing for `RustNmap`.
//!
//! This module provides comprehensive Nmap-compatible argument parsing
//! using lexopt for proper compound short option support.

use crate::help::{print_help, print_version};
use lexopt::{Arg, Parser, ValueExt};
use std::path::PathBuf;

/// Output format specification for nmap-compatible `-o` options.
///
/// Represents the parsed result of `-oN`, `-oX`, `-oG`, or `-oA` options.
#[derive(Debug, Clone)]
pub enum OutputFormat {
    /// Normal output (-oN)
    Normal(PathBuf),
    /// XML output (-oX)
    Xml(PathBuf),
    /// Grepable output (-oG)
    Grepable(PathBuf),
    /// All formats (-oA), takes basename and outputs to .nmap, .xml, .gnmap
    All(PathBuf),
    /// JSON output (-oJ)
    Json(PathBuf),
}

impl OutputFormat {
    /// Returns the file path for this output format.
    #[must_use]
    pub const fn path(&self) -> &PathBuf {
        match self {
            Self::Normal(p) | Self::Xml(p) | Self::Grepable(p) | Self::All(p) | Self::Json(p) => p,
        }
    }
}

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
#[derive(Debug, Clone, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Args is a CLI argument struct with independent boolean flags"
)]
pub struct Args {
    /// Target hosts to scan
    pub targets: Vec<String>,

    // Scan Types
    /// TCP SYN scan (default with root)
    pub scan_syn: bool,
    /// TCP Connect scan (default without root)
    pub scan_connect: bool,
    /// UDP scan
    pub scan_udp: bool,
    /// TCP FIN scan
    pub scan_fin: bool,
    /// TCP NULL scan
    pub scan_null: bool,
    /// TCP XMAS scan
    pub scan_xmas: bool,
    /// TCP MAIMON scan
    pub scan_maimon: bool,
    /// TCP ACK scan
    pub scan_ack: bool,
    /// TCP Window scan
    pub scan_window: bool,
    /// FTP Bounce scan (-b username:password@host:port)
    pub ftp_bounce: Option<String>,
    /// Scan type from -s option (S, T, U, F, N, X, M, A, W, V, C)
    pub scan_type: Option<String>,

    // Port Specification
    /// Ports to scan (e.g., -p 22,80,443 or -p 1-1000)
    pub ports: Option<String>,
    /// Scan all 65535 ports
    pub port_range_all: bool,
    /// Exclude specified ports from scan
    pub exclude_port: Option<String>,
    /// Top N most common ports
    pub top_ports: Option<u16>,
    /// Scan fewer ports than the default scan (top 100)
    pub fast_scan: bool,
    /// Scan the specified protocol
    pub protocol: Option<String>,
    /// Scan ports sequentially (don't randomize)
    pub sequential_ports: bool,

    // Service/OS Detection
    /// Aggressive scan options
    pub aggressive_scan: bool,
    /// Probe open ports to determine service/version info
    pub service_detection: bool,
    /// Intensity level of service detection (0-9)
    pub version_intensity: Option<u8>,
    /// Detect operating system
    pub os_detection: bool,
    /// Limit OS detection to promising targets
    pub osscan_limit: bool,
    /// Guess OS more aggressively
    pub osscan_guess: bool,

    // Timing and Performance
    /// Timing template (0-5, higher is faster)
    pub timing: Option<u8>,
    /// Minimum milliseconds between probes
    pub scan_delay: Option<u64>,
    /// Maximum milliseconds overall probe timeout
    pub min_parallelism: Option<usize>,
    /// Maximum number of parallel probes
    pub max_parallelism: Option<usize>,
    /// Minimum rate (packets per second)
    pub min_rate: Option<u64>,
    /// Maximum rate (packets per second)
    pub max_rate: Option<u64>,

    // Firewall/IDS Evasion
    /// Decoy scan with multiple hosts
    pub decoys: Option<String>,
    /// Spoof source address
    pub spoof_ip: Option<String>,
    /// Use specified interface
    pub interface: Option<String>,
    /// Fragment packets (MTU)
    pub fragment_mtu: Option<u16>,
    /// Specify source port number
    pub source_port: Option<u16>,
    /// Use specific data length
    pub data_length: Option<usize>,
    /// Send packets with bogus TCP/UDP/SCTP checksum
    pub badsum: bool,
    /// Append custom binary data to packets
    pub data_hex: Option<String>,
    /// Append custom string data to packets
    pub data_string: Option<String>,

    // Output Formats
    /// Output file in specified format
    pub output: Option<OutputFormat>,
    /// JSON output to file
    pub output_json: Option<PathBuf>,
    /// NDJSON output to file
    pub output_ndjson: Option<PathBuf>,
    /// Markdown output to file
    pub output_markdown: Option<PathBuf>,
    /// Script Kiddie output
    pub output_script_kiddie: bool,
    /// No output (suppress default output)
    pub no_output: bool,
    /// Enable streaming output
    pub stream: bool,
    /// Append to output files
    pub append_output: bool,
    /// Increase verbosity level
    pub verbose: u8,
    /// Decrease verbosity level
    pub quiet: bool,
    /// Increase debugging level
    pub debug: u8,
    /// Display reason codes for port status
    pub reasons: bool,
    /// Show open ports in summary
    pub open: bool,
    /// Show packet trace of scan
    pub packet_trace: bool,
    /// Show interface list and routes
    pub if_list: bool,

    // Scripting
    /// NSE scripts to run
    pub script: Option<String>,
    /// Run default script set
    pub script_default: bool,
    /// Script arguments
    pub script_args: Option<String>,
    /// Script update database
    pub script_updatedb: bool,
    /// Script help for specified script
    pub script_help: Option<String>,
    /// Script execution timeout
    pub script_timeout: Option<String>,

    // Misc
    /// Trace hop path to host
    pub traceroute: bool,
    /// Number of traceroute probes
    pub traceroute_hops: Option<u8>,
    /// Read target specifications from file
    pub input_file: Option<PathBuf>,
    /// Randomize target host order
    pub randomize_hosts: bool,
    /// Host group size
    pub host_group_size: Option<usize>,
    /// Ping type for host discovery
    pub ping_type: Option<String>,
    /// Disable ping (skip host discovery)
    pub disable_ping: bool,
    /// Ping scan - disable port scan (-sn, equivalent to nmap's noportscan)
    pub no_port_scan: bool,
    /// Retry ratio for host discovery
    pub host_timeout: Option<u64>,
    /// Print the interacted URLs
    pub print_urls: bool,
    /// Never do DNS resolution
    pub no_dns: bool,
    /// Always do DNS resolution
    pub always_dns: bool,

    // Scan Management
    /// Query scan history
    pub history: bool,
    /// List available profiles
    pub list_profiles: bool,
    /// Validate a profile file
    pub validate_profile: Option<PathBuf>,
    /// Generate a profile template
    pub generate_profile: bool,
    /// Use a scan profile
    pub profile: Option<PathBuf>,
    /// Compare two scans
    pub diff: Option<Vec<String>>,
    /// Compare scans from history database
    pub from_history: Option<Vec<String>>,
    /// Diff output format
    pub diff_format: String,
    /// Show only vulnerability changes in diff
    pub vulns_only: bool,
    /// Filter history by time range (since)
    pub since: Option<String>,
    /// Filter history by time range (until)
    pub until: Option<String>,
    /// Filter history by target
    pub target: Option<String>,
    /// Filter history by scan type
    pub scan_type_filter: Option<String>,
    /// Limit history results
    pub limit: Option<usize>,
    /// Show scan details by ID
    pub scan_id: Option<String>,
    /// Database path for scan history
    pub db_path: String,
    /// Data directory for Nmap databases
    pub datadir: String,
    /// DNS server for local IP detection
    pub dns_server: String,
}

/// Error type for argument parsing.
#[derive(Debug)]
pub enum ParseError {
    /// Unknown option
    UnknownOption(String),
    /// Missing required value for option
    MissingValue(String),
    /// Invalid value for option
    InvalidValue(String, String),
    /// IO error
    Io(std::io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnknownOption(opt) => write!(f, "Unknown option: {opt}"),
            Self::MissingValue(opt) => write!(f, "Option {opt} requires a value"),
            Self::InvalidValue(opt, value) => write!(f, "Invalid value '{value}' for option {opt}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<lexopt::Error> for ParseError {
    fn from(e: lexopt::Error) -> Self {
        Self::UnknownOption(e.to_string())
    }
}

impl Args {
    /// Parse command-line arguments from environment.
    ///
    /// # Errors
    ///
    /// Returns an error if argument parsing fails or help/version was requested
    /// (in which case the function prints and exits).
    #[expect(
        clippy::too_many_lines,
        reason = "Argument parsing requires handling all CLI options"
    )]
    pub fn parse() -> Result<Self, ParseError> {
        let mut args = Self::default();
        let mut parser = Parser::from_env();

        // Set default values
        args.db_path = "~/.rustnmap/scans.db".to_string();
        args.datadir = "~/.rustnmap".to_string();
        args.dns_server = "8.8.8.8:53".to_string();
        args.diff_format = "text".to_string();

        while let Some(arg) = parser.next()? {
            match arg {
                // Help
                Arg::Short('h') | Arg::Long("help") => {
                    print_help()?;
                    std::process::exit(0);
                }

                // Version
                Arg::Short('V') | Arg::Long("version") => {
                    print_version()?;
                    std::process::exit(0);
                }

                // Compound scan options (-sS, -sT, -sU, -sV, -sC, -sF, -sN, -sX, -sM, -sA, -sW)
                Arg::Short('s') => {
                    // Check for attached value first (e.g., -sT where T is attached to -s)
                    if let Some(attached) = parser.optional_value() {
                        let scan_chars = attached.to_string_lossy();
                        for ch in scan_chars.chars() {
                            match ch {
                                'S' => args.scan_syn = true,
                                'T' => args.scan_connect = true,
                                'U' => args.scan_udp = true,
                                'V' => args.service_detection = true,
                                'C' => args.script_default = true,
                                'F' => args.scan_fin = true,
                                'N' => args.scan_null = true,
                                'X' => args.scan_xmas = true,
                                'M' => args.scan_maimon = true,
                                'A' => args.scan_ack = true,
                                'W' => args.scan_window = true,
                                'n' | 'P' => args.no_port_scan = true,
                                _ => {
                                    args.scan_type = Some(ch.to_string());
                                }
                            }
                        }
                    } else {
                        // Standalone -s needs a value
                        let value = parser.value()?.string()?;
                        args.scan_type = Some(value);
                    }
                }

                // Compound output options (-oN file, -oX file, -oG file, -oA file)
                Arg::Short('o') => {
                    // Check for attached format char first (e.g., -oN where N is attached)
                    if let Some(format_os) = parser.optional_value() {
                        let format_char = format_os.to_string_lossy();
                        let path = PathBuf::from(parser.value()?.string()?);

                        match format_char.as_ref() {
                            "N" => args.output = Some(OutputFormat::Normal(path)),
                            "X" => args.output = Some(OutputFormat::Xml(path)),
                            "G" => args.output = Some(OutputFormat::Grepable(path)),
                            "A" => args.output = Some(OutputFormat::All(path)),
                            "J" => args.output = Some(OutputFormat::Json(path)),
                            _ => return Err(ParseError::UnknownOption(format!("-o{format_char}"))),
                        }
                    } else {
                        // --output long form or -o with space
                        let value = parser.value()?;
                        // Try parsing as format:path
                        let value_str = value.string()?;
                        if let Some((format, path)) = value_str.split_once(':') {
                            let path = PathBuf::from(path);
                            match format {
                                "N" => args.output = Some(OutputFormat::Normal(path)),
                                "X" => args.output = Some(OutputFormat::Xml(path)),
                                "G" => args.output = Some(OutputFormat::Grepable(path)),
                                "A" => args.output = Some(OutputFormat::All(path)),
                                "J" => args.output = Some(OutputFormat::Json(path)),
                                _ => return Err(ParseError::UnknownOption(format!("-o{format}"))),
                            }
                        } else {
                            return Err(ParseError::InvalidValue("-o".to_string(), value_str));
                        }
                    }
                }

                // Timing template (-T0 through -T5)
                Arg::Short('T') => {
                    // Check if value is attached (e.g., -T4)
                    if let Some(timing_os) = parser.optional_value() {
                        let timing_str = timing_os.to_string_lossy();
                        if let Ok(timing) = timing_str.parse::<u8>() {
                            if timing <= 5 {
                                args.timing = Some(timing);
                            } else {
                                return Err(ParseError::InvalidValue(
                                    "-T".to_string(),
                                    timing_str.to_string(),
                                ));
                            }
                        } else {
                            return Err(ParseError::InvalidValue(
                                "-T".to_string(),
                                timing_str.to_string(),
                            ));
                        }
                    } else {
                        // Separate value
                        let timing = parser.value()?.string()?;
                        if let Ok(timing_val) = timing.parse::<u8>() {
                            if timing_val <= 5 {
                                args.timing = Some(timing_val);
                            } else {
                                return Err(ParseError::InvalidValue("-T".to_string(), timing));
                            }
                        } else {
                            return Err(ParseError::InvalidValue("-T".to_string(), timing));
                        }
                    }
                }

                // Aggressive scan
                Arg::Short('A') => {
                    args.aggressive_scan = true;
                }

                // Verbosity
                Arg::Short('v') | Arg::Long("verbose") => {
                    args.verbose += 1;
                }

                // Quiet
                Arg::Short('q') | Arg::Long("quiet") => {
                    args.quiet = true;
                }

                // Debug
                Arg::Short('d') | Arg::Long("debug") => {
                    args.debug += 1;
                }

                // Port specification
                Arg::Short('p') | Arg::Long("ports") => {
                    args.ports = Some(parser.value()?.string()?);
                }

                // Fast scan
                Arg::Short('F') | Arg::Long("fast-scan") => {
                    args.fast_scan = true;
                }

                // Sequential ports
                Arg::Short('r') | Arg::Long("sequential-ports") => {
                    args.sequential_ports = true;
                }

                // Service detection (-sV is handled above)
                Arg::Long("service-detection" | "version-detection") => {
                    args.service_detection = true;
                }

                // Version intensity
                Arg::Long("version-intensity") => {
                    let intensity = parser.value()?.string()?;
                    if let Ok(val) = intensity.parse::<u8>() {
                        if val <= 9 {
                            args.version_intensity = Some(val);
                        } else {
                            return Err(ParseError::InvalidValue(
                                "--version-intensity".to_string(),
                                intensity,
                            ));
                        }
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--version-intensity".to_string(),
                            intensity,
                        ));
                    }
                }

                // OS detection
                Arg::Short('O') => {
                    args.os_detection = true;
                }
                Arg::Long("osscan-limit") => {
                    args.osscan_limit = true;
                }
                Arg::Long("osscan-guess") => {
                    args.osscan_guess = true;
                }

                // FTP Bounce scan
                Arg::Short('b') => {
                    args.ftp_bounce = Some(parser.value()?.string()?);
                }
                Arg::Short('D') | Arg::Long("decoys") => {
                    args.decoys = Some(parser.value()?.string()?);
                }

                // Spoof IP
                Arg::Short('S') | Arg::Long("spoof-ip") => {
                    args.spoof_ip = Some(parser.value()?.string()?);
                }

                // Interface
                Arg::Short('e') | Arg::Long("interface") => {
                    args.interface = Some(parser.value()?.string()?);
                }

                // Fragment MTU (-f or -f16)
                // In nmap, -f is a flag (no separate value). Use --mtu or
                // --fragment-mtu for custom MTU. We also support -f16 (attached).
                Arg::Short('f') => {
                    if let Some(mtu_os) = parser.optional_value() {
                        let mtu_str = mtu_os.to_string_lossy();
                        if let Ok(mtu) = mtu_str.parse::<u16>() {
                            args.fragment_mtu = Some(mtu);
                        } else {
                            args.fragment_mtu = Some(16);
                        }
                    } else {
                        args.fragment_mtu = Some(16);
                    }
                }
                Arg::Long("fragment-mtu" | "mtu") => {
                    let mtu = parser.value()?.string()?;
                    if let Ok(val) = mtu.parse::<u16>() {
                        args.fragment_mtu = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--fragment-mtu".to_string(), mtu));
                    }
                }

                // Source port
                Arg::Short('g') => {
                    let port = parser.value()?.string()?;
                    if let Ok(val) = port.parse::<u16>() {
                        args.source_port = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("-g".to_string(), port));
                    }
                }
                Arg::Long("source-port") => {
                    let port = parser.value()?.string()?;
                    if let Ok(val) = port.parse::<u16>() {
                        args.source_port = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--source-port".to_string(), port));
                    }
                }

                // Bad checksum
                Arg::Long("badsum") => {
                    args.badsum = true;
                }

                // Data length
                Arg::Long("data-length") => {
                    let len = parser.value()?.string()?;
                    if let Ok(val) = len.parse::<usize>() {
                        args.data_length = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--data-length".to_string(), len));
                    }
                }

                // Data hex
                Arg::Long("data-hex") => {
                    args.data_hex = Some(parser.value()?.string()?);
                }

                // Data string
                Arg::Long("data-string") => {
                    args.data_string = Some(parser.value()?.string()?);
                }

                // Scan delay
                Arg::Long("scan-delay") => {
                    let delay = parser.value()?.string()?;
                    if let Some(val) = parse_time_to_ms(&delay) {
                        args.scan_delay = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--scan-delay".to_string(), delay));
                    }
                }

                // Min parallelism
                Arg::Long("min-parallelism") => {
                    let val = parser.value()?.string()?;
                    if let Ok(parsed) = val.parse::<usize>() {
                        args.min_parallelism = Some(parsed);
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--min-parallelism".to_string(),
                            val,
                        ));
                    }
                }

                // Max parallelism
                Arg::Long("max-parallelism") => {
                    let val = parser.value()?.string()?;
                    if let Ok(parsed) = val.parse::<usize>() {
                        args.max_parallelism = Some(parsed);
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--max-parallelism".to_string(),
                            val,
                        ));
                    }
                }

                // Min rate
                Arg::Long("min-rate") => {
                    let rate = parser.value()?.string()?;
                    if let Ok(val) = rate.parse::<u64>() {
                        args.min_rate = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--min-rate".to_string(), rate));
                    }
                }

                // Max rate
                Arg::Long("max-rate") => {
                    let rate = parser.value()?.string()?;
                    if let Ok(val) = rate.parse::<u64>() {
                        args.max_rate = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--max-rate".to_string(), rate));
                    }
                }

                // Exclude ports (nmap accepts both --exclude-ports and --exclude-port)
                Arg::Long("exclude-ports" | "exclude-port") => {
                    args.exclude_port = Some(parser.value()?.string()?);
                }

                // Top ports
                Arg::Long("top-ports") => {
                    let num = parser.value()?.string()?;
                    if let Ok(val) = num.parse::<u16>() {
                        args.top_ports = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--top-ports".to_string(), num));
                    }
                }

                // Protocol
                Arg::Long("protocol") => {
                    args.protocol = Some(parser.value()?.string()?);
                }

                // Port range all
                Arg::Long("port-range-all") => {
                    args.port_range_all = true;
                }

                // Output JSON
                Arg::Long("output-json") => {
                    args.output_json = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Output NDJSON
                Arg::Long("output-ndjson") => {
                    args.output_ndjson = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Output Markdown
                Arg::Long("output-markdown") => {
                    args.output_markdown = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Script kiddie output
                Arg::Long("output-script-kiddie") => {
                    args.output_script_kiddie = true;
                }

                // No output
                Arg::Long("no-output") => {
                    args.no_output = true;
                }

                // Stream output
                Arg::Long("stream") => {
                    args.stream = true;
                }

                // Append output
                Arg::Long("append-output") => {
                    args.append_output = true;
                }

                // Reasons
                Arg::Long("reason" | "reasons") => {
                    args.reasons = true;
                }

                // Open only
                Arg::Long("open") => {
                    args.open = true;
                }

                // Packet trace
                Arg::Long("packet-trace") => {
                    args.packet_trace = true;
                }

                // Interface list (nmap uses --iflist, also accept --if-list)
                Arg::Long("iflist" | "if-list") => {
                    args.if_list = true;
                }

                // Script
                Arg::Long("script") => {
                    args.script = Some(parser.value()?.string()?);
                }

                // Script args
                Arg::Long("script-args") => {
                    args.script_args = Some(parser.value()?.string()?);
                }

                // Script updatedb
                Arg::Long("script-updatedb") => {
                    args.script_updatedb = true;
                }

                // Script help
                Arg::Long("script-help") => {
                    args.script_help = Some(parser.value()?.string()?);
                }

                // Script timeout
                Arg::Long("script-timeout") => {
                    args.script_timeout = Some(parser.value()?.string()?);
                }

                // Traceroute
                Arg::Long("traceroute") => {
                    args.traceroute = true;
                }

                // Traceroute hops
                Arg::Long("traceroute-hops") => {
                    let hops = parser.value()?.string()?;
                    if let Ok(val) = hops.parse::<u8>() {
                        args.traceroute_hops = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--traceroute-hops".to_string(),
                            hops,
                        ));
                    }
                }

                // Input file
                Arg::Short('i') | Arg::Long("input-file") => {
                    args.input_file = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Randomize hosts
                Arg::Long("randomize-hosts") => {
                    args.randomize_hosts = true;
                }

                // Host group size
                Arg::Long("host-group-size") => {
                    let size = parser.value()?.string()?;
                    if let Ok(val) = size.parse::<usize>() {
                        args.host_group_size = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--host-group-size".to_string(),
                            size,
                        ));
                    }
                }

                // Ping type
                Arg::Long("ping-type") => {
                    args.ping_type = Some(parser.value()?.string()?);
                }

                // Disable ping (skip host discovery)
                Arg::Short('P') => {
                    // Check if it's compound like -Pn
                    if let Some(next_os) = parser.optional_value() {
                        let next_str = next_os.to_string_lossy();
                        if next_str == "n" {
                            args.disable_ping = true;
                        } else {
                            args.ping_type = Some(next_str.to_string());
                        }
                    } else {
                        // Standalone -P means disable ping in nmap
                        args.disable_ping = true;
                    }
                }
                Arg::Long("disable-ping") => {
                    args.disable_ping = true;
                }

                // Host timeout
                Arg::Long("host-timeout") => {
                    let timeout = parser.value()?.string()?;
                    if let Some(val) = parse_time_to_ms(&timeout) {
                        args.host_timeout = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue(
                            "--host-timeout".to_string(),
                            timeout,
                        ));
                    }
                }

                // Print URLs
                Arg::Long("print-urls") => {
                    args.print_urls = true;
                }

                // No DNS
                Arg::Short('n') | Arg::Long("no-dns") => {
                    args.no_dns = true;
                }

                // Always DNS
                Arg::Short('R') | Arg::Long("always-dns") => {
                    args.always_dns = true;
                }

                // DNS servers
                Arg::Long("dns-servers") => {
                    // Store but don't use - this would need different handling
                    let _servers = parser.value()?;
                }

                // History
                Arg::Long("history") => {
                    args.history = true;
                }

                // List profiles
                Arg::Long("list-profiles") => {
                    args.list_profiles = true;
                }

                // Validate profile
                Arg::Long("validate-profile") => {
                    args.validate_profile = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Generate profile
                Arg::Long("generate-profile") => {
                    args.generate_profile = true;
                }

                // Profile
                Arg::Long("profile") => {
                    args.profile = Some(PathBuf::from(parser.value()?.string()?));
                }

                // Diff
                Arg::Long("diff") => {
                    let files = vec![parser.value()?.string()?, parser.value()?.string()?];
                    args.diff = Some(files);
                }

                // From history
                Arg::Long("from-history") => {
                    let ids = vec![parser.value()?.string()?, parser.value()?.string()?];
                    args.from_history = Some(ids);
                }

                // Diff format
                Arg::Long("diff-format") => {
                    args.diff_format = parser.value()?.string()?;
                }

                // Vulns only
                Arg::Long("vulns-only") => {
                    args.vulns_only = true;
                }

                // Since
                Arg::Long("since") => {
                    args.since = Some(parser.value()?.string()?);
                }

                // Until
                Arg::Long("until") => {
                    args.until = Some(parser.value()?.string()?);
                }

                // Target (for history filtering)
                Arg::Long("target") => {
                    args.target = Some(parser.value()?.string()?);
                }

                // Scan type filter
                Arg::Long("scan-type-filter") => {
                    args.scan_type_filter = Some(parser.value()?.string()?);
                }

                // Limit
                Arg::Long("limit") => {
                    let limit = parser.value()?.string()?;
                    if let Ok(val) = limit.parse::<usize>() {
                        args.limit = Some(val);
                    } else {
                        return Err(ParseError::InvalidValue("--limit".to_string(), limit));
                    }
                }

                // Scan ID
                Arg::Long("scan-id") => {
                    args.scan_id = Some(parser.value()?.string()?);
                }

                // Database path
                Arg::Long("db-path") => {
                    args.db_path = parser.value()?.string()?;
                }

                // Data directory
                Arg::Long("datadir") => {
                    args.datadir = parser.value()?.string()?;
                }

                // DNS server
                Arg::Long("dns-server") => {
                    args.dns_server = parser.value()?.string()?;
                }

                // Positional arguments (targets)
                Arg::Value(val) => {
                    args.targets.push(val.string()?);
                }

                _ => {
                    return Err(ParseError::UnknownOption(format!("{arg:?}")));
                }
            }
        }

        Ok(args)
    }

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
                .map_err(|_e| format!("Invalid spoof IP address: {ip}"))?;
        }

        // Validate decoy IP addresses
        if let Some(ref decoys) = self.decoys {
            for part in decoys.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some(number_str) = part.strip_prefix("RND:") {
                    let count: usize = number_str
                        .parse()
                        .map_err(|_e| format!("Invalid RND number: {number_str}"))?;
                    if count == 0 || count > 100 {
                        return Err(format!("RND count must be between 1 and 100, got {count}"));
                    }
                } else {
                    part.parse::<std::net::IpAddr>()
                        .map_err(|_e| format!("Invalid decoy IP address: {part}"))?;
                }
            }
        }

        // Validate fragment MTU
        if let Some(mtu) = self.fragment_mtu {
            if !(8..=1500).contains(&mtu) {
                return Err(format!(
                    "Fragment MTU must be between 8 and 1500, got {mtu}"
                ));
            }
        }

        // Cannot specify both -p and -F (fast scan)
        if self.ports.is_some() && self.fast_scan {
            return Err(
                "Cannot specify both --ports/-p and --fast-scan/-F. Use one or the other."
                    .to_string(),
            );
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
    pub fn scan_type(&self) -> ScanType {
        // Handle FTP bounce scan (-b)
        if self.ftp_bounce.is_some() {
            return ScanType::FtpBounce;
        }

        // Handle -s TYPE option (nmap style)
        if let Some(ref scan_type_str) = self.scan_type {
            return match scan_type_str.to_uppercase().as_str() {
                "T" => ScanType::Connect,
                "U" => ScanType::Udp,
                "F" => ScanType::Fin,
                "N" => ScanType::Null,
                "X" => ScanType::Xmas,
                "M" => ScanType::Maimon,
                "A" => ScanType::Ack,
                "W" => ScanType::Window,
                _ => ScanType::Syn,
            };
        }

        // Handle boolean flags
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
        } else if self.scan_ack {
            ScanType::Ack
        } else if self.scan_window {
            ScanType::Window
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
    /// TCP ACK scan
    Ack,
    /// TCP Window scan
    Window,
    /// FTP Bounce scan
    FtpBounce,
}

/// Parses a time specification string to milliseconds, matching nmap's `tval2msecs`.
///
/// Supports the following suffixes (case-insensitive):
/// - `ms` - milliseconds (e.g., `"500ms"`)
/// - `s` or no suffix - seconds (e.g., `"30s"` or `"30"`)
/// - `m` - minutes (e.g., `"5m"`)
/// - `h` - hours (e.g., `"1h"`)
///
/// # Errors
///
/// Returns `None` if the input is empty, contains no numeric portion,
/// or uses an unrecognized suffix.
fn parse_time_to_ms(spec: &str) -> Option<u64> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }

    // Find where the numeric portion ends
    let num_end = spec
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(spec.len());

    if num_end == 0 {
        return None;
    }

    let num_str = &spec[..num_end];
    let suffix = spec[num_end..].to_ascii_lowercase();

    let value: f64 = num_str.parse().ok()?;

    let ms = match suffix.as_str() {
        "ms" => value,
        "" | "s" => value * 1_000.0,
        "m" => value * 60_000.0,
        "h" => value * 3_600_000.0,
        _ => return None,
    };

    if ms < 0.0 || !ms.is_finite() {
        return None;
    }

    // Safely convert to u64; values beyond u64 range are rejected.
    // u64::MAX is approximately 1.8e19 which far exceeds any practical
    // timeout value, so truncation at high values is acceptable.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range validated above; practical timeouts are small"
    )]
    let result = ms as u64;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_validation_timing() {
        let mut args = Args::default();
        args.targets = vec!["192.168.1.1".to_string()];
        args.timing = Some(6);
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_args_validation_valid() {
        let mut args = Args::default();
        args.targets = vec!["192.168.1.1".to_string()];
        args.timing = Some(3);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_scan_type_default() {
        let args = Args::default();
        assert_eq!(args.scan_type(), ScanType::Syn);
    }

    #[test]
    fn test_scan_type_udp() {
        let mut args = Args::default();
        args.targets = vec!["192.168.1.1".to_string()];
        args.scan_udp = true;
        assert_eq!(args.scan_type(), ScanType::Udp);
    }

    #[test]
    fn test_scan_type_connect() {
        let mut args = Args::default();
        args.targets = vec!["192.168.1.1".to_string()];
        args.scan_connect = true;
        assert_eq!(args.scan_type(), ScanType::Connect);
    }

    #[test]
    fn test_parse_time_to_ms_seconds_suffix() {
        assert_eq!(parse_time_to_ms("30s"), Some(30_000));
        assert_eq!(parse_time_to_ms("1s"), Some(1_000));
        assert_eq!(parse_time_to_ms("0s"), Some(0));
    }

    #[test]
    fn test_parse_time_to_ms_no_suffix() {
        // No suffix defaults to seconds (matching nmap behavior)
        assert_eq!(parse_time_to_ms("30"), Some(30_000));
        assert_eq!(parse_time_to_ms("5"), Some(5_000));
    }

    #[test]
    fn test_parse_time_to_ms_milliseconds() {
        assert_eq!(parse_time_to_ms("500ms"), Some(500));
        assert_eq!(parse_time_to_ms("100ms"), Some(100));
    }

    #[test]
    fn test_parse_time_to_ms_minutes() {
        assert_eq!(parse_time_to_ms("5m"), Some(300_000));
        assert_eq!(parse_time_to_ms("1m"), Some(60_000));
    }

    #[test]
    fn test_parse_time_to_ms_hours() {
        assert_eq!(parse_time_to_ms("1h"), Some(3_600_000));
    }

    #[test]
    fn test_parse_time_to_ms_case_insensitive() {
        assert_eq!(parse_time_to_ms("30S"), Some(30_000));
        assert_eq!(parse_time_to_ms("500MS"), Some(500));
        assert_eq!(parse_time_to_ms("5M"), Some(300_000));
        assert_eq!(parse_time_to_ms("1H"), Some(3_600_000));
    }

    #[test]
    fn test_parse_time_to_ms_fractional() {
        assert_eq!(parse_time_to_ms("1.5s"), Some(1_500));
        assert_eq!(parse_time_to_ms("0.5m"), Some(30_000));
    }

    #[test]
    fn test_parse_time_to_ms_invalid() {
        assert_eq!(parse_time_to_ms(""), None);
        assert_eq!(parse_time_to_ms("abc"), None);
        assert_eq!(parse_time_to_ms("30x"), None);
    }
}
