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

//! Data models for scan results.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Complete scan result containing all information about the scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[expect(clippy::derivable_impls, reason = "Manual Default implementation is clearer for this complex struct")]
pub struct ScanResult {
    /// Scan metadata (version, timing, etc.)
    pub metadata: ScanMetadata,
    /// Results for each scanned host
    pub hosts: Vec<HostResult>,
    /// Scan statistics
    pub statistics: ScanStatistics,
    /// Any errors that occurred during scanning
    pub errors: Vec<ScanError>,
}

/// Metadata about the scan itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Scanner version string
    pub scanner_version: String,
    /// Original command line invocation
    pub command_line: String,
    /// Scan start time
    pub start_time: DateTime<Utc>,
    /// Scan end time
    pub end_time: DateTime<Utc>,
    /// Total elapsed time
    pub elapsed: Duration,
    /// Type of scan performed
    pub scan_type: ScanType,
    /// Protocol used for scanning
    pub protocol: Protocol,
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            command_line: String::new(),
            start_time: Utc::now(),
            end_time: Utc::now(),
            elapsed: Duration::default(),
            scan_type: ScanType::TcpSyn,
            protocol: Protocol::Tcp,
        }
    }
}

/// Type of scan performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    /// TCP SYN scan (stealth)
    TcpSyn,
    /// TCP Connect scan (full connection)
    TcpConnect,
    /// TCP FIN scan
    TcpFin,
    /// TCP NULL scan
    TcpNull,
    /// TCP XMAS scan
    TcpXmas,
    /// TCP Maimon scan
    TcpMaimon,
    /// UDP scan
    Udp,
    /// SCTP INIT scan
    SctpInit,
    /// SCTP COOKIE scan
    SctpCookie,
    /// IP protocol scan
    IpProtocol,
    /// Ping scan (host discovery only)
    Ping,
    /// ACK scan (firewall detection)
    TcpAck,
    /// Window scan
    TcpWindow,
}

/// Network protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol
    Tcp,
    /// User Datagram Protocol
    Udp,
    /// Stream Control Transmission Protocol
    Sctp,
}

/// Result for a single scanned host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    /// IP address of the host
    pub ip: IpAddr,
    /// MAC address (if available)
    pub mac: Option<MacAddress>,
    /// Hostname (if reverse DNS was performed)
    pub hostname: Option<String>,
    /// Host status (up/down)
    pub status: HostStatus,
    /// Reason for status determination
    pub status_reason: String,
    /// Network latency to host
    pub latency: Duration,
    /// Port scan results
    pub ports: Vec<PortResult>,
    /// OS detection matches
    pub os_matches: Vec<OsMatch>,
    /// NSE script results
    pub scripts: Vec<ScriptResult>,
    /// Traceroute results
    pub traceroute: Option<TracerouteResult>,
    /// Timing information
    pub times: HostTimes,
}

/// MAC address information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddress {
    /// MAC address bytes
    pub address: String,
    /// Vendor name (from OUI lookup)
    pub vendor: Option<String>,
}

/// Host status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    /// Host is up
    Up,
    /// Host is down
    Down,
    /// Host status unknown
    Unknown,
}

/// Port scan result for a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// Port number
    pub number: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Port state
    pub state: PortState,
    /// Reason for state determination
    pub state_reason: String,
    /// TTL from response
    pub state_ttl: Option<u8>,
    /// Service information (if detected)
    pub service: Option<ServiceInfo>,
    /// NSE script results for this port
    pub scripts: Vec<ScriptResult>,
}

/// Port state following Nmap's 10-state model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// Port is open
    Open,
    /// Port is closed
    Closed,
    /// Port is filtered (no response)
    Filtered,
    /// Port is unfiltered (probes work but state uncertain)
    Unfiltered,
    /// Port is open or filtered
    OpenOrFiltered,
    /// Port is closed or filtered
    ClosedOrFiltered,
    /// Port is open or closed (conflicting responses)
    OpenOrClosed,
    /// Port is filtered or closed
    FilteredOrClosed,
    /// Port state unknown
    Unknown,
}

/// Service detection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name (e.g., "http", "ssh")
    pub name: String,
    /// Product name (e.g., "nginx", "OpenSSH")
    pub product: Option<String>,
    /// Version string (e.g., "1.18.0", "8.9p1")
    pub version: Option<String>,
    /// Extra info (e.g., "Ubuntu Linux")
    pub extrainfo: Option<String>,
    /// Hostname from service banner
    pub hostname: Option<String>,
    /// Operating system type
    pub ostype: Option<String>,
    /// Device type
    pub devicetype: Option<String>,
    /// Detection method used
    pub method: String,
    /// Confidence level (1-10)
    pub confidence: u8,
    /// CPE identifiers
    pub cpe: Vec<String>,
}

/// NSE script execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// Script ID (filename without extension)
    pub id: String,
    /// Script output
    pub output: String,
    /// Structured output elements (tables)
    pub elements: Vec<ScriptElement>,
}

/// Structured element from NSE script output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptElement {
    /// Element key
    pub key: String,
    /// Element value
    pub value: serde_json::Value,
}

/// OS detection match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    /// OS name/description
    pub name: String,
    /// Accuracy percentage (0-100)
    pub accuracy: u8,
    /// OS family (e.g., "Linux", "Windows")
    pub os_family: Option<String>,
    /// OS generation (e.g., "5.X", "10")
    pub os_generation: Option<String>,
    /// Manufacturer/manufacturer type
    pub vendor: Option<String>,
    /// Device type
    pub device_type: Option<String>,
    /// CPE identifiers
    pub cpe: Vec<String>,
}

/// Traceroute hop information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    /// Hop number (TTL)
    pub ttl: u8,
    /// IP address of hop
    pub ip: IpAddr,
    /// Hostname (if resolved)
    pub hostname: Option<String>,
    /// Round-trip time
    pub rtt: Option<Duration>,
}

/// Traceroute results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    /// Protocol used for traceroute
    pub protocol: Protocol,
    /// Port used for traceroute
    pub port: u16,
    /// List of hops
    pub hops: Vec<TracerouteHop>,
}

/// Host timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostTimes {
    /// Smoothed round-trip time (microseconds)
    pub srtt: Option<u64>,
    /// Round-trip time variance (microseconds)
    pub rttvar: Option<u64>,
    /// Timeout value (microseconds)
    pub timeout: Option<u64>,
}

/// Overall scan statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total hosts scanned
    pub total_hosts: usize,
    /// Hosts that are up
    pub hosts_up: usize,
    /// Hosts that are down
    pub hosts_down: usize,
    /// Total ports scanned
    pub total_ports: u64,
    /// Open ports found
    pub open_ports: u64,
    /// Closed ports found
    pub closed_ports: u64,
    /// Filtered ports found
    pub filtered_ports: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
}

/// Error that occurred during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    /// Error message
    pub message: String,
    /// Target that caused the error
    pub target: Option<String>,
    /// Timestamp of error
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_default() {
        let result = ScanResult::default();
        assert_eq!(result.hosts.len(), 0);
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn test_port_state_serialization() {
        let state = PortState::Open;
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("open"));
    }

    #[test]
    fn test_host_status_display() {
        assert_eq!(HostStatus::Up, HostStatus::Up);
        assert_eq!(HostStatus::Down, HostStatus::Down);
    }

    #[test]
    fn test_protocol_serialization() {
        let proto = Protocol::Tcp;
        let json = serde_json::to_string(&proto).unwrap();
        assert!(json.contains("tcp"));
    }

    #[test]
    fn test_scan_type_equality() {
        assert_eq!(ScanType::TcpSyn, ScanType::TcpSyn);
        assert_ne!(ScanType::TcpSyn, ScanType::TcpConnect);
    }

    #[test]
    fn test_service_info_empty_cpe() {
        let service = ServiceInfo {
            name: "http".to_string(),
            product: None,
            version: None,
            extrainfo: None,
            hostname: None,
            ostype: None,
            devicetype: None,
            method: "probed".to_string(),
            confidence: 10,
            cpe: Vec::new(),
        };
        assert!(service.cpe.is_empty());
    }

    #[test]
    fn test_os_match_fields() {
        let os_match = OsMatch {
            name: "Linux 5.4".to_string(),
            accuracy: 99,
            os_family: Some("Linux".to_string()),
            os_generation: Some("5.X".to_string()),
            vendor: None,
            device_type: None,
            cpe: Vec::new(),
        };
        assert_eq!(os_match.accuracy, 99);
        assert_eq!(os_match.os_family.as_deref(), Some("Linux"));
    }
}
