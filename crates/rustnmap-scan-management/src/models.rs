// rustnmap-scan-management
// Copyright (C) 2026  greatwallisme

//! Data models for scan management.

use chrono::{DateTime, Utc};
use rustnmap_output::models::{HostStatus, Protocol, ScanType};
use rustnmap_output::ScanResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scan status enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Scan is running.
    Running,
    /// Scan completed successfully.
    Completed,
    /// Scan failed.
    Failed,
    /// Scan was cancelled.
    Cancelled,
}

impl Default for ScanStatus {
    fn default() -> Self {
        Self::Running
    }
}

/// Summary of a scan for list views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Unique scan identifier.
    pub id: String,
    /// Scan start time.
    pub started_at: DateTime<Utc>,
    /// Scan completion time.
    pub completed_at: Option<DateTime<Utc>>,
    /// Target specification.
    pub target_spec: String,
    /// Scan type.
    pub scan_type: ScanType,
    /// Scan status.
    pub status: ScanStatus,
    /// Number of hosts scanned.
    pub hosts_count: usize,
    /// Number of hosts up.
    pub hosts_up: usize,
    /// Number of open ports.
    pub ports_open: usize,
    /// Number of vulnerabilities found.
    pub vulnerabilities_count: usize,
    /// Profile name if used.
    pub profile_name: Option<String>,
}

/// Stored scan with full details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredScan {
    /// Unique scan identifier.
    pub id: String,
    /// Scan start time.
    pub started_at: DateTime<Utc>,
    /// Scan completion time.
    pub completed_at: Option<DateTime<Utc>>,
    /// Command line invocation.
    pub command_line: String,
    /// Target specification.
    pub target_spec: String,
    /// Scan type.
    pub scan_type: ScanType,
    /// Scan options as JSON.
    pub options_json: String,
    /// Scan status.
    pub status: ScanStatus,
    /// User who created the scan.
    pub created_by: Option<String>,
    /// Profile name if used.
    pub profile_name: Option<String>,
    /// Scan results (loaded on demand).
    #[serde(skip)]
    pub results: Option<ScanResult>,
}

impl StoredScan {
    /// Create a new stored scan from a `ScanResult`.
    pub fn from_scan_result(
        result: &ScanResult,
        target_spec: &str,
        created_by: Option<&str>,
    ) -> Self {
        let options_json = serde_json::to_string(&result.metadata).unwrap_or_default();

        Self {
            id: Uuid::new_v4().to_string(),
            started_at: result.metadata.start_time,
            completed_at: Some(result.metadata.end_time),
            command_line: result.metadata.command_line.clone(),
            target_spec: target_spec.to_string(),
            scan_type: result.metadata.scan_type,
            options_json,
            status: ScanStatus::Completed,
            created_by: created_by.map(String::from),
            profile_name: None,
            results: Some(result.clone()),
        }
    }

    /// Convert to `ScanSummary`.
    pub fn to_summary(
        &self,
        hosts_up: usize,
        ports_open: usize,
        vulns_count: usize,
    ) -> ScanSummary {
        ScanSummary {
            id: self.id.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            target_spec: self.target_spec.clone(),
            scan_type: self.scan_type,
            status: self.status,
            hosts_count: self.results.as_ref().map_or(0, |r| r.hosts.len()),
            hosts_up,
            ports_open,
            vulnerabilities_count: vulns_count,
            profile_name: self.profile_name.clone(),
        }
    }
}

/// Stored host result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHost {
    /// Database row ID.
    pub id: Option<i64>,
    /// Reference to scan ID.
    pub scan_id: String,
    /// IP address.
    pub ip_addr: String,
    /// Hostname if resolved.
    pub hostname: Option<String>,
    /// MAC address if discovered.
    pub mac_addr: Option<String>,
    /// Host status (up/down).
    pub status: String,
    /// OS match if detected.
    pub os_match: Option<String>,
    /// OS match accuracy.
    pub os_accuracy: Option<i32>,
    /// Ports for this host.
    #[serde(default)]
    pub ports: Vec<StoredPort>,
    /// Vulnerabilities for this host.
    #[serde(default)]
    pub vulnerabilities: Vec<StoredVulnerability>,
}

impl StoredHost {
    /// Create from `HostResult`.
    pub fn from_host_result(host: &rustnmap_output::HostResult, scan_id: &str) -> Self {
        let status = match host.status {
            HostStatus::Up => "up".to_string(),
            HostStatus::Down => "down".to_string(),
            HostStatus::Unknown => "unknown".to_string(),
        };

        let os_match = host.os_matches.first().map(|os| os.name.clone());
        let os_accuracy = host.os_matches.first().map(|os| i32::from(os.accuracy));

        let ports = host
            .ports
            .iter()
            .map(StoredPort::from_port_result)
            .collect();

        Self {
            id: None,
            scan_id: scan_id.to_string(),
            ip_addr: host.ip.to_string(),
            hostname: host.hostname.clone(),
            mac_addr: host.mac.as_ref().map(|m| m.address.clone()),
            status,
            os_match,
            os_accuracy,
            ports,
            vulnerabilities: Vec::new(),
        }
    }
}

/// Stored port result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPort {
    /// Database row ID.
    pub id: Option<i64>,
    /// Reference to host ID.
    pub host_id: Option<i64>,
    /// Port number.
    pub port: u16,
    /// Protocol (tcp/udp).
    pub protocol: String,
    /// Port state.
    pub state: String,
    /// Service name if detected.
    pub service_name: Option<String>,
    /// Service version if detected.
    pub service_version: Option<String>,
    /// CPE string if detected.
    pub cpe: Option<String>,
    /// Reason for state determination.
    pub reason: Option<String>,
}

impl StoredPort {
    /// Create from `PortResult`.
    pub fn from_port_result(port: &rustnmap_output::PortResult) -> Self {
        let protocol = match port.protocol {
            Protocol::Tcp => "tcp".to_string(),
            Protocol::Udp => "udp".to_string(),
            Protocol::Sctp => "sctp".to_string(),
        };

        let state = format!("{:?}", port.state);

        Self {
            id: None,
            host_id: None,
            port: port.number,
            protocol,
            state,
            service_name: port.service.as_ref().map(|s| s.name.clone()),
            service_version: port.service.as_ref().and_then(|s| s.version.clone()),
            cpe: port.service.as_ref().and_then(|s| s.cpe.first().cloned()),
            reason: Some(port.state_reason.clone()),
        }
    }
}

/// Stored vulnerability result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVulnerability {
    /// Database row ID.
    pub id: Option<i64>,
    /// Reference to host ID.
    pub host_id: Option<i64>,
    /// CVE identifier.
    pub cve_id: String,
    /// CVSS v3 score.
    pub cvss_v3: Option<f64>,
    /// EPSS score.
    pub epss_score: Option<f64>,
    /// Is in CISA KEV catalog.
    pub is_kev: bool,
    /// Affected CPE.
    pub affected_cpe: Option<String>,
}

impl StoredVulnerability {
    /// Create from `VulnInfo`.
    pub fn from_vuln_info(vuln: &rustnmap_vuln::VulnInfo, host_id: i64) -> Self {
        Self {
            id: None,
            host_id: Some(host_id),
            cve_id: vuln.cve_id.clone(),
            cvss_v3: Some(f64::from(vuln.cvss_v3)),
            epss_score: Some(f64::from(vuln.epss_score)),
            is_kev: vuln.is_kev,
            affected_cpe: Some(vuln.affected_cpe.clone()),
        }
    }
}
