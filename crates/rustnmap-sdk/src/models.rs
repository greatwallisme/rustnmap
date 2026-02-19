//! Scan result models

use chrono::{DateTime, Utc};
use rustnmap_output::models::{PortState, ScanStatistics};

/// Scan result containing all hosts and statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanOutput {
    /// Scan ID
    pub id: String,

    /// Scan status
    pub status: ScanStatus,

    /// Start time
    pub started_at: DateTime<Utc>,

    /// End time
    pub completed_at: Option<DateTime<Utc>>,

    /// Host results
    pub hosts: Vec<HostResult>,

    /// Scan statistics
    pub statistics: ScanStatistics,
}

impl ScanOutput {
    /// Get all open ports across all hosts
    #[must_use]
    pub fn all_open_ports(&self) -> Vec<(&HostResult, &PortResult)> {
        self.hosts
            .iter()
            .flat_map(|host| {
                host.ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(move |port| (host, port))
            })
            .collect()
    }

    /// Get high-risk hosts (hosts with KEV vulnerabilities or CVSS >= 7.0)
    #[must_use]
    pub fn high_risk_hosts(&self) -> Vec<&HostResult> {
        self.hosts
            .iter()
            .filter(|h| h.has_high_risk_vulnerabilities())
            .collect()
    }

    /// Get hosts with a specific service
    #[must_use]
    pub fn hosts_with_service(&self, service: &str) -> Vec<&HostResult> {
        self.hosts
            .iter()
            .filter(|h| h.has_service(service))
            .collect()
    }

    /// Export to JSON string
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> crate::error::ScanResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::ScanError::InternalError(e.into()))
    }

    /// Export to XML string
    ///
    /// # Errors
    ///
    /// Returns an error if XML serialization fails.
    pub fn to_xml(&self) -> crate::error::ScanResult<String> {
        use std::fmt::Write;

        // Simple XML serialization
        let mut xml = String::new();
        writeln!(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(xml, "<scan_result>")?;
        writeln!(xml, "  <id>{}</id>", self.id)?;
        writeln!(xml, "  <status>{:?}</status>", self.status)?;
        writeln!(
            xml,
            "  <started_at>{}</started_at>",
            self.started_at.to_rfc3339()
        )?;
        writeln!(xml, "  <hosts>")?;
        for host in &self.hosts {
            writeln!(
                xml,
                "    <host ip=\"{}\" status=\"{:?}\">",
                host.ip, host.status
            )?;
            writeln!(xml, "      <ports>")?;
            for port in &host.ports {
                writeln!(
                    xml,
                    "        <port number=\"{}\" state=\"{:?}\" />",
                    port.port, port.state
                )?;
            }
            writeln!(xml, "      </ports>")?;
            writeln!(xml, "    </host>")?;
        }
        writeln!(xml, "  </hosts>")?;
        write!(xml, "</scan_result>")?;
        Ok(xml)
    }
}

/// Scan status
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

/// Host scan result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostResult {
    /// IP address
    pub ip: std::net::IpAddr,

    /// Hostname
    pub hostname: Option<String>,

    /// MAC address
    pub mac: Option<String>,

    /// Host status
    pub status: HostStatus,

    /// Port results
    pub ports: Vec<PortResult>,

    /// OS match
    pub os: Option<OsMatch>,

    /// Vulnerabilities
    pub vulnerabilities: Vec<VulnInfo>,
}

impl HostResult {
    /// Get open ports
    #[must_use]
    pub fn open_ports(&self) -> Vec<&PortResult> {
        self.ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .collect()
    }

    /// Get high-risk vulnerabilities
    #[must_use]
    pub fn high_risk_vulnerabilities(&self) -> Vec<&VulnInfo> {
        self.vulnerabilities
            .iter()
            .filter(|v| v.is_high_risk())
            .collect()
    }

    /// Check if host has high-risk vulnerabilities
    #[must_use]
    pub fn has_high_risk_vulnerabilities(&self) -> bool {
        self.vulnerabilities.iter().any(VulnInfo::is_high_risk)
    }

    /// Check if host has a specific service
    #[must_use]
    pub fn has_service(&self, service: &str) -> bool {
        self.ports
            .iter()
            .any(|p| p.service.as_ref().is_some_and(|s| s.name == service))
    }
}

/// Host status
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    Unknown,
}

/// Port result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortResult {
    /// Port number
    pub port: u16,

    /// Protocol
    pub protocol: Protocol,

    /// Port state
    pub state: PortState,

    /// Service information
    pub service: Option<ServiceInfo>,
}

/// Protocol
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

/// Service information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceInfo {
    /// Service name
    pub name: String,

    /// Product name
    pub product: Option<String>,

    /// Version
    pub version: Option<String>,

    /// Extra info
    pub extra_info: Option<String>,

    /// CPE identifiers
    pub cpe: Vec<String>,
}

/// OS match
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsMatch {
    /// OS name
    pub name: String,

    /// Accuracy percentage
    pub accuracy: u8,

    /// CPE identifiers
    pub cpe: Vec<String>,
}

/// Vulnerability information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnInfo {
    /// CVE ID
    pub cve_id: String,

    /// CVSS v3 score
    pub cvss_v3: f32,

    /// EPSS score
    pub epss_score: Option<f32>,

    /// Whether it's in CISA KEV catalog
    pub is_kev: bool,

    /// Risk priority score
    pub risk_priority: f32,
}

impl VulnInfo {
    /// Check if vulnerability is high risk (CVSS >= 7.0 or in KEV)
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.cvss_v3 >= 7.0 || self.is_kev
    }
}
