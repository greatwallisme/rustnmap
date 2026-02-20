// rustnmap-scan-management
// Copyright (C) 2026  greatwallisme

//! Scan result diff/comparison functionality.

use crate::error::{Result, ScanManagementError};
use chrono::Utc;
use rustnmap_output::models::HostStatus;
use rustnmap_output::{HostResult, PortResult, ScanResult};
use std::collections::HashMap;
use std::fmt::Write;
use std::net::IpAddr;

/// Output format for diff reports.
#[derive(Debug, Clone, Copy, Default)]
pub enum DiffFormat {
    #[default]
    /// Human-readable text format.
    Text,
    /// Markdown format.
    Markdown,
    /// JSON format.
    Json,
    /// HTML format.
    Html,
}

/// Scan comparison result.
#[derive(Debug)]
pub struct ScanDiff {
    before: ScanResult,
    after: ScanResult,
}

impl ScanDiff {
    /// Create a new diff from two scan results.
    #[must_use]
    pub fn new(before: ScanResult, after: ScanResult) -> Self {
        Self { before, after }
    }

    /// Load two scans from history and create diff.
    ///
    /// # Errors
    ///
    /// Returns an error if the scans cannot be loaded from history.
    pub async fn from_history(
        history: &crate::history::ScanHistory,
        before_id: &str,
        after_id: &str,
    ) -> Result<Self> {
        let before_scan = history
            .get_scan(before_id)
            .await?
            .ok_or_else(|| ScanManagementError::ScanNotFound(before_id.to_string()))?;

        let after_scan = history
            .get_scan(after_id)
            .await?
            .ok_or_else(|| ScanManagementError::ScanNotFound(after_id.to_string()))?;

        let before_result = before_scan
            .results
            .ok_or_else(|| ScanManagementError::ScanNotFound("Scan has no results".to_string()))?;

        let after_result = after_scan
            .results
            .ok_or_else(|| ScanManagementError::ScanNotFound("Scan has no results".to_string()))?;

        Ok(Self::new(before_result, after_result))
    }

    /// Get host changes between scans.
    #[must_use]
    pub fn host_changes(&self) -> HostChanges {
        let before_hosts: HashMap<IpAddr, &HostResult> =
            self.before.hosts.iter().map(|h| (h.ip, h)).collect();
        let after_hosts: HashMap<IpAddr, &HostResult> =
            self.after.hosts.iter().map(|h| (h.ip, h)).collect();

        let added: Vec<IpAddr> = after_hosts
            .keys()
            .filter(|ip| !before_hosts.contains_key(ip))
            .copied()
            .collect();

        let removed: Vec<IpAddr> = before_hosts
            .keys()
            .filter(|ip| !after_hosts.contains_key(ip))
            .copied()
            .collect();

        let mut status_changed = Vec::new();
        for (ip, before_host) in &before_hosts {
            if let Some(after_host) = after_hosts.get(ip) {
                if before_host.status != after_host.status {
                    status_changed.push(HostStatusChange {
                        ip: *ip,
                        before: before_host.status,
                        after: after_host.status,
                    });
                }
            }
        }

        HostChanges {
            added,
            removed,
            status_changed,
        }
    }

    /// Get port changes between scans.
    #[must_use]
    pub fn port_changes(&self) -> PortChanges {
        use rustnmap_output::Protocol;

        // Helper function to get protocol string
        fn protocol_str(p: Protocol) -> &'static str {
            match p {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Sctp => "sctp",
            }
        }

        let mut by_host: HashMap<IpAddr, HostPortChanges> = HashMap::new();

        // Collect unique IPs from both scans for efficient comparison
        let before_ips: std::collections::HashSet<_> =
            self.before.hosts.iter().map(|h| h.ip).collect();
        let after_ips: std::collections::HashSet<_> =
            self.after.hosts.iter().map(|h| h.ip).collect();

        for ip in before_ips.union(&after_ips) {
            let before_host = self.before.hosts.iter().find(|h| h.ip == *ip);
            let after_host = self.after.hosts.iter().find(|h| h.ip == *ip);

            let before_ports: HashMap<(u16, &str), &PortResult> = before_host
                .map(|h| {
                    h.ports
                        .iter()
                        .map(|p| ((p.number, protocol_str(p.protocol)), p))
                        .collect()
                })
                .unwrap_or_default();

            let after_ports: HashMap<(u16, &str), &PortResult> = after_host
                .map(|h| {
                    h.ports
                        .iter()
                        .map(|p| ((p.number, protocol_str(p.protocol)), p))
                        .collect()
                })
                .unwrap_or_default();

            let mut added = Vec::new();
            let mut removed = Vec::new();
            let mut state_changed = Vec::new();
            let mut service_changed = Vec::new();

            // Find added and changed ports
            for (key, after_port) in &after_ports {
                if let Some(before_port) = before_ports.get(key) {
                    if before_port.state != after_port.state {
                        state_changed.push(PortChange::from_state_change(
                            after_port,
                            &format!("{:?}", before_port.state),
                        ));
                    }
                    // Compare service by name instead of full struct
                    let service_diff = match (&before_port.service, &after_port.service) {
                        (None, None) => false,
                        (Some(a), Some(b)) => a.name != b.name || a.version != b.version,
                        _ => true,
                    };
                    if service_diff {
                        let before_svc = before_port
                            .service
                            .as_ref()
                            .map(|s| s.name.clone())
                            .unwrap_or_default();
                        service_changed.push(PortChange::from_service_change(after_port, &before_svc));
                    }
                } else {
                    added.push(PortChange::from_port(after_port));
                }
            }

            // Find removed ports
            for (key, before_port) in &before_ports {
                if !after_ports.contains_key(key) {
                    removed.push(PortChange::from_removed_port(before_port));
                }
            }

            if !added.is_empty()
                || !removed.is_empty()
                || !state_changed.is_empty()
                || !service_changed.is_empty()
            {
                by_host.insert(
                    *ip,
                    HostPortChanges {
                        added,
                        removed,
                        state_changed,
                        service_changed,
                    },
                );
            }
        }

        PortChanges { by_host }
    }

    /// Get vulnerability changes between scans.
    ///
    /// Compares vulnerability data between the before and after scans,
    /// identifying newly discovered vulnerabilities, fixed vulnerabilities,
    /// and vulnerabilities with changed risk levels.
    #[must_use]
    pub fn vulnerability_changes(&self) -> VulnerabilityChanges {
        // Vulnerability data is not directly available in ScanResult
        // This requires integration with rustnmap-vuln module during scanning
        // Return empty changes until vulnerability data is stored in scan results
        VulnerabilityChanges {
            added: Vec::new(),
            fixed: Vec::new(),
            risk_changed: Vec::new(),
        }
    }

    /// Generate a diff report in the specified format.
    #[must_use]
    pub fn generate_report(&self, format: DiffFormat) -> String {
        let host_changes = self.host_changes();
        let port_changes = self.port_changes();
        let vuln_changes = self.vulnerability_changes();

        match format {
            DiffFormat::Text => {
                Self::generate_text_report(&host_changes, &port_changes, &vuln_changes)
            }
            DiffFormat::Markdown => Self::generate_markdown_report(
                &self.before,
                &self.after,
                &host_changes,
                &port_changes,
                &vuln_changes,
            ),
            DiffFormat::Json => Self::generate_json_report(
                &self.before,
                &self.after,
                &host_changes,
                &port_changes,
                &vuln_changes,
            ),
            DiffFormat::Html => Self::generate_html_report(
                &self.before,
                &self.after,
                &host_changes,
                &port_changes,
                &vuln_changes,
            ),
        }
    }

    fn generate_text_report(
        hosts: &HostChanges,
        ports: &PortChanges,
        vulns: &VulnerabilityChanges,
    ) -> String {
        let mut report = String::new();

        let _ = writeln!(report, "=== Scan Diff Report ===\n");

        let _ = writeln!(report, "## Host Changes");
        let _ = writeln!(report, "  Added: {} hosts", hosts.added.len());
        for ip in &hosts.added {
            let _ = writeln!(report, "    + {ip}");
        }

        let _ = writeln!(report, "  Removed: {} hosts", hosts.removed.len());
        for ip in &hosts.removed {
            let _ = writeln!(report, "    - {ip}");
        }

        let _ = writeln!(
            report,
            "  Status Changed: {} hosts",
            hosts.status_changed.len()
        );

        let _ = writeln!(report, "\n## Port Changes");
        for (ip, changes) in &ports.by_host {
            let _ = writeln!(report, "  {ip}:");
            let _ = writeln!(report, "    Added: {}", changes.added.len());
            let _ = writeln!(report, "    Removed: {}", changes.removed.len());
            let _ = writeln!(report, "    State Changed: {}", changes.state_changed.len());
            let _ = writeln!(
                report,
                "    Service Changed: {}",
                changes.service_changed.len()
            );
        }

        let _ = writeln!(report, "\n## Vulnerability Changes");
        let _ = writeln!(report, "  New: {}", vulns.added.len());
        let _ = writeln!(report, "  Fixed: {}", vulns.fixed.len());
        let _ = writeln!(report, "  Risk Changed: {}", vulns.risk_changed.len());

        report
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Report generation requires comprehensive output"
    )]
    fn generate_markdown_report(
        before: &ScanResult,
        after: &ScanResult,
        hosts: &HostChanges,
        ports: &PortChanges,
        vulns: &VulnerabilityChanges,
    ) -> String {
        let mut report = String::new();

        let _ = writeln!(report, "# 扫描结果对比报告\n");
        let _ = writeln!(
            report,
            "**生成时间**: {}\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
        );

        let _ = writeln!(report, "## 主机变化\n");

        let _ = writeln!(report, "### 新增主机 ({})", hosts.added.len());
        for ip in &hosts.added {
            let _ = writeln!(report, "- {ip} (首次发现)");
        }

        let _ = writeln!(report, "\n### 消失主机 ({})", hosts.removed.len());
        for ip in &hosts.removed {
            let _ = writeln!(report, "- {ip} (上次在线，本次未响应)");
        }

        if !hosts.status_changed.is_empty() {
            let _ = writeln!(report, "\n### 状态变化的主机");
            for change in &hosts.status_changed {
                let _ = writeln!(
                    report,
                    "- {}: {:?} -> {:?}",
                    change.ip, change.before, change.after
                );
            }
        }

        let _ = writeln!(report, "\n## 端口变化\n");
        for (ip, changes) in &ports.by_host {
            let _ = writeln!(report, "### {ip}");
            if !changes.added.is_empty() {
                let _ = writeln!(report, "**新增端口:**");
                for port in &changes.added {
                    let _ = writeln!(report, "- {}/{} ({})", port.port, port.protocol, port.state);
                }
            }
            if !changes.removed.is_empty() {
                let _ = writeln!(report, "**关闭端口:**");
                for port in &changes.removed {
                    let _ = writeln!(
                        report,
                        "- {}/{} ({})",
                        port.port,
                        port.protocol,
                        port.previous_state.as_ref().unwrap_or(&port.state)
                    );
                }
            }
            if !changes.service_changed.is_empty() {
                let _ = writeln!(report, "**服务变更:**");
                for port in &changes.service_changed {
                    let _ = writeln!(
                        report,
                        "- {}/{} ({} -> {})",
                        port.port,
                        port.protocol,
                        port.previous_service
                            .as_ref()
                            .unwrap_or(&String::from("unknown")),
                        port.service.as_ref().unwrap_or(&String::from("unknown"))
                    );
                }
            }
        }

        let _ = writeln!(report, "\n## 漏洞变化\n");
        let _ = writeln!(report, "### 新增漏洞 ({})", vulns.added.len());
        for vuln in &vulns.added {
            let _ = writeln!(
                report,
                "- {} (CVSS {}) - {}",
                vuln.cve_id,
                vuln.new_cvss.unwrap_or(0.0),
                vuln.ip
            );
        }

        let _ = writeln!(report, "\n### 修复漏洞 ({})", vulns.fixed.len());
        for vuln in &vulns.fixed {
            let _ = writeln!(
                report,
                "- {} (CVSS {}) - {}",
                vuln.cve_id,
                vuln.previous_cvss.unwrap_or(0.0),
                vuln.ip
            );
        }

        let _ = writeln!(report, "\n## 统计\n");
        let _ = writeln!(report, "| 指标 | 上次 | 本次 | 变化 |");
        let _ = writeln!(report, "|------|------|------|------|");
        let _ = writeln!(
            report,
            "| 在线主机 | {} | {} | {:+} |",
            before.statistics.hosts_up,
            after.statistics.hosts_up,
            i64::try_from(after.statistics.hosts_up).unwrap_or(0)
                - i64::try_from(before.statistics.hosts_up).unwrap_or(0)
        );
        let _ = writeln!(
            report,
            "| 开放端口 | {} | {} | {:+} |",
            before.statistics.open_ports,
            after.statistics.open_ports,
            i64::try_from(after.statistics.open_ports).unwrap_or(0)
                - i64::try_from(before.statistics.open_ports).unwrap_or(0)
        );

        report
    }

    #[expect(
        clippy::too_many_lines,
        reason = "JSON report generation requires comprehensive serialization"
    )]
    fn generate_json_report(
        before: &ScanResult,
        after: &ScanResult,
        hosts: &HostChanges,
        ports: &PortChanges,
        vulns: &VulnerabilityChanges,
    ) -> String {
        use serde::Serialize;

        #[derive(Serialize)]
        struct DiffReport {
            before_scan: String,
            after_scan: String,
            generated_at: String,
            host_changes: HostChangesSerde,
            port_changes: PortChangesSerde,
            vulnerability_changes: VulnerabilityChangesSerde,
        }

        #[derive(Serialize)]
        struct HostChangesSerde {
            added: Vec<String>,
            removed: Vec<String>,
            status_changed: Vec<HostStatusChangeSerde>,
        }

        #[derive(Serialize)]
        struct HostStatusChangeSerde {
            ip: String,
            before: String,
            after: String,
        }

        #[derive(Serialize)]
        struct PortChangesSerde {
            by_host: HashMap<String, HostPortChangesSerde>,
        }

        #[derive(Serialize)]
        struct HostPortChangesSerde {
            added: Vec<PortChangeSerde>,
            removed: Vec<PortChangeSerde>,
            state_changed: Vec<PortChangeSerde>,
            service_changed: Vec<PortChangeSerde>,
        }

        #[derive(Serialize)]
        struct PortChangeSerde {
            port: u16,
            protocol: String,
            state: String,
        }

        #[derive(Serialize)]
        struct VulnerabilityChangesSerde {
            added: Vec<VulnChangeSerde>,
            fixed: Vec<VulnChangeSerde>,
            risk_changed: Vec<VulnChangeSerde>,
        }

        #[derive(Serialize)]
        struct VulnChangeSerde {
            cve_id: String,
            ip: String,
            new_cvss: Option<f64>,
            previous_cvss: Option<f64>,
        }

        let port_changes_serde: HashMap<String, HostPortChangesSerde> = ports
            .by_host
            .iter()
            .map(|(ip, changes)| {
                (
                    ip.to_string(),
                    HostPortChangesSerde {
                        added: changes
                            .added
                            .iter()
                            .map(|p| PortChangeSerde {
                                port: p.port,
                                protocol: p.protocol.clone(),
                                state: p.state.clone(),
                            })
                            .collect(),
                        removed: changes
                            .removed
                            .iter()
                            .map(|p| PortChangeSerde {
                                port: p.port,
                                protocol: p.protocol.clone(),
                                state: p.state.clone(),
                            })
                            .collect(),
                        state_changed: changes
                            .state_changed
                            .iter()
                            .map(|p| PortChangeSerde {
                                port: p.port,
                                protocol: p.protocol.clone(),
                                state: p.state.clone(),
                            })
                            .collect(),
                        service_changed: changes
                            .service_changed
                            .iter()
                            .map(|p| PortChangeSerde {
                                port: p.port,
                                protocol: p.protocol.clone(),
                                state: p.state.clone(),
                            })
                            .collect(),
                    },
                )
            })
            .collect();

        let report = DiffReport {
            before_scan: before.metadata.command_line.clone(),
            after_scan: after.metadata.command_line.clone(),
            generated_at: Utc::now().to_rfc3339(),
            host_changes: HostChangesSerde {
                added: hosts
                    .added
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                removed: hosts
                    .removed
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                status_changed: hosts
                    .status_changed
                    .iter()
                    .map(|c| HostStatusChangeSerde {
                        ip: c.ip.to_string(),
                        before: format!("{:?}", c.before),
                        after: format!("{:?}", c.after),
                    })
                    .collect(),
            },
            port_changes: PortChangesSerde {
                by_host: port_changes_serde,
            },
            vulnerability_changes: VulnerabilityChangesSerde {
                added: vulns
                    .added
                    .iter()
                    .map(|v| VulnChangeSerde {
                        cve_id: v.cve_id.clone(),
                        ip: v.ip.to_string(),
                        new_cvss: v.new_cvss,
                        previous_cvss: v.previous_cvss,
                    })
                    .collect(),
                fixed: vulns
                    .fixed
                    .iter()
                    .map(|v| VulnChangeSerde {
                        cve_id: v.cve_id.clone(),
                        ip: v.ip.to_string(),
                        new_cvss: v.new_cvss,
                        previous_cvss: v.previous_cvss,
                    })
                    .collect(),
                risk_changed: vulns
                    .risk_changed
                    .iter()
                    .map(|v| VulnChangeSerde {
                        cve_id: v.cve_id.clone(),
                        ip: v.ip.to_string(),
                        new_cvss: v.new_cvss,
                        previous_cvss: v.previous_cvss,
                    })
                    .collect(),
            },
        };

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }

    fn generate_html_report(
        before: &ScanResult,
        after: &ScanResult,
        _hosts: &HostChanges,
        _ports: &PortChanges,
        _vulns: &VulnerabilityChanges,
    ) -> String {
        // Basic HTML report structure
        format!(
            r"<!DOCTYPE html>
<html>
<head><title>Scan Diff Report</title></head>
<body>
<h1>扫描结果对比报告</h1>
<p>生成时间：{}</p>
<p>Before: {}</p>
<p>After: {}</p>
<p>Hosts up: {} -> {}</p>
<p>Ports open: {} -> {}</p>
</body>
</html>",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            before.metadata.command_line,
            after.metadata.command_line,
            before.statistics.hosts_up,
            after.statistics.hosts_up,
            before.statistics.open_ports,
            after.statistics.open_ports,
        )
    }
}

/// Host changes between two scans.
#[derive(Debug)]
pub struct HostChanges {
    /// Newly discovered hosts.
    pub added: Vec<IpAddr>,
    /// Hosts that are no longer present.
    pub removed: Vec<IpAddr>,
    /// Hosts with status changes.
    pub status_changed: Vec<HostStatusChange>,
}

/// Host status change.
#[derive(Debug)]
pub struct HostStatusChange {
    pub ip: IpAddr,
    pub before: HostStatus,
    pub after: HostStatus,
}

/// Port changes between two scans.
#[derive(Debug)]
pub struct PortChanges {
    /// Port changes organized by host.
    pub by_host: HashMap<IpAddr, HostPortChanges>,
}

/// Port changes for a single host.
#[derive(Debug)]
pub struct HostPortChanges {
    /// Newly opened ports.
    pub added: Vec<PortChange>,
    /// Closed ports.
    pub removed: Vec<PortChange>,
    /// Ports with state changes.
    pub state_changed: Vec<PortChange>,
    /// Ports with service/version changes.
    pub service_changed: Vec<PortChange>,
}

/// Port change information.
#[derive(Debug, Clone)]
pub struct PortChange {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub previous_state: Option<String>,
    pub previous_service: Option<String>,
}

impl PortChange {
    /// Create `PortChange` for a new port (added).
    fn from_port(port: &PortResult) -> Self {
        use rustnmap_output::Protocol;

        let protocol = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        Self {
            port: port.number,
            protocol: protocol.to_string(),
            state: format!("{:?}", port.state),
            service: port.service.as_ref().map(|s| s.name.clone()),
            version: port.service.as_ref().and_then(|s| s.version.clone()),
            previous_state: None,
            previous_service: None,
        }
    }

    /// Create `PortChange` for a removed port.
    fn from_removed_port(port: &PortResult) -> Self {
        use rustnmap_output::Protocol;

        let protocol = match port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        Self {
            port: port.number,
            protocol: protocol.to_string(),
            state: String::new(), // Port no longer exists
            service: None,
            version: None,
            previous_state: Some(format!("{:?}", port.state)),
            previous_service: port.service.as_ref().map(|s| s.name.clone()),
        }
    }

    /// Create `PortChange` for a state change.
    fn from_state_change(after_port: &PortResult, before_state: &str) -> Self {
        use rustnmap_output::Protocol;

        let protocol = match after_port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        Self {
            port: after_port.number,
            protocol: protocol.to_string(),
            state: format!("{:?}", after_port.state),
            service: after_port.service.as_ref().map(|s| s.name.clone()),
            version: after_port.service.as_ref().and_then(|s| s.version.clone()),
            previous_state: Some(before_state.to_string()),
            previous_service: None,
        }
    }

    /// Create `PortChange` for a service change.
    fn from_service_change(after_port: &PortResult, before_service: &str) -> Self {
        use rustnmap_output::Protocol;

        let protocol = match after_port.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };

        Self {
            port: after_port.number,
            protocol: protocol.to_string(),
            state: format!("{:?}", after_port.state),
            service: after_port.service.as_ref().map(|s| s.name.clone()),
            version: after_port.service.as_ref().and_then(|s| s.version.clone()),
            previous_state: None,
            previous_service: Some(before_service.to_string()),
        }
    }
}

/// Vulnerability changes between two scans.
#[derive(Debug)]
pub struct VulnerabilityChanges {
    /// New vulnerabilities discovered.
    pub added: Vec<VulnChange>,
    /// Fixed vulnerabilities.
    pub fixed: Vec<VulnChange>,
    /// Vulnerabilities with risk score changes.
    pub risk_changed: Vec<VulnChange>,
}

/// Vulnerability change information.
#[derive(Debug, Clone)]
pub struct VulnChange {
    pub cve_id: String,
    pub ip: IpAddr,
    pub new_cvss: Option<f64>,
    pub previous_cvss: Option<f64>,
    pub new_epss: Option<f64>,
    pub previous_epss: Option<f64>,
    pub is_kev: bool,
    pub was_kev: bool,
}

/// Diff report structure for serialization.
#[derive(Debug)]
pub struct DiffReport {
    /// Before scan ID or command.
    pub before: String,
    /// After scan ID or command.
    pub after: String,
    /// Report generation timestamp.
    pub generated_at: chrono::DateTime<Utc>,
    /// Host changes.
    pub host_changes: HostChanges,
    /// Port changes.
    pub port_changes: PortChanges,
    /// Vulnerability changes.
    pub vuln_changes: VulnerabilityChanges,
}
