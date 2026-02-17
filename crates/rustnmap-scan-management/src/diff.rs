// rustnmap-scan-management
// Copyright (C) 2026  greatwallisme

//! Scan result diff/comparison functionality.

use crate::error::{Result, ScanManagementError};
use chrono::Utc;
use rustnmap_output::{HostResult, PortResult, ScanResult};
use rustnmap_output::models::HostStatus;
use std::collections::HashMap;
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
    pub fn new(before: ScanResult, after: ScanResult) -> Self {
        Self { before, after }
    }

    /// Load two scans from history and create diff.
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

        let before_result = before_scan.results.ok_or_else(|| {
            ScanManagementError::ScanNotFound("Scan has no results".to_string())
        })?;

        let after_result = after_scan.results.ok_or_else(|| {
            ScanManagementError::ScanNotFound("Scan has no results".to_string())
        })?;

        Ok(Self::new(before_result, after_result))
    }

    /// Get host changes between scans.
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
    pub fn port_changes(&self) -> PortChanges {
        use rustnmap_output::Protocol;

        let mut by_host: HashMap<IpAddr, HostPortChanges> = HashMap::new();

        // Helper function to get protocol string
        fn protocol_str(p: Protocol) -> &'static str {
            match p {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
                Protocol::Sctp => "sctp",
            }
        }

        // Find all hosts - simplified approach
        let before_ips: std::collections::HashSet<_> = self.before.hosts.iter().map(|h| h.ip).collect();
        let after_ips: std::collections::HashSet<_> = self.after.hosts.iter().map(|h| h.ip).collect();

        for ip in before_ips.union(&after_ips) {
            let before_host = self.before.hosts.iter().find(|h| h.ip == *ip);
            let after_host = self.after.hosts.iter().find(|h| h.ip == *ip);

            let before_ports: HashMap<(u16, &str), &PortResult> = before_host.map(|h| {
                h.ports.iter().map(|p| ((p.number, protocol_str(p.protocol)), p)).collect()
            }).unwrap_or_default();

            let after_ports: HashMap<(u16, &str), &PortResult> = after_host.map(|h| {
                h.ports.iter().map(|p| ((p.number, protocol_str(p.protocol)), p)).collect()
            }).unwrap_or_default();

            let mut added = Vec::new();
            let mut removed = Vec::new();
            let mut state_changed = Vec::new();
            let mut service_changed = Vec::new();

            // Find added and changed ports
            for (key, after_port) in &after_ports {
                if let Some(before_port) = before_ports.get(key) {
                    if before_port.state != after_port.state {
                        state_changed.push(PortChange::from_port(after_port, ChangeType::State));
                    }
                    // Compare service by name instead of full struct
                    let service_diff = match (&before_port.service, &after_port.service) {
                        (None, None) => false,
                        (Some(a), Some(b)) => a.name != b.name || a.version != b.version,
                        _ => true,
                    };
                    if service_diff {
                        service_changed
                            .push(PortChange::from_port(after_port, ChangeType::Service));
                    }
                } else {
                    added.push(PortChange::from_port(after_port, ChangeType::Added));
                }
            }

            // Find removed ports
            for (key, before_port) in &before_ports {
                if !after_ports.contains_key(key) {
                    removed.push(PortChange::from_port(before_port, ChangeType::Removed));
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
    pub fn vulnerability_changes(&self) -> VulnerabilityChanges {
        // This would require integration with rustnmap-vuln
        // For now, return empty changes
        VulnerabilityChanges {
            added: Vec::new(),
            fixed: Vec::new(),
            risk_changed: Vec::new(),
        }
    }

    /// Generate a diff report in the specified format.
    pub fn generate_report(&self, format: DiffFormat) -> String {
        let host_changes = self.host_changes();
        let port_changes = self.port_changes();
        let vuln_changes = self.vulnerability_changes();

        match format {
            DiffFormat::Text => self.generate_text_report(&host_changes, &port_changes, &vuln_changes),
            DiffFormat::Markdown => {
                self.generate_markdown_report(&host_changes, &port_changes, &vuln_changes)
            }
            DiffFormat::Json => self.generate_json_report(&host_changes, &port_changes, &vuln_changes),
            DiffFormat::Html => self.generate_html_report(&host_changes, &port_changes, &vuln_changes),
        }
    }

    fn generate_text_report(
        &self,
        hosts: &HostChanges,
        ports: &PortChanges,
        vulns: &VulnerabilityChanges,
    ) -> String {
        let mut report = String::new();

        report.push_str("=== Scan Diff Report ===\n\n");

        report.push_str("## Host Changes\n");
        report.push_str(&format!("  Added: {} hosts\n", hosts.added.len()));
        for ip in &hosts.added {
            report.push_str(&format!("    + {}\n", ip));
        }

        report.push_str(&format!("  Removed: {} hosts\n", hosts.removed.len()));
        for ip in &hosts.removed {
            report.push_str(&format!("    - {}\n", ip));
        }

        report.push_str(&format!("  Status Changed: {} hosts\n", hosts.status_changed.len()));

        report.push_str("\n## Port Changes\n");
        for (ip, changes) in &ports.by_host {
            report.push_str(&format!("  {}:\n", ip));
            report.push_str(&format!("    Added: {}\n", changes.added.len()));
            report.push_str(&format!("    Removed: {}\n", changes.removed.len()));
            report.push_str(&format!("    State Changed: {}\n", changes.state_changed.len()));
            report.push_str(&format!("    Service Changed: {}\n", changes.service_changed.len()));
        }

        report.push_str("\n## Vulnerability Changes\n");
        report.push_str(&format!("  New: {}\n", vulns.added.len()));
        report.push_str(&format!("  Fixed: {}\n", vulns.fixed.len()));
        report.push_str(&format!("  Risk Changed: {}\n", vulns.risk_changed.len()));

        report
    }

    fn generate_markdown_report(
        &self,
        hosts: &HostChanges,
        ports: &PortChanges,
        vulns: &VulnerabilityChanges,
    ) -> String {
        let mut report = String::new();

        report.push_str("# 扫描结果对比报告\n\n");
        report.push_str(&format!("**生成时间**: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")));

        report.push_str("## 主机变化\n\n");

        report.push_str(&format!("### 新增主机 ({})\n", hosts.added.len()));
        for ip in &hosts.added {
            report.push_str(&format!("- {} (首次发现)\n", ip));
        }

        report.push_str(&format!("\n### 消失主机 ({})\n", hosts.removed.len()));
        for ip in &hosts.removed {
            report.push_str(&format!("- {} (上次在线，本次未响应)\n", ip));
        }

        if !hosts.status_changed.is_empty() {
            report.push_str("\n### 状态变化的主机\n");
            for change in &hosts.status_changed {
                report.push_str(&format!(
                    "- {}: {:?} -> {:?}\n",
                    change.ip, change.before, change.after
                ));
            }
        }

        report.push_str("\n## 端口变化\n\n");
        for (ip, changes) in &ports.by_host {
            report.push_str(&format!("### {}\n", ip));
            if !changes.added.is_empty() {
                report.push_str("**新增端口:**\n");
                for port in &changes.added {
                    report.push_str(&format!("- {}/{} ({})\n", port.port, port.protocol, port.state));
                }
            }
            if !changes.removed.is_empty() {
                report.push_str("**关闭端口:**\n");
                for port in &changes.removed {
                    report.push_str(&format!("- {}/{} ({})\n", port.port, port.protocol, port.previous_state.as_ref().unwrap_or(&port.state)));
                }
            }
            if !changes.service_changed.is_empty() {
                report.push_str("**服务变更:**\n");
                for port in &changes.service_changed {
                    report.push_str(&format!(
                        "- {}/{} ({} -> {})\n",
                        port.port,
                        port.protocol,
                        port.previous_service.as_ref().unwrap_or(&String::from("unknown")),
                        port.service.as_ref().unwrap_or(&String::from("unknown"))
                    ));
                }
            }
        }

        report.push_str("\n## 漏洞变化\n\n");
        report.push_str(&format!("### 新增漏洞 ({})\n", vulns.added.len()));
        for vuln in &vulns.added {
            report.push_str(&format!(
                "- {} (CVSS {}) - {}\n",
                vuln.cve_id,
                vuln.new_cvss.unwrap_or(0.0),
                vuln.ip
            ));
        }

        report.push_str(&format!("\n### 修复漏洞 ({})\n", vulns.fixed.len()));
        for vuln in &vulns.fixed {
            report.push_str(&format!(
                "- {} (CVSS {}) - {}\n",
                vuln.cve_id,
                vuln.previous_cvss.unwrap_or(0.0),
                vuln.ip
            ));
        }

        report.push_str("\n## 统计\n\n");
        report.push_str("| 指标 | 上次 | 本次 | 变化 |\n");
        report.push_str("|------|------|------|------|\n");
        report.push_str(&format!(
            "| 在线主机 | {} | {} | {:+} |\n",
            self.before.statistics.hosts_up,
            self.after.statistics.hosts_up,
            self.after.statistics.hosts_up as i64 - self.before.statistics.hosts_up as i64
        ));
        report.push_str(&format!(
            "| 开放端口 | {} | {} | {:+} |\n",
            self.before.statistics.open_ports,
            self.after.statistics.open_ports,
            self.after.statistics.open_ports as i64 - self.before.statistics.open_ports as i64
        ));

        report
    }

    fn generate_json_report(
        &self,
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
            before_scan: self
                .before
                .metadata
                .command_line
                .clone(),
            after_scan: self
                .after
                .metadata
                .command_line
                .clone(),
            generated_at: Utc::now().to_rfc3339(),
            host_changes: HostChangesSerde {
                added: hosts.added.iter().map(std::string::ToString::to_string).collect(),
                removed: hosts.removed.iter().map(std::string::ToString::to_string).collect(),
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
        &self,
        _hosts: &HostChanges,
        _ports: &PortChanges,
        _vulns: &VulnerabilityChanges,
    ) -> String {
        // Simplified HTML report - can be expanded
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
            self.before.metadata.command_line,
            self.after.metadata.command_line,
            self.before.statistics.hosts_up,
            self.after.statistics.hosts_up,
            self.before.statistics.open_ports,
            self.after.statistics.open_ports,
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
    fn from_port(port: &PortResult, change_type: ChangeType) -> Self {
        use rustnmap_output::Protocol;

        let previous_state = None;
        let previous_service = None;

        if change_type == ChangeType::State || change_type == ChangeType::Service {
            // These would be set when comparing two ports
            // For now, leave as None
        }

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
            previous_state,
            previous_service,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ChangeType {
    Added,
    Removed,
    State,
    Service,
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
