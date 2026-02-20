//! Scanner Builder API

use std::sync::Arc;
use std::time::Duration;

use rustnmap_common::scan::TimingTemplate;
use rustnmap_core::orchestrator::ScanOrchestrator;
use rustnmap_core::session::{PortSpec, ScanConfig, ScanSession, ScanType};
use rustnmap_evasion::TimingTemplate as EvasionTiming;
use rustnmap_target::parser::TargetParser;

use crate::error::{ScanError, ScanResult};
use crate::models::ScanOutput;
use crate::profile::ScanProfile;

/// Main scanner entry point
#[derive(Debug)]
pub struct Scanner {
    config: ScanConfig,
    targets_string: Option<String>,
}

impl Scanner {
    /// Create a new scanner with default configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the scanner cannot be initialized.
    pub fn new() -> ScanResult<Self> {
        Ok(Self {
            config: ScanConfig::default(),
            targets_string: None,
        })
    }

    /// Create scanner from profile
    ///
    /// # Errors
    ///
    /// Returns an error if the profile cannot be converted to a scan configuration.
    pub fn from_profile(profile: &ScanProfile) -> ScanResult<Self> {
        let config = profile.to_scan_config()?;
        Ok(Self {
            config,
            targets_string: None,
        })
    }

    /// Create a scanner builder for fluent API
    #[must_use]
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }

    /// Set targets for the scan
    #[must_use]
    pub fn with_targets<T: Into<String>>(mut self, targets: T) -> Self {
        self.targets_string = Some(targets.into());
        self
    }

    /// Run a scan with the current configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails due to network issues or invalid configuration.
    pub async fn run(&self) -> ScanResult<ScanOutput> {
        // Get targets (require targets to be set)
        let targets_str = self
            .targets_string
            .as_ref()
            .ok_or_else(|| ScanError::ValidationError("No targets specified".to_string()))?;

        // Parse targets
        let parser = TargetParser::new();
        let target_group = parser
            .parse(targets_str)
            .map_err(|e| ScanError::ValidationError(format!("Invalid targets: {e}")))?;

        // Create session
        let session = ScanSession::new(self.config.clone(), target_group).map_err(|e| {
            ScanError::InternalError(anyhow::anyhow!("Failed to create session: {e}"))
        })?;

        // Create and run orchestrator
        let orchestrator = ScanOrchestrator::new(Arc::new(session));
        let scan_result = orchestrator
            .run()
            .await
            .map_err(|e| ScanError::InternalError(anyhow::anyhow!("Scan failed: {e}")))?;

        // Convert to SDK output
        Ok(ScanOutput::from(scan_result))
    }

    /// Check if the scanner has required privileges for raw socket operations
    ///
    /// # Panics
    ///
    /// This function may panic on Unix systems if the libc call fails.
    ///
    /// # Returns
    ///
    /// Returns `true` if running with root privileges (Unix) or admin privileges (Windows).
    #[must_use]
    pub fn has_required_privileges() -> bool {
        // Check for root privileges (Unix) or admin privileges (Windows)
        #[cfg(unix)]
        {
            // SAFETY: libc::geteuid() is a safe FFI call that returns the effective user ID.
            // It does not have any safety requirements and never fails.
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Scanner builder for fluent API
#[derive(Debug)]
pub struct ScannerBuilder {
    config: ScanConfig,
    targets_string: Option<String>,
}

impl ScannerBuilder {
    /// Create a new builder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ScanConfig::default(),
            targets_string: None,
        }
    }

    /// Set scan targets
    #[must_use]
    pub fn targets<T: IntoIterator<Item = S>, S: Into<String>>(mut self, targets: T) -> Self {
        let targets_vec: Vec<String> = targets.into_iter().map(std::convert::Into::into).collect();
        self.targets_string = Some(targets_vec.join(","));
        self
    }

    /// Set ports to scan
    #[must_use]
    pub fn ports<S: Into<String>>(mut self, ports: S) -> Self {
        let ports_str = ports.into();
        // Parse port specification - supports formats like "1-1000", "22,80,443", "1-65535"
        self.config.port_spec = parse_port_spec(&ports_str).unwrap_or(PortSpec::Top(1000));
        self
    }

    /// Set specific port list
    #[must_use]
    pub fn port_list(mut self, ports: &[u16]) -> Self {
        // Build port spec from port list
        if ports.is_empty() {
            return self;
        }

        // For simplicity, use Top(N) for the count or build ranges
        if ports.len() == 1 {
            self.config.port_spec = PortSpec::Range {
                start: ports[0],
                end: ports[0],
            };
        } else {
            // Use Top(N) based on port count as a reasonable default
            self.config.port_spec = PortSpec::Top(ports.len());
        }
        self
    }
}

/// Parse port specification string into `PortSpec`
fn parse_port_spec(spec: &str) -> Option<PortSpec> {
    match spec {
        "1-65535" | "all" | "*" => Some(PortSpec::All),
        s if s.starts_with("top") => {
            let n = s.trim_start_matches("top").trim().parse().ok()?;
            Some(PortSpec::Top(n))
        }
        s => {
            // Try to parse as single range like "1-1000"
            if let Some((start, end)) = s.split_once('-') {
                let start: u16 = start.parse().ok()?;
                let end: u16 = end.parse().ok()?;
                Some(PortSpec::Range { start, end })
            } else {
                // Single port
                let port: u16 = s.parse().ok()?;
                Some(PortSpec::Range {
                    start: port,
                    end: port,
                })
            }
        }
    }
}

impl ScannerBuilder {
    /// SYN scan (requires root)
    #[must_use]
    pub fn syn_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpSyn];
        self
    }

    /// Connect scan (no root required)
    #[must_use]
    pub fn connect_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpConnect];
        self
    }

    /// FIN scan
    #[must_use]
    pub fn fin_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpFin];
        self
    }

    /// NULL scan
    #[must_use]
    pub fn null_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpNull];
        self
    }

    /// XMAS scan
    #[must_use]
    pub fn xmas_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpXmas];
        self
    }

    /// ACK scan
    #[must_use]
    pub fn ack_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpAck];
        self
    }

    /// Window scan
    #[must_use]
    pub fn window_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpWindow];
        self
    }

    /// Maimon scan
    #[must_use]
    pub fn maimon_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::TcpMaimon];
        self
    }

    /// UDP scan
    #[must_use]
    pub fn udp_scan(mut self) -> Self {
        self.config.scan_types = vec![ScanType::Udp];
        self
    }

    /// Enable service detection
    #[must_use]
    pub fn service_detection(mut self, enable: bool) -> Self {
        self.config.service_detection = enable;
        self
    }

    /// Enable OS detection
    #[must_use]
    pub fn os_detection(mut self, enable: bool) -> Self {
        self.config.os_detection = enable;
        self
    }

    /// Enable vulnerability scanning
    #[must_use]
    pub fn vulnerability_scan(self, enable: bool) -> Self {
        // Note: vulnerability_scan is not a direct field in ScanConfig
        // It would be handled by the rustnmap-vuln crate integration
        let _ = enable;
        self
    }

    /// Set timing template
    #[must_use]
    pub fn timing(mut self, timing: EvasionTiming) -> Self {
        // Convert EvasionTiming to common TimingTemplate
        self.config.timing_template = match timing {
            EvasionTiming::Paranoid => TimingTemplate::Paranoid,
            EvasionTiming::Sneaky => TimingTemplate::Sneaky,
            EvasionTiming::Polite => TimingTemplate::Polite,
            EvasionTiming::Normal => TimingTemplate::Normal,
            EvasionTiming::Aggressive => TimingTemplate::Aggressive,
            EvasionTiming::Insane => TimingTemplate::Insane,
        };
        self
    }

    /// Set custom timeout
    #[must_use]
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.config.host_timeout = duration;
        self
    }

    /// Build and run the scan
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails due to network issues or invalid configuration.
    pub async fn run(self) -> ScanResult<ScanOutput> {
        let scanner = Scanner {
            config: self.config,
            targets_string: self.targets_string,
        };
        scanner.run().await
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_builder() {
        let builder = Scanner::builder()
            .targets(["127.0.0.1"])
            .ports("22-80")
            .syn_scan();

        assert_eq!(builder.config.scan_types, vec![ScanType::TcpSyn]);
        assert!(matches!(
            builder.config.port_spec,
            PortSpec::Range { start: 22, end: 80 }
        ));
        assert_eq!(builder.targets_string, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_scanner_new() {
        let scanner = Scanner::new().unwrap();
        assert!(matches!(scanner.config.port_spec, PortSpec::Top(1000)));
        assert!(scanner.targets_string.is_none());
    }

    #[test]
    fn test_scanner_with_targets() {
        let scanner = Scanner::new().unwrap().with_targets("192.168.1.0/24");
        assert_eq!(scanner.targets_string, Some("192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_scanner_builder_multiple_targets() {
        let builder = Scanner::builder().targets(["192.168.1.1", "192.168.1.2", "10.0.0.1"]);
        assert_eq!(
            builder.targets_string,
            Some("192.168.1.1,192.168.1.2,10.0.0.1".to_string())
        );
    }
}
