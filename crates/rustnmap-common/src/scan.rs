//! Scan configuration and timing templates for `RustNmap`.
//!
//! This module provides configuration types for scanning operations,
//! including timing templates and scan parameters.

use std::fmt;
use std::time::Duration;

/// Configuration for scanning operations.
///
/// This struct contains all the parameters that control how scanning is performed,
/// including timing templates, parallelism, and evasion techniques.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Minimum round-trip time estimate.
    pub min_rtt: Duration,
    /// Maximum round-trip time before giving up.
    pub max_rtt: Duration,
    /// Initial RTT estimate.
    pub initial_rtt: Duration,
    /// Maximum number of retries for a probe.
    pub max_retries: u8,
    /// Host timeout in milliseconds.
    pub host_timeout: u64,
    /// Scan delay between probes.
    pub scan_delay: Duration,
    /// DNS server address for local IP detection (default: 8.8.8.8:53).
    pub dns_server: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_rtt: Duration::from_millis(100), // Nmap MIN_RTT_TIMEOUT
            max_rtt: Duration::from_secs(10),    // Nmap MAX_RTT_TIMEOUT
            initial_rtt: Duration::from_millis(1000), // Nmap INITIAL_RTT_TIMEOUT
            max_retries: 10, // Nmap MAX_RETRANSMISSIONS (11 probes max)
            host_timeout: 900_000,
            scan_delay: Duration::ZERO,
            dns_server: crate::DEFAULT_DNS_SERVER.to_string(),
        }
    }
}

/// Timing template as defined by Nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimingTemplate {
    /// T0 - Paranoid: very slow, IDS evasion
    Paranoid,
    /// T1 - Sneaky: slow, stealthy
    Sneaky,
    /// T2 - Polite: bandwidth-friendly
    Polite,
    /// T3 - Normal: default
    Normal,
    /// T4 - Aggressive: fast
    Aggressive,
    /// T5 - Insane: very fast, may drop packets
    Insane,
}

impl TimingTemplate {
    /// Returns the timing parameters for this template.
    ///
    /// These values are based on nmap's `timing.cc` implementation:
    /// - T0 (Paranoid): 5min `scan_delay`, 5min `initial_rtt`
    /// - T1 (Sneaky): 15s `scan_delay`, 15s `initial_rtt`
    /// - T2 (Polite): 400ms `scan_delay`
    /// - T3 (Normal): defaults (1s `initial_rtt`, 10 `max_retries`)
    /// - T4 (Aggressive): 500ms `initial_rtt`, 6 `max_retries`
    /// - T5 (Insane): 250ms `initial_rtt`, 2 `max_retries`
    #[must_use]
    pub fn scan_config(&self) -> ScanConfig {
        match self {
            Self::Paranoid => ScanConfig {
                min_rtt: Duration::from_millis(100),
                max_rtt: Duration::from_secs(300), // 5 minutes
                initial_rtt: Duration::from_secs(300), // 5 minutes
                max_retries: 10,
                host_timeout: 900_000,
                scan_delay: Duration::from_millis(300_000), // 5 minutes
                ..Default::default()
            },
            Self::Sneaky => ScanConfig {
                min_rtt: Duration::from_millis(100),
                max_rtt: Duration::from_secs(15),
                initial_rtt: Duration::from_secs(15),
                max_retries: 10,
                host_timeout: 900_000,
                scan_delay: Duration::from_millis(15_000), // 15 seconds
                ..Default::default()
            },
            Self::Polite => ScanConfig {
                min_rtt: Duration::from_millis(100),
                max_rtt: Duration::from_secs(10),
                initial_rtt: Duration::from_millis(1000),
                max_retries: 10,
                host_timeout: 900_000,
                scan_delay: Duration::from_millis(400),
                ..Default::default()
            },
            Self::Normal => ScanConfig::default(),
            Self::Aggressive => ScanConfig {
                min_rtt: Duration::from_millis(100),
                max_rtt: Duration::from_millis(1250),
                initial_rtt: Duration::from_millis(500),
                max_retries: 6,
                host_timeout: 900_000,
                scan_delay: Duration::ZERO,
                ..Default::default()
            },
            Self::Insane => ScanConfig {
                min_rtt: Duration::from_millis(50),
                max_rtt: Duration::from_millis(300),
                initial_rtt: Duration::from_millis(250),
                max_retries: 2,
                host_timeout: 300_000, // 15 minutes (nmap: host_timeout = 900000)
                scan_delay: Duration::ZERO,
                ..Default::default()
            },
        }
    }
}

/// Errors that can occur during port scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// Network-related error during scanning.
    Network(#[from] crate::Error),

    /// Timeout during scan operation.
    Timeout {
        /// The target that timed out.
        target: String,
        /// The port that was being scanned.
        port: crate::Port,
    },

    /// Permission denied for raw socket operation.
    PermissionDenied {
        /// The operation that was attempted.
        operation: String,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network error: {e}"),
            Self::Timeout { target, port } => {
                write!(f, "timeout scanning {target}:{port}")
            }
            Self::PermissionDenied { operation } => {
                write!(f, "permission denied: {operation}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_template_normal() {
        let config = TimingTemplate::Normal.scan_config();
        // Nmap MAX_RETRANSMISSIONS = 10 (11 probes max)
        assert_eq!(config.max_retries, 10);
        // Nmap INITIAL_RTT_TIMEOUT = 1000ms
        assert_eq!(config.initial_rtt, Duration::from_millis(1000));
    }

    #[test]
    fn test_timing_template_insane() {
        let config = TimingTemplate::Insane.scan_config();
        // Nmap T5: max_retransmissions = 2
        assert_eq!(config.max_retries, 2);
        // Nmap T5: initial_rtt = 250ms
        assert_eq!(config.initial_rtt, Duration::from_millis(250));
    }

    #[test]
    fn test_timing_template_aggressive() {
        let config = TimingTemplate::Aggressive.scan_config();
        // Nmap T4: max_retransmissions = 6
        assert_eq!(config.max_retries, 6);
        // Nmap T4: initial_rtt = 500ms
        assert_eq!(config.initial_rtt, Duration::from_millis(500));
    }

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert_eq!(config.max_retries, 10);
        assert_eq!(config.host_timeout, 900_000);
        assert_eq!(config.initial_rtt, Duration::from_millis(1000));
    }

    #[test]
    fn test_scan_error_display() {
        let err = ScanError::PermissionDenied {
            operation: "create raw socket".to_string(),
        };
        assert!(err.to_string().contains("permission denied"));
        assert!(err.to_string().contains("create raw socket"));
    }
}
