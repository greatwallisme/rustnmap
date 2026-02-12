//! Port scanner trait and common scanning functionality.
//!
//! This module defines the [`PortScanner`] trait that all scanning implementations
//! must use, along with common scanning configuration types.

use rustnmap_common::{Port, PortState, Protocol};
use rustnmap_target::Target;
use std::fmt;

/// Result type for scanning operations.
pub type ScanResult<T> = Result<T, ScanError>;

/// Errors that can occur during port scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// Network-related error during scanning.
    Network(#[from] rustnmap_common::Error),

    /// Timeout during scan operation.
    Timeout {
        /// The target that timed out.
        target: String,
        /// The port that was being scanned.
        port: Port,
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

/// Trait defining the interface for port scanners.
///
/// All scanning implementations (TCP SYN, TCP Connect, UDP, etc.) must
/// implement this trait to provide a consistent interface.
pub trait PortScanner {
    /// Scans a single port on a target.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan cannot be performed due to network
    /// issues or permissions.
    fn scan_port(&self, target: &Target, port: Port, protocol: Protocol) -> ScanResult<PortState>;

    /// Returns true if this scanner requires root privileges.
    #[must_use]
    fn requires_root(&self) -> bool {
        false
    }
}

/// Configuration for scanning operations.
///
/// This struct contains all the parameters that control how scanning is performed,
/// including timing templates, parallelism, and evasion techniques.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Minimum round-trip time estimate.
    pub min_rtt: std::time::Duration,
    /// Maximum round-trip time before giving up.
    pub max_rtt: std::time::Duration,
    /// Initial RTT estimate.
    pub initial_rtt: std::time::Duration,
    /// Maximum number of retries for a probe.
    pub max_retries: u8,
    /// Host timeout in milliseconds.
    pub host_timeout: u64,
    /// Scan delay between probes.
    pub scan_delay: std::time::Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_rtt: std::time::Duration::from_millis(50),
            max_rtt: std::time::Duration::from_secs(10),
            initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
            max_retries: 2,
            host_timeout: 900_000,
            scan_delay: std::time::Duration::ZERO,
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
    #[must_use]
    pub const fn scan_config(&self) -> ScanConfig {
        match self {
            Self::Paranoid => ScanConfig {
                min_rtt: std::time::Duration::from_millis(100),
                max_rtt: std::time::Duration::from_secs(30),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 10,
                host_timeout: 900_000,
                scan_delay: std::time::Duration::from_millis(500),
            },
            Self::Sneaky => ScanConfig {
                min_rtt: std::time::Duration::from_millis(100),
                max_rtt: std::time::Duration::from_secs(15),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 8,
                host_timeout: 900_000,
                scan_delay: std::time::Duration::from_millis(400),
            },
            Self::Polite => ScanConfig {
                min_rtt: std::time::Duration::from_millis(100),
                max_rtt: std::time::Duration::from_secs(10),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 6,
                host_timeout: 900_000,
                scan_delay: std::time::Duration::from_millis(100),
            },
            Self::Normal => ScanConfig {
                min_rtt: std::time::Duration::from_millis(50),
                max_rtt: std::time::Duration::from_secs(5),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 2,
                host_timeout: 900_000,
                scan_delay: std::time::Duration::ZERO,
            },
            Self::Aggressive => ScanConfig {
                min_rtt: std::time::Duration::from_millis(20),
                max_rtt: std::time::Duration::from_millis(1250),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 1,
                host_timeout: 900_000,
                scan_delay: std::time::Duration::ZERO,
            },
            Self::Insane => ScanConfig {
                min_rtt: std::time::Duration::from_millis(5),
                max_rtt: std::time::Duration::from_millis(300),
                initial_rtt: rustnmap_common::timeout::INITIAL_RTT,
                max_retries: 0,
                host_timeout: 300_000,
                scan_delay: std::time::Duration::ZERO,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_template_normal() {
        let config = TimingTemplate::Normal.scan_config();
        assert_eq!(config.max_retries, 2);
    }

    #[test]
    fn test_timing_template_insane() {
        let config = TimingTemplate::Insane.scan_config();
        assert_eq!(config.max_retries, 0);
    }
}
