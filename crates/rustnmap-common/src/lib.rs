//! `RustNmap` common types, errors, and utilities.
//!
//! This crate provides the foundational types and error handling used across
//! all `RustNmap` crates. It defines the core domain types for network scanning
//! including port states, scan types, and target specifications.

#![warn(missing_docs)]

pub mod error;
pub mod scan;
pub mod services;
pub mod types;

// Re-exports for convenience
pub use error::{Error, Result, ScanError};
pub use scan::{ScanConfig, TimingTemplate};
pub use services::{DatabaseSource, ServiceDatabase, ServiceProtocol};
pub use types::{MacAddr, Port, PortList, PortRange, PortSelector, PortState, Protocol, ScanStats};

// Re-export std types for convenience
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Default DNS server used for local IP address detection.
///
/// This is Google's public DNS server (8.8.8.8:53), used to determine
/// the local IP address by creating a UDP socket connection (no data sent).
/// Users in different regions may override this via the `--dns-server` CLI option.
pub const DEFAULT_DNS_SERVER: &str = "8.8.8.8:53";

/// Common timeout values used throughout `RustNmap`.
///
/// These values are based on Nmap's defaults and represent reasonable
/// starting points for network scanning operations.
pub mod timeout {
    use std::time::Duration;

    /// Default initial round-trip time estimate.
    ///
    /// Based on Nmap's initial RTT of approximately 100ms for LAN scanning.
    pub const INITIAL_RTT: Duration = Duration::from_millis(100);

    /// Minimum timeout for any probe.
    ///
    /// Even on very fast networks, we need some minimum time to process responses.
    pub const MIN_TIMEOUT: Duration = Duration::from_millis(10);

    /// Maximum timeout for a single probe.
    ///
    /// Prevents indefinite waiting on unresponsive hosts.
    pub const MAX_TIMEOUT: Duration = Duration::from_secs(60);

    /// Default host timeout for the entire scanning process.
    ///
    /// Nmap's default is that each host gets no more than this amount of time.
    pub const HOST_TIMEOUT: Duration = Duration::from_secs(900);

    /// Create a timeout based on round-trip time with multiplier.
    ///
    /// This follows Nmap's adaptive timeout algorithm which adjusts based on
    /// observed network conditions.
    ///
    /// # Arguments
    ///
    /// * `rtt` - The observed round-trip time
    /// * `multiplier` - The multiplier to apply (typically 2-4)
    ///
    /// # Returns
    ///
    /// A timeout duration clamped between [`MIN_TIMEOUT`] and [`MAX_TIMEOUT`].
    #[inline]
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "Duration values are within u64 range"
    )]
    pub fn adaptive_timeout(rtt: Duration, multiplier: u32) -> Duration {
        let millis = rtt.as_millis() * u128::from(multiplier);
        let max_millis = MAX_TIMEOUT.as_millis();
        let min_millis = MIN_TIMEOUT.as_millis();
        let capped = millis.min(max_millis).max(min_millis);
        Duration::from_millis(capped as u64)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_adaptive_timeout_basic() {
            let rtt = Duration::from_millis(100);
            let timeout = adaptive_timeout(rtt, 2);
            assert_eq!(timeout, Duration::from_millis(200));
        }

        #[test]
        fn test_adaptive_timeout_min_clamp() {
            let rtt = Duration::from_millis(1);
            let timeout = adaptive_timeout(rtt, 2);
            assert_eq!(timeout, MIN_TIMEOUT);
        }

        #[test]
        fn test_adaptive_timeout_max_clamp() {
            let rtt = Duration::from_secs(30);
            let timeout = adaptive_timeout(rtt, 10);
            assert_eq!(timeout, MAX_TIMEOUT);
        }
    }
}
