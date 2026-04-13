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

// Rust guideline compliant 2026-02-12

//! # rustnmap-evasion
//!
//! Firewall and IDS evasion techniques for network scanning.
//!
//! This crate provides implementations of various evasion techniques that can be used
//! to bypass firewalls and intrusion detection systems during network reconnaissance.
//!
//! ## Modules
//!
//! - [`config`] - Configuration types for evasion techniques
//! - [`fragment`] - IP fragmentation evasion
//! - [`decoy`] - Decoy scanning with multiple source IPs
//! - [`source`] - Source address spoofing
//! - [`modify`] - Packet modification techniques
//! - [`timing`] - Timing template configuration
//!
//! ## Example
//!
//! ```rust,no_run
//! use rustnmap_evasion::{EvasionConfig, FragmentMode};
//! use std::time::Duration;
//!
//! let config = EvasionConfig::builder()
//!     .fragmentation(8)  // 8-byte fragments
//!     .decoys(vec![
//!         "192.0.2.1".parse().unwrap(),
//!         "192.0.2.2".parse().unwrap(),
//!     ])
//!     .source_port(53)
//!     .ttl(64)
//!     .build()
//!     .unwrap();
//! ```

pub mod config;
pub mod decoy;
pub mod fragment;
pub mod modify;
pub mod source;
pub mod timing;

// Re-export main types for convenience
pub use config::{
    DecoyConfig, EvasionConfig, EvasionConfigBuilder, FragmentConfig, FragmentMode, IpOption,
    PacketModConfig, SourceConfig, TimingTemplate, TimingValues,
};

pub use decoy::DecoyScheduler;
pub use fragment::Fragmenter;
pub use modify::PacketModifier;
pub use source::SourceSpoofer;

/// Result type for evasion operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during evasion configuration or operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid fragment size specified.
    #[error("invalid fragment size: {size} (must be > 8 and <= 1500)")]
    InvalidFragmentSize { size: usize },

    /// Invalid decoy configuration.
    #[error("invalid decoy configuration: {0}")]
    InvalidDecoyConfig(String),

    /// Invalid IP address specified.
    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// Invalid port number.
    #[error("invalid port: {port} (must be 1-65535)")]
    InvalidPort { port: u16 },

    /// Invalid TTL value.
    #[error("invalid TTL: {ttl} (must be 1-255)")]
    InvalidTtl { ttl: u8 },

    /// Invalid timing template.
    #[error("invalid timing template: {0}")]
    InvalidTimingTemplate(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidFragmentSize { size: 0 };
        assert!(err.to_string().contains("invalid fragment size"));

        let err = Error::InvalidPort { port: 0 };
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn test_evasion_config_builder_default() {
        let config = EvasionConfig::builder().build().unwrap();
        assert!(config.fragmentation.is_none());
        assert!(config.decoys.is_none());
        assert!(config.source.source_ip.is_none());
    }
}
