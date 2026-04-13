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

//! Service and OS fingerprinting for network detection.
//!
//! This crate provides network service version detection and operating system
//! fingerprinting capabilities compatible with Nmap's detection algorithms.
//!
//! # Architecture
//!
//! The crate is organized into two main subsystems:
//!
//! - **Service Detection** ([`service`]) - Identifies network services by sending
//!   version probes and matching responses against known service fingerprints
//! - **OS Detection** ([`os`]) - Determines the operating system by analyzing
//!   TCP/IP stack behavior and matching against fingerprint databases
//!
//! # Service Detection
//!
//! Service detection works by:
//! 1. Sending probes to open ports
//! 2. Analyzing responses with regex patterns
//! 3. Extracting version information with confidence scores
//!
//! ```no_run
//! use rustnmap_fingerprint::service::{ProbeDatabase, ServiceDetector};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = ProbeDatabase::load_from_nmap_db("nmap-service-probes").await?;
//! let detector = ServiceDetector::new(db);
//!
//! let target: SocketAddr = "127.0.0.1:80".parse().unwrap();
//! let results = detector.detect_service_with_protocol(&target, 80, "tcp").await?;
//!
//! if let Some(service) = results.first() {
//!     tracing::info!("Service: {} {}", service.name, service.version.as_ref().unwrap_or(&"?".into()));
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # OS Detection
//!
//! OS detection analyzes TCP/IP stack characteristics:
//! - TCP ISN (Initial Sequence Number) patterns
//! - IP ID increment behavior
//! - TCP options ordering and values
//! - TCP window size characteristics
//! - Responses to specially crafted TCP/ICMP probes
//!
//! ```no_run
//! use rustnmap_fingerprint::os::{FingerprintDatabase, OsDetector};
//! use std::net::{Ipv4Addr, SocketAddr};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = FingerprintDatabase::load_from_nmap_db("nmap-os-db")?;
//! let local_addr = Ipv4Addr::new(192, 168, 1, 100);
//! let detector = OsDetector::new(db, local_addr);
//!
//! let target: SocketAddr = "127.0.0.1:80".parse().unwrap();
//! let matches = detector.detect_os(&target).await?;
//! for os_match in matches.iter().take(3) {
//!     tracing::info!("{}: {}%", os_match.name, os_match.accuracy);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Database Formats
//!
//! This crate supports Nmap's standard database formats:
//! - `nmap-service-probes` - Service version detection patterns
//! - `nmap-os-db` - OS fingerprint reference database
//! - `nmap-mac-prefixes` - MAC vendor mappings
//! - `nmap-services` - Port-to-service name mappings
//! - `nmap-protocols` - Protocol number-to-name mappings
//! - `nmap-rpc` - RPC program number-to-name mappings
//!
//! # Performance
//!
//! Both detection systems are optimized for:
//! - Minimal allocations in hot paths
//! - Efficient regex compilation and caching
//! - Parallel probing where network conditions allow
//!
//! # Testing
//!
//! Enable the `test-util` feature for testing utilities.

#![warn(missing_docs)]

pub mod database;
pub mod error;
pub mod os;
pub mod service;
pub mod tls;

/// Result type for fingerprinting operations.
pub type Result<T> = std::result::Result<T, error::FingerprintError>;

// Re-exports for convenience
#[doc(inline)]
pub use database::{
    DatabaseUpdater, MacPrefixDatabase, ProtocolDatabase, RpcDatabase, UpdateOptions,
};
pub use error::FingerprintError;
pub use os::{
    EcnFingerprint, FingerprintDatabase, IcmpTestResult, IpIdPattern, IpIdSeqClass, IsnClass,
    OpsFingerprint, OsDetector, OsFingerprint, OsMatch, SeqFingerprint, TestResult,
    UdpTestResult,
};
pub use service::{ProbeDatabase, ProbeDefinition, ServiceDetector, ServiceInfo};
pub use tls::{CertificateInfo, TlsDetector, TlsInfo, TlsVersion};
