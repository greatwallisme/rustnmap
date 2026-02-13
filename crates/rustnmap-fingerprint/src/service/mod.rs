//! Network service version detection.
//!
//! This module implements service detection by sending version probes to open ports
//! and matching responses against known service fingerprints. Compatible with
//! Nmap's service detection engine (-sV flag).
//!
//! # Components
//!
//! - [`ProbeDatabase`] - Loads and manages service probe definitions
//! - [`ServiceDetector`] - Executes probes and matches responses
//! - [`ServiceInfo`] - Represents detected service information
//! - [`ProbeDefinition`] - Service probe specification
//! - [`MatchRule`] - Regex pattern for response matching
//!
//! # Version Intensity
//!
//! Probes are organized by rarity levels (1-9). Higher intensity levels
//! include more probes but increase scan time and network traffic.

pub mod database;
pub mod detector;
pub mod probe;

pub use database::ProbeDatabase;
pub use detector::{ServiceDetector, ServiceInfo};
pub use probe::{MatchRule, MatchTemplate, ProbeDefinition};

// Rust guideline compliant (2026-02-12)
