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
