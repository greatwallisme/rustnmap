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

//! Operating system fingerprinting.
//!
//! Implements OS detection through TCP/IP stack behavior analysis.
//! Compatible with Nmap's OS detection engine (-O flag).
//!
//! # Detection Methods
//!
//! OS detection uses multiple fingerprinting techniques:
//!
//! - **SEQ** - TCP Initial Sequence Number analysis
//! - **OPS** - TCP options ordering and values
//! - **WIN** - TCP window size patterns
//! - **ECN** - Explicit Congestion Notification support
//! - **T1-T7** - Special TCP probe responses
//! - **IE** - ICMP Echo response characteristics
//! - **U1** - UDP probe responses
//!
//! # Accuracy
//!
//! OS detection returns multiple possible matches with accuracy percentages.
//! Higher accuracy indicates better fingerprint match.

pub mod database;
pub mod detector;
pub mod fingerprint;
pub mod matching;

pub use database::{FingerprintDatabase, OsMatch};
pub use detector::OsDetector;
pub use fingerprint::{
    EcnFingerprint, IcmpTestResult, IpIdPattern, IpIdSeqClass, IsnClass, OpsFingerprint,
    OsFingerprint, SeqFingerprint, TestResult, UdpTestResult,
};

// Rust guideline compliant 2026-04-09
