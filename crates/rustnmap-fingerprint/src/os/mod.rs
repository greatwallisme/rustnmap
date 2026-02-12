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

pub mod fingerprint;
pub mod database;
pub mod detector;

pub use fingerprint::{OsFingerprint, SeqFingerprint, OpsFingerprint};
pub use database::{FingerprintDatabase, OsMatch};
pub use detector::OsDetector;

// Rust guideline compliant (2026-02-12)
