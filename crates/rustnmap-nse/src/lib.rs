//! `rustnmap-nse` - Nmap Script Engine (NSE) implementation.
//!
//! This crate provides a Lua 5.4-based scripting engine that is 100% compatible
//! with Nmap's NSE (Nmap Script Engine). It allows users to write and execute
//! Lua scripts for network discovery, vulnerability detection, and advanced
//! scanning techniques.
//!
//! # Architecture
//!
//! The NSE engine consists of several layers:
//!
//! - **Script Loader**: Parses NSE script files and extracts metadata
//! - **Script Database**: Manages available scripts and their categories
//! - **Script Scheduler**: Executes scripts with proper concurrency control
//! - **Lua Runtime**: Isolated Lua 5.4 environments with NSE libraries
//! - **NSE Libraries**: Standard Nmap libraries (nmap, stdnse, http, etc.)
//!
//! # Quick Start
//!
//! ```no_run
//! use rustnmap_nse::{ScriptEngine, ScriptDatabase};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create script database from Nmap scripts directory
//! let db = ScriptDatabase::from_directory(Path::new("/usr/share/nmap/scripts"))?;
//!
//! // Create script engine
//! let engine = ScriptEngine::new(db);
//!
//! // Execute a script
//! let script = engine.database().get("script-id").unwrap();
//! let result = engine.execute_script(script, "127.0.0.1".parse().unwrap(), None);
//! # Ok(())
//! # }
//! ```
//!
//! # Script Categories
//!
//! NSE scripts are organized into categories:
//!
//! - **auth**: Authentication cracking scripts
//! - **broadcast**: Network broadcast discovery
//! - **brute**: Brute force authentication
//! - **default**: Default safe scripts
//! - **discovery**: Service and version discovery
//! - **dos**: Denial of service detection
//! - **exploit**: Exploitation scripts
//! - **external**: Third-party service queries
//! - **fuzzer**: Protocol fuzzing
//! - **intrusive**: Intrusive scanning
//! - **malware**: Malware detection
//! - **safe**: Non-intrusive checks
//! - **version**: Version detection
//! - **vuln**: Vulnerability detection
//!
//! # NSE Library Compatibility
//!
//! This crate provides the following NSE libraries:
//!
//! - `nmap`: Core functions (socket, clock, logging)
//! - `stdnse`: Standard extensions (formatting, debugging)
//! - `comm`: Communication utilities
//! - `shortport`: Port rule helpers
//! - `http`: HTTP protocol support
//! - `ssl`: TLS/SSL protocol support
//! - `ssh`: SSH protocol support
//! - And more...

#![warn(missing_docs)]

pub mod engine;
pub mod error;
pub mod libs;
pub mod lua;
pub mod process_executor;
pub mod registry;
pub mod script;
pub mod selector;
pub mod vm;

// Re-exports for convenience
pub use engine::{ScriptEngine, ScriptScheduler};
pub use error::{Error, Result};
pub use registry::{ScriptDatabase, ScriptIndexEntry};
pub use script::{match_pattern, NseScript, ScriptCategory, ScriptOutput};
pub use selector::ScriptSelector;

/// NSE engine version for compatibility checking.
///
/// Scripts can declare a minimum required NSE version using `@nse_version`.
pub const NSE_VERSION: &str = "1.0.0";

/// Default timeout for script execution (10 minutes).
///
/// This matches nmap's default script timeout.
/// Scripts that exceed this timeout will be terminated.
pub const DEFAULT_SCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Maximum memory allocation per Lua state (10MB).
///
/// Prevents runaway scripts from consuming excessive memory.
pub const MAX_MEMORY_BYTES: usize = 10 * 1024 * 1024;

/// Maximum number of concurrent scripts to execute.
///
/// This limit prevents overwhelming the target host or local system.
pub const MAX_CONCURRENT_SCRIPTS: usize = 20;

/// NSE script file extension.
pub const NSE_EXTENSION: &str = "nse";

/// NSE library directory name.
pub const NSE_LIB_DIR: &str = "nselib";

/// Number of version fields in service fingerprint.
///
/// Corresponds to `NSE_NUM_VERSION_FIELDS` in `nse_nmaplib.cc`.
pub const NSE_NUM_VERSION_FIELDS: usize = 12;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nse_version_format() {
        // NSE version should be valid semver
        let parts: Vec<&str> = NSE_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "NSE_VERSION should be in semver format");
    }

    #[test]
    fn test_default_timeout_reasonable() {
        // Default timeout should be 10 minutes (nmap default)
        assert!(
            DEFAULT_SCRIPT_TIMEOUT.as_secs() >= 600,
            "Default script timeout should be 10 minutes (nmap default)"
        );
    }

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "compile-time constant sanity check"
    )]
    fn test_memory_limit_positive() {
        assert!(MAX_MEMORY_BYTES > 0, "Memory limit must be positive");
    }

    #[test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "compile-time constant sanity check"
    )]
    fn test_concurrent_limit_positive() {
        assert!(
            MAX_CONCURRENT_SCRIPTS > 0,
            "Concurrent limit must be positive"
        );
    }
}
