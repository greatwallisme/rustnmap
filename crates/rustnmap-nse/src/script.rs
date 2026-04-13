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

//! NSE script types and metadata.
//!
//! This module defines the core types representing NSE scripts,
//! including their metadata, categories, and execution results.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Script category classification.
///
/// Scripts can belong to multiple categories, which determine when
/// they are executed and what permissions they require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum ScriptCategory {
    /// Authentication cracking scripts.
    Auth,
    /// Network broadcast discovery.
    Broadcast,
    /// Brute force authentication.
    Brute,
    /// Default safe scripts.
    #[default]
    Default,
    /// Service and version discovery.
    Discovery,
    /// Denial of service detection.
    Dos,
    /// Exploitation scripts.
    Exploit,
    /// Third-party service queries.
    External,
    /// Protocol fuzzing.
    Fuzzer,
    /// Intrusive scanning.
    Intrusive,
    /// Malware detection.
    Malware,
    /// Information gathering.
    Info,
    /// Non-intrusive checks.
    Safe,
    /// Version detection.
    Version,
    /// Vulnerability detection.
    Vuln,
}

impl ScriptCategory {
    /// Parse a category from string.
    ///
    /// # Arguments
    ///
    /// * `s` - Category string (case-insensitive)
    ///
    /// # Returns
    ///
    /// `Some(category)` if recognized, `None` otherwise.
    #[expect(
        clippy::should_implement_trait,
        reason = "Returns Option not Result; FromStr trait requires Result"
    )]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auth" => Some(Self::Auth),
            "broadcast" => Some(Self::Broadcast),
            "brute" => Some(Self::Brute),
            "default" => Some(Self::Default),
            "discovery" => Some(Self::Discovery),
            "dos" => Some(Self::Dos),
            "exploit" => Some(Self::Exploit),
            "external" => Some(Self::External),
            "fuzzer" => Some(Self::Fuzzer),
            "intrusive" => Some(Self::Intrusive),
            "malware" => Some(Self::Malware),
            "info" => Some(Self::Info),
            "safe" => Some(Self::Safe),
            "version" => Some(Self::Version),
            "vuln" => Some(Self::Vuln),
            _ => None,
        }
    }

    /// Convert category to string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Broadcast => "broadcast",
            Self::Brute => "brute",
            Self::Default => "default",
            Self::Discovery => "discovery",
            Self::Dos => "dos",
            Self::Exploit => "exploit",
            Self::External => "external",
            Self::Fuzzer => "fuzzer",
            Self::Intrusive => "intrusive",
            Self::Malware => "malware",
            Self::Info => "info",
            Self::Safe => "safe",
            Self::Version => "version",
            Self::Vuln => "vuln",
        }
    }

    /// Check if this category is considered "safe" for default scanning.
    #[must_use]
    pub const fn is_safe(self) -> bool {
        matches!(
            self,
            Self::Safe | Self::Discovery | Self::Version | Self::Default
        )
    }

    /// Check if this category is considered "intrusive".
    #[must_use]
    pub const fn is_intrusive(self) -> bool {
        matches!(
            self,
            Self::Intrusive | Self::Brute | Self::Exploit | Self::Dos | Self::Fuzzer
        )
    }
}

impl std::fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed NSE script metadata.
///
/// Represents a loaded NSE script with all its metadata and
/// compiled Lua code.
#[derive(Debug, Clone)]
pub struct NseScript {
    /// Unique script identifier (filename without extension).
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// Script categories.
    pub categories: Vec<ScriptCategory>,

    /// Script author(s).
    pub author: Vec<String>,

    /// License information.
    pub license: String,

    /// Required NSE libraries.
    pub dependencies: Vec<String>,

    /// Required NSE version (if specified).
    pub required_version: Option<String>,

    /// Filesystem path to script.
    pub file_path: PathBuf,

    /// Original Lua source code.
    pub source: String,

    /// Script arguments (default values).
    pub arguments: HashMap<String, String>,

    /// Hostrule function source code (if present).
    pub hostrule_source: Option<String>,

    /// Portrule function source code (if present).
    pub portrule_source: Option<String>,

    /// Action function source code.
    pub action_source: Option<String>,
}

impl NseScript {
    /// Create a new script with minimal metadata.
    #[must_use]
    pub fn new(id: impl Into<String>, file_path: PathBuf, source: String) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            categories: Vec::new(),
            author: Vec::new(),
            license: "Same as Nmap".to_string(),
            dependencies: Vec::new(),
            required_version: None,
            file_path,
            source,
            arguments: HashMap::new(),
            hostrule_source: None,
            portrule_source: None,
            action_source: None,
        }
    }

    /// Check if the script matches any of the given categories.
    #[must_use]
    pub fn matches_categories(&self, categories: &[ScriptCategory]) -> bool {
        if categories.is_empty() {
            return true;
        }
        self.categories.iter().any(|c| categories.contains(c))
    }

    /// Check if the script matches a name pattern.
    ///
    /// Supports exact match, substring match, glob patterns (`*`, `?`),
    /// and automatically strips `.nse` extension from patterns so that
    /// `--script ssl-cert.nse` matches script ID `ssl-cert`.
    #[must_use]
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        // Strip .nse extension from pattern if present
        let normalized = pattern.strip_suffix(".nse").unwrap_or(pattern);

        if normalized.contains('*') || normalized.contains('?') {
            // Glob pattern matching
            match_pattern(&self.id, normalized)
        } else {
            // Exact match or substring
            self.id == normalized || self.id.contains(normalized)
        }
    }

    /// Check if the script has a hostrule.
    #[must_use]
    pub fn has_hostrule(&self) -> bool {
        self.hostrule_source.is_some()
            || (self.source.contains("hostrule")
                && (self.source.contains("hostrule =")
                    || self.source.contains("function hostrule")))
    }

    /// Check if the script has a portrule.
    #[must_use]
    pub fn has_portrule(&self) -> bool {
        self.portrule_source.is_some()
            || (self.source.contains("portrule")
                && (self.source.contains("portrule =")
                    || self.source.contains("function portrule")))
    }

    /// Check if the script has an action function.
    #[must_use]
    pub fn has_action(&self) -> bool {
        self.action_source.is_some()
            || (self.source.contains("action")
                && (self.source.contains("action =") || self.source.contains("function action")))
    }

    /// Extract rule and action function source code from script.
    ///
    /// This should be called after parsing to populate the function sources.
    pub fn extract_functions(&mut self) {
        self.hostrule_source = Self::extract_function(&self.source, "hostrule");
        self.portrule_source = Self::extract_function(&self.source, "portrule");
        self.action_source = Self::extract_function(&self.source, "action");
    }

    /// Extract a function definition from Lua source.
    fn extract_function(source: &str, name: &str) -> Option<String> {
        // Try to find function definition: "name = function(...)" or "function name(...)"
        let patterns = [format!("{name} = function"), format!("function {name}")];

        for pattern in &patterns {
            if let Some(start_pos) = source.find(pattern) {
                // Find the complete function body
                let func_start = start_pos;
                let rest = &source[func_start..];

                // Count braces to find function end
                let mut brace_count = 0;
                let mut in_string = false;
                let mut string_char = '\0';
                let found_first_brace = false;

                for (i, c) in rest.char_indices() {
                    if in_string {
                        if c == string_char {
                            in_string = false;
                        } else if c == '\\' {
                            // Skip escaped character
                        }
                    } else if c == '"' || c == '\'' || c == '[' {
                        in_string = true;
                        string_char = c;
                        if c == '[' {
                            // Handle long strings [[...]]
                            if rest[i..].starts_with("[[") {
                                // Find closing ]]
                                if rest[i + 2..].contains("]]") {
                                    // Skip to after ]]
                                }
                            }
                        }
                    } else if c == '{' || c == '(' {
                        // Lua tables or function calls - not relevant for function body
                    } else if c == '}' {
                        if found_first_brace {
                            brace_count -= 1;
                            if brace_count == 0 {
                                // Found end of function
                                return Some(rest[..=i].to_string());
                            }
                        }
                    } else if c == 'e' && rest[i..].starts_with("end") && !found_first_brace {
                        // Check if this is a standalone "end"
                        let after_end = i + 3;
                        if after_end <= rest.len() {
                            let after = &rest[after_end..];
                            if after.starts_with('\n')
                                || after.starts_with('\r')
                                || after.starts_with(' ')
                                || after.starts_with('\t')
                                || after.is_empty()
                            {
                                return Some(rest[..after_end].trim().to_string());
                            }
                        }
                    }
                }

                // If we couldn't find a proper end, return what we have
                return Some(rest.to_string());
            }
        }

        None
    }
}

/// Simple glob pattern matching for script selection.
///
/// Supports `*` (any sequence) and `?` (single character) wildcards.
/// Used by both [`NseScript::matches_pattern`] and [`crate::selector::ScriptSelector::select_from_index`].
#[must_use]
pub fn match_pattern(text: &str, pattern: &str) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let pat_bytes = pattern.as_bytes();
    let txt_bytes = text.as_bytes();
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0;

    while ti < txt_bytes.len() {
        if pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if pi < pat_bytes.len() && (pat_bytes[pi] == b'?' || pat_bytes[pi] == txt_bytes[ti])
        {
            pi += 1;
            ti += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < pat_bytes.len() && pat_bytes[pi] == b'*' {
        pi += 1;
    }

    pi == pat_bytes.len()
}

/// Script execution output format.
///
/// Scripts can return structured data in various formats.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum ScriptOutput {
    /// Plain text output.
    Plain(String),
    /// Structured table data.
    Table {
        /// Column headers.
        headers: Vec<String>,
        /// Data rows.
        rows: Vec<Vec<String>>,
    },
    /// JSON data.
    Json(serde_json::Value),
    /// Empty output.
    #[default]
    Empty,
}

impl ScriptOutput {
    /// Convert output to display string.
    #[must_use]
    pub fn to_display(&self) -> String {
        match self {
            Self::Plain(s) => s.clone(),
            Self::Table { headers, rows } => {
                let mut result = String::new();
                if !headers.is_empty() {
                    result.push_str(&headers.join("\t"));
                    result.push('\n');
                }
                for row in rows {
                    result.push_str(&row.join("\t"));
                    result.push('\n');
                }
                result
            }
            Self::Json(v) => v.to_string(),
            Self::Empty => String::new(),
        }
    }

    /// Check if output is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

impl From<String> for ScriptOutput {
    fn from(s: String) -> Self {
        Self::Plain(s)
    }
}

impl From<&str> for ScriptOutput {
    fn from(s: &str) -> Self {
        Self::Plain(s.to_string())
    }
}

impl From<serde_json::Value> for ScriptOutput {
    fn from(v: serde_json::Value) -> Self {
        Self::Json(v)
    }
}

/// Script execution result.
///
/// Contains the complete results of executing a script against a target.
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Script ID.
    pub script_id: String,

    /// Target IP address.
    pub target_ip: std::net::IpAddr,

    /// Target port (if port script).
    pub port: Option<u16>,

    /// Protocol (tcp/udp).
    pub protocol: Option<String>,

    /// Execution status.
    pub status: ExecutionStatus,

    /// Script output.
    pub output: ScriptOutput,

    /// Execution duration.
    pub duration: std::time::Duration,

    /// Debug log entries.
    pub debug_log: Vec<String>,
}

impl ScriptResult {
    /// Create a new successful result.
    #[must_use]
    pub fn success(script_id: impl Into<String>, target_ip: std::net::IpAddr) -> Self {
        Self {
            script_id: script_id.into(),
            target_ip,
            port: None,
            protocol: None,
            status: ExecutionStatus::Success,
            output: ScriptOutput::default(),
            duration: std::time::Duration::ZERO,
            debug_log: Vec::new(),
        }
    }

    /// Check if execution succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, ExecutionStatus::Success)
    }

    /// Check if execution timed out.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(self.status, ExecutionStatus::Timeout)
    }
}

/// Script execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecutionStatus {
    /// Script executed successfully.
    Success,
    /// Script failed with an error.
    Failed,
    /// Script execution timed out.
    Timeout,
    /// Script was not run (rule didn't match).
    Skipped,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Failed => f.write_str("failed"),
            Self::Timeout => f.write_str("timeout"),
            Self::Skipped => f.write_str("skipped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_from_str() {
        assert_eq!(ScriptCategory::from_str("vuln"), Some(ScriptCategory::Vuln));
        assert_eq!(ScriptCategory::from_str("VULN"), Some(ScriptCategory::Vuln));
        assert_eq!(ScriptCategory::from_str("invalid"), None);
    }

    #[test]
    fn test_category_is_safe() {
        assert!(ScriptCategory::Safe.is_safe());
        assert!(ScriptCategory::Discovery.is_safe());
        assert!(!ScriptCategory::Intrusive.is_safe());
        assert!(!ScriptCategory::Exploit.is_safe());
    }

    #[test]
    fn test_category_is_intrusive() {
        assert!(ScriptCategory::Intrusive.is_intrusive());
        assert!(ScriptCategory::Brute.is_intrusive());
        assert!(!ScriptCategory::Safe.is_intrusive());
    }

    #[test]
    fn test_match_pattern() {
        assert!(match_pattern("http-vuln", "http-vuln"));
        assert!(match_pattern("http-vuln-cve", "http-vuln*"));
        assert!(match_pattern("ssh-auth", "ssh-?uth"));
        assert!(!match_pattern("http-vuln", "ftp-*"));
    }

    #[test]
    fn test_script_has_rules() {
        let script = NseScript::new(
            "test",
            PathBuf::from("/test.nse"),
            "hostrule = function(host) return true end \
             action = function(host) return 'output' end"
                .to_string(),
        );
        assert!(script.has_hostrule());
        assert!(!script.has_portrule());
        assert!(script.has_action());
    }

    #[test]
    fn test_script_matches_categories() {
        let mut script = NseScript::new("test", PathBuf::from("/test.nse"), String::new());
        script.categories = vec![ScriptCategory::Vuln, ScriptCategory::Safe];

        assert!(script.matches_categories(&[ScriptCategory::Vuln]));
        assert!(script.matches_categories(&[ScriptCategory::Safe]));
        assert!(!script.matches_categories(&[ScriptCategory::Auth]));
        assert!(script.matches_categories(&[])); // Empty matches all
    }

    #[test]
    fn test_script_output_to_display() {
        let output = ScriptOutput::Plain("test output".to_string());
        assert_eq!(output.to_display(), "test output");

        let output = ScriptOutput::Table {
            headers: vec!["A".to_string(), "B".to_string()],
            rows: vec![vec!["1".to_string(), "2".to_string()]],
        };
        let display = output.to_display();
        assert!(display.contains("A\tB"));
        assert!(display.contains("1\t2"));
    }

    #[test]
    fn test_execution_status_display() {
        assert_eq!(ExecutionStatus::Success.to_string(), "success");
        assert_eq!(ExecutionStatus::Failed.to_string(), "failed");
        assert_eq!(ExecutionStatus::Timeout.to_string(), "timeout");
        assert_eq!(ExecutionStatus::Skipped.to_string(), "skipped");
    }
}
