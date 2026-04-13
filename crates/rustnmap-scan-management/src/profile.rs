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

//! Scan profile management (YAML configuration).

use crate::error::{Result, ScanManagementError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Scan profile configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    /// Profile name.
    pub name: String,
    /// Profile description.
    #[serde(default)]
    pub description: Option<String>,
    /// Target list.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Excluded targets.
    #[serde(default, rename = "exclude")]
    pub exclude_targets: Vec<String>,
    /// Scan configuration.
    pub scan: ScanConfig,
    /// Output configuration.
    #[serde(default)]
    pub output: OutputConfig,
    /// Inherited profile name.
    #[serde(rename = "extends")]
    pub extends_from: Option<String>,
}

/// Scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Scan type.
    #[serde(rename = "type", default = "default_scan_type")]
    pub scan_type: String,
    /// Port range specification.
    #[serde(default)]
    pub ports: Option<String>,
    /// Service detection enabled.
    #[serde(default)]
    pub service_detection: bool,
    /// OS detection enabled.
    #[serde(default)]
    pub os_detection: bool,
    /// NSE scripts to run.
    #[serde(default)]
    pub scripts: Vec<String>,
    /// Vulnerability scanning enabled.
    #[serde(default)]
    pub vulnerability_scan: bool,
    /// Timing template (T0-T5).
    #[serde(default = "default_timing")]
    pub timing: String,
    /// Version detection intensity (0-9).
    #[serde(default)]
    pub version_intensity: Option<u8>,
    /// EPSS threshold for vulnerability filtering.
    #[serde(default)]
    pub epss_threshold: Option<f32>,
    /// Additional Nmap-compatible options.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output formats to generate.
    #[serde(default)]
    pub formats: Vec<String>,
    /// Output directory.
    #[serde(default)]
    pub directory: Option<String>,
    /// Save to history database.
    #[serde(default = "default_true")]
    pub save_to_history: bool,
    /// NDJSON output file.
    #[serde(default)]
    pub ndjson_file: Option<String>,
    /// Markdown report file.
    #[serde(default)]
    pub markdown_file: Option<String>,
    /// HTML report file.
    #[serde(default)]
    pub html_file: Option<String>,
    /// SARIF report file.
    #[serde(default)]
    pub sarif_file: Option<String>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            formats: vec![],
            directory: None,
            save_to_history: true,
            ndjson_file: None,
            markdown_file: None,
            html_file: None,
            sarif_file: None,
        }
    }
}

fn default_scan_type() -> String {
    "syn".to_string()
}

fn default_timing() -> String {
    "T3".to_string()
}

fn default_true() -> bool {
    true
}

impl ScanProfile {
    /// Load profile from file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the YAML is invalid.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = tokio::task::block_in_place(|| {
            fs::read_to_string(path).map_err(ScanManagementError::from)
        })?;
        Self::from_yaml(&content)
    }

    /// Parse profile from YAML string.
    ///
    /// # Errors
    ///
    /// Returns an error if the YAML cannot be parsed.
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let profile: ScanProfile = serde_yaml::from_str(yaml)?;
        Ok(profile)
    }

    /// Save profile to file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or the profile cannot be serialized.
    pub fn save(&self, path: &Path) -> Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        tokio::task::block_in_place(|| fs::write(path, yaml).map_err(ScanManagementError::from))?;
        Ok(())
    }

    /// Validate profile configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile configuration is invalid.
    pub fn validate(&self) -> Result<()> {
        // Validate scan type
        let scan_type_lower = self.scan.scan_type.to_lowercase();
        let valid_types = [
            "syn", "connect", "fin", "null", "xmas", "maimon", "udp", "ack", "window",
        ];
        if !valid_types.contains(&scan_type_lower.as_str()) {
            return Err(ScanManagementError::ProfileValidation(format!(
                "Invalid scan type: {}. Valid types: {:?}",
                self.scan.scan_type, valid_types
            )));
        }

        // Validate timing
        let timing = self.scan.timing.to_uppercase();
        if !timing.starts_with('T') {
            return Err(ScanManagementError::ProfileValidation(format!(
                "Invalid timing: {}. Must be T0-T5",
                self.scan.timing
            )));
        }

        // Check that the digit is between 0 and 5
        if let Some(digit_char) = timing.chars().nth(1) {
            if let Some(digit) = digit_char.to_digit(10) {
                if digit > 5 {
                    return Err(ScanManagementError::ProfileValidation(format!(
                        "Invalid timing: {}. Must be T0-T5",
                        self.scan.timing
                    )));
                }
            } else {
                return Err(ScanManagementError::ProfileValidation(format!(
                    "Invalid timing: {}. Must be T0-T5",
                    self.scan.timing
                )));
            }
        } else {
            return Err(ScanManagementError::ProfileValidation(format!(
                "Invalid timing: {}. Must be T0-T5",
                self.scan.timing
            )));
        }

        // Validate version intensity
        if let Some(intensity) = self.scan.version_intensity {
            if intensity > 9 {
                return Err(ScanManagementError::ProfileValidation(format!(
                    "Invalid version_intensity: {intensity}. Must be 0-9"
                )));
            }
        }

        // Validate EPSS threshold
        if let Some(threshold) = self.scan.epss_threshold {
            if !(0.0..=1.0).contains(&threshold) {
                return Err(ScanManagementError::ProfileValidation(format!(
                    "Invalid epss_threshold: {threshold}. Must be 0.0-1.0"
                )));
            }
        }

        Ok(())
    }

    /// Apply defaults to profile.
    #[must_use]
    pub fn with_defaults(mut self) -> Self {
        if self.scan.timing.is_empty() {
            self.scan.timing = default_timing();
        }
        if self.scan.scan_type.is_empty() {
            self.scan.scan_type = default_scan_type();
        }
        self
    }
}

/// Profile manager for handling multiple profiles.
#[derive(Debug)]
pub struct ProfileManager {
    profiles: HashMap<String, ScanProfile>,
    profile_dir: Option<String>,
}

impl ProfileManager {
    /// Create a new profile manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            profile_dir: None,
        }
    }

    /// Create from profile directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read or profiles cannot be loaded.
    pub fn from_directory(path: &str) -> Result<Self> {
        let mut manager = Self::new();
        manager.profile_dir = Some(path.to_string());

        let dir_path = Path::new(path);
        if dir_path.exists() {
            let entries = tokio::task::block_in_place(|| {
                fs::read_dir(dir_path).map_err(ScanManagementError::from)
            })?;

            for entry in entries {
                let entry = entry.map_err(ScanManagementError::from)?;
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
                {
                    if let Ok(profile) = ScanProfile::from_file(&path) {
                        manager.profiles.insert(profile.name.clone(), profile);
                    }
                }
            }
        }

        Ok(manager)
    }

    /// Add a profile.
    pub fn add_profile(&mut self, profile: ScanProfile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// Get a profile by name.
    #[must_use]
    pub fn get_profile(&self, name: &str) -> Option<&ScanProfile> {
        self.profiles.get(name)
    }

    /// List all profiles.
    #[must_use]
    pub fn list_profiles(&self) -> Vec<&str> {
        self.profiles
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Validate all profiles.
    #[must_use]
    pub fn validate_all(&self) -> Vec<(String, Result<()>)> {
        self.profiles
            .iter()
            .map(|(name, profile)| (name.clone(), profile.validate()))
            .collect()
    }

    /// Generate a default profile template.
    #[must_use]
    pub fn generate_template() -> String {
        r#"# Scan Profile Template
name: "My Scan Profile"
description: "Custom scan configuration"

# Targets to scan
targets:
  - "192.168.1.0/24"
  - "10.0.0.0/8"

# Exclude these targets
exclude:
  - "192.168.1.1"  # Gateway

# Scan configuration
scan:
  type: "syn"           # syn, connect, fin, null, xmas, udp, etc.
  ports: "1-10000"      # Port range or "top-100", "top-1000"
  service_detection: true
  os_detection: true
  scripts:              # NSE scripts to run
    - "default"
    - "vuln"
  vulnerability_scan: true
  timing: "T3"          # T0 (paranoid) to T5 (insane)
  version_intensity: 5  # 0-9, service version detection intensity

# Output configuration
output:
  formats:
    - "json"
    - "html"
  directory: "/var/lib/rustnmap/reports/"
  save_to_history: true
"#
        .to_string()
    }
}

impl Default for ProfileManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_profile() {
        let yaml = r#"
name: "Test Profile"
description: "Test"
targets:
  - "192.168.1.0/24"
scan:
  type: "syn"
  ports: "1-1000"
  service_detection: true
  os_detection: false
  timing: "T3"
output:
  formats:
    - "json"
  save_to_history: true
"#;

        let profile = ScanProfile::from_yaml(yaml).unwrap();
        assert_eq!(profile.name, "Test Profile");
        assert_eq!(profile.scan.scan_type, "syn");
        assert!(profile.scan.service_detection);
        assert!(!profile.scan.os_detection);
    }

    #[test]
    fn test_validate_profile() {
        let yaml = r#"
name: "Valid Profile"
targets:
  - "10.0.0.0/8"
scan:
  type: "connect"
  ports: "top-100"
  timing: "T4"
output:
  save_to_history: true
"#;

        let profile = ScanProfile::from_yaml(yaml).unwrap();
        profile.validate().unwrap();
    }

    #[test]
    fn test_validate_invalid_timing() {
        let yaml = r#"
name: "Invalid Profile"
targets: []
scan:
  type: "syn"
  timing: "T9"
output:
  save_to_history: true
"#;

        let profile = ScanProfile::from_yaml(yaml).unwrap();
        assert!(profile.validate().is_err());
    }
}
