//! Scan profile configuration

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ScanError, ScanResult};
use rustnmap_core::session::ScanConfig;

/// Scan profile for YAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    /// Profile name
    pub name: String,

    /// Profile description
    pub description: Option<String>,

    /// Target hosts/networks
    pub targets: Vec<String>,

    /// Excluded targets
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Scan configuration
    pub scan: ScanSettings,

    /// Timing template
    #[serde(default)]
    pub timing: String,

    /// Output configuration
    #[serde(default)]
    pub output: OutputSettings,
}

/// Scan settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "ScanSettings is a configuration struct where bool fields represent independent feature flags"
)]
pub struct ScanSettings {
    /// Scan type
    #[serde(default = "default_scan_type")]
    pub scan_type: String,

    /// Ports to scan
    #[serde(default)]
    pub ports: Option<String>,

    /// Service detection
    #[serde(default)]
    pub service_detection: bool,

    /// OS detection
    #[serde(default)]
    pub os_detection: bool,

    /// Vulnerability scanning
    #[serde(default)]
    pub vulnerability_scan: bool,

    /// NSE scripts
    #[serde(default)]
    pub scripts: Vec<String>,

    /// Traceroute
    #[serde(default)]
    pub traceroute: bool,
}

fn default_scan_type() -> String {
    "syn".to_string()
}

/// Output settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSettings {
    /// Output formats
    #[serde(default)]
    pub formats: Vec<String>,

    /// Output directory
    #[serde(default)]
    pub directory: Option<String>,
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: None,
            targets: vec![],
            exclude: vec![],
            scan: ScanSettings {
                scan_type: "syn".to_string(),
                ports: None,
                service_detection: false,
                os_detection: false,
                vulnerability_scan: false,
                scripts: vec![],
                traceroute: false,
            },
            timing: "T3".to_string(),
            output: OutputSettings::default(),
        }
    }
}

impl Default for OutputSettings {
    fn default() -> Self {
        Self {
            formats: vec!["json".to_string()],
            directory: None,
        }
    }
}

impl ScanProfile {
    /// Load profile from YAML file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the YAML is invalid.
    pub fn from_file<P: AsRef<Path>>(path: P) -> ScanResult<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ScanError::InternalError(e.into()))?;

        let profile: ScanProfile = serde_yaml::from_str(&content)
            .map_err(|e| ScanError::InvalidRequest(format!("Invalid YAML: {e}")))?;

        Ok(profile)
    }

    /// Save profile to YAML file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or the profile cannot be serialized.
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> ScanResult<()> {
        let content =
            serde_yaml::to_string(self).map_err(|e| ScanError::InternalError(e.into()))?;

        std::fs::write(path.as_ref(), content).map_err(|e| ScanError::InternalError(e.into()))?;

        Ok(())
    }

    /// Convert to `ScanConfig`
    ///
    /// # Errors
    ///
    /// Returns an error if the scan type is unknown.
    pub fn to_scan_config(&self) -> ScanResult<ScanConfig> {
        let mut config = ScanConfig::default();

        // Set ports
        if let Some(ref ports) = self.scan.ports {
            // Parse port specification
            let port_spec = match ports.as_str() {
                "1-65535" | "all" | "*" => rustnmap_core::session::PortSpec::All,
                s if s.starts_with("top") => {
                    let n: usize = s.trim_start_matches("top").trim().parse().unwrap_or(1000);
                    rustnmap_core::session::PortSpec::Top(n)
                }
                s => {
                    // Try to parse as single range like "1-1000"
                    if let Some((start, end)) = s.split_once('-') {
                        let start: u16 = start.parse().unwrap_or(1);
                        let end: u16 = end.parse().unwrap_or(1000);
                        rustnmap_core::session::PortSpec::Range { start, end }
                    } else {
                        // Single port
                        let port: u16 = s.parse().unwrap_or(1000);
                        rustnmap_core::session::PortSpec::Range {
                            start: port,
                            end: port,
                        }
                    }
                }
            };
            config.port_spec = port_spec;
        }

        config.service_detection = self.scan.service_detection;
        config.os_detection = self.scan.os_detection;

        // Parse scan type
        config.scan_types = match self.scan.scan_type.as_str() {
            "syn" => vec![rustnmap_core::session::ScanType::TcpSyn],
            "connect" => vec![rustnmap_core::session::ScanType::TcpConnect],
            "fin" => vec![rustnmap_core::session::ScanType::TcpFin],
            "null" => vec![rustnmap_core::session::ScanType::TcpNull],
            "xmas" => vec![rustnmap_core::session::ScanType::TcpXmas],
            "ack" => vec![rustnmap_core::session::ScanType::TcpAck],
            "window" => vec![rustnmap_core::session::ScanType::TcpWindow],
            "maimon" => vec![rustnmap_core::session::ScanType::TcpMaimon],
            "udp" => vec![rustnmap_core::session::ScanType::Udp],
            _ => {
                return Err(ScanError::InvalidRequest(format!(
                    "Unknown scan type: {}",
                    self.scan.scan_type
                )))
            }
        };

        Ok(config)
    }
}

/// Profile manager for loading and listing profiles
#[derive(Debug)]
pub struct ProfileManager {
    profile_dir: Option<std::path::PathBuf>,
}

impl ProfileManager {
    /// Create a new profile manager
    #[must_use]
    pub fn new() -> Self {
        Self { profile_dir: None }
    }

    /// Set the profile directory
    #[must_use]
    pub fn with_profile_dir<P: Into<std::path::PathBuf>>(mut self, path: P) -> Self {
        self.profile_dir = Some(path.into());
        self
    }

    /// Load a profile by name
    ///
    /// # Errors
    ///
    /// Returns an error if the profile is not found or cannot be loaded.
    pub fn load_profile(&self, name: &str) -> ScanResult<ScanProfile> {
        let path = if let Some(dir) = &self.profile_dir {
            dir.join(format!("{name}.yaml"))
        } else {
            // Default profile locations
            let system_dir = std::path::Path::new("/etc/rustnmap/profiles");
            let home_dir = dirs::home_dir().map(|h| h.join(".config/rustnmap/profiles"));

            // Try system directory first, then home directory
            if system_dir.exists() {
                system_dir.join(format!("{name}.yaml"))
            } else if let Some(hd) = &home_dir {
                hd.join(format!("{name}.yaml"))
            } else {
                return Err(ScanError::InvalidRequest(
                    "Profile directory not configured and no default found".to_string(),
                ));
            }
        };

        if !path.exists() {
            return Err(ScanError::InvalidRequest(format!(
                "Profile '{name}' not found at {}",
                path.display()
            )));
        }

        ScanProfile::from_file(&path)
    }

    /// List available profiles
    ///
    /// # Errors
    ///
    /// Returns an error if the profile directory cannot be read.
    pub fn list_profiles(&self) -> ScanResult<Vec<String>> {
        let dirs: Vec<_> = if let Some(dir) = &self.profile_dir {
            vec![dir.clone()]
        } else {
            let mut dirs = vec![];
            let system_dir = std::path::Path::new("/etc/rustnmap/profiles");
            if system_dir.exists() {
                dirs.push(system_dir.to_path_buf());
            }
            if let Some(hd) = dirs::home_dir() {
                dirs.push(hd.join(".config/rustnmap/profiles"));
            }
            dirs
        };

        let mut profiles = Vec::new();
        for dir in dirs {
            if dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            if std::path::Path::new(name)
                                .extension()
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
                            {
                                profiles.push(name.trim_end_matches(".yaml").to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(profiles)
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
    fn test_scan_profile_default() {
        let profile = ScanProfile::default();
        assert_eq!(profile.name, "default");
        assert_eq!(profile.scan.scan_type, "syn");
    }

    #[test]
    fn test_profile_manager() {
        let manager = ProfileManager::new();
        let profiles = manager.list_profiles().unwrap();
        assert!(profiles.is_empty()); // No profiles in default locations
    }
}
