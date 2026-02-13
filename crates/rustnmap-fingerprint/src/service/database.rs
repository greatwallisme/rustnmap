//! Service probe database loader and management.
//!
//! Handles loading and parsing of nmap-service-probes database files,
//! managing probe definitions and indexing by port and rarity.

use std::{collections::HashMap, path::Path};

use regex::Regex;
use tracing::info;

use super::probe::{MatchRule, ProbeDefinition, Protocol};
use crate::{FingerprintError, Result};

/// Database of service probes for version detection.
///
/// Indexes probes by rarity level and port for efficient
/// probe selection during scanning.
#[derive(Debug, Clone)]
pub struct ProbeDatabase {
    /// All probe definitions indexed by name.
    probes: HashMap<String, ProbeDefinition>,

    /// Maps port numbers to probe names that should run on that port.
    port_mapping: HashMap<u16, Vec<String>>,

    /// Maps rarity levels (1-9) to probe names at that level.
    intensity_levels: HashMap<u8, Vec<String>>,
}

/// Service probe for a specific port.
///
/// Used internally to associate probes with target ports.
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    /// Probe definition containing payload and match rules.
    pub definition: ProbeDefinition,

    /// Compiled regex for each match rule.
    pub match_regexes: Vec<Regex>,
}

impl ProbeDatabase {
    /// Empty database with no probes.
    pub fn empty() -> Self {
        Self {
            probes: HashMap::new(),
            port_mapping: HashMap::new(),
            intensity_levels: HashMap::new(),
        }
    }

    /// Load probes from nmap-service-probes database file.
    pub async fn load_from_nmap_db(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Check if file exists first
        if !path.try_exists().map_err(|e| FingerprintError::Io {
            path: path.to_path_buf(),
            source: e,
        })? {
            return Err(FingerprintError::DatabaseNotFound {
                path: path.to_path_buf(),
            });
        }

        let content = tokio::fs::read(path)
            .await
            .map_err(|e| FingerprintError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        let content_str = String::from_utf8_lossy(&content);
        Self::parse(&content_str)
    }

    /// Load probes from string content (for testing).
    pub fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();

        let mut line_num = 0;
        let mut current_probe: Option<ProbeDefinition> = None;

        for line in content.lines() {
            line_num += 1;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse directive lines
            if let Some(rest) = line.strip_prefix("Match ") {
                if let Some(ref mut probe) = current_probe {
                    let rule = Self::parse_match_rule(rest, line_num)?;
                    probe.matches.push(rule);
                }
            } else if let Some(rest) = line.strip_prefix("Probe ") {
                // Save previous probe if exists
                if let Some(probe) = current_probe {
                    db.add_probe(probe)?;
                }
                current_probe = Some(Self::parse_probe_directive(rest, line_num)?);
            } else if let Some(rest) = line.strip_prefix("Ports ") {
                if let Some(ref mut probe) = current_probe {
                    probe.ports = Self::parse_ports(rest)?;
                }
            } else if let Some(rest) = line.strip_prefix("sslPorts ") {
                if let Some(ref mut probe) = current_probe {
                    probe.ssl_ports = Self::parse_ports(rest)?;
                }
            } else if let Some(rest) = line.strip_prefix("rarity ") {
                if let Some(ref mut probe) = current_probe {
                    probe.rarity = Self::parse_rarity(rest)?;
                }
            }
        }

        // Add final probe
        if let Some(probe) = current_probe {
            db.add_probe(probe)?;
        }

        info!("Loaded {} service probes from database", db.probes.len());
        Ok(db)
    }

    /// Parse probe directive line.
    fn parse_probe_directive(line: &str, line_num: usize) -> Result<ProbeDefinition> {
        // Format: "Probe TCP Name q|payload|" or "Probe UDP Name q|payload|"
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(FingerprintError::ParseError {
                line: line_num,
                content: line.to_string(),
            });
        }

        let protocol = match parts[0] {
            "TCP" | "tcp" => Protocol::Tcp,
            "UDP" | "udp" => Protocol::Udp,
            _ => {
                return Err(FingerprintError::ParseError {
                    line: line_num,
                    content: format!("Unknown protocol: {}", parts[0]),
                });
            }
        };

        let name = parts[1].to_string();

        // Extract payload between q|...|
        let payload_start = line
            .find("q|")
            .ok_or_else(|| FingerprintError::ParseError {
                line: line_num,
                content: "Missing payload delimiter q|".to_string(),
            })?
            + 2;

        let payload_end = line[3..]
            .rfind("|")
            .ok_or_else(|| FingerprintError::ParseError {
                line: line_num,
                content: "Missing closing pipe |".to_string(),
            })?
            + 3;

        let payload_bytes = Self::parse_payload(&line[payload_start..=payload_end])?;

        Ok(ProbeDefinition {
            name,
            protocol,
            ports: Vec::new(),
            payload: payload_bytes,
            rarity: 5,
            ssl_ports: Vec::new(),
            matches: Vec::new(),
        })
    }

    /// Parse payload string with escape sequences.
    fn parse_payload(s: &str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut chars = s.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    if let Some(next_ch) = chars.next() {
                        match next_ch {
                            'r' => bytes.push(b'\r'),
                            'n' => bytes.push(b'\n'),
                            't' => bytes.push(b'\t'),
                            '0' => bytes.push(0x00),
                            '\\' => bytes.push(b'\\'),
                            'x' => {
                                // Hex escape \xHH
                                let hex1 = chars.next().unwrap_or('0');
                                let hex2 = chars.next().unwrap_or('0');
                                let hex_str = format!("{hex1}{hex2}");
                                let byte = u8::from_str_radix(&hex_str, 16).unwrap_or(0);
                                bytes.push(byte);
                            }
                            _ => {
                                // Unknown escape, keep backslash and char
                                bytes.push(b'\\');
                                bytes.push(next_ch as u8);
                            }
                        }
                    }
                }
                _ => bytes.push(ch as u8),
            }
        }

        Ok(bytes)
    }

    /// Parse match rule directive.
    fn parse_match_rule(line: &str, _line_num: usize) -> Result<MatchRule> {
        // TODO: Implement full nmap match rule parser with:
        // - Version templates ($1, $2, etc.)
        // - Soft match detection
        // - Multiple match patterns per rule
        // - Service-specific overrides
        // Currently handles basic: m/regex/ p/service/...
        let mut rule = MatchRule {
            pattern: ".*".to_string(),
            service: "unknown".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        };

        // Extract regex from m/pattern/
        if let Some(start) = line.find("m/") {
            if let Some(end) = line[start + 2..].find('/') {
                rule.pattern = line[start + 2..start + 2 + end].to_string();
            }
        }

        // Extract service from p/service/
        if let Some(start) = line.find("p/") {
            let rest = &line[start + 2..];
            if let Some(end) = rest.find('/') {
                rule.service = rest[..end].to_string();
            }
        }

        // Mark soft matches with s/
        if line.contains("s/") {
            rule.soft = true;
        }

        Ok(rule)
    }

    /// Parse port list from directive.
    fn parse_ports(s: &str) -> Result<Vec<u16>> {
        let mut ports = Vec::new();
        let parts: Vec<&str> = s.split(',').collect();

        for part in parts {
            let part = part.trim();
            if let Some(range_idx) = part.find('-') {
                // Range: "80-85"
                let start: u16 =
                    part[..range_idx]
                        .parse()
                        .map_err(|_| FingerprintError::ParseError {
                            line: 0,
                            content: format!("Invalid port range start: {part}"),
                        })?;
                let end: u16 =
                    part[range_idx + 1..]
                        .parse()
                        .map_err(|_| FingerprintError::ParseError {
                            line: 0,
                            content: format!("Invalid port range end: {part}"),
                        })?;
                ports.extend(start..=end);
            } else {
                // Single port
                let port: u16 = part.parse().map_err(|_| FingerprintError::ParseError {
                    line: 0,
                    content: format!("Invalid port: {part}"),
                })?;
                ports.push(port);
            }
        }

        Ok(ports)
    }

    /// Parse rarity value.
    fn parse_rarity(s: &str) -> Result<u8> {
        let rarity: u8 = s.trim().parse().map_err(|_| FingerprintError::ParseError {
            line: 0,
            content: format!("Invalid rarity: {s}"),
        })?;
        Ok(rarity.clamp(1, 9))
    }

    /// Add a probe to the database.
    fn add_probe(&mut self, probe: ProbeDefinition) -> Result<()> {
        let name = probe.name.clone();

        // Check for duplicate probe names
        if self.probes.contains_key(&name) {
            return Err(FingerprintError::InvalidProbe {
                reason: format!("Duplicate probe name: {name}"),
            });
        }

        // Index by port
        if probe.ports.is_empty() {
            // Universal probe - add to all ports
            for port in 1..=65535 {
                self.port_mapping
                    .entry(port)
                    .or_default()
                    .push(name.clone());
            }
        } else {
            for port in &probe.ports {
                self.port_mapping
                    .entry(*port)
                    .or_default()
                    .push(name.clone());
            }
        }

        // Index by rarity
        self.intensity_levels
            .entry(probe.rarity)
            .or_default()
            .push(name.clone());

        self.probes.insert(name, probe);
        Ok(())
    }

    /// Get probes for a specific port.
    pub fn probes_for_port(&self, port: u16) -> Vec<&ProbeDefinition> {
        let mut probe_names: Vec<String> =
            self.port_mapping.get(&port).cloned().unwrap_or_default();

        // If no port-specific probes, return universal probes
        if probe_names.is_empty() {
            probe_names = self.probes.keys().cloned().collect();
        }

        probe_names
            .iter()
            .filter_map(|name| self.probes.get(name))
            .collect()
    }

    /// Get probes for a specific intensity level (1-9).
    pub fn probes_for_intensity(&self, intensity: u8) -> Vec<&ProbeDefinition> {
        self.intensity_levels
            .get(&intensity.clamp(1, 9))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .filter_map(|name| self.probes.get(name))
            .collect()
    }

    /// Get all probe names in the database.
    pub fn all_probe_names(&self) -> Vec<&str> {
        self.probes.keys().map(|s| s.as_str()).collect()
    }

    /// Get probe by name.
    pub fn get_probe(&self, name: &str) -> Option<&ProbeDefinition> {
        self.probes.get(name)
    }

    /// Get number of probes in database.
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }
}

impl Default for ProbeDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_database() {
        let db = ProbeDatabase::empty();
        assert_eq!(db.probe_count(), 0);
        assert!(db.probes_for_port(80).is_empty());
    }

    #[test]
    fn test_parse_payload_simple() {
        let payload = ProbeDatabase::parse_payload("Hello World").unwrap();
        assert_eq!(payload, b"Hello World");
    }

    #[test]
    fn test_parse_payload_escapes() {
        let payload = ProbeDatabase::parse_payload(r"Hello\r\nWorld\t\x00").unwrap();
        assert_eq!(payload, b"Hello\r\nWorld\t\x00");
    }

    #[test]
    fn test_parse_ports_single() {
        let ports = ProbeDatabase::parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_multiple() {
        let ports = ProbeDatabase::parse_ports("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = ProbeDatabase::parse_ports("80-85").unwrap();
        assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = ProbeDatabase::parse_ports("80,443,8000-8010").unwrap();
        assert_eq!(ports[..3], vec![80, 443, 8000]);
        assert_eq!(ports.len(), 13); // 80, 443, 8000-8010
    }

    #[test]
    fn test_parse_rarity_valid() {
        assert_eq!(ProbeDatabase::parse_rarity("5").unwrap(), 5);
        assert_eq!(ProbeDatabase::parse_rarity("1").unwrap(), 1);
        assert_eq!(ProbeDatabase::parse_rarity("9").unwrap(), 9);
    }

    #[test]
    fn test_parse_rarity_clamp() {
        // Below minimum
        assert_eq!(ProbeDatabase::parse_rarity("0").unwrap(), 1);
        // Above maximum
        assert_eq!(ProbeDatabase::parse_rarity("10").unwrap(), 9);
    }

    #[test]
    fn test_simple_database_parse() {
        let content = r#"
# Test service probe database
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
Ports 1-65535
Match ssh m|^SSH-([\d.]+) p/OpenSSH/$1/

Probe TCP HTTP q|GET / HTTP/1.0\r\n\r\n|
rarity 3
Ports 80,8080
Match http m|^Server: ([\w/]+) p/$1/
"#;
        let db = ProbeDatabase::parse(content).unwrap();

        assert_eq!(db.probe_count(), 2);
        assert!(db.get_probe("GenericLines").is_some());
        assert!(db.get_probe("HTTP").is_some());
    }

    #[test]
    fn test_invalid_port_range() {
        let result = ProbeDatabase::parse_ports("abc-def");
        assert!(result.is_err());
    }
}
