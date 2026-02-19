//! Service probe database loader and management.
//!
//! Handles loading and parsing of nmap-service-probes database files,
//! managing probe definitions and indexing by port and rarity.

use std::{collections::HashMap, path::Path};

use regex::Regex;
use tracing::info;

use super::probe::{MatchRule, MatchTemplate, ProbeDefinition, Protocol};
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

/// Version info fields parsed from match rule.
#[derive(Debug, Default)]
struct VersionInfo {
    product: Option<MatchTemplate>,
    version: Option<MatchTemplate>,
    info: Option<MatchTemplate>,
    hostname: Option<MatchTemplate>,
    os_type: Option<MatchTemplate>,
    device_type: Option<MatchTemplate>,
    cpe: Option<MatchTemplate>,
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
            } else if line.starts_with("softmatch ") {
                if let Some(ref mut probe) = current_probe {
                    let rule = Self::parse_match_rule(line, line_num)?;
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
        // The delimiter can be any character, not just |
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

        // Find the 'q' followed by a delimiter
        let q_pos = line.find('q').ok_or_else(|| FingerprintError::ParseError {
            line: line_num,
            content: "Missing payload marker 'q'".to_string(),
        })?;

        let after_q = &line[q_pos + 1..];
        if after_q.is_empty() {
            return Err(FingerprintError::ParseError {
                line: line_num,
                content: "Missing payload delimiter after 'q'".to_string(),
            });
        }

        // Get the delimiter (first character after 'q')
        let delimiter = after_q.chars().next().unwrap();
        let after_delimiter = &after_q[1..];

        // Find the closing delimiter
        let mut payload_end = 0;
        let mut escaped = false;

        for (i, ch) in after_delimiter.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == delimiter {
                payload_end = i;
                break;
            }
        }

        if payload_end == 0 && !after_delimiter.contains(delimiter) {
            return Err(FingerprintError::ParseError {
                line: line_num,
                content: format!("Unclosed payload delimiter '{delimiter}'"),
            });
        }

        let payload_str = &after_delimiter[..payload_end];
        let payload_bytes = Self::parse_payload(payload_str)?;

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
    ///
    /// Format: match <service> m<pattern>[opts] [versioninfo]
    ///         softmatch <service> m<pattern>[opts]
    ///
    /// Version info fields:
    ///   p/<product>/     - Product name
    ///   v/<version>/     - Version number
    ///   i/<info>/        - Additional info
    ///   h/<hostname>/    - Hostname
    ///   o/<ostype>/      - OS type
    ///   d/<devicetype>/  - Device type
    ///   cpe:/<cpe>/      - CPE identifier
    fn parse_match_rule(line: &str, line_num: usize) -> Result<MatchRule> {
        let is_soft = line.starts_with("softmatch");
        let content = if is_soft {
            line.strip_prefix("softmatch ").unwrap_or(line)
        } else {
            line.strip_prefix("match ").unwrap_or(line)
        };

        // Parse service name (first word)
        let mut parts = content.split_whitespace();
        let service = parts
            .next()
            .ok_or_else(|| FingerprintError::ParseError {
                line: line_num,
                content: "Missing service name in match rule".to_string(),
            })?
            .to_string();

        // Find the pattern directive starting with 'm'
        let pattern_start = content
            .find(" m")
            .ok_or_else(|| FingerprintError::ParseError {
                line: line_num,
                content: "Missing pattern directive in match rule".to_string(),
            })?;

        let after_service = &content[pattern_start + 1..];

        // Extract pattern using m<delimiter><regex><delimiter>[flags]
        let (pattern, flags, remainder) = Self::extract_pattern(after_service, line_num)?;

        // Build the regex with flags
        let full_pattern = Self::build_regex_pattern(&pattern, &flags);

        // Parse version info fields from remainder
        let version_info = Self::parse_version_info(remainder)?;

        Ok(MatchRule {
            pattern: full_pattern,
            service,
            product_template: version_info.product,
            version_template: version_info.version,
            info_template: version_info.info,
            hostname_template: version_info.hostname,
            os_type_template: version_info.os_type,
            device_type_template: version_info.device_type,
            cpe_template: version_info.cpe,
            soft: is_soft,
        })
    }

    /// Extract pattern from m<delimiter><regex><delimiter>[flags] format.
    fn extract_pattern(s: &str, line_num: usize) -> Result<(String, String, &str)> {
        // Find 'm' followed by a delimiter
        let m_pos = s.find('m').ok_or_else(|| FingerprintError::ParseError {
            line: line_num,
            content: "Missing pattern marker 'm'".to_string(),
        })?;

        let after_m = &s[m_pos + 1..];
        if after_m.is_empty() {
            return Err(FingerprintError::ParseError {
                line: line_num,
                content: "Empty pattern after 'm'".to_string(),
            });
        }

        // Get the delimiter (first character after 'm')
        let delimiter = after_m.chars().next().unwrap();
        let after_delimiter = &after_m[1..];

        // Find the closing delimiter
        let mut pattern_end = 0;
        let mut escaped = false;

        for (i, ch) in after_delimiter.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == delimiter {
                pattern_end = i;
                break;
            }
        }

        if pattern_end == 0 && !after_delimiter.contains(delimiter) {
            return Err(FingerprintError::ParseError {
                line: line_num,
                content: format!("Unclosed pattern delimiter '{delimiter}'"),
            });
        }

        let pattern = after_delimiter[..pattern_end].to_string();
        let after_pattern = &after_delimiter[pattern_end + 1..];

        // Extract flags (i, s, etc.) until whitespace or end
        let flags: String = after_pattern
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();

        // Find the remainder after flags
        let remainder_start = flags.len().min(after_pattern.len());
        let remainder = &after_pattern[remainder_start..];

        Ok((pattern, flags, remainder))
    }

    /// Build full regex pattern with flags.
    fn build_regex_pattern(pattern: &str, flags: &str) -> String {
        let mut result = String::with_capacity(pattern.len() + 10);

        // Start with (?flags) if we have any
        let mut rust_flags = String::new();
        if flags.contains('i') {
            rust_flags.push('i');
        }
        if flags.contains('s') {
            // Rust's dot matches newlines by default in some modes,
            // but we use (?s) for single-line mode
            rust_flags.push('s');
        }

        if !rust_flags.is_empty() {
            result.push_str("(?");
            result.push_str(&rust_flags);
            result.push(')');
        }

        result.push_str(pattern);
        result
    }

    /// Parse version info fields from remainder of match line.
    fn parse_version_info(s: &str) -> Result<VersionInfo> {
        let mut info = VersionInfo {
            product: None,
            version: None,
            info: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: None,
        };

        let mut remaining = s;

        while !remaining.is_empty() {
            remaining = remaining.trim_start();
            if remaining.is_empty() {
                break;
            }

            // Try to extract each field type
            if let Some((field, rest)) = Self::extract_version_field(remaining)? {
                match field.0 {
                    'p' => info.product = Some(MatchTemplate { value: field.1 }),
                    'v' => info.version = Some(MatchTemplate { value: field.1 }),
                    'i' => info.info = Some(MatchTemplate { value: field.1 }),
                    'h' => info.hostname = Some(MatchTemplate { value: field.1 }),
                    'o' => info.os_type = Some(MatchTemplate { value: field.1 }),
                    'd' => info.device_type = Some(MatchTemplate { value: field.1 }),
                    'c' => info.cpe = Some(MatchTemplate { value: field.1 }),
                    _ => {}
                }
                remaining = rest;
            } else {
                // Could not extract a field, skip to next whitespace
                if let Some(pos) = remaining.find(|c: char| c.is_whitespace()) {
                    remaining = &remaining[pos..];
                } else {
                    break;
                }
            }
        }

        Ok(info)
    }

    /// Extract a single version field (p/, v/, i/, h/, o/, d/, cpe/).
    /// Returns ((`field_type`, value), remaining) or None.
    fn extract_version_field(s: &str) -> Result<Option<((char, String), &str)>> {
        let s = s.trim_start();
        if s.is_empty() {
            return Ok(None);
        }

        // Check for field prefixes
        let (field_type, after_prefix) = if let Some(stripped) = s.strip_prefix("cpe:") {
            // CPE field: cpe:/value/
            ('c', stripped)
        } else if let Some(first) = s.chars().next() {
            if "pvihod".contains(first) && s.len() > 1 && s.as_bytes()[1] == b'/' {
                (first, &s[2..])
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        };

        // In nmap format, the delimiter is the character right after the field type
        // For p/OpenSSH/, the delimiter is '/' and after_prefix already starts with value
        // For cpe:/value/, after_prefix starts with '/' followed by the value
        // So we need to handle both cases
        let delimiter = '/';
        let after_delimiter = if let Some(stripped) = after_prefix.strip_prefix('/') {
            stripped
        } else {
            after_prefix
        };

        // Find closing delimiter
        let mut value_end = 0;
        let mut escaped = false;

        for (i, ch) in after_delimiter.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == delimiter {
                value_end = i;
                break;
            }
        }

        // Check if we found the closing delimiter
        // value_end will be 0 if the delimiter is at position 0 (empty value) or if not found
        let found_delimiter = after_delimiter.chars().enumerate().any(|(i, ch)| {
            if i == 0 && ch == delimiter {
                return true;
            }
            false
        });

        if value_end == 0 && !found_delimiter {
            // Unclosed field, treat as empty
            return Ok(None);
        }

        let value = after_delimiter[..value_end].to_string();
        let remaining = &after_delimiter[value_end + 1..];

        Ok(Some(((field_type, value), remaining)))
    }

    /// Parse port list from directive.
    fn parse_ports(s: &str) -> Result<Vec<u16>> {
        let mut ports = Vec::new();
        let split_parts: Vec<&str> = s.split(',').collect();

        for part in split_parts {
            let trimmed = part.trim();
            if let Some(range_idx) = trimmed.find('-') {
                // Range: "80-85"
                let start: u16 =
                    trimmed[..range_idx]
                        .parse()
                        .map_err(|_| FingerprintError::ParseError {
                            line: 0,
                            content: format!("Invalid port range start: {trimmed}"),
                        })?;
                let end: u16 =
                    trimmed[range_idx + 1..]
                        .parse()
                        .map_err(|_| FingerprintError::ParseError {
                            line: 0,
                            content: format!("Invalid port range end: {trimmed}"),
                        })?;
                ports.extend(start..=end);
            } else {
                // Single port
                let port: u16 = trimmed.parse().map_err(|_| FingerprintError::ParseError {
                    line: 0,
                    content: format!("Invalid port: {trimmed}"),
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
        let content = r"
# Test service probe database
Probe TCP GenericLines q|\r\n\r\n|
rarity 1
Ports 1-65535
Match ssh m|^SSH-([\d.]+)| p/OpenSSH/ v/$1/

Probe TCP HTTP q|GET / HTTP/1.0\r\n\r\n|
rarity 3
Ports 80,8080
Match http m|^Server: ([\w/]+)| p/$1/
";
        let db = ProbeDatabase::parse(content).unwrap();

        assert_eq!(db.probe_count(), 2);
        assert!(db.get_probe("GenericLines").is_some());
        assert!(db.get_probe("HTTP").is_some());

        // Verify match rules were parsed correctly
        let generic_probe = db.get_probe("GenericLines").unwrap();
        assert_eq!(generic_probe.matches.len(), 1);
        assert_eq!(generic_probe.matches[0].service, "ssh");
        assert_eq!(
            generic_probe.matches[0]
                .product_template
                .as_ref()
                .map(|t| t.value.clone()),
            Some("OpenSSH".to_string())
        );
        assert_eq!(
            generic_probe.matches[0]
                .version_template
                .as_ref()
                .map(|t| t.value.clone()),
            Some("$1".to_string())
        );

        let http_probe = db.get_probe("HTTP").unwrap();
        assert_eq!(http_probe.matches.len(), 1);
        assert_eq!(http_probe.matches[0].service, "http");
        assert_eq!(
            http_probe.matches[0]
                .product_template
                .as_ref()
                .map(|t| t.value.clone()),
            Some("$1".to_string())
        );
    }

    #[test]
    fn test_invalid_port_range() {
        let result = ProbeDatabase::parse_ports("abc-def");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_info_fields() {
        let remainder = " p/OpenSSH/ v/$1/ i/protocol 2.0/";
        let info = ProbeDatabase::parse_version_info(remainder).unwrap();

        assert!(info.product.is_some());
        assert_eq!(info.product.as_ref().unwrap().value, "OpenSSH");

        assert!(info.version.is_some());
        assert_eq!(info.version.as_ref().unwrap().value, "$1");

        assert!(info.info.is_some());
        assert_eq!(info.info.as_ref().unwrap().value, "protocol 2.0");
    }

    #[test]
    fn test_extract_version_field() {
        // Test basic extraction first
        let result = ProbeDatabase::extract_version_field("p/OpenSSH/ rest");
        println!("Result: {result:?}");
        assert!(result.is_ok());
        assert!(
            result.as_ref().unwrap().is_some(),
            "Expected Some but got None"
        );

        // Test p/ field
        let (field, rest) = result.unwrap().unwrap();
        assert_eq!(field.0, 'p');
        assert_eq!(field.1, "OpenSSH");
        assert_eq!(rest, " rest");

        // Test v/ field
        let (field, rest) = ProbeDatabase::extract_version_field("v/$1/ rest")
            .unwrap()
            .unwrap();
        assert_eq!(field.0, 'v');
        assert_eq!(field.1, "$1");
        assert_eq!(rest, " rest");

        // Test cpe:/ field
        let (field, rest) = ProbeDatabase::extract_version_field("cpe:/a:openbsd:openssh:$1/ rest")
            .unwrap()
            .unwrap();
        assert_eq!(field.0, 'c');
        assert_eq!(field.1, "a:openbsd:openssh:$1");
        assert_eq!(rest, " rest");
    }

    #[test]
    fn test_extract_pattern() {
        // Test with | delimiter
        let (pattern, flags, remainder) =
            ProbeDatabase::extract_pattern("m|^SSH-([\\d.]+)| p/OpenSSH/", 1).unwrap();
        assert_eq!(pattern, "^SSH-([\\d.]+)");
        assert_eq!(flags, "");
        assert_eq!(remainder, " p/OpenSSH/");

        // Test with / delimiter and flags
        let (pattern, flags, remainder) =
            ProbeDatabase::extract_pattern("m/SSH-([\\d.]+)/i p/OpenSSH/", 1).unwrap();
        assert_eq!(pattern, "SSH-([\\d.]+)");
        assert_eq!(flags, "i");
        assert_eq!(remainder, " p/OpenSSH/");
    }
}
