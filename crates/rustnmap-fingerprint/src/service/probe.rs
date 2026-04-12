//! Service probe definitions and pattern matching.

use std::collections::HashMap;
use std::sync;

use pcre2::bytes::Regex;
use serde::{Deserialize, Serialize};

use crate::Result;

/// Service probe definition from nmap-service-probes database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeDefinition {
    /// Probe name (e.g., "`GenericLines`", "`GetRequest`", "`SSH`").
    pub name: String,

    /// Protocol: TCP or UDP.
    pub protocol: Protocol,

    /// Target ports for this probe. Empty means all ports.
    #[serde(default)]
    pub ports: Vec<u16>,

    /// Raw probe payload bytes.
    pub payload: Vec<u8>,

    /// Probe rarity (1-9). Lower rarity = more common services.
    #[serde(default = "default_rarity")]
    pub rarity: u8,

    /// Ports that require SSL wrapping.
    #[serde(default)]
    pub ssl_ports: Vec<u16>,

    /// Match rules for responses to this probe.
    #[serde(default)]
    pub matches: Vec<MatchRule>,
}

fn default_rarity() -> u8 {
    5
}

/// Network protocol for service probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
}

/// Match rule for parsing probe responses.
#[derive(Serialize, Deserialize)]
pub struct MatchRule {
    /// Regex pattern to match against response.
    pub pattern: String,

    /// Service name if pattern matches.
    pub service: String,

    /// Product name template (optional).
    #[serde(rename = "product")]
    pub product_template: Option<MatchTemplate>,

    /// Version string template (optional).
    #[serde(rename = "version")]
    pub version_template: Option<MatchTemplate>,

    /// Additional info template (optional).
    #[serde(rename = "info")]
    pub info_template: Option<MatchTemplate>,

    /// Hostname template (optional).
    #[serde(rename = "hostname")]
    pub hostname_template: Option<MatchTemplate>,

    /// OS type template (optional).
    #[serde(rename = "ostype")]
    pub os_type_template: Option<MatchTemplate>,

    /// Device type template (optional).
    #[serde(rename = "devicetype")]
    pub device_type_template: Option<MatchTemplate>,

    /// CPE template (optional).
    #[serde(rename = "cpe")]
    pub cpe_template: Option<MatchTemplate>,

    /// Whether this is a soft match (lower confidence).
    #[serde(default)]
    pub soft: bool,
}

/// Global regex cache keyed by pattern string.  Lives here rather than inside
/// each `MatchRule` so that `MatchRule` can stay `Clone + Serialize`.
/// Identical patterns across different probes share one compiled `Regex`.
static REGEX_CACHE: sync::LazyLock<sync::RwLock<HashMap<String, sync::Arc<Regex>>>> =
    sync::LazyLock::new(|| sync::RwLock::new(HashMap::new()));

/// Template for extracting structured data from regex matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchTemplate {
    /// Template string with variable substitution markers.
    pub value: String,
}

impl std::fmt::Debug for MatchRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchRule")
            .field("pattern", &self.pattern)
            .field("service", &self.service)
            .field("soft", &self.soft)
            .finish_non_exhaustive()
    }
}

impl Clone for MatchRule {
    fn clone(&self) -> Self {
        Self {
            pattern: self.pattern.clone(),
            service: self.service.clone(),
            product_template: self.product_template.clone(),
            version_template: self.version_template.clone(),
            info_template: self.info_template.clone(),
            hostname_template: self.hostname_template.clone(),
            os_type_template: self.os_type_template.clone(),
            device_type_template: self.device_type_template.clone(),
            cpe_template: self.cpe_template.clone(),
            soft: self.soft,
        }
    }
}

/// Result of applying a match rule to a response.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Detected service name.
    pub service: String,

    /// Product name with variables substituted.
    pub product: Option<String>,

    /// Version string with variables substituted.
    pub version: Option<String>,

    /// Additional info with variables substituted.
    pub info: Option<String>,

    /// Hostname with variables substituted.
    pub hostname: Option<String>,

    /// OS type with variables substituted.
    pub os_type: Option<String>,

    /// Device type with variables substituted.
    pub device_type: Option<String>,

    /// CPE with variables substituted.
    pub cpe: Option<String>,

    /// Confidence score (0-10).
    pub confidence: u8,
}

impl ProbeDefinition {
    /// Create a new TCP probe with specified payload.
    #[must_use]
    pub fn new_tcp(name: String, payload: Vec<u8>) -> Self {
        Self {
            name,
            protocol: Protocol::Tcp,
            ports: Vec::new(),
            payload,
            rarity: 5,
            ssl_ports: Vec::new(),
            matches: Vec::new(),
        }
    }

    /// Create a new UDP probe with specified payload.
    #[must_use]
    pub fn new_udp(name: String, payload: Vec<u8>) -> Self {
        Self {
            name,
            protocol: Protocol::Udp,
            ports: Vec::new(),
            payload,
            rarity: 5,
            ssl_ports: Vec::new(),
            matches: Vec::new(),
        }
    }

    /// Add a match rule to this probe.
    pub fn add_match(&mut self, rule: MatchRule) -> &mut Self {
        self.matches.push(rule);
        self
    }

    /// Set rarity level (1-9).
    pub fn with_rarity(&mut self, rarity: u8) -> &mut Self {
        self.rarity = rarity.clamp(1, 9);
        self
    }

    /// Add target ports for this probe.
    pub fn with_ports(&mut self, ports: &[u16]) -> &mut Self {
        self.ports.extend_from_slice(ports);
        self
    }

    /// Check if this probe should run on a specific port.
    #[must_use]
    pub fn matches_port(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.contains(&port)
    }
}

impl MatchRule {
    /// Get the compiled regex, compiling lazily on first access.
    /// Uses a global cache keyed by pattern string so identical
    /// patterns across probes share one compiled `Regex`.
    ///
    /// # Errors
    /// Returns error if the regex pattern is invalid.
    pub fn compile_regex(&self) -> Result<sync::Arc<Regex>> {
        // Fast path: read lock
        {
            let cache = REGEX_CACHE.read().expect("regex cache lock poisoned");
            if let Some(regex) = cache.get(&self.pattern) {
                return Ok(sync::Arc::clone(regex));
            }
        }
        // Slow path: compile and insert under write lock
        let regex = Regex::new(&self.pattern).map_err(|e| {
            crate::error::FingerprintError::InvalidRegex {
                pattern: self.pattern.clone(),
                reason: e.to_string(),
            }
        })?;
        let arc = sync::Arc::new(regex);
        let mut cache = REGEX_CACHE.write().expect("regex cache lock poisoned");
        cache
            .entry(self.pattern.clone())
            .or_insert_with(|| sync::Arc::clone(&arc));
        Ok(arc)
    }

    /// Apply this match rule to a response with captured groups.
    #[must_use]
    pub fn apply(&self, captures: &HashMap<usize, Vec<u8>>) -> MatchResult {
        let confidence = if self.soft { 5 } else { 8 };

        MatchResult {
            service: self.service.clone(),
            product: Self::resolve_template(self.product_template.as_ref(), captures),
            version: Self::resolve_template(self.version_template.as_ref(), captures),
            info: Self::resolve_template(self.info_template.as_ref(), captures),
            hostname: Self::resolve_template(self.hostname_template.as_ref(), captures),
            os_type: Self::resolve_template(self.os_type_template.as_ref(), captures),
            device_type: Self::resolve_template(self.device_type_template.as_ref(), captures),
            cpe: Self::resolve_template(self.cpe_template.as_ref(), captures),
            confidence,
        }
    }

    /// Resolve a template variable using capture group values.
    fn resolve_template(
        template: Option<&MatchTemplate>,
        captures: &HashMap<usize, Vec<u8>>,
    ) -> Option<String> {
        let template = template?.value.clone();
        Some(Self::substitute_template_vars(&template, captures))
    }

    /// Substitute template variables with captured values.
    fn substitute_template_vars(template: &str, captures: &HashMap<usize, Vec<u8>>) -> String {
        let mut result = String::new();
        let mut chars = template.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '$' {
                if let Some(&next_ch) = chars.peek() {
                    if next_ch.is_ascii_digit() {
                        let _ = chars.next(); // consume the digit
                        let group_num = next_ch.to_digit(10).unwrap() as usize;
                        let value = captures.get(&group_num);
                        if let Some(bytes) = value {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                result.push_str(s);
                            }
                        }
                    } else if next_ch == '$' {
                        let _ = chars.next();
                        result.push('$');
                    } else {
                        result.push('$');
                    }
                } else {
                    result.push('$');
                }
            } else {
                result.push(ch);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_definition_creation() {
        let probe =
            ProbeDefinition::new_tcp("TestProbe".to_string(), b"GET / HTTP/1.0\r\n\r\n".to_vec());
        assert_eq!(probe.name, "TestProbe");
        assert_eq!(probe.protocol, Protocol::Tcp);
        assert_eq!(probe.rarity, 5);
    }

    #[test]
    fn test_probe_with_rarity() {
        let mut probe = ProbeDefinition::new_tcp("Test".to_string(), Vec::new());
        probe.with_rarity(9);
        assert_eq!(probe.rarity, 9);

        probe.with_rarity(15); // Over max, should clamp
        assert_eq!(probe.rarity, 9);

        probe.with_rarity(0); // Under min, should clamp
        assert_eq!(probe.rarity, 1);
    }

    #[test]
    fn test_matches_port() {
        let mut probe = ProbeDefinition::new_tcp("HTTP".to_string(), Vec::new());
        assert!(probe.matches_port(80)); // Empty ports matches all

        probe.with_ports(&[80, 443, 8080]);
        assert!(probe.matches_port(80));
        assert!(probe.matches_port(443));
        assert!(!probe.matches_port(22));
    }

    #[test]
    fn test_template_resolution() {
        let rule = MatchRule {
            pattern: r"SSH-([\d.]+)-(.*)".to_string(),
            service: "ssh".to_string(),
            product_template: Some(MatchTemplate {
                value: "OpenSSH/$1".to_string(),
            }),
            version_template: Some(MatchTemplate {
                value: "$2".to_string(),
            }),
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        };

        let mut captures = HashMap::new();
        captures.insert(1, b"8.4".to_vec());
        captures.insert(2, b"p1".to_vec());

        let result = rule.apply(&captures);
        assert_eq!(result.service, "ssh");
        assert_eq!(result.product, Some("OpenSSH/8.4".to_string()));
        assert_eq!(result.version, Some("p1".to_string()));
        assert_eq!(result.confidence, 8);
    }

    #[test]
    fn test_template_empty_capture() {
        let template = MatchTemplate {
            value: "Product/$1/$2".to_string(),
        };

        let rule = MatchRule {
            pattern: ".*".to_string(),
            service: "test".to_string(),
            product_template: Some(template.clone()),
            version_template: Some(template.clone()),
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        };

        let empty_captures = HashMap::new();
        let result = rule.apply(&empty_captures);

        assert_eq!(result.product, Some("Product//".to_string()));
        assert_eq!(result.version, Some("Product//".to_string()));
    }

    #[test]
    fn test_regex_compilation() {
        let rule = MatchRule {
            pattern: r"^SSH-[\d.]+-OpenSSH".to_string(),
            service: "ssh".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        };

        assert!(rule.compile_regex().is_ok());
    }

    #[test]
    fn test_invalid_regex() {
        let rule = MatchRule {
            pattern: r"[\d".to_string(),
            service: "test".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: false,
        };

        assert!(rule.compile_regex().is_err());
    }

    #[test]
    fn test_soft_match_confidence() {
        let rule = MatchRule {
            pattern: ".*".to_string(),
            service: "test".to_string(),
            product_template: None,
            version_template: None,
            info_template: None,
            hostname_template: None,
            os_type_template: None,
            device_type_template: None,
            cpe_template: None,
            soft: true,
        };

        let result = rule.apply(&HashMap::new());
        assert_eq!(result.confidence, 5);

        let mut rule2 = rule;
        rule2.soft = false;
        let result = rule2.apply(&HashMap::new());
        assert_eq!(result.confidence, 8);
    }
}
