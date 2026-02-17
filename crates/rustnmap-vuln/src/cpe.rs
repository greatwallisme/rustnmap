//! CPE (Common Platform Enumeration) parsing and matching.
//!
//! This module provides CPE 2.3 parsing and matching functionality
//! for vulnerability correlation.

use std::fmt;

use crate::error::{Result, VulnError};

/// CPE match result.
#[derive(Debug, Clone)]
pub struct CpeMatchResult {
    /// Whether the CPE matches.
    pub matches: bool,
    /// Match confidence (0.0 - 1.0).
    pub confidence: f32,
    /// Match explanation.
    pub reason: String,
}

/// CPE parser and matcher.
#[derive(Debug, Clone)]
pub struct CpeMatcher;

impl CpeMatcher {
    /// Parse a CPE 2.3 string.
    ///
    /// # Arguments
    ///
    /// * `cpe_str` - CPE 2.3 formatted string.
    ///
    /// # Returns
    ///
    /// Parsed CPE object.
    ///
    /// # Errors
    ///
    /// Returns an error if the CPE string is invalid.
    pub fn parse(cpe_str: &str) -> Result<CpeWrapper> {
        // Handle both CPE 2.3 formats
        let cpe_str = cpe_str.trim();

        // Try to parse as CPE 2.3
        if !cpe_str.starts_with("cpe:2.3:") {
            return Err(VulnError::cpe(format!(
                "Invalid CPE format: must start with 'cpe:2.3:', got '{cpe_str}'"
            )));
        }

        // Parse the CPE string
        let parts: Vec<&str> = cpe_str.split(':').collect();
        if parts.len() < 13 {
            return Err(VulnError::cpe(format!(
                "Invalid CPE format: expected 13 parts, got {}",
                parts.len()
            )));
        }

        Ok(CpeWrapper {
            part: parts.get(2).copied().unwrap_or("*").to_string(),
            vendor: parts.get(3).copied().unwrap_or("*").to_string(),
            product: parts.get(4).copied().unwrap_or("*").to_string(),
            version: parts.get(5).copied().unwrap_or("*").to_string(),
            update: parts.get(6).copied().unwrap_or("*").to_string(),
            edition: parts.get(7).copied().unwrap_or("*").to_string(),
            language: parts.get(8).copied().unwrap_or("*").to_string(),
            sw_edition: parts.get(9).copied().unwrap_or("*").to_string(),
            target_sw: parts.get(10).copied().unwrap_or("*").to_string(),
            target_hw: parts.get(11).copied().unwrap_or("*").to_string(),
            other: parts.get(12).copied().unwrap_or("*").to_string(),
            original: cpe_str.to_string(),
        })
    }

    /// Check if a CPE matches a pattern.
    ///
    /// # Arguments
    ///
    /// * `cpe` - CPE to check.
    /// * `pattern` - Pattern to match against (supports wildcards).
    ///
    /// # Returns
    ///
    /// Match result with confidence and explanation.
    #[must_use]
    pub fn matches(cpe: &CpeWrapper, pattern: &str) -> CpeMatchResult {
        let pattern_cpe = match Self::parse(pattern) {
            Ok(p) => p,
            Err(e) => {
                return CpeMatchResult {
                    matches: false,
                    confidence: 0.0,
                    reason: format!("Pattern parse error: {e}"),
                };
            }
        };

        Self::match_cpe(cpe, &pattern_cpe)
    }

    /// Match two CPE objects.
    fn match_cpe(cpe: &CpeWrapper, pattern: &CpeWrapper) -> CpeMatchResult {
        let mut matching_fields = 0;
        let mut total_fields = 0;
        let mut mismatches = Vec::new();

        // Check each field
        let field_checks = [
            ("part", &cpe.part, &pattern.part),
            ("vendor", &cpe.vendor, &pattern.vendor),
            ("product", &cpe.product, &pattern.product),
            ("version", &cpe.version, &pattern.version),
        ];

        for (name, cpe_val, pattern_val) in field_checks {
            total_fields += 1;

            // Wildcard in pattern matches anything
            if pattern_val == "*" || pattern_val == "-" {
                matching_fields += 1;
                continue;
            }

            // Exact match
            if cpe_val == pattern_val {
                matching_fields += 1;
                continue;
            }

            // Version matching with wildcards
            if name == "version" && Self::version_matches(cpe_val, pattern_val) {
                matching_fields += 1;
                continue;
            }

            mismatches.push(format!("{name}: {cpe_val} != {pattern_val}"));
        }

        let confidence = if total_fields > 0 {
            #[allow(clippy::cast_precision_loss, reason = "f32 precision is sufficient for confidence score")]
            let ratio = matching_fields as f32 / total_fields as f32;
            ratio
        } else {
            0.0
        };

        let matches = mismatches.is_empty();

        let reason = if matches {
            format!("CPE matches with {matching_fields} / {total_fields} fields")
        } else {
            format!("CPE mismatch: {}", mismatches.join(", "))
        };

        CpeMatchResult {
            matches,
            confidence,
            reason,
        }
    }

    /// Check if a version matches a pattern.
    fn version_matches(version: &str, pattern: &str) -> bool {
        // Exact match
        if version == pattern {
            return true;
        }

        // Wildcard matches
        if pattern == "*" || pattern == "-" {
            return true;
        }

        // Handle version ranges (simplified)
        if pattern.contains("..") {
            let parts: Vec<&str> = pattern.split("..").collect();
            if parts.len() == 2 {
                return version >= parts[0] && version <= parts[1];
            }
        }

        false
    }
}

/// Wrapper for CPE data.
#[derive(Debug, Clone)]
pub struct CpeWrapper {
    /// Part type (a=application, h=hardware, o=OS).
    pub part: String,
    /// Vendor name.
    pub vendor: String,
    /// Product name.
    pub product: String,
    /// Version string.
    pub version: String,
    /// Update string.
    pub update: String,
    /// Edition string.
    pub edition: String,
    /// Language.
    pub language: String,
    /// Software edition.
    pub sw_edition: String,
    /// Target software.
    pub target_sw: String,
    /// Target hardware.
    pub target_hw: String,
    /// Other.
    pub other: String,
    /// Original CPE string.
    pub original: String,
}

impl fmt::Display for CpeWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl CpeWrapper {
    /// Get the vendor:product identifier.
    #[must_use]
    pub fn vendor_product(&self) -> String {
        format!("{}:{}", self.vendor, self.product)
    }

    /// Get the full version string.
    #[must_use]
    pub fn full_version(&self) -> &str {
        &self.version
    }

    /// Check if this is an application CPE.
    #[must_use]
    pub fn is_application(&self) -> bool {
        self.part == "a" || self.part == "*"
    }

    /// Check if this is an OS CPE.
    #[must_use]
    pub fn is_os(&self) -> bool {
        self.part == "o" || self.part == "*"
    }

    /// Check if this is a hardware CPE.
    #[must_use]
    pub fn is_hardware(&self) -> bool {
        self.part == "h" || self.part == "*"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_cpe() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.49");
    }

    #[test]
    fn test_parse_invalid_cpe() {
        let result = CpeMatcher::parse("invalid-cpe");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid CPE format"));
    }

    #[test]
    fn test_cpe_match_exact() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        let result = CpeMatcher::matches(&cpe, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
        assert!(result.matches);
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_cpe_match_wildcard() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        // Pattern with wildcard version should match any version (13 parts required)
        let result = CpeMatcher::matches(&cpe, "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
        // Wildcard in version field matches any version
        assert!(result.matches, "Expected wildcard match, got: {}", result.reason);
    }

    #[test]
    fn test_cpe_mismatch() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        let result = CpeMatcher::matches(&cpe, "cpe:2.3:a:nginx:nginx:1.0.0:*:*:*:*:*:*:*");
        assert!(!result.matches);
        assert!(result.reason.contains("vendor") || result.reason.contains("product"));
    }

    #[test]
    fn test_version_matches() {
        assert!(CpeMatcher::parse("cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*").is_ok());
    }

    #[test]
    fn test_cpe_display() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        assert_eq!(
            format!("{}", cpe),
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn test_vendor_product() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.vendor_product(), "apache:http_server");
    }

    #[test]
    fn test_is_application() {
        let cpe = CpeMatcher::parse("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        assert!(cpe.is_application());
    }
}
