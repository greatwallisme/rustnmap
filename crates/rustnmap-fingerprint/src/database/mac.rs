//! MAC address prefix database for vendor lookups.
//!
//! This module provides functionality to lookup vendor/manufacturer
//! information from MAC address OUI (Organizationally Unique Identifier)
//! prefixes.
//!
//! # Example
//!
//! ```
//! use rustnmap_fingerprint::database::MacPrefixDatabase;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = MacPrefixDatabase::parse(r#"
//! 000000    Private
//! 00000C    Cisco
//! 00000E    Fujitsu
//! "#)?;
//!
//! let vendor = db.lookup("00:00:0C:12:34:56");
//! assert_eq!(vendor, Some("Cisco"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::Path;

use tracing::info;

use crate::{FingerprintError, Result};

/// Database of MAC address prefixes to vendor mappings.
///
/// Stores OUI (Organizationally Unique Identifier) prefixes and their
/// corresponding vendor/manufacturer names. The OUI is the first 24 bits
/// (3 bytes) of a MAC address.
#[derive(Debug, Clone)]
pub struct MacPrefixDatabase {
    /// Maps OUI prefixes (6 hex digits) to vendor names.
    prefixes: HashMap<String, String>,
}

/// Result of a MAC vendor lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct MacVendorInfo {
    /// The vendor/manufacturer name.
    pub vendor: String,
    /// The OUI prefix that matched.
    pub oui: String,
    /// Whether this is a private/random MAC address.
    pub is_private: bool,
}

impl MacPrefixDatabase {
    /// Create an empty database with no entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// let db = MacPrefixDatabase::empty();
    /// assert!(db.lookup("00:00:00:00:00:00").is_none());
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            prefixes: HashMap::new(),
        }
    }

    /// Load database from nmap-mac-prefixes file.
    ///
    /// Parses the Nmap MAC prefixes file format which consists of
    /// lines with "OUI`<whitespace>`Vendor" format.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains
    /// invalid data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = MacPrefixDatabase::load_from_file("/usr/share/nmap/nmap-mac-prefixes").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
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

        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| FingerprintError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        Self::parse(&content)
    }

    /// Parse database content from string.
    ///
    /// Parses the Nmap MAC prefixes file format. Each line should
    /// contain a 6-character hex OUI followed by whitespace and
    /// the vendor name.
    ///
    /// # Errors
    ///
    /// Returns an error if the content contains invalid OUI format.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let content = r#"
    /// # This is a comment
    /// 000000    Private
    /// 00000C    Cisco
    /// 00000E    Fujitsu
    /// "#;
    ///
    /// let db = MacPrefixDatabase::parse(content)?;
    /// assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            // Line numbers are 1-indexed for error reporting
            let line_num = line_num + 1;

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: "OUI<whitespace>Vendor"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue; // Skip malformed lines
            }

            let oui = parts[0].to_uppercase();
            let vendor = parts[1..].join(" ");

            // Validate OUI format (should be 6 hex digits)
            if oui.len() != 6 || !oui.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(FingerprintError::ParseError {
                    line: line_num,
                    content: format!("Invalid OUI format: {oui}"),
                });
            }

            db.prefixes.insert(oui, vendor);
        }

        info!(
            "Loaded {} MAC prefix entries from database",
            db.prefixes.len()
        );
        Ok(db)
    }

    /// Lookup vendor for a MAC address.
    ///
    /// Extracts the OUI (first 3 bytes) from the MAC address and
    /// returns the corresponding vendor name if found.
    ///
    /// # Supported Formats
    ///
    /// - Colon-separated: "00:00:0C:12:34:56"
    /// - Hyphen-separated: "00-00-0C-12-34-56"
    /// - Dot-separated: "0000.0C12.3456"
    /// - No separator: "00000C123456"
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = MacPrefixDatabase::parse(r#"
    /// 00000C    Cisco
    /// 001B11    Intel
    /// "#)?;
    ///
    /// // Colon-separated
    /// assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));
    ///
    /// // Hyphen-separated
    /// assert_eq!(db.lookup("00-00-0C-12-34-56"), Some("Cisco"));
    ///
    /// // Dot-separated
    /// assert_eq!(db.lookup("0000.0C12.3456"), Some("Cisco"));
    ///
    /// // No separator
    /// assert_eq!(db.lookup("00000C123456"), Some("Cisco"));
    ///
    /// // Unknown MAC
    /// assert_eq!(db.lookup("FF:FF:FF:00:00:00"), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let oui = Self::extract_oui(mac)?;
        self.prefixes.get(&oui).map(String::as_str)
    }

    /// Lookup vendor with detailed information.
    ///
    /// Returns detailed information about the vendor lookup including
    /// whether this is a private/random MAC address.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = MacPrefixDatabase::parse(r#"
    /// 000000    Private
    /// 00000C    Cisco
    /// "#)?;
    ///
    /// let info = db.lookup_detail("00:00:0C:12:34:56");
    /// assert!(info.is_some());
    /// let info = info.unwrap();
    /// assert_eq!(info.vendor, "Cisco");
    /// assert_eq!(info.oui, "00000C");
    /// assert!(!info.is_private);
    ///
    /// let private = db.lookup_detail("00:00:00:12:34:56").unwrap();
    /// assert!(private.is_private);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup_detail(&self, mac: &str) -> Option<MacVendorInfo> {
        let oui = Self::extract_oui(mac)?;
        let vendor = self.prefixes.get(&oui)?;

        let is_private = vendor.to_lowercase().contains("private")
            || oui == "000000"
            || oui.starts_with('0') && oui.len() > 1 && matches!(oui.chars().nth(1), Some('2' | '6' | 'A' | 'E'));

        Some(MacVendorInfo {
            vendor: vendor.clone(),
            oui,
            is_private,
        })
    }

    /// Extract OUI from a MAC address string.
    ///
    /// Normalizes various MAC address formats and extracts the
    /// first 3 bytes (24 bits) as a 6-character hex string.
    fn extract_oui(mac: &str) -> Option<String> {
        let normalized = Self::normalize_mac(mac)?;

        // Take first 6 characters (3 bytes)
        if normalized.len() >= 6 {
            Some(normalized[..6].to_uppercase())
        } else {
            None
        }
    }

    /// Normalize MAC address to a continuous hex string.
    ///
    /// Removes all separators (colon, hyphen, dot) and returns
    /// uppercase hex digits.
    fn normalize_mac(mac: &str) -> Option<String> {
        // Remove all separators and whitespace
        let cleaned: String = mac.chars().filter(char::is_ascii_hexdigit).collect();

        // Validate length (should be 12 hex digits for a full MAC)
        if cleaned.len() != 12 {
            return None;
        }

        // Validate all characters are hex digits
        if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        Some(cleaned.to_uppercase())
    }

    /// Get number of entries in the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// let db = MacPrefixDatabase::empty();
    /// assert_eq!(db.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    /// Check if the database is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// let db = MacPrefixDatabase::empty();
    /// assert!(db.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    /// Check if a MAC address has a locally administered (random) bit set.
    ///
    /// The second least significant bit of the first byte indicates
    /// whether this is a locally administered MAC address.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// // Locally administered MAC (bit 1 set)
    /// assert!(MacPrefixDatabase::is_locally_administered("02:00:00:00:00:00"));
    ///
    /// // Universal MAC (bit 1 clear)
    /// assert!(!MacPrefixDatabase::is_locally_administered("00:00:00:00:00:00"));
    /// ```
    #[must_use]
    pub fn is_locally_administered(mac: &str) -> bool {
        let normalized = Self::normalize_mac(mac);
        if let Some(norm) = normalized {
            if let Ok(first_byte) = u8::from_str_radix(&norm[..2], 16) {
                // Check bit 1 (second LSB of first byte)
                return (first_byte & 0x02) != 0;
            }
        }
        false
    }

    /// Check if a MAC address is a multicast address.
    ///
    /// The least significant bit of the first byte indicates
    /// whether this is a multicast address.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::MacPrefixDatabase;
    ///
    /// // Multicast MAC (bit 0 set)
    /// assert!(MacPrefixDatabase::is_multicast("01:00:00:00:00:00"));
    ///
    /// // Unicast MAC (bit 0 clear)
    /// assert!(!MacPrefixDatabase::is_multicast("00:00:00:00:00:00"));
    /// ```
    #[must_use]
    pub fn is_multicast(mac: &str) -> bool {
        let normalized = Self::normalize_mac(mac);
        if let Some(norm) = normalized {
            if let Ok(first_byte) = u8::from_str_radix(&norm[..2], 16) {
                // Check bit 0 (LSB of first byte)
                return (first_byte & 0x01) != 0;
            }
        }
        false
    }
}

impl Default for MacPrefixDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_database() {
        let db = MacPrefixDatabase::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(db.lookup("00:00:00:00:00:00").is_none());
    }

    #[test]
    fn test_parse_simple() {
        let content = r"
# Comment line
000000    Private
00000C    Cisco
00000E    Fujitsu
001B11    Intel Corporate
";

        let db = MacPrefixDatabase::parse(content).unwrap();
        assert_eq!(db.len(), 4);
        assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));
        assert_eq!(db.lookup("00:1B:11:00:00:00"), Some("Intel Corporate"));
    }

    #[test]
    fn test_lookup_various_formats() {
        let db = MacPrefixDatabase::parse("00000C    Cisco\n").unwrap();

        // Colon-separated
        assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));

        // Hyphen-separated
        assert_eq!(db.lookup("00-00-0C-12-34-56"), Some("Cisco"));

        // Dot-separated
        assert_eq!(db.lookup("0000.0C12.3456"), Some("Cisco"));

        // No separator
        assert_eq!(db.lookup("00000C123456"), Some("Cisco"));

        // Unknown MAC
        assert_eq!(db.lookup("FF:FF:FF:00:00:00"), None);
    }

    #[test]
    fn test_lookup_detail() {
        let db = MacPrefixDatabase::parse("000000    Private\n00000C    Cisco\n").unwrap();

        let cisco = db.lookup_detail("00:00:0C:12:34:56").unwrap();
        assert_eq!(cisco.vendor, "Cisco");
        assert_eq!(cisco.oui, "00000C");
        assert!(!cisco.is_private);

        let private = db.lookup_detail("00:00:00:12:34:56").unwrap();
        assert_eq!(private.vendor, "Private");
        assert!(private.is_private);
    }

    #[test]
    fn test_is_locally_administered() {
        assert!(MacPrefixDatabase::is_locally_administered(
            "02:00:00:00:00:00"
        ));
        assert!(MacPrefixDatabase::is_locally_administered(
            "06:00:00:00:00:00"
        ));
        assert!(!MacPrefixDatabase::is_locally_administered(
            "00:00:00:00:00:00"
        ));
        assert!(!MacPrefixDatabase::is_locally_administered(
            "04:00:00:00:00:00"
        ));
    }

    #[test]
    fn test_is_multicast() {
        assert!(MacPrefixDatabase::is_multicast("01:00:00:00:00:00"));
        assert!(MacPrefixDatabase::is_multicast("03:00:00:00:00:00"));
        assert!(!MacPrefixDatabase::is_multicast("00:00:00:00:00:00"));
        assert!(!MacPrefixDatabase::is_multicast("02:00:00:00:00:00"));
    }

    #[test]
    fn test_parse_invalid_oui() {
        let content = "XYZABC    Invalid\n";
        assert!(MacPrefixDatabase::parse(content).is_err());
    }

    #[test]
    fn test_normalize_mac_invalid() {
        // Too short
        assert!(MacPrefixDatabase::normalize_mac("00:00:00").is_none());

        // Too long
        assert!(MacPrefixDatabase::normalize_mac("00:00:00:00:00:00:00:00").is_none());

        // Invalid characters
        assert!(MacPrefixDatabase::normalize_mac("00:00:GG:00:00:00").is_none());
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let db = MacPrefixDatabase::parse("00000C    Cisco\n").unwrap();

        // Uppercase
        assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));

        // Lowercase
        assert_eq!(db.lookup("00:00:0c:12:34:56"), Some("Cisco"));

        // Mixed case
        assert_eq!(db.lookup("00:00:0C:12:34:56"), Some("Cisco"));
    }
}
