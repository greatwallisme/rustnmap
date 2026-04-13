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

//! Protocol database for protocol number-to-name lookups.
//!
//! This module provides functionality to lookup protocol names from
//! protocol numbers using the nmap-protocols database.
//!
//! # Example
//!
//! ```
//! use rustnmap_fingerprint::database::ProtocolDatabase;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = ProtocolDatabase::parse(r#"
//! icmp 1 # Internet Control Message
//! tcp 6 # Transmission Control
//! udp 17 # User Datagram
//! "#)?;
//!
//! let protocol = db.lookup(6);
//! assert_eq!(protocol, Some("tcp"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::Path;

use tracing::info;

use crate::{FingerprintError, Result};

/// A single protocol entry in the database.
#[derive(Debug, Clone)]
pub struct ProtocolEntry {
    /// Protocol name (e.g., "tcp", "udp", "icmp")
    pub name: String,
    /// Protocol number
    pub number: u8,
    /// Optional comment/description
    pub comment: Option<String>,
}

/// Database of protocol names mapped to protocol numbers.
///
/// Stores the nmap-protocols data for efficient number-to-name lookups.
#[derive(Debug, Clone)]
pub struct ProtocolDatabase {
    /// Maps protocol number to protocol entry
    protocols: HashMap<u8, ProtocolEntry>,
}

impl ProtocolDatabase {
    /// Create an empty database with no entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// let db = ProtocolDatabase::empty();
    /// assert_eq!(db.lookup(6), None);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            protocols: HashMap::new(),
        }
    }

    /// Load database from nmap-protocols file.
    ///
    /// Parses the Nmap protocols file format which consists of:
    /// name number [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains
    /// invalid data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ProtocolDatabase::load_from_file("/usr/share/nmap/nmap-protocols").await?;
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
    /// Parses the Nmap protocols file format. Each line should
    /// contain: name number [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the content contains invalid format.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let content = r#"
    /// # This is a comment
    /// tcp 6 # Transmission Control
    /// udp 17 # User Datagram
    /// icmp 1 # Internet Control Message
    /// "#;
    ///
    /// let db = ProtocolDatabase::parse(content)?;
    /// assert_eq!(db.lookup(6), Some("tcp"));
    /// assert_eq!(db.lookup(17), Some("udp"));
    /// assert_eq!(db.lookup(1), Some("icmp"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();

        for (line_num, line) in content.lines().enumerate() {
            // Line numbers are 1-indexed for error reporting
            let line_num = line_num + 1;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: name number [# comment]
            // First, split off any comment
            let line_without_comment = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            let parts: Vec<&str> = line_without_comment.split_whitespace().collect();
            if parts.len() < 2 {
                continue; // Skip malformed lines
            }

            let name = parts[0].to_string();

            // Parse protocol number
            let number: u8 = parts[1].parse().map_err(|_| FingerprintError::ParseError {
                line: line_num,
                content: format!("Invalid protocol number: {}", parts[1]),
            })?;

            // Parse optional comment (from original line)
            let comment = line.find('#').and_then(|pos| {
                let comment_str = line[pos + 1..].trim();
                if comment_str.is_empty() {
                    None
                } else {
                    Some(comment_str.to_string())
                }
            });

            let entry = ProtocolEntry {
                name,
                number,
                comment,
            };

            db.protocols.insert(number, entry);
        }

        info!(
            "Loaded {} protocol entries from database",
            db.protocols.len()
        );
        Ok(db)
    }

    /// Lookup protocol name for a protocol number.
    ///
    /// # Arguments
    ///
    /// * `number` - The protocol number (0-255)
    ///
    /// # Returns
    ///
    /// `Some(protocol_name)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ProtocolDatabase::parse("tcp 6\nudp 17\nicmp 1\n")?;
    ///
    /// assert_eq!(db.lookup(6), Some("tcp"));
    /// assert_eq!(db.lookup(17), Some("udp"));
    /// assert_eq!(db.lookup(1), Some("icmp"));
    /// assert_eq!(db.lookup(99), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup(&self, number: u8) -> Option<&str> {
        self.protocols.get(&number).map(|entry| entry.name.as_str())
    }

    /// Lookup protocol entry with full details.
    ///
    /// # Arguments
    ///
    /// * `number` - The protocol number (0-255)
    ///
    /// # Returns
    ///
    /// `Some(&ProtocolEntry)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ProtocolDatabase::parse("tcp 6 # Transmission Control\n")?;
    ///
    /// let entry = db.lookup_entry(6);
    /// assert!(entry.is_some());
    /// let entry = entry.unwrap();
    /// assert_eq!(entry.name, "tcp");
    /// assert_eq!(entry.number, 6);
    /// assert_eq!(entry.comment, Some("Transmission Control".to_string()));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup_entry(&self, number: u8) -> Option<&ProtocolEntry> {
        self.protocols.get(&number)
    }

    /// Get number of entries in the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// let db = ProtocolDatabase::empty();
    /// assert_eq!(db.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Check if the database is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ProtocolDatabase;
    ///
    /// let db = ProtocolDatabase::empty();
    /// assert!(db.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }
}

impl Default for ProtocolDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_database() {
        let db = ProtocolDatabase::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(db.lookup(6).is_none());
    }

    #[test]
    fn test_parse_simple() {
        let content = r"
# Comment line
tcp 6 # Transmission Control
udp 17 # User Datagram
icmp 1 # Internet Control Message
";

        let db = ProtocolDatabase::parse(content).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.lookup(6), Some("tcp"));
        assert_eq!(db.lookup(17), Some("udp"));
        assert_eq!(db.lookup(1), Some("icmp"));
    }

    #[test]
    fn test_parse_with_comment() {
        let content = "tcp 6 # Transmission Control Protocol\n";
        let db = ProtocolDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(6).unwrap();
        assert_eq!(entry.name, "tcp");
        assert_eq!(entry.number, 6);
        assert_eq!(
            entry.comment,
            Some("Transmission Control Protocol".to_string())
        );
    }

    #[test]
    fn test_parse_without_comment() {
        let content = "unknown 253\n";
        let db = ProtocolDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(253).unwrap();
        assert_eq!(entry.name, "unknown");
        assert!(entry.comment.is_none());
    }

    #[test]
    fn test_parse_invalid_number() {
        let content = "invalid abc\n";
        assert!(ProtocolDatabase::parse(content).is_err());
    }

    #[test]
    fn test_parse_number_out_of_range() {
        let content = "invalid 256\n";
        assert!(ProtocolDatabase::parse(content).is_err());
    }

    #[test]
    fn test_parse_malformed_line() {
        let content = "justname\n";
        // Should skip malformed lines
        let db = ProtocolDatabase::parse(content);
        assert!(db.is_ok());
        assert_eq!(db.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_all_protocols() {
        // Test parsing a larger set of protocols
        let content = r"
hopopt 0 # IPv6 Hop-by-Hop Option
icmp 1 # Internet Control Message
igmp 2 # Internet Group Management
ggp 3 # Gateway-to-Gateway
ipv4 4 # IP in IP
st 5 # Stream
tcp 6 # Transmission Control
cbt 7 # CBT
egp 8 # Exterior Gateway Protocol
igp 9 # any private interior gateway
udp 17 # User Datagram
";

        let db = ProtocolDatabase::parse(content).unwrap();
        assert_eq!(db.len(), 11);
        assert_eq!(db.lookup(0), Some("hopopt"));
        assert_eq!(db.lookup(1), Some("icmp"));
        assert_eq!(db.lookup(6), Some("tcp"));
        assert_eq!(db.lookup(17), Some("udp"));
    }
}
