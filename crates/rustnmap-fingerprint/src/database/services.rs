//! Service database for port-to-service name lookups.
//!
//! This module provides functionality to lookup service names from
//! port numbers and protocols using the nmap-services database.
//!
//! # Example
//!
//! ```
//! use rustnmap_fingerprint::database::ServiceDatabase;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = ServiceDatabase::parse(r#"
//! ssh 22/tcp 0.182286 # Secure Shell Login
//! http 80/tcp 0.250000 # World Wide Web HTTP
//! "#)?;
//!
//! let service = db.lookup(22, "tcp");
//! assert_eq!(service, Some("ssh"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::Path;

use tracing::info;

use crate::{FingerprintError, Result};

/// Protocol type for service entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceProtocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// SCTP protocol
    Sctp,
    /// Unknown protocol
    Unknown,
}

impl ServiceProtocol {
    /// Parse protocol from string.
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "sctp" => Self::Sctp,
            _ => Self::Unknown,
        }
    }

    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Unknown => "unknown",
        }
    }
}

/// A single service entry in the database.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Service name (e.g., "ssh", "http")
    pub name: String,
    /// Port number
    pub port: u16,
    /// Protocol
    pub protocol: ServiceProtocol,
    /// Open frequency (0.0 to 1.0) - how often this port is open
    pub frequency: f64,
    /// Optional comment/description
    pub comment: Option<String>,
}

/// Database of service names mapped to port/protocol combinations.
///
/// Stores the nmap-services data for efficient port-to-service lookups.
#[derive(Debug, Clone)]
pub struct ServiceDatabase {
    /// Maps (port, protocol) to service entries
    /// Key: (port, protocol_str)
    services: HashMap<(u16, String), ServiceEntry>,
}

impl ServiceDatabase {
    /// Create an empty database with no entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// let db = ServiceDatabase::empty();
    /// assert_eq!(db.lookup(80, "tcp"), None);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    /// Load database from nmap-services file.
    ///
    /// Parses the Nmap services file format which consists of:
    /// service_name port/protocol frequency [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains
    /// invalid data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ServiceDatabase::load_from_file("/usr/share/nmap/nmap-services").await?;
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
    /// Parses the Nmap services file format. Each line should
    /// contain: service_name port/protocol frequency [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the content contains invalid format.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let content = r#"
    /// # This is a comment
    /// ssh 22/tcp 0.182286 # Secure Shell Login
    /// http 80/tcp 0.250000 # World Wide Web HTTP
    /// "#;
    ///
    /// let db = ServiceDatabase::parse(content)?;
    /// assert_eq!(db.lookup(22, "tcp"), Some("ssh"));
    /// assert_eq!(db.lookup(80, "tcp"), Some("http"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse(content: &str) -> Result<Self> {
        let mut db = Self::empty();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: service_name port/protocol frequency [# comment]
            // First, split off any comment
            let line_without_comment = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            let parts: Vec<&str> = line_without_comment.split_whitespace().collect();
            if parts.len() < 3 {
                continue; // Skip malformed lines
            }

            let service_name = parts[0].to_string();

            // Parse port/protocol
            let port_protocol = parts[1];
            let Some((port_str, protocol_str)) = port_protocol.split_once('/') else {
                continue; // Skip malformed lines (missing /)
            };

            let port: u16 = match port_str.parse() {
                Ok(p) => p,
                Err(_) => continue, // Skip lines with invalid port number
            };

            let protocol = ServiceProtocol::from_str(protocol_str);

            // Parse frequency
            let frequency: f64 = parts[2].parse().unwrap_or(0.0);

            // Parse optional comment (from original line)
            let comment = line.find('#').and_then(|pos| {
                let comment_str = line[pos + 1..].trim();
                if comment_str.is_empty() {
                    None
                } else {
                    Some(comment_str.to_string())
                }
            });

            let entry = ServiceEntry {
                name: service_name.clone(),
                port,
                protocol,
                frequency,
                comment,
            };

            db.services
                .insert((port, protocol_str.to_ascii_lowercase()), entry);
        }

        info!("Loaded {} service entries from database", db.services.len());
        Ok(db)
    }

    /// Lookup service name for a port and protocol.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number
    /// * `protocol` - The protocol ("tcp", "udp", "sctp")
    ///
    /// # Returns
    ///
    /// `Some(service_name)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ServiceDatabase::parse("ssh 22/tcp 0.18\nhttp 80/tcp 0.25\n")?;
    ///
    /// assert_eq!(db.lookup(22, "tcp"), Some("ssh"));
    /// assert_eq!(db.lookup(80, "tcp"), Some("http"));
    /// assert_eq!(db.lookup(443, "tcp"), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup(&self, port: u16, protocol: &str) -> Option<&str> {
        self.services
            .get(&(port, protocol.to_ascii_lowercase()))
            .map(|entry| entry.name.as_str())
    }

    /// Lookup service entry with full details.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number
    /// * `protocol` - The protocol ("tcp", "udp", "sctp")
    ///
    /// # Returns
    ///
    /// `Some(&ServiceEntry)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = ServiceDatabase::parse("ssh 22/tcp 0.18 # Secure Shell\n")?;
    ///
    /// let entry = db.lookup_entry(22, "tcp");
    /// assert!(entry.is_some());
    /// let entry = entry.unwrap();
    /// assert_eq!(entry.name, "ssh");
    /// assert_eq!(entry.port, 22);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup_entry(&self, port: u16, protocol: &str) -> Option<&ServiceEntry> {
        self.services.get(&(port, protocol.to_ascii_lowercase()))
    }

    /// Get number of entries in the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// let db = ServiceDatabase::empty();
    /// assert_eq!(db.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Check if the database is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::ServiceDatabase;
    ///
    /// let db = ServiceDatabase::empty();
    /// assert!(db.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }
}

impl Default for ServiceDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_database() {
        let db = ServiceDatabase::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(db.lookup(80, "tcp").is_none());
    }

    #[test]
    fn test_parse_simple() {
        let content = r"
# Comment line
ssh 22/tcp 0.182286 # Secure Shell Login
http 80/tcp 0.250000 # World Wide Web HTTP
https 443/tcp 0.200000 # HTTP Secure
";

        let db = ServiceDatabase::parse(content).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.lookup(22, "tcp"), Some("ssh"));
        assert_eq!(db.lookup(80, "tcp"), Some("http"));
        assert_eq!(db.lookup(443, "tcp"), Some("https"));
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let db = ServiceDatabase::parse("ssh 22/tcp 0.18\n").unwrap();

        assert_eq!(db.lookup(22, "tcp"), Some("ssh"));
        assert_eq!(db.lookup(22, "TCP"), Some("ssh"));
        assert_eq!(db.lookup(22, "Tcp"), Some("ssh"));
    }

    #[test]
    fn test_parse_with_comment() {
        let content = "ssh 22/tcp 0.18 # Secure Shell Login\n";
        let db = ServiceDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(22, "tcp").unwrap();
        assert_eq!(entry.name, "ssh");
        assert_eq!(entry.port, 22);
        assert_eq!(entry.frequency, 0.18);
        assert_eq!(entry.comment, Some("Secure Shell Login".to_string()));
    }

    #[test]
    fn test_parse_without_comment() {
        let content = "unknown 12/tcp 0.000063\n";
        let db = ServiceDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(12, "tcp").unwrap();
        assert_eq!(entry.name, "unknown");
        assert!(entry.comment.is_none());
    }

    #[test]
    fn test_parse_multiple_protocols() {
        let content = r"
echo 7/tcp 0.004855
echo 7/udp 0.024679
echo 7/sctp 0.000000
";

        let db = ServiceDatabase::parse(content).unwrap();
        assert_eq!(db.lookup(7, "tcp"), Some("echo"));
        assert_eq!(db.lookup(7, "udp"), Some("echo"));
        assert_eq!(db.lookup(7, "sctp"), Some("echo"));
    }

    #[test]
    fn test_parse_invalid_port() {
        let content = "invalid abc/tcp 0.5\n";
        // Should skip malformed lines (invalid port number), not error
        let db = ServiceDatabase::parse(content);
        assert!(db.is_ok());
        assert_eq!(db.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_invalid_port_protocol_format() {
        let content = "invalid 22 0.5\n";
        // Should skip malformed lines, not error
        let db = ServiceDatabase::parse(content);
        assert!(db.is_ok());
        assert_eq!(db.unwrap().len(), 0);
    }
}
