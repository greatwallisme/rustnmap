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

//! RPC database for RPC program number-to-name lookups.
//!
//! This module provides functionality to lookup RPC service names from
//! RPC program numbers using the nmap-rpc database.
//!
//! # Example
//!
//! ```
//! use rustnmap_fingerprint::database::RpcDatabase;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let db = RpcDatabase::parse(r#"
//! rpcbind 100000 portmap sunrpc rpcbind pmapprog # portmapper
//! nfs 100003 nfsprog nfsd # nfs
//! "#)?;
//!
//! let rpc = db.lookup(100003);
//! assert_eq!(rpc, Some("nfs"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::Path;

use tracing::info;

use crate::{FingerprintError, Result};

/// A single RPC entry in the database.
#[derive(Debug, Clone)]
pub struct RpcEntry {
    /// Primary RPC name (e.g., "nfs", "rpcbind")
    pub name: String,
    /// RPC program number
    pub number: u32,
    /// Aliases for this RPC service
    pub aliases: Vec<String>,
    /// Optional comment/description
    pub comment: Option<String>,
}

/// Database of RPC names mapped to RPC program numbers.
///
/// Stores the nmap-rpc data for efficient RPC number-to-name lookups.
#[derive(Debug, Clone)]
pub struct RpcDatabase {
    /// Maps RPC number to RPC entry
    rpc_services: HashMap<u32, RpcEntry>,
}

impl RpcDatabase {
    /// Create an empty database with no entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// let db = RpcDatabase::empty();
    /// assert_eq!(db.lookup(100003), None);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rpc_services: HashMap::new(),
        }
    }

    /// Load database from nmap-rpc file.
    ///
    /// Parses the Nmap RPC file format which consists of:
    /// name number [aliases...] [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains
    /// invalid data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = RpcDatabase::load_from_file("/usr/share/nmap/nmap-rpc").await?;
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
    /// Parses the Nmap RPC file format. Each line should
    /// contain: name number [aliases...] [# comment]
    ///
    /// # Errors
    ///
    /// Returns an error if the content contains invalid format.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let content = r#"
    /// # This is a comment
    /// rpcbind 100000 portmap sunrpc rpcbind pmapprog # portmapper
    /// nfs 100003 nfsprog nfsd # nfs
    /// "#;
    ///
    /// let db = RpcDatabase::parse(content)?;
    /// assert_eq!(db.lookup(100000), Some("rpcbind"));
    /// assert_eq!(db.lookup(100003), Some("nfs"));
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

            // Parse line: name number [aliases...] [# comment]
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

            // Parse RPC number
            let number: u32 = parts[1].parse().map_err(|_| FingerprintError::ParseError {
                line: line_num,
                content: format!("Invalid RPC number: {}", parts[1]),
            })?;

            // Collect aliases (everything between name and comment)
            let aliases: Vec<String> = parts[2..].iter().map(|s| s.to_string()).collect();

            // Parse optional comment (from original line)
            let comment = line.find('#').and_then(|pos| {
                let comment_str = line[pos + 1..].trim();
                if comment_str.is_empty() {
                    None
                } else {
                    Some(comment_str.to_string())
                }
            });

            let entry = RpcEntry {
                name,
                number,
                aliases,
                comment,
            };

            db.rpc_services.insert(number, entry);
        }

        info!("Loaded {} RPC entries from database", db.rpc_services.len());
        Ok(db)
    }

    /// Lookup RPC name for an RPC program number.
    ///
    /// # Arguments
    ///
    /// * `number` - The RPC program number
    ///
    /// # Returns
    ///
    /// `Some(rpc_name)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = RpcDatabase::parse("rpcbind 100000\nnfs 100003\n")?;
    ///
    /// assert_eq!(db.lookup(100000), Some("rpcbind"));
    /// assert_eq!(db.lookup(100003), Some("nfs"));
    /// assert_eq!(db.lookup(999999), None);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup(&self, number: u32) -> Option<&str> {
        self.rpc_services
            .get(&number)
            .map(|entry| entry.name.as_str())
    }

    /// Lookup RPC entry with full details.
    ///
    /// # Arguments
    ///
    /// * `number` - The RPC program number
    ///
    /// # Returns
    ///
    /// `Some(&RpcEntry)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = RpcDatabase::parse("nfs 100003 nfsprog nfsd # Network File System\n")?;
    ///
    /// let entry = db.lookup_entry(100003);
    /// assert!(entry.is_some());
    /// let entry = entry.unwrap();
    /// assert_eq!(entry.name, "nfs");
    /// assert_eq!(entry.number, 100003);
    /// assert!(entry.aliases.contains(&"nfsprog".to_string()));
    /// assert_eq!(entry.comment, Some("Network File System".to_string()));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup_entry(&self, number: u32) -> Option<&RpcEntry> {
        self.rpc_services.get(&number)
    }

    /// Lookup RPC name by alias.
    ///
    /// # Arguments
    ///
    /// * `alias` - The RPC alias name
    ///
    /// # Returns
    ///
    /// `Some(rpc_name)` if found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let db = RpcDatabase::parse("rpcbind 100000 portmap sunrpc\n")?;
    ///
    /// assert_eq!(db.lookup_by_alias("portmap"), Some("rpcbind"));
    /// assert_eq!(db.lookup_by_alias("sunrpc"), Some("rpcbind"));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn lookup_by_alias(&self, alias: &str) -> Option<&str> {
        let alias_lower = alias.to_ascii_lowercase();
        for entry in self.rpc_services.values() {
            if entry
                .aliases
                .iter()
                .any(|a| a.to_ascii_lowercase() == alias_lower)
            {
                return Some(&entry.name);
            }
        }
        None
    }

    /// Get number of entries in the database.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// let db = RpcDatabase::empty();
    /// assert_eq!(db.len(), 0);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.rpc_services.len()
    }

    /// Check if the database is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use rustnmap_fingerprint::database::RpcDatabase;
    ///
    /// let db = RpcDatabase::empty();
    /// assert!(db.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rpc_services.is_empty()
    }
}

impl Default for RpcDatabase {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_database() {
        let db = RpcDatabase::empty();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        assert!(db.lookup(100000).is_none());
    }

    #[test]
    fn test_parse_simple() {
        let content = r"
# Comment line
rpcbind 100000 portmap sunrpc # portmapper
nfs 100003 nfsprog nfsd # nfs
mountd 100005 mount showmount # mount daemon
";

        let db = RpcDatabase::parse(content).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.lookup(100000), Some("rpcbind"));
        assert_eq!(db.lookup(100003), Some("nfs"));
        assert_eq!(db.lookup(100005), Some("mountd"));
    }

    #[test]
    fn test_parse_with_comment() {
        let content = "nfs 100003 nfsprog nfsd # Network File System\n";
        let db = RpcDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(100003).unwrap();
        assert_eq!(entry.name, "nfs");
        assert_eq!(entry.number, 100003);
        assert!(entry.aliases.contains(&"nfsprog".to_string()));
        assert!(entry.aliases.contains(&"nfsd".to_string()));
        assert_eq!(entry.comment, Some("Network File System".to_string()));
    }

    #[test]
    fn test_parse_without_comment() {
        let content = "unknown 999999\n";
        let db = RpcDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(999999).unwrap();
        assert_eq!(entry.name, "unknown");
        assert!(entry.aliases.is_empty());
        assert!(entry.comment.is_none());
    }

    #[test]
    fn test_lookup_by_alias() {
        let content = "rpcbind 100000 portmap sunrpc pmapprog # portmapper\n";
        let db = RpcDatabase::parse(content).unwrap();

        assert_eq!(db.lookup_by_alias("portmap"), Some("rpcbind"));
        assert_eq!(db.lookup_by_alias("sunrpc"), Some("rpcbind"));
        assert_eq!(db.lookup_by_alias("pmapprog"), Some("rpcbind"));
        assert_eq!(db.lookup_by_alias("unknown"), None);
    }

    #[test]
    fn test_parse_invalid_number() {
        let content = "invalid abc\n";
        assert!(RpcDatabase::parse(content).is_err());
    }

    #[test]
    fn test_parse_malformed_line() {
        let content = "justname\n";
        // Should skip malformed lines
        let db = RpcDatabase::parse(content);
        assert!(db.is_ok());
        assert_eq!(db.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_many_aliases() {
        let content = "rpcbind 100000 portmap sunrpc rpcbind pmapprog # portmapper\n";
        let db = RpcDatabase::parse(content).unwrap();

        let entry = db.lookup_entry(100000).unwrap();
        assert_eq!(entry.name, "rpcbind");
        assert_eq!(entry.aliases.len(), 4);
        assert!(entry.aliases.contains(&"portmap".to_string()));
        assert!(entry.aliases.contains(&"sunrpc".to_string()));
        assert!(entry.aliases.contains(&"rpcbind".to_string()));
        assert!(entry.aliases.contains(&"pmapprog".to_string()));
    }
}
