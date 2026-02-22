//! Port-to-service name mapping from the `nmap-services` database.
//!
//! Provides O(1) lookup of service names by port/protocol and
//! frequency-sorted port lists for `--top-ports` functionality.
//!
//! Loading priority:
//! 1. Runtime file from `~/.rustnmap/db/nmap-services` (user-replaceable)
//! 2. Embedded fallback compiled from `reference/nmap/nmap-services`

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

/// Embedded `nmap-services` database content (compile-time fallback).
const EMBEDDED_NMAP_SERVICES: &str = include_str!("../../../reference/nmap/nmap-services");

/// Default data directory under the user's home.
const DEFAULT_DATA_DIR: &str = ".rustnmap";

/// Subdirectory for Nmap database files.
const DB_SUBDIR: &str = "db";

/// Filename for the services database.
const SERVICES_FILENAME: &str = "nmap-services";

/// A single entry from the `nmap-services` database.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Service name (e.g., "http", "ssh").
    pub name: String,
    /// Port number.
    pub port: u16,
    /// Protocol type.
    pub protocol: ServiceProtocol,
    /// Open frequency (0.0 to 1.0). Higher means more commonly open.
    pub frequency: f64,
}

/// Protocol type for service entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceProtocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// SCTP protocol.
    Sctp,
}

/// Composite key for port+protocol lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PortKey {
    port: u16,
    protocol: ServiceProtocol,
}

/// Database of port-to-service mappings parsed from `nmap-services`.
///
/// Provides O(1) service name lookup and frequency-sorted port lists.
/// Loads from a runtime file if available, otherwise falls back to
/// the embedded database compiled into the binary.
#[derive(Debug)]
pub struct ServiceDatabase {
    /// Port+protocol -> service name mapping.
    lookup: HashMap<PortKey, String>,
    /// TCP ports sorted by frequency (descending).
    top_tcp_ports: Vec<u16>,
    /// UDP ports sorted by frequency (descending).
    top_udp_ports: Vec<u16>,
    /// Source of the loaded data (for diagnostics).
    source: DatabaseSource,
}

/// Indicates where the database was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseSource {
    /// Loaded from a file on disk.
    File(PathBuf),
    /// Using the embedded fallback data.
    Embedded,
}

/// Custom data directory override. Set before first `global()` call.
static CUSTOM_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Global singleton instance, lazily initialized on first access.
static GLOBAL_DB: LazyLock<ServiceDatabase> = LazyLock::new(|| {
    let custom_dir = CUSTOM_DATA_DIR.get();
    ServiceDatabase::load_with_fallback(custom_dir.map(PathBuf::as_path))
});

impl ServiceDatabase {
    /// Sets a custom data directory for loading `nmap-services`.
    ///
    /// Must be called before the first call to `global()`.
    /// The file is expected at `<data_dir>/db/nmap-services`.
    ///
    /// Returns `false` if the global database was already initialized.
    pub fn set_data_dir(path: impl Into<PathBuf>) -> bool {
        CUSTOM_DATA_DIR.set(path.into()).is_ok()
    }

    /// Returns the global singleton database instance.
    ///
    /// On first call, attempts to load from the runtime file path.
    /// Falls back to the embedded database if the file is not found.
    #[must_use]
    pub fn global() -> &'static Self {
        &GLOBAL_DB
    }

    /// Returns the default path for the `nmap-services` file.
    ///
    /// Resolves to `~/.rustnmap/db/nmap-services`.
    #[must_use]
    pub fn default_services_path() -> Option<PathBuf> {
        home_dir().map(|h| {
            h.join(DEFAULT_DATA_DIR)
                .join(DB_SUBDIR)
                .join(SERVICES_FILENAME)
        })
    }

    /// Returns the default database directory path.
    ///
    /// Resolves to `~/.rustnmap/db/`.
    #[must_use]
    pub fn default_db_dir() -> Option<PathBuf> {
        home_dir().map(|h| h.join(DEFAULT_DATA_DIR).join(DB_SUBDIR))
    }

    /// Loads from a runtime file, falling back to embedded data.
    fn load_with_fallback(custom_data_dir: Option<&Path>) -> Self {
        let file_path = custom_data_dir
            .map_or_else(Self::default_services_path, |dir| Some(dir.join(DB_SUBDIR).join(SERVICES_FILENAME)));

        // Try loading from runtime file
        if let Some(path) = &file_path {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    let mut db = Self::parse(&content);
                    db.source = DatabaseSource::File(path.clone());
                    return db;
                }
            }
        }

        // Fallback to embedded data
        let mut db = Self::parse(EMBEDDED_NMAP_SERVICES);
        db.source = DatabaseSource::Embedded;
        db
    }

    /// Loads from a specific file path (no fallback).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn load_from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut db = Self::parse(&content);
        db.source = DatabaseSource::File(path.to_path_buf());
        Ok(db)
    }

    /// Returns where this database was loaded from.
    #[must_use]
    pub const fn source(&self) -> &DatabaseSource {
        &self.source
    }

    /// Looks up the service name for a TCP port.
    #[must_use]
    pub fn lookup_tcp(&self, port: u16) -> Option<&str> {
        self.lookup
            .get(&PortKey {
                port,
                protocol: ServiceProtocol::Tcp,
            })
            .map(String::as_str)
    }

    /// Looks up the service name for a UDP port.
    #[must_use]
    pub fn lookup_udp(&self, port: u16) -> Option<&str> {
        self.lookup
            .get(&PortKey {
                port,
                protocol: ServiceProtocol::Udp,
            })
            .map(String::as_str)
    }

    /// Looks up the service name for a port with the given protocol.
    #[must_use]
    pub fn lookup(&self, port: u16, protocol: ServiceProtocol) -> Option<&str> {
        self.lookup
            .get(&PortKey { port, protocol })
            .map(String::as_str)
    }

    /// Returns the top N TCP ports sorted by open frequency (descending).
    ///
    /// Used by `--top-ports N` to select the most commonly open ports.
    #[must_use]
    pub fn top_tcp_ports(&self, n: usize) -> &[u16] {
        let end = n.min(self.top_tcp_ports.len());
        &self.top_tcp_ports[..end]
    }

    /// Returns the top N UDP ports sorted by open frequency (descending).
    #[must_use]
    pub fn top_udp_ports(&self, n: usize) -> &[u16] {
        let end = n.min(self.top_udp_ports.len());
        &self.top_udp_ports[..end]
    }

    /// Returns the total number of entries in the database.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lookup.len()
    }

    /// Returns true if the database has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lookup.is_empty()
    }

    /// Parses the `nmap-services` file content into a database.
    ///
    /// File format: `service_name\tport/protocol\tfrequency\t# comment`
    fn parse(content: &str) -> Self {
        let mut lookup = HashMap::new();
        let mut tcp_entries: Vec<(u16, f64)> = Vec::new();
        let mut udp_entries: Vec<(u16, f64)> = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(entry) = Self::parse_line(line) {
                let key = PortKey {
                    port: entry.port,
                    protocol: entry.protocol,
                };

                if let std::collections::hash_map::Entry::Vacant(e) = lookup.entry(key) {
                    match entry.protocol {
                        ServiceProtocol::Tcp => tcp_entries.push((entry.port, entry.frequency)),
                        ServiceProtocol::Udp => udp_entries.push((entry.port, entry.frequency)),
                        ServiceProtocol::Sctp => {}
                    }
                    e.insert(entry.name);
                }
            }
        }

        // Sort by frequency descending, then by port number ascending for stability
        tcp_entries.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        udp_entries.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        let top_tcp_ports: Vec<u16> = tcp_entries.iter().map(|(port, _)| *port).collect();
        let top_udp_ports: Vec<u16> = udp_entries.iter().map(|(port, _)| *port).collect();

        Self {
            lookup,
            top_tcp_ports,
            top_udp_ports,
            source: DatabaseSource::Embedded,
        }
    }

    /// Parses a single line from the `nmap-services` file.
    fn parse_line(line: &str) -> Option<ServiceEntry> {
        let mut fields = line.split('\t');

        let name = fields.next()?.trim().to_string();
        let port_proto = fields.next()?.trim();
        let freq_str = fields.next()?.trim();

        // Parse port/protocol (e.g., "80/tcp")
        let (port_str, proto_str) = port_proto.split_once('/')?;
        let port: u16 = port_str.parse().ok()?;
        let protocol = match proto_str {
            "tcp" => ServiceProtocol::Tcp,
            "udp" => ServiceProtocol::Udp,
            "sctp" => ServiceProtocol::Sctp,
            _ => return None,
        };

        let frequency: f64 = freq_str.parse().ok()?;

        Some(ServiceEntry {
            name,
            port,
            protocol,
            frequency,
        })
    }
}

/// Returns the user's home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_database_loads() {
        let db = ServiceDatabase::global();
        assert!(!db.is_empty());
        // nmap-services has ~27,454 entries
        assert!(db.len() > 20_000, "Expected 20k+ entries, got {}", db.len());
    }

    #[test]
    fn test_tcp_lookup_common_ports() {
        let db = ServiceDatabase::global();
        assert_eq!(db.lookup_tcp(80), Some("http"));
        assert_eq!(db.lookup_tcp(443), Some("https"));
        assert_eq!(db.lookup_tcp(22), Some("ssh"));
        assert_eq!(db.lookup_tcp(21), Some("ftp"));
        assert_eq!(db.lookup_tcp(25), Some("smtp"));
        assert_eq!(db.lookup_tcp(3306), Some("mysql"));
        assert_eq!(db.lookup_tcp(5432), Some("postgresql"));
    }

    #[test]
    fn test_udp_lookup() {
        let db = ServiceDatabase::global();
        assert_eq!(db.lookup_udp(53), Some("domain"));
        assert_eq!(db.lookup_udp(161), Some("snmp"));
        assert_eq!(db.lookup_udp(123), Some("ntp"));
    }

    #[test]
    fn test_lookup_with_protocol() {
        let db = ServiceDatabase::global();
        assert_eq!(db.lookup(80, ServiceProtocol::Tcp), Some("http"));
        assert_eq!(db.lookup(53, ServiceProtocol::Udp), Some("domain"));
    }

    #[test]
    fn test_unknown_port_returns_none() {
        let db = ServiceDatabase::global();
        // Port 0 is not a real service
        assert_eq!(db.lookup_tcp(0), None);
    }

    #[test]
    fn test_top_tcp_ports_frequency_order() {
        let db = ServiceDatabase::global();
        let top10 = db.top_tcp_ports(10);
        assert_eq!(top10.len(), 10);
        // HTTP (80) should be the most common TCP port
        assert_eq!(top10[0], 80, "Port 80 (http) should be top TCP port");
        // Top 10 should contain well-known ports
        assert!(top10.contains(&22), "Top 10 should contain SSH (22)");
        assert!(top10.contains(&443), "Top 10 should contain HTTPS (443)");
    }

    #[test]
    fn test_top_ports_zero() {
        let db = ServiceDatabase::global();
        assert!(db.top_tcp_ports(0).is_empty());
        assert!(db.top_udp_ports(0).is_empty());
    }

    #[test]
    fn test_top_ports_clamps_to_available() {
        let db = ServiceDatabase::global();
        let all = db.top_tcp_ports(100_000);
        assert!(all.len() < 100_000);
        assert!(!all.is_empty());
    }

    #[test]
    fn test_parse_line_valid() {
        let entry = ServiceDatabase::parse_line("http\t80/tcp\t0.484143\t# World Wide Web HTTP");
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.name, "http");
        assert_eq!(entry.port, 80);
        assert_eq!(entry.protocol, ServiceProtocol::Tcp);
        assert!((entry.frequency - 0.484_143).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_line_no_comment() {
        let entry = ServiceDatabase::parse_line("ssh\t22/tcp\t0.182286");
        assert!(entry.is_some());
    }

    #[test]
    fn test_parse_line_invalid() {
        assert!(ServiceDatabase::parse_line("# comment").is_none());
        assert!(ServiceDatabase::parse_line("").is_none());
        assert!(ServiceDatabase::parse_line("incomplete").is_none());
        assert!(ServiceDatabase::parse_line("svc\tbadport\t0.1").is_none());
    }

    #[test]
    fn test_parse_custom_content() {
        let content = "\
http\t80/tcp\t0.5\t# HTTP
ssh\t22/tcp\t0.3\t# SSH
domain\t53/udp\t0.2\t# DNS
";
        let db = ServiceDatabase::parse(content);
        assert_eq!(db.len(), 3);
        assert_eq!(db.lookup_tcp(80), Some("http"));
        assert_eq!(db.lookup_tcp(22), Some("ssh"));
        assert_eq!(db.lookup_udp(53), Some("domain"));

        // Frequency order: http (0.5) > ssh (0.3)
        let top = db.top_tcp_ports(2);
        assert_eq!(top[0], 80);
        assert_eq!(top[1], 22);
    }

    #[test]
    fn test_duplicate_entries_first_wins() {
        let content = "\
http\t80/tcp\t0.5
apache\t80/tcp\t0.3
";
        let db = ServiceDatabase::parse(content);
        assert_eq!(db.lookup_tcp(80), Some("http"));
    }

    #[test]
    fn test_top_udp_ports() {
        let db = ServiceDatabase::global();
        let top10 = db.top_udp_ports(10);
        assert_eq!(top10.len(), 10);
        assert!(top10.contains(&161), "Top 10 UDP should contain SNMP (161)");
        assert!(top10.contains(&53), "Top 10 UDP should contain DNS (53)");
    }

    #[test]
    fn test_load_from_file_nonexistent() {
        let result = ServiceDatabase::load_from_file("/nonexistent/path/nmap-services");
        result.unwrap_err();
    }

    #[test]
    fn test_default_services_path() {
        let path = ServiceDatabase::default_services_path();
        // Should resolve if HOME is set
        if std::env::var_os("HOME").is_some() {
            assert!(path.is_some());
            let p = path.unwrap();
            assert!(p.ends_with("db/nmap-services"));
        }
    }

    #[test]
    fn test_database_source() {
        // Global DB uses embedded fallback (no file at ~/.rustnmap/db/ in test env)
        let db = ServiceDatabase::global();
        // Source should be either File or Embedded depending on test environment
        match db.source() {
            DatabaseSource::File(p) => {
                assert!(p.exists(), "Source file should exist");
            }
            DatabaseSource::Embedded => {
                // Expected in most test environments
            }
        }
    }
}

// Rust guideline compliant 2026-02-21
