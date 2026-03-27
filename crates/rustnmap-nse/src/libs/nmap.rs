//! Nmap base library for NSE.
//!
//! This module provides the `nmap` library which exposes core scan information
//! and utilities to Lua scripts. It corresponds to Nmap's nmap NSE library.
//!
//! # Available Functions and Values
//!
//! ## Values (Tables/Constants)
//! - `nmap.registry` - Global registry table for script communication
//! - `nmap.scan_start_time` - Scan start timestamp (seconds since epoch)
//! - `nmap.scan_type` - Current scan type ("syn", "connect", "udp", etc.)
//! - `nmap.timing_level` - Timing template level (0-5, corresponding to T0-T5)
//!
//! ## Functions
//! - `nmap.verbosity()` - Returns the current verbosity level (0-9)
//! - `nmap.debugging()` - Returns the current debugging level (0-9)
//! - `nmap.version_intensity()` - Returns the service probe intensity (0-9)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! -- Access scan information
//! local scan_type = nmap.scan_type
//! local timing = nmap.timing_level
//!
//! -- Use registry for script communication
//! nmap.registry["my_script_result"] = "found something"
//!
//! -- Check verbosity level
//! if nmap.verbosity() >= 2 then
//!     print("Verbose output")
//! end
//! ```

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::lua::NseLua;

#[cfg(feature = "openssl")]
use openssl::x509::X509;

/// Scan type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanType {
    /// TCP SYN scan (default, requires root).
    #[default]
    Syn,
    /// TCP Connect scan.
    Connect,
    /// UDP scan.
    Udp,
    /// TCP ACK scan.
    Ack,
    /// TCP FIN scan.
    Fin,
    /// TCP NULL scan.
    Null,
    /// TCP Xmas scan (FIN+PSH+URG).
    Xmas,
    /// TCP Maimon scan (FIN+ACK).
    Maimon,
    /// TCP Window scan.
    Window,
    /// IP Protocol scan.
    IpProtocol,
}

impl ScanType {
    /// Convert scan type to string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Connect => "connect",
            Self::Udp => "udp",
            Self::Ack => "ack",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Maimon => "maimon",
            Self::Window => "window",
            Self::IpProtocol => "ipproto",
        }
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ScanType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "syn" | "-ss" => Ok(Self::Syn),
            "connect" | "-st" => Ok(Self::Connect),
            "udp" | "-su" => Ok(Self::Udp),
            "ack" | "-sa" => Ok(Self::Ack),
            "fin" | "-sf" => Ok(Self::Fin),
            "null" | "-sn" => Ok(Self::Null),
            "xmas" | "-sx" => Ok(Self::Xmas),
            "maimon" | "-sm" => Ok(Self::Maimon),
            "window" | "-sw" => Ok(Self::Window),
            "ipproto" | "-so" => Ok(Self::IpProtocol),
            _ => Err(format!("unknown scan type: {s}")),
        }
    }
}

/// Nmap library configuration/state.
#[derive(Debug, Clone)]
pub struct NmapLibConfig {
    /// Scan start timestamp (seconds since Unix epoch).
    pub scan_start_time: u64,

    /// Current scan type.
    pub scan_type: ScanType,

    /// Timing template level (0-5, corresponding to T0-T5).
    pub timing_level: u8,

    /// Verbosity level (0-9).
    pub verbosity: u8,

    /// Debugging level (0-9).
    pub debugging: u8,

    /// Service probe intensity (0-9).
    pub version_intensity: u8,
}

impl Default for NmapLibConfig {
    fn default() -> Self {
        Self {
            scan_start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            scan_type: ScanType::Syn,
            timing_level: 3, // Normal (T3)
            verbosity: 0,
            debugging: 0,
            version_intensity: 7,
        }
    }
}

/// Thread-safe handle to nmap library state.
static NMAP_CONFIG: std::sync::OnceLock<std::sync::RwLock<NmapLibConfig>> =
    std::sync::OnceLock::new();

/// Global mutex storage for `nmap.mutex()` implementation.
/// Maps object string keys to mutex state.
type MutexMap = std::sync::Mutex<HashMap<String, Arc<std::sync::Mutex<MutexState>>>>;
static MUTEX_STORAGE: std::sync::OnceLock<MutexMap> = std::sync::OnceLock::new();

/// Mutex state tracking.
#[derive(Debug, Default)]
struct MutexState {
    /// Thread currently holding the lock (represented as string for simplicity)
    holder: Option<String>,
}

/// Get or initialize the global mutex storage.
fn get_mutex_storage() -> &'static MutexMap {
    MUTEX_STORAGE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Get the search paths for fetchfile.
/// Returns paths in order of priority.
fn get_fetchfile_search_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    // 1. User's home directory: ~/.rustnmap/
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(std::path::PathBuf::from(home).join(".rustnmap"));
    }

    // 2. RUSTNMAPDIR environment variable
    if let Ok(rustnmapdir) = std::env::var("RUSTNMAPDIR") {
        paths.push(std::path::PathBuf::from(rustnmapdir));
    }

    // 3. Development path: ./reference/nmap/ (relative to current directory)
    paths.push(std::path::PathBuf::from("reference/nmap"));

    // 4. Installed data directory
    paths.push(std::path::PathBuf::from("/usr/share/rustnmap"));

    // 5. Fallback to nmap's data directory (for compatibility)
    paths.push(std::path::PathBuf::from("/usr/share/nmap"));

    paths
}

/// Convert a Lua value to a string key for mutex lookup.
fn value_to_mutex_key(value: &mlua::Value) -> Option<String> {
    match value {
        mlua::Value::String(s) => s.to_str().ok().map(|s| format!("s:{s}")),
        mlua::Value::Table(t) => {
            // Use table pointer as key (similar to nmap behavior)
            Some(format!("t:{:p}", t.to_pointer()))
        }
        mlua::Value::UserData(ud) => Some(format!("u:{:p}", ud.to_pointer())),
        mlua::Value::Function(f) => Some(format!("f:{:p}", f.to_pointer())),
        mlua::Value::Thread(t) => Some(format!("c:{:p}", t.to_pointer())),
        mlua::Value::Integer(i) => Some(format!("i:{i}")),
        mlua::Value::Nil
        | mlua::Value::Boolean(_)
        | mlua::Value::Number(_)
        | mlua::Value::LightUserData(_)
        | mlua::Value::Error(_)
        | mlua::Value::Other(_) => None,
    }
}

/// Get or initialize the global nmap library configuration.
fn get_config() -> &'static std::sync::RwLock<NmapLibConfig> {
    NMAP_CONFIG.get_or_init(|| std::sync::RwLock::new(NmapLibConfig::default()))
}

/// Set the global nmap library configuration.
///
/// # Arguments
///
/// * `config` - The configuration to set
pub fn set_config(config: NmapLibConfig) {
    if let Ok(mut guard) = get_config().write() {
        *guard = config;
    }
}

/// Get a copy of the current nmap library configuration.
///
/// # Returns
///
/// A copy of the current configuration, or the default if the lock is poisoned.
#[must_use]
pub fn get_config_copy() -> NmapLibConfig {
    get_config()
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

/// Register the nmap library with the Lua runtime.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register with
///
/// # Errors
///
/// Returns an error if registration fails.
#[expect(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    reason = "Lua FFI requires c_int/i64 casts; library registration is inherently verbose"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the nmap table
    let nmap_table = lua.create_table()?;

    // Get current config
    let config = get_config_copy();

    // Create registry table (empty table that scripts can use)
    let registry = lua.create_table()?;

    // Create args table inside registry (for --script-args, empty by default)
    // Scripts access this via nmap.registry.args.scriptname
    let args = lua.create_table()?;
    registry.set("args", args)?;

    nmap_table.set("registry", registry)?;

    // Set scan_start_time
    nmap_table.set("scan_start_time", config.scan_start_time as i64)?;

    // Set scan_type
    nmap_table.set("scan_type", config.scan_type.as_str())?;

    // Set timing_level
    nmap_table.set("timing_level", config.timing_level as i64)?;

    // Register verbosity() function
    let verbosity_fn = lua.create_function(|_, ()| {
        let config = get_config_copy();
        Ok(config.verbosity as i64)
    })?;
    nmap_table.set("verbosity", verbosity_fn)?;

    // Register debugging() function
    let debugging_fn = lua.create_function(|_, ()| {
        let config = get_config_copy();
        Ok(config.debugging as i64)
    })?;
    nmap_table.set("debugging", debugging_fn)?;

    // Register version_intensity() function
    let version_intensity_fn = lua.create_function(|_, ()| {
        let config = get_config_copy();
        Ok(config.version_intensity as i64)
    })?;
    nmap_table.set("version_intensity", version_intensity_fn)?;

    // Register clock() function - returns seconds since epoch with microsecond precision
    let clock_fn = lua.create_function(|_, ()| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // Use as_secs_f64 for proper precision
        Ok(now.as_secs_f64())
    })?;
    nmap_table.set("clock", clock_fn)?;

    // Register address_family() function - returns "inet" for IPv4 or "inet6" for IPv6
    let address_family_fn = lua.create_function(|_, host: mlua::Table| {
        let ip_str: String = host.get("ip")?;
        if ip_str.contains(':') {
            Ok("inet6")
        } else {
            Ok("inet")
        }
    })?;
    nmap_table.set("address_family", address_family_fn)?;

    // Register log_write(level, message) function
    let log_write_fn = lua.create_function(|_, (level, message): (String, String)| {
        log_write_impl(&level, &message);
        Ok(())
    })?;
    nmap_table.set("log_write", log_write_fn)?;

    // Register new_socket() function - creates a new NSE socket
    let new_socket_fn = lua.create_function(|lua, ()| {
        let socket = NseSocket::new();
        Ok(mlua::Value::UserData(lua.create_userdata(socket)?))
    })?;
    nmap_table.set("new_socket", new_socket_fn)?;

    // Register socket table with utility functions
    // nmap.socket.sleep(secs) - sleep for specified seconds
    let socket_table = lua.create_table()?;
    let socket_sleep_fn = lua.create_function(|_, secs: f64| {
        // Convert seconds to milliseconds and sleep
        // Value is clamped to safe u64 range before casting
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "value clamped to u64 range"
        )]
        let ms = secs.clamp(0.0, 3_153_600_000.0) as u64; // cap at ~100 years in ms
        std::thread::sleep(std::time::Duration::from_millis(ms));
        Ok(())
    })?;
    socket_table.set("sleep", socket_sleep_fn)?;
    nmap_table.set("socket", socket_table)?;

    // Register mutex(object) function - creates or gets a mutex for an object
    // nmap.mutex returns a function that handles mutex operations:
    // "lock" - blocking lock, "trylock" - non-blocking, "done" - release, "running" - get holder
    let mutex_fn = lua.create_function(|lua, object: mlua::Value| {
        // Convert object to a string key
        let key = value_to_mutex_key(&object).ok_or_else(|| {
            mlua::Error::RuntimeError(
                "mutex object must be a string, table, function, thread, or userdata".to_string(),
            )
        })?;

        // Get or create the mutex for this key
        let mutex_arc = {
            let storage = get_mutex_storage();
            let mut guard = storage.lock().map_err(|e| {
                mlua::Error::RuntimeError(format!("mutex storage lock failed: {e}"))
            })?;
            Arc::clone(
                guard
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(MutexState::default()))),
            )
        };

        // Create the mutex operation function
        // This function is returned by nmap.mutex() and takes one argument:
        // "lock", "trylock", "done", or "running"
        let mutex_op_fn = lua.create_function(move |lua, operation: String| {
            let mut guard = mutex_arc
                .lock()
                .map_err(|e| mlua::Error::RuntimeError(format!("mutex lock failed: {e}")))?;

            match operation.as_str() {
                "lock" => {
                    // Blocking lock - acquires the mutex for the current thread
                    guard.holder = Some("current".to_string());
                    Ok(mlua::Value::Boolean(true))
                }
                "trylock" => {
                    // Non-blocking lock attempt - returns true if lock acquired
                    if guard.holder.is_some() {
                        Ok(mlua::Value::Boolean(false))
                    } else {
                        guard.holder = Some("current".to_string());
                        Ok(mlua::Value::Boolean(true))
                    }
                }
                "done" => {
                    // Release the mutex
                    guard.holder = None;
                    Ok(mlua::Value::Boolean(true))
                }
                "running" => {
                    // Return the thread holding the lock or nil
                    match &guard.holder {
                        Some(holder) => Ok(mlua::Value::String(lua.create_string(holder)?)),
                        None => Ok(mlua::Value::Nil),
                    }
                }
                _ => Err(mlua::Error::RuntimeError(format!(
                    "invalid mutex operation: {operation}"
                ))),
            }
        })?;

        Ok(mutex_op_fn)
    })?;
    nmap_table.set("mutex", mutex_fn)?;

    // Register fetchfile(filename) function - searches for a data file
    // Searches in order: ~/.rustnmap/, RUSTNMAPDIR env, ./reference/nmap/, /usr/share/rustnmap/
    let fetchfile_fn = lua.create_function(|lua, filename: String| {
        let search_paths = get_fetchfile_search_paths();

        for base_path in &search_paths {
            let full_path = base_path.join(&filename);
            if full_path.exists() {
                return Ok(mlua::Value::String(
                    lua.create_string(full_path.to_string_lossy().to_string())?,
                ));
            }
        }

        // File not found - return nil
        Ok(mlua::Value::Nil)
    })?;
    nmap_table.set("fetchfile", fetchfile_fn)?;

    // Set the nmap table as a global
    lua.globals().set("nmap", nmap_table)?;

    Ok(())
}

/// Log write implementation.
fn log_write_impl(level: &str, message: &str) {
    match level {
        "stdout" => {
            let _ = std::io::stdout().write_all(message.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
        "stderr" => {
            let _ = std::io::stderr().write_all(message.as_bytes());
            let _ = std::io::stderr().write_all(b"\n");
        }
        _ => {
            // Log to appropriate channel based on level
            tracing::debug!("[{level}] {message}");
        }
    }
}

/// NSE Socket implementation for `nmap.new_socket()`.
#[derive(Debug)]
pub struct NseSocket {
    /// Internal socket state
    state: SocketState,
    /// Listen backlog size
    backlog: i32,
    /// Socket timeout in milliseconds
    timeout: u64,
    /// SSL/TLS certificate (if SSL connection)
    #[cfg(feature = "openssl")]
    certificate: Option<X509>,
    /// SSL stream for encrypted connections
    #[cfg(feature = "openssl")]
    ssl_stream: Option<openssl::ssl::SslStream<std::net::TcpStream>>,
}

#[derive(Debug)]
enum SocketState {
    /// Socket is not connected
    Disconnected,
    /// Socket is connected to a remote host
    Connected {
        /// Remote address
        addr: std::net::SocketAddr,
        /// Protocol
        proto: String,
        /// TCP stream for send/receive operations (None if using SSL)
        stream: Option<std::net::TcpStream>,
        /// Whether this connection uses SSL
        is_ssl: bool,
    },
    /// Socket is listening for connections
    Listening {
        /// Local address
        addr: std::net::SocketAddr,
        /// Protocol
        proto: String,
    },
}

/// Convert X509 name to Lua table with DN fields.
#[cfg(feature = "openssl")]
fn x509_name_to_table(
    lua: &mlua::Lua,
    name: &openssl::x509::X509NameRef,
) -> mlua::Result<mlua::Table> {
    let table = lua.create_table()?;

    for entry in name.entries() {
        let obj = entry.object();
        let data = entry.data();

        // Try to get the NID (numeric identifier) for the object
        let nid = obj.nid();

        // Get the long name for the NID (e.g., "commonName", "organizationName")
        let key = if nid == openssl::nid::Nid::UNDEF {
            // Fallback to OID string representation
            format!("{obj:?}")
        } else {
            openssl::nid::Nid::from_raw(nid.as_raw())
                .long_name()
                .unwrap_or("unknown")
                .to_string()
        };

        // Convert ASN1_STRING to UTF-8 string
        let value = data
            .as_utf8()
            .map_or_else(|_| format!("{data:?}"), |s| s.to_string());

        table.set(key, value)?;
    }

    Ok(table)
}

/// Convert `ASN1_TIME` to Lua table or string.
#[cfg(feature = "openssl")]
fn asn1_time_to_table(
    lua: &mlua::Lua,
    time: &openssl::asn1::Asn1TimeRef,
) -> mlua::Result<mlua::Value> {
    // Convert ASN1_TIME to Unix timestamp, then to date components
    // OpenSSL's to_string() returns format like "Jan 23 00:00:00 2023 GMT"
    // We need to parse this properly

    use std::str::FromStr;

    let time_str = time.to_string();

    // Parse the OpenSSL time format: "Mon DD HH:MM:SS YYYY GMT"
    // Example: "Jan 23 00:00:00 2023 GMT"
    let parts: Vec<&str> = time_str.split_whitespace().collect();

    if parts.len() >= 4 {
        // Explicit month names for clarity even though "Jan" and default both return 1
        #[expect(clippy::match_same_arms, reason = "Explicit month names for readability")]
        let month = match parts[0] {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => 1, // Default to January for unknown months
        };

        let day = u8::from_str(parts[1]).unwrap_or(1);

        // Parse time HH:MM:SS
        let time_parts: Vec<&str> = parts[2].split(':').collect();
        let hour = time_parts
            .first()
            .map_or(0, |s| u8::from_str(s).unwrap_or(0));
        let min = time_parts
            .get(1)
            .map_or(0, |s| u8::from_str(s).unwrap_or(0));
        let sec = time_parts
            .get(2)
            .map_or(0, |s| u8::from_str(s).unwrap_or(0));

        let year = i32::from_str(parts[3]).unwrap_or(1970);

        let date_table = lua.create_table()?;
        date_table.set("year", year)?;
        date_table.set("month", month)?;
        date_table.set("day", day)?;
        date_table.set("hour", hour)?;
        date_table.set("min", min)?;
        date_table.set("sec", sec)?;

        Ok(mlua::Value::Table(date_table))
    } else {
        // Fallback to string if parsing fails
        Ok(mlua::Value::String(lua.create_string(&time_str)?))
    }
}

/// Convert X509 certificate to NSE-compatible Lua table.
#[cfg(feature = "openssl")]
fn cert_to_table(lua: &mlua::Lua, cert: &X509) -> mlua::Result<mlua::Table> {
    let cert_table = lua.create_table()?;

    // PEM encoding
    let pem = cert
        .to_pem()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to encode PEM: {e}")))?;
    let pem_str = String::from_utf8_lossy(&pem);
    cert_table.set("pem", pem_str.as_ref())?;

    // Subject
    let subject = cert.subject_name();
    let subject_table = x509_name_to_table(lua, subject)?;
    cert_table.set("subject", subject_table)?;

    // Issuer
    let issuer = cert.issuer_name();
    let issuer_table = x509_name_to_table(lua, issuer)?;
    cert_table.set("issuer", issuer_table)?;

    // Validity period
    let validity_table = lua.create_table()?;
    let not_before = cert.not_before();
    let not_before_val = asn1_time_to_table(lua, not_before)?;
    validity_table.set("notBefore", not_before_val)?;

    let not_after = cert.not_after();
    let not_after_val = asn1_time_to_table(lua, not_after)?;
    validity_table.set("notAfter", not_after_val)?;
    cert_table.set("validity", validity_table)?;

    // Signature algorithm
    let sig_alg = cert.signature_algorithm();
    let sig_algo_name = sig_alg
        .object()
        .nid()
        .long_name()
        .unwrap_or("unknown")
        .to_string();
    cert_table.set("sig_algorithm", sig_algo_name)?;

    // Public key information
    let pubkey_table = lua.create_table()?;
    let pkey = cert
        .public_key()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get public key: {e}")))?;

    // Key type
    let key_type = match pkey.id() {
        openssl::pkey::Id::RSA => "rsa",
        openssl::pkey::Id::DSA => "dsa",
        openssl::pkey::Id::DH => "dh",
        openssl::pkey::Id::EC => "ec",
        _ => "unknown",
    };
    pubkey_table.set("type", key_type)?;

    // Key bits
    let bits = pkey.bits();
    pubkey_table.set("bits", bits)?;

    // RSA-specific fields
    if pkey.id() == openssl::pkey::Id::RSA {
        let rsa = pkey
            .rsa()
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get RSA key: {e}")))?;

        let e = rsa.e();
        let exponent_bytes = e.to_vec();
        let exponent_hex = hex::encode(&exponent_bytes);
        pubkey_table.set("exponent", exponent_hex)?;

        let n = rsa.n();
        let modulus_bytes = n.to_vec();
        let modulus_hex = hex::encode(&modulus_bytes);
        pubkey_table.set("modulus", modulus_hex)?;
    }
    cert_table.set("pubkey", pubkey_table)?;

    // Add digest function to the certificate table
    // This will be called as cert:digest("sha1") etc.
    // When called as a method, Lua passes self as the first argument
    let cert_clone = cert.clone();
    let digest_fn = lua.create_function(move |lua, (_self, algo): (mlua::Table, String)| {
        use openssl::hash::MessageDigest;

        let message_digest = match algo.to_lowercase().as_str() {
            "md5" => MessageDigest::md5(),
            "sha1" => MessageDigest::sha1(),
            "sha256" => MessageDigest::sha256(),
            _ => {
                return Err(mlua::Error::RuntimeError(format!(
                    "Unknown digest algorithm: {algo}"
                )))
            }
        };

        match cert_clone.digest(message_digest) {
            Ok(digest_bytes) => {
                // Return raw binary bytes - stdnse.tohex will convert to hex
                Ok(mlua::Value::String(lua.create_string(digest_bytes)?))
            }
            Err(e) => Err(mlua::Error::RuntimeError(format!(
                "Digest calculation failed: {e}"
            ))),
        }
    })?;

    // Add extensions - build a list of known extensions
    let extensions_table = lua.create_table()?;

    // Subject Alternative Name
    if let Some(san) = cert.subject_alt_names() {
        let san_values: Vec<String> = san
            .iter()
            .filter_map(|name| {
                name.dnsname().map(|dns| format!("DNS:{dns}"))
                    .or_else(|| name.ipaddress().map(|ip| format!("IP:{ip:?}")))
            })
            .collect();
        if !san_values.is_empty() {
            let ext_table = lua.create_table()?;
            ext_table.set("name", "X509v3 Subject Alternative Name")?;
            ext_table.set("value", san_values.join(", "))?;
            extensions_table.set(1, ext_table)?;
        }
    }

    // Add empty extensions table if no extensions found
    cert_table.set("extensions", extensions_table)?;

    // Add digest as a regular method (not via metatable __index)
    cert_table.set("digest", digest_fn)?;

    Ok(cert_table)
}

impl NseSocket {
    /// Create a new unconnected socket.
    fn new() -> Self {
        Self {
            state: SocketState::Disconnected,
            backlog: 128,
            timeout: 10_000, // Default 10 second timeout
            #[cfg(feature = "openssl")]
            certificate: None,
            #[cfg(feature = "openssl")]
            ssl_stream: None,
        }
    }

    /// Set the listen backlog size.
    fn set_backlog(&mut self, backlog: i32) {
        self.backlog = backlog.max(1);
    }

    /// Get the socket timeout in milliseconds.
    #[must_use]
    const fn timeout(&self) -> u64 {
        self.timeout
    }

    /// Set the socket timeout in milliseconds.
    fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout = timeout_ms;
    }

    /// Get a mutable reference to the TCP stream if connected.
    ///
    /// For SSL connections, returns the underlying TCP stream from the SSL stream.
    ///
    /// # Errors
    ///
    /// Returns error if socket is not connected.
    /// Note: This function is reserved for future use.
    #[allow(dead_code, reason = "Reserved for future SSL/TLS read/write operations")]
    fn get_stream_mut(&mut self) -> mlua::Result<&mut std::net::TcpStream> {
        match &mut self.state {
            SocketState::Connected { stream, is_ssl, .. } => {
                if *is_ssl {
                    // For SSL connections, we can't return the TCP stream directly
                    // because the SSL stream owns it
                    return Err(mlua::Error::RuntimeError(
                        "Cannot get TCP stream from SSL connection".to_string(),
                    ));
                }
                stream.as_mut().ok_or_else(|| {
                    mlua::Error::RuntimeError("Socket not properly connected".to_string())
                })
            }
            _ => Err(mlua::Error::RuntimeError(
                "Socket is not connected".to_string(),
            )),
        }
    }

    /// Get a reference to the SSL stream if connected via SSL.
    #[cfg(feature = "openssl")]
    #[allow(dead_code, reason = "Reserved for future SSL/TLS read/write operations")]
    #[must_use]
    fn get_ssl_stream(&self) -> Option<&openssl::ssl::SslStream<std::net::TcpStream>> {
        self.ssl_stream.as_ref()
    }

    /// Get a mutable reference to the SSL stream if connected via SSL.
    #[cfg(feature = "openssl")]
    #[allow(dead_code, reason = "Reserved for future SSL/TLS read/write operations")]
    fn get_ssl_stream_mut(&mut self) -> Option<&mut openssl::ssl::SslStream<std::net::TcpStream>> {
        self.ssl_stream.as_mut()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "UserData impl requires many method registrations"
)]
impl mlua::UserData for NseSocket {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        // NSE socket connect method
        // Signature: sock:connect(host, port, proto)
        // - host: string IP or table {ip=..., targetname=...}
        // - port: port number or port table with .number field
        // - proto: optional protocol string ("tcp", "ssl", etc.)
        //
        // Note: This is a synchronous (blocking) method for NSE compatibility.
        // Uses block_in_place to handle blocking operations without async yields.
        methods.add_method_mut("connect", |_, this, args: mlua::MultiValue| {
            let args_vec: Vec<mlua::Value> = args.into_iter().collect();

            // Need at least 2 args: host and port
            if args_vec.len() < 2 {
                return Err(mlua::Error::RuntimeError(format!(
                    "connect requires at least 2 arguments (host, port), got {}",
                    args_vec.len()
                )));
            }

            // Extract host (string or table)
            let host = match &args_vec[0] {
                mlua::Value::String(s) => s.to_string_lossy().to_string(),
                mlua::Value::Table(t) => {
                    // Get IP from table
                    let ip: mlua::String = t.get("ip").map_err(|_e| {
                        mlua::Error::RuntimeError("Missing 'ip' field in host table".to_string())
                    })?;
                    ip.to_string_lossy().to_string()
                }
                _ => {
                    return Err(mlua::Error::RuntimeError(
                        "Host must be string or table".to_string(),
                    ))
                }
            };

            // Extract port (can be number or port table with .number field)
            let port = match &args_vec[1] {
                mlua::Value::Integer(n) => u16::try_from(*n)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Port out of range: {e}")))?,
                mlua::Value::Number(n) =>
                {
                    #[expect(clippy::cast_possible_truncation, reason = "try_from validates range")]
                    u16::try_from(*n as i64)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Port out of range: {e}")))?
                }
                mlua::Value::Table(t) => {
                    // NSE port object - get the .number field
                    let port_val: mlua::Value = t.get("number").map_err(|_e| {
                        mlua::Error::RuntimeError("Port table missing 'number' field".to_string())
                    })?;
                    match port_val {
                        mlua::Value::Integer(n) => u16::try_from(n).map_err(|e| {
                            mlua::Error::RuntimeError(format!("Port out of range: {e}"))
                        })?,
                        mlua::Value::Number(n) =>
                        {
                            #[expect(
                                clippy::cast_possible_truncation,
                                reason = "try_from validates range"
                            )]
                            u16::try_from(n as i64).map_err(|e| {
                                mlua::Error::RuntimeError(format!("Port out of range: {e}"))
                            })?
                        }
                        _ => {
                            return Err(mlua::Error::RuntimeError(
                                "Port.number must be a number".to_string(),
                            ))
                        }
                    }
                }
                _ => {
                    return Err(mlua::Error::RuntimeError(
                        "Port must be a number or port table".to_string(),
                    ))
                }
            };

            // Proto is optional 3rd argument
            let proto = if args_vec.len() > 2 {
                match &args_vec[2] {
                    mlua::Value::String(s) => s.to_string_lossy().to_string(),
                    _ => "tcp".to_string(),
                }
            } else {
                "tcp".to_string()
            };

            let addr = format!("{host}:{port}");
            match addr.parse::<std::net::SocketAddr>() {
                Ok(socket_addr) => {
                    // Check if this is an SSL connection
                    let is_ssl = proto == "ssl";

                    // Block to perform the connect operation
                    let result = tokio::task::block_in_place(|| {
                        std::net::TcpStream::connect_timeout(
                            &socket_addr,
                            std::time::Duration::from_secs(30),
                        )
                    });

                    let stream = result.map_err(|e| mlua::Error::RuntimeError(format!("Connect failed: {e}")))?;

                    // Perform SSL handshake if requested
                    #[cfg(feature = "openssl")]
                    if is_ssl {
                        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

                        // Create SSL connector with certificate verification disabled
                        // (Nmap doesn't verify certificates during scanning)
                        let mut builder = SslConnector::builder(SslMethod::tls())
                            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to create SSL connector: {e}")))?;
                        builder.set_verify(SslVerifyMode::NONE);
                        let connector = builder.build();

                        // Perform SSL handshake using connector's connect method
                        let ssl_stream = tokio::task::block_in_place(|| {
                            connector.connect(host.as_str(), stream)
                        })
                        .map_err(|e| mlua::Error::RuntimeError(format!("SSL handshake failed: {e}")))?;

                        // Extract peer certificate
                        let cert = ssl_stream.ssl().peer_certificate();

                        // Store SSL stream and certificate
                        this.ssl_stream = Some(ssl_stream);
                        this.certificate = cert;

                        // Update state - no TCP stream stored since we have SSL stream
                        this.state = SocketState::Connected {
                            addr: socket_addr,
                            proto,
                            stream: None, // SSL stream stored separately
                            is_ssl: true,
                        };
                    } else {
                        #[cfg(feature = "openssl")]
                        {
                            this.state = SocketState::Connected {
                                addr: socket_addr,
                                proto,
                                stream: Some(stream),
                                is_ssl: false,
                            };
                        }

                        #[cfg(not(feature = "openssl"))]
                        {
                            this.state = SocketState::Connected {
                                addr: socket_addr,
                                proto,
                                stream: Some(stream),
                                is_ssl: false,
                            };
                        }
                    }

                    Ok(true)
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Invalid address: {e}"))),
            }
        });

        // Bind socket to local address
        methods.add_method_mut("bind", |_, _this, (host, port): (String, u16)| {
            let addr_str = format!("{host}:{port}");
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(_socket_addr) => {
                    // For NSE scripts, binding is conceptual - we just track the state
                    // Actual socket binding would be done by the listener
                    Ok(true)
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Invalid address: {e}"))),
            }
        });

        // Listen for connections (puts socket in listening state)
        methods.add_method_mut("listen", |_, this, (host, port): (String, u16)| {
            let addr_str = format!("{host}:{port}");
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(socket_addr) => {
                    this.state = SocketState::Listening {
                        addr: socket_addr,
                        proto: "tcp".to_string(),
                    };
                    Ok(true)
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Invalid address: {e}"))),
            }
        });

        // Set backlog size for listening socket
        methods.add_method_mut("set_backlog", |_, this, backlog: i32| {
            this.set_backlog(backlog);
            Ok(())
        });

        // Accept a connection (returns new socket for accepted connection)
        methods.add_async_method_mut("accept", |lua, this, ()| async move {
            match &this.state {
                SocketState::Listening { addr, proto } => {
                    // In a real implementation, this would accept from a TcpListener
                    // For NSE compatibility, we simulate accepting a connection
                    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
                        mlua::Error::RuntimeError(format!("Accept bind failed: {e}"))
                    })?;

                    // Try to accept with timeout
                    let accept_result =
                        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                            .await;

                    match accept_result {
                        Ok(Ok((tokio_stream, peer_addr))) => {
                            // Try to convert tokio TcpStream to std TcpStream
                            let std_stream = match tokio_stream.into_std() {
                                Ok(s) => s,
                                Err(e) => {
                                    return Err(mlua::Error::RuntimeError(format!(
                                        "Stream conversion failed: {e}"
                                    )))
                                }
                            };

                            // Create new socket for accepted connection
                            let mut accepted_socket = NseSocket::new();
                            accepted_socket.state = SocketState::Connected {
                                addr: peer_addr,
                                proto: proto.clone(),
                                stream: Some(std_stream),
                                is_ssl: false,
                            };
                            let accepted = lua.create_userdata(accepted_socket)?;
                            Ok(accepted)
                        }
                        Ok(Err(e)) => Err(mlua::Error::RuntimeError(format!("Accept failed: {e}"))),
                        Err(_) => Err(mlua::Error::RuntimeError("Accept timeout".to_string())),
                    }
                }
                _ => Err(mlua::Error::RuntimeError(
                    "Socket not in listening state".to_string(),
                )),
            }
        });

        methods.add_method_mut("close", |_, this, ()| {
            this.state = SocketState::Disconnected;
            // Clear SSL state when closing (feature flag conditional)
            #[cfg(feature = "openssl")]
            let _ = this.ssl_stream.take();
            #[cfg(feature = "openssl")]
            let _ = this.certificate.take();
            Ok(true)
        });

        methods.add_method("is_connected", |_, this, ()| {
            Ok(matches!(this.state, SocketState::Connected { .. }))
        });

        methods.add_method("is_listening", |_, this, ()| {
            Ok(matches!(this.state, SocketState::Listening { .. }))
        });

        methods.add_method("get_info", |lua, this, ()| {
            let table = lua.create_table()?;
            match &this.state {
                SocketState::Connected { addr, proto, .. } => {
                    table.set("addr", addr.to_string())?;
                    table.set("proto", proto.clone())?;
                    table.set("state", "connected")?;
                }
                SocketState::Listening { addr, proto } => {
                    table.set("addr", addr.to_string())?;
                    table.set("proto", proto.clone())?;
                    table.set("state", "listening")?;
                }
                SocketState::Disconnected => {
                    table.set("addr", mlua::Value::Nil)?;
                    table.set("proto", mlua::Value::Nil)?;
                    table.set("state", "disconnected")?;
                }
            }
            Ok(table)
        });

        // Set socket timeout in milliseconds
        methods.add_method_mut("set_timeout", |_, this, timeout_ms: u64| {
            this.set_timeout(timeout_ms);
            Ok(())
        });

        // Send data to the socket
        methods.add_method_mut("send", |_, this, data: mlua::String| {
            let bytes = data.to_string_lossy().into_bytes();

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                // Use SSL stream for SSL connections
                std::io::Write::write_all(ssl_stream, &bytes)
                    .map_err(|e| mlua::Error::RuntimeError(format!("SSL send failed: {e}")))?;
                return Ok(bytes.len());
            }

            // Fall back to TCP stream
            let stream = this.get_stream_mut()?;
            stream
                .write_all(&bytes)
                .map_err(|e| mlua::Error::RuntimeError(format!("Send failed: {e}")))?;
            Ok(bytes.len())
        });

        // Receive data with pattern matching (bytes, or all)
        // Pattern can be: "a" = all, number = exact bytes
        methods.add_method_mut("receive", |lua, this, pattern: mlua::Value| {
            // Get timeout before borrowing stream
            let timeout_ms = this.timeout();

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                // Use SSL stream for SSL connections
                ssl_stream
                    .get_ref()
                    .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

                return match pattern {
                    // Pattern "a" - read all available data
                    mlua::Value::String(s) if s.to_string_lossy() == "a" => {
                        let mut buffer = Vec::new();
                        ssl_stream
                            .read_to_end(&mut buffer)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                        let s = String::from_utf8_lossy(&buffer);
                        lua.create_string(&*s)
                    }
                    // Pattern number - read exactly N bytes
                    mlua::Value::Integer(n) if n > 0 => {
                        let mut buffer = vec![0u8; usize::try_from(n).unwrap_or(usize::MAX)];
                        ssl_stream
                            .read_exact(&mut buffer)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                        let s = String::from_utf8_lossy(&buffer);
                        lua.create_string(&*s)
                    }
                    // Pattern 0 - read all available (same as "a")
                    mlua::Value::Integer(0) => {
                        let mut buffer = Vec::new();
                        ssl_stream
                            .read_to_end(&mut buffer)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                        let s = String::from_utf8_lossy(&buffer);
                        lua.create_string(&*s)
                    }
                    _ => Err(mlua::Error::RuntimeError(
                        "Invalid receive pattern".to_string(),
                    )),
                };
            }

            // Fall back to TCP stream
            let stream = this.get_stream_mut()?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

            match pattern {
                // Pattern "a" - read all available data
                mlua::Value::String(s) if s.to_string_lossy() == "a" => {
                    let mut buffer = Vec::new();
                    stream
                        .read_to_end(&mut buffer)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                    let s = String::from_utf8_lossy(&buffer);
                    lua.create_string(&*s)
                }
                // Pattern number - read exactly N bytes
                mlua::Value::Integer(n) if n > 0 => {
                    let mut buffer = vec![0u8; usize::try_from(n).unwrap_or(usize::MAX)];
                    stream
                        .read_exact(&mut buffer)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                    let s = String::from_utf8_lossy(&buffer);
                    lua.create_string(&*s)
                }
                // Pattern 0 - read all available (same as "a")
                mlua::Value::Integer(0) => {
                    let mut buffer = Vec::new();
                    stream
                        .read_to_end(&mut buffer)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                    let s = String::from_utf8_lossy(&buffer);
                    lua.create_string(&*s)
                }
                _ => Err(mlua::Error::RuntimeError(
                    "Invalid receive pattern".to_string(),
                )),
            }
        });

        // Receive exactly N bytes
        methods.add_method_mut("receive_bytes", |lua, this, n: usize| {
            // Get timeout before borrowing stream
            let timeout_ms = this.timeout();

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                // Use SSL stream for SSL connections
                ssl_stream
                    .get_ref()
                    .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

                let mut buffer = vec![0u8; n];
                ssl_stream
                    .read_exact(&mut buffer)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;

                let s = String::from_utf8_lossy(&buffer);
                return lua.create_string(&*s);
            }

            // Fall back to TCP stream
            let stream = this.get_stream_mut()?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

            let mut buffer = vec![0u8; n];
            stream
                .read_exact(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
            let s = String::from_utf8_lossy(&buffer);
            lua.create_string(&*s)
        });

        // Receive data into a buffer of specified size
        methods.add_method_mut("receive_buf", |lua, this, size: usize| {
            // Get timeout before borrowing stream
            let timeout_ms = this.timeout();

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                // Use SSL stream for SSL connections
                ssl_stream
                    .get_ref()
                    .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

                let mut buffer = vec![0u8; size];
                let n = ssl_stream
                    .read(&mut buffer)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;

                let s = String::from_utf8_lossy(&buffer[..n]);
                return lua.create_string(&*s);
            }

            // Fall back to TCP stream
            let stream = this.get_stream_mut()?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(timeout_ms)))
                .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

            let mut buffer = vec![0u8; size];
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
            let s = String::from_utf8_lossy(&buffer[..n]);
            lua.create_string(&*s)
        });

        // Get SSL certificate (if SSL connection)
        #[cfg(feature = "openssl")]
        methods.add_method("get_ssl_certificate", |lua, this, ()| {
            if let Some(ref cert) = this.certificate {
                match cert_to_table(lua, cert) {
                    Ok(table) => Ok(mlua::Value::Table(table)),
                    Err(e) => Err(mlua::Error::RuntimeError(format!(
                        "Failed to convert certificate to table: {e}"
                    ))),
                }
            } else {
                Ok(mlua::Value::Nil)
            }
        });
    }
}

/// Update the scan type in the global configuration.
///
/// # Arguments
///
/// * `scan_type` - The new scan type
pub fn set_scan_type(scan_type: ScanType) {
    if let Ok(mut guard) = get_config().write() {
        guard.scan_type = scan_type;
    }
}

/// Update the timing level in the global configuration.
///
/// # Arguments
///
/// * `level` - The new timing level (0-5)
pub fn set_timing_level(level: u8) {
    if let Ok(mut guard) = get_config().write() {
        guard.timing_level = level.min(5);
    }
}

/// Update the verbosity level in the global configuration.
///
/// # Arguments
///
/// * `level` - The new verbosity level (0-9)
pub fn set_verbosity(level: u8) {
    if let Ok(mut guard) = get_config().write() {
        guard.verbosity = level.min(9);
    }
}

/// Update the debugging level in the global configuration.
///
/// # Arguments
///
/// * `level` - The new debugging level (0-9)
pub fn set_debugging(level: u8) {
    if let Ok(mut guard) = get_config().write() {
        guard.debugging = level.min(9);
    }
}

/// Update the version intensity in the global configuration.
///
/// # Arguments
///
/// * `intensity` - The new version intensity (0-9)
pub fn set_version_intensity(intensity: u8) {
    if let Ok(mut guard) = get_config().write() {
        guard.version_intensity = intensity.min(9);
    }
}

/// Reset the registry (clear all script communication data).
pub fn reset_registry() {
    // Registry is per-Lua-state, so this is a no-op at the global level.
    // Individual Lua states manage their own registry tables.
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Table;

    #[test]
    fn test_scan_type_as_str() {
        assert_eq!(ScanType::Syn.as_str(), "syn");
        assert_eq!(ScanType::Connect.as_str(), "connect");
        assert_eq!(ScanType::Udp.as_str(), "udp");
        assert_eq!(ScanType::Fin.as_str(), "fin");
        assert_eq!(ScanType::Null.as_str(), "null");
        assert_eq!(ScanType::Xmas.as_str(), "xmas");
        assert_eq!(ScanType::Ack.as_str(), "ack");
        assert_eq!(ScanType::Maimon.as_str(), "maimon");
    }

    #[test]
    fn test_scan_type_from_str() {
        assert_eq!("syn".parse::<ScanType>().unwrap(), ScanType::Syn);
        assert_eq!("connect".parse::<ScanType>().unwrap(), ScanType::Connect);
        assert_eq!("udp".parse::<ScanType>().unwrap(), ScanType::Udp);
        assert_eq!("SYN".parse::<ScanType>().unwrap(), ScanType::Syn);
        assert_eq!("Connect".parse::<ScanType>().unwrap(), ScanType::Connect);
    }

    #[test]
    fn test_scan_type_display() {
        assert_eq!(format!("{}", ScanType::Syn), "syn");
        assert_eq!(format!("{}", ScanType::Udp), "udp");
    }

    #[test]
    fn test_nmap_config_default() {
        let config = NmapLibConfig::default();
        assert_eq!(config.scan_type, ScanType::Syn);
        assert_eq!(config.timing_level, 3);
        assert_eq!(config.verbosity, 0);
        assert_eq!(config.debugging, 0);
        assert_eq!(config.version_intensity, 7);
    }

    #[test]
    fn test_reset_registry() {
        // This is a no-op, but we test it doesn't panic
        reset_registry();
    }

    #[test]
    fn test_register_nmap_library() {
        let mut lua = NseLua::new_default().unwrap();
        let result = register(&mut lua);
        result.unwrap();

        // Check that nmap table exists
        let nmap: Table = lua.lua().globals().get("nmap").unwrap();

        // Check registry is a table
        let registry: Table = nmap.get("registry").unwrap();
        let test_val: Option<String> = registry.get("test").unwrap();
        assert!(test_val.is_none());

        // Check scan_start_time is set
        let scan_start: i64 = nmap.get("scan_start_time").unwrap();
        assert!(scan_start > 0);

        // Check scan_type is set
        let scan_type: String = nmap.get("scan_type").unwrap();
        assert_eq!(scan_type, "syn");

        // Check timing_level is set
        let timing: i64 = nmap.get("timing_level").unwrap();
        assert_eq!(timing, 3);
    }

    #[test]
    fn test_verbosity_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Set verbosity to 5
        set_verbosity(5);

        // Call nmap.verbosity() from Lua
        let result: i64 = lua.lua().load("return nmap.verbosity()").eval().unwrap();
        assert_eq!(result, 5);
    }

    #[test]
    fn test_debugging_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Set debugging to 3
        set_debugging(3);

        // Call nmap.debugging() from Lua
        let result: i64 = lua.lua().load("return nmap.debugging()").eval().unwrap();
        assert_eq!(result, 3);
    }

    #[test]
    fn test_version_intensity_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Set version intensity to 9
        set_version_intensity(9);

        // Call nmap.version_intensity() from Lua
        let result: i64 = lua
            .lua()
            .load("return nmap.version_intensity()")
            .eval()
            .unwrap();
        assert_eq!(result, 9);
    }

    #[test]
    fn test_set_scan_type() {
        set_scan_type(ScanType::Udp);
        let config = get_config_copy();
        assert_eq!(config.scan_type, ScanType::Udp);

        // Reset to default for other tests
        set_scan_type(ScanType::Syn);
    }

    #[test]
    fn test_set_timing_level() {
        set_timing_level(5);
        let config = get_config_copy();
        assert_eq!(config.timing_level, 5);

        // Test clamping to max 5
        set_timing_level(10);
        let config = get_config_copy();
        assert_eq!(config.timing_level, 5);

        // Reset to default
        set_timing_level(3);
    }

    #[test]
    fn test_registry_usage_from_lua() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Set a value in the registry from Lua
        lua.lua()
            .load("nmap.registry[\"test_key\"] = \"test_value\"")
            .exec()
            .unwrap();

        // Read the value back
        let value: String = lua
            .lua()
            .load("return nmap.registry[\"test_key\"]")
            .eval()
            .unwrap();
        assert_eq!(value, "test_value");
    }
}
