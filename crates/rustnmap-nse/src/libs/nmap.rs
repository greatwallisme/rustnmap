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

//! Nmap base library for NSE.
//! Nmap base library for NSE.
//!
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

    // // 3. Development path: ./reference/nmap/ (relative to current directory)
    // paths.push(std::path::PathBuf::from("reference/nmap"));

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

    // Register timing_level() function - returns timing template level (0-5)
    // nmap exposes this as a function, not a property, since scripts call nmap.timing_level()
    let timing_level_fn = lua.create_function(|_, ()| {
        let config = get_config_copy();
        Ok(config.timing_level as i64)
    })?;
    nmap_table.set("timing_level", timing_level_fn)?;

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

    // Register is_privileged() function — returns true if running as root
    let is_privileged_fn = lua.create_function(|_, ()| {
        // SAFETY: `geteuid()` is a read-only POSIX syscall with no preconditions.
        Ok(unsafe { libc::geteuid() } == 0)
    })?;
    nmap_table.set("is_privileged", is_privileged_fn)?;

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
    // Can be called with no args (uses scan config) or with a host table
    let address_family_fn = lua.create_function(|_, host: Option<mlua::Table>| {
        match host {
            Some(h) => {
                let ip_str: String = h.get("ip")?;
                if ip_str.contains(':') {
                    Ok("inet6")
                } else {
                    Ok("inet")
                }
            }
            None => {
                // No host argument - default to inet (IPv4) since most scans are IPv4
                Ok("inet")
            }
        }
    })?;
    nmap_table.set("address_family", address_family_fn)?;

    // Register get_dns_servers() function - returns list of DNS server IPs
    // Reads from /etc/resolv.conf, matching nmap's behavior
    let get_dns_servers_fn = lua.create_function(|lua, ()| {
        let servers = lua.create_table()?;
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            let mut idx = 1i64;
            for line in contents.lines() {
                let trimmed = line.trim();
                if let Some(addr) = trimmed.strip_prefix("nameserver") {
                    let addr = addr.trim();
                    if !addr.is_empty() {
                        servers.set(idx, addr)?;
                        idx += 1;
                    }
                }
            }
        }
        Ok(servers)
    })?;
    nmap_table.set("get_dns_servers", get_dns_servers_fn)?;

    // Register log_write(level, message) function
    let log_write_fn = lua.create_function(|_, (level, message): (String, String)| {
        log_write_impl(&level, &message);
        Ok(())
    })?;
    nmap_table.set("log_write", log_write_fn)?;

    // Register new_socket() function - creates a new NSE socket
    // Accepts optional protocol parameter: new_socket() or new_socket("udp")
    let new_socket_fn = lua.create_function(|lua, proto: Option<String>| {
        let socket = NseSocket::new(proto);
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

    // Register nmap.socket.parse_ssl_certificate(der_data) function
    // This static function parses a DER-encoded certificate and returns a table
    // with certificate fields (subject, issuer, validity, etc.)
    #[cfg(feature = "openssl")]
    let parse_ssl_cert_fn = lua.create_function(|lua, der_data: mlua::String| {
        let der_bytes = der_data.as_bytes();
        let cert = X509::from_der(&der_bytes).map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to parse DER certificate: {e}"))
        })?;
        cert_to_table(lua, &cert)
    })?;
    #[cfg(not(feature = "openssl"))]
    let parse_ssl_cert_fn = lua.create_function(|_, _: mlua::Value| Ok(mlua::Value::Nil))?;
    socket_table.set("parse_ssl_certificate", parse_ssl_cert_fn)?;

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
    // Searches in order: ~/.rustnmap/, RUSTNMAPDIR env, /usr/share/rustnmap/
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

    // Register condvar(id) function - creates a condition variable for thread synchronization.
    // In Nmap, nmap.condvar(obj) returns a FUNCTION that can be called:
    //   local cv = nmap.condvar(obj)
    //   cv "signal"    -- signal the condition variable
    //   cv "wait"      -- wait on the condition variable
    //   cv "broadcast" -- broadcast to all waiters
    // Since our engine runs Lua single-threaded within a process, these are no-ops.
    let condvar_fn = lua.create_function(|lua, _id: mlua::Value| {
        // Return a function that accepts a command string
        let cv_fn = lua.create_function(|_, cmd: Option<String>| {
            // Single-threaded: signal/wait/broadcast are all no-ops
            let _ = cmd;
            Ok(true)
        })?;

        Ok(cv_fn)
    })?;
    nmap_table.set("condvar", condvar_fn)?;

    // Register get_port_state(host, port_table) function
    // Returns a port table with state info, or nil if port not scanned.
    // For host scripts, checks if the requested port was in the scan results.
    let get_port_state_fn =
        lua.create_function(|lua, (host, port_spec): (mlua::Table, mlua::Table)| {
            let port_num: u16 = port_spec.get("number")?;
            let proto: String = port_spec
                .get::<String>("protocol")
                .unwrap_or_else(|_| "tcp".to_string());

            // Check if host has a "ports" table (populated by the engine)
            if let Ok(ports) = host.get::<mlua::Table>("ports") {
                // ports is a sequence of port tables
                for pt in ports.sequence_values::<mlua::Table>().flatten() {
                    let p_num: u16 = pt.get("number").unwrap_or(0);
                    let p_proto: String = pt.get("protocol").unwrap_or_else(|_| "tcp".to_string());
                    if p_num == port_num && p_proto == proto {
                        // Ensure the port table has a "version" subtable.
                        // Scripts like smb-os-discovery write to port.version.product.
                        if pt.get::<mlua::Value>("version").is_err() {
                            let _ = pt.set("version", lua.create_table()?);
                        }
                        return Ok(mlua::Value::Table(pt));
                    }
                }
            }

            // If port not found in scan results, construct a synthetic result
            // based on whether we can connect to the port
            if proto == "tcp" {
                let host_ip: String = host.get("ip")?;
                let addr = format!("{host_ip}:{port_num}");
                if let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() {
                    let is_open = tokio::task::block_in_place(|| {
                        std::net::TcpStream::connect_timeout(
                            &socket_addr,
                            std::time::Duration::from_secs(2),
                        )
                        .is_ok()
                    });

                    if is_open {
                        let port_table = lua.create_table()?;
                        port_table.set("number", port_num)?;
                        port_table.set("protocol", proto)?;
                        port_table.set("state", "open")?;
                        port_table.set("service", lua.create_table()?)?;
                        port_table.set("version", lua.create_table()?)?;
                        return Ok(mlua::Value::Table(port_table));
                    }
                }
            }

            Ok(mlua::Value::Nil)
        })?;
    nmap_table.set("get_port_state", get_port_state_fn)?;

    // Register new_try(catch_fn) function - creates an error-handling wrapper.
    // Pattern from nmap nse_nmaplib.cc l_new_try / new_try_finalize:
    //   local try = nmap.new_try(catch)
    //   try(socket:connect(host, port))  -- if first return is falsy, calls catch and throws
    //
    // The returned try function checks its first argument:
    //   - If truthy (true): returns remaining arguments unchanged
    //   - If falsy (nil/false): calls catch function (if provided), then throws
    //     a table {errtype="nmap.new_try", message=error_string}
    let new_try_fn = lua.create_function(|lua, catch_fn: Option<mlua::Function>| {
        lua.create_function(move |lua, args: mlua::MultiValue| {
            let mut args_vec: Vec<mlua::Value> = args.into_iter().collect();
            if args_vec.is_empty() {
                return Err(mlua::Error::RuntimeError(
                    "nmap.new_try: try() called with no arguments".to_string(),
                ));
            }

            let first = &args_vec[0];
            let is_ok = !matches!(first, mlua::Value::Nil | mlua::Value::Boolean(false));

            if is_ok {
                // Success: return remaining args (skip the boolean/true first arg)
                let rest: Vec<mlua::Value> = args_vec.drain(1..).collect();
                Ok(mlua::MultiValue::from_vec(rest))
            } else {
                // Failure: get error message from second arg, call catch, then throw
                let err_msg = match args_vec.get(1) {
                    Some(mlua::Value::String(s)) => s.to_string_lossy().to_string(),
                    Some(mlua::Value::Nil) => "nil error".to_string(),
                    Some(v) => format!("{v:?}"),
                    None => "no error message".to_string(),
                };

                // Call catch function if provided
                if let Some(ref catch) = catch_fn {
                    let _ = catch.call::<mlua::MultiValue>(mlua::Value::String(
                        lua.create_string(&err_msg)?,
                    ));
                }

                // Throw a RuntimeError with the error message
                // NSE scripts catch this via pcall and check the error
                Err(mlua::Error::RuntimeError(format!(
                    "nmap.new_try: {err_msg}"
                )))
            }
        })
    })?;
    nmap_table.set("new_try", new_try_fn)?;

    // Register set_port_state(host, port, state) function
    // NSE scripts call this to change the port state (e.g., from "open|filtered" to "open")
    // In our implementation, this is a no-op since port states are determined by the scan engine
    let set_port_state_fn = lua.create_function(
        |_, (_host, _port, _state): (mlua::Value, mlua::Value, mlua::Value)| {
            // Port state changes from scripts are acknowledged but not applied
            // The actual port state is managed by the scan engine
            Ok(())
        },
    )?;
    nmap_table.set("set_port_state", set_port_state_fn)?;

    // Register set_port_version(host, port, probestate) function
    // NSE scripts call this to update service version info on a port.
    // The port table's version fields (name, product, version, etc.) are modified
    // directly by the script before calling this. In nmap, this commits those
    // changes to the internal service database. In our implementation, the version
    // info is already captured from the port table when scripts complete.
    let set_port_version_fn = lua.create_function(
        |_, (_host, _port, _probestate): (mlua::Value, mlua::Value, mlua::Value)| Ok(()),
    )?;
    nmap_table.set("set_port_version", set_port_version_fn)?;

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
    /// Protocol hint from `new_socket()`
    proto_hint: Option<String>,
    /// Requested local bind address from `socket:bind()`
    bind_addr: Option<std::net::SocketAddr>,
    /// Listen backlog size
    backlog: i32,
    /// Socket timeout in milliseconds
    timeout: u64,
    /// Internal buffer for `receive_buf` delimiter matching
    buffer: Vec<u8>,
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
        #[expect(dead_code, reason = "stored for future protocol-specific behavior")]
        proto: String,
        /// TCP stream for send/receive operations (None if using SSL)
        stream: Option<std::net::TcpStream>,
        /// Whether this connection uses SSL
        is_ssl: bool,
    },
    /// UDP socket bound to remote address
    ConnectedUdp {
        /// Remote address
        addr: std::net::SocketAddr,
        /// UDP socket
        socket: std::net::UdpSocket,
    },
    /// Socket is listening for connections
    Listening {
        /// Local address
        addr: std::net::SocketAddr,
        /// Protocol
        proto: String,
    },
}

/// Convert X509 certificate to NSE-compatible Lua table.
///
/// Delegates to [`super::ssl::build_cert_table`] for consistent certificate table
/// construction across all code paths (including ecdhparams for EC keys).
#[cfg(feature = "openssl")]
fn cert_to_table(lua: &mlua::Lua, cert: &X509) -> mlua::Result<mlua::Table> {
    super::ssl::build_cert_table(lua, cert)
}

impl NseSocket {
    /// Create a new unconnected socket.
    fn new(proto_hint: Option<String>) -> Self {
        Self {
            state: SocketState::Disconnected,
            proto_hint,
            bind_addr: None,
            backlog: 128,
            timeout: 10_000,
            buffer: Vec::new(),
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
    #[allow(
        dead_code,
        reason = "Reserved for future SSL/TLS read/write operations"
    )]
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
    #[allow(
        dead_code,
        reason = "Reserved for future SSL/TLS read/write operations"
    )]
    #[must_use]
    fn get_ssl_stream(&self) -> Option<&openssl::ssl::SslStream<std::net::TcpStream>> {
        self.ssl_stream.as_ref()
    }

    /// Get a mutable reference to the SSL stream if connected via SSL.
    #[cfg(feature = "openssl")]
    #[allow(
        dead_code,
        reason = "Reserved for future SSL/TLS read/write operations"
    )]
    fn get_ssl_stream_mut(&mut self) -> Option<&mut openssl::ssl::SslStream<std::net::TcpStream>> {
        self.ssl_stream.as_mut()
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::items_after_statements,
    reason = "UserData impl requires many method registrations; inner helpers after let statements"
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
            // Also extract targetname for SSL SNI (Server Name Indication)
            let (host, ssl_sni) = match &args_vec[0] {
                mlua::Value::String(s) => (s.to_string_lossy().to_string(), None),
                mlua::Value::Table(t) => {
                    // Get IP from table
                    let ip: mlua::String = t.get("ip").map_err(|_e| {
                        mlua::Error::RuntimeError("Missing 'ip' field in host table".to_string())
                    })?;
                    let ip_str = ip.to_string_lossy().to_string();
                    // Get targetname for SNI (SSL connections need hostname, not IP)
                    let sni: Option<String> = t
                        .get::<Option<mlua::String>>("targetname")
                        .ok()
                        .flatten()
                        .map(|s| s.to_string_lossy().to_string());
                    (ip_str, sni)
                }
                _ => {
                    return Err(mlua::Error::RuntimeError(
                        "Host must be string or table".to_string(),
                    ))
                }
            };

            // Extract port (can be number or port table with .number field)
            // Also extract protocol from port table if present
            let mut port_proto: Option<String> = None;
            let port = match &args_vec[1] {
                mlua::Value::Integer(n) => u16::try_from(*n)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Port out of range: {e}")))?,
                mlua::Value::Number(n) =>
                {
                    #[expect(clippy::cast_possible_truncation, reason = "try_from validates range")]
                    u16::try_from(*n as i64)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Port out of range: {e}")))?
                }
                mlua::Value::String(s) => {
                    let s = s.to_string_lossy();
                    s.parse::<u16>().map_err(|e| {
                        mlua::Error::RuntimeError(format!("Port string parse error: {e}"))
                    })?
                }
                mlua::Value::Table(t) => {
                    // Extract protocol from port table (e.g., "udp", "tcp")
                    if let Ok(Some(proto_str)) = t.get::<Option<mlua::String>>("protocol") {
                        port_proto = Some(proto_str.to_string_lossy().to_string());
                    }
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

            // Proto is optional 3rd argument, or from port table, or proto_hint from new_socket()
            let proto = if args_vec.len() > 2 {
                match &args_vec[2] {
                    mlua::Value::String(s) => s.to_string_lossy().to_string(),
                    _ => port_proto
                        .or(this.proto_hint.clone())
                        .unwrap_or_else(|| "tcp".to_string()),
                }
            } else {
                port_proto
                    .or(this.proto_hint.clone())
                    .unwrap_or_else(|| "tcp".to_string())
            };

            let addr = format!("{host}:{port}");
            match addr.parse::<std::net::SocketAddr>() {
                Ok(socket_addr) => {
                    // Handle UDP protocol
                    if proto == "udp" {
                        let bind_addr = this.bind_addr.take();
                        let result = tokio::task::block_in_place(|| {
                            let local_bind = bind_addr
                                .map_or_else(|| "0.0.0.0:0".to_string(), |a| a.to_string());
                            let socket = std::net::UdpSocket::bind(local_bind)?;
                            socket.set_nonblocking(false)?;
                            socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
                            socket.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
                            // For UDP, connect() just sets the default destination
                            let _ = socket.connect(socket_addr);
                            Ok::<_, std::io::Error>(socket)
                        });

                        let udp_socket = result.map_err(|e| {
                            mlua::Error::RuntimeError(format!("UDP socket creation failed: {e}"))
                        })?;

                        this.state = SocketState::ConnectedUdp {
                            addr: socket_addr,
                            socket: udp_socket,
                        };

                        return Ok(true);
                    }

                    // Check if this is an SSL connection
                    let is_ssl = proto == "ssl";

                    // Connect with optional source port binding
                    let bind_addr = this.bind_addr.take();
                    let result = tokio::task::block_in_place(|| {
                        if let Some(local_addr) = bind_addr {
                            // Use socket2 for bind-then-connect
                            let domain = if socket_addr.is_ipv4() {
                                socket2::Domain::IPV4
                            } else {
                                socket2::Domain::IPV6
                            };
                            let sock = socket2::Socket::new(
                                domain,
                                socket2::Type::STREAM,
                                Some(socket2::Protocol::TCP),
                            )?;
                            sock.set_reuse_address(true)?;
                            sock.bind(&local_addr.into())?;
                            sock.connect_timeout(
                                &socket_addr.into(),
                                std::time::Duration::from_secs(30),
                            )?;
                            Ok(std::net::TcpStream::from(sock))
                        } else {
                            std::net::TcpStream::connect_timeout(
                                &socket_addr,
                                std::time::Duration::from_secs(30),
                            )
                        }
                    });

                    let stream = result
                        .map_err(|e| mlua::Error::RuntimeError(format!("Connect failed: {e}")))?;

                    // Perform SSL handshake if requested
                    #[cfg(feature = "openssl")]
                    if is_ssl {
                        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

                        // Create SSL connector with certificate verification disabled
                        // (Nmap doesn't verify certificates during scanning)
                        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| {
                            mlua::Error::RuntimeError(format!(
                                "Failed to create SSL connector: {e}"
                            ))
                        })?;
                        builder.set_verify(SslVerifyMode::NONE);
                        let connector = builder.build();

                        // Perform SSL handshake using connector's connect method
                        // Use targetname for SNI if available, otherwise fall back to IP
                        let ssl_hostname = ssl_sni.as_deref().unwrap_or(&host);
                        let ssl_stream =
                            tokio::task::block_in_place(|| connector.connect(ssl_hostname, stream))
                                .map_err(|e| {
                                    mlua::Error::RuntimeError(format!("SSL handshake failed: {e}"))
                                })?;

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
        methods.add_method_mut("bind", |_, this, (host, port): (mlua::Value, u16)| {
            let host_str = match host {
                mlua::Value::String(s) => s.to_string_lossy().to_string(),
                _ => "0.0.0.0".to_string(),
            };
            let addr_str = format!("{host_str}:{port}");
            match addr_str.parse::<std::net::SocketAddr>() {
                Ok(socket_addr) => {
                    this.bind_addr = Some(socket_addr);
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
                            let mut accepted_socket = NseSocket::new(None);
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
            // Returns: (true, lhost, lport, rhost, rport) or (false, err_msg)
            match &this.state {
                SocketState::Connected { addr, stream, .. } => {
                    let rhost = lua.create_string(addr.ip().to_string().as_str())?;
                    let rport = addr.port();
                    let (lhost, lport) = if let Some(s) = stream {
                        match s.local_addr() {
                            Ok(local) => (local.ip().to_string(), local.port()),
                            Err(_) => ("0.0.0.0".to_string(), 0),
                        }
                    } else {
                        #[cfg(feature = "openssl")]
                        {
                            if let Some(ssl) = &this.ssl_stream {
                                match ssl.get_ref().local_addr() {
                                    Ok(local) => (local.ip().to_string(), local.port()),
                                    Err(_) => ("0.0.0.0".to_string(), 0),
                                }
                            } else {
                                ("0.0.0.0".to_string(), 0)
                            }
                        }
                        #[cfg(not(feature = "openssl"))]
                        {
                            ("0.0.0.0".to_string(), 0)
                        }
                    };
                    let lhost_str = lua.create_string(lhost.as_str())?;
                    Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Boolean(true),
                        mlua::Value::String(lhost_str),
                        mlua::Value::Integer(i64::from(lport)),
                        mlua::Value::String(rhost),
                        mlua::Value::Integer(i64::from(rport)),
                    ]))
                }
                SocketState::ConnectedUdp { addr, socket } => {
                    let rhost = lua.create_string(addr.ip().to_string().as_str())?;
                    let rport = addr.port();
                    let (lhost, lport) = match socket.local_addr() {
                        Ok(local) => (local.ip().to_string(), local.port()),
                        Err(_) => ("0.0.0.0".to_string(), 0),
                    };
                    let lhost_str = lua.create_string(lhost.as_str())?;
                    Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Boolean(true),
                        mlua::Value::String(lhost_str),
                        mlua::Value::Integer(i64::from(lport)),
                        mlua::Value::String(rhost),
                        mlua::Value::Integer(i64::from(rport)),
                    ]))
                }
                _ => {
                    let err = lua.create_string("Not connected")?;
                    Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Boolean(false),
                        mlua::Value::String(err),
                    ]))
                }
            }
        });

        // Set socket timeout in milliseconds
        methods.add_method_mut("set_timeout", |_, this, timeout_ms: u64| {
            this.set_timeout(timeout_ms);
            Ok(())
        });

        // Send data to the socket
        // Returns: (true, bytes_sent) on success, (nil, error_msg) on failure
        methods.add_method_mut("send", |lua, this, data: mlua::String| {
            let bytes = data.as_bytes();
            let byte_count = bytes.len();

            // Handle UDP socket
            if let SocketState::ConnectedUdp { socket, .. } = &this.state {
                return match socket.send(&bytes) {
                    Ok(n) => Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Boolean(true),
                        mlua::Value::Integer(i64::try_from(n).unwrap_or(i64::MAX)),
                    ])),
                    Err(e) => {
                        let err_str = lua.create_string(format!("UDP send failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                };
            }

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                return match std::io::Write::write_all(ssl_stream, &bytes) {
                    Ok(()) => Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Boolean(true),
                        mlua::Value::Integer(i64::try_from(byte_count).unwrap_or(i64::MAX)),
                    ])),
                    Err(e) => {
                        let err_str = lua.create_string(format!("SSL send failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                };
            }

            let stream = match this.get_stream_mut() {
                Ok(s) => s,
                Err(e) => {
                    let err_str = lua.create_string(e.to_string())?;
                    return Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Nil,
                        mlua::Value::String(err_str),
                    ]));
                }
            };
            match stream.write_all(&bytes) {
                Ok(()) => Ok(mlua::MultiValue::from_vec(vec![
                    mlua::Value::Boolean(true),
                    mlua::Value::Integer(i64::try_from(byte_count).unwrap_or(i64::MAX)),
                ])),
                Err(e) => {
                    let err_str = lua.create_string(format!("Send failed: {e}"))?;
                    Ok(mlua::MultiValue::from_vec(vec![
                        mlua::Value::Nil,
                        mlua::Value::String(err_str),
                    ]))
                }
            }
        });

        // Send a UDP datagram to a specific host:port without prior connect()
        // Signature: sendto(host, port, data)
        // If socket is Disconnected, creates a UDP socket first.
        // If socket is already ConnectedUdp, uses send_to on the existing socket.
        // Returns: (true, nil) on success, (nil, error_msg) on failure
        methods.add_method_mut(
            "sendto",
            |lua, this, (host, port, data): (mlua::Value, mlua::Value, mlua::String)| {
                // Extract host string
                let host_str = match &host {
                    mlua::Value::String(s) => s.to_string_lossy().to_string(),
                    mlua::Value::Table(t) => {
                        let ip: mlua::String = t.get("ip").map_err(|_e| {
                            mlua::Error::RuntimeError(
                                "Missing 'ip' field in host table".to_string(),
                            )
                        })?;
                        ip.to_string_lossy().to_string()
                    }
                    _ => {
                        return Err(mlua::Error::RuntimeError(
                            "sendto: host must be string or table".to_string(),
                        ))
                    }
                };

                // Extract port number
                let port_num = match &port {
                    mlua::Value::Integer(n) => u16::try_from(*n).map_err(|e| {
                        mlua::Error::RuntimeError(format!("sendto: port out of range: {e}"))
                    })?,
                    mlua::Value::Number(n) =>
                    {
                        #[expect(
                            clippy::cast_possible_truncation,
                            reason = "try_from validates range"
                        )]
                        u16::try_from(*n as i64).map_err(|e| {
                            mlua::Error::RuntimeError(format!("sendto: port out of range: {e}"))
                        })?
                    }
                    mlua::Value::String(s) => {
                        let s = s.to_string_lossy();
                        s.parse::<u16>().map_err(|e| {
                            mlua::Error::RuntimeError(format!("sendto: port string parse error: {e}"))
                        })?
                    }
                    mlua::Value::Table(t) => {
                        let port_val: mlua::Value = t.get("number").map_err(|_e| {
                            mlua::Error::RuntimeError(
                                "sendto: port table missing 'number' field".to_string(),
                            )
                        })?;
                        match port_val {
                            mlua::Value::Integer(n) => u16::try_from(n).map_err(|e| {
                                mlua::Error::RuntimeError(format!("sendto: port out of range: {e}"))
                            })?,
                            mlua::Value::Number(n) =>
                            {
                                #[expect(
                                    clippy::cast_possible_truncation,
                                    reason = "try_from validates range"
                                )]
                                u16::try_from(n as i64).map_err(|e| {
                                    mlua::Error::RuntimeError(format!(
                                        "sendto: port out of range: {e}"
                                    ))
                                })?
                            }
                            _ => {
                                return Err(mlua::Error::RuntimeError(
                                    "sendto: port.number must be a number".to_string(),
                                ))
                            }
                        }
                    }
                    _ => {
                        return Err(mlua::Error::RuntimeError(
                            "sendto: port must be a number or table".to_string(),
                        ))
                    }
                };

                let dest_addr_str = format!("{host_str}:{port_num}");
                let dest_addr: std::net::SocketAddr =
                    dest_addr_str
                        .parse()
                        .map_err(|e: std::net::AddrParseError| {
                            mlua::Error::RuntimeError(format!("sendto: invalid address: {e}"))
                        })?;

                let bytes = data.as_bytes();

                // Get or create UDP socket
                match &this.state {
                    SocketState::ConnectedUdp { socket, .. } => {
                        match socket.send_to(&bytes, dest_addr) {
                            Ok(_n) => Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Boolean(true),
                                mlua::Value::Nil,
                            ])),
                            Err(e) => {
                                let err_str =
                                    lua.create_string(format!("sendto: UDP send failed: {e}"))?;
                                Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Nil,
                                    mlua::Value::String(err_str),
                                ]))
                            }
                        }
                    }
                    SocketState::Disconnected => {
                        // Create a new UDP socket for sendto
                        let bind_str = if dest_addr.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        };
                        let socket = std::net::UdpSocket::bind(bind_str).map_err(|e| {
                            mlua::Error::RuntimeError(format!(
                                "sendto: UDP socket bind failed: {e}"
                            ))
                        })?;
                        socket.set_nonblocking(false).map_err(|e| {
                            mlua::Error::RuntimeError(format!(
                                "sendto: set_nonblocking failed: {e}"
                            ))
                        })?;
                        let timeout_dur = std::time::Duration::from_millis(this.timeout());
                        let _ = socket.set_read_timeout(Some(timeout_dur));
                        let _ = socket.set_write_timeout(Some(timeout_dur));

                        let send_result = socket.send_to(&bytes, dest_addr);
                        // Transition state so subsequent receive() calls work
                        this.state = SocketState::ConnectedUdp {
                            addr: dest_addr,
                            socket,
                        };

                        match send_result {
                            Ok(_n) => Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Boolean(true),
                                mlua::Value::Nil,
                            ])),
                            Err(e) => {
                                let err_str =
                                    lua.create_string(format!("sendto: UDP send failed: {e}"))?;
                                Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Nil,
                                    mlua::Value::String(err_str),
                                ]))
                            }
                        }
                    }
                    SocketState::Connected { .. } => {
                        // For TCP, sendto delegates to regular send on the connected stream
                        #[cfg(feature = "openssl")]
                        if let Some(ssl) = &mut this.ssl_stream {
                            return match std::io::Write::write_all(ssl, &bytes) {
                                Ok(()) => Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Boolean(true),
                                    mlua::Value::Nil,
                                ])),
                                Err(e) => {
                                    let err_str =
                                        lua.create_string(format!("sendto: SSL send failed: {e}"))?;
                                    Ok(mlua::MultiValue::from_vec(vec![
                                        mlua::Value::Nil,
                                        mlua::Value::String(err_str),
                                    ]))
                                }
                            };
                        }

                        if let SocketState::Connected {
                            stream: Some(s), ..
                        } = &mut this.state
                        {
                            match std::io::Write::write_all(s, &bytes) {
                                Ok(()) => Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Boolean(true),
                                    mlua::Value::Nil,
                                ])),
                                Err(e) => {
                                    let err_str =
                                        lua.create_string(format!("sendto: TCP send failed: {e}"))?;
                                    Ok(mlua::MultiValue::from_vec(vec![
                                        mlua::Value::Nil,
                                        mlua::Value::String(err_str),
                                    ]))
                                }
                            }
                        } else {
                            let err_str = lua.create_string("sendto: no stream available")?;
                            Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Nil,
                                mlua::Value::String(err_str),
                            ]))
                        }
                    }
                    SocketState::Listening { .. } => {
                        let err_str = lua.create_string("sendto: socket is in listening state")?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                }
            },
        );

        // Receive data with pattern matching (bytes, or all)
        // Pattern can be: "a" = all, number = exact bytes
        // Receive data with pattern matching
        // Returns: (true, data) on success, (nil, err_msg) on failure
        // Pattern can be: "a" = all, number = exact bytes, 0 = all
        methods.add_method_mut("receive", |lua, this, pattern: mlua::Value| {
            // Handle UDP socket
            if let SocketState::ConnectedUdp { socket, .. } = &this.state {
                let timeout_dur = std::time::Duration::from_millis(this.timeout());
                let _ = socket.set_read_timeout(Some(timeout_dur));
                let mut buf = vec![0u8; 65536];
                return match socket.recv(&mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        let s = lua.create_string(&buf)?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(s),
                        ]))
                    }
                    Err(e) => {
                        let err_str = lua.create_string(format!("UDP receive failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                };
            }

            /// Read all data from a Read trait object, return (true, data) or (nil, err)
            fn read_all<R: Read>(lua: &mlua::Lua, mut reader: R) -> mlua::Result<mlua::MultiValue> {
                let mut buf = Vec::new();
                match reader.read_to_end(&mut buf) {
                    Ok(_) => {
                        let s = lua.create_string(&*String::from_utf8_lossy(&buf))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(s),
                        ]))
                    }
                    Err(e) => {
                        let err_str = lua.create_string(format!("Receive failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                }
            }

            /// Helper: read exact N bytes, return (true, data) or (nil, err)
            fn read_exact<R: Read>(
                lua: &mlua::Lua,
                mut reader: R,
                n: usize,
            ) -> mlua::Result<mlua::MultiValue> {
                let mut buf = vec![0u8; n];
                match reader.read_exact(&mut buf) {
                    Ok(()) => {
                        let s = lua.create_string(&*String::from_utf8_lossy(&buf))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(s),
                        ]))
                    }
                    Err(e) => {
                        let err_str = lua.create_string(format!("Receive failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]))
                    }
                }
            }

            let timeout_ms = this.timeout();
            let timeout_dur = std::time::Duration::from_millis(timeout_ms);

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                ssl_stream
                    .get_ref()
                    .set_read_timeout(Some(timeout_dur))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

                return match pattern {
                    mlua::Value::String(s) if s.to_string_lossy() == "a" => {
                        read_all(lua, ssl_stream)
                    }
                    mlua::Value::Integer(n) if n > 0 => {
                        read_exact(lua, ssl_stream, usize::try_from(n).unwrap_or(usize::MAX))
                    }
                    mlua::Value::Integer(0) => read_all(lua, ssl_stream),
                    mlua::Value::Nil => {
                        let mut buf = vec![0u8; 8192];
                        match ssl_stream.read(&mut buf) {
                            Ok(0) => {
                                let err_str = lua.create_string("EOF")?;
                                Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Nil,
                                    mlua::Value::String(err_str),
                                ]))
                            }
                            Ok(n) => {
                                buf.truncate(n);
                                let s = lua.create_string(&buf)?;
                                Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Boolean(true),
                                    mlua::Value::String(s),
                                ]))
                            }
                            Err(e) => {
                                let err_str = lua.create_string(format!("Receive failed: {e}"))?;
                                Ok(mlua::MultiValue::from_vec(vec![
                                    mlua::Value::Nil,
                                    mlua::Value::String(err_str),
                                ]))
                            }
                        }
                    }
                    _ => Err(mlua::Error::RuntimeError(
                        "Invalid receive pattern".to_string(),
                    )),
                };
            }

            let stream = this
                .get_stream_mut()
                .map_err(|e| mlua::Error::RuntimeError(format!("Socket not connected: {e}")))?;
            stream
                .set_read_timeout(Some(timeout_dur))
                .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;

            match pattern {
                mlua::Value::String(s) if s.to_string_lossy() == "a" => read_all(lua, stream),
                mlua::Value::Integer(n) if n > 0 => {
                    read_exact(lua, stream, usize::try_from(n).unwrap_or(usize::MAX))
                }
                mlua::Value::Integer(0) => read_all(lua, stream),
                // Default (nil or no pattern): read whatever is available in the buffer
                mlua::Value::Nil => {
                    let mut buf = vec![0u8; 8192];
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            let err_str = lua.create_string("EOF")?;
                            Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Nil,
                                mlua::Value::String(err_str),
                            ]))
                        }
                        Ok(n) => {
                            buf.truncate(n);
                            let s = lua.create_string(&buf)?;
                            Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Boolean(true),
                                mlua::Value::String(s),
                            ]))
                        }
                        Err(e) => {
                            let err_str = lua.create_string(format!("Receive failed: {e}"))?;
                            Ok(mlua::MultiValue::from_vec(vec![
                                mlua::Value::Nil,
                                mlua::Value::String(err_str),
                            ]))
                        }
                    }
                }
                _ => Err(mlua::Error::RuntimeError(
                    "Invalid receive pattern".to_string(),
                )),
            }
        });

        // Receive exactly N bytes.
        // Returns: (true, data) on success, (nil, err_msg, partial_data) on failure.
        // Respects the internal buffer: consumes data from `this.buffer` first,
        // then reads remaining bytes from the stream.
        methods.add_method_mut("receive_bytes", |lua, this, n: usize| {
            // Handle UDP socket - return full datagram (UDP is message-oriented)
            if let SocketState::ConnectedUdp { socket, .. } = &this.state {
                let timeout_dur = std::time::Duration::from_millis(this.timeout());
                let _ = socket.set_read_timeout(Some(timeout_dur));
                let mut buf = vec![0u8; 65536];
                return match socket.recv(&mut buf) {
                    Ok(recv_n) => {
                        buf.truncate(recv_n);
                        let s = lua.create_string(&buf)?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(s),
                        ]))
                    }
                    Err(e) => {
                        let err_str = lua.create_string(format!("UDP receive failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                            mlua::Value::String(lua.create_string("")?),
                        ]))
                    }
                };
            }

            /// Read at least 1 byte, up to n bytes from a reader.
            /// Returns as soon as any data is available (nmap behavior).
            fn read_from_stream<R: Read>(
                lua: &mlua::Lua,
                mut reader: R,
                n: usize,
            ) -> mlua::Result<mlua::MultiValue> {
                let mut buf = vec![0u8; n];
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let err_str = lua.create_string("EOF")?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                            mlua::Value::String(lua.create_string("")?),
                        ]))
                    }
                    Ok(count) => {
                        buf.truncate(count);
                        let s = lua.create_string(&buf)?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(s),
                        ]))
                    }
                    Err(e) => {
                        let err_str = lua.create_string(format!("Receive failed: {e}"))?;
                        Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                            mlua::Value::String(lua.create_string("")?),
                        ]))
                    }
                }
            }

            // Step 1: consume from internal buffer first
            let buffered = this.buffer.len();
            if buffered > 0 {
                let take_n = buffered.min(n);
                let chunk = this.buffer[..take_n].to_vec();
                this.buffer = this.buffer[take_n..].to_vec();
                let s = lua.create_string(&chunk)?;
                return Ok(mlua::MultiValue::from_vec(vec![
                    mlua::Value::Boolean(true),
                    mlua::Value::String(s),
                ]));
            }

            // Step 2: read from stream (return as soon as any data available)
            let timeout_ms = this.timeout();
            let timeout_dur = std::time::Duration::from_millis(timeout_ms);

            #[cfg(feature = "openssl")]
            if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                ssl_stream
                    .get_ref()
                    .set_read_timeout(Some(timeout_dur))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;
                return read_from_stream(lua, ssl_stream, n);
            }

            let stream = this
                .get_stream_mut()
                .map_err(|e| mlua::Error::RuntimeError(format!("Socket not connected: {e}")))?;
            stream
                .set_read_timeout(Some(timeout_dur))
                .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;
            read_from_stream(lua, stream, n)
        });

        // Buffered receive with delimiter matching.
        // Signature: sock:receive_buf(delimiter, keeppattern)
        // - delimiter: string pattern or function (e.g., match.numbytes(n))
        // - keeppattern: boolean, if true include delimiter in returned data
        // Returns: (true, data) on match, (nil, err_msg) on error
        // Maintains internal buffer across calls for delimiter matching.
        methods.add_method_mut(
            "receive_buf",
            |lua, this, (delimiter, keeppattern): (mlua::Value, bool)| {
                let timeout_ms = this.timeout();
                let timeout_dur = std::time::Duration::from_millis(timeout_ms);

                // Check the internal buffer for a delimiter match
                // Returns Some((extracted_bytes, remaining_bytes)) on match, None on no match
                fn check_delimiter(
                    lua: &mlua::Lua,
                    buf: &[u8],
                    delimiter: &mlua::Value,
                ) -> mlua::Result<Option<(Vec<u8>, Vec<u8>)>> {
                    match delimiter {
                        mlua::Value::Function(func) => {
                            // Function delimiter: call with buffer as binary string
                            let buf_lua_str = lua.create_string(buf)?;
                            let result: mlua::MultiValue =
                                func.call(mlua::Value::String(buf_lua_str))?;
                            let vals: Vec<mlua::Value> = result.into_iter().collect();
                            if vals.len() >= 2 {
                                let left = match &vals[0] {
                                    mlua::Value::Integer(n) => usize::try_from(*n).unwrap_or(0),
                                    mlua::Value::Number(n) => {
                                        #[expect(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_sign_loss,
                                            reason = "value from Lua, clamped to usize range"
                                        )]
                                        let v = *n as usize;
                                        v
                                    }
                                    _ => return Ok(None),
                                };
                                let right = match &vals[1] {
                                    mlua::Value::Integer(n) => usize::try_from(*n).unwrap_or(0),
                                    mlua::Value::Number(n) => {
                                        #[expect(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_sign_loss,
                                            reason = "value from Lua, clamped to usize range"
                                        )]
                                        let v = *n as usize;
                                        v
                                    }
                                    _ => return Ok(None),
                                };
                                if left > 0 && right > 0 && right <= buf.len() {
                                    return Ok(Some((
                                        buf[..right].to_vec(),
                                        buf[right..].to_vec(),
                                    )));
                                }
                            }
                            Ok(None)
                        }
                        mlua::Value::String(pattern) => {
                            // String delimiter: use Lua pattern matching via string.find
                            // Nmap's receive_buf uses Lua patterns (e.g., "\r?\n") not
                            // literal strings. We delegate to string.find for correctness.
                            let buf_lua_str = lua.create_string(buf)?;
                            let string_lib: mlua::Table = lua.globals().get("string")?;
                            let find_fn: mlua::Function = string_lib.get("find")?;

                            // string.find(buffer, pattern, init, plain=false)
                            let result: mlua::MultiValue = find_fn.call((
                                mlua::Value::String(buf_lua_str),
                                mlua::Value::String(pattern.clone()),
                                1,     // start from position 1 (Lua 1-indexed)
                                false, // plain = false (enable pattern matching)
                            ))?;

                            let vals: Vec<mlua::Value> = result.into_iter().collect();
                            // string.find returns nil if no match, or (start, end) on match
                            if vals.len() >= 2 {
                                let start = match &vals[0] {
                                    mlua::Value::Integer(n) => usize::try_from(*n).unwrap_or(0),
                                    mlua::Value::Number(n) => {
                                        #[expect(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_sign_loss,
                                            reason = "value from Lua, clamped to usize range"
                                        )]
                                        let v = *n as usize;
                                        v
                                    }
                                    _ => return Ok(None),
                                };
                                let end_pos = match &vals[1] {
                                    mlua::Value::Integer(n) => usize::try_from(*n).unwrap_or(0),
                                    mlua::Value::Number(n) => {
                                        #[expect(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_sign_loss,
                                            reason = "value from Lua, clamped to usize range"
                                        )]
                                        let v = *n as usize;
                                        v
                                    }
                                    _ => return Ok(None),
                                };
                                // Lua string.find uses 1-based indices, convert to 0-based
                                if start > 0 && end_pos > 0 && end_pos <= buf.len() {
                                    return Ok(Some((
                                        buf[..end_pos].to_vec(),
                                        buf[end_pos..].to_vec(),
                                    )));
                                }
                            }
                            Ok(None)
                        }
                        _ => Err(mlua::Error::RuntimeError(
                            "Delimiter must be a string or function".to_string(),
                        )),
                    }
                }

                // Read from the underlying stream into the socket's internal buffer
                fn read_into_buffer(
                    this: &mut NseSocket,
                    timeout_dur: std::time::Duration,
                ) -> mlua::Result<()> {
                    let mut tmp = [0u8; 8192];

                    #[cfg(feature = "openssl")]
                    if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                        ssl_stream
                            .get_ref()
                            .set_read_timeout(Some(timeout_dur))
                            .map_err(|e| {
                                mlua::Error::RuntimeError(format!("Set timeout failed: {e}"))
                            })?;
                        let count = ssl_stream.read(&mut tmp).map_err(|e| {
                            mlua::Error::RuntimeError(format!("Receive failed: {e}"))
                        })?;
                        if count == 0 {
                            return Err(mlua::Error::RuntimeError("EOF".to_string()));
                        }
                        this.buffer.extend_from_slice(&tmp[..count]);
                        return Ok(());
                    }

                    let stream = this.get_stream_mut().map_err(|e| {
                        mlua::Error::RuntimeError(format!("Socket not connected: {e}"))
                    })?;
                    stream.set_read_timeout(Some(timeout_dur)).map_err(|e| {
                        mlua::Error::RuntimeError(format!("Set timeout failed: {e}"))
                    })?;
                    let count = stream
                        .read(&mut tmp)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                    if count == 0 {
                        return Err(mlua::Error::RuntimeError("EOF".to_string()));
                    }
                    this.buffer.extend_from_slice(&tmp[..count]);
                    Ok(())
                }

                // Main loop: check delimiter, if no match read more data and retry
                // Limit iterations to prevent infinite loops on bad delimiters
                for _ in 0..1000 {
                    if let Some((matched, remaining)) =
                        check_delimiter(lua, &this.buffer, &delimiter)?
                    {
                        let extracted = if keeppattern {
                            matched
                        } else {
                            // keeppattern=false: for function delimiters, return data up to
                            // left-1 (exclusive). For string delimiters, exclude the pattern.
                            match &delimiter {
                                mlua::Value::Function(func) => {
                                    let buf_lua_str = lua.create_string(&matched)?;
                                    let result: mlua::MultiValue =
                                        func.call(mlua::Value::String(buf_lua_str))?;
                                    let vals: Vec<mlua::Value> = result.into_iter().collect();
                                    let left = match vals.first() {
                                        Some(mlua::Value::Integer(n)) => {
                                            usize::try_from(*n).unwrap_or(0)
                                        }
                                        Some(mlua::Value::Number(n)) => {
                                            #[expect(
                                                clippy::cast_possible_truncation,
                                                clippy::cast_sign_loss,
                                                reason = "value from Lua, clamped to usize range"
                                            )]
                                            let v = *n as usize;
                                            v
                                        }
                                        _ => matched.len(),
                                    };
                                    if left > 0 && left <= matched.len() {
                                        matched[..left.saturating_sub(1)].to_vec()
                                    } else {
                                        matched
                                    }
                                }
                                mlua::Value::String(pattern) => {
                                    let pat = pattern.as_bytes().to_vec();
                                    if let Some(pos) =
                                        matched.windows(pat.len()).position(|w| w == pat.as_slice())
                                    {
                                        matched[..pos].to_vec()
                                    } else {
                                        matched
                                    }
                                }
                                _ => matched,
                            }
                        };
                        this.buffer = remaining;
                        // Return raw binary data as Lua string (not UTF-8 lossy)
                        let data_str = lua.create_string(&extracted)?;
                        return Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Boolean(true),
                            mlua::Value::String(data_str),
                        ]));
                    }

                    // No delimiter match -- read more data from the stream
                    if let Err(e) = read_into_buffer(this, timeout_dur) {
                        let err_str = lua.create_string(e.to_string())?;
                        return Ok(mlua::MultiValue::from_vec(vec![
                            mlua::Value::Nil,
                            mlua::Value::String(err_str),
                        ]));
                    }
                }

                let err_str = lua.create_string("receive_buf: too many iterations")?;
                Ok(mlua::MultiValue::from_vec(vec![
                    mlua::Value::Nil,
                    mlua::Value::String(err_str),
                ]))
            },
        );

        // Receive exactly n lines from socket.
        // Signature: sock:receive_lines(n)
        // - n: number of lines to read (each terminated by \r\n or \n)
        // Returns: (true, data) on success, (nil, err_msg) on failure
        methods.add_method_mut("receive_lines", |lua, this, n: usize| {
            let timeout_ms = this.timeout();
            let timeout_dur = std::time::Duration::from_millis(timeout_ms);

            let mut lines_read = 0usize;
            let mut result = Vec::new();
            let mut tmp = [0u8; 8192];

            while lines_read < n {
                // Check existing buffer first for any newline-terminated lines
                while lines_read < n {
                    // Find \r\n or \n in buffer
                    let buf_str = String::from_utf8_lossy(&this.buffer);
                    let line_end = buf_str
                        .find("\r\n")
                        .map(|pos| pos + 2)
                        .or_else(|| buf_str.find('\n').map(|pos| pos + 1));

                    if let Some(end) = line_end {
                        result.extend_from_slice(&this.buffer[..end]);
                        this.buffer = this.buffer[end..].to_vec();
                        lines_read += 1;
                    } else {
                        break;
                    }
                }

                if lines_read >= n {
                    break;
                }

                // Need more data from stream
                #[cfg(feature = "openssl")]
                if let Some(ssl_stream) = this.get_ssl_stream_mut() {
                    ssl_stream
                        .get_ref()
                        .set_read_timeout(Some(timeout_dur))
                        .map_err(|e| {
                            mlua::Error::RuntimeError(format!("Set timeout failed: {e}"))
                        })?;
                    let count = ssl_stream
                        .read(&mut tmp)
                        .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                    if count == 0 {
                        break; // EOF
                    }
                    this.buffer.extend_from_slice(&tmp[..count]);
                    continue;
                }

                let stream = this
                    .get_stream_mut()
                    .map_err(|e| mlua::Error::RuntimeError(format!("Socket not connected: {e}")))?;
                stream
                    .set_read_timeout(Some(timeout_dur))
                    .map_err(|e| mlua::Error::RuntimeError(format!("Set timeout failed: {e}")))?;
                let count = stream
                    .read(&mut tmp)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Receive failed: {e}")))?;
                if count == 0 {
                    break; // EOF
                }
                this.buffer.extend_from_slice(&tmp[..count]);
            }

            if result.is_empty() {
                let err_str = lua.create_string("EOF")?;
                return Ok(mlua::MultiValue::from_vec(vec![
                    mlua::Value::Nil,
                    mlua::Value::String(err_str),
                ]));
            }

            let s = lua.create_string(&*String::from_utf8_lossy(&result))?;
            Ok(mlua::MultiValue::from_vec(vec![
                mlua::Value::Boolean(true),
                mlua::Value::String(s),
            ]))
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

        // Check timing_level function returns correct value
        let timing_fn: mlua::Function = nmap.get("timing_level").unwrap();
        let timing: i64 = timing_fn.call(()).unwrap();
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
