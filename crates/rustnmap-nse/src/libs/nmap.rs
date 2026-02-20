//! Nmap base library for NSE.

#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::too_many_lines,
    reason = "NSE library implementation requires these patterns"
)]
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

use crate::error::Result;
use crate::lua::NseLua;

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
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the nmap table
    let nmap_table = lua.create_table()?;

    // Get current config
    let config = get_config_copy();

    // Create registry table (empty table that scripts can use)
    let registry = lua.create_table()?;
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

    // Set the nmap table as a global
    lua.globals().set("nmap", nmap_table)?;

    Ok(())
}

/// Log write implementation.
fn log_write_impl(level: &str, message: &str) {
    match level {
        "stdout" => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(message.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
        "stderr" => {
            use std::io::Write;
            let _ = std::io::stderr().write_all(message.as_bytes());
            let _ = std::io::stderr().write_all(b"\n");
        }
        _ => {
            // Log to appropriate channel based on level
            tracing::debug!("[{level}] {message}");
        }
    }
}

/// NSE Socket implementation for nmap.new_socket().
#[derive(Debug)]
pub struct NseSocket {
    /// Internal socket state
    state: SocketState,
}

#[derive(Debug)]
#[expect(dead_code, reason = "Listening state reserved for future use")]
enum SocketState {
    /// Socket is not connected
    Disconnected,
    /// Socket is connected to a remote host
    Connected {
        /// Remote address
        addr: std::net::SocketAddr,
        /// Protocol
        proto: String,
    },
    /// Socket is listening
    Listening,
}

impl NseSocket {
    /// Create a new unconnected socket.
    fn new() -> Self {
        Self {
            state: SocketState::Disconnected,
        }
    }
}

impl mlua::UserData for NseSocket {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        // Async connect method - uses spawn_blocking for non-blocking TCP connect
        methods.add_async_method_mut(
            "connect",
            |_, mut this, (host, port): (String, u16)| async move {
                let addr = format!("{host}:{port}");
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(socket_addr) => {
                        match tokio::task::spawn_blocking(move || {
                            std::net::TcpStream::connect_timeout(
                                &socket_addr,
                                std::time::Duration::from_secs(30),
                            )
                        })
                        .await
                        {
                            Ok(_stream) => {
                                this.state = SocketState::Connected {
                                    addr: socket_addr,
                                    proto: "tcp".to_string(),
                                };
                                Ok(true)
                            }
                            Err(e) => {
                                Err(mlua::Error::RuntimeError(format!("Connect failed: {e}")))
                            }
                        }
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Invalid address: {e}"))),
                }
            },
        );

        methods.add_method_mut("close", |_, this, ()| {
            this.state = SocketState::Disconnected;
            Ok(true)
        });

        methods.add_method("is_connected", |_, this, ()| {
            Ok(matches!(this.state, SocketState::Connected { .. }))
        });

        methods.add_method("get_info", |lua, this, ()| {
            let table = lua.create_table()?;
            if let SocketState::Connected { addr, proto } = &this.state {
                table.set("addr", addr.to_string())?;
                table.set("proto", proto.clone())?;
            } else {
                table.set("addr", mlua::Value::Nil)?;
                table.set("proto", mlua::Value::Nil)?;
            }
            Ok(table)
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
            .load("nmap.registry['test_key'] = 'test_value'")
            .exec()
            .unwrap();

        // Read the value back
        let value: String = lua
            .lua()
            .load("return nmap.registry['test_key']")
            .eval()
            .unwrap();
        assert_eq!(value, "test_value");
    }
}
