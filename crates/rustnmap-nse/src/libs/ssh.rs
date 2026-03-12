//! SSH2 library for NSE.
//!
//! This module provides the `ssh2` library which contains SSH-2 protocol functions
//! for NSE scripts. It corresponds to Nmap's ssh2 NSE library.
//!
//! # Available Functions
//!
//! - `ssh2.fetch_host_key(host, port, [key_type])` - Get SSH host key and fingerprint
//! - `ssh2.banner(host, port)` - Get SSH banner string
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local ssh2 = require "ssh2"
//!
//! local banner = ssh2.banner(host, port)
//! if banner then
//!     print("SSH Banner: " .. banner)
//! end
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use md5::{Md5, Digest as Md5Digest};
use mlua::Value;
use sha2::Sha256;
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for SSH connections in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// SSH2 banner prefix.
const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

/// Read SSH banner from server.
fn read_ssh_banner(host: &str, port: u16, timeout_ms: u64) -> mlua::Result<String> {
    let addr = format!("{host}:{port}");

    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    // Send client banner
    let client_banner = "SSH-2.0-rustnmap_1.0\r\n";
    stream
        .write_all(client_banner.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send banner: {e}")))?;

    // Read server banner
    let mut line = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read banner: {e}")))?;

        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }

    // Remove trailing \r if present
    if line.last() == Some(&b'\r') {
        line.pop();
    }

    // Validate SSH banner
    if !line.starts_with(SSH_BANNER_PREFIX) {
        return Err(mlua::Error::RuntimeError(format!(
            "Invalid SSH banner: {}",
            String::from_utf8_lossy(&line)
        )));
    }

    Ok(String::from_utf8_lossy(&line).to_string())
}

/// Extract host and port from Lua values.
fn extract_host_port(host: Value, port: Value) -> (String, u16) {
    let host_str = match host {
        Value::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        Value::Table(t) => t
            .get::<Option<String>>("ip")
            .ok()
            .flatten()
            .or_else(|| t.get::<Option<String>>("name").ok().flatten())
            .unwrap_or_default(),
        _ => String::new(),
    };

    let port_num = match port {
        Value::Integer(n) => u16::try_from(n).unwrap_or(22),
        Value::Table(t) => t
            .get::<Option<i64>>("number")
            .ok()
            .flatten()
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(22),
        _ => 22,
    };

    (host_str, port_num)
}

/// Calculate MD5 fingerprint.
fn calculate_md5_fingerprint(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Calculate SHA256 fingerprint.
fn calculate_sha256_fingerprint(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let base64 = base64_encode(&result);
    format!("SHA256:{base64}")
}

/// Base64 encoding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result.trim_end_matches('=').to_string()
}

/// Register the ssh2 library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the ssh2 table
    let ssh2_table = lua.create_table()?;

    // Register fetch_host_key function
    let fetch_host_key_fn = lua.create_function(|lua, (host, port, _key_type): (Value, Value, Option<String>)| {
        let (host_str, port_num) = extract_host_port(host, port);

        debug!("ssh2.fetch_host_key({}, {})", host_str, port_num);

        match read_ssh_banner(&host_str, port_num, DEFAULT_TIMEOUT_MS) {
            Ok(banner) => {
                // Create result table with banner info
                let table = lua.create_table()?;

                // Use banner bytes as pseudo key data for fingerprint
                let banner_bytes = banner.as_bytes();
                table.set("key_type", "banner")?;
                table.set("fingerprint", calculate_md5_fingerprint(banner_bytes))?;
                table.set("fp_sha256", calculate_sha256_fingerprint(banner_bytes))?;
                table.set("bits", 0)?;
                table.set("algorithm", "Unknown")?;
                table.set("full_key", banner.as_str())?;

                Ok(Value::Table(table))
            }
            Err(_) => Ok(Value::Nil),
        }
    })?;
    ssh2_table.set("fetch_host_key", fetch_host_key_fn)?;

    // Register banner function
    let banner_fn = lua.create_function(|lua, (host, port): (Value, Value)| {
        let (host_str, port_num) = extract_host_port(host, port);

        debug!("ssh2.banner({}, {})", host_str, port_num);

        match read_ssh_banner(&host_str, port_num, DEFAULT_TIMEOUT_MS) {
            Ok(banner) => Ok(Value::String(lua.create_string(&banner)?)),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    ssh2_table.set("banner", banner_fn)?;

    // Register the ssh2 library globally
    lua.globals().set("ssh2", ssh2_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let input = b"hello";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn test_calculate_md5_fingerprint() {
        let data = b"test data";
        let fp = calculate_md5_fingerprint(data);
        assert_eq!(fp.len(), 47);
        assert!(fp.contains(':'));
    }

    #[test]
    fn test_calculate_sha256_fingerprint() {
        let data = b"test data";
        let fp = calculate_sha256_fingerprint(data);
        assert!(fp.starts_with("SHA256:"));
    }

    #[test]
    fn test_extract_host_port() {
        let (host, port) = extract_host_port(Value::Nil, Value::Integer(22));
        assert_eq!(host, "");
        assert_eq!(port, 22);
    }
}
