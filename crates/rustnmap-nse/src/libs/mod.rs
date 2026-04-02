//! NSE (Nmap Scripting Engine) standard libraries.
//!
//! This module provides the core NSE libraries that are available to Lua scripts:
//!
//! - `nmap`: Core scan information and utilities
//! - `stdnse`: Standard utility functions
//! - `comm`: Network communication functions
//! - `shortport`: Port rule definitions
//! - `http`: HTTP protocol library
//! - `ssh2`: SSH protocol library
//! - `ssl`: TLS/SSL protocol library
//! - `dns`: DNS protocol library
//! - `ftp`: FTP protocol library
//! - `unpwdb`: Username/password database
//! - `smb`: SMB/CIFS protocol library
//! - `netbios`: `NetBIOS` name service
//! - `smbauth`: NTLM authentication
//! - `unicode`: UTF-8/UTF-16 conversions
//! - `openssl`: Cryptographic operations
//! - `brute`: Brute force engine
//! - `creds`: Credential management
//! - `json`: JSON encoding and decoding
//! - `url`: URL parsing and composition
//! - `rand`: Random data generation
//! - `ipOps`: IP address operations
//!
//! These libraries are registered with the Lua runtime in two places:
//! 1. Global namespace (e.g., `http` table accessible directly)
//! 2. package.preload (so `require("http")` works)
//!
//! This dual registration ensures compatibility with both:
//! - Direct global access: `local http = http`
//! - Standard require: `local http = require "http"`

pub mod base64;
pub mod brute;
pub mod comm;
pub mod creds;
pub mod dns;
pub mod ftp;
pub mod http;
pub mod ip_ops;
pub mod json;
pub mod libssh2_utility;
pub mod lpeg;
pub mod lpeg_utility;
pub mod netbios;
pub mod nmap;
pub mod openssl;
pub mod rand;
pub mod shortport;
pub mod smb;
pub mod smbauth;
pub mod ssh1;
pub mod ssh2;
pub mod ssl;
pub mod stdnse;
pub mod stringaux;
pub mod tableaux;
pub mod unicode;
pub mod unpwdb;
pub mod url;

use crate::error::Result;
use crate::lua::NseLua;

/// Register all NSE standard libraries with the Lua runtime.
///
/// This function registers the core NSE libraries (nmap, stdnse, comm, shortport)
/// and protocol libraries (http, ssh, ssl, dns, ftp, unpwdb, smb, netbios, smbauth, unicode)
/// and utility libraries (openssl, brute, creds) with the given Lua instance, making them
/// available to NSE scripts.
///
/// # Arguments
///
/// * `lua` - The NSE Lua runtime to register libraries with
///
/// # Errors
///
/// Returns an error if any library registration fails.
///
/// # Example
///
/// ```no_run
/// use rustnmap_nse::lua::NseLua;
/// use rustnmap_nse::libs::register_all;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut lua = NseLua::new_default()?;
/// register_all(&mut lua)?;
/// # Ok(())
/// # }
/// ```
pub fn register_all(lua: &mut NseLua) -> Result<()> {
    // Core libraries - these are registered in both global namespace and package.preload
    nmap::register(lua)?;
    stdnse::register(lua)?;
    comm::register(lua)?;
    shortport::register(lua)?;

    // Protocol libraries
    http::register(lua)?;
    ssh1::register(lua)?;
    ssh2::register(lua)?;
    ssl::register(lua)?;
    dns::register(lua)?;
    ftp::register(lua)?;
    unpwdb::register(lua)?;

    // SMB protocol libraries
    smb::register(lua)?;
    netbios::register(lua)?;
    smbauth::register(lua)?;
    unicode::register(lua)?;

    // Utility libraries
    json::register(lua)?;
    openssl::register(lua)?;
    brute::register(lua)?;
    creds::register(lua)?;
    url::register(lua)?;
    rand::register(lua)?;
    stringaux::register(lua)?;
    tableaux::register(lua)?;
    libssh2_utility::register(lua)?;
    // Register pure-Rust lpeg module BEFORE lpeg-utility (which requires itpeg)
    lpeg::register(lua)?;
    lpeg_utility::register(lua)?;
    ip_ops::register(lua)?;
    base64::register(lua)?;

    // After registering all libraries in global namespace,
    // also register them in package.preload so require() works
    register_package_preload(lua)?;

    Ok(())
}

/// Register all NSE libraries in package.preload for `require()` support.
///
/// This function copies the globally registered libraries into package.preload
/// so that scripts can use `require("http")` instead of just `http`.
///
/// In Lua, package.preload[`modname`] should contain a loader function that
/// returns the module. We create loader functions that return the globally
/// registered library tables.
fn register_package_preload(lua: &mut NseLua) -> Result<()> {
    let lua_state = lua.lua_mut();

    // Get or create package.preload table
    let package: mlua::Table = if let Ok(t) = lua_state.globals().get("package") {
        t
    } else {
        let t = lua_state.create_table()?;
        lua_state.globals().set("package", t.clone())?;
        t
    };

    let preload: mlua::Table = if let Ok(t) = package.get("preload") {
        t
    } else {
        let t = lua_state.create_table()?;
        package.set("preload", t.clone())?;
        t
    };

    // List of all library names to register in preload
    let library_names = [
        "nmap",
        "stdnse",
        "comm",
        "shortport",
        "http",
        "ssh2",
        "ssl",
        "dns",
        "ftp",
        "unpwdb",
        "smb",
        "netbios",
        "smbauth",
        "unicode",
        "json",
        "openssl",
        "brute",
        "creds",
        "url",
        "rand",
        "stringaux",
        "tableaux",
        "libssh2-utility",
        "lpeg-utility",
        "ipOps",
        "base64",
        "ssh1",
    ];

    for name in library_names {
        // Clone the name for the loader function
        let name_owned = name.to_string();

        // Create a loader function that returns the library table from globals
        let loader = lua_state.create_function(move |lua, (): ()| {
            // Get the library table from globals and return it
            let lib_table: mlua::Table = lua.globals().get(name_owned.as_str())?;
            Ok(lib_table)
        })?;

        // Store the loader function in package.preload
        preload.set(name, loader)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_all() {
        let mut lua = NseLua::new_default().unwrap();
        let result = register_all(&mut lua);
        result.unwrap();

        // Verify nmap library is registered
        let nmap: mlua::Value = lua.lua().globals().get("nmap").unwrap();
        assert!(!matches!(nmap, mlua::Value::Nil));

        // Verify stdnse library is registered
        let stdnse: mlua::Value = lua.lua().globals().get("stdnse").unwrap();
        assert!(!matches!(stdnse, mlua::Value::Nil));

        // Verify comm library is registered
        let comm: mlua::Value = lua.lua().globals().get("comm").unwrap();
        assert!(!matches!(comm, mlua::Value::Nil));

        // Verify shortport library is registered
        let shortport: mlua::Value = lua.lua().globals().get("shortport").unwrap();
        assert!(!matches!(shortport, mlua::Value::Nil));
    }
}
