//! NSE (Nmap Scripting Engine) standard libraries.
//!
//! This module provides the core NSE libraries that are available to Lua scripts:
//!
//! - `nmap`: Core scan information and utilities
//! - `stdnse`: Standard utility functions
//! - `comm`: Network communication functions
//! - `shortport`: Port rule definitions
//!
//! These libraries are registered with the Lua runtime and provide
//! Nmap-compatible APIs for script authors.

pub mod brute;
pub mod comm;
pub mod dns;
pub mod ftp;
pub mod http;
pub mod nmap;
pub mod shortport;
pub mod ssh2;
pub mod ssl;
pub mod stdnse;
pub mod unpwdb;

use crate::error::Result;
use crate::lua::NseLua;

/// Register all NSE standard libraries with the Lua runtime.
///
/// This function registers the core NSE libraries (nmap, stdnse, comm, shortport)
/// and protocol libraries (http, ssh, ssl, dns, ftp, unpwdb) and the brute force
/// framework (brute) with the given Lua instance, making them available to NSE scripts.
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
    // Core libraries
    nmap::register(lua)?;
    stdnse::register(lua)?;
    comm::register(lua)?;
    shortport::register(lua)?;

    // Protocol libraries
    http::register(lua)?;
    ssh2::register(lua)?;
    ssl::register(lua)?;
    dns::register(lua)?;
    ftp::register(lua)?;
    unpwdb::register(lua)?;

    // Brute force framework
    brute::register(lua)?;

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
