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

pub mod comm;
pub mod nmap;
pub mod shortport;
pub mod stdnse;

use crate::error::Result;
use crate::lua::NseLua;

/// Register all NSE standard libraries with the Lua runtime.
///
/// This function registers the core NSE libraries (nmap, stdnse, comm, shortport)
/// with the given Lua instance, making them available to NSE scripts.
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
    nmap::register(lua)?;
    stdnse::register(lua)?;
    comm::register(lua)?;
    shortport::register(lua)?;
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
