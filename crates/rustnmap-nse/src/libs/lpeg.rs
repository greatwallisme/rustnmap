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

//! Pure Lua `lpeg` module for NSE scripts.
//!
//! Loads [`LuLPeg`](https://github.com/pygy/LuLPeg), a pure-Lua port of Roberto
//! Ierusalimschy's `LPeg` library, into the Lua VM. This provides `PEG`
//! (Parsing Expression Grammar) pattern matching to NSE scripts that
//! `require "lpeg"`.
//!
//! No native C code is used -- the entire `LPeg` implementation runs inside the
//! Lua VM.

use crate::error::Result;
use crate::lua::NseLua;

/// `LPeg` Lua source ([`LuLPeg`] v0.12, pure Lua, WTFPL license).
const LULPEG_LUA: &str = include_str!("lua/lulpeg.lua");

/// Register the `lpeg` library with the Lua runtime.
///
/// Loads the pure-Lua [`LuLPeg`] implementation and registers it as both the
/// `lpeg` global and in [`package.preload`] so `require "lpeg"` works.
///
/// # Errors
///
/// Returns an error if Lua code execution fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Load and execute LuLPeg -- it returns an LL table with the full lpeg API
    let lulpeg: mlua::Table = lua.load(LULPEG_LUA).set_name("lulpeg.lua").eval()?;

    // Call LL:register() to set package.loaded.lpeg and package.loaded.re
    let register_fn: mlua::Function = lulpeg.get("register")?;
    register_fn.call::<mlua::Value>((lulpeg.clone(), mlua::Value::Nil))?;

    // Also set lpeg as a global for direct access
    lua.globals().set("lpeg", lulpeg.clone())?;

    // Verify the registration worked
    let lpeg_loaded: mlua::Value = lua
        .globals()
        .get::<mlua::Table>("package")?
        .get::<mlua::Table>("loaded")?
        .get("lpeg")?;

    if matches!(lpeg_loaded, mlua::Value::Nil) {
        // Fallback: manually set package.loaded.lpeg
        let loaded: mlua::Table = lua.globals().get::<mlua::Table>("package")?.get("loaded")?;
        loaded.set("lpeg", lulpeg.clone())?;
    }

    // Also register in package.preload for require() support
    let preload: mlua::Table = lua
        .globals()
        .get::<mlua::Table>("package")?
        .get("preload")?;

    let lpeg_ref: mlua::Table = lulpeg;
    let loader = lua.create_function(move |_, (): ()| Ok(mlua::Value::Table(lpeg_ref.clone())))?;
    preload.set("lpeg", loader)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lpeg_basic_match() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test basic P() match -- returns end position (6), not the string
        let result: i64 = lua
            .lua()
            .load(r#"return lpeg.P("hello"):match("hello world")"#)
            .eval()
            .unwrap();
        assert_eq!(result, 6);

        // Test C() capture returns matched string
        let captured: String = lua
            .lua()
            .load(r#"return lpeg.C(lpeg.P("hello")):match("hello world")"#)
            .eval()
            .unwrap();
        assert_eq!(captured, "hello");
    }

    #[test]
    fn test_lpeg_require() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test require("lpeg") works
        let result: i64 = lua
            .lua()
            .load(r#"local l = require "lpeg"; return l.P("a"):match("abc") and 1 or 0"#)
            .eval()
            .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_lpeg_r_and_s() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test R (range) and S (set)
        let result: i64 = lua
            .lua()
            .load(
                r#"
                local lpeg = require "lpeg"
                local digit = lpeg.R("09")
                local space = lpeg.S(" \t")
                return (digit + space):match("5") and 1 or 0
            "#,
            )
            .eval()
            .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_lpeg_captures() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Test C (capture) and Ct (table capture)
        let result: mlua::Value = lua
            .lua()
            .load(
                r#"
                local lpeg = require "lpeg"
                local C = lpeg.C
                local P = lpeg.P
                local Ct = lpeg.Ct
                return Ct(C(P("a") + P("b"))^0):match("abba")
            "#,
            )
            .eval()
            .unwrap();
        assert!(!matches!(result, mlua::Value::Nil));
    }
}
