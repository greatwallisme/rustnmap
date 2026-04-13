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

//! SMB (Server Message Block) library for NSE.
//!
//! This module provides the `smb` library which registers SMB command constants
//! for use by Lua scripts. The full SMB protocol implementation lives in
//! `nselib/smb.lua` (the Lua side of this `DUAL_MODULE`).
//!
//! Since SMB is a `DUAL_MODULE`, the Lua `nselib/smb.lua` loads first with the
//! complete protocol implementation, then these Rust constants are merged in
//! without overwriting Lua functions.

use crate::error::Result;
use crate::lua::NseLua;

// SMB Commands exported to Lua
const SMB_COM_NEGOTIATE: u8 = 0x72;
const SMB_COM_SESSION_SETUP_ANDX: u8 = 0x73;
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const SMB_COM_NT_CREATE_ANDX: u8 = 0xA2;
const SMB_COM_CLOSE: u8 = 0x04;
const SMB_COM_READ_ANDX: u8 = 0x2E;
const SMB_COM_WRITE_ANDX: u8 = 0x2F;

/// Register the smb library with the Lua runtime.
///
/// Only registers SMB command constants. The Lua `nselib/smb.lua` provides
/// the full protocol implementation (connect, negotiate, session setup, etc.).
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    let smb_table = lua.create_table()?;

    smb_table.set("COMMAND_NEGOTIATE", SMB_COM_NEGOTIATE)?;
    smb_table.set("COMMAND_SESSION_SETUP", SMB_COM_SESSION_SETUP_ANDX)?;
    smb_table.set("COMMAND_TREE_CONNECT", SMB_COM_TREE_CONNECT_ANDX)?;
    smb_table.set("COMMAND_TREE_DISCONNECT", SMB_COM_TREE_DISCONNECT)?;
    smb_table.set("COMMAND_NT_CREATE", SMB_COM_NT_CREATE_ANDX)?;
    smb_table.set("COMMAND_CLOSE", SMB_COM_CLOSE)?;
    smb_table.set("COMMAND_READ", SMB_COM_READ_ANDX)?;
    smb_table.set("COMMAND_WRITE", SMB_COM_WRITE_ANDX)?;

    lua.globals().set("smb", smb_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_smb_constants() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let smb: mlua::Table = lua.lua().globals().get("smb").unwrap();
        let negotiate: u8 = smb.get("COMMAND_NEGOTIATE").unwrap();
        assert_eq!(negotiate, 0x72);
    }
}
