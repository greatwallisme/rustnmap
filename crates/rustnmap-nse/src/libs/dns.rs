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

//! DNS library constants for NSE.
//!
//! This module provides DNS record type constants for the `dns` NSE library.
//! The actual DNS query logic is handled by `dns.lua` via the `DUAL_MODULE` mechanism.
//!
//! # Available Constants
//!
//! - `dns.TYPE_A` = 1 (IPv4 address)
//! - `dns.TYPE_NS` = 2 (Name server)
//! - `dns.TYPE_CNAME` = 5 (Canonical name)
//! - `dns.TYPE_SOA` = 6 (Start of authority)
//! - `dns.TYPE_PTR` = 12 (Pointer record)
//! - `dns.TYPE_MX` = 15 (Mail exchange)
//! - `dns.TYPE_TXT` = 16 (Text record)
//! - `dns.TYPE_AAAA` = 28 (IPv6 address)
//! - `dns.TYPE_SRV` = 33 (Service record)
//! - `dns.TYPE_ANY` = 255 (Any record)

use crate::error::Result;
use crate::lua::NseLua;

#[cfg(test)]
use mlua::Table;

/// Register DNS constants with the Lua runtime.
///
/// Only registers type constants; the actual `query` and `reverse` functions
/// are provided by `dns.lua` loaded via `DUAL_MODULE`.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    let dns_table = lua.create_table()?;

    dns_table.set("TYPE_A", 1i64)?;
    dns_table.set("TYPE_NS", 2i64)?;
    dns_table.set("TYPE_CNAME", 5i64)?;
    dns_table.set("TYPE_SOA", 6i64)?;
    dns_table.set("TYPE_PTR", 12i64)?;
    dns_table.set("TYPE_MX", 15i64)?;
    dns_table.set("TYPE_TXT", 16i64)?;
    dns_table.set("TYPE_AAAA", 28i64)?;
    dns_table.set("TYPE_SRV", 33i64)?;
    dns_table.set("TYPE_ANY", 255i64)?;

    lua.globals().set("dns", dns_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_constants_registered() {
        let mut nse_lua = NseLua::new_default().expect("Failed to create Lua state");
        register(&mut nse_lua).expect("Failed to register dns constants");

        let lua = nse_lua.lua();
        let dns: Table = lua.globals().get("dns").expect("dns table missing");

        assert_eq!(dns.get::<i64>("TYPE_A").unwrap(), 1);
        assert_eq!(dns.get::<i64>("TYPE_NS").unwrap(), 2);
        assert_eq!(dns.get::<i64>("TYPE_CNAME").unwrap(), 5);
        assert_eq!(dns.get::<i64>("TYPE_SOA").unwrap(), 6);
        assert_eq!(dns.get::<i64>("TYPE_PTR").unwrap(), 12);
        assert_eq!(dns.get::<i64>("TYPE_MX").unwrap(), 15);
        assert_eq!(dns.get::<i64>("TYPE_TXT").unwrap(), 16);
        assert_eq!(dns.get::<i64>("TYPE_AAAA").unwrap(), 28);
        assert_eq!(dns.get::<i64>("TYPE_SRV").unwrap(), 33);
        assert_eq!(dns.get::<i64>("TYPE_ANY").unwrap(), 255);
    }
}
