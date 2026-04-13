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

//! `nmapdb` module — direct lookups into nmap data files.
//!
//! This mirrors the C-level `nmapdb` module that nmap exposes to Lua.
//! It provides:
//! - `getservbyport(port, proto)` — look up service name by port number and protocol
//! - `mac2corp(mac)` — look up vendor/manufacturer by MAC OUI prefix

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::Result;
use crate::lua::NseLua;

/// Global MAC prefix database, loaded once on first use.
static MAC_DB: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Register the `nmapdb` library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(lua: &mut NseLua) -> Result<()> {
    let lua_state = lua.lua_mut();

    let nmapdb = lua_state.create_table()?;

    // nmapdb.getservbyport(port, proto) -> service_name or nil
    let getservbyport_fn = lua_state.create_function(|lua, (port, proto): (u16, String)| {
        let db = rustnmap_common::ServiceDatabase::global();
        let protocol = match proto.as_str() {
            "tcp" => rustnmap_common::ServiceProtocol::Tcp,
            "udp" => rustnmap_common::ServiceProtocol::Udp,
            "sctp" => rustnmap_common::ServiceProtocol::Sctp,
            _ => return Ok(mlua::Value::Nil),
        };
        match db.lookup(port, protocol) {
            Some(name) => Ok(mlua::Value::String(lua.create_string(name)?)),
            None => Ok(mlua::Value::Nil),
        }
    })?;
    nmapdb.set("getservbyport", getservbyport_fn)?;

    // nmapdb.mac2corp(mac) -> vendor_name or nil
    // mac can be: 6-byte binary, or 12-char hex string, or 6-char hex prefix
    let mac2corp_fn = lua_state.create_function(|lua, mac: mlua::Value| {
        let prefix = match &mac {
            mlua::Value::String(s) => {
                let bytes = s.as_bytes();
                if bytes.len() <= 6 {
                    // Binary MAC or short hex — convert first 3 bytes to hex prefix
                    let b0 = bytes.first().copied().unwrap_or(0);
                    let b1 = bytes.get(1).copied().unwrap_or(0);
                    let b2 = bytes.get(2).copied().unwrap_or(0);
                    format!("{b0:02X}{b1:02X}{b2:02X}")
                } else {
                    // Hex string (12+ chars) — take first 6 hex chars
                    let raw_bytes = s.as_bytes();
                    let text = String::from_utf8_lossy(&raw_bytes);
                    let hex: String = text
                        .chars()
                        .filter(char::is_ascii_hexdigit)
                        .take(6)
                        .collect();
                    hex.to_uppercase()
                }
            }
            _ => return Ok(mlua::Value::Nil),
        };

        let db = MAC_DB.get_or_init(load_mac_db);
        match db.get(&prefix) {
            Some(vendor) => Ok(mlua::Value::String(lua.create_string(vendor.as_str())?)),
            None => Ok(mlua::Value::Nil),
        }
    })?;
    nmapdb.set("mac2corp", mac2corp_fn)?;

    lua_state.globals().set("nmapdb", nmapdb)?;

    Ok(())
}

/// Load the `nmap-mac-prefixes` file into a `HashMap`.
/// Searches the same paths as `nmap.fetchfile`.
fn load_mac_db() -> HashMap<String, String> {
    let mut db = HashMap::new();

    let search_paths: Vec<std::path::PathBuf> = {
        let mut paths = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            paths.push(
                std::path::PathBuf::from(home)
                    .join(".rustnmap")
                    .join("nmap-mac-prefixes"),
            );
        }
        paths.push(std::path::PathBuf::from("db/nmap-mac-prefixes"));
        // paths.push(std::path::PathBuf::from("reference/nmap/nmap-mac-prefixes"));
        paths.push(std::path::PathBuf::from(
            "/usr/share/rustnmap/nmap-mac-prefixes",
        ));
        paths.push(std::path::PathBuf::from(
            "/usr/share/nmap/nmap-mac-prefixes",
        ));
        paths
    };

    for path in &search_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                // Format: "AABBCC Vendor Name"
                if line.len() >= 7 {
                    let prefix = &line[..6];
                    let vendor = line[7..].trim();
                    if prefix.chars().all(|c| c.is_ascii_hexdigit()) && !vendor.is_empty() {
                        db.insert(prefix.to_uppercase(), vendor.to_string());
                    }
                }
            }
            break; // Use first found file
        }
    }

    db
}
