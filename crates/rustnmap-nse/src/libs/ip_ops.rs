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

//! IP address operations library for NSE.
//!
//! This module provides the `ipOps` library which contains utility functions
//! for manipulating and comparing IP addresses. It corresponds to Nmap's ipOps NSE library.
//!
//! # Available Functions
//!
//! - `ipOps.compare(ip1, ip2)` - Compare two IP addresses
//! - `ipOps.is_private(ip)` - Check if IP is in private address space
//! - `ipOps.is_loopback(ip)` - Check if IP is a loopback address
//! - `ipOps.is_link_local(ip)` - Check if IP is a link-local address
//! - `ipOps.todword(ip)` - Convert IPv4 address to 32-bit integer
//! - `ipOps.fromdword(num)` - Convert 32-bit integer to IPv4 address
//! - `ipOps.get_parts_as_number(ip)` - Get high and low parts of IPv6 address
//! - `ipOps.ip_to_str(ip)` - Convert IP address to binary string
//! - `ipOps.str_to_ip(str)` - Convert binary string to IP address
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local ipOps = require "ipOps"
//!
//! -- Check if address is private
//! if ipOps.is_private("192.168.1.1") then
//!     print("Private address")
//! end
//!
//! -- Compare addresses
//! local cmp = ipOps.compare("192.168.1.1", "192.168.1.2")
//! -- Returns -1, 0, or 1
//!
//! -- Convert to number
//! local num = ipOps.todword("192.168.1.1")
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Result;
use crate::lua::NseLua;

/// Register the ipOps library with the Lua runtime.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register with
///
/// # Errors
///
/// Returns an error if registration fails.
#[expect(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    reason = "Library registration requires many function registrations; expect calls are guarded by prior validation"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the ipOps table
    let ip_ops = lua.create_table()?;

    // Register compare(ip1, ip2) function
    let compare_fn = lua.create_function(|_, (ip1, ip2): (String, String)| {
        let addr1: IpAddr = ip1
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip1}': {e}")))?;
        let addr2: IpAddr = ip2
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip2}': {e}")))?;

        let result = match addr1.cmp(&addr2) {
            std::cmp::Ordering::Less => -1i64,
            std::cmp::Ordering::Equal => 0i64,
            std::cmp::Ordering::Greater => 1i64,
        };
        Ok(result)
    })?;
    ip_ops.set("compare", compare_fn)?;
    // compare_ip is provided by ipOps.lua with full operator support ("eq", "lt", etc.)
    // Do NOT register from Rust to avoid overriding the Lua version.

    // Register is_private(ip) function
    let is_private_fn = lua.create_function(|_, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        let is_private = match addr {
            IpAddr::V4(v4) => is_private_ipv4(v4),
            IpAddr::V6(v6) => is_private_ipv6(&v6),
        };
        Ok(is_private)
    })?;
    ip_ops.set("is_private", is_private_fn.clone())?;
    ip_ops.set("isPrivate", is_private_fn)?; // Nmap-compatible camelCase alias

    // Register is_loopback(ip) function
    let is_loopback_fn = lua.create_function(|_, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        let is_loopback = match addr {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        Ok(is_loopback)
    })?;
    ip_ops.set("is_loopback", is_loopback_fn)?;

    // Register is_link_local(ip) function
    let is_link_local_fn = lua.create_function(|_, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        let is_link_local = match addr {
            IpAddr::V4(v4) => is_link_local_ipv4(v4),
            IpAddr::V6(v6) => v6.is_unicast_link_local(),
        };
        Ok(is_link_local)
    })?;
    ip_ops.set("is_link_local", is_link_local_fn)?;

    // Register todword(ip) function - convert IPv4 to 32-bit integer
    let todword_fn = lua.create_function(|_, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let num = u32::from_be_bytes(octets);
                Ok(i64::from(num))
            }
            IpAddr::V6(_) => Err(mlua::Error::RuntimeError(
                "todword only supports IPv4 addresses".to_string(),
            )),
        }
    })?;
    ip_ops.set("todword", todword_fn)?;

    // Register fromdword(num) function - convert 32-bit integer to IPv4
    let fromdword_fn = lua.create_function(|_, num: i64| {
        if num < 0 || num > i64::from(u32::MAX) {
            return Err(mlua::Error::RuntimeError(format!(
                "Number {num} is out of range for IPv4 address"
            )));
        }
        let bytes = u32::try_from(num).expect("validated range").to_be_bytes();
        let addr = Ipv4Addr::from(bytes);
        Ok(addr.to_string())
    })?;
    ip_ops.set("fromdword", fromdword_fn)?;

    // Register ip_to_str(ip) function - convert IP to binary string
    let ip_to_str_fn = lua.create_function(|lua, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        let bytes = match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        // Return as a Lua string (raw bytes), not a table — callers expect a
        // string suitable for string.pack(), string.len(), etc.
        lua.create_string(&bytes)
    })?;
    ip_ops.set("ip_to_str", ip_to_str_fn)?;

    // Register str_to_ip(str) function - convert binary string to IP
    let str_to_ip_fn = lua.create_function(|_, bytes: mlua::String| {
        let bytes = bytes.as_bytes().to_vec();
        match bytes.len() {
            4 => {
                let arr: [u8; 4] = bytes.try_into().map_err(|_err| {
                    mlua::Error::RuntimeError("Failed to convert bytes to IPv4".to_string())
                })?;
                Ok(Ipv4Addr::from(arr).to_string())
            }
            16 => {
                let arr: [u8; 16] = bytes.try_into().map_err(|_err| {
                    mlua::Error::RuntimeError("Failed to convert bytes to IPv6".to_string())
                })?;
                Ok(Ipv6Addr::from(arr).to_string())
            }
            _ => Err(mlua::Error::RuntimeError(format!(
                "Invalid byte length for IP address: {} (expected 4 or 16)",
                bytes.len()
            ))),
        }
    })?;
    ip_ops.set("str_to_ip", str_to_ip_fn)?;

    // Register get_parts_as_number(ip) function for IPv6
    let get_parts_fn = lua.create_function(|_, ip: String| {
        let addr: IpAddr = ip
            .parse()
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip}': {e}")))?;

        match addr {
            IpAddr::V4(v4) => {
                let num = u32::from(v4);
                Ok((0i64, i64::from(num)))
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                // High 64 bits (first 8 bytes)
                let mut high_bytes = [0u8; 8];
                high_bytes.copy_from_slice(&octets[0..8]);
                let high = i64::from_be_bytes(high_bytes);
                // Low 64 bits (last 8 bytes)
                let mut low_bytes = [0u8; 8];
                low_bytes.copy_from_slice(&octets[8..16]);
                let low = i64::from_be_bytes(low_bytes);
                Ok((high, low))
            }
        }
    })?;
    ip_ops.set("get_parts_as_number", get_parts_fn)?;

    // Set the ipOps table as a global
    lua.globals().set("ipOps", ip_ops)?;

    Ok(())
}

/// Check if an IPv4 address is in private address space.
fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    false
}

/// Check if an IPv6 address is in private address space.
fn is_private_ipv6(addr: &Ipv6Addr) -> bool {
    // Unique local addresses fc00::/7
    let segments = addr.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Check if an IPv4 address is a link-local address.
fn is_link_local_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    // 169.254.0.0/16
    octets[0] == 169 && octets[1] == 254
}
