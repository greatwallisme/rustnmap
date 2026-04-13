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

//! lpeg-utility library for NSE.
//!
//! This module provides the `lpeg-utility` library which contains utility functions
//! for parsing service fingerprints and HTTP responses. It corresponds to Nmap's lpeg-utility
//! NSE library.
//!
//! # Functions
//!
//! - `get_response(fp, probe)` - Extract response for a specific probe from service fingerprint
//! - `parse_fp(fp)` - Parse service fingerprint into table of probe->response pairs
//!
//! # Service Fingerprint Format
//!
//! Service fingerprints are formatted as:
//! ```text
//! SF-SSL:<probe>,<hex_length>,<hex_data>\r\n
//! SF:<probe>,<hex_length>,<hex_data>\r\n
//! ```
//!
//! The `hex_data` contains escape sequences like `\x00` which need to be decoded.
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local U = require "lpeg-utility"
//!
//! -- Get response for specific probe
//! local response = U.get_response(port.version.service_fp, "GetRequest")
//!
//! -- Parse full fingerprint
//! local fp_table = U.parse_fp(port.version.service_fp)
//! ```

use std::collections::HashMap;

use mlua::Value;
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Parse hex escape sequences in a string.
///
/// Handles escape sequences like `\x00`, `\n`, `\r`, `\t`, `\\`, etc.
fn parse_escapes(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars();
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if escaped {
            match c {
                'x' => {
                    // Hex escape: \xHH
                    let h1 = chars.next().unwrap_or('0');
                    let h2 = chars.next().unwrap_or('0');
                    let byte = u8::from_str_radix(&format!("{h1}{h2}"), 16).unwrap_or(0);
                    result.push(byte as char);
                }
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                '0' => result.push('\0'),
                '\\' => result.push('\\'),
                '"' => result.push('"'),
                '\'' => result.push('\''),
                _ => {
                    // Unknown escape, keep as-is
                    result.push('\\');
                    result.push(c);
                }
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            result.push(c);
        }
    }

    result
}

/// Extract a quoted string from the input.
///
/// Handles escaped quotes within the string.
#[cfg(test)]
fn extract_quoted_string(input: &str) -> Option<(String, usize)> {
    let chars: Vec<char> = input.chars().collect();
    if chars.is_empty() {
        return None;
    }

    let quote_char = chars[0];
    if quote_char != '"' && quote_char != '\'' {
        return None;
    }

    let mut result = String::new();
    let mut i = 1;
    let mut escaped = false;

    while i < chars.len() {
        let c = chars[i];
        if escaped {
            match c {
                'x' => {
                    // Hex escape: \xHH
                    if i + 2 < chars.len() {
                        let h1 = chars[i + 1];
                        let h2 = chars[i + 2];
                        if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                            result.push(byte as char);
                        }
                        i += 2;
                    }
                }
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                '0' => result.push('\0'),
                '\\' => result.push('\\'),
                '"' => result.push('"'),
                '\'' => result.push('\''),
                _ => result.push(c),
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == quote_char {
            return Some((result, i + 1));
        } else {
            result.push(c);
        }
        i += 1;
    }

    None
}

/// Get response for a specific probe from service fingerprint.
///
/// # Arguments
///
/// * `fp` - Service fingerprint string
/// * `probe` - Probe name (e.g., "`GetRequest`", "`GenericLines`")
///
/// # Returns
///
/// The decoded response data for the probe, or nil if not found.
fn get_response_impl(fp: &str, probe: &str) -> Option<String> {
    // The service fingerprint format is:
    // SF-SSL:<probe>,<hex_length>,<hex_data>\r\n
    // SF:<probe>,<hex_length>,<hex_data>\r\n
    //
    // We need to find the line for the specific probe and decode the hex_data.

    // First, remove newlines and work with the raw format
    let fp_normalized = fp.replace("\nSF:", "SF:").replace("\nSF-SSL:", "SF-SSL:");

    // Build the search pattern: SF:<probe>,
    let search_pattern = format!("SF:{probe},");

    // Find the probe entry
    let start_idx = fp_normalized.find(&search_pattern)?;

    // Find the end of this entry (next SF: or end of string)
    let entry_start = start_idx;
    let entry_end = fp_normalized[entry_start + search_pattern.len()..]
        .find("SF:")
        .map_or(fp_normalized.len(), |next_sf| {
            entry_start + search_pattern.len() + next_sf
        });

    let entry = &fp_normalized[entry_start..entry_end];

    // Parse the entry: SF:<probe>,<hex_length>,<hex_data>
    let after_probe = &entry[search_pattern.len()..];

    // Find the first comma (after hex_length)
    let comma_idx = after_probe.find(',')?;

    // Skip the hex_length and comma
    let after_length = &after_probe[comma_idx + 1..];

    // The rest is the hex data (with escapes)
    // First decode hex escapes in the format string
    let decoded = parse_escapes(after_length);

    Some(decoded)
}

/// Parse service fingerprint into a table of probe->response pairs.
///
/// # Arguments
///
/// * `fp` - Service fingerprint string
///
/// # Returns
///
/// A `HashMap` mapping probe names to their decoded responses.
fn parse_fp_impl(fp: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();

    // Normalize: remove newlines between SF entries
    let fp_normalized = fp
        .replace("\nSF:", "|||SF:")
        .replace("\nSF-SSL:", "|||SF-SSL:");

    // Split by our marker
    for entry in fp_normalized.split("|||") {
        if entry.is_empty() {
            continue;
        }

        // Entry format: SF:<probe>,<hex_length>,<hex_data>
        // or SF-SSL:<probe>,<hex_length>,<hex_data>

        let (_probe_prefix, rest) = if let Some(stripped) = entry.strip_prefix("SF-SSL:") {
            ("SF-SSL", stripped)
        } else if let Some(stripped) = entry.strip_prefix("SF:") {
            ("SF", stripped)
        } else {
            continue;
        };

        // Find the probe name (up to first comma)
        let Some(comma_idx) = rest.find(',') else {
            continue;
        };

        let probe = &rest[..comma_idx];

        // Skip hex_length and comma to get to data
        let after_length = &rest[comma_idx + 1..];
        let Some(next_comma) = after_length.find(',') else {
            continue;
        };

        let hex_data = &after_length[next_comma + 1..];

        // Decode escapes
        let decoded = parse_escapes(hex_data);
        result.insert(probe.to_string(), decoded);
    }

    result
}

/// Register the lpeg-utility library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
#[expect(
    clippy::too_many_lines,
    reason = "Register function contains inline Lua code for LPeg utility functions"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the lpeg-utility table
    let lpeg_utility_table = lua.create_table()?;

    // Register get_response function
    let get_response_fn = lua.create_function(|lua, (fp, probe): (String, String)| {
        debug!("lpeg-utility.get_response({}, {})", fp, probe);

        match get_response_impl(&fp, &probe) {
            Some(response) => Ok(Value::String(lua.create_string(&response)?)),
            None => Ok(Value::Nil),
        }
    })?;
    lpeg_utility_table.set("get_response", get_response_fn)?;

    // Register parse_fp function
    let parse_fp_fn = lua.create_function(|lua, fp: String| {
        debug!("lpeg-utility.parse_fp({})", fp);

        let result = parse_fp_impl(&fp);

        // Convert HashMap to Lua table
        let table = lua.create_table()?;
        for (key, value) in result {
            table.set(key, value)?;
        }

        Ok(Value::Table(table))
    })?;
    lpeg_utility_table.set("parse_fp", parse_fp_fn)?;

    // Register lpeg-dependent Lua functions directly via inline Lua code.
    // The full nselib/lpeg-utility.lua cannot be loaded at registration time
    // because it has transitive dependencies (require "stdnse" -> require "nmap")
    // that are not yet set up. Instead, we inline only the functions that
    // depend solely on the already-registered lpeg module.
    let lua_fn_table: mlua::Table = lua
        .load(
            r#"
local lpeg = require "lpeg"
local string = require "string"
local assert = assert
local tonumber = tonumber
local pairs = pairs
local rawset = rawset
local lower = string.lower
local upper = string.upper

local result = {}

-- Case-insensitive pattern builder
local caselessP = lpeg.Cf(
  (lpeg.P(1) / function(a) return lpeg.S(lower(a)..upper(a)) end)^1,
  function(a, b) return a * b end
)

function result.caseless(literal)
  return assert(caselessP:match(literal))
end

function result.anywhere(patt)
  return lpeg.P { patt + 1 * lpeg.V(1) }
end

function result.split(str, sep)
  return lpeg.P {
    lpeg.V "elem" * (lpeg.V "sep" * lpeg.V "elem")^0,
    elem = lpeg.C((1 - lpeg.V "sep")^0),
    sep = sep,
  }:match(str)
end

-- localize adds locale-aware character classes to a grammar.
-- Equivalent to lpeg.locale(grammar) but works with LuLPeg which may not
-- implement locale().
function result.localize(grammar)
  if not grammar then return lpeg.P(false) end
  if not grammar.alpha then
    grammar.alpha = lpeg.R("az", "AZ") + lpeg.P("_")
  end
  if not grammar.digit then
    grammar.digit = lpeg.R("09")
  end
  if not grammar.alnum then
    grammar.alnum = grammar.alpha + grammar.digit
  end
  if not grammar.space then
    grammar.space = lpeg.S(" \t\r\n\v\f")^1
  end
  if not grammar.xdigit then
    grammar.xdigit = lpeg.R("09", "AF", "af")
  end
  if not grammar.punct then
    grammar.punct = lpeg.R("\33\47") + lpeg.R("\58\64") + lpeg.R("\91\96") + lpeg.R("\123\126")
  end
  if not grammar.lower then
    grammar.lower = lpeg.R("az")
  end
  if not grammar.upper then
    grammar.upper = lpeg.R("AZ")
  end
  return lpeg.P(grammar)
end

function result.atwordboundary(patt)
  return result.localize {
    patt + lpeg.V "alpha"^0 * (1 - lpeg.V "alpha")^1 * lpeg.V(1)
  }
end

function result.escaped_quote(quot, esc)
  quot = quot or '"'
  esc = esc or '\\'
  return lpeg.P {
    lpeg.Cs(lpeg.V "quot" * lpeg.Cs((lpeg.V "simple_char" + lpeg.V "noesc" + lpeg.V "unesc")^0) * lpeg.V "quot"),
    quot = lpeg.P(quot)/"",
    esc = lpeg.P(esc),
    simple_char = (lpeg.P(1) - (lpeg.V "quot" + lpeg.V "esc")),
    unesc = (lpeg.V "esc" * lpeg.C(lpeg.V "esc" + lpeg.P(quot)))/"%1",
    noesc = lpeg.V "esc" * lpeg.V "simple_char",
  }
end

return result
"#,
        )
        .set_name("lpeg-utility-functions")
        .eval()?;

    for (key, value) in lua_fn_table.pairs::<mlua::String, mlua::Value>().flatten() {
        // Rust-registered functions take priority
        if lpeg_utility_table.get::<mlua::Value>(key.clone())?.is_nil() {
            lpeg_utility_table.set(key, value)?;
        }
    }
    debug!("lpeg-utility Lua functions registered");

    // Register the library globally as "lpeg-utility"
    lua.globals().set("lpeg-utility", lpeg_utility_table)?;

    debug!("lpeg-utility library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_escapes() {
        let input = r"Hello\x00World\nTest";
        let result = parse_escapes(input);
        assert!(result.contains('\0'));
        assert!(result.contains('\n'));
    }

    #[test]
    fn test_extract_quoted_string() {
        let input = r#""test\x00string""#;
        let result = extract_quoted_string(input);
        assert!(result.is_some());
        let (decoded, _len) = result.unwrap();
        assert!(decoded.contains('\0'));
    }

    #[test]
    fn test_get_response_impl() {
        let fp = "SF:GetRequest,15,test\\x00data
SF:GenericLines,10,other\\x00data";
        let result = get_response_impl(fp, "GetRequest");
        assert!(result.is_some());
        let decoded = result.unwrap();
        assert!(decoded.contains('\0'));
        assert!(decoded.contains("test"));
    }

    #[test]
    fn test_parse_fp_impl() {
        let fp = "SF:GetRequest,15,test\\x00data
SF:GenericLines,10,other\\x00data";
        let result = parse_fp_impl(fp);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("GetRequest"));
        assert!(result.contains_key("GenericLines"));
    }
}
