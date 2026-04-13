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

//! Random data generation library for NSE.
//!
//! This module provides the `rand` library which contains functions for generating
//! random data for NSE scripts. It corresponds to Nmap's rand NSE library.
//!
//! # Functions
//!
//! - `random_string(length, charset)` - Generate a random string
//! - `random_alpha(length)` - Generate random lowercase alphabetic string
//! - `charset(left, right, charset_table)` - Generate a charset table from a range
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local rand = require "rand"
//!
//! -- Generate random 8-character lowercase string
//! local username = rand.random_alpha(8)
//!
//! -- Generate random string from custom charset
//! local password = rand.random_string(12, "abcdefghijklmnopqrstuvwxyz0123456789")
//!
//! -- Create a charset for digits only
//! local digits = rand.charset('0', '9')
//! ```

use mlua::{Table, Value};
use rand::Rng;

use crate::error::Result;
use crate::lua::NseLua;

/// Generate a random string using the provided charset.
///
/// If charset is a string, picks random characters from it.
/// If charset is a table, picks random elements from it.
/// If no charset provided, returns random bytes.
///
/// # Arguments
///
/// * `length` - Length of the string to generate
/// * `charset` - Optional charset (string or table)
fn random_string_impl(
    lua: &mlua::Lua,
    length: i64,
    charset: Option<Value>,
) -> mlua::Result<mlua::String> {
    let length = usize::try_from(length)
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid length: {e}")))?;

    if length == 0 {
        return lua.create_string("");
    }

    match charset {
        None => {
            // Return random bytes as binary string (critical for TLS and crypto)
            let mut rng = rand::thread_rng();
            let mut bytes = vec![0u8; length];
            rng.fill(bytes.as_mut_slice());
            lua.create_string(&bytes)
        }
        Some(Value::String(s)) => {
            // Charset is a string - pick random characters from it
            let charset_str = s.to_str().map(|s| s.to_string()).unwrap_or_default();
            if charset_str.is_empty() {
                return lua.create_string("");
            }

            let mut rng = rand::thread_rng();
            let mut result = Vec::with_capacity(length);
            let charset_bytes = charset_str.as_bytes();
            for _ in 0..length {
                let idx = rng.gen_range(0..charset_bytes.len());
                result.push(charset_bytes[idx]);
            }
            lua.create_string(&result)
        }
        Some(Value::Table(t)) => {
            // Charset is a table - pick random elements from it
            let mut rng = rand::thread_rng();
            let mut result = Vec::with_capacity(length);

            // Get the length of the table (sequence)
            let table_len = t.raw_len();
            if table_len == 0 {
                return lua.create_string("");
            }

            for _ in 0..length {
                let idx = rng.gen_range(1..=table_len);
                let val: Value = t.get(idx)?;
                if let Value::String(s) = val {
                    result.extend_from_slice(&s.as_bytes());
                }
            }
            lua.create_string(&result)
        }
        Some(_) => Err(mlua::Error::RuntimeError(
            "Charset must be a string or table".to_string(),
        )),
    }
}

/// Generate a charset table from a character range.
///
/// # Arguments
///
/// * `left_bound` - Lower bound (character or byte value)
/// * `right_bound` - Upper bound (character or byte value)
/// * `charset_table` - Optional existing table to augment
fn charset_impl(
    lua: &mlua::Lua,
    left_bound: Value,
    right_bound: Value,
    charset_table: Option<Value>,
) -> mlua::Result<Table> {
    let table = if let Some(Value::Table(t)) = charset_table {
        t
    } else {
        lua.create_table()?
    };

    // Parse left bound
    let left_byte = match left_bound {
        Value::String(s) => {
            let s = s.to_str().map(|s| s.to_string()).unwrap_or_default();
            if s.is_empty() {
                return Err(mlua::Error::RuntimeError(
                    "Left bound string is empty".to_string(),
                ));
            }
            i64::from(s.as_bytes()[0])
        }
        Value::Integer(n) => n,
        _ => {
            return Err(mlua::Error::RuntimeError(
                "Left bound must be a string or number".to_string(),
            ))
        }
    };

    // Parse right bound
    let right_byte = match right_bound {
        Value::String(s) => {
            let s = s.to_str().map(|s| s.to_string()).unwrap_or_default();
            if s.is_empty() {
                return Err(mlua::Error::RuntimeError(
                    "Right bound string is empty".to_string(),
                ));
            }
            i64::from(s.as_bytes()[0])
        }
        Value::Integer(n) => n,
        _ => {
            return Err(mlua::Error::RuntimeError(
                "Right bound must be a string or number".to_string(),
            ))
        }
    };

    let left = usize::try_from(left_byte).unwrap_or(0);
    let right = usize::try_from(right_byte).unwrap_or(0);

    if left > right {
        return Ok(table);
    }

    // Add each character in the range to the table
    let mut seq_idx = 1;
    for byte in left..=right {
        let ch = u8::try_from(byte)
            .map_err(|e| mlua::Error::RuntimeError(format!("Byte value out of range: {e}")))?
            as char;
        table.set(seq_idx, ch.to_string())?;
        seq_idx += 1;
    }

    Ok(table)
}

/// Register the rand library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the rand table
    let rand_table = lua.create_table()?;

    // Register random_string function
    let random_string_fn =
        lua.create_function(|lua, (length, charset): (i64, Option<Value>)| {
            random_string_impl(lua, length, charset)
        })?;
    rand_table.set("random_string", random_string_fn)?;

    // Register random_alpha function - convenience wrapper for lowercase letters
    let random_alpha_fn = lua.create_function(|_lua, length: i64| {
        let length = usize::try_from(length)
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid length: {e}")))?;

        if length == 0 {
            return Ok(String::new());
        }

        // Generate random lowercase alphabetic string
        let charset = "abcdefghijklmnopqrstuvwxyz";
        let mut rng = rand::thread_rng();
        let mut result = String::with_capacity(length);
        for _ in 0..length {
            let idx = rng.gen_range(0..charset.len());
            result.push(charset.as_bytes()[idx] as char);
        }
        Ok(result)
    })?;
    rand_table.set("random_alpha", random_alpha_fn)?;

    // Register charset function
    let charset_fn = lua.create_function(
        |lua, (left_bound, right_bound, charset_table): (Value, Value, Option<Value>)| {
            charset_impl(lua, left_bound, right_bound, charset_table)
        },
    )?;
    rand_table.set("charset", charset_fn)?;

    // Register the library globally as "rand"
    lua.globals().set("rand", rand_table)?;

    tracing::debug!("rand library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string_with_charset() {
        let lua = mlua::Lua::new();
        let result = random_string_impl(
            &lua,
            10,
            Some(Value::String(lua.create_string("abc").unwrap())),
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        let s_str = s.to_str().unwrap();
        assert_eq!(s_str.len(), 10);
        for c in s_str.chars() {
            assert!(c == 'a' || c == 'b' || c == 'c');
        }
    }

    #[test]
    fn test_random_string_empty_length() {
        let lua = mlua::Lua::new();
        let result = random_string_impl(&lua, 0, None::<Value>);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_str().unwrap(), "");
    }

    #[test]
    fn test_random_alpha() {
        let lua = mlua::Lua::new();
        let result = random_string_impl(
            &lua,
            8,
            Some(Value::String(
                lua.create_string("abcdefghijklmnopqrstuvwxyz").unwrap(),
            )),
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        let s_str = s.to_str().unwrap();
        assert_eq!(s_str.len(), 8);
        for c in s_str.chars() {
            assert!(c.is_ascii_lowercase());
        }
    }

    #[test]
    fn test_random_string_binary() {
        // Verify that random_string with no charset returns exact number of raw bytes
        let lua = mlua::Lua::new();
        let result = random_string_impl(&lua, 28, None::<Value>);
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.as_bytes().len(), 28);
    }

    #[test]
    fn test_charset_range() {
        let lua = mlua::Lua::new();
        let result = charset_impl(
            &lua,
            Value::String(lua.create_string("a").unwrap()),
            Value::String(lua.create_string("c").unwrap()),
            None,
        );
        assert!(result.is_ok());
        let table = result.unwrap();
        assert_eq!(table.raw_len(), 3);
    }
}
