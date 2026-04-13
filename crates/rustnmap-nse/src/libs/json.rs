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

//! JSON library for NSE.
//!
//! This module provides the `json` library which contains functions for
//! handling JSON data. It supports JSON encoding and decoding according to
//! RFC 4627.
//!
//! # Available Functions
//!
//! - `json.parse(data)` - Parse JSON string into Lua table
//! - `json.generate(data)` - Generate JSON string from Lua table
//! - `json.make_array(t)` - Mark a table as JSON array
//! - `json.make_object(t)` - Mark a table as JSON object
//! - `json.typeof(var)` - Get JSON type of a variable
//!
//! # Special Values
//!
//! - `json.NULL` - Represents JSON null (different from Lua nil)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! -- Parse JSON
//! local status, result = json.parse('{"name": "value"}')
//! if status then
//!   print(result.name)
//! end
//!
//! -- Generate JSON
//! local data = {name = "value", count = 42}
//! local json_str = json.generate(data)
//!
//! -- Mark table as array
//! local arr = json.make_array({1, 2, 3})
//! local json_arr = json.generate(arr)
//!
//! -- Check type
//! print(json.typeof({1, 2, 3}))  -- "array"
//! print(json.typeof({x = 1}))     -- "object"
//! ```

use mlua::{IntoLua, Table, UserData, Value};
use serde_json::{Number as JsonNumber, Value as JsonValue};

use crate::error::Result;
use crate::lua::NseLua;

/// Special userdata type representing JSON null.
///
/// This is used to distinguish JSON null from Lua nil, since Lua nil
/// represents JavaScript undefined more closely.
#[derive(Debug, Clone, Copy)]
struct JsonNull;

impl UserData for JsonNull {}

/// Marker key for JSON type stored directly in tables.
const MARKER_JSON_TYPE: &str = "__json_type";

/// Marker value for JSON array type.
const TYPE_ARRAY: &str = "array";

/// Marker value for JSON object type.
const TYPE_OBJECT: &str = "object";

/// Convert a `Lua` value to a `serde_json` `Value`.
///
/// # Arguments
///
/// * `value` - The Lua value to convert
///
/// # Returns
///
/// * `Result<JsonValue>` - The corresponding JSON value
fn lua_value_to_json(value: &Value) -> Result<JsonValue> {
    match value {
        Value::Nil => Ok(JsonValue::Null),
        Value::Boolean(b) => Ok(JsonValue::Bool(*b)),
        Value::Integer(i) => Ok(JsonValue::Number(JsonNumber::from(*i))),
        Value::Number(n) => {
            // mlua::Number is f64, try to convert to integer if it's a whole number
            #[expect(
                clippy::cast_precision_loss,
                reason = "i64::MIN/MAX need to be compared with f64"
            )]
            if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "Already checked that value is in i64 range and is whole number"
                )]
                Ok(JsonValue::Number(JsonNumber::from(*n as i64)))
            } else if n.is_finite() {
                Ok(JsonValue::Number(JsonNumber::from_f64(*n).ok_or_else(
                    || {
                        mlua::Error::RuntimeError(
                            "Number cannot be represented as JSON".to_string(),
                        )
                    },
                )?))
            } else {
                // NaN or Infinity - convert to null as per JSON spec
                Ok(JsonValue::Null)
            }
        }
        Value::String(s) => Ok(JsonValue::String(s.to_string_lossy().to_string())),
        Value::Table(t) => {
            // Check if table has a JSON type marker
            let is_array = if let Ok(Value::String(marker)) = t.get(MARKER_JSON_TYPE) {
                marker == TYPE_ARRAY
            } else {
                // No marker, check if it's array-like
                is_array_like(t)
            };

            if is_array {
                let mut arr = Vec::new();
                // Iterate over all pairs and only include numeric keys
                for pair in t.clone().pairs::<Value, Value>() {
                    let (k, v) = pair?;
                    match k {
                        Value::Integer(i) if i > 0 => {
                            #[expect(clippy::cast_sign_loss, reason = "Already checked that i > 0")]
                            #[expect(
                                clippy::cast_possible_truncation,
                                reason = "Already checked that i > 0 and usize is 64-bit on target platform"
                            )]
                            let idx = i as usize;
                            // Ensure array is large enough
                            if arr.len() < idx {
                                arr.resize(idx, JsonValue::Null);
                            }
                            arr[idx - 1] = lua_value_to_json(&v)?;
                        }
                        _ => {
                            // Skip non-integer keys for arrays
                        }
                    }
                }
                Ok(JsonValue::Array(arr))
            } else {
                let mut obj = serde_json::Map::new();
                for pair in t.clone().pairs::<String, Value>() {
                    let (k, v) = pair?;
                    // Skip the internal marker key
                    if k == MARKER_JSON_TYPE {
                        continue;
                    }
                    obj.insert(k, lua_value_to_json(&v)?);
                }
                Ok(JsonValue::Object(obj))
            }
        }
        Value::Function(_) => {
            Err(mlua::Error::RuntimeError("Cannot convert function to JSON".to_string()).into())
        }
        Value::Thread(_) => {
            Err(mlua::Error::RuntimeError("Cannot convert thread to JSON".to_string()).into())
        }
        Value::UserData(ud) => {
            // Check if it's JsonNull
            if ud.is::<JsonNull>() {
                Ok(JsonValue::Null)
            } else {
                Err(mlua::Error::RuntimeError("Cannot convert userdata to JSON".to_string()).into())
            }
        }
        Value::LightUserData(_) => Err(mlua::Error::RuntimeError(
            "Cannot convert lightuserdata to JSON".to_string(),
        )
        .into()),
        Value::Error(_) => {
            Err(mlua::Error::RuntimeError("Cannot convert error to JSON".to_string()).into())
        }
        Value::Other(_) => Err(mlua::Error::RuntimeError(
            "Cannot convert unknown value to JSON".to_string(),
        )
        .into()),
    }
}

/// Check if a table looks like an array (has sequential numeric keys starting from 1).
#[expect(
    clippy::manual_let_else,
    reason = "Match pattern with early return is clearer here"
)]
fn is_array_like(table: &Table) -> bool {
    // Check length - returns Result
    let len = match table.len() {
        Ok(l) => l,
        Err(_) => return false,
    };

    if len == 0 {
        // Empty table could be either, but we'll treat it as object by default
        // unless it has the array marker
        return false;
    }

    // Check if all keys are sequential integers from 1 to len
    for pair in table.clone().pairs::<Value, Value>() {
        #[expect(
            clippy::manual_let_else,
            reason = "Match pattern with early return is clearer here"
        )]
        let (k, _) = match pair {
            Ok(p) => p,
            Err(_) => return false,
        };
        match k {
            Value::Integer(i) => {
                if i < 1 || i > len {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

/// Convert a `serde_json` Value to a Lua value.
///
/// # Arguments
///
/// * `lua` - The Lua instance
/// * `json_value` - The JSON value to convert
///
/// # Returns
///
/// * `Result<Value>` - The corresponding Lua value
fn json_value_to_lua(lua: &mlua::Lua, json_value: &JsonValue) -> Result<Value> {
    match json_value {
        JsonValue::Null => {
            // Return JsonNull userdata instead of nil
            Ok(JsonNull.into_lua(lua)?)
        }
        JsonValue::Bool(b) => Ok(Value::Boolean(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Number(f))
            } else {
                // Handle special numbers (NaN, Infinity) - convert to null
                Ok(Value::Nil)
            }
        }
        JsonValue::String(s) => Ok(Value::String(lua.create_string(s)?)),
        JsonValue::Array(arr) => {
            let table = lua.create_table()?;
            for (i, item) in arr.iter().enumerate() {
                let lua_value = json_value_to_lua(lua, item)?;
                table.raw_set(i + 1, lua_value)?;
            }
            // Mark as array
            table.set(MARKER_JSON_TYPE, TYPE_ARRAY)?;
            Ok(Value::Table(table))
        }
        JsonValue::Object(obj) => {
            let table = lua.create_table()?;
            #[expect(
                clippy::explicit_iter_loop,
                reason = "Need both key and value from serde_json Map"
            )]
            for (k, v) in obj.iter() {
                let lua_value = json_value_to_lua(lua, v)?;
                table.raw_set(k.as_str(), lua_value)?;
            }
            // Mark as object
            table.set(MARKER_JSON_TYPE, TYPE_OBJECT)?;
            Ok(Value::Table(table))
        }
    }
}

/// Register the json library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the json table
    let json_table = lua.create_table()?;

    // Register json.NULL
    let null_userdata = JsonNull;
    json_table.set("NULL", null_userdata)?;

    // Register json.parse(data) -> (status, result_or_error)
    let parse_fn =
        lua.create_function(
            |lua, data: String| match serde_json::from_str::<JsonValue>(&data) {
                Ok(json_value) => match json_value_to_lua(lua, &json_value) {
                    Ok(lua_value) => Ok((true, lua_value)),
                    Err(e) => Ok((false, Value::String(lua.create_string(e.to_string())?))),
                },
                Err(e) => Ok((
                    false,
                    Value::String(lua.create_string(format!("JSON parse error: {e}"))?),
                )),
            },
        )?;
    json_table.set("parse", parse_fn)?;

    // Register json.generate(data) -> json_string
    let generate_fn = lua.create_function(|_, value: Value| {
        let json_value = lua_value_to_json(&value)
            .map_err(|e| mlua::Error::RuntimeError(format!("JSON generate error: {e}")))?;

        // Use to_string() for compact JSON (no pretty printing)
        serde_json::to_string(&json_value)
            .map_err(|e| mlua::Error::RuntimeError(format!("JSON serialization error: {e}")))
    })?;
    json_table.set("generate", generate_fn)?;

    // Register json.make_array(t) -> t
    let make_array_fn = lua.create_function(|_, table: Table| {
        table.set(MARKER_JSON_TYPE, TYPE_ARRAY)?;
        Ok(table)
    })?;
    json_table.set("make_array", make_array_fn)?;

    // Register json.make_object(t) -> t
    let make_object_fn = lua.create_function(|_, table: Table| {
        table.set(MARKER_JSON_TYPE, TYPE_OBJECT)?;
        Ok(table)
    })?;
    json_table.set("make_object", make_object_fn)?;

    // Register json.typeof(var) -> type_string
    let typeof_fn = lua.create_function(|_, value: Value| {
        match value {
            Value::UserData(ud) if ud.is::<JsonNull>() => Ok("null"),
            Value::Nil => Ok("nil"),
            Value::Boolean(_) => Ok("boolean"),
            Value::Integer(_) | Value::Number(_) => Ok("number"),
            Value::String(_) => Ok("string"),
            Value::Table(t) => {
                // Check for type marker first
                if let Ok(Value::String(marker)) = t.get(MARKER_JSON_TYPE) {
                    if let Ok(s) = marker.to_str() {
                        if s == TYPE_ARRAY {
                            return Ok("array");
                        } else if s == TYPE_OBJECT {
                            return Ok("object");
                        }
                    }
                }
                // Determine based on content
                if is_array_like(&t) {
                    Ok("array")
                } else {
                    Ok("object")
                }
            }
            _ => Ok("unknown"),
        }
    })?;
    json_table.set("typeof", typeof_fn)?;

    // Set the json table in globals
    lua.globals().set("json", json_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        // Check that json module exists
        let lua = nse_lua.lua();
        let json_table: Table = lua.globals().get("json").unwrap();
        assert!(json_table.contains_key("parse").unwrap());
        assert!(json_table.contains_key("generate").unwrap());
        assert!(json_table.contains_key("make_array").unwrap());
        assert!(json_table.contains_key("make_object").unwrap());
        assert!(json_table.contains_key("typeof").unwrap());
        assert!(json_table.contains_key("NULL").unwrap());
    }

    #[test]
    fn test_parse_simple_object() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let result: (bool, mlua::Value) = lua
            .load("return json.parse('{\"name\": \"value\"}')")
            .eval()
            .unwrap();

        assert!(result.0);
        if let mlua::Value::Table(t) = result.1 {
            let name: String = t.get("name").unwrap();
            assert_eq!(name, "value");
        } else {
            panic!("Expected table");
        }
    }

    #[test]
    fn test_parse_simple_array() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let result: (bool, mlua::Value) =
            lua.load("return json.parse('[1, 2, 3]')").eval().unwrap();

        assert!(result.0);
        if let mlua::Value::Table(t) = result.1 {
            let first: i64 = t.get(1).unwrap();
            assert_eq!(first, 1);
        } else {
            panic!("Expected table");
        }
    }

    #[test]
    fn test_parse_null() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let result: (bool, mlua::Value) = lua.load("return json.parse('null')").eval().unwrap();

        assert!(result.0);
        // Check that it's JSON NULL (userdata), not Lua nil
        match result.1 {
            mlua::Value::UserData(ud) => assert!(ud.is::<JsonNull>()),
            mlua::Value::Nil => panic!("Got Lua nil instead of JSON NULL"),
            _ => panic!("Expected userdata (JsonNull)"),
        }
    }

    #[test]
    fn test_generate_simple_object() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let json_str: String = lua
            .load("return json.generate({name = \"value\"})")
            .eval()
            .unwrap();

        // Parse and verify
        if let Ok(JsonValue::Object(obj)) = serde_json::from_str::<JsonValue>(&json_str) {
            assert_eq!(
                obj.get("name"),
                Some(&JsonValue::String("value".to_string()))
            );
        } else {
            panic!("Generated invalid JSON");
        }
    }

    #[test]
    fn test_generate_simple_array() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let json_str: String = lua.load("return json.generate({1, 2, 3})").eval().unwrap();

        // Parse and verify
        if let Ok(JsonValue::Array(arr)) = serde_json::from_str::<JsonValue>(&json_str) {
            assert_eq!(arr.len(), 3);
        } else {
            panic!("Generated invalid JSON");
        }
    }

    #[test]
    fn test_generate_null() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let json_str: String = lua.load("return json.generate(json.NULL)").eval().unwrap();

        assert_eq!(json_str, "null");
    }

    #[test]
    fn test_typeof_array() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let typeof_result: String = lua.load("return json.typeof({1, 2, 3})").eval().unwrap();

        assert_eq!(typeof_result, "array");
    }

    #[test]
    fn test_typeof_object() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let typeof_result: String = lua.load("return json.typeof({x = 1})").eval().unwrap();

        assert_eq!(typeof_result, "object");
    }

    #[test]
    fn test_typeof_null() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let typeof_result: String = lua.load("return json.typeof(json.NULL)").eval().unwrap();

        assert_eq!(typeof_result, "null");
    }

    #[test]
    fn test_make_array() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let json_str: String = lua
            .load("return json.generate(json.make_array({x = 1, y = 2}))")
            .eval()
            .unwrap();

        // Should be treated as array, so non-numeric keys are ignored
        // Empty array or array with nil values
        let parsed: JsonValue = serde_json::from_str(&json_str).unwrap();
        assert!(matches!(parsed, JsonValue::Array(_)));
    }

    #[test]
    fn test_make_object() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let json_str: String = lua
            .load("return json.generate(json.make_object({1, 2, 3}))")
            .eval()
            .unwrap();

        // Should be treated as object, so numeric keys are stringified
        let parsed: JsonValue = serde_json::from_str(&json_str).unwrap();
        assert!(matches!(parsed, JsonValue::Object(_)));
    }

    #[test]
    fn test_parse_error() {
        let mut nse_lua = NseLua::new_default().unwrap();
        register(&mut nse_lua).unwrap();

        let lua = nse_lua.lua();
        let result: (bool, String) = lua
            .load("return json.parse('{invalid json}')")
            .eval()
            .unwrap();

        assert!(!result.0);
        assert!(result.1.contains("JSON parse error"));
    }
}
