//! Auxiliary functions for table manipulation.
//!
//! This module provides the `tableaux` library which contains utility functions
//! for table manipulation in NSE scripts. It corresponds to Nmap's tableaux NSE library.
//!
//! # Functions
//!
//! - `tcopy(t)` - Recursively deep copy a table
//! - `shallow_tcopy(t)` - Copy one level of a table (shallow copy)
//! - `invert(t)` - Invert a one-to-one mapping (swap keys and values)
//! - `contains(t, item, array)` - Check for presence of a value in a table
//! - `keys(t)` - Get the keys of a table as an array
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local tableaux = require "tableaux"
//!
//! -- Deep copy a table
//! local copy = tableaux.tcopy(original)
//!
//! -- Check if table contains value
//! local found, key = tableaux.contains({"a", "b", "c"}, "b")
//! -- Result: found=true, key=2
//!
//! -- Get all keys
//! local k = tableaux.keys({name="Alice", age=30})
//! -- Result: {"name", "age"}
//! ```

use mlua::{Lua, Table, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Recursively copy a table (deep copy).
///
/// Uses simple assignment to copy keys and values from a table, recursing into
/// subtables as necessary.
///
/// # Arguments
///
/// * `lua` - Lua state
/// * `t` - The table to copy
///
/// # Returns
///
/// A deep copy of the table.
fn tcopy_impl(lua: &Lua, t: &Table) -> mlua::Result<Table> {
    let copy = lua.create_table()?;

    for pair in t.pairs::<Value, Value>() {
        let (k, v) = pair?;
        let new_val = match v {
            Value::Table(inner_table) => Value::Table(tcopy_impl(lua, &inner_table)?),
            other => other,
        };
        copy.set(k, new_val)?;
    }

    Ok(copy)
}

/// Copy one level of a table (shallow copy).
///
/// Iterates over the keys of a table and copies their values into a new table.
/// If any values are tables, they are copied by reference only, and modifying
/// the copy will modify the original table value as well.
///
/// # Arguments
///
/// * `lua` - Lua state
/// * `t` - The table to copy
///
/// # Returns
///
/// A shallow copy of the table.
fn shallow_tcopy_impl(lua: &Lua, t: &Table) -> mlua::Result<Table> {
    let copy = lua.create_table()?;

    for pair in t.pairs::<Value, Value>() {
        let (k, v) = pair?;
        copy.set(k, v)?;
    }

    Ok(copy)
}

/// Invert a one-to-one mapping.
///
/// Swaps keys and values in a table.
///
/// # Arguments
///
/// * `lua` - Lua state
/// * `t` - The table to invert
///
/// # Returns
///
/// An inverted mapping where original values become keys and vice versa.
fn invert_impl(lua: &Lua, t: &Table) -> mlua::Result<Table> {
    let inverted = lua.create_table()?;

    for pair in t.pairs::<Value, Value>() {
        let (k, v) = pair?;
        inverted.set(v, k)?;
    }

    Ok(inverted)
}

/// Check for the presence of a value in a table.
///
/// # Arguments
///
/// * `_lua` - Lua state (unused, kept for API consistency)
/// * `t` - The table to search
/// * `item` - The searched value
/// * `array` - If true, use ipairs to only search array indices
///
/// # Returns
///
/// A tuple of:
/// - Boolean `true` if the item was found, `false` if not
/// - The index or key where the value was found, or `nil`
fn contains_impl(
    _lua: &Lua,
    t: &Table,
    item: &Value,
    array: Option<bool>,
) -> mlua::Result<(bool, Value)> {
    let use_ipairs = array.unwrap_or(false);

    if use_ipairs {
        // Only search array indices using ipairs equivalent
        let mut idx: i64 = 1;
        loop {
            let val: Value = t.get(idx)?;
            if matches!(val, Value::Nil) {
                break;
            }
            if &val == item {
                return Ok((true, Value::Integer(idx)));
            }
            idx += 1;
        }
    } else {
        // Search all keys using pairs
        for pair in t.pairs::<Value, Value>() {
            let (k, v) = pair?;
            if &v == item {
                return Ok((true, k));
            }
        }
    }

    Ok((false, Value::Nil))
}

/// Get the keys of a table as an array.
///
/// # Arguments
///
/// * `lua` - Lua state
/// * `t` - The table
///
/// # Returns
///
/// A table (array) containing all keys from the input table.
fn keys_impl(lua: &Lua, t: &Table) -> mlua::Result<Table> {
    let result = lua.create_table()?;

    let mut idx: i64 = 1;
    for pair in t.pairs::<Value, Value>() {
        let (k, _v) = pair?;
        result.set(idx, k)?;
        idx += 1;
    }

    Ok(result)
}

/// Register the tableaux library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the tableaux table
    let tableaux_table = lua.create_table()?;

    // Register tcopy function
    let tcopy_fn = lua.create_function(|lua, t: Table| tcopy_impl(lua, &t))?;
    tableaux_table.set("tcopy", tcopy_fn)?;

    // Register shallow_tcopy function
    let shallow_tcopy_fn = lua.create_function(|lua, t: Table| shallow_tcopy_impl(lua, &t))?;
    tableaux_table.set("shallow_tcopy", shallow_tcopy_fn)?;

    // Register invert function
    let invert_fn = lua.create_function(|lua, t: Table| invert_impl(lua, &t))?;
    tableaux_table.set("invert", invert_fn)?;

    // Register contains function
    let contains_fn =
        lua.create_function(|lua, (t, item, array): (Table, Value, Option<bool>)| {
            contains_impl(lua, &t, &item, array)
        })?;
    tableaux_table.set("contains", contains_fn)?;

    // Register keys function
    let keys_fn = lua.create_function(|lua, t: Table| keys_impl(lua, &t))?;
    tableaux_table.set("keys", keys_fn)?;

    // Register the library globally as "tableaux"
    lua.globals().set("tableaux", tableaux_table)?;

    tracing::debug!("tableaux library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcopy_simple() {
        let lua = Lua::new();
        let original = lua.create_table().unwrap();
        original.set("name", "test").unwrap();
        original.set("value", 42).unwrap();

        let copy = tcopy_impl(&lua, &original).unwrap();

        // Verify copy has same values
        let name: String = copy.get("name").unwrap();
        let value: i64 = copy.get("value").unwrap();
        assert_eq!(name, "test");
        assert_eq!(value, 42);

        // Modify original and verify copy is independent
        original.set("name", "modified").unwrap();
        let copy_name: String = copy.get("name").unwrap();
        assert_eq!(copy_name, "test");
    }

    #[test]
    fn test_tcopy_nested() {
        let lua = Lua::new();
        let original = lua.create_table().unwrap();
        let nested = lua.create_table().unwrap();
        nested.set("inner", "value").unwrap();
        original.set("nested", nested).unwrap();

        let copy = tcopy_impl(&lua, &original).unwrap();

        // Modify original nested table
        let orig_nested: Table = original.get("nested").unwrap();
        orig_nested.set("inner", "modified").unwrap();

        // Verify copy's nested table is independent
        let copy_nested: Table = copy.get("nested").unwrap();
        let inner: String = copy_nested.get("inner").unwrap();
        assert_eq!(inner, "value");
    }

    #[test]
    fn test_shallow_tcopy() {
        let lua = Lua::new();
        let original = lua.create_table().unwrap();
        original.set("a", 1).unwrap();
        original.set("b", 2).unwrap();

        let copy = shallow_tcopy_impl(&lua, &original).unwrap();

        let a: i64 = copy.get("a").unwrap();
        let b: i64 = copy.get("b").unwrap();
        assert_eq!(a, 1);
        assert_eq!(b, 2);
    }

    #[test]
    fn test_shallow_tcopy_nested_reference() {
        let lua = Lua::new();
        let original = lua.create_table().unwrap();
        let nested = lua.create_table().unwrap();
        nested.set("inner", "value").unwrap();
        original.set("nested", nested.clone()).unwrap();

        let copy = shallow_tcopy_impl(&lua, &original).unwrap();

        // Modify original nested table
        let orig_nested: Table = original.get("nested").unwrap();
        orig_nested.set("inner", "modified").unwrap();

        // Shallow copy shares nested table reference
        let copy_nested: Table = copy.get("nested").unwrap();
        let inner: String = copy_nested.get("inner").unwrap();
        assert_eq!(inner, "modified");
    }

    #[test]
    fn test_invert() {
        let lua = Lua::new();
        let original = lua.create_table().unwrap();
        original.set("a", "1").unwrap();
        original.set("b", "2").unwrap();

        let inverted = invert_impl(&lua, &original).unwrap();

        let a: String = inverted.get("1").unwrap();
        let b: String = inverted.get("2").unwrap();
        assert_eq!(a, "a");
        assert_eq!(b, "b");
    }

    #[test]
    fn test_contains_found() {
        let lua = Lua::new();
        let table = lua.create_table().unwrap();
        table.set(1, "a").unwrap();
        table.set(2, "b").unwrap();
        table.set(3, "c").unwrap();

        let result = contains_impl(
            &lua,
            &table,
            &Value::String(lua.create_string("b").unwrap()),
            Some(false),
        );
        assert!(result.is_ok());
        let (found, key) = result.unwrap();
        assert!(found);
        assert_eq!(key, Value::Integer(2));
    }

    #[test]
    fn test_contains_not_found() {
        let lua = Lua::new();
        let table = lua.create_table().unwrap();
        table.set(1, "a").unwrap();
        table.set(2, "b").unwrap();

        let result = contains_impl(
            &lua,
            &table,
            &Value::String(lua.create_string("z").unwrap()),
            Some(false),
        );
        assert!(result.is_ok());
        let (found, _key) = result.unwrap();
        assert!(!found);
    }

    #[test]
    fn test_contains_array_mode() {
        let lua = Lua::new();
        let table = lua.create_table().unwrap();
        table.set(1, "a").unwrap();
        table.set(2, "b").unwrap();
        table.set("key", "c").unwrap(); // Non-array key

        // Array mode should not find "c"
        let result = contains_impl(
            &lua,
            &table,
            &Value::String(lua.create_string("c").unwrap()),
            Some(true),
        );
        assert!(result.is_ok());
        let (found, _key) = result.unwrap();
        assert!(!found);

        // Non-array mode should find "c"
        let result = contains_impl(
            &lua,
            &table,
            &Value::String(lua.create_string("c").unwrap()),
            Some(false),
        );
        assert!(result.is_ok());
        let (found, _key) = result.unwrap();
        assert!(found);
    }

    #[test]
    fn test_keys() {
        let lua = Lua::new();
        let table = lua.create_table().unwrap();
        table.set("name", "Alice").unwrap();
        table.set("age", 30).unwrap();

        let keys = keys_impl(&lua, &table).unwrap();

        assert_eq!(keys.raw_len(), 2);

        // Collect keys into a set (extract string values)
        let mut key_set = std::collections::HashSet::new();
        for pair in keys.sequence_values::<mlua::String>() {
            if let Ok(s) = pair {
                if let Ok(str_val) = s.to_str() {
                    key_set.insert(str_val.to_string());
                }
            }
        }
        // For string keys, they should be present
        assert!(key_set.contains("name") || key_set.contains("age"));
    }

    #[test]
    fn test_register() {
        let mut nse_lua = NseLua::new_default().unwrap();
        let result = register(&mut nse_lua);
        assert!(result.is_ok());

        // Verify library is registered
        let tableaux: Value = nse_lua.lua().globals().get("tableaux").unwrap();
        assert!(!matches!(tableaux, Value::Nil));
    }
}
