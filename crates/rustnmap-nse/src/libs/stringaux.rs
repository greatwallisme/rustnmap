//! Auxiliary functions for string manipulation.
//!
//! This module provides the `stringaux` library which contains utility functions
//! for string manipulation in NSE scripts. It corresponds to Nmap's stringaux NSE library.
//!
//! # Functions
//!
//! - `strjoin(delimiter, list)` - Join a list of strings with a separator
//! - `strsplit(pattern, text)` - Split a string at a given delimiter pattern
//! - `filename_escape(s)` - Escape a string for filesystem safety
//! - `ipattern(pattern)` - Convert a pattern to case-insensitive form
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local stringaux = require "stringaux"
//!
//! -- Join strings
//! local joined = stringaux.strjoin(", ", {"Anna", "Bob", "Charlie"})
//! -- Result: "Anna, Bob, Charlie"
//!
//! -- Split string
//! local parts = stringaux.strsplit(",%s*", "Anna, Bob, Charlie")
//! -- Result: {"Anna", "Bob", "Charlie"}
//!
//! -- Escape filename
//! local safe = stringaux.filename_escape("input/output")
//! -- Result: "input%2foutput"
//!
//! -- Case-insensitive pattern
//! local ipat = stringaux.ipattern("user")
//! -- Result: "[uU][sS][eE][rR]"
//! ```

use std::fmt::Write;

use mlua::{Lua, Table, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Join a list of strings with a separator string.
///
/// This is Lua's `table.concat` function with the parameters swapped for coherence.
///
/// # Arguments
///
/// * `delimiter` - String to delimit each element of the list
/// * `list` - Array of strings to concatenate
///
/// # Returns
///
/// Concatenated string.
///
/// # Errors
///
/// Returns an error if delimiter is not a string or nil, or if list is not a table.
fn strjoin_impl(_lua: &Lua, delimiter: Option<Value>, list: &Table) -> mlua::Result<String> {
    // Validate delimiter type
    match &delimiter {
        None | Some(Value::String(_)) => {}
        Some(_) => {
            return Err(mlua::Error::RuntimeError(
                "delimiter is of the wrong type! (did you get the parameters backward?)"
                    .to_string(),
            ));
        }
    }

    // Collect string values from table
    let mut parts = Vec::new();
    for pair in list.sequence_values::<Value>() {
        let val = pair?;
        match val {
            Value::String(s) => {
                parts.push(s.to_str().map(|s| s.to_string()).unwrap_or_default());
            }
            Value::Nil => break,
            _ => {
                return Err(mlua::Error::RuntimeError(
                    "list must contain only strings".to_string(),
                ));
            }
        }
    }

    // Join with delimiter
    let delim = match delimiter {
        Some(Value::String(s)) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        _ => String::new(),
    };

    Ok(parts.join(&delim))
}

/// Split a string at a given delimiter pattern.
///
/// If you want to loop over the resulting values, consider using `string.gmatch` instead.
///
/// # Arguments
///
/// * `pattern` - Lua pattern that separates the desired strings
/// * `text` - String to split
///
/// # Returns
///
/// Array of substrings without the separating pattern.
///
/// # Errors
///
/// Returns an error if pattern matches empty string.
fn strsplit_impl(lua: &Lua, pattern: &str, text: &str) -> mlua::Result<Table> {
    if pattern.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "delimiter matches empty string!".to_string(),
        ));
    }

    let result = lua.create_table()?;

    // Use Lua's string.find to find pattern matches
    let string_mod: Table = lua.globals().get("string")?;

    // Use i64 for positions to match Lua's number type
    let mut pos: i64 = 1;
    let mut idx: i64 = 1;
    let text_len = i64::try_from(text.len()).unwrap_or(i64::MAX);

    // Get find function
    let find_fn: mlua::Function = string_mod.get("find")?;

    while pos <= text_len {
        // Call string.find(text, pattern, pos)
        let find_result: Value = find_fn.call((text, pattern, pos))?;

        match find_result {
            Value::Nil => {
                // No more matches - add remaining text
                let sub_fn: mlua::Function = string_mod.get("sub")?;
                let remaining: String = sub_fn.call((text, pos))?;
                result.set(idx, remaining)?;
                break;
            }
            Value::Integer(first) => {
                // Single return value (no captures) - this shouldn't happen for find
                let sub_fn: mlua::Function = string_mod.get("sub")?;
                let remaining: String = sub_fn.call((text, pos, first - 1))?;
                result.set(idx, remaining)?;
                idx += 1;
                pos = first + 1;
            }
            Value::Table(t) => {
                // Multiple return values: first, last, ...
                let first: i64 = t.get(1)?;
                let last: i64 = t.get(2)?;

                // Get substring before match
                let sub_fn: mlua::Function = string_mod.get("sub")?;
                let before: String = sub_fn.call((text, pos, first - 1))?;
                result.set(idx, before)?;
                idx += 1;
                pos = last + 1;
            }
            _ => {
                // Unexpected return type
                let sub_fn: mlua::Function = string_mod.get("sub")?;
                let remaining: String = sub_fn.call((text, pos))?;
                result.set(idx, remaining)?;
                break;
            }
        }
    }

    Ok(result)
}

/// Escape a string to remove bytes and strings that may have meaning to a filesystem.
///
/// All bytes are escaped, except for:
/// - alphabetic `a`-`z` and `A`-`Z`
/// - digits 0-9
/// - `.` `_` `-`
///
/// In addition, the strings `"."` and `".."` have their characters escaped.
///
/// Bytes are escaped by a percent sign followed by the two-digit hexadecimal representation
/// of the byte value.
///
/// # Arguments
///
/// * `s` - String to escape
///
/// # Returns
///
/// Escaped string safe for use as a filename.
fn filename_escape_impl(s: &str) -> String {
    // Special cases for "." and ".."
    if s == "." {
        return "%2e".to_string();
    }
    if s == ".." {
        return "%2e%2e".to_string();
    }

    let mut result = String::with_capacity(s.len() * 3);

    for byte in s.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            result.push(ch);
        } else {
            // Use write! to avoid allocation from format!
            let _ = std::write!(result, "%{byte:02x}");
        }
    }

    result
}

/// Convert a pattern to case-insensitive form.
///
/// Useful while doing case insensitive pattern match using string library.
///
/// # Arguments
///
/// * `pattern` - The pattern string
///
/// # Returns
///
/// A case-insensitive pattern string where each alphabetic character is replaced
/// with a character class like `[aA]`.
fn ipattern_impl(lua: &Lua, pattern: &str) -> mlua::Result<String> {
    let string_mod: Table = lua.globals().get("string")?;
    let lower_fn: mlua::Function = string_mod.get("lower")?;
    let upper_fn: mlua::Function = string_mod.get("upper")?;

    let mut result = String::with_capacity(pattern.len() * 4);
    let mut in_brackets = false;
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        // Check for %-escape
        if ch == '%' && i + 1 < chars.len() {
            // It's a %-escape, keep both characters as-is
            result.push(ch);
            result.push(chars[i + 1]);
            i += 2;
            continue;
        }

        // Track bracket state
        if ch == '[' {
            in_brackets = true;
            result.push(ch);
            i += 1;
            continue;
        }
        if ch == ']' {
            in_brackets = false;
            result.push(ch);
            i += 1;
            continue;
        }

        // Check if alphabetic
        if ch.is_ascii_alphabetic() && !in_brackets {
            // Create case-insensitive character class
            let lower: String = lower_fn.call(ch.to_string())?;
            let upper: String = upper_fn.call(ch.to_string())?;
            result.push('[');
            result.push_str(&lower);
            result.push_str(&upper);
            result.push(']');
        } else {
            result.push(ch);
        }

        i += 1;
    }

    Ok(result)
}

/// Register the stringaux library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the stringaux table
    let stringaux_table = lua.create_table()?;

    // Register strjoin function
    let strjoin_fn = lua.create_function(|lua, (delimiter, list): (Option<Value>, Table)| {
        strjoin_impl(lua, delimiter, &list)
    })?;
    stringaux_table.set("strjoin", strjoin_fn)?;

    // Register strsplit function
    let strsplit_fn = lua.create_function(|lua, (pattern, text): (String, String)| {
        strsplit_impl(lua, &pattern, &text)
    })?;
    stringaux_table.set("strsplit", strsplit_fn)?;

    // Register filename_escape function
    let filename_escape_fn = lua.create_function(|_lua, s: String| Ok(filename_escape_impl(&s)))?;
    stringaux_table.set("filename_escape", filename_escape_fn)?;

    // Register ipattern function
    let ipattern_fn = lua.create_function(|lua, pattern: String| ipattern_impl(lua, &pattern))?;
    stringaux_table.set("ipattern", ipattern_fn)?;

    // Register the library globally as "stringaux"
    lua.globals().set("stringaux", stringaux_table)?;

    tracing::debug!("stringaux library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_lua() -> Lua {
        let lua = Lua::new();
        // Ensure string library is available
        lua.load(
            r#"
            local string = require "string"
        "#,
        )
        .exec()
        .ok();
        lua
    }

    #[test]
    fn test_strjoin_basic() {
        let lua = setup_lua();
        let list = lua.create_table().unwrap();
        list.set(1, "Anna").unwrap();
        list.set(2, "Bob").unwrap();
        list.set(3, "Charlie").unwrap();

        let result = strjoin_impl(
            &lua,
            Some(Value::String(lua.create_string(", ").unwrap())),
            &list,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Anna, Bob, Charlie");
    }

    #[test]
    fn test_strjoin_empty_delimiter() {
        let lua = setup_lua();
        let list = lua.create_table().unwrap();
        list.set(1, "a").unwrap();
        list.set(2, "b").unwrap();
        list.set(3, "c").unwrap();

        let result = strjoin_impl(&lua, None, &list);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc");
    }

    #[test]
    fn test_strjoin_wrong_type() {
        let lua = setup_lua();
        let list = lua.create_table().unwrap();
        list.set(1, "a").unwrap();

        let result = strjoin_impl(&lua, Some(Value::Integer(123)), &list);
        assert!(result.is_err());
    }

    #[test]
    fn test_strsplit_basic() {
        let lua = setup_lua();
        // Use simple comma separator (not Lua pattern)
        let result = strsplit_impl(&lua, ",", "Anna,Bob,Charlie");
        assert!(result.is_ok());
        let table = result.unwrap();
        assert_eq!(table.raw_len(), 3);

        let v1: String = table.get(1).unwrap();
        let v2: String = table.get(2).unwrap();
        let v3: String = table.get(3).unwrap();
        assert_eq!(v1, "Anna");
        assert_eq!(v2, "Bob");
        assert_eq!(v3, "Charlie");
    }

    #[test]
    fn test_strsplit_empty_pattern() {
        let lua = setup_lua();
        let result = strsplit_impl(&lua, "", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_filename_escape_basic() {
        assert_eq!(filename_escape_impl("filename.ext"), "filename.ext");
        assert_eq!(filename_escape_impl("input/output"), "input%2foutput");
        assert_eq!(filename_escape_impl("."), "%2e");
        assert_eq!(filename_escape_impl(".."), "%2e%2e");
    }

    #[test]
    fn test_filename_escape_special_chars() {
        assert_eq!(filename_escape_impl("hello world"), "hello%20world");
        assert_eq!(filename_escape_impl("file.txt"), "file.txt");
        assert_eq!(filename_escape_impl("my-file_name.txt"), "my-file_name.txt");
    }

    #[test]
    fn test_ipattern_basic() {
        let lua = setup_lua();
        let result = ipattern_impl(&lua, "user");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "[uU][sS][eE][rR]");
    }

    #[test]
    fn test_ipattern_with_escape() {
        let lua = setup_lua();
        let result = ipattern_impl(&lua, "%d+");
        assert!(result.is_ok());
        // %d should stay as-is because it's an escape sequence
        assert_eq!(result.unwrap(), "%d+");
    }

    #[test]
    fn test_ipattern_with_brackets() {
        let lua = setup_lua();
        let result = ipattern_impl(&lua, "[abc]");
        assert!(result.is_ok());
        // Characters inside brackets should stay as-is
        assert_eq!(result.unwrap(), "[abc]");
    }

    #[test]
    fn test_register() {
        let mut nse_lua = NseLua::new_default().unwrap();
        let result = register(&mut nse_lua);
        assert!(result.is_ok());

        // Verify library is registered
        let stringaux: Value = nse_lua.lua().globals().get("stringaux").unwrap();
        assert!(!matches!(stringaux, Value::Nil));
    }
}
