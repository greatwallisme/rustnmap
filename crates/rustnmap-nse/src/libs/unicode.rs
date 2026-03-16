//! Unicode library for NSE.
//!
//! This module provides the `unicode` library which contains functions for
//! converting between UTF-8 and UTF-16LE encodings. It corresponds to
//! Nmap's unicode NSE library.
//!
//! # Available Functions
//!
//! - `unicode.utf8to16(str)` - Convert UTF-8 string to UTF-16LE
//! - `unicode.utf16to8(str)` - Convert UTF-16LE string to UTF-8
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local unicode = require "unicode"
//!
//! -- Convert to UTF-16LE (for SMB/Windows protocols)
//! local utf16_str = unicode.utf8to16("Hello")
//! -- Returns: "H\0e\0l\0l\0o\0" (little-endian UTF-16)
//!
//! -- Convert from UTF-16LE
//! local utf8_str = unicode.utf16to8(utf16_str)
//! -- Returns: "Hello"
//! ```

use crate::error::Result;
use crate::lua::NseLua;

use std::string::FromUtf16Error;

/// Register the unicode library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the unicode table
    let unicode_table = lua.create_table()?;

    // Register utf8to16 function
    let utf8to16_fn = lua.create_function(|_lua, s: String| Ok(utf8_to_utf16le(&s)))?;
    unicode_table.set("utf8to16", utf8to16_fn)?;

    // Register utf16to8 function
    let utf16to8_fn = lua.create_function(|_lua, s: Vec<u8>| {
        utf16le_to_utf8(&s).map_err(|e| mlua::Error::external(e.to_string()))
    })?;
    unicode_table.set("utf16to8", utf16to8_fn)?;

    // Set the unicode table in globals
    lua.globals().set("unicode", unicode_table)?;

    Ok(())
}

/// Convert a UTF-8 string to UTF-16LE (little-endian) encoding.
///
/// This is the encoding used by Windows/SMB protocols. Each character
/// is encoded as 2 bytes in little-endian order.
///
/// # Arguments
///
/// * `s` - The UTF-8 string to convert
///
/// # Returns
///
/// A byte vector containing the UTF-16LE encoded string
#[must_use]
pub fn utf8_to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Convert a UTF-8 string to UTF-16LE with null terminator.
///
/// This is useful for C-style string handling in SMB/Windows protocols.
///
/// # Arguments
///
/// * `s` - The UTF-8 string to convert
///
/// # Returns
///
/// A byte vector containing the UTF-16LE encoded string with null terminator
#[must_use]
pub fn utf8_to_utf16le_null(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0, 0]) // Null terminator
        .collect()
}
/// Convert UTF-16LE (little-endian) encoded bytes to a UTF-8 string.
///
/// # Arguments
///
/// * `bytes` - The UTF-16LE encoded bytes
///
/// # Errors
///
/// Returns an error if the input contains invalid UTF-16 sequences.
///
/// # Returns
///
/// The decoded UTF-8 string
pub fn utf16le_to_utf8(bytes: &[u8]) -> std::result::Result<String, FromUtf16Error> {
    // Convert bytes to u16 values (little-endian)
    let u16_vals: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0) // Stop at null terminator
        .collect();

    String::from_utf16(&u16_vals)
}
/// Convert null-terminated UTF-16LE bytes to a UTF-8 string.
///
/// Stops at the first null character (two consecutive zero bytes).
///
/// # Arguments
///
/// * `bytes` - The UTF-16LE encoded bytes (may include null terminator)
///
/// # Errors
///
/// Returns an error if the input contains invalid UTF-16 sequences.
///
/// # Returns
///
/// The decoded UTF-8 string (without null terminator)
pub fn utf16le_null_to_utf8(bytes: &[u8]) -> std::result::Result<String, FromUtf16Error> {
    utf16le_to_utf8(bytes)
}
/// Encode a Unicode code point to UTF-16LE.
///
/// Supports the full Unicode range including surrogate pairs for code points > 0xFFFF.
///
/// # Arguments
///
/// * `cp` - The Unicode code point
///
/// # Returns
///
/// A byte vector containing the UTF-16LE encoded code point
#[must_use]
pub fn utf16_encode_codepoint(cp: u32) -> Vec<u8> {
    if cp <= 0xFFFF {
        // Basic Multilingual Plane - single 16-bit code unit
        #[expect(clippy::cast_possible_truncation, reason = "cp <= 0xFFFF, safe cast")]
        (cp as u16).to_le_bytes().to_vec()
    } else if cp <= 0x0010_FFFF {
        // Supplementary Planes - surrogate pair
        let cp = cp - 0x10000;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "cp <= 0x0010_FFFF, so (cp >> 10) <= 0x3FF < 0xD800"
        )]
        let high = 0xD800 + ((cp >> 10) as u16);
        let low = 0xDC00 + ((cp & 0x03FF) as u16);
        [high.to_le_bytes(), low.to_le_bytes()].concat()
    } else {
        // Invalid code point - return replacement character
        0xFFFDu16.to_le_bytes().to_vec()
    }
}
/// Decode a UTF-16LE code point from bytes.
///
/// Handles surrogate pairs for code points > 0xFFFF.
///
/// # Arguments
///
/// * `bytes` - The UTF-16LE encoded bytes
/// * `pos` - The starting position (0-indexed)
///
/// # Returns
///
/// A tuple of (`new_position`, `code_point`) or `None` if invalid
#[must_use]
pub fn utf16_decode_codepoint(bytes: &[u8], pos: usize) -> Option<(usize, u32)> {
    if pos + 2 > bytes.len() {
        return None;
    }

    let code_unit = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);

    // Check for high surrogate
    if (0xD800..=0xDBFF).contains(&code_unit) {
        // High surrogate - need low surrogate
        if pos + 4 > bytes.len() {
            return None;
        }
        let low_surrogate = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]);

        // Validate low surrogate
        if !(0xDC00..=0xDFFF).contains(&low_surrogate) {
            return None;
        }

        // Combine surrogates
        let code_point =
            0x10000 + (u32::from(code_unit - 0xD800) << 10) + u32::from(low_surrogate - 0xDC00);

        Some((pos + 4, code_point))
    } else if (0xDC00..=0xDFFF).contains(&code_unit) {
        // Low surrogate without high surrogate - invalid
        None
    } else {
        // Regular character
        Some((pos + 2, u32::from(code_unit)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_to_utf16le() {
        let result = utf8_to_utf16le("Hello");
        // 'H' = 0x0048, 'e' = 0x0065, in little-endian
        assert_eq!(
            result,
            vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]
        );
    }

    #[test]
    fn test_utf8_to_utf16le_null() {
        let result = utf8_to_utf16le_null("Hi");
        assert_eq!(result, vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_utf16le_to_utf8() {
        let input = vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let result = utf16le_to_utf8(&input).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_utf16le_null_to_utf8() {
        let input = vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x41, 0x00];
        let result = utf16le_null_to_utf8(&input).unwrap();
        assert_eq!(result, "Hi"); // Stops at null terminator
    }

    #[test]
    fn test_utf16_encode_codepoint_basic() {
        let result = utf16_encode_codepoint(0x0041); // 'A'
        assert_eq!(result, vec![0x41, 0x00]);
    }

    #[test]
    fn test_utf16_encode_codepoint_surrogate() {
        // U+1F600 (grinning face emoji) - requires surrogate pair
        let result = utf16_encode_codepoint(0x1F600);
        // High surrogate: 0xD83D, Low surrogate: 0xDE00
        assert_eq!(result, vec![0x3D, 0xD8, 0x00, 0xDE]);
    }

    #[test]
    fn test_roundtrip() {
        let original = "Hello, World!";
        let utf16 = utf8_to_utf16le(original);
        let back = utf16le_to_utf8(&utf16).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn test_unicode_characters() {
        let original = "日本語"; // Japanese characters
        let utf16 = utf8_to_utf16le(original);
        let back = utf16le_to_utf8(&utf16).unwrap();
        assert_eq!(original, back);
    }
}
