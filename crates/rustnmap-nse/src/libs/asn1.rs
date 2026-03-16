//! ASN.1 library for NSE.
//!
//! This module provides the `asn1` library which contains functions for
//! encoding and decoding ASN.1 BER (Basic Encoding Rules) data
//! structures. It corresponds to Nmap's asn1 NSE library
//! and is used for SMB extended security.
//!
//! # Available Functions
//!
//! - `asn1.encode_integer(value)` - Encode an integer
//! - `asn1.encode_octet_string(data)` - Encode an octet string
//! - `asn1.encode_sequence(items)` - Encode a sequence
//! - `asn1.encode_length(length)` - Encode length field
//! - `asn1.decode_length(data, pos)` - Decode length field
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local asn1 = require "asn1"
//!
//! -- Encode an integer
//! local encoded = asn1.encode_integer(42)
//! -- Returns: "\x02\x01\x2A"
//!
//! -- Encode a sequence
//! local seq = asn1.encode_sequence({
//!     asn1.encode_integer(1),
//!     asn1.encode_octet_string("test"),
//! })
//! -- Returns: "\x30\x06\x02\x01\x01\x01\x04\x04test"
//! ```

use crate::error::Result;
use crate::lua::NseLua;
use std::cmp::Ordering;

// ASN.1 BER Tags
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_NULL: u8 = 0x05;

/// Register the asn1 library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the asn1 table
    let asn1_table = lua.create_table()?;

    // Register encode_integer function
    let encode_integer_fn = lua.create_function(|_lua, value: i64| {
        Ok(encode_integer(value))
    })?;
    asn1_table.set("encode_integer", encode_integer_fn)?;

    // Register encode_octet_string function
    let encode_octet_string_fn = lua.create_function(|_lua, data: Vec<u8>| {
        Ok(encode_octet_string(&data))
    })?;
    asn1_table.set("encode_octet_string", encode_octet_string_fn)?;

    // Register encode_sequence function
    let encode_sequence_fn = lua.create_function(|_lua, items: Vec<Vec<u8>>| {
        Ok(encode_sequence(&items))
    })?;
    asn1_table.set("encode_sequence", encode_sequence_fn)?;

    // Register encode_length function (exposed for testing)
    let encode_length_fn = lua.create_function(|_lua, length: usize| {
        Ok(encode_length(length))
    })?;
    asn1_table.set("encode_length", encode_length_fn)?;

    // Register decode_length function
    let decode_length_fn = lua.create_function(|_lua, (data, pos): (Vec<u8>, usize)| {
        decode_length(&data, pos).map_err(|e| {
            mlua::Error::external(format!("ASN1 decode_length failed: {e}"))
        })
    })?;
    asn1_table.set("decode_length", decode_length_fn)?;

    // Set constants
    asn1_table.set("TAG_INTEGER", TAG_INTEGER)?;
    asn1_table.set("TAG_OCTET_STRING", TAG_OCTET_STRING)?;
    asn1_table.set("TAG_SEQUENCE", TAG_SEQUENCE)?;
    asn1_table.set("TAG_BOOLEAN", TAG_BOOLEAN)?;
    asn1_table.set("TAG_NULL", TAG_NULL)?;

    // Set the asn1 table in globals
    lua.globals().set("asn1", asn1_table)?;

    Ok(())
}

/// Encode an integer according to ASN.1 BER.
///
/// This encodes a signed or unsigned integer value using the Basic Encoding
/// Rules (BER). The encoding is as follows:
///
/// Format:
/// ```text
/// 0x02 [length] [bytes...]
/// ```
///
/// For positive integers:
/// - If the value fits in one byte (0-127), use 1 byte
/// - If the value fits in two bytes, use 2 bytes
/// - Otherwise, use as many bytes as needed
/// - If the MSB is set, prepend a 0x00 byte to avoid sign confusion
///
/// For negative integers:
/// - Use two's complement encoding
/// - Encode as if for the corresponding positive value
///
/// # Arguments
///
/// * `value` - The integer value to encode
///
/// # Returns
///
/// A `Vec<u8>` containing the BER-encoded integer
#[must_use]
pub fn encode_integer(value: i64) -> Vec<u8> {
    let mut result = Vec::new();

    match value.cmp(&0) {
        Ordering::Equal => {
            // Zero: single zero byte
            result.push(0x00);
        }
        Ordering::Greater => {
            // Positive integer
            let mut temp = value;
            let mut bytes = Vec::new();

            while temp > 0 {
                bytes.push(u8::try_from(temp & 0xFF).unwrap_or(0));
                temp >>= 8;
            }

            // Reverse to big-endian order
            bytes.reverse();

            // If MSB is set (value > 127), prepend a 0x00 byte
            // to avoid confusion with negative numbers
            if bytes[0] > 0x7F {
                bytes.insert(0, 0);
            }

            result.extend(bytes);
        }
        Ordering::Less => {
            // Negative integer: use two's complement
            // Calculate the minimum number of bytes needed
            let abs_value = u64::try_from(-value).unwrap_or(0);
            let mut temp = abs_value;
            let mut byte_count = 1;

            while temp > 0 {
                byte_count += 1;
                temp >>= 8;
            }

            // Create mask for sign bit
            let mut mask: u64 = 0x80;
            for _ in 0..byte_count - 1 {
                mask = (mask << 8) | 0xFF;
            }

            // Convert to two's complement
            #[allow(clippy::cast_sign_loss, reason = "Intentional two's complement conversion for negative integer encoding")]
            let twos_complement = ((value as u64) ^ mask).wrapping_add(1) & mask;

            // Encode in big-endian
            for i in (0..byte_count).rev() {
                result.push(u8::try_from((twos_complement >> (i * 8)) & 0xFF).unwrap_or(0));
            }
        }
    }

    result
}

/// Encode an octet string according to ASN.1 BER.
///
/// Format:
/// ```text
/// 0x04 [length] [bytes...]
/// ```
///
/// # Arguments
///
/// * `data` - The data to encode
///
/// # Returns
///
/// A `Vec<u8>` containing the BER-encoded octet string
#[must_use]
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(TAG_OCTET_STRING);
    result.extend(encode_length(data.len()));
    result.extend(data);
    result
}

/// Encode a sequence according to ASN.1 BER.
///
/// A sequence is a collection of BER-encoded items concatenated together,
/// preceded by the SEQUENCE tag and total length.
///
/// Format:
/// ```text
/// 0x30 [length] [items...]
/// ```
///
/// # Arguments
///
/// * `items` - Slice of BER-encoded items to concatenate
///
/// # Returns
///
/// A `Vec<u8>` containing the BER-encoded sequence
#[must_use]
pub fn encode_sequence(items: &[Vec<u8>]) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(TAG_SEQUENCE);

    // Calculate total length of all items
    let total_len: usize = items.iter().map(Vec::len).sum();
    result.extend(encode_length(total_len));

    // Append all items
    for item in items {
        result.extend(item);
    }

    result
}

/// Encode a length field according to ASN.1 BER.
///
/// For lengths < 128, use short form (single byte).
/// For lengths >= 128, use long form (multiple bytes)
///
/// Short: bit 7 is 0, then 7-bit length (0-127)
/// Long: bit 7 is 1, then bit 6-0 indicate count, then length bytes
///
/// # Arguments
///
/// * `length` - The length value to encode
///
/// # Returns
///
/// A `Vec<u8>` containing the BER-encoded length
#[must_use]
pub fn encode_length(length: usize) -> Vec<u8> {
    let mut result = Vec::new();

    if length < 128 {
        // Short form
        result.push(u8::try_from(length).unwrap_or(127));
    } else {
        // Long form
        let mut len = length;
        let mut len_bytes = Vec::new();

        // Build length bytes in reverse order
        while len > 0 {
            len_bytes.push(u8::try_from(len & 0xFF).unwrap_or(255));
            len >>= 8;
        }
        len_bytes.reverse();

        // First byte: 0x80 | number of length bytes
        result.push(0x80 | u8::try_from(len_bytes.len()).unwrap_or(127));
        result.extend(len_bytes);
    }

    result
}

/// Decode a length field according to ASN.1 BER.
///
/// # Arguments
///
/// * `data` - The data to decode from
/// * `pos` - Starting position in the data (0-indexed)
///
/// # Returns
///
/// A tuple of (`decoded_length`, `new_position`) on success, or error on failure
///
/// # Errors
///
/// Returns an error if:
/// - Position is out of bounds
/// - Indefinite length encoding is used
/// - Not enough bytes for length field
pub fn decode_length(data: &[u8], pos: usize) -> Result<(usize, usize)> {
    if pos >= data.len() {
        return Err(crate::error::Error::LuaLibError(format!(
            "position {} out of bounds (data length {})",
            pos,
            data.len()
        )));
    }

    let first_byte = data[pos];
    let new_pos = pos + 1;

    if first_byte < 0x80 {
        // Short form
        Ok((first_byte as usize, new_pos))
    } else {
        // Long form
        let num_bytes = (first_byte & 0x7F) as usize;

        if num_bytes == 0 {
            return Err(crate::error::Error::LuaLibError(
                "indefinite length encoding not supported".to_string()
            ));
        }

        if new_pos + num_bytes > data.len() {
            return Err(crate::error::Error::LuaLibError(format!(
                "not enough bytes for length field (need {}, have {})",
                num_bytes,
                data.len() - new_pos
            )));
        }

        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[new_pos + i] as usize);
        }

        Ok((length, new_pos + num_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_integer_zero() {
        let result = encode_integer(0);
        assert_eq!(result, vec![0x00]);
    }

    #[test]
    fn test_encode_integer_small_positive() {
        let result = encode_integer(42);
        assert_eq!(result, vec![0x2A]);
    }

    #[test]
    fn test_encode_integer_positive_msb_set() {
        // Value 128 has MSB set, should prepend 0x00
        let result = encode_integer(128);
        assert_eq!(result, vec![0x00, 0x80]);
    }

    #[test]
    fn test_encode_integer_255() {
        // Value 255: MSB is set in first byte, prepend 0x00
        let result = encode_integer(255);
        assert_eq!(result, vec![0x00, 0xFF]);
    }

    #[test]
    fn test_encode_integer_large() {
        let result = encode_integer(256);
        assert_eq!(result, vec![0x01, 0x00]);
    }

    #[test]
    fn test_encode_length_short() {
        let result = encode_length(127);
        assert_eq!(result, vec![127]);
    }

    #[test]
    fn test_encode_length_long() {
        let result = encode_length(128);
        assert_eq!(result, vec![0x81, 0x80]);
    }

    #[test]
    fn test_encode_length_256() {
        let result = encode_length(256);
        assert_eq!(result, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_decode_length_short() {
        let data = vec![42];
        let (len, pos) = decode_length(&data, 0).unwrap();
        assert_eq!(len, 42);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_decode_length_long() {
        let data = vec![0x81, 0x80];
        let (len, pos) = decode_length(&data, 0).unwrap();
        assert_eq!(len, 128);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_encode_octet_string() {
        let result = encode_octet_string(b"test");
        // 0x04 (tag) + 0x04 (length) + "test"
        assert_eq!(result, vec![0x04, 0x04, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_encode_sequence() {
        let item1 = vec![0x02, 0x01, 0x01]; // integer 1
        let item2 = vec![0x04, 0x04, b't', b'e', b's', b't']; // octet string "test"
        let result = encode_sequence(&[item1, item2]);
        // 0x30 (tag) + 0x09 (length) + items
        assert_eq!(result[0], 0x30); // SEQUENCE tag
        assert_eq!(result[1], 0x09); // Total length
    }
}
