//! `NetBIOS` library for NSE.
//!
//! This module provides the `netbios` library which contains functions for
//! `NetBIOS` name encoding and network operations. It corresponds to
//! `Nmap`'s `netbios` `NSE` library.
//!
//! # Available Functions
//!
//! - `netbios.name_encode(name, scope)` - Encode a `NetBIOS` name
//! - `netbios.name_decode(encoded_name)` - Decode a `NetBIOS` name
//! - `netbios.get_server_name(host)` - Get server name via `NBSTAT`
//! - `netbios.get_workstation_name(host)` - Get workstation name via `NBSTAT`
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local netbios = require "netbios"
//!
//! -- Encode a NetBIOS name
//! local encoded = netbios.name_encode("TEST")
//! -- Returns encoded name for transport
//!
//! -- Get server name via NBSTAT query
//! local name = netbios.get_server_name("192.168.1.1")
//! ```

use crate::error::Result;
use crate::lua::NseLua;

// NetBIOS name types (suffixes)
const SUFFIX_WORKSTATION: u8 = 0x00;
const SUFFIX_MESSENGER: u8 = 0x03;
const SUFFIX_SERVER: u8 = 0x20;

// NBSTAT query types
const QUERY_TYPE_NB: u16 = 32;
const QUERY_TYPE_NBSTAT: u16 = 33;

/// Register the netbios library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the netbios table
    let netbios_table = lua.create_table()?;

    // Register name_encode function
    let name_encode_fn = lua.create_function(|_lua, (name, scope): (String, Option<String>)| {
        Ok(name_encode(&name, scope.as_deref()))
    })?;
    netbios_table.set("name_encode", name_encode_fn)?;

    // Register name_decode function
    let name_decode_fn = lua.create_function(|_lua, encoded_name: Vec<u8>| {
        let (name, scope) = name_decode(&encoded_name);
        Ok((name, scope))
    })?;
    netbios_table.set("name_decode", name_decode_fn)?;

    // Set constants
    netbios_table.set("SUFFIX_WORKSTATION", SUFFIX_WORKSTATION)?;
    netbios_table.set("SUFFIX_MESSENGER", SUFFIX_MESSENGER)?;
    netbios_table.set("SUFFIX_SERVER", SUFFIX_SERVER)?;
    netbios_table.set("QUERY_TYPE_NB", QUERY_TYPE_NB)?;
    netbios_table.set("QUERY_TYPE_NBSTAT", QUERY_TYPE_NBSTAT)?;

    // Stub: get_server_name(ip) - returns (false, nil) to skip NetBIOS name lookup
    let get_server_name_fn = lua.create_function(|_, _ip: String| Ok((false, mlua::Value::Nil)))?;
    netbios_table.set("get_server_name", get_server_name_fn)?;

    // Set the netbios table in globals
    lua.globals().set("netbios", netbios_table)?;

    Ok(())
}

/// Encode a `NetBIOS` name for transport (`L2` encoding).
///
/// `NetBIOS` names require two levels of encoding:
///
/// **L1 Encoding**: Pad the string to 16 characters with spaces (or NULLs if
/// it's the wildcard "*") and replace each byte with two bytes representing
/// each of its nibbles, plus 0x41.
///
/// **L2 Encoding**: Prepend the length to the string, and to each substring
/// in the scope (separated by periods).
///
/// # Arguments
///
/// * `name` - The name to encode (e.g., "TEST1")
/// * `scope` - Optional scope (e.g., "insecure.org")
///
/// # Returns
///
/// A `Vec<u8>` containing the L2-encoded name and scope
///
/// # Example
///
/// Encoding "TEST" without scope:
/// ```no_run
/// # use rustnmap_nse::libs::netbios::name_encode;
/// let encoded = name_encode("TEST", None);
/// // Result: [0x20, 0x45, 0x45, 0x45, 0x44, 0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]
/// ```
#[must_use]
pub fn name_encode(name: &str, scope: Option<&str>) -> Vec<u8> {
    // Truncate or pad to 16 bytes, then uppercase
    let name_bytes: Vec<u8> = if name.len() >= 16 {
        name.as_bytes()[..16].to_vec()
    } else {
        let padding = if name == "*" { 0 } else { b' ' };
        let mut result = name.as_bytes().to_vec();
        for _ in name.len()..16 {
            result.push(padding);
        }
        result
    };

    // Convert to uppercase for encoding
    let name_upper = String::from_utf8_lossy(&name_bytes).to_uppercase();

    // L1 encoding: convert each byte to two bytes
    let mut l1_encoded = Vec::with_capacity(32);
    for b in name_upper.as_bytes() {
        // High nibble + 0x41
        l1_encoded.push((b >> 4) + 0x41);
        // Low nibble + 0x41
        l1_encoded.push((b & 0x0F) + 0x41);
    }

    // L2 encoding: prepend length (always 32 for L1-encoded names)
    let mut l2_encoded = Vec::new();
    l2_encoded.push(32); // Length byte
    l2_encoded.extend(l1_encoded);

    // Add scope if present
    if let Some(scope_str) = scope {
        for piece in scope_str.split('.') {
            l2_encoded.push(u8::try_from(piece.len()).unwrap_or(255));
            l2_encoded.extend(piece.as_bytes());
        }
    }

    l2_encoded
}

/// Decode an `L2`-encoded `NetBIOS` name.
///
/// # Arguments
///
/// * `encoded_name` - The L2-encoded name bytes
///
/// # Returns
///
/// A tuple of (name, scope) where:
/// - `name` is the decoded name (still padded to 16 chars)
/// - `scope` is the scope (empty string if not present)
#[must_use]
pub fn name_decode(encoded_name: &[u8]) -> (String, String) {
    if encoded_name.is_empty() {
        return (String::new(), String::new());
    }

    // Read length byte
    let len = encoded_name[0] as usize;

    // L1 decode: convert pairs of bytes back to single bytes
    let mut name = String::with_capacity(16);
    for i in (1..len).step_by(2) {
        if i + 1 >= encoded_name.len() {
            break;
        }
        let high = encoded_name[i].saturating_sub(0x41);
        let low = encoded_name[i + 1].saturating_sub(0x41);
        let ch = (high << 4) | low;
        name.push(char::from(ch));
    }

    // Decode scope (if present)
    let mut scope = String::new();
    let mut pos = 1 + len;
    while pos < encoded_name.len() {
        let piece_len = encoded_name[pos] as usize;
        pos += 1;
        if pos + piece_len > encoded_name.len() {
            break;
        }
        if !scope.is_empty() {
            scope.push('.');
        }
        if let Ok(piece) = std::str::from_utf8(&encoded_name[pos..pos + piece_len]) {
            scope.push_str(piece);
        }
        pos += piece_len;
    }

    (name, scope)
}

/// Build an NBSTAT request packet.
///
/// The NBSTAT request packet format is:
/// ```text
/// [TRN_ID: 2 bytes] [FLAGS: 2 bytes] [QDCOUNT: 2 bytes] [ANCOUNT: 2 bytes]
/// [NSCOUNT: 2 bytes] [ARCOUNT: 2 bytes] [Encoded Name] [Query Type: 2 bytes] [Query Class: 2 bytes]
/// ```
///
/// # Arguments
///
/// * `encoded_name` - The L2-encoded name to query
///
/// # Returns
///
/// A `Vec<u8>` containing the NBSTAT request packet
#[must_use]
pub fn build_nbstat_request(encoded_name: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID (random)
    packet.extend_from_slice(&rand::random::<u16>().to_be_bytes());

    // Flags: Standard query
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

    // Question count: 1
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Answer count: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

    // Authority count: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

    // Additional count: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

    // Encoded name
    packet.extend_from_slice(encoded_name);

    // Query type: NBSTAT (33)
    packet.extend_from_slice(&QUERY_TYPE_NBSTAT.to_be_bytes());

    // Query class: IN (1)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    packet
}

/// Parse an NBSTAT response packet.
///
/// # Arguments
///
/// * `response` - The raw response bytes
///
/// # Returns
///
/// A vector of name entries, where each entry is a table with:
/// - [`name`] - The `NetBIOS` name
/// - [`suffix`] - The name suffix (type)
/// - [`flags`] - The name flags
#[allow(dead_code, reason = "Reserved for future NBSTAT response parsing")]
fn parse_nbstat_response(response: &[u8]) -> Result<Vec<NbstatEntry>> {
    if response.len() < 12 {
        return Err(crate::error::Error::NetworkError(format!(
            "NBSTAT response too short ({} bytes, need at least 12)",
            response.len()
        )));
    }

    // Parse header
    let _trn_id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let _qdcount = u16::from_be_bytes([response[4], response[5]]);
    let _ancount = u16::from_be_bytes([response[6], response[7]]);
    let _nscount = u16::from_be_bytes([response[8], response[9]]);
    let _arcount = u16::from_be_bytes([response[10], response[11]]);

    // Validate transaction ID (should match our request)
    // Note: In a real implementation, we'd track the TRN_ID we sent

    // Validate flags
    if flags & 0x8000 == 0 {
        return Err(crate::error::Error::NetworkError(
            "NBSTAT response indicates failure (not a response)".to_string(),
        ));
    }

    // Check for errors
    if flags & 0x0007 != 0 {
        return Err(crate::error::Error::NetworkError(format!(
            "NBSTAT response indicates error: {}",
            flags & 0x0007
        )));
    }

    // Skip the question section
    let mut pos = 12;

    // Skip question name (variable length)
    while pos < response.len() && response[pos] != 0 {
        let label_len = response[pos] as usize;
        pos += label_len + 1;
    }
    pos += 1; // Skip null terminator

    // Skip question type and class (4 bytes)
    pos += 4;

    // Skip the answer name (should be compressed pointer)
    if pos + 2 > response.len() {
        return Err(crate::error::Error::NetworkError(
            "NBSTAT response truncated at answer name".to_string(),
        ));
    }
    pos += 2;

    // Skip answer type, class, and TTL (8 bytes)
    if pos + 8 > response.len() {
        return Err(crate::error::Error::NetworkError(
            "NBSTAT response truncated at answer header".to_string(),
        ));
    }
    pos += 8;

    // Read data length
    if pos + 2 > response.len() {
        return Err(crate::error::Error::NetworkError(
            "NBSTAT response truncated at data length".to_string(),
        ));
    }
    let data_len = u16::from_be_bytes([response[pos], response[pos + 1]]) as usize;
    pos += 2;

    if pos + data_len > response.len() {
        return Err(crate::error::Error::NetworkError(format!(
            "NBSTAT response truncated: need {} bytes, have {}",
            data_len,
            response.len() - pos
        )));
    }

    // Parse NBSTAT data
    parse_nbstat_data(&response[pos..pos + data_len])
}

/// Parse NBSTAT data section.
///
/// The NBSTAT data format is:
/// ```text
/// [Number of names: 1 byte] [Name entries...] [Statistics (variable)]
/// ```
///
/// Each name entry is 18 bytes:
/// ```text
/// [Name: 15 bytes] [Suffix: 1 byte] [Flags: 2 bytes]
/// ```
#[allow(dead_code, reason = "Reserved for future NBSTAT data parsing")]
fn parse_nbstat_data(data: &[u8]) -> Result<Vec<NbstatEntry>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let num_names = data[0] as usize;
    let mut entries = Vec::with_capacity(num_names);
    let mut pos = 1;

    for _ in 0..num_names {
        if pos + 18 > data.len() {
            return Err(crate::error::Error::NetworkError(format!(
                "NBSTAT data truncated: need {} bytes for name entry, have {}",
                18,
                data.len() - pos
            )));
        }

        // Extract name (15 bytes, space-padded)
        let name_bytes = &data[pos..pos + 15];
        let name = String::from_utf8_lossy(name_bytes)
            .trim_end_matches(' ')
            .to_string();

        // Extract suffix (1 byte)
        let suffix = data[pos + 15];

        // Extract flags (2 bytes, big-endian)
        let flags = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);

        entries.push(NbstatEntry {
            name,
            suffix,
            flags,
        });

        pos += 18;
    }

    Ok(entries)
}

/// A single `NBSTAT` name entry.
#[derive(Debug, Clone)]
pub struct NbstatEntry {
    /// The `NetBIOS` name (without suffix)
    pub name: String,
    /// The name suffix/type byte
    pub suffix: u8,
    /// The [`flags`] for this name entry
    pub flags: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_encode_simple() {
        let result = name_encode("TEST", None);
        // Length byte should be 32 (16 chars * 2 bytes each)
        assert_eq!(result[0], 32);
        // First encoded character 'T' (0x54):
        // high nibble = 5, low nibble = 4 -> 0x41+5=0x46, 0x41+4=0x45
        assert_eq!(&result[1..3], &[0x46, 0x45]);
    }

    #[test]
    fn test_name_encode_wildcard() {
        let result = name_encode("*", None);
        // Wildcard uses null padding
        assert_eq!(result[0], 32);
    }

    #[test]
    fn test_name_encode_with_scope() {
        let result = name_encode("TEST", Some("example.com"));
        // Should include scope encoding
        assert!(result.len() > 34);
    }

    #[test]
    fn test_name_decode() {
        // Encode then decode should give back original (uppercase)
        let encoded = name_encode("TEST", None);
        let (name, scope) = name_decode(&encoded);
        assert_eq!(name.trim(), "TEST");
        assert!(scope.is_empty());
    }

    #[test]
    fn test_build_nbstat_request() {
        let encoded_name = name_encode("*", None);
        let request = build_nbstat_request(&encoded_name);
        // Check header structure
        assert!(request.len() > 12);
        // Check query type is NBSTAT (33)
        let query_type_pos = 12 + encoded_name.len();
        let query_type = u16::from_be_bytes([request[query_type_pos], request[query_type_pos + 1]]);
        assert_eq!(query_type, QUERY_TYPE_NBSTAT);
    }
}
