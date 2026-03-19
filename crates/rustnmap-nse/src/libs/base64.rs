//! Base64 encoding/decoding library for NSE.
//!
//! This module provides the `base64` library which contains base64 encoding
//! and decoding functions. It corresponds to Nmap's base64 NSE library.
//!
//! # Available Functions
//!
//! - `base64.enc(data)` - Encode binary data to base64 string
//! - `base64.dec(str)` - Decode base64 string to binary data
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local base64 = require "base64"
//!
//! -- Encode
//! local encoded = base64.enc("Hello World")
//! -- Returns "SGVsbG8gV29ybGQ="
//!
//! -- Decode
//! local decoded = base64.dec("SGVsbG8gV29ybGQ=")
//! -- Returns "Hello World"
//! ```

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::error::Result;
use crate::lua::NseLua;

/// Register the base64 library with the Lua runtime.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register with
///
/// # Errors
///
/// Returns an error if registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the base64 table
    let base64_table = lua.create_table()?;

    // Register enc(data) function - encode to base64
    let enc_fn = lua.create_function(|_, data: Vec<u8>| {
        let encoded = STANDARD.encode(&data);
        Ok(encoded)
    })?;
    base64_table.set("enc", enc_fn)?;

    // Register dec(str) function - decode from base64
    let dec_fn = lua.create_function(|_, str: String| {
        let decoded = STANDARD
            .decode(str.as_bytes())
            .map_err(|e| mlua::Error::RuntimeError(format!("Base64 decode error: {e}")))?;
        Ok(decoded)
    })?;
    base64_table.set("dec", dec_fn)?;

    // Set the base64 table as a global
    lua.globals().set("base64", base64_table)?;

    Ok(())
}
