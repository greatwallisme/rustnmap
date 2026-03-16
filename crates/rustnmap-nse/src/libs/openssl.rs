//! OpenSSL library for NSE.
//!
//! This module provides the `openssl` library which contains cryptographic functions
//! for NSE scripts. It corresponds to Nmap's openssl NSE library.
//!
//! # Available Functions
//!
//! ## Hash Functions
//!
//! - `openssl.md4(message)` - Calculate MD4 digest
//! - `openssl.md5(message)` - Calculate MD5 digest
//! - `openssl.sha1(message)` - Calculate SHA-1 digest
//! - `openssl.sha256(message)` - Calculate SHA-256 digest
//! - `openssl.sha512(message)` - Calculate SHA-512 digest
//! - `openssl.ripemd160(message)` - Calculate RIPEMD-160 digest
//!
//! ## HMAC Functions
//!
//! - `openssl.hmac(algorithm, key, message)` - Calculate HMAC
//!
//! ## Random Bytes
//!
//! - `openssl.rand_bytes(bytes)` - Generate cryptographically strong random bytes
//! - `openssl.rand_pseudo_bytes(bytes)` - Generate pseudorandom bytes
//!
//! ## Bignum Functions
//!
//! - `openssl.bignum_bin2bn(string)` - Convert binary string to bignum
//! - `openssl.bignum_dec2bn(string)` - Convert decimal string to bignum
//! - `openssl.bignum_hex2bn(string)` - Convert hex string to bignum
//! - `openssl.bignum_bn2bin(bignum)` - Convert bignum to binary string
//! - `openssl.bignum_bn2dec(bignum)` - Convert bignum to decimal string
//! - `openssl.bignum_bn2hex(bignum)` - Convert bignum to hex string
//! - `openssl.bignum_num_bits(bignum)` - Get size of bignum in bits
//! - `openssl.bignum_num_bytes(bignum)` - Get size of bignum in bytes
//! - `openssl.bignum_rand(bits)` - Generate random bignum
//! - `openssl.bignum_mod_exp(a, p, m)` - Modular exponentiation
//!
//! ## Encryption/Decryption
//!
//! - `openssl.encrypt(algorithm, key, iv, data, padding)` - Encrypt data
//! - `openssl.decrypt(algorithm, key, iv, data, padding)` - Decrypt data
//!
//! ## Utility Functions
//!
//! - `openssl.DES_string_to_key(data)` - Convert 56-bit DES key to 64-bit with parity
//! - `openssl.supported_ciphers()` - Return list of supported cipher algorithms
//! - `openssl.supported_digests()` - Return list of supported digest algorithms
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local openssl = require "openssl"
//!
//! -- Calculate hash
//! local hash = openssl.md5("Hello World")
//!
//! -- Calculate HMAC
//! local mac = openssl.hmac("sha256", "secret", "message")
//!
//! -- Random bytes
//! local random = openssl.rand_bytes(16)
//! ```
//!
//! # Bignum Usage
//!
//! ```lua
//! local openssl = require "openssl"
//!
//! -- Create bignum from hex
//! local bn = openssl.bignum_hex2bn("FF")
//!
//! -- Convert back
//! local hex = openssl.bignum_bn2hex(bn)
//! local dec = openssl.bignum_bn2dec(bn)
//!
//! -- Modular exponentiation
//! local result = openssl.bignum_mod_exp("2", "10", "1000")
//! ```

use des::cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use des::Des;
use hmac::Mac as HmacMac;
use mlua::{Lua, Value};
use num_bigint::BigUint;
use rand::RngCore;
use ripemd::Digest as RipemdDigest;
use ripemd::Ripemd160;
use sha1::Digest as Sha1Digest;
use sha1::Sha1;
use sha2::Digest as Sha2Digest;
use sha2::{Sha256, Sha512};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Maximum number of bytes for `rand_bytes` requests (1MB).
const MAX_RAND_BYTES: usize = 1_048_576;

/// Maximum bits for `bignum_rand` (4096 bits).
const MAX_BIGNUM_BITS: u64 = 4096;

/// Convert a Lua string to bytes.
fn lua_string_to_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(s) => {
            let bytes = s.as_bytes().to_vec();
            Some(bytes)
        }
        _ => None,
    }
}

/// Convert bytes to a Lua string.
fn bytes_to_lua_string(lua: &Lua, bytes: &[u8]) -> mlua::Result<Value> {
    lua.create_string(bytes)
        .map(Value::String)
}

/// MD4 hash function.
fn md4_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = md4::Md4::new();
    md4::Digest::update(&mut hasher, data);
    md4::Digest::finalize(hasher).to_vec()
}

/// MD5 hash function.
fn md5_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = md5::Md5::new();
    md5::Digest::update(&mut hasher, data);
    md5::Digest::finalize(hasher).to_vec()
}

/// SHA-1 hash function.
fn sha1_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    Sha1Digest::update(&mut hasher, data);
    Sha1Digest::finalize(hasher).to_vec()
}

/// SHA-256 hash function.
fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, data);
    Sha2Digest::finalize(hasher).to_vec()
}

/// SHA-512 hash function.
fn sha512_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    Sha2Digest::update(&mut hasher, data);
    Sha2Digest::finalize(hasher).to_vec()
}

/// RIPEMD-160 hash function.
fn ripemd160_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    RipemdDigest::update(&mut hasher, data);
    RipemdDigest::finalize(hasher).to_vec()
}

/// Generic hash function that dispatches based on algorithm name.
fn hash_digest(algorithm: &str, data: &[u8]) -> mlua::Result<Vec<u8>> {
    let algo_lower = algorithm.to_lowercase();
    match algo_lower.as_str() {
        "md4" => Ok(md4_hash(data)),
        "md5" => Ok(md5_hash(data)),
        "sha" | "sha1" => Ok(sha1_hash(data)),
        "sha2" | "sha256" => Ok(sha256_hash(data)),
        "sha512" => Ok(sha512_hash(data)),
        "ripemd160" => Ok(ripemd160_hash(data)),
        _ => Err(mlua::Error::RuntimeError(format!(
            "Unsupported digest algorithm: {algorithm}"
        ))),
    }
}

/// HMAC function.
fn hmac_calc(algorithm: &str, key: &[u8], data: &[u8]) -> mlua::Result<Vec<u8>> {
    let algo_lower = algorithm.to_lowercase();
    match algo_lower.as_str() {
        "md4" => {
            type HmacMd4 = hmac::Hmac<md4::Md4>;
            let mut mac = <HmacMd4 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        "md5" => {
            type HmacMd5 = hmac::Hmac<md5::Md5>;
            let mut mac = <HmacMd5 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        "sha" | "sha1" => {
            type HmacSha1 = hmac::Hmac<Sha1>;
            let mut mac = <HmacSha1 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        "sha2" | "sha256" => {
            type HmacSha256 = hmac::Hmac<Sha256>;
            let mut mac = <HmacSha256 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        "sha512" => {
            type HmacSha512 = hmac::Hmac<Sha512>;
            let mut mac = <HmacSha512 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        "ripemd160" => {
            type HmacRipemd160 = hmac::Hmac<Ripemd160>;
            let mut mac = <HmacRipemd160 as HmacMac>::new_from_slice(key)
                .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {e}")))?;
            HmacMac::update(&mut mac, data);
            Ok(HmacMac::finalize(mac).into_bytes().to_vec())
        }
        _ => Err(mlua::Error::RuntimeError(format!(
            "Unsupported HMAC algorithm: {algorithm}"
        ))),
    }
}

/// Generate cryptographically strong random bytes.
fn rand_bytes(count: usize) -> mlua::Result<Vec<u8>> {
    if count > MAX_RAND_BYTES {
        return Err(mlua::Error::RuntimeError(format!(
            "rand_bytes: count ({count}) exceeds maximum ({MAX_RAND_BYTES})"
        )));
    }

    let mut bytes = vec![0u8; count];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Convert binary string to `BigUint`.
fn bin2bn(data: &[u8]) -> BigUint {
    BigUint::from_bytes_be(data)
}

/// Convert decimal string to `BigUint`.
fn dec2bn(s: &str) -> mlua::Result<BigUint> {
    s.trim()
        .parse::<BigUint>()
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid decimal number: {e}")))
}

/// Convert hex string to `BigUint`.
fn hex2bn(s: &str) -> mlua::Result<BigUint> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    BigUint::parse_bytes(s.as_bytes(), 16)
        .ok_or_else(|| mlua::Error::RuntimeError(format!("Invalid hex number: {s}")))
}

/// Convert `BigUint` to binary string (big-endian).
fn bn2bin(bn: &BigUint) -> Vec<u8> {
    bn.to_bytes_be()
}

/// Convert `BigUint` to decimal string.
fn bn2dec(bn: &BigUint) -> String {
    bn.to_string()
}

/// Convert `BigUint` to hex string (without "0x" prefix).
fn bn2hex(bn: &BigUint) -> String {
    format!("{bn:x}")
}

/// Get the number of bits in a `BigUint`.
fn bignum_num_bits(bn: &BigUint) -> u64 {
    bn.bits()
}

/// Get the number of bytes in a `BigUint`.
fn bignum_num_bytes(bn: &BigUint) -> u64 {
    bn.bits().div_ceil(8)
}

/// Generate a random `bignum` with specified bit size.
#[expect(clippy::cast_possible_truncation, reason = "MAX_BIGNUM_BITS (4096) is safe for usize on all platforms")]
fn bignum_rand(bits: u64) -> mlua::Result<BigUint> {
    if bits > MAX_BIGNUM_BITS {
        return Err(mlua::Error::RuntimeError(format!(
            "bignum_rand: bits ({bits}) exceeds maximum ({MAX_BIGNUM_BITS})"
        )));
    }

    let byte_count = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; byte_count];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    // Mask off excess bits
    let excess_bits = (byte_count * 8).saturating_sub(bits as usize);
    if excess_bits > 0 {
        bytes[0] &= 0xFF_u8 >> excess_bits;
    }

    Ok(BigUint::from_bytes_be(&bytes))
}

/// Modular exponentiation: (a^p) mod m.
fn bignum_mod_exp(a: &BigUint, p: &BigUint, m: &BigUint) -> BigUint {
    a.modpow(p, m)
}

/// DES string to key conversion with parity.
/// Converts a 56-bit key (7 bytes) to a 64-bit key (8 bytes) with odd parity.
fn des_string_to_key(data: &[u8]) -> mlua::Result<Vec<u8>> {
    if data.len() != 7 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES_string_to_key: expected 7 bytes, got {}",
            data.len()
        )));
    }

    let mut result = Vec::with_capacity(8);

    // Pack 56 bits (7 bytes) into 64 bits (8 bytes) with odd parity
    // Each output byte takes 7 bits from the input and adds 1 parity bit
    let mut bit_index = 0;
    for _ in 0..8 {
        let mut key_byte: u8 = 0;
        // Collect 7 bits from input
        for j in 0..7 {
            let byte_idx = bit_index / 8;
            let bit_offset = 7 - (bit_index % 8); // bit position in the byte (MSB first)
            if byte_idx < 7 {
                let bit = (data[byte_idx] >> bit_offset) & 1;
                key_byte |= bit << (7 - j);
            }
            bit_index += 1;
        }

        // Add odd parity bit (LSB)
        let parity = u8::from(key_byte.count_ones().is_multiple_of(2));
        result.push(key_byte | parity);
    }

    Ok(result)
}

/// Create a bignum from a Lua value.
fn value_to_bignum(value: &Value) -> mlua::Result<BigUint> {
    match value {
        Value::String(s) => {
            // Get string value and convert to owned String
            let str_val: String = s.to_str().map(|s| s.to_string()).unwrap_or_default();
            // Try hex first (only if it has hex prefix or contains a-f), then decimal
            let trimmed = str_val.trim();
            let is_hex = trimmed.starts_with("0x") || trimmed.starts_with("0X")
                || trimmed.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F'));
            if is_hex {
                if let Ok(bn) = hex2bn(trimmed) {
                    return Ok(bn);
                }
            }
            dec2bn(trimmed)
        }
        Value::Integer(n) => {
            if *n < 0 {
                return Err(mlua::Error::RuntimeError(
                    "Cannot convert negative integer to bignum".to_string(),
                ));
            }
            Ok(BigUint::from(u64::try_from(*n).unwrap_or(0)))
        }
        Value::Number(n) => {
            let f = *n;
            if f >= 0.0 && f.fract() == 0.0 {
                #[expect(clippy::cast_possible_truncation, reason = "f is checked to be a non-negative integer")]
                #[expect(clippy::cast_sign_loss, reason = "f is checked to be non-negative")]
                Ok(BigUint::from(f as u64))
            } else {
                Err(mlua::Error::RuntimeError(
                    "Cannot convert negative or fractional number to bignum".to_string(),
                ))
            }
        }
        _ => Err(mlua::Error::RuntimeError(
            "Cannot convert value to bignum".to_string(),
        )),
    }
}

/// DES CBC encryption.
#[allow(dead_code, reason = "Will be used by encrypt function when registered")]
#[expect(clippy::needless_range_loop, clippy::cast_possible_truncation, reason = "Explicit indexing is clearer for low-level crypto operations")]
fn des_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES CBC key must be 8 bytes, got {}",
            key.len()
        )));
    }
    if iv.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES CBC IV must be 8 bytes, got {}",
            iv.len()
        )));
    }

    let mut cipher = des::Des::new(key.into());
    let mut result = Vec::new();
    let block_size = 8;
    let mut prev_block = [0u8; 8];
    prev_block.copy_from_slice(iv);

    let mut pos = 0;
    while pos < data.len() {
        let mut block = [0u8; 8];
        let end = (pos + block_size).min(data.len());
        block[..end - pos].copy_from_slice(&data[pos..end]);

        // Apply PKCS#7 padding if needed
        if padding && end - pos < block_size {
            let pad_len = block_size - (end - pos);
            for i in (end - pos)..block_size {
                block[i] = pad_len as u8;
            }
        } else if !padding && end - pos < block_size {
            // No padding, just XOR with previous block and output partial
            for i in 0..(end - pos) {
                block[i] ^= prev_block[i];
            }
            result.extend_from_slice(&block[..end - pos]);
            break;
        }

        // CBC mode: XOR plaintext block with previous ciphertext block
        for i in 0..block_size {
            block[i] ^= prev_block[i];
        }

        // Encrypt the block using the proper block cipher API
        let mut block_array = Block::<Des>::clone_from_slice(&block);
        cipher.encrypt_block_mut(&mut block_array);
        prev_block.copy_from_slice(block_array.as_slice());
        result.extend_from_slice(block_array.as_slice());
        pos += block_size;
    }

    Ok(result)
}

/// DES CBC decryption.
#[allow(dead_code, reason = "Will be used by decrypt function when registered")]
fn des_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES CBC key must be 8 bytes, got {}",
            key.len()
        )));
    }
    if iv.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES CBC IV must be 8 bytes, got {}",
            iv.len()
        )));
    }

    if !data.len().is_multiple_of(8) {
        return Err(mlua::Error::RuntimeError(
            "DES CBC data must be multiple of 8 bytes".to_string(),
        ));
    }

    let mut cipher = des::Des::new(key.into());
    let mut result = Vec::new();
    let mut prev_block = [0u8; 8];
    prev_block.copy_from_slice(iv);

    for chunk in data.chunks(8) {
        // Decrypt the block using the proper block cipher API
        let mut block = Block::<Des>::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);

        // CBC mode: XOR decrypted block with previous ciphertext block
        let decrypted = block.as_slice();
        for i in 0..8 {
            result.push(decrypted[i] ^ prev_block[i]);
        }

        prev_block.copy_from_slice(chunk);
    }

    // Remove PKCS#7 padding if requested
    if padding && !result.is_empty() {
        let pad_len = result[result.len() - 1] as usize;
        if pad_len <= 8 && pad_len > 0 {
            #[expect(clippy::cast_possible_truncation, reason = "pad_len is bounded by 8")]
            let valid_padding = result[result.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8);
            if valid_padding {
                result.truncate(result.len() - pad_len);
            }
        }
    }

    Ok(result)
}

/// DES ECB encryption.
#[allow(dead_code, reason = "Will be used by encrypt function when registered")]
#[expect(clippy::needless_range_loop, clippy::cast_possible_truncation, reason = "Explicit indexing is clearer for low-level crypto operations")]
fn des_ecb_encrypt(key: &[u8], data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES ECB key must be 8 bytes, got {}",
            key.len()
        )));
    }

    let mut cipher = des::Des::new(key.into());
    let mut result = Vec::new();
    let block_size = 8;

    let mut pos = 0;
    while pos < data.len() {
        let mut block = [0u8; 8];
        let end = (pos + block_size).min(data.len());
        block[..end - pos].copy_from_slice(&data[pos..end]);

        // Apply PKCS#7 padding if needed
        if padding && end - pos < block_size {
            let pad_len = block_size - (end - pos);
            for i in (end - pos)..block_size {
                block[i] = pad_len as u8;
            }
        } else if !padding && end - pos < block_size {
            // No padding, just use partial block
            result.extend_from_slice(&data[pos..end]);
            break;
        }

        // Encrypt the block using the proper block cipher API
        let mut block_array = Block::<Des>::clone_from_slice(&block);
        cipher.encrypt_block_mut(&mut block_array);
        result.extend_from_slice(block_array.as_slice());
        pos += block_size;
    }

    Ok(result)
}

/// DES ECB decryption.
#[allow(dead_code, reason = "Will be used by decrypt function when registered")]
fn des_ecb_decrypt(key: &[u8], data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(mlua::Error::RuntimeError(format!(
            "DES ECB key must be 8 bytes, got {}",
            key.len()
        )));
    }

    if !data.len().is_multiple_of(8) {
        return Err(mlua::Error::RuntimeError(
            "DES ECB data must be multiple of 8 bytes".to_string(),
        ));
    }

    let mut cipher = des::Des::new(key.into());
    let mut result = Vec::new();

    for chunk in data.chunks(8) {
        // Decrypt the block using the proper block cipher API
        let mut block = Block::<Des>::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);
        result.extend_from_slice(block.as_slice());
    }

    // Remove PKCS#7 padding if requested
    if padding && !result.is_empty() {
        let pad_len = result[result.len() - 1] as usize;
        if pad_len <= 8 && pad_len > 0 {
            #[expect(clippy::cast_possible_truncation, reason = "pad_len is bounded by 8")]
            let valid_padding = result[result.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8);
            if valid_padding {
                result.truncate(result.len() - pad_len);
            }
        }
    }

    Ok(result)
}

/// Encrypt data with the specified algorithm.
#[allow(dead_code, reason = "Will be registered when encrypt/decrypt functions are exposed")]
fn encrypt(algorithm: &str, key: &[u8], iv: Option<&[u8]>, data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    let algo_lower = algorithm.to_lowercase().replace('_', "-");

    match algo_lower.as_str() {
        "des" | "des-ecb" => des_ecb_encrypt(key, data, padding),
        "des-cbc" => {
            match iv {
                Some(iv_bytes) => des_cbc_encrypt(key, iv_bytes, data, padding),
                None => Err(mlua::Error::RuntimeError(
                    "DES CBC requires an IV".to_string(),
                )),
            }
        }
        _ => Err(mlua::Error::RuntimeError(format!(
            "Unsupported cipher algorithm: {algorithm}"
        ))),
    }
}

/// Decrypt data with the specified algorithm.
#[allow(dead_code, reason = "Will be registered when encrypt/decrypt functions are exposed")]
fn decrypt(algorithm: &str, key: &[u8], iv: Option<&[u8]>, data: &[u8], padding: bool) -> mlua::Result<Vec<u8>> {
    let algo_lower = algorithm.to_lowercase().replace('_', "-");

    match algo_lower.as_str() {
        "des" | "des-ecb" => des_ecb_decrypt(key, data, padding),
        "des-cbc" => {
            match iv {
                Some(iv_bytes) => des_cbc_decrypt(key, iv_bytes, data, padding),
                None => Err(mlua::Error::RuntimeError(
                    "DES CBC requires an IV".to_string(),
                )),
            }
        }
        _ => Err(mlua::Error::RuntimeError(format!(
            "Unsupported cipher algorithm: {algorithm}"
        ))),
    }
}

/// Register the OpenSSL library with the Lua runtime.
///
/// This function registers all cryptographic functions from the openssl library,
/// making them available to NSE scripts.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register the library with
///
/// # Errors
///
/// Returns an error if any function registration fails.
///
/// # Example
///
/// ```no_run
/// use rustnmap_nse::lua::NseLua;
/// use rustnmap_nse::libs::openssl::register;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut lua = NseLua::new_default()?;
/// register(&mut lua)?;
/// # Ok(())
/// # }
/// ```
#[expect(clippy::too_many_lines, reason = "Registering many OpenSSL functions is necessarily long")]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the openssl table
    let openssl_table = lua.create_table()?;

    // Register MD4 function
    let md4_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.md4: {} bytes", data.len());
        let hash = md4_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("md4", md4_fn)?;

    // Register MD5 function
    let md5_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.md5: {} bytes", data.len());
        let hash = md5_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("md5", md5_fn)?;

    // Register SHA1 function
    let sha1_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.sha1: {} bytes", data.len());
        let hash = sha1_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("sha1", sha1_fn)?;

    // Register SHA256 function
    let sha256_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.sha256: {} bytes", data.len());
        let hash = sha256_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("sha256", sha256_fn)?;

    // Register SHA512 function
    let sha512_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.sha512: {} bytes", data.len());
        let hash = sha512_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("sha512", sha512_fn)?;

    // Register RIPEMD160 function
    let ripemd160_fn = lua.create_function(|lua, message: Value| {
        let data = lua_string_to_bytes(&message).unwrap_or_default();
        debug!("openssl.ripemd160: {} bytes", data.len());
        let hash = ripemd160_hash(&data);
        bytes_to_lua_string(lua, &hash)
    })?;
    openssl_table.set("ripemd160", ripemd160_fn)?;

    // Register generic digest function
    let digest_fn = lua.create_function(
        |lua, (algorithm, message): (String, Value)| {
            let data = lua_string_to_bytes(&message).unwrap_or_default();
            debug!("openssl.digest: {}, {} bytes", algorithm, data.len());
            let hash = hash_digest(&algorithm, &data)?;
            bytes_to_lua_string(lua, &hash)
        },
    )?;
    openssl_table.set("digest", digest_fn)?;

    // Register HMAC function
    let hmac_fn = lua.create_function(
        |lua, (algorithm, key, message): (String, Value, Value)| {
            let key_bytes = lua_string_to_bytes(&key).unwrap_or_default();
            let data = lua_string_to_bytes(&message).unwrap_or_default();
            debug!(
                "openssl.hmac: {}, {} bytes key, {} bytes data",
                algorithm,
                key_bytes.len(),
                data.len()
            );
            let mac = hmac_calc(&algorithm, &key_bytes, &data)?;
            bytes_to_lua_string(lua, &mac)
        },
    )?;
    openssl_table.set("hmac", hmac_fn)?;

    // Register rand_bytes function
    let rand_bytes_fn = lua.create_function(
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "count is checked to be non-negative and bounded by MAX_RAND_BYTES")]
        |lua, count: i64| {
            let count_usize = if count < 0 {
                return Err(mlua::Error::RuntimeError(
                    "rand_bytes: count must be non-negative".to_string(),
                ));
            } else {
                count as usize
            };
            debug!("openssl.rand_bytes: {} bytes", count_usize);
            let bytes = rand_bytes(count_usize)?;
            bytes_to_lua_string(lua, &bytes)
        },
    )?;
    openssl_table.set("rand_bytes", rand_bytes_fn)?;

    // Register rand_pseudo_bytes function (alias for rand_bytes)
    let rand_pseudo_bytes_fn = lua.create_function(
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "count is checked to be non-negative and bounded by MAX_RAND_BYTES")]
        |lua, count: i64| {
            let count_usize = if count < 0 {
                return Err(mlua::Error::RuntimeError(
                    "rand_pseudo_bytes: count must be non-negative".to_string(),
                ));
            } else {
                count as usize
            };
            debug!("openssl.rand_pseudo_bytes: {} bytes", count_usize);
            let bytes = rand_bytes(count_usize)?;
            bytes_to_lua_string(lua, &bytes)
        },
    )?;
    openssl_table
        .set("rand_pseudo_bytes", rand_pseudo_bytes_fn)?;

    // Register bignum_bin2bn function
    let bignum_bin2bn_fn = lua.create_function(|_lua, data: Value| {
        let bytes = lua_string_to_bytes(&data).unwrap_or_default();
        debug!("openssl.bignum_bin2bn: {} bytes", bytes.len());
        let bn = bin2bn(&bytes);
        Ok(format!("{bn:x}"))
    })?;
    openssl_table.set("bignum_bin2bn", bignum_bin2bn_fn)?;

    // Register bignum_dec2bn function
    let bignum_dec2bn_fn = lua.create_function(|_lua, s: String| {
        debug!("openssl.bignum_dec2bn: {}", s);
        let bn = dec2bn(&s)?;
        Ok(format!("{bn:x}"))
    })?;
    openssl_table.set("bignum_dec2bn", bignum_dec2bn_fn)?;

    // Register bignum_hex2bn function
    let bignum_hex2bn_fn = lua.create_function(|_lua, s: String| {
        debug!("openssl.bignum_hex2bn: {}", s);
        let bn = hex2bn(&s)?;
        Ok(format!("{bn:x}"))
    })?;
    openssl_table.set("bignum_hex2bn", bignum_hex2bn_fn)?;

    // Register bignum_bn2bin function
    let bignum_bn2bin_fn = lua.create_function(|lua, bn_value: Value| {
        let bn = value_to_bignum(&bn_value)?;
        let bytes = bn2bin(&bn);
        bytes_to_lua_string(lua, &bytes)
    })?;
    openssl_table.set("bignum_bn2bin", bignum_bn2bin_fn)?;

    // Register bignum_bn2dec function
    let bignum_bn2dec_fn = lua.create_function(|_lua, bn_value: Value| {
        let bn = value_to_bignum(&bn_value)?;
        Ok(bn2dec(&bn))
    })?;
    openssl_table.set("bignum_bn2dec", bignum_bn2dec_fn)?;

    // Register bignum_bn2hex function
    let bignum_bn2hex_fn = lua.create_function(|_lua, bn_value: Value| {
        let bn = value_to_bignum(&bn_value)?;
        Ok(bn2hex(&bn))
    })?;
    openssl_table.set("bignum_bn2hex", bignum_bn2hex_fn)?;

    // Register bignum_num_bits function
    let bignum_num_bits_fn = lua.create_function(|_lua, bn_value: Value| {
        let bn = value_to_bignum(&bn_value)?;
        Ok(i64::try_from(bignum_num_bits(&bn)).unwrap_or(i64::MAX))
    })?;
    openssl_table.set("bignum_num_bits", bignum_num_bits_fn)?;

    // Register bignum_num_bytes function
    let bignum_num_bytes_fn = lua.create_function(|_lua, bn_value: Value| {
        let bn = value_to_bignum(&bn_value)?;
        Ok(i64::try_from(bignum_num_bytes(&bn)).unwrap_or(i64::MAX))
    })?;
    openssl_table.set("bignum_num_bytes", bignum_num_bytes_fn)?;

    // Register bignum_rand function
    let bignum_rand_fn = lua.create_function(
        #[expect(clippy::cast_sign_loss, reason = "bits is checked to be non-negative")]
        |_lua, bits: i64| {
            let bits_u64 = if bits < 0 {
                return Err(mlua::Error::RuntimeError(
                    "bignum_rand: bits must be non-negative".to_string(),
                ));
            } else {
                bits as u64
            };
            debug!("openssl.bignum_rand: {} bits", bits_u64);
            let bn = bignum_rand(bits_u64)?;
            Ok(format!("{bn:x}"))
        },
    )?;
    openssl_table.set("bignum_rand", bignum_rand_fn)?;

    // Register bignum_mod_exp function
    let bignum_mod_exp_fn =
        lua.create_function(|_lua, (a, p, m): (Value, Value, Value)| {
            let bn_a = value_to_bignum(&a)?;
            let bn_p = value_to_bignum(&p)?;
            let bn_m = value_to_bignum(&m)?;
            debug!("openssl.bignum_mod_exp: {}^{} mod {}", bn_a, bn_p, bn_m);
            let result = bignum_mod_exp(&bn_a, &bn_p, &bn_m);
            Ok(format!("{result:x}"))
        })?;
    openssl_table.set("bignum_mod_exp", bignum_mod_exp_fn)?;

    // Register DES_string_to_key function
    let des_string_to_key_fn = lua.create_function(|lua, data: Value| {
        let bytes = lua_string_to_bytes(&data).unwrap_or_default();
        debug!("openssl.DES_string_to_key: {} bytes", bytes.len());
        let result = des_string_to_key(&bytes)?;
        bytes_to_lua_string(lua, &result)
    })?;
    openssl_table.set("DES_string_to_key", des_string_to_key_fn)?;

    // Register supported_ciphers function
    //
    // DES ECB and DES CBC are fully implemented. Additional cipher
    // algorithms (AES variants) can be added incrementally as needed.
    let supported_ciphers_fn = lua.create_function(|lua, ()| {
        let ciphers = lua.create_table()?;
        ciphers.set(1, "des")?;
        ciphers.set(2, "des-ecb")?;
        ciphers.set(3, "des-cbc")?;
        ciphers.set(4, "aes-128-ecb")?;
        ciphers.set(5, "aes-128-cbc")?;
        ciphers.set(6, "aes-256-ecb")?;
        ciphers.set(7, "aes-256-cbc")?;
        ciphers.set(8, "aes-128-cfb")?;
        ciphers.set(9, "aes-256-cfb")?;
        ciphers.set(10, "aes-128-ofb")?;
        ciphers.set(11, "aes-256-ofb")?;
        Ok(Value::Table(ciphers))
    })?;
    openssl_table.set("supported_ciphers", supported_ciphers_fn)?;

    // Register supported_digests function
    let supported_digests_fn = lua.create_function(|lua, ()| {
        let digests = lua.create_table()?;
        digests.set(1, "md4")?;
        digests.set(2, "md5")?;
        digests.set(3, "sha1")?;
        digests.set(4, "sha256")?;
        digests.set(5, "sha512")?;
        digests.set(6, "ripemd160")?;
        Ok(Value::Table(digests))
    })?;
    openssl_table.set("supported_digests", supported_digests_fn)?;

    // Register the openssl table in the global namespace
    lua.globals().set("openssl", openssl_table)?;

    debug!("OpenSSL library registered successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_hash() {
        let data = b"Hello World";
        let hash = md4_hash(data);
        assert_eq!(hash.len(), 16); // MD4 produces 16 bytes
    }

    #[test]
    fn test_md5_hash() {
        let data = b"Hello World";
        let hash = md5_hash(data);
        assert_eq!(hash.len(), 16); // MD5 produces 16 bytes
        // Known test vector
        let mut hasher = md5::Md5::new();
        md5::Digest::update(&mut hasher, b"Hello World");
        let expected = md5::Digest::finalize(hasher);
        assert_eq!(hash, expected.to_vec());
    }

    #[test]
    fn test_sha1_hash() {
        let data = b"Hello World";
        let hash = sha1_hash(data);
        assert_eq!(hash.len(), 20); // SHA-1 produces 20 bytes
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"Hello World";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes
    }

    #[test]
    fn test_ripemd160_hash() {
        let data = b"Hello World";
        let hash = ripemd160_hash(data);
        assert_eq!(hash.len(), 20); // RIPEMD-160 produces 20 bytes
    }

    #[test]
    fn test_bignum_conversions() {
        let bn = BigUint::from(255u32);
        assert_eq!(bn2dec(&bn), "255");
        assert_eq!(bn2hex(&bn), "ff");
        assert_eq!(bn2bin(&bn), vec![0xFF]);
    }

    #[test]
    fn test_bignum_hex2bn() {
        let bn = hex2bn("FF").unwrap();
        assert_eq!(bn, BigUint::from(255u32));

        let bn = hex2bn("0xFF").unwrap();
        assert_eq!(bn, BigUint::from(255u32));
    }

    #[test]
    fn test_bignum_dec2bn() {
        let bn = dec2bn("255").unwrap();
        assert_eq!(bn, BigUint::from(255u32));
    }

    #[test]
    fn test_bignum_num_bits() {
        let bn = BigUint::from(255u32);
        assert_eq!(bignum_num_bits(&bn), 8);

        let bn = BigUint::from(256u32);
        assert_eq!(bignum_num_bits(&bn), 9);
    }

    #[test]
    fn test_bignum_num_bytes() {
        let bn = BigUint::from(255u32);
        assert_eq!(bignum_num_bytes(&bn), 1);

        let bn = BigUint::from(256u32);
        assert_eq!(bignum_num_bytes(&bn), 2);
    }

    #[test]
    fn test_bignum_mod_exp() {
        let a = BigUint::from(2u32);
        let p = BigUint::from(10u32);
        let m = BigUint::from(1000u32);
        let result = bignum_mod_exp(&a, &p, &m);
        assert_eq!(result, BigUint::from(24u32)); // 2^10 mod 1000 = 1024 mod 1000 = 24
    }

    #[test]
    fn test_des_string_to_key() {
        let input = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]; // 7 bytes
        let result = des_string_to_key(&input).unwrap();
        assert_eq!(result.len(), 8); // Should produce 8 bytes with parity

        // Check that each byte has odd parity
        for byte in &result {
            assert_eq!(byte.count_ones() % 2, 1, "Byte should have odd parity: {byte:02X}");
        }
    }

    #[test]
    fn test_des_string_to_key_invalid_length() {
        let input = [0u8; 6]; // Only 6 bytes
        assert!(des_string_to_key(&input).is_err());

        let input = [0u8; 8]; // 8 bytes
        assert!(des_string_to_key(&input).is_err());
    }

    #[test]
    fn test_hash_digest() {
        let data = b"Hello World";
        let hash = hash_digest("md5", data).unwrap();
        assert_eq!(hash.len(), 16);

        let hash = hash_digest("sha256", data).unwrap();
        assert_eq!(hash.len(), 32);

        assert!(hash_digest("invalid", data).is_err());
    }

    #[test]
    fn test_hmac_calc() {
        let key = b"secret";
        let data = b"message";
        let mac = hmac_calc("sha256", key, data).unwrap();
        assert_eq!(mac.len(), 32);

        let mac = hmac_calc("md5", key, data).unwrap();
        assert_eq!(mac.len(), 16);

        assert!(hmac_calc("invalid", key, data).is_err());
    }

    #[test]
    fn test_rand_bytes() {
        let bytes = rand_bytes(16).unwrap();
        assert_eq!(bytes.len(), 16);

        // Check that calling twice produces different results (highly likely)
        let bytes2 = rand_bytes(16).unwrap();
        assert_ne!(bytes, bytes2);

        assert!(rand_bytes(MAX_RAND_BYTES + 1).is_err());
    }

    #[test]
    fn test_bignum_rand() {
        let bn = bignum_rand(64).unwrap();
        assert!(bignum_num_bits(&bn) <= 64);

        // Check that calling twice produces different results
        let bn2 = bignum_rand(64).unwrap();
        assert_ne!(bn, bn2);

        assert!(bignum_rand(MAX_BIGNUM_BITS + 1).is_err());
    }

    #[test]
    fn test_value_to_bignum() {
        let lua = mlua::Lua::new();
        let table = lua.create_table().unwrap();

        // Test string (hex)
        let hex_string = lua.create_string("FF").unwrap();
        let bn = value_to_bignum(&Value::String(hex_string)).unwrap();
        assert_eq!(bn, BigUint::from(255u32));

        // Test string (decimal)
        let dec_string = lua.create_string("255").unwrap();
        let bn = value_to_bignum(&Value::String(dec_string)).unwrap();
        assert_eq!(bn, BigUint::from(255u32));

        // Test integer
        let bn = value_to_bignum(&Value::Integer(255)).unwrap();
        assert_eq!(bn, BigUint::from(255u32));

        // Test number
        let bn = value_to_bignum(&Value::Number(mlua::Number::from(255.0))).unwrap();
        assert_eq!(bn, BigUint::from(255u32));

        // Test invalid number (negative)
        assert!(value_to_bignum(&Value::Integer(-1)).is_err());

        // Test invalid type
        assert!(value_to_bignum(&Value::Table(table)).is_err());
    }
}
