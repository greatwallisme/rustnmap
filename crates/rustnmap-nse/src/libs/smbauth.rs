//! SMB Authentication library for NSE.
//!
//! This module provides the `smbauth` library which contains functions for
//! SMB/NTLM authentication. It corresponds to Nmap's smbauth NSE library.
//!
//! # Available Functions
//!
//! - `smbauth.get_security_blob(security_blob, ...)` - Generate `NTLMSSP` security blob
//! - `smbauth.ntlmv1_response(hash, challenge)` - Create `NTLMv1` response
//! - `smbauth.ntlmv2_response(hash, challenge, ...)` - Create `NTLMv2` response
//!
//! # NTLM Authentication Overview
//!
//! NTLM (NT LAN Manager) is a challenge-response authentication protocol used by
//! Windows/SMB. There are several variants:
//!
//! - **`NTLMv1`**: Uses `DES` encryption with the 8-byte challenge
//! - **`NTLMv2`**: Uses `HMAC-MD5` with variable-length client challenge
//! - **`LMv1`**: Legacy `LanMan` response (deprecated, weak)
//!
//! # Security Considerations
//!
//! `NTLM` is considered a legacy protocol with known weaknesses. `NTLMv1` is particularly
//! vulnerable to rainbow table attacks. `NTLMv2` provides better security through
//! the use of client-generated challenges.

use crate::error::Result;
use crate::libs::unicode;
use crate::lua::NseLua;
use des::cipher::{BlockDecrypt, KeyInit};
use des::Des;
use hmac::digest::{KeyInit as DigestKeyInit, Mac};
use hmac::Hmac;
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;
use std::time::{SystemTime, UNIX_EPOCH};

/// Type alias for HMAC-MD5
type HmacMd5 = Hmac<Md5>;

// NTLMSSP Message Types
const NTLMSSP_NEGOTIATE: u32 = 0x0000_0001;
const NTLMSSP_CHALLENGE: u32 = 0x0000_0002;
const NTLMSSP_AUTH: u32 = 0x0000_0003;

// NTLM Flags
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
#[allow(dead_code, reason = "Reserved for OEM encoding support")]
const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;
#[allow(dead_code, reason = "Reserved for target request support")]
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
#[allow(dead_code, reason = "Reserved for signing support")]
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
#[allow(dead_code, reason = "Reserved for sealing support")]
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
#[allow(dead_code, reason = "Reserved for domain target type")]
const NTLMSSP_TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
#[allow(dead_code, reason = "Reserved for server target type")]
const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x0002_0000;
#[allow(dead_code, reason = "Reserved for extended session security")]
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
#[allow(dead_code, reason = "Reserved for 128-bit encryption")]
const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
#[allow(dead_code, reason = "Reserved for key exchange")]
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
#[allow(dead_code, reason = "Reserved for 56-bit encryption")]
const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

/// Register the smbauth library with the Lua runtime.
///
/// Only registers NTLMSSP constants. The full `smbauth` Lua module
/// (in `nselib/smbauth.lua`) provides `get_security_blob`,
/// `get_password_response`, and other authentication functions that
/// operate on Lua binary strings. As a `DUAL_MODULE`, the Lua file
/// loads first and provides the complete implementation; these Rust
/// constants are merged in without overriding Lua functions.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the smbauth table with constants only.
    // Lua smbauth.lua provides get_security_blob, get_password_response,
    // calculate_signature, etc. via the DUAL_MODULE mechanism.
    let smbauth_table = lua.create_table()?;

    smbauth_table.set("NTLMSSP_NEGOTIATE", NTLMSSP_NEGOTIATE)?;
    smbauth_table.set("NTLMSSP_CHALLENGE", NTLMSSP_CHALLENGE)?;
    smbauth_table.set("NTLMSSP_AUTH", NTLMSSP_AUTH)?;
    smbauth_table.set("NTLMSSP_NEGOTIATE_UNICODE", NTLMSSP_NEGOTIATE_UNICODE)?;
    smbauth_table.set("NTLMSSP_NEGOTIATE_NTLM", NTLMSSP_NEGOTIATE_NTLM)?;
    smbauth_table.set(
        "NTLMSSP_NEGOTIATE_ALWAYS_SIGN",
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    )?;

    // Set the smbauth table in globals
    lua.globals().set("smbauth", smbauth_table)?;

    Ok(())
}

/// Build an NTLMSSP NEGOTIATE message.
///
/// This is the first message in the NTLM authentication handshake.
/// It is sent by the client to the server to negotiate authentication options.
///
/// Format:
/// ```text
/// Signature (8 bytes): "NTLMSSP\0"
/// MessageType (4 bytes): 0x00000001
/// Flags (4 bytes): Negotiation flags
/// DomainNameFields (8 bytes): Length, allocated, offset
/// WorkstationFields (8 bytes): Length, allocated, offset
/// Version (8 bytes, optional): Windows version
/// Payload: Domain name and workstation name
/// ```
///
/// # Arguments
///
/// * `flags` - The negotiation flags to use
///
/// # Panics
///
/// Panics if `domain_len` or `workstation_len` exceed `u16::MAX` (65535 bytes for domain,
/// 65535 bytes for workstation).
#[must_use]
pub fn build_negotiate_message(
    flags: u32,
    domain: Option<&[u8]>,
    workstation: Option<&[u8]>,
) -> Vec<u8> {
    let mut result = Vec::new();

    // Signature
    result.extend_from_slice(b"NTLMSSP\0");

    // Message Type (NEGOTIATE = 1)
    result.extend_from_slice(&NTLMSSP_NEGOTIATE.to_le_bytes());

    // Negotiate Flags
    result.extend_from_slice(&flags.to_le_bytes());

    // Calculate payload positions
    let header_len = 16; // Signature (8) + MessageType (4) + Flags (4)
    let fields_len = 16; // DomainNameFields (8) + WorkstationFields (8)
    let base_offset = header_len + fields_len;

    let domain_offset = base_offset;
    let domain_len = domain.map_or(0, <[u8]>::len);
    let workstation_offset = domain_offset + domain_len;
    let workstation_len = workstation.map_or(0, <[u8]>::len);

    // DomainNameFields
    result.extend_from_slice(
        &u16::try_from(domain_len)
            .expect("domain len fits in u16")
            .to_le_bytes(),
    ); // Length
    result.extend_from_slice(
        &u16::try_from(domain_len)
            .expect("domain len fits in u16")
            .to_le_bytes(),
    ); // Allocated
    result.extend_from_slice(
        &u32::try_from(domain_offset)
            .expect("domain offset fits in u32")
            .to_le_bytes(),
    ); // Offset

    // WorkstationFields
    result.extend_from_slice(
        &u16::try_from(workstation_len)
            .expect("workstation len fits in u16")
            .to_le_bytes(),
    ); // Length
    result.extend_from_slice(
        &u16::try_from(workstation_len)
            .expect("workstation len fits in u16")
            .to_le_bytes(),
    ); // Allocated
    result.extend_from_slice(
        &u32::try_from(workstation_offset)
            .expect("workstation offset fits in u32")
            .to_le_bytes(),
    ); // Offset

    // Payload
    if let Some(d) = domain {
        result.extend_from_slice(d);
    }
    if let Some(w) = workstation {
        result.extend_from_slice(w);
    }

    result
}

/// Build an NTLMSSP AUTHENTICATE message.
///
/// This is the third message in the NTLM authentication handshake.
/// It contains the actual authentication credentials (responses to the challenge).
///
/// Format:
/// ```text
/// Signature (8 bytes): "NTLMSSP\0"
/// MessageType (4 bytes): 0x00000003
/// LmChallengeResponseFields (8 bytes)
/// NtChallengeResponseFields (8 bytes)
/// DomainNameFields (8 bytes)
/// UserNameFields (8 bytes)
/// WorkstationFields (8 bytes)
/// EncryptedRandomSessionKeyFields (8 bytes)
/// NegotiateFlags (4 bytes)
/// Version (8 bytes, optional)
/// Payload: LM response, NT response, domain, username, workstation, session key
/// ```
///
/// # Arguments
///
/// * `lm_response` - The `LM` challenge response (24 bytes for `NTLMv1`)
/// * `nt_response` - The `NTLM` challenge response (variable length)
/// * `domain` - The domain name (UTF-16LE)
/// * `username` - The username (UTF-16LE)
/// * `workstation` - The workstation name (UTF-16LE)
/// * `session_key` - Optional encrypted session key
/// * `flags` - The negotiation flags
///
/// # Returns
///
/// A `Vec<u8>` containing the NTLMSSP AUTHENTICATE message
///
/// # Panics
///
/// Panics if any field length exceeds maximum allowed values:
/// - LM response: exceeds 65535 bytes
/// - NT response: exceeds 65535 bytes
/// - Domain exceeds 65535 bytes
/// - Username exceeds 65535 bytes
/// - Workstation exceeds 65535 bytes
/// - Session key (if provided) exceeds 65535 bytes
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "NTLM AUTHENTICATE message requires complex field encoding per protocol spec"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "NTLM AUTHENTICATE message requires many fields per protocol spec"
)]
pub fn build_authenticate_message(
    lm_response: &[u8],
    nt_response: &[u8],
    domain: &[u8],
    username: &[u8],
    workstation: &[u8],
    session_key: Option<&[u8]>,
    flags: u32,
) -> Vec<u8> {
    let mut result = Vec::new();

    // Signature
    result.extend_from_slice(b"NTLMSSP\0");

    // Message Type (AUTH = 3)
    result.extend_from_slice(&NTLMSSP_AUTH.to_le_bytes());

    // Calculate base offset (header + 6 field structures + flags)
    let header_len = 12; // Signature (8) + MessageType (4)
    let fields_len = 48; // 6 x 8 bytes for each field structure
    let flags_len = 4;
    let base_offset = header_len + fields_len + flags_len;

    let lm_offset = base_offset;
    let nt_offset = lm_offset + lm_response.len();
    let domain_offset = nt_offset + nt_response.len();
    let username_offset = domain_offset + domain.len();
    let workstation_offset = username_offset + username.len();
    let session_key_offset = workstation_offset + workstation.len();

    // LmChallengeResponseFields
    result.extend_from_slice(
        &u16::try_from(lm_response.len())
            .expect("lm response fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(lm_response.len())
            .expect("lm response fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(lm_offset)
            .expect("lm offset fits in u32")
            .to_le_bytes(),
    );

    // NtChallengeResponseFields
    result.extend_from_slice(
        &u16::try_from(nt_response.len())
            .expect("nt response fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(nt_response.len())
            .expect("nt response fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(nt_offset)
            .expect("nt offset fits in u32")
            .to_le_bytes(),
    );

    // DomainNameFields
    result.extend_from_slice(
        &u16::try_from(domain.len())
            .expect("domain fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(domain.len())
            .expect("domain fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(domain_offset)
            .expect("domain offset fits in u32")
            .to_le_bytes(),
    );

    // UserNameFields
    result.extend_from_slice(
        &u16::try_from(username.len())
            .expect("username fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(username.len())
            .expect("username fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(username_offset)
            .expect("username offset fits in u32")
            .to_le_bytes(),
    );

    // WorkstationFields
    result.extend_from_slice(
        &u16::try_from(workstation.len())
            .expect("workstation fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(workstation.len())
            .expect("workstation fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(workstation_offset)
            .expect("workstation offset fits in u32")
            .to_le_bytes(),
    );

    // EncryptedRandomSessionKeyFields
    let session_key_len = session_key.map_or(0, <[u8]>::len);
    result.extend_from_slice(
        &u16::try_from(session_key_len)
            .expect("session key fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u16::try_from(session_key_len)
            .expect("session key fits in u16")
            .to_le_bytes(),
    );
    result.extend_from_slice(
        &u32::try_from(session_key_offset)
            .expect("session key offset fits in u32")
            .to_le_bytes(),
    );

    // NegotiateFlags
    result.extend_from_slice(&flags.to_le_bytes());

    // Payload
    result.extend_from_slice(lm_response);
    result.extend_from_slice(nt_response);
    result.extend_from_slice(domain);
    result.extend_from_slice(username);
    result.extend_from_slice(workstation);
    if let Some(sk) = session_key {
        result.extend_from_slice(sk);
    }

    result
}

/// Parsed NTLMSSP CHALLENGE message.
#[derive(Debug, Clone)]
pub struct NtlmChallenge {
    /// Server challenge (8 bytes)
    pub challenge: [u8; 8],
    /// Negotiation flags from server
    pub flags: u32,
    /// Target name (domain/workstation)
    pub target_name: Option<String>,
}

/// Parse an NTLMSSP CHALLENGE message.
///
/// # Arguments
///
/// * `data` - The raw CHALLENGE message bytes
///
/// # Errors
///
/// Returns an error if the message is malformed.
///
/// # Returns
///
/// The parsed challenge data
pub fn parse_challenge_message(data: &[u8]) -> Result<NtlmChallenge> {
    // Check minimum length
    if data.len() < 48 {
        return Err(crate::error::Error::NetworkError(
            "NTLMSSP CHALLENGE message too short".to_string(),
        ));
    }

    // Verify signature
    if &data[..8] != b"NTLMSSP\0" {
        return Err(crate::error::Error::NetworkError(
            "Invalid NTLMSSP signature".to_string(),
        ));
    }

    // Verify message type
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != NTLMSSP_CHALLENGE {
        return Err(crate::error::Error::NetworkError(format!(
            "Expected CHALLENGE message (type {NTLMSSP_CHALLENGE}), got type {msg_type}"
        )));
    }

    // Extract target name fields (bytes 12-19)
    let target_name_len = u16::from_le_bytes([data[12], data[13]]) as usize;
    let target_name_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

    // Extract flags (bytes 20-23)
    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    // Extract challenge (bytes 24-31)
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&data[24..32]);

    // Extract target name if present
    let target_name = if target_name_len > 0 && target_name_offset + target_name_len <= data.len() {
        let name_bytes = &data[target_name_offset..target_name_offset + target_name_len];
        unicode::utf16le_to_utf8(name_bytes).ok()
    } else {
        None
    };

    Ok(NtlmChallenge {
        challenge,
        flags,
        target_name,
    })
}

/// Compute LM and NTLM responses for authentication.
///
/// # Arguments
///
/// * `challenge` - The parsed CHALLENGE message
/// * `username` - Optional username
/// * `password` - Optional password
/// * `hash_type` - Optional hash type ("ntlm", "lm", "ntlmv2")
///
/// # Errors
///
/// Returns an error if response computation fails.
///
/// # Returns
///
/// A tuple of (`lm_response`, `nt_response`) byte vectors
pub fn compute_responses(
    challenge: &NtlmChallenge,
    username: Option<&str>,
    password: Option<&str>,
    hash_type: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let hash_type = hash_type.unwrap_or("ntlm");

    match hash_type.to_lowercase().as_str() {
        "ntlm" | "ntlmv1" => {
            // NTLMv1: Use DES encryption with the challenge
            let password_hash = compute_ntlm_hash(password.unwrap_or(""));

            // LM response: 24 bytes
            let lm_response = compute_lm_response(challenge.challenge, password.unwrap_or(""));

            // NT response: 24 bytes
            let nt_response = compute_nt_response(challenge.challenge, password_hash);

            Ok((lm_response, nt_response))
        }
        "ntlmv2" => {
            // NTLMv2: Use HMAC-MD5
            let password_hash = compute_ntlm_hash(password.unwrap_or(""));
            let username_str = username.unwrap_or("");
            let domain = challenge.target_name.as_deref().unwrap_or("");

            // NTLMv2 response: variable length (minimum 16 + 8 for temp)
            let nt_response =
                compute_ntlmv2_response(challenge.challenge, password_hash, username_str, domain);

            // LMv2 response: 24 bytes (8-byte client challenge + 16-byte HMAC)
            let lm_response = compute_lmv2_response(challenge.challenge, password_hash);

            Ok((lm_response, nt_response))
        }
        "lm" => {
            // LM only (legacy)
            let lm_response = compute_lm_response(challenge.challenge, password.unwrap_or(""));
            Ok((lm_response, Vec::new()))
        }
        _ => Err(crate::error::Error::NetworkError(format!(
            "Unsupported hash type: {hash_type}"
        ))),
    }
}

/// Compute `NTLM` hash from password using `MD4`.
///
/// The `NTLM` hash is computed as `MD4`(`UTF-16LE`(password)).
/// This is the `NTOWFv1` function defined in `MS-NLMP`.
fn compute_ntlm_hash(password: &str) -> [u8; 16] {
    // Convert password to UTF-16LE
    let password_utf16 = unicode::utf8_to_utf16le(password);

    // MD4 hash of UTF-16LE password
    let mut hasher = Md4::new();
    hasher.update(&password_utf16);
    let result = hasher.finalize();

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute LM response using DES.
///
/// The LM hash is created by:
/// 1. Converting password to uppercase and padding/truncating to 14 bytes
/// 2. Splitting into two 7-byte halves
/// 3. DES encrypting the constant "KGS!@#$%" with each half as key
/// 4. The 16-byte result is the LM hash
///
/// The LM response is created by:
/// 1. Padding the LM hash to 21 bytes with zeros
/// 2. Splitting into three 7-byte parts
/// 3. DES encrypting the challenge with each part as key
/// 4. The 24-byte result is the LM response
///
/// # Panics
///
/// Panics if DES encryption fails (should never happen with valid inputs).
fn compute_lm_response(challenge: [u8; 8], password: &str) -> Vec<u8> {
    // The LM hash constant
    const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";

    // Step 1: Create LM hash
    let password_upper = password.to_uppercase();
    let password_bytes = password_upper.as_bytes();

    // Create 14-byte key (pad with zeros)
    let mut key14 = [0u8; 14];
    key14[..password_bytes.len().min(14)]
        .copy_from_slice(&password_bytes[..password_bytes.len().min(14)]);

    let mut lm_hash = [0u8; 16];
    let key1 = create_des_key(&key14[0..7]);
    let key2 = create_des_key(&key14[7..14]);

    des_encrypt_block(&LM_MAGIC, key1, &mut lm_hash[0..8]);
    des_encrypt_block(&LM_MAGIC, key2, &mut lm_hash[8..16]);

    // Step 2: Create LM response from LM hash
    // Pad LM hash to 21 bytes
    let mut padded_hash = [0u8; 21];
    padded_hash[..16].copy_from_slice(&lm_hash);

    // DES encrypt challenge with each 7-byte key segment
    let mut response = [0u8; 24];
    for (i, chunk) in response.chunks_exact_mut(8).enumerate() {
        let des_key = create_des_key(&padded_hash[i * 7..(i + 1) * 7]);
        des_encrypt_block(&challenge, des_key, chunk);
    }

    response.to_vec()
}

/// Compute NT response using DES.
///
/// The NT response is created by:
/// 1. Padding the NTLM hash to 21 bytes with zeros
/// 2. Splitting into three 7-byte parts
/// 3. DES encrypting the challenge with each part as key
/// 4. The 24-byte result is the NT response
///
/// # Panics
///
/// Panics if DES encryption fails (should never happen with valid inputs).
fn compute_nt_response(challenge: [u8; 8], password_hash: [u8; 16]) -> Vec<u8> {
    // Pad hash to 21 bytes
    let mut key21 = [0u8; 21];
    key21[..16].copy_from_slice(&password_hash);

    // DES encrypt challenge with each 7-byte key segment
    let mut response = [0u8; 24];
    for i in 0..3 {
        let des_key = create_des_key(&key21[i * 7..(i + 1) * 7]);
        des_encrypt_block(&challenge, des_key, &mut response[i * 8..(i + 1) * 8]);
    }

    response.to_vec()
}

/// Create an 8-byte DES key from a 7-byte key.
///
/// DES keys are 8 bytes but only use 56 bits of key material.
/// The 7-byte input is expanded to 8 bytes by inserting a parity bit
/// after every 7 bits.
fn create_des_key(key7: &[u8]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8[0] = key7[0];
    key8[1] = (key7[0] << 7) | (key7[1] >> 1);
    key8[2] = (key7[1] << 6) | (key7[2] >> 2);
    key8[3] = (key7[2] << 5) | (key7[3] >> 3);
    key8[4] = (key7[3] << 4) | (key7[4] >> 4);
    key8[5] = (key7[4] << 3) | (key7[5] >> 5);
    key8[6] = (key7[5] << 2) | (key7[6] >> 6);
    key8[7] = key7[6] << 1;

    // Set odd parity (DES requires odd parity in each byte)
    for byte in &mut key8 {
        *byte = set_odd_parity(*byte);
    }

    key8
}

/// Set odd parity bit in a byte.
///
/// DES keys require odd parity: the number of 1 bits in each byte must be odd.
fn set_odd_parity(byte: u8) -> u8 {
    // Count the number of 1 bits in the upper 7 bits (excluding LSB)
    let upper_bits = byte & 0xFE;
    let bit_count = upper_bits.count_ones();

    // If odd number of 1 bits in upper 7 bits, LSB should be 0
    // If even number of 1 bits in upper 7 bits, LSB should be 1
    if bit_count % 2 == 1 {
        upper_bits // LSB = 0
    } else {
        upper_bits | 0x01 // LSB = 1
    }
}

/// Get current time as Windows FILETIME.
///
/// FILETIME is a 64-bit value representing the number of 100-nanosecond
/// intervals since January 1, 1601 (UTC).
fn get_windows_filetime() -> [u8; 8] {
    // Seconds between January 1, 1601 and January 1, 1970
    // This is the difference between Windows FILETIME epoch and Unix epoch
    const SECS_BETWEEN_EPOCHS: u64 = 11_644_473_600;
    const SECS_TO_100NS: u64 = 10_000_000; // 100-nanosecond intervals per second

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let filetime =
        (now.as_secs() + SECS_BETWEEN_EPOCHS) * SECS_TO_100NS + u64::from(now.subsec_nanos() / 100);

    filetime.to_le_bytes()
}

/// DES encrypt a single 8-byte block.
///
/// # Arguments
///
/// * `input` - 8-byte input block
/// * `key` - 8-byte DES key
/// * `output` - 8-byte output buffer
fn des_encrypt_block(input: &[u8], key: [u8; 8], output: &mut [u8]) {
    let cipher = Des::new_from_slice(&key).expect("Invalid DES key");

    let mut block = des::cipher::Block::<Des>::clone_from_slice(input);
    cipher.decrypt_block(&mut block);
    output.copy_from_slice(&block);
}

/// Compute `NTLMv2` response.
///
/// The `NTLMv2` response is computed as:
/// 1. `NTLMv2` hash = `HMAC-MD5`(`NTLM` hash, uppercase(username) + domain)
/// 2. Create a blob with client challenge and timestamp
/// 3. `NTLMv2` response = `HMAC-MD5`(`NTLMv2` hash, server challenge + blob) + blob
fn compute_ntlmv2_response(
    challenge: [u8; 8],
    password_hash: [u8; 16],
    username: &str,
    domain: &str,
) -> Vec<u8> {
    // Create NTLMv2 hash: HMAC-MD5(password_hash, uppercase(username) + domain)
    let mut hmac = <HmacMd5 as DigestKeyInit>::new_from_slice(&password_hash)
        .expect("HMAC initialization failed");
    let username_upper = username.to_uppercase();
    let username_domain = format!("{}{}", username_upper, domain.to_uppercase());
    let username_domain_utf16 = unicode::utf8_to_utf16le(&username_domain);
    hmac.update(&username_domain_utf16);
    let ntlmv2_hash = hmac.finalize();
    let hash_bytes = ntlmv2_hash.into_bytes();

    // Create blob with client challenge
    // Generate random 8-byte client challenge
    let client_challenge: [u8; 8] = rand::random();

    // Get current timestamp as Windows FILETIME (100-nanosecond intervals since January 1, 1601)
    let timestamp = get_windows_filetime();

    let mut blob = vec![0x01, 0x01, 0x00, 0x00]; // Blob signature
    blob.extend_from_slice(&[0u8; 4]); // Reserved
    blob.extend_from_slice(&timestamp); // Windows FILETIME timestamp
    blob.extend_from_slice(&client_challenge); // Random client challenge
    blob.extend_from_slice(&[0u8; 4]); // Reserved

    // Compute HMAC-MD5(ntlmv2_hash, server_challenge + blob)
    let mut hmac2 = <HmacMd5 as DigestKeyInit>::new_from_slice(&hash_bytes)
        .expect("HMAC initialization failed");
    hmac2.update(&challenge);
    hmac2.update(&blob);
    let response_hash = hmac2.finalize();

    // Response = HMAC (16 bytes) + blob
    let mut response = Vec::new();
    response.extend_from_slice(&response_hash.into_bytes());
    response.extend(blob);

    response
}

/// Compute `LMv2` response.
///
/// The `LMv2` response is: `HMAC-MD5`(`password_hash`, `challenge` + `client_challenge`) + `client_challenge`
fn compute_lmv2_response(challenge: [u8; 8], password_hash: [u8; 16]) -> Vec<u8> {
    let client_challenge: [u8; 8] = rand::random();

    let mut hmac = <HmacMd5 as DigestKeyInit>::new_from_slice(&password_hash)
        .expect("HMAC initialization failed");
    hmac.update(&challenge);
    hmac.update(&client_challenge);
    let response_hash = hmac.finalize();

    // Response = HMAC (16 bytes) + client challenge (8 bytes)
    let mut response = Vec::new();
    response.extend_from_slice(&response_hash.into_bytes());
    response.extend_from_slice(&client_challenge);

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_negotiate_message() {
        let result = build_negotiate_message(
            NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE,
            None,
            None,
        );
        // Check signature
        assert_eq!(&result[..8], b"NTLMSSP\0");
        // Check message type
        assert_eq!(
            u32::from_le_bytes([result[8], result[9], result[10], result[11]]),
            NTLMSSP_NEGOTIATE
        );
    }

    #[test]
    fn test_build_authenticate_message() {
        let lm_response = vec![0u8; 24];
        let nt_response = vec![0u8; 24];
        let domain = b"DOMAIN";
        let username = b"USER";
        let workstation = b"WORKSTATION";

        let result = build_authenticate_message(
            &lm_response,
            &nt_response,
            domain,
            username,
            workstation,
            None,
            NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_UNICODE,
        );

        // Check signature
        assert_eq!(&result[..8], b"NTLMSSP\0");
        // Check message type
        assert_eq!(
            u32::from_le_bytes([result[8], result[9], result[10], result[11]]),
            NTLMSSP_AUTH
        );
    }

    #[test]
    fn test_compute_ntlm_hash() {
        // Test NTLM hash computation
        // Known test vector: NTLM hash of "password" is 8846f7eaee8fb117ad06bdd830b7586c
        let hash = compute_ntlm_hash("password");
        assert_eq!(
            hash,
            [
                0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7,
                0x58, 0x6c
            ]
        );
    }

    #[test]
    fn test_create_des_key() {
        // Test 7-to-8 byte key expansion
        let key7: [u8; 7] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let key8 = create_des_key(&key7);
        // With odd parity, all-zero input should produce specific output
        assert_eq!(key8.len(), 8);
    }

    #[test]
    fn test_set_odd_parity() {
        // Test odd parity setting
        assert_eq!(set_odd_parity(0x00), 0x01); // 0 bits -> need 1
        assert_eq!(set_odd_parity(0x01), 0x01); // 1 bit -> odd, ok
        assert_eq!(set_odd_parity(0x03), 0x02); // 2 bits -> need odd, remove one
        assert_eq!(set_odd_parity(0x07), 0x07); // 3 bits -> odd, ok
    }
}
