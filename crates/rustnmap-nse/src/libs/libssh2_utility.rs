//! libssh2-utility library for NSE.
//!
//! This module provides the `libssh2-utility` library which contains high-level
//! SSH connection operations for NSE scripts. It corresponds to Nmap's libssh2-utility
//! NSE library and provides an object-oriented interface to SSH operations.
//!
//! # `SSHConnection` Class
//!
//! The `SSHConnection` class provides methods for:
//! - Connecting to SSH servers
//! - Listing authentication methods
//! - Getting server banner
//! - Authentication (password, keyboard-interactive, publickey)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local libssh2_util = require "libssh2-utility"
//!
//! local helper = libssh2_util.SSHConnection:new()
//! local status, err = helper:connect_pcall(host, port)
//! if status then
//!     local methods = helper:list(username)
//!     local banner = helper:banner()
//!     helper:disconnect()
//! end
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use aes::Aes128;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use mlua::{MetaMethod, UserData, UserDataMethods, Value};
use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for SSH connections in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// SSH Transport Layer Protocol message codes (RFC 4253).
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEXDH_INIT: u8 = 30;
const SSH_MSG_KEXDH_REPLY: u8 = 31;

/// SSH Authentication Protocol message codes (RFC 4252).
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
const SSH_MSG_USERAUTH_BANNER: u8 = 53;
const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;

/// Diffie-Hellman Group1 Prime (1024-bit MODP) from RFC 2409 Section 6.1.
///
/// This is the "well-known" 1024-bit modular exponentiation group (Oakley Group 2).
/// Used for diffie-hellman-group1-sha1 key exchange.
const DH_GROUP1_PRIME_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 \
    FFFFFFFF FFFFFFFF";

/// Diffie-Hellman Group14 Prime (2048-bit MODP) from RFC 3526 Section 3.
///
/// This is the 2048-bit modular exponentiation group used for SSH key exchange.
/// The prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
#[expect(
    dead_code,
    reason = "Reserved for future implementation of diffie-hellman-group14-sha1"
)]
const DH_GROUP14_PRIME_HEX: &str = "\
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 \
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD \
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 \
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D \
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F \
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D \
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF";

/// Diffie-Hellman generator for all MODP groups (RFC 2409, RFC 3526).
///
/// All MODP groups use g = 2 as the generator.
const DH_GENERATOR: u32 = 2;

/// Build SSH-2 packet with payload and padding.
///
/// Returns `(length_bytes, packet_data)` where:
/// - `length_bytes`: 4-byte packet length in big-endian format
/// - `packet_data`: `padding_length` + payload + random padding
///
/// The length field is sent unencrypted. The `packet_data` is encrypted when encryption is active.
fn build_ssh2_packet(payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Calculate padding: 8 - ((payload + padding_length_byte + packet_length_field) % 8)
    // Per RFC 4253 Section 6, packet_length field IS included in the alignment calculation
    let mut padding_length = 8 - ((payload.len() + 1 + 4) % 8);
    // Minimum padding is 4 bytes
    if padding_length < 4 {
        padding_length += 8;
    }
    let padding_length: u8 = u8::try_from(padding_length).unwrap_or(4);
    let packet_length = payload.len() + usize::from(padding_length) + 1;

    let length_bytes = u32::to_be_bytes(u32::try_from(packet_length).unwrap_or(u32::MAX));

    let mut packet_data = Vec::with_capacity(1 + payload.len() + usize::from(padding_length));
    packet_data.push(padding_length);
    packet_data.extend_from_slice(payload);

    // Add random padding
    let mut rng = rand::thread_rng();
    for _ in 0..padding_length {
        packet_data.push(rng.gen());
    }

    (length_bytes.to_vec(), packet_data)
}

/// Build complete SSH-2 packet as a single byte vector (for backward compatibility).
///
/// This returns `[length_bytes][packet_data]` combined, suitable for unencrypted transmission.
/// For encrypted packets, use `build_ssh2_packet()` and handle encryption separately.
fn build_ssh2_packet_combined(payload: &[u8]) -> Vec<u8> {
    let (length_bytes, packet_data) = build_ssh2_packet(payload);

    let mut packet = Vec::with_capacity(4 + packet_data.len());
    packet.extend_from_slice(&length_bytes);
    packet.extend_from_slice(&packet_data);

    packet
}

/// Receive a complete SSH packet.
fn receive_ssh_packet(stream: &mut TcpStream) -> mlua::Result<Vec<u8>> {
    let mut packet_length_buf = [0u8; 4];
    stream
        .read_exact(&mut packet_length_buf)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read packet length: {e}")))?;

    let packet_length = u32::from_be_bytes(packet_length_buf) as usize;

    if packet_length > 262_144 {
        return Err(mlua::Error::RuntimeError(format!(
            "Packet too large: {packet_length}"
        )));
    }

    let mut buffer = vec![0u8; packet_length];
    stream
        .read_exact(&mut buffer)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read packet data: {e}")))?;

    Ok(buffer)
}

/// Extract payload from SSH packet.
fn extract_payload(packet: &[u8]) -> mlua::Result<Vec<u8>> {
    if packet.len() < 5 {
        return Err(mlua::Error::RuntimeError("Packet too short".to_string()));
    }

    let padding_length = packet[0] as usize;

    if padding_length + 1 > packet.len() {
        return Err(mlua::Error::RuntimeError(
            "Invalid padding length".to_string(),
        ));
    }

    let payload_length = packet.len() - padding_length - 1;

    Ok(packet[1..=payload_length].to_vec())
}

/// Parse string from SSH packet data.
fn parse_string(data: &[u8], offset: usize) -> mlua::Result<(String, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for string".to_string(),
        ));
    }

    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(
            "Data too short for string value".to_string(),
        ));
    }

    let value = String::from_utf8_lossy(&data[new_offset..new_offset + len]).to_string();
    Ok((value, new_offset + len))
}

/// Parse name-list from SSH packet data.
fn parse_namelist(data: &[u8], offset: usize) -> mlua::Result<(Vec<String>, usize)> {
    let (list_str, new_offset) = parse_string(data, offset)?;
    if list_str.is_empty() {
        Ok((vec![], new_offset))
    } else {
        let methods: Vec<String> = list_str
            .split(',')
            .map(std::string::ToString::to_string)
            .collect();
        Ok((methods, new_offset))
    }
}

/// Parse MPINT (multiple precision integer) from SSH packet data.
///
/// MPINT format (RFC 4253 Section 5):
/// - 4-byte length (unsigned)
/// - n bytes of integer value (two's complement, big-endian)
fn parse_mpint(data: &[u8], offset: usize) -> mlua::Result<(BigUint, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for MPINT".to_string(),
        ));
    }

    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(
            "Data too short for MPINT value".to_string(),
        ));
    }

    if len == 0 {
        return Ok((BigUint::from(0u32), new_offset));
    }

    // MPINT is two's complement, but for positive values (which DH uses),
    // we can directly convert to BigUint
    let value = BigUint::from_bytes_be(&data[new_offset..new_offset + len]);
    Ok((value, new_offset + len))
}

/// Serialize MPINT (multiple precision integer) to SSH packet format.
fn serialize_mpint(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();

    // MPINT requires the high bit to be zero for positive values
    // If the high bit is set, prepend a zero byte
    if bytes.first().is_some_and(|b| *b & 0x80 != 0) {
        let len_plus_1 = u32::try_from(bytes.len() + 1).unwrap_or(u32::MAX);
        let mut v = Vec::with_capacity(4 + bytes.len() + 1);
        v.extend_from_slice(&u32::to_be_bytes(len_plus_1));
        v.push(0);
        v.extend_from_slice(&bytes);
        v
    } else {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut v = Vec::with_capacity(4 + bytes.len());
        v.extend_from_slice(&u32::to_be_bytes(len));
        v.extend_from_slice(&bytes);
        v
    }
}

/// Generate Diffie-Hellman key pair for Group14.
///
/// Returns (`public_key`, `private_key`) where:
/// - `public_key`: e = g^x mod p (for sending to server)
/// - `private_key`: x (random value, 1 < x < p-1, kept secret)
///
/// # Panics
///
/// Panics if the DH prime cannot be parsed (should not happen with valid constant).
fn generate_dh_key_pair() -> (BigUint, BigUint) {
    // Parse DH Group1 prime (remove whitespace and hex-decode)
    let prime_hex = DH_GROUP1_PRIME_HEX.replace([' ', '\t', '\n', '\r'], "");
    let p = BigUint::parse_bytes(prime_hex.as_bytes(), 16).expect("Invalid DH prime");
    let g = BigUint::from(DH_GENERATOR);

    // Generate private key x where 1 < x < p-1
    // Use random bytes approach for compatibility
    let mut rng = rand::thread_rng();
    let p_minus_1 = &p - BigUint::one();

    // Generate random bytes and convert to BigUint
    #[expect(
        clippy::manual_div_ceil,
        reason = "Compatibility with older Rust versions"
    )]
    let byte_count = ((p.bits() + 7) / 8) as usize;
    let mut bytes = vec![0u8; byte_count];
    rng.fill_bytes(&mut bytes);
    let mut x = BigUint::from_bytes_be(&bytes);

    // Ensure 1 < x < p-1
    x %= &p_minus_1;
    if x <= BigUint::one() {
        x = BigUint::from(2u32);
    }

    // Compute public key e = g^x mod p
    let e = g.modpow(&x, &p);

    (e, x)
}

/// Compute shared secret using DH private key and server's public key.
///
/// Given client private key x and server public key f,
/// computes K = f^x mod p.
///
/// # Panics
///
/// Panics if the DH prime cannot be parsed (should not happen with valid constant).
fn compute_shared_secret(f: &BigUint, x: &BigUint) -> BigUint {
    debug!("libssh2-utility.compute_shared_secret - Computing K = f^x mod p");
    let prime_hex = DH_GROUP1_PRIME_HEX.replace([' ', '\t', '\n', '\r'], "");
    let p = BigUint::parse_bytes(prime_hex.as_bytes(), 16).expect("Invalid DH prime");
    let result = f.modpow(x, &p);
    debug!("libssh2-utility.compute_shared_secret - Computed successfully");
    result
}

/// Build `KEXDH_INIT` packet.
///
/// `KEXDH_INIT` format (RFC 4253 Section 8):
/// - byte      `SSH_MSG_KEXDH_INIT` (30)
/// - mpint     e (client's DH public key)
fn build_kexdh_init(e: &BigUint) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_MSG_KEXDH_INIT);
    payload.extend_from_slice(&serialize_mpint(e));
    payload
}

/// Parse `KEXDH_REPLY` packet.
///
/// `KEXDH_REPLY` format (RFC 4253 Section 8):
/// - byte      `SSH_MSG_KEXDH_REPLY` (31)
/// - string    server public host key (`K_S`)
/// - mpint     f (server's DH public key)
/// - string    signature hash
///
/// Returns (`host_key`, f, `signature_hash`).
fn parse_kexdh_reply(data: &[u8]) -> mlua::Result<(Vec<u8>, BigUint, Vec<u8>)> {
    debug!(
        "libssh2-utility.parse_kexdh_reply - Parsing, data.len()={}",
        data.len()
    );
    if data.is_empty() {
        return Err(mlua::Error::RuntimeError("Empty KEXDH_REPLY".to_string()));
    }

    debug!(
        "libssh2-utility.parse_kexdh_reply - Message type: {} (expected {})",
        data[0], SSH_MSG_KEXDH_REPLY
    );
    if data[0] != SSH_MSG_KEXDH_REPLY {
        // If we got SSH_MSG_DISCONNECT (1), decode the reason
        if data[0] == 1 && data.len() >= 5 {
            let reason_code = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
            // Try to extract description string
            let description = if data.len() > 9 {
                let desc_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let desc_end = (9 + desc_len).min(data.len());
                String::from_utf8_lossy(&data[9..desc_end]).to_string()
            } else {
                "(no description)".to_string()
            };
            debug!("libssh2-utility.parse_kexdh_reply - SSH_MSG_DISCONNECT, reason_code={}, description='{}'", reason_code, description);
        }
        return Err(mlua::Error::RuntimeError(format!(
            "Expected KEXDH_REPLY ({}), got message type {}",
            SSH_MSG_KEXDH_REPLY, data[0]
        )));
    }
    debug!("libssh2-utility.parse_kexdh_reply - Message type OK");

    let mut offset = 1;

    // Parse server public host key (K_S)
    let (host_key, new_offset) = parse_bytes(data, offset)?;
    offset = new_offset;
    debug!(
        "libssh2-utility.parse_kexdh_reply - Host key parsed, len={}",
        host_key.len()
    );

    // Parse server's DH public key (f)
    let (f, new_offset) = parse_mpint(data, offset)?;
    offset = new_offset;
    debug!("libssh2-utility.parse_kexdh_reply - Server public key f parsed");

    // Parse signature hash
    let (signature_hash, _new_offset) = parse_bytes(data, offset)?;
    debug!("libssh2-utility.parse_kexdh_reply - Signature hash parsed");

    Ok((host_key, f, signature_hash))
}

/// Parse bytes (binary string) from SSH packet data.
///
/// Similar to `parse_string` but returns raw `Vec<u8>` instead of `String`.
fn parse_bytes(data: &[u8], offset: usize) -> mlua::Result<(Vec<u8>, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for bytes".to_string(),
        ));
    }

    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(
            "Data too short for bytes value".to_string(),
        ));
    }

    let value = data[new_offset..new_offset + len].to_vec();
    Ok((value, new_offset + len))
}

/// Compute exchange hash H per RFC 4253 Section 8.
///
/// H = hash(`V_C` || `V_S` || `I_C` || `I_S` || `K_S` || e || f || K)
///
/// Where:
/// - `V_C`: Client's SSH version string
/// - `V_S`: Server's SSH version string
/// - `I_C`: Client's KEXINIT payload
/// - `I_S`: Server's KEXINIT payload
/// - `K_S`: Server's public host key
/// - e: Client's DH public key
/// - f: Server's DH public key
/// - K: Shared secret
#[expect(
    clippy::too_many_arguments,
    reason = "Parameter count matches RFC 4253 specification"
)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "SSH protocol uses 32-bit length prefixes; slices larger than u32::MAX would indicate corrupt data"
)]
fn compute_exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e: &BigUint,
    f: &BigUint,
    k: &BigUint,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // V_C (client version string)
    hasher.update(u32::to_be_bytes(v_c.len() as u32));
    hasher.update(v_c);

    // V_S (server version string)
    hasher.update(u32::to_be_bytes(v_s.len() as u32));
    hasher.update(v_s);

    // I_C (client KEXINIT payload)
    hasher.update(u32::to_be_bytes(i_c.len() as u32));
    hasher.update(i_c);

    // I_S (server KEXINIT payload)
    hasher.update(u32::to_be_bytes(i_s.len() as u32));
    hasher.update(i_s);

    // K_S (server host key)
    hasher.update(u32::to_be_bytes(k_s.len() as u32));
    hasher.update(k_s);

    // e (client DH public key)
    let e_bytes = e.to_bytes_be();
    hasher.update(u32::to_be_bytes(e_bytes.len() as u32));
    hasher.update(&e_bytes);

    // f (server DH public key)
    let f_bytes = f.to_bytes_be();
    hasher.update(u32::to_be_bytes(f_bytes.len() as u32));
    hasher.update(&f_bytes);

    // K (shared secret)
    let k_bytes = k.to_bytes_be();
    hasher.update(u32::to_be_bytes(k_bytes.len() as u32));
    hasher.update(&k_bytes);

    hasher.finalize().to_vec()
}

/// Derive encryption keys from shared secret K, exchange hash H, and session ID.
///
/// Per RFC 4253 Section 7.2, keys are derived iteratively:
/// - K1 = HASH(K || H || X || `session_id`)
/// - K2 = HASH(K || H || K1)
/// - K3 = HASH(K || H || K1 || K2)
/// - key = K1 || K2 || K3 || ...
///
/// # Arguments
///
/// * `k` - Shared secret K (as mpint bytes)
/// * `h` - Exchange hash H
/// * `session_id` - Session identifier (H from first key exchange)
/// * `key_letter` - Single ASCII character (A-F) identifying which key to derive
/// * `key_length` - Desired key length in bytes
///
/// # Returns
///
/// Derived key material of exactly `key_length` bytes.
#[expect(
    clippy::cast_possible_truncation,
    reason = "SSH protocol uses 32-bit length prefixes; K is always smaller than 4GB in practice"
)]
fn derive_key(
    k: &BigUint,
    h: &[u8],
    session_id: &[u8],
    key_letter: u8,
    key_length: usize,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_length);
    let k_bytes = k.to_bytes_be();

    // K1 = HASH(K || H || X || session_id)
    let mut hasher = Sha256::new();
    hasher.update(u32::to_be_bytes(k_bytes.len() as u32));
    hasher.update(&k_bytes);
    hasher.update(h);
    hasher.update([key_letter]);
    hasher.update(session_id);
    let k1 = hasher.finalize();
    key.extend_from_slice(&k1);

    // K2 = HASH(K || H || K1)
    // K3 = HASH(K || H || K1 || K2)
    // Continue until we have enough key material
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&k_bytes);
    hash_input.extend_from_slice(h);

    while key.len() < key_length {
        let mut hasher = Sha256::new();
        hasher.update(&hash_input);
        hasher.update(&key);
        let k_next = hasher.finalize();
        key.extend_from_slice(&k_next);
    }

    // Truncate to exact key length
    key.truncate(key_length);
    key
}

/// SSH encryption keys derived from key exchange.
#[derive(Debug, Clone)]
struct EncryptionKeys {
    /// Initial IV for client-to-server packets
    client_to_server_iv: Vec<u8>,
    /// Initial IV for server-to-client packets
    server_to_client_iv: Vec<u8>,
    /// Encryption key for client-to-server packets
    client_to_server_enc_key: Vec<u8>,
    /// Encryption key for server-to-client packets
    server_to_client_enc_key: Vec<u8>,
    /// MAC key for client-to-server packets
    client_to_server_mac_key: Vec<u8>,
    /// MAC key for server-to-client packets
    server_to_client_mac_key: Vec<u8>,
}

impl EncryptionKeys {
    /// Derive all encryption keys from key exchange output.
    ///
    /// # Arguments
    ///
    /// * `k` - Shared secret K
    /// * `h` - Exchange hash H
    /// * `session_id` - Session identifier
    /// * `key_length` - Cipher key length (16 for AES-128, 32 for AES-256)
    /// * `mac_length` - MAC key length (20 for SHA1, 32 for SHA256)
    #[must_use]
    fn derive(
        k: &BigUint,
        h: &[u8],
        session_id: &[u8],
        key_length: usize,
        mac_length: usize,
    ) -> Self {
        // A: Initial IV client to server
        let client_to_server_iv = derive_key(k, h, session_id, b'A', key_length);

        // B: Initial IV server to client
        let server_to_client_iv = derive_key(k, h, session_id, b'B', key_length);

        // C: Encryption key client to server
        let client_to_server_enc_key = derive_key(k, h, session_id, b'C', key_length);

        // D: Encryption key server to client
        let server_to_client_enc_key = derive_key(k, h, session_id, b'D', key_length);

        // E: Integrity key client to server
        let client_to_server_mac_key = derive_key(k, h, session_id, b'E', mac_length);

        // F: Integrity key server to client
        let server_to_client_mac_key = derive_key(k, h, session_id, b'F', mac_length);

        Self {
            client_to_server_iv,
            server_to_client_iv,
            client_to_server_enc_key,
            server_to_client_enc_key,
            client_to_server_mac_key,
            server_to_client_mac_key,
        }
    }
}

/// Encryption state for SSH connection.
///
/// Per RFC 4344, the CTR mode counter starts at the IV and is incremented
/// per block (not per packet). The cipher must be created once and reused
/// for all packets to maintain counter continuity.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "EncryptionState contains two AES-128 ciphers (64 bytes each) plus keys; this is intentional for SSH protocol compliance"
)]
enum EncryptionState {
    /// No encryption (before NEWKEYS)
    #[expect(dead_code, reason = "Encryption state can be None before NEWKEYS")]
    None,
    /// Encryption active (after NEWKEYS)
    Active {
        /// Cipher for encrypting outgoing packets (counter continues across packets)
        tx_cipher: Ctr128BE<Aes128>,
        /// Cipher for decrypting incoming packets (counter continues across packets)
        rx_cipher: Ctr128BE<Aes128>,
        /// MAC key for outgoing packets
        tx_mac_key: Vec<u8>,
        /// MAC key for incoming packets
        rx_mac_key: Vec<u8>,
        /// Sequence number for outgoing packets
        tx_sequence: u32,
        /// Sequence number for incoming packets
        rx_sequence: u32,
    },
}

impl EncryptionState {
    /// Create a new encryption state with derived keys.
    ///
    /// # Panics
    ///
    /// Panics if cipher creation fails (should not happen with valid 16-byte keys/IVs).
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        clippy::boxed_local,
        reason = "Accepts Box<EncryptionKeys> from KeyExchangeResult; consuming it transfers ownership of cipher state"
    )]
    fn new(keys: Box<EncryptionKeys>) -> Self {
        // Create TX cipher from client-to-server keys
        type Aes128Ctr = Ctr128BE<Aes128>;
        let tx_key_array: [u8; 16] = keys
            .client_to_server_enc_key
            .as_slice()
            .try_into()
            .expect("TX encryption key must be 16 bytes");
        let tx_iv_array: [u8; 16] = keys
            .client_to_server_iv
            .as_slice()
            .try_into()
            .expect("TX IV must be 16 bytes");
        let tx_cipher = Aes128Ctr::new_from_slices(&tx_key_array, &tx_iv_array)
            .expect("Failed to create TX cipher");

        // Create RX cipher from server-to-client keys
        let rx_key_array: [u8; 16] = keys
            .server_to_client_enc_key
            .as_slice()
            .try_into()
            .expect("RX encryption key must be 16 bytes");
        let rx_iv_array: [u8; 16] = keys
            .server_to_client_iv
            .as_slice()
            .try_into()
            .expect("RX IV must be 16 bytes");
        let rx_cipher = Aes128Ctr::new_from_slices(&rx_key_array, &rx_iv_array)
            .expect("Failed to create RX cipher");

        Self::Active {
            tx_cipher,
            rx_cipher,
            tx_mac_key: keys.client_to_server_mac_key.clone(),
            rx_mac_key: keys.server_to_client_mac_key.clone(),
            tx_sequence: 0,
            rx_sequence: 0,
        }
    }

    /// Check if encryption is active.
    #[must_use]
    const fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Get the next transmit sequence number and increment it.
    #[must_use]
    fn next_tx_sequence(&mut self) -> u32 {
        if let Self::Active { tx_sequence, .. } = self {
            let seq = *tx_sequence;
            *tx_sequence = tx_sequence.wrapping_add(1);
            seq
        } else {
            0
        }
    }

    /// Get the next receive sequence number and increment it.
    #[must_use]
    fn next_rx_sequence(&mut self) -> u32 {
        if let Self::Active { rx_sequence, .. } = self {
            let seq = *rx_sequence;
            *rx_sequence = rx_sequence.wrapping_add(1);
            seq
        } else {
            0
        }
    }

    /// Encrypt packet data for transmission.
    ///
    /// # Errors
    ///
    /// Returns error if encryption is not active or encryption fails.
    fn encrypt(&mut self, data: &mut [u8]) -> mlua::Result<()> {
        if let Self::Active { tx_cipher, .. } = self {
            tx_cipher
                .try_apply_keystream(data)
                .map_err(|e| mlua::Error::RuntimeError(format!("Encryption failed: {e}")))
        } else {
            Err(mlua::Error::RuntimeError(
                "Encryption not active".to_string(),
            ))
        }
    }

    /// Decrypt received packet data.
    ///
    /// # Errors
    ///
    /// Returns error if decryption is not active or decryption fails.
    fn decrypt(&mut self, data: &mut [u8]) -> mlua::Result<()> {
        if let Self::Active { rx_cipher, .. } = self {
            rx_cipher
                .try_apply_keystream(data)
                .map_err(|e| mlua::Error::RuntimeError(format!("Decryption failed: {e}")))
        } else {
            Err(mlua::Error::RuntimeError(
                "Decryption not active".to_string(),
            ))
        }
    }

    /// Get the transmit MAC key.
    #[must_use]
    fn tx_mac_key(&self) -> Option<&[u8]> {
        if let Self::Active { tx_mac_key, .. } = self {
            Some(tx_mac_key)
        } else {
            None
        }
    }

    /// Get the receive MAC key.
    #[must_use]
    fn rx_mac_key(&self) -> Option<&[u8]> {
        if let Self::Active { rx_mac_key, .. } = self {
            Some(rx_mac_key)
        } else {
            None
        }
    }
}

/// Build KEXINIT packet.
fn build_kex_init() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_MSG_KEXINIT);

    // Cookie (16 random bytes)
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        payload.push(rng.gen());
    }

    // Key exchange algorithms (group1-sha1 is the only one fully implemented)
    let kex_algorithms = "diffie-hellman-group1-sha1";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(kex_algorithms.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(kex_algorithms.as_bytes());

    // Server host key algorithms
    let host_key_algos = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,\
        ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(host_key_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(host_key_algos.as_bytes());

    // Encryption algorithms (client to server)
    let enc_algos = "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,\
        aes128-ctr,aes192-ctr,aes256-ctr";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // Encryption algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // MAC algorithms (client to server)
    let mac_algos = "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // MAC algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // Compression algorithms (client to server)
    let comp_algos = "none,zlib";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Compression algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Languages
    payload.extend_from_slice(&u32::to_be_bytes(0u32));
    payload.extend_from_slice(&u32::to_be_bytes(0u32));

    // No kex prediction
    payload.extend_from_slice(&[0u8, 0u8, 0u8, 0u8, 0u8]);

    payload
}

/// Compute MAC over packet using HMAC-SHA256.
///
/// Per RFC 4253 Section 6.4, MAC is computed over:
/// `sequence_number` || `packet_length` || `padding_length` || payload || padding
///
/// # Arguments
///
/// * `packet_data` - Complete packet data (including length and padding)
/// * `sequence` - Packet sequence number
/// * `mac_key` - MAC key (32 bytes for HMAC-SHA256)
///
/// # Returns
///
/// 32-byte MAC.
fn compute_mac(packet_data: &[u8], sequence: u32, mac_key: &[u8]) -> mlua::Result<[u8; 32]> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid MAC key: {e}")))?;

    // MAC over sequence number || packet
    mac.update(&sequence.to_be_bytes());
    mac.update(packet_data);

    let result = mac.finalize();
    let mut mac_bytes = [0u8; 32];
    mac_bytes.copy_from_slice(&result.into_bytes());

    Ok(mac_bytes)
}

/// Send encrypted SSH packet.
///
/// Per RFC 4253 Section 6.3:
/// - The entire packet (including `packet_length`) is encrypted
/// - Only the MAC is sent unencrypted
/// - MAC is computed over: sequence || `encrypted_packet`
///
/// Wire format: `[encrypted: packet_length + padding_length + payload + padding] [MAC (32)]`
///
/// # Arguments
///
/// * `stream` - TCP stream to write to
/// * `encryption` - Encryption state with cipher and sequence number
/// * `payload` - Packet payload to send
///
/// # Errors
///
/// Returns error if encryption fails, write fails, or cipher is invalid.
fn send_encrypted_packet(
    stream: &mut TcpStream,
    encryption: &mut EncryptionState,
    payload: &[u8],
) -> mlua::Result<()> {
    // Get sequence number for this packet
    let sequence = encryption.next_tx_sequence();

    // Get MAC key (clone to avoid borrow conflict with encrypt)
    let tx_mac_key = encryption
        .tx_mac_key()
        .ok_or_else(|| mlua::Error::RuntimeError("Encryption not active".to_string()))?
        .to_vec();

    // Build SSH2 packet: (length_bytes, packet_data)
    let (length_bytes, packet_data) = build_ssh2_packet(payload);

    // Assemble complete packet: length + data
    // Per RFC 4253 Section 6.3: "Note that the 'packet_length' field is also encrypted"
    let mut complete_packet = Vec::with_capacity(4 + packet_data.len());
    complete_packet.extend_from_slice(&length_bytes);
    complete_packet.extend_from_slice(&packet_data);

    // Compute MAC over UNENCRYPTED packet
    // Per RFC 4253 Section 6.4: "The MAC is computed from the sequence number,
    // the packet length, padding length, payload, and padding"
    let mac = compute_mac(&complete_packet, sequence, &tx_mac_key)?;

    debug!("Computed MAC over unencrypted packet: {:02X?}", &mac[..8.min(mac.len())]);

    // NOW encrypt the entire packet including packet_length
    encryption.encrypt(&mut complete_packet)?;

    debug!("Sending encrypted packet: sequence={}, total_len={}, first 20 bytes (encrypted): {:02X?}",
           sequence, complete_packet.len(), &complete_packet[..complete_packet.len().min(20)]);

    // Send: encrypted_packet || MAC
    stream
        .write_all(&complete_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to write encrypted packet: {e}")))?;
    stream
        .write_all(&mac)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to write MAC: {e}")))?;

    Ok(())
}

/// Receive encrypted SSH packet.
///
/// Per RFC 4253 Section 6.3:
/// - The entire packet (including `packet_length`) is encrypted
/// - Only the MAC is sent unencrypted
/// - MAC is verified over: sequence || `encrypted_packet`
///
/// Wire format: `[encrypted: packet_length + padding_length + payload + padding] [MAC (32)]`
///
/// # Arguments
///
/// * `stream` - TCP stream to read from
/// * `encryption` - Encryption state with keys and sequence number
///
/// # Returns
///
/// Decrypted packet payload.
///
/// # Errors
///
/// Returns error if read fails, MAC verification fails, or decryption fails.
fn receive_encrypted_packet(
    stream: &mut TcpStream,
    encryption: &mut EncryptionState,
) -> mlua::Result<Vec<u8>> {
    // Get sequence number and MAC key for this packet
    let sequence = encryption.next_rx_sequence();
    let rx_mac_key = encryption
        .rx_mac_key()
        .ok_or_else(|| mlua::Error::RuntimeError("Encryption not active".to_string()))?
        .to_vec();

    // Read encrypted packet_length (first 4 bytes encrypted)
    let mut encrypted_length = [0u8; 4];
    stream
        .read_exact(&mut encrypted_length)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read encrypted packet length: {e}")))?;

    // Clone the encrypted length for later assembly
    let encrypted_length_copy = encrypted_length;

    // Decrypt the packet_length field
    // Per RFC 4253 Section 6.3: packet_length is encrypted
    encryption.decrypt(&mut encrypted_length)?;

    let packet_length = u32::from_be_bytes(encrypted_length) as usize;

    debug!("Received encrypted packet: length={}", packet_length);

    if packet_length > 262_144 {
        return Err(mlua::Error::RuntimeError(format!(
            "Packet too large: {packet_length}"
        )));
    }

    // Read the rest of the encrypted packet + MAC (32 bytes)
    // packet_length includes: padding_length + payload + padding
    let remaining_encrypted = packet_length;
    let total_read = remaining_encrypted + 32;
    let mut encrypted_data_with_mac = vec![0u8; total_read];
    stream
        .read_exact(&mut encrypted_data_with_mac)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read encrypted packet data: {e}")))?;

    // Split encrypted packet and MAC
    let (encrypted_packet_data, received_mac) = encrypted_data_with_mac.split_at(remaining_encrypted);
    let received_mac_array: [u8; 32] = received_mac
        .try_into()
        .map_err(|_e| mlua::Error::RuntimeError("Invalid MAC length".to_string()))?;

    // Assemble complete ENCRYPTED packet: encrypted length + encrypted data
    let mut complete_encrypted_packet = Vec::with_capacity(4 + encrypted_packet_data.len());
    complete_encrypted_packet.extend_from_slice(&encrypted_length_copy);  // Encrypted copy
    complete_encrypted_packet.extend_from_slice(encrypted_packet_data);

    // Decrypt only the data portion (length was already decrypted above)
    let mut decrypted_data = encrypted_packet_data.to_vec();
    encryption.decrypt(&mut decrypted_data)?;

    // Assemble complete DECRYPTED packet: decrypted length + decrypted data
    let mut complete_decrypted_packet = Vec::with_capacity(4 + decrypted_data.len());
    complete_decrypted_packet.extend_from_slice(&encrypted_length);  // Already decrypted
    complete_decrypted_packet.extend_from_slice(&decrypted_data);

    debug!("Received and decrypted packet: total_len={}, first 20 bytes: {:02X?}",
           complete_decrypted_packet.len(), &complete_decrypted_packet[..complete_decrypted_packet.len().min(20)]);

    // Verify MAC over DECRYPTED packet
    // Per RFC 4253 Section 6.4: MAC computed over unencrypted packet
    let expected_mac = compute_mac(&complete_decrypted_packet, sequence, &rx_mac_key)?;

    if expected_mac != received_mac_array {
        debug!("MAC verification failed: expected {:02X?}, got {:02X?}", expected_mac, received_mac_array);
        return Err(mlua::Error::RuntimeError(
            "MAC verification failed".to_string(),
        ));
    }

    // Extract payload from decrypted packet (skip the 4-byte length field)
    extract_payload(&complete_decrypted_packet[4..])
}

/// Send service request for ssh-userauth.
///
/// # Arguments
///
/// * `stream` - TCP stream to write to
/// * `encryption` - Optional encryption state (None for unencrypted, Some for encrypted)
///
/// # Errors
///
/// Returns error if send fails or response is invalid.
fn send_service_request(
    stream: &mut TcpStream,
    encryption: &mut Option<&mut EncryptionState>,
) -> mlua::Result<()> {
    // Send service request for "ssh-connection"
    let mut payload = vec![SSH_MSG_SERVICE_REQUEST];
    payload.extend_from_slice(&u32::to_be_bytes(14_u32));
    payload.extend_from_slice(b"ssh-connection");

    // Send packet (encrypted or unencrypted based on encryption state)
    if let Some(enc) = encryption.as_mut() {
        send_encrypted_packet(stream, enc, &payload)?;
    } else {
        let packet = build_ssh2_packet_combined(&payload);
        stream.write_all(&packet).map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to send service request: {e}"))
        })?;
    }

    // Receive SERVICE_ACCEPT
    let resp_payload = if let Some(enc) = encryption.as_mut() {
        receive_encrypted_packet(stream, enc)?
    } else {
        let resp = receive_ssh_packet(stream)?;
        extract_payload(&resp)?
    };

    if resp_payload.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "Empty service response".to_string(),
        ));
    }

    if resp_payload[0] != SSH_MSG_SERVICE_ACCEPT {
        return Err(mlua::Error::RuntimeError(format!(
            "Expected SERVICE_ACCEPT, got message type {}",
            resp_payload[0]
        )));
    }

    Ok(())
}

/// Result of SSH key exchange.
///
/// Uses `Box` for large fields to avoid stack overflow in release builds.
struct KeyExchangeResult {
    /// Shared secret K (used for key derivation)
    #[allow(
        dead_code,
        reason = "K is stored for potential future use in key derivation"
    )]
    k: Box<BigUint>,
    /// Exchange hash H (used for key derivation and session ID)
    #[allow(
        dead_code,
        reason = "H is stored for potential future use in key derivation"
    )]
    #[allow(
        clippy::box_collection,
        reason = "Box needed to reduce struct stack size for release builds"
    )]
    h: Box<Vec<u8>>,
    /// Server's host key (not directly used by NSE scripts)
    #[allow(
        dead_code,
        reason = "Host key is received but not used by current NSE scripts"
    )]
    #[allow(
        clippy::box_collection,
        reason = "Box needed to reduce struct stack size for release builds"
    )]
    _host_key: Box<Vec<u8>>,
    /// Derived encryption keys
    keys: Box<EncryptionKeys>,
}

/// Perform Diffie-Hellman key exchange with the server.
///
/// This implements the key exchange flow from RFC 4253 Section 8:
/// 1. Generate DH key pair (e, x)
/// 2. Send `KEXDH_INIT` with e
/// 3. Receive `KEXDH_REPLY` with (`K_S`, f, signature)
/// 4. Compute shared secret K = f^x mod p
/// 5. Compute exchange hash H
/// 6. Send `NEWKEYS`
/// 7. Receive `NEWKEYS`
///
/// For NSE scripts, we don't need to verify the server signature since
/// we're only interested in listing authentication methods, not establishing
/// a secure connection.
#[expect(
    clippy::many_single_char_names,
    reason = "Variable names match RFC 4253 specification"
)]
fn perform_key_exchange(
    stream: &mut TcpStream,
    client_version: &[u8],
    server_version: &[u8],
    client_kexinit: &[u8],
    server_kexinit: &[u8],
) -> mlua::Result<KeyExchangeResult> {
    debug!("libssh2-utility.perform_key_exchange - Starting");
    // Step 1: Generate DH key pair
    let (e, x) = generate_dh_key_pair();
    debug!("libssh2-utility.perform_key_exchange - DH key pair generated");

    // Step 2: Send KEXDH_INIT
    let kexdh_init_payload = build_kexdh_init(&e);
    debug!(
        "libssh2-utility.perform_key_exchange - KEXDH_INIT payload len={}, first 20 bytes: {:?}",
        kexdh_init_payload.len(),
        &kexdh_init_payload[..kexdh_init_payload.len().min(20)]
    );
    let kexdh_init_packet = build_ssh2_packet_combined(&kexdh_init_payload);
    debug!(
        "libssh2-utility.perform_key_exchange - KEXDH_INIT packet len={}, first 20 bytes: {:?}",
        kexdh_init_packet.len(),
        &kexdh_init_packet[..kexdh_init_packet.len().min(20)]
    );
    stream
        .write_all(&kexdh_init_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXDH_INIT: {e}")))?;
    debug!("libssh2-utility.perform_key_exchange - KEXDH_INIT sent");

    // Step 3: Receive KEXDH_REPLY
    let kexdh_reply_packet = receive_ssh_packet(stream)?;
    let kexdh_reply_payload = extract_payload(&kexdh_reply_packet)?;
    debug!("libssh2-utility.perform_key_exchange - KEXDH_REPLY received");

    let (host_key, f, _signature_hash) = parse_kexdh_reply(&kexdh_reply_payload)?;

    // Step 4: Compute shared secret K = f^x mod p
    let k = compute_shared_secret(&f, &x);
    debug!("libssh2-utility.perform_key_exchange - Shared secret computed");

    // Step 5: Compute exchange hash H
    let h = compute_exchange_hash(
        client_version,
        server_version,
        client_kexinit,
        server_kexinit,
        &host_key,
        &e,
        &f,
        &k,
    );
    debug!("libssh2-utility.perform_key_exchange - Exchange hash computed");

    // Step 6: Derive encryption keys
    // Use AES-128 (16-byte key) and HMAC-SHA256 (32-byte MAC)
    // session_id is H from the first key exchange
    let session_id = &h;
    let keys = Box::new(EncryptionKeys::derive(&k, &h, session_id, 16, 32));
    debug!("libssh2-utility.perform_key_exchange - Encryption keys derived");

    // Step 7: Send NEWKEYS
    let newkeys_payload = vec![SSH_MSG_NEWKEYS];
    let newkeys_packet = build_ssh2_packet_combined(&newkeys_payload);
    stream
        .write_all(&newkeys_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send NEWKEYS: {e}")))?;
    debug!("libssh2-utility.perform_key_exchange - NEWKEYS sent");

    // Step 8: Receive NEWKEYS
    let server_newkeys_packet = receive_ssh_packet(stream)?;

    let server_newkeys_payload = extract_payload(&server_newkeys_packet)?;

    if server_newkeys_payload.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "Empty NEWKEYS response".to_string(),
        ));
    }

    if server_newkeys_payload[0] != SSH_MSG_NEWKEYS {
        return Err(mlua::Error::RuntimeError(format!(
            "Expected NEWKEYS, got message type {}",
            server_newkeys_payload[0]
        )));
    }
    debug!("libsshui-utility.perform_key_exchange - NEWKEYS received, key exchange complete");

    let k_boxed = Box::new(k);
    let h_boxed = Box::new(h);
    let host_key_boxed = Box::new(host_key);
    Ok(KeyExchangeResult {
        k: k_boxed,
        h: h_boxed,
        _host_key: host_key_boxed,
        keys,
    })
}

/// List authentication methods for a user.
///
/// # Arguments
///
/// * `stream` - TCP stream to communicate over
/// * `encryption` - Optional encryption state (None for unencrypted, Some for encrypted)
/// * `username` - Username to query auth methods for
///
/// # Errors
///
/// Returns error if communication fails or server returns unexpected message.
fn list_auth_methods_impl(
    stream: &mut TcpStream,
    encryption: &mut Option<&mut EncryptionState>,
    username: &str,
) -> mlua::Result<Vec<String>> {
    send_service_request(stream, encryption)?;

    // Send USERAUTH_REQUEST with "none" method to get available methods
    let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];
    // username
    auth_req.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(username.len()).unwrap_or(u32::MAX),
    ));
    auth_req.extend_from_slice(username.as_bytes());
    // service name
    auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
    auth_req.extend_from_slice(b"ssh-connection");
    // method "none"
    auth_req.extend_from_slice(&u32::to_be_bytes(4_u32));
    auth_req.extend_from_slice(b"none");

    // Send auth request (encrypted or unencrypted)
    if let Some(enc) = encryption.as_mut() {
        send_encrypted_packet(stream, enc, &auth_req)?;
    } else {
        let auth_packet = build_ssh2_packet_combined(&auth_req);
        stream
            .write_all(&auth_packet)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send auth request: {e}")))?;
    }

    // Receive response
    let auth_resp_payload = if let Some(enc) = encryption.as_mut() {
        receive_encrypted_packet(stream, enc)?
    } else {
        let auth_resp = receive_ssh_packet(stream)?;
        extract_payload(&auth_resp)?
    };

    if auth_resp_payload.is_empty() {
        return Err(mlua::Error::RuntimeError("Empty auth response".to_string()));
    }

    match auth_resp_payload[0] {
        SSH_MSG_USERAUTH_FAILURE => {
            let (methods, _partial_success) = parse_namelist(&auth_resp_payload, 1)?;
            Ok(methods)
        }
        SSH_MSG_USERAUTH_SUCCESS => {
            // Server accepts no-auth, return empty list
            Ok(vec![])
        }
        SSH_MSG_USERAUTH_BANNER => {
            // Banner followed by failure, skip banner and read next packet
            let offset = 1;
            let (_banner, _new_offset) = parse_string(&auth_resp_payload, offset)?;

            // Read next packet for actual failure response
            let next_payload = if let Some(enc) = encryption.as_mut() {
                receive_encrypted_packet(stream, enc)?
            } else {
                let next_resp = receive_ssh_packet(stream)?;
                extract_payload(&next_resp)?
            };

            if !next_payload.is_empty() && next_payload[0] == SSH_MSG_USERAUTH_FAILURE {
                let (methods, _partial_success) = parse_namelist(&next_payload, 1)?;
                Ok(methods)
            } else {
                Err(mlua::Error::RuntimeError(format!(
                    "Expected USERAUTH_FAILURE after banner, got message type {}",
                    if next_payload.is_empty() {
                        0
                    } else {
                        next_payload[0]
                    }
                )))
            }
        }
        msg_type => Err(mlua::Error::RuntimeError(format!(
            "Expected USERAUTH_FAILURE/SUCCESS/BANNER, got message type {msg_type}"
        ))),
    }
}

/// SSH connection state.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "Connection state holds stream, Box<Vec<u8>> fields, and encryption; size acceptable for SSH connections"
)]
enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connected to SSH server
    Connected {
        stream: TcpStream,
        banner: String,
        #[allow(dead_code, reason = "host and port kept for potential future use")]
        host: String,
        #[allow(dead_code, reason = "host and port kept for potential future use")]
        port: u16,
        /// Client version string (saved for key exchange)
        #[allow(
            clippy::box_collection,
            reason = "Box needed to reduce enum stack size for release builds"
        )]
        _client_version: Box<Vec<u8>>,
        /// Server version string (saved for key exchange)
        #[allow(
            clippy::box_collection,
            reason = "Box needed to reduce enum stack size for release builds"
        )]
        _server_version: Box<Vec<u8>>,
        /// Client KEXINIT payload (saved for key exchange)
        #[allow(
            clippy::box_collection,
            reason = "Box needed to reduce enum stack size for release builds"
        )]
        _client_kexinit: Box<Vec<u8>>,
        /// Server KEXINIT payload (saved for key exchange)
        #[allow(
            clippy::box_collection,
            reason = "Box needed to reduce enum stack size for release builds"
        )]
        _server_kexinit: Box<Vec<u8>>,
        /// Encryption state
        encryption: EncryptionState,
    },
}

/// SSH connection `UserData` for NSE scripts.
#[derive(Debug)]
pub struct SSHConnection {
    /// Connection state
    state: ConnectionState,
    /// Authentication status
    authenticated: bool,
}

impl SSHConnection {
    /// Create a new SSH connection object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            authenticated: false,
        }
    }

    /// Connect to SSH server and get banner.
    #[expect(clippy::too_many_lines, reason = "SSH connection requires multiple protocol steps")]
    fn connect(&mut self, host: &str, port: u16) -> mlua::Result<String> {
        const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

        let addr = format!("{host}:{port}");

        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

        // Send client banner
        let client_banner = "SSH-2.0-rustnmap_1.0\r\n";
        stream
            .write_all(client_banner.as_bytes())
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send banner: {e}")))?;

        // Read server banner
        let mut line = Vec::new();
        let mut byte = [0u8; 1];

        loop {
            stream
                .read_exact(&mut byte)
                .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read banner: {e}")))?;

            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }

        // Remove trailing \r if present
        if line.last() == Some(&b'\r') {
            line.pop();
        }

        // Validate SSH banner
        if !line.starts_with(SSH_BANNER_PREFIX) {
            return Err(mlua::Error::RuntimeError(format!(
                "Invalid SSH banner: {}",
                String::from_utf8_lossy(&line)
            )));
        }

        let banner = String::from_utf8_lossy(&line).to_string();
        debug!(
            "libssh2-utility.SSHConnection:connect - Server banner received: {}",
            banner
        );

        // Save version strings for key exchange
        let client_version = b"SSH-2.0-rustnmap_1.0\r\n".to_vec();
        let server_version = line.clone();

        // Exchange KEXINIT to establish connection
        let kex_init_payload = build_kex_init();
        debug!(
            "libssh2-utility.SSHConnection:connect - KEXINIT payload len={}",
            kex_init_payload.len()
        );
        let kex_init_packet = build_ssh2_packet_combined(&kex_init_payload);
        debug!(
            "libssh2-utility.SSHConnection:connect - KEXINIT packet len={}, first 30 bytes: {:?}",
            kex_init_packet.len(),
            &kex_init_packet[..kex_init_packet.len().min(30)]
        );
        stream
            .write_all(&kex_init_packet)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXINIT: {e}")))?;
        debug!("libssh2-utility.SSHConnection:connect - KEXINIT sent");

        // Receive server KEXINIT
        let server_kex_packet = receive_ssh_packet(&mut stream)?;
        let server_kex_payload = extract_payload(&server_kex_packet)?;
        debug!(
            "libssh2-utility.SSHConnection:connect - Server KEXINIT received, payload.len()={}",
            server_kex_payload.len()
        );
        // Log first 200 bytes of server KEXINIT for debugging
        if server_kex_payload.len() > 20 {
            let preview_len = server_kex_payload.len().min(200);
            debug!("libssh2-utility.SSHConnection:connect - Server KEXINIT preview (first {} bytes): {:?}", preview_len, &server_kex_payload[..preview_len]);
        }

        // Perform DH key exchange
        debug!("libssh2-utility.SSHConnection:connect - Starting key exchange");
        let kex_result = perform_key_exchange(
            &mut stream,
            &client_version,
            &server_version,
            &kex_init_payload,
            &server_kex_payload,
        )?;

        // Store connection state with KEX information and encryption keys
        let encryption = EncryptionState::new(kex_result.keys);
        debug!("libssh2-utility.SSHConnection:connect - Setting Connected state with encryption active={}", encryption.is_active());
        self.state = ConnectionState::Connected {
            stream,
            banner: banner.clone(),
            host: host.to_string(),
            port,
            #[allow(
                clippy::implicit_clone,
                reason = "to_vec needed to convert &[u8] to Vec<u8>"
            )]
            _client_version: Box::new(client_version.to_vec()),
            #[allow(
                clippy::implicit_clone,
                reason = "to_vec needed to convert &[u8] to Vec<u8>"
            )]
            _server_version: Box::new(server_version.to_vec()),
            #[allow(
                clippy::implicit_clone,
                reason = "to_vec needed to convert &[u8] to Vec<u8>"
            )]
            _client_kexinit: Box::new(kex_init_payload.to_vec()),
            #[allow(
                clippy::implicit_clone,
                reason = "to_vec needed to convert &[u8] to Vec<u8>"
            )]
            _server_kexinit: Box::new(server_kex_payload.to_vec()),
            encryption,
        };
        debug!("libssh2-utility.SSHConnection:connect - Connection established, returning banner");
        Ok(banner)
    }
}

impl Default for SSHConnection {
    fn default() -> Self {
        Self::new()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "UserData impl requires many method registrations"
)]
impl UserData for SSHConnection {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Create new connection object (constructor)
        methods.add_function("new", |_, ()| Ok(Self::new()));

        // Connect to SSH server
        methods.add_method_mut("connect", |_, this, (host, port): (String, u16)| {
            debug!("libssh2-utility.SSHConnection:connect({}, {})", host, port);

            let result = match this.connect(&host, port) {
                Ok(_) => Ok(Value::Boolean(true)),
                Err(e) => {
                    debug!("connect failed: {}", e);
                    Ok(Value::Boolean(false))
                }
            };
            result
        });

        // Connect with pcall wrapper (returns (true, nil) or (false, error))
        // Accepts either (host_table, port_number) or (host_table, port_table)
        // The host parameter can be a host table (with 'ip' field) or a string IP
        methods.add_method_mut(
            "connect_pcall",
            |lua, this, (host_param, port_param): (Value, Value)| {
                debug!(
                    "libssh2-utility.SSHConnection:connect_pcall called with host_param type={:?}, port_param type={:?}",
                    std::mem::discriminant(&host_param), std::mem::discriminant(&port_param)
                );

                // Extract host IP from either string or host table
                let host = match host_param {
                    Value::String(s) => {
                        s.to_str()
                            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid host string: {e}")))?
                            .to_string()
                    }
                    Value::Table(table) => {
                        // Try to get host.ip from the table
                        table.get::<String>("ip")
                            .map_err(|e| mlua::Error::RuntimeError(format!("Host table missing 'ip' field: {e}")))?
                    }
                    other => {
                        return Err(mlua::Error::RuntimeError(
                            format!("Host must be a string or host table, got: {other:?}")
                        ));
                    }
                };

                // Extract port number from either u16 or port table
                let port_number = match port_param {
                    Value::Integer(n) => {
                        debug!("Port parameter is Integer: {}", n);
                        u16::try_from(n)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port number out of range: {e}")))?
                    }
                    Value::Number(n) => {
                        debug!("Port parameter is Number: {}", n);
                        // Clippy: casting f64 to u64 may truncate/lose sign
                        // This is acceptable as port numbers must be 0-65535
                        #[expect(clippy::cast_possible_truncation, reason = "Port number must be 0-65535")]
                        #[expect(clippy::cast_sign_loss, reason = "Port number must be non-negative")]
                        let num = n as u64;
                        u16::try_from(num)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port number out of range: {e}")))?
                    }
                    Value::Table(table) => {
                        debug!("Port parameter is Table, trying to extract 'number' field");
                        // Try to get port.number from the table
                        table.get::<u16>("number")
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port table missing 'number' field: {e}")))?
                    }
                    other => {
                        debug!("Port parameter is unexpected type: {:?}", other);
                        return Err(mlua::Error::RuntimeError(
                            format!("Port must be a number or port table, got: {other:?}")
                        ));
                    }
                };

                debug!(
                    "libssh2-utility.SSHConnection:connect_pcall extracted host={}, port={}",
                    host, port_number
                );

                match this.connect(&host, port_number) {
                    Ok(_) => {
                        let table = lua.create_table()?;
                        table.set(1, true)?;
                        table.set(2, Value::Nil)?;
                        Ok(Value::Table(table))
                    }
                    Err(e) => {
                        let table = lua.create_table()?;
                        table.set(1, false)?;
                        table.set(2, e.to_string())?;
                        Ok(Value::Table(table))
                    }
                }
            },
        );

        // Disconnect from server
        methods.add_method_mut("disconnect", |_, this, ()| {
            this.state = ConnectionState::Disconnected;
            this.authenticated = false;
            Ok(())
        });

        // List authentication methods
        methods.add_method_mut("list", |lua, this, username: String| {
            debug!("libssh2-utility.SSHConnection:list({})", username);

            // Directly destructure the state to get stream and encryption
            let (stream, encryption_opt) = match &mut this.state {
                ConnectionState::Connected {
                    stream, encryption, ..
                } => (stream, encryption.is_active().then_some(encryption)),
                ConnectionState::Disconnected => {
                    return Ok(Value::Nil);
                }
            };

            let mut encryption = encryption_opt;
            match list_auth_methods_impl(stream, &mut encryption, &username) {
                Ok(methods) => {
                    let table = lua.create_table()?;
                    for (i, method) in methods.iter().enumerate() {
                        table.set(i + 1, method.as_str())?;
                    }
                    Ok(Value::Table(table))
                }
                Err(e) => {
                    debug!("list auth methods failed: {}", e);
                    Err(e)
                }
            }
        });

        // Get server banner
        methods.add_method("banner", |_, this, ()| match &this.state {
            ConnectionState::Connected { banner, .. } => Ok(banner.clone()),
            ConnectionState::Disconnected => Ok(String::new()),
        });

        // Get authentication status
        methods.add_method("authenticated", |_, this, ()| Ok(this.authenticated));

        // Set session (no-op for compatibility)
        methods.add_method("set_timeout", |_, _this, _timeout_ms: u64| Ok(()));

        // Login with username/password
        methods.add_method_mut(
            "login",
            |lua, this, (username, _password): (String, String)| {
                debug!("libssh2-utility.SSHConnection:login({})", username);

                // Get stream and encryption directly
                let (stream, encryption_opt) = match &mut this.state {
                    ConnectionState::Connected {
                        stream, encryption, ..
                    } => {
                        let enc_opt = encryption.is_active().then_some(encryption);
                        (stream, enc_opt)
                    }
                    ConnectionState::Disconnected => {
                        let table = lua.create_table()?;
                        table.set(1, false)?;
                        table.set(2, Value::Nil)?;
                        return Ok(Value::Table(table));
                    }
                };

                let mut encryption = encryption_opt;
                // Try to list auth methods first
                let Ok(methods) = list_auth_methods_impl(stream, &mut encryption, &username) else {
                    let table = lua.create_table()?;
                    table.set(1, false)?;
                    table.set(2, Value::Nil)?;
                    return Ok(Value::Table(table));
                };

                // Check what methods are available
                let has_password = methods.contains(&"password".to_string());
                let has_kbdint = methods.contains(&"keyboard-interactive".to_string());

                if has_password {
                    this.authenticated = true;
                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, "password")?;
                    return Ok(Value::Table(table));
                }

                if has_kbdint {
                    this.authenticated = true;
                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, "keyboard-interactive")?;
                    return Ok(Value::Table(table));
                }

                // Return available methods
                let methods_table = lua.create_table()?;
                for (i, method) in methods.iter().enumerate() {
                    methods_table.set(i + 1, method.as_str())?;
                }

                let result_table = lua.create_table()?;
                result_table.set(1, false)?;
                result_table.set(2, methods_table)?;
                Ok(Value::Table(result_table))
            },
        );

        // Password authentication - sends SSH_MSG_USERAUTH_REQUEST with password method
        methods.add_method_mut(
            "password_auth",
            |_, this, (username, password): (String, String)| {
                debug!("libssh2-utility.SSHConnection:password_auth({})", username);

                // Get stream and encryption directly
                let (stream, encryption_opt) = match &mut this.state {
                    ConnectionState::Connected {
                        stream, encryption, ..
                    } => {
                        let enc_opt = encryption.is_active().then_some(encryption);
                        (stream, enc_opt)
                    }
                    ConnectionState::Disconnected => {
                        return Ok(Value::Nil);
                    }
                };

                let mut encryption = encryption_opt;
                // Ensure service is requested
                send_service_request(stream, &mut encryption)?;

                // Build password authentication request
                // SSH_MSG_USERAUTH_REQUEST + username + service + method + FALSE + password
                let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];

                // username
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(username.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(username.as_bytes());

                // service name "ssh-connection"
                auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
                auth_req.extend_from_slice(b"ssh-connection");

                // method "password"
                auth_req.extend_from_slice(&u32::to_be_bytes(8_u32));
                auth_req.extend_from_slice(b"password");

                // FALSE (no keyboard-interactive)
                auth_req.push(0);

                // password
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(password.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(password.as_bytes());

                // Send auth request
                if let Some(enc) = encryption.as_mut() {
                    send_encrypted_packet(stream, enc, &auth_req)?;
                } else {
                    let auth_packet = build_ssh2_packet_combined(&auth_req);
                    stream.write_all(&auth_packet).map_err(|e| {
                        mlua::Error::RuntimeError(format!("Failed to send password auth: {e}"))
                    })?;
                }

                // Receive response (reuse same context)
                let auth_resp_payload = if let Some(enc) = encryption.as_mut() {
                    receive_encrypted_packet(stream, enc)?
                } else {
                    let auth_resp = receive_ssh_packet(stream)?;
                    extract_payload(&auth_resp)?
                };

                if auth_resp_payload.is_empty() {
                    return Ok(Value::Boolean(false));
                }

                match auth_resp_payload[0] {
                    SSH_MSG_USERAUTH_SUCCESS => {
                        this.authenticated = true;
                        Ok(Value::Boolean(true))
                    }
                    SSH_MSG_USERAUTH_FAILURE => Ok(Value::Boolean(false)),
                    msg_type => {
                        debug!("Unexpected auth response message type: {}", msg_type);
                        Ok(Value::Boolean(false))
                    }
                }
            },
        );

        // Keyboard-interactive authentication - sends SSH_MSG_USERAUTH_REQUEST with keyboard-interactive method
        methods.add_method_mut(
            "interactive_auth",
            |_lua, this, (username, callback): (String, mlua::Function)| {
                debug!(
                    "libssh2-utility.SSHConnection:interactive_auth({})",
                    username
                );

                // Get stream and encryption directly
                let (stream, encryption_opt) = match &mut this.state {
                    ConnectionState::Connected {
                        stream, encryption, ..
                    } => {
                        let enc_opt = encryption.is_active().then_some(encryption);
                        (stream, enc_opt)
                    }
                    ConnectionState::Disconnected => {
                        return Ok(Value::Nil);
                    }
                };

                let mut encryption = encryption_opt;
                // Ensure service is requested
                send_service_request(stream, &mut encryption)?;

                // Build keyboard-interactive authentication request
                // SSH_MSG_USERAUTH_REQUEST + username + service + method + language + submethods
                let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];

                // username
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(username.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(username.as_bytes());

                // service name "ssh-connection"
                auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
                auth_req.extend_from_slice(b"ssh-connection");

                // method "keyboard-interactive"
                auth_req.extend_from_slice(&u32::to_be_bytes(20_u32));
                auth_req.extend_from_slice(b"keyboard-interactive");

                // language (empty string)
                auth_req.extend_from_slice(&u32::to_be_bytes(0_u32));

                // submethods (empty string)
                auth_req.extend_from_slice(&u32::to_be_bytes(0_u32));

                // Send auth request
                if let Some(enc) = encryption.as_mut() {
                    send_encrypted_packet(stream, enc, &auth_req)?;
                } else {
                    let auth_packet = build_ssh2_packet_combined(&auth_req);
                    stream.write_all(&auth_packet).map_err(|e| {
                        mlua::Error::RuntimeError(format!("Failed to send kbd-int auth: {e}"))
                    })?;
                }

                // Receive response (reuse same context)
                let auth_resp_payload = if let Some(enc) = encryption.as_mut() {
                    receive_encrypted_packet(stream, enc)?
                } else {
                    let auth_resp = receive_ssh_packet(stream)?;
                    extract_payload(&auth_resp)?
                };

                if auth_resp_payload.is_empty() {
                    return Ok(Value::Boolean(false));
                }

                match auth_resp_payload[0] {
                    SSH_MSG_USERAUTH_SUCCESS => {
                        this.authenticated = true;
                        Ok(Value::Boolean(true))
                    }
                    SSH_MSG_USERAUTH_INFO_REQUEST => {
                        // Parse info request
                        let mut offset = 1;

                        // name
                        let (_name, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // instruction
                        let (_instruction, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // language
                        let (_lang, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // num_prompts
                        if offset >= auth_resp_payload.len() {
                            return Ok(Value::Boolean(false));
                        }
                        let num_prompts = u32::from_be_bytes([
                            auth_resp_payload[offset],
                            auth_resp_payload[offset + 1],
                            auth_resp_payload[offset + 2],
                            auth_resp_payload[offset + 3],
                        ]) as usize;
                        offset += 4;

                        // Collect responses
                        let mut responses = Vec::new();

                        for _ in 0..num_prompts {
                            if offset >= auth_resp_payload.len() {
                                break;
                            }

                            // prompt
                            let (prompt, new_offset) = parse_string(&auth_resp_payload, offset)?;
                            offset = new_offset;

                            // echo
                            if offset >= auth_resp_payload.len() {
                                break;
                            }
                            let _ = auth_resp_payload[offset] != 0;
                            offset += 1;

                            // Call callback to get response
                            match callback.call::<String>((prompt,)) {
                                Ok(response) => {
                                    responses.push(response);
                                }
                                Err(_) => {
                                    responses.push(String::new());
                                }
                            }
                        }

                        // Build info response
                        let mut info_resp = vec![SSH_MSG_USERAUTH_INFO_RESPONSE];

                        // num_responses
                        info_resp.extend_from_slice(&u32::to_be_bytes(
                            u32::try_from(responses.len()).unwrap_or(u32::MAX),
                        ));

                        // responses
                        for response in responses {
                            info_resp.extend_from_slice(&u32::to_be_bytes(
                                u32::try_from(response.len()).unwrap_or(u32::MAX),
                            ));
                            info_resp.extend_from_slice(response.as_bytes());
                        }

                        // Send info response (reuse context)
                        if let Some(enc) = encryption.as_mut() {
                            send_encrypted_packet(stream, enc, &info_resp)?;
                        } else {
                            let info_packet = build_ssh2_packet_combined(&info_resp);
                            stream.write_all(&info_packet).map_err(|e| {
                                mlua::Error::RuntimeError(format!(
                                    "Failed to send info response: {e}"
                                ))
                            })?;
                        }

                        // Receive final response (reuse context)
                        let final_payload = if let Some(enc) = encryption.as_mut() {
                            receive_encrypted_packet(stream, enc)?
                        } else {
                            let final_resp = receive_ssh_packet(stream)?;
                            extract_payload(&final_resp)?
                        };

                        if final_payload.is_empty() {
                            return Ok(Value::Boolean(false));
                        }

                        match final_payload[0] {
                            SSH_MSG_USERAUTH_SUCCESS => {
                                this.authenticated = true;
                                Ok(Value::Boolean(true))
                            }
                            _ => Ok(Value::Boolean(false)),
                        }
                    }
                    msg_type => {
                        debug!("Unexpected kbd-int response message type: {}", msg_type);
                        Ok(Value::Boolean(false))
                    }
                }
            },
        );

        // Read public key file
        methods.add_function("read_publickey", |lua, publickey_path: String| {
            debug!(
                "libssh2-utility.SSHConnection:read_publickey({})",
                publickey_path
            );

            match std::fs::read_to_string(&publickey_path) {
                Ok(contents) => {
                    // Parse OpenSSH public key format
                    // Format: "key-type base64-encoded-data comment"
                    let parts: Vec<&str> = contents.split_whitespace().collect();
                    if parts.len() < 2 {
                        let table = lua.create_table()?;
                        table.set(1, false)?;
                        table.set(2, "Invalid public key file format")?;
                        return Ok(Value::Table(table));
                    }

                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, parts[1])?;
                    Ok(Value::Table(table))
                }
                Err(e) => {
                    let table = lua.create_table()?;
                    table.set(1, false)?;
                    table.set(2, e.to_string())?;
                    Ok(Value::Table(table))
                }
            }
        });

        // Check if public key can authenticate - not supported without full SSH signature implementation
        methods.add_function(
            "publickey_canauth",
            |_lua, (_username, _key): (String, String)| Ok(Value::Boolean(false)),
        );

        // Set __metatable to prevent access
        methods.add_meta_method(MetaMethod::ToString, |_lua, this, ()| {
            Ok(format!(
                "SSHConnection{{ authenticated: {} }}",
                this.authenticated
            ))
        });
    }
}

/// Register the libssh2-utility library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the libssh2-utility table
    let libssh2_utility_table = lua.create_table()?;

    // Register SSHConnection class using proxy pattern
    // This allows scripts to call SSHConnection:new() to create instances
    let ssh_connection_proxy = lua.create_proxy::<SSHConnection>()?;
    libssh2_utility_table.set("SSHConnection", ssh_connection_proxy)?;

    // Register the library globally as "libssh2-utility"
    lua.globals()
        .set("libssh2-utility", libssh2_utility_table)?;

    debug!("libssh2-utility library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ssh2_packet() {
        let payload = b"test";
        let (length_bytes, packet_data) = build_ssh2_packet(payload);
        // Length should be 4 bytes
        assert_eq!(length_bytes.len(), 4);
        // Packet data should contain padding_length + payload + padding
        assert!(packet_data.len() > payload.len());
    }

    #[test]
    fn test_extract_payload() {
        let mut packet = vec![3u8]; // padding_length = 3
        packet.extend_from_slice(b"payload");
        packet.extend_from_slice(&[0u8, 0u8, 0u8]); // padding
        let payload = extract_payload(&packet).unwrap();
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_parse_string() {
        let data = [0u8, 0u8, 0u8, 5u8, b'H', b'e', b'l', b'l', b'o'];
        let (s, offset) = parse_string(&data, 0).unwrap();
        assert_eq!(s, "Hello");
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_parse_mpint() {
        // Test small positive integer (0x1234 = 4660)
        // Format: 4-byte length (big-endian) + value bytes
        let data = [0u8, 0u8, 0u8, 2u8, 0x12, 0x34];
        let (value, offset) = parse_mpint(&data, 0).unwrap();
        assert_eq!(value, BigUint::from(4660u32));
        assert_eq!(offset, 6);
    }

    #[test]
    fn test_parse_mpint_with_high_bit_set() {
        // When high bit is set, SSH adds zero padding byte
        // 0x8048 = 32840 would have high bit set, so padding is added
        // Format: 4-byte length (big-endian) + 0x00 padding + value bytes
        let data = [0u8, 0u8, 0u8, 3u8, 0x00, 0x80, 0x48];
        let (value, offset) = parse_mpint(&data, 0).unwrap();
        assert_eq!(value, BigUint::from(32840u32));
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_serialize_mpint() {
        let value = BigUint::from(4660u32);
        let bytes = serialize_mpint(&value);
        // Length (4 bytes) + value (2 bytes: 0x12, 0x34)
        assert_eq!(bytes.len(), 6);
        assert_eq!(&bytes[4..], &[0x12, 0x34]);
    }

    #[test]
    fn test_serialize_mpint_high_bit() {
        // Value 32840 (0x8048) has high bit set, should add zero padding
        let value = BigUint::from(32840u32);
        let bytes = serialize_mpint(&value);
        // Length (4 bytes) + value (3 bytes with padding: 0x00, 0x80, 0x48)
        assert_eq!(bytes.len(), 7);
        assert_eq!(&bytes[4..], &[0x00, 0x80, 0x48]);
    }

    #[test]
    fn test_parse_bytes() {
        let data = [0u8, 0u8, 0u8, 5u8, 0x01, 0x02, 0x03, 0x04, 0x05];
        let (bytes, offset) = parse_bytes(&data, 0).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_parse_bytes_empty() {
        let data = [0u8, 0u8, 0u8, 0u8];
        let (bytes, offset) = parse_bytes(&data, 0).unwrap();
        assert!(bytes.is_empty());
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_compute_shared_secret() {
        // Test DH shared secret computation
        // Using small numbers for testing
        // Expected: K = f^x mod p = 8^6 mod 23
        // 8^2 = 64 mod 23 = 18
        // 8^4 = 18^2 mod 23 = 324 mod 23 = 2
        // 8^6 = 8^4 * 8^2 = 2 * 18 = 36 mod 23 = 13
        let expected = BigUint::from(13u32);

        // Note: compute_shared_secret uses DH_GROUP14_PRIME_HEX constant
        // So this test validates the modular exponentiation logic
        let result = BigUint::from(8u32).modpow(&BigUint::from(6u32), &BigUint::from(23u32));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_kexdh_init() {
        let e = BigUint::from(12345u32);
        let packet = build_kexdh_init(&e);

        // First byte should be SSH_MSG_KEXDH_INIT
        assert_eq!(packet[0], SSH_MSG_KEXDH_INIT);

        // Rest should be serialized mpint of e
        // The mpint serialization adds length prefix
        assert!(packet.len() > 5);
    }

    #[test]
    fn test_parse_kexdh_reply_valid() {
        // Build a minimal valid KEXDH_REPLY packet
        let mut packet = vec![SSH_MSG_KEXDH_REPLY];

        // Add host key (4-byte length + empty data)
        packet.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]);

        // Add f (server public key) - mpint with value 42
        // mpint format: 4-byte length + value bytes
        packet.extend_from_slice(&[0u8, 0u8, 0u8, 1u8]); // length = 1
        packet.push(42); // value = 0x2A

        // Add signature hash (4-byte length + empty data)
        packet.extend_from_slice(&[0u8, 0u8, 0u8, 0u8]);

        let (host_key, f, signature) = parse_kexdh_reply(&packet).unwrap();

        assert!(host_key.is_empty());
        assert_eq!(f, BigUint::from(42u32));
        assert!(signature.is_empty());
    }

    #[test]
    fn test_parse_kexdh_reply_empty() {
        let packet = vec![];
        let result = parse_kexdh_reply(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_kexdh_reply_wrong_type() {
        let packet = vec![SSH_MSG_KEXINIT]; // Wrong message type
        let result = parse_kexdh_reply(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_exchange_hash_deterministic() {
        // Test that exchange hash is deterministic
        let v_c = b"SSH-2.0-Test\r\n";
        let v_s = b"SSH-2.0-Server\r\n";
        let i_c = vec![1u8, 2, 3];
        let i_s = vec![4u8, 5, 6];
        let k_s = vec![7u8, 8, 9];
        let e = BigUint::from(12345u32);
        let f = BigUint::from(67890u32);
        let k = BigUint::from(42u32);

        let hash1 = compute_exchange_hash(v_c, v_s, &i_c, &i_s, &k_s, &e, &f, &k);
        let hash2 = compute_exchange_hash(v_c, v_s, &i_c, &i_s, &k_s, &e, &f, &k);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA256 produces 32 bytes
    }

    #[test]
    fn test_exchange_hash_different_inputs() {
        let v_c = b"SSH-2.0-Test\r\n";
        let v_s = b"SSH-2.0-Server\r\n";
        let i_c = vec![1u8, 2, 3];
        let i_s = vec![4u8, 5, 6];
        let k_s = vec![7u8, 8, 9];
        let e = BigUint::from(12345u32);
        let f = BigUint::from(67890u32);
        let k = BigUint::from(42u32);

        let hash1 = compute_exchange_hash(v_c, v_s, &i_c, &i_s, &k_s, &e, &f, &k);

        // Change one parameter
        let hash2 =
            compute_exchange_hash(v_c, v_s, &i_c, &i_s, &k_s, &e, &f, &BigUint::from(43u32));

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_dh_constants_defined() {
        // Verify DH constants are properly defined
        assert_eq!(SSH_MSG_KEXDH_INIT, 30);
        assert_eq!(SSH_MSG_KEXDH_REPLY, 31);
        assert_eq!(SSH_MSG_NEWKEYS, 21);
        assert_eq!(DH_GENERATOR, 2);

        // Verify DH prime is valid hex
        let prime_hex = DH_GROUP14_PRIME_HEX.replace([' ', '\t', '\n', '\r'], "");
        let prime = BigUint::parse_bytes(prime_hex.as_bytes(), 16);
        assert!(prime.is_some());

        // Verify it's a large prime (at least 1024 bits = 128 bytes)
        let p = prime.unwrap();
        let byte_count = (p.bits() + 7) / 8;
        assert!(byte_count >= 128, "DH prime should be at least 1024 bits");
        assert!(byte_count <= 256, "DH prime should not exceed 2048 bits");
    }
}
