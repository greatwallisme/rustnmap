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

//! SSH2 library for NSE.
//!
//! This module provides the `ssh2` library which contains SSH-2 protocol functions
//! for NSE scripts. It corresponds to Nmap's ssh2 NSE library.
//!
//! # Available Functions
//!
//! - `ssh2.fetch_host_key(host, port, [key_type])` - Get SSH host key and fingerprint
//! - `ssh2.banner(host, port)` - Get SSH banner string
//!
//! # Supported Key Types
//!
//! - ssh-rsa: RSA keys
//! - ssh-dss: DSA keys
//! - ecdsa-sha2-nistp256: ECDSA P-256 keys
//! - ecdsa-sha2-nistp384: ECDSA P-384 keys
//! - ecdsa-sha2-nistp521: ECDSA P-521 keys
//! - ssh-ed25519: Ed25519 keys
//!
//! # Diffie-Hellman Groups
//!
//! - diffie-hellman-group1-sha1: 1024-bit prime (Oakley group 2)
//! - diffie-hellman-group14-sha1: 2048-bit prime (Oakley group 14)
//! - diffie-hellman-group16-sha512: 4096-bit prime (Oakley group 16)
//! - diffie-hellman-group-exchange-sha1: Variable size
//! - diffie-hellman-group-exchange-sha256: Variable size
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local ssh2 = require "ssh2"
//!
//! -- Get host key
//! local key = ssh2.fetch_host_key(host, port, "ssh-rsa")
//! if key then
//!     print("Key type: " .. key.key_type)
//!     print("Algorithm: " .. key.algorithm)
//!     print("Bits: " .. key.bits)
//!     print("Fingerprint: " .. key.fingerprint)
//!     print("SHA256: " .. key.fp_sha256)
//! end
//!
//! -- Get banner
//! local banner = ssh2.banner(host, port)
//! if banner then
//!     print("SSH Banner: " .. banner)
//! end
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use md5::{Digest as Md5Digest, Md5};
use mlua::Value;
use num_bigint::{BigUint, RandBigInt};
use rand::Rng;
use sha2::Sha256;
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for SSH connections in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// SSH-2 message codes.
const SSH_MSG_KEXINIT: u8 = 20;
#[expect(dead_code, reason = "Defined for protocol completeness")]
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEXDH_INIT: u8 = 30;
const SSH_MSG_KEXDH_REPLY: u8 = 31;

/// SSH2 banner prefix.
const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

/// Oakley group 2 prime (1024-bit) from RFC 2409.
const PRIME_GROUP1: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
    FFFFFFFFFFFFFFFF";

/// Oakley group 14 prime (2048-bit) from RFC 3526.
const PRIME_GROUP14: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\
    670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
    DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
    15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// Oakley group 16 prime (4096-bit) from RFC 3526.
const PRIME_GROUP16: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\
    670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
    DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
    15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
    ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
    ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
    F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
    BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
    43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
    88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA\
    2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6\
    287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED\
    1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
    93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
    FFFFFFFFFFFFFFFF";

/// Diffie-Hellman generator.
const DH_GENERATOR: u32 = 2;

/// Read SSH banner from an existing stream.
fn read_banner_from_stream(stream: &mut TcpStream) -> mlua::Result<String> {
    // Read server banner line (until \n)
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

    Ok(String::from_utf8_lossy(&line).to_string())
}

/// Read SSH banner from server (standalone function for banner-only queries).
fn read_ssh_banner(host: &str, port: u16, timeout_ms: u64) -> mlua::Result<String> {
    let addr = format!("{host}:{port}");

    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    // Send client banner
    let client_banner = "SSH-2.0-rustnmap_1.0\r\n";
    stream
        .write_all(client_banner.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send banner: {e}")))?;

    // Read server banner using the shared function
    read_banner_from_stream(&mut stream)
}

/// Extract host and port from Lua values.
fn extract_host_port(host: Value, port: Value) -> (String, u16) {
    let host_str = match host {
        Value::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        Value::Table(t) => t
            .get::<Option<String>>("ip")
            .ok()
            .flatten()
            .or_else(|| t.get::<Option<String>>("name").ok().flatten())
            .unwrap_or_default(),
        _ => String::new(),
    };

    let port_num = match port {
        Value::Integer(n) => u16::try_from(n).unwrap_or(22),
        Value::Table(t) => t
            .get::<Option<i64>>("number")
            .ok()
            .flatten()
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(22),
        _ => 22,
    };

    (host_str, port_num)
}

/// Calculate MD5 fingerprint (raw bytes).
fn calculate_md5_fingerprint(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut fp = [0u8; 16];
    fp.copy_from_slice(&result);
    fp
}

/// Calculate SHA256 fingerprint (Base64 format).
fn calculate_sha256_fingerprint(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let base64 = base64_encode(&result);
    format!("SHA256:{base64}")
}

/// Base64 encoding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result.trim_end_matches('=').to_string()
}

/// Pack a multiprecision integer (mpint) as SSH-2 binary format.
fn pack_mpint(bn: &BigUint) -> Vec<u8> {
    let bits = bn.bits();
    let bytes = bn.to_bytes_be();

    // SSH-2 mpint format: prepend zero byte if number uses exact multiple of 8 bits
    // This matches Nmap's: if bytes > 0 and bn:num_bits() % 8 == 0
    let data = if bits > 0 && bits.is_multiple_of(8) {
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(0);
        padded.extend_from_slice(&bytes);
        padded
    } else {
        bytes
    };

    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let mut result = Vec::with_capacity(4 + data.len());
    result.extend_from_slice(&u32::to_be_bytes(len));
    result.extend_from_slice(&data);
    result
}

/// Build SSH-2 packet with payload and padding.
/// Per RFC 4253 Section 6: the concatenation of `packet_length`, `padding_length`, `payload`, and `random padding`
/// MUST be a multiple of the cipher block size or 8, whichever is larger.
fn build_ssh2_packet(payload: &[u8]) -> Vec<u8> {
    // Calculate padding: 8 - ((payload + padding_length_byte + packet_length_field) % 8)
    // Per RFC 4253 Section 6, packet_length field IS included in the alignment calculation
    let mut padding_length = 8 - ((payload.len() + 1 + 4) % 8);
    // Minimum padding is 4 bytes
    if padding_length < 4 {
        padding_length += 8;
    }
    let padding_length: u8 = u8::try_from(padding_length).unwrap_or(4);
    let packet_length = payload.len() + usize::from(padding_length) + 1;

    let mut packet = Vec::with_capacity(4 + packet_length);
    packet.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(packet_length).unwrap_or(u32::MAX),
    ));
    packet.push(padding_length);
    packet.extend_from_slice(payload);

    // Add random padding
    let mut rng = rand::thread_rng();
    for _ in 0..padding_length {
        packet.push(rng.gen());
    }

    packet
}

/// Build KEXINIT packet.
fn build_kex_init(key_type: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(SSH_MSG_KEXINIT);

    // Cookie (16 random bytes)
    let mut rng = rand::thread_rng();
    for _ in 0..16 {
        payload.push(rng.gen());
    }

    // Key exchange algorithms
    let kex_algorithms = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,\
        diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,\
        diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(kex_algorithms.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(kex_algorithms.as_bytes());

    // Server host key algorithms
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(key_type.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(key_type.as_bytes());

    // Encryption algorithms (client->server)
    let enc_algos = "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,\
        aes128-ctr,aes192-ctr,aes256-ctr";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // Encryption algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // MAC algorithms (client->server)
    let mac_algos = "hmac-md5,hmac-sha1,hmac-ripemd160";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // MAC algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // Compression algorithms (client->server)
    let comp_algos = "none";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Compression algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Languages (client->server)
    payload.extend_from_slice(&u32::to_be_bytes(0u32));

    // Languages (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(0u32));

    // No kex prediction
    payload.extend_from_slice(&[0u8, 0u8, 0u8, 0u8, 0u8]);

    payload
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

    // Check for overflow: padding_length + 1 must not exceed packet length
    if padding_length + 1 > packet.len() {
        return Err(mlua::Error::RuntimeError(
            "Invalid padding length".to_string(),
        ));
    }

    let payload_length = packet.len() - padding_length - 1;

    Ok(packet[1..=payload_length].to_vec())
}

/// Parse name-list from KEXINIT payload at given offset.
/// Returns (list of algorithm names, new offset).
fn parse_name_list(data: &[u8], offset: usize) -> mlua::Result<(Vec<String>, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for name-list length".to_string(),
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
            "Data too short for name-list value".to_string(),
        ));
    }

    let list_str = String::from_utf8_lossy(&data[new_offset..new_offset + len]).to_string();
    let algorithms: Vec<String> = list_str
        .split(',')
        .map(std::string::ToString::to_string)
        .collect();

    Ok((algorithms, new_offset + len))
}

/// Select a matching key exchange algorithm.
/// Per RFC 4253: server chooses the FIRST algorithm in CLIENT's list that it supports.
/// Returns (`algorithm_name`, `prime_hex`, `group_bits`) as owned String.
fn select_kex_algorithm(server_kex_algorithms: &[String]) -> mlua::Result<(String, String, usize)> {
    // Our client's algorithms in order of preference (what we send in KEXINIT)
    // Server will choose the FIRST one it supports from this list
    let our_algorithms: [(&str, &str, usize); 6] = [
        ("diffie-hellman-group1-sha1", PRIME_GROUP1, 1024),
        ("diffie-hellman-group14-sha1", PRIME_GROUP14, 2048),
        ("diffie-hellman-group14-sha256", PRIME_GROUP14, 2048),
        ("diffie-hellman-group16-sha512", PRIME_GROUP16, 4096),
        ("diffie-hellman-group-exchange-sha1", PRIME_GROUP14, 2048),
        ("diffie-hellman-group-exchange-sha256", PRIME_GROUP14, 2048),
    ];

    // Convert server algorithms to a set for fast lookup
    let server_set: std::collections::HashSet<&str> =
        server_kex_algorithms.iter().map(String::as_str).collect();

    // Find first algorithm in OUR list that server supports
    // This matches SSH protocol: server picks first client algorithm it supports
    for (name, prime, bits) in &our_algorithms {
        if server_set.contains(*name) {
            debug!(
                "ssh2: selected kex algorithm: {} (server supports it)",
                name
            );
            return Ok(((*name).to_string(), (*prime).to_string(), *bits));
        }
    }

    // No matching algorithm found
    let server_algos = server_kex_algorithms.join(", ");
    Err(mlua::Error::RuntimeError(format!(
        "No compatible key exchange algorithm. Server offers: {server_algos}"
    )))
}

/// Parse mpint from SSH packet data.
fn parse_mpint(data: &[u8], offset: usize) -> mlua::Result<(BigUint, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for mpint".to_string(),
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
        return Err(mlua::Error::RuntimeError(format!(
            "Data too short for mpint value: need {} bytes at offset {}, have {}",
            len,
            new_offset,
            data.len()
        )));
    }

    let value_bytes = &data[new_offset..new_offset + len];
    let value = BigUint::from_bytes_be(value_bytes);

    Ok((value, new_offset + len))
}

/// Parse bytes from SSH packet data (for binary data like host keys).
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

    // Check if length points to valid data within bounds
    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(format!(
            "Data too short for bytes value: need {} bytes at offset {}, have {}",
            len,
            new_offset,
            data.len()
        )));
    }

    let value = data[new_offset..new_offset + len].to_vec();
    Ok((value, new_offset + len))
}

/// Parse string from SSH packet data.
/// Note: For binary data like host keys, use `parse_bytes` instead.
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

    // Check if length points to valid data within bounds
    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(format!(
            "Data too short for string value: need {} bytes at offset {}, have {}",
            len,
            new_offset,
            data.len()
        )));
    }

    let value = String::from_utf8_lossy(&data[new_offset..new_offset + len]).to_string();
    Ok((value, new_offset + len))
}

/// Parse SSH DISCONNECT message from payload.
/// Returns `Ok(reason_code, description)` if payload is a valid DISCONNECT message.
fn parse_disconnect_message(payload: &[u8]) -> mlua::Result<(u32, String)> {
    // DISCONNECT format: reason_code(4) + description(string) + language(string)
    if payload.len() <= 4 {
        return Err(mlua::Error::RuntimeError(
            "DISCONNECT payload too short".to_string(),
        ));
    }

    let reason_code = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

    if payload.len() > 8 {
        let desc_len =
            u32::from_be_bytes([payload[5], payload[6], payload[7], payload[8]]) as usize;
        if payload.len() > 9 + desc_len {
            let desc = String::from_utf8_lossy(&payload[9..9 + desc_len]).to_string();
            return Ok((reason_code, desc));
        }
    }

    Ok((reason_code, String::new()))
}

/// Parse server KEXINIT and verify key type is supported.
/// Returns the selected KEX algorithm name, prime hex, and group bits.
fn parse_server_kexinit_and_check_key_type(
    server_kex_payload: &[u8],
    key_type: &str,
) -> mlua::Result<(String, String, usize)> {
    // Format: MSG_KEXINIT(1) + cookie(16) + kex_algorithms(name-list) + ...
    if server_kex_payload.len() < 17 {
        return Err(mlua::Error::RuntimeError(
            "Server KEXINIT payload too short".to_string(),
        ));
    }

    // Skip MSG_KEXINIT (1 byte) and cookie (16 bytes)
    let (server_kex_algorithms, offset_after_kex) = parse_name_list(server_kex_payload, 17)?;

    // Parse server's host key algorithms to check if requested key type is supported
    let (server_host_key_algorithms, _) = parse_name_list(server_kex_payload, offset_after_kex)?;

    // Check if server supports the requested key type
    let server_supports_key_type = server_host_key_algorithms
        .iter()
        .any(|algo| algo == key_type);

    if !server_supports_key_type {
        debug!(
            "ssh2.fetch_host_key: server does not support requested key type '{}'. Supported: {:?}",
            key_type, server_host_key_algorithms
        );
        return Err(mlua::Error::RuntimeError(format!(
            "Server does not support key type: {key_type}"
        )));
    }

    // Select matching algorithm
    select_kex_algorithm(&server_kex_algorithms)
}

/// Validate `KEXDH_REPLY` message type and extract the host key.
/// Returns the parsed host key bytes.
fn validate_kexdh_reply_and_extract_host_key(
    kexdh_reply_payload: &[u8],
    key_type: &str,
) -> mlua::Result<Vec<u8>> {
    // Check message type - log actual type for debugging
    if kexdh_reply_payload.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "Empty KEXDH_REPLY payload".to_string(),
        ));
    }
    let msg_type = kexdh_reply_payload[0];
    if msg_type != SSH_MSG_KEXDH_REPLY {
        // SSH message types: 1=DISCONNECT, 2=IGNORE, 3=UNIMPLEMENTED, 4=DEBUG, 20=KEXINIT, 31=KEXDH_REPLY
        let msg_name = match msg_type {
            1 => "DISCONNECT",
            2 => "IGNORE",
            3 => "UNIMPLEMENTED",
            4 => "DEBUG",
            20 => "KEXINIT",
            31 => "KEXDH_REPLY",
            _ => "UNKNOWN",
        };

        // If DISCONNECT, try to parse the error message
        if msg_type == 1 {
            if let Ok((reason_code, desc)) = parse_disconnect_message(kexdh_reply_payload) {
                debug!(
                    "ssh2.fetch_host_key: server DISCONNECT - reason={reason_code}, description={desc}"
                );
                return Err(mlua::Error::RuntimeError(format!(
                    "Server disconnected (reason {reason_code}): {desc}"
                )));
            }
        }

        debug!(
            "ssh2.fetch_host_key: received message type {} ({}) instead of KEXDH_REPLY (31)",
            msg_type, msg_name
        );
        return Err(mlua::Error::RuntimeError(format!(
            "Expected KEXDH_REPLY (31), got message type {msg_type} ({msg_name})"
        )));
    }

    // Parse KEXDH_REPLY: host key (string), f (mpint), signature (string)
    let offset = 1;

    // Debug: show raw bytes at offset to see length field
    if kexdh_reply_payload.len() > 10 {
        debug!(
            "ssh2.fetch_host_key: raw bytes at offset {}: {:02x} {:02x} {:02x} {:02x}",
            offset,
            kexdh_reply_payload[offset],
            kexdh_reply_payload[offset + 1],
            kexdh_reply_payload[offset + 2],
            kexdh_reply_payload[offset + 3]
        );
    }

    // Parse public host key - use parse_bytes for binary data, not parse_string
    let (host_key, _new_offset) = parse_bytes(kexdh_reply_payload, offset)?;

    // Debug: log the actual key type returned by server
    if let Ok((returned_key_type, _)) = parse_string(&host_key, 0) {
        debug!(
            "ssh2.fetch_host_key: server returned '{}' key, requested '{}'",
            returned_key_type, key_type
        );
    }

    Ok(host_key)
}

/// Perform Diffie-Hellman key exchange and send `KEXDH_INIT`.
fn perform_dh_key_exchange(
    stream: &mut TcpStream,
    prime_hex: &str,
    group_bits: usize,
) -> mlua::Result<(BigUint, BigUint)> {
    let p = BigUint::parse_bytes(prime_hex.as_bytes(), 16)
        .ok_or_else(|| mlua::Error::RuntimeError("Failed to parse prime".to_string()))?;
    let g = BigUint::from(DH_GENERATOR);

    // Generate random private key x (should be in range [1, q-1] where q = (p-1)/2)
    // Use group_bits - 1 to ensure x < q
    let mut rng = rand::thread_rng();
    let x = rng.gen_biguint(
        u64::try_from(group_bits.saturating_sub(1))
            .map_err(|_err| mlua::Error::RuntimeError("Group bits too large".to_string()))?,
    );
    let e = g.modpow(&x, &p); // e = g^x mod p

    // Build and send KEXDH_INIT
    let mut kexdh_payload = Vec::new();
    kexdh_payload.push(SSH_MSG_KEXDH_INIT);
    let e_mpint = pack_mpint(&e);
    debug!("ssh2: e_mpint length = {} bytes", e_mpint.len());
    kexdh_payload.extend_from_slice(&e_mpint);

    let kexdh_packet = build_ssh2_packet(&kexdh_payload);

    // Debug: full packet hex dump
    let hex_all: Vec<String> = kexdh_packet.iter().map(|b| format!("{b:02x}")).collect();
    debug!(
        "ssh2: KEXDH_INIT full packet ({} bytes): {}",
        kexdh_packet.len(),
        hex_all.join("")
    );
    debug!(
        "ssh2: KEXDH_INIT breakdown - payload_len={}, packet_len_field={}, padding={}",
        kexdh_payload.len(),
        u32::from_be_bytes(kexdh_packet[0..4].try_into().unwrap()),
        kexdh_packet[4]
    );

    stream
        .write_all(&kexdh_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXDH_INIT: {e}")))?;

    Ok((x, e))
}

/// Fetch SSH host key with proper key exchange.
fn fetch_host_key_impl(host: &str, port: u16, key_type: &str) -> mlua::Result<HostKeyInfo> {
    let addr = format!("{host}:{port}");

    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    // Exchange banners - send client banner first
    let client_banner = "SSH-2.0-rustnmap_1.0\r\n";
    stream
        .write_all(client_banner.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send banner: {e}")))?;

    // Read server banner from the same stream
    let _server_banner = read_banner_from_stream(&mut stream)?;

    // Send KEXINIT
    let kex_init_payload = build_kex_init(key_type);
    let kex_init_packet = build_ssh2_packet(&kex_init_payload);
    stream
        .write_all(&kex_init_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXINIT: {e}")))?;
    stream
        .flush()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to flush: {e}")))?;

    // Receive server KEXINIT and parse to find matching algorithm
    let server_kex_packet = receive_ssh_packet(&mut stream)?;
    let server_kex_payload = extract_payload(&server_kex_packet)?;

    // Parse server KEXINIT and verify key type is supported
    let (algo_name, prime_hex, group_bits) =
        parse_server_kexinit_and_check_key_type(&server_kex_payload, key_type)?;
    debug!("ssh2: using prime for {algo_name} ({group_bits} bits)");

    // Perform DH key exchange and send KEXDH_INIT
    let (_x, _e) = perform_dh_key_exchange(&mut stream, &prime_hex, group_bits)?;

    // Receive KEXDH_REPLY
    let kexdh_reply_packet = receive_ssh_packet(&mut stream)?;
    let kexdh_reply_payload = extract_payload(&kexdh_reply_packet)?;

    debug!(
        "ssh2.fetch_host_key: received KEXDH_REPLY packet, {} bytes, payload {} bytes",
        kexdh_reply_packet.len(),
        kexdh_reply_payload.len()
    );

    // Validate KEXDH_REPLY message type and extract the host key
    let host_key = validate_kexdh_reply_and_extract_host_key(&kexdh_reply_payload, key_type)?;

    // The host key is in SSH format: type + key data
    // For ssh-rsa: string "ssh-rsa" + mpint e + mpint n
    // For ssh-dss: string "ssh-dss" + mpint p + mpint q + mpint g + mpint y
    let parsed_key = parse_ssh_host_key(&host_key)?;

    Ok(parsed_key)
}

/// Parsed SSH host key information.
#[derive(Debug, Clone)]
struct HostKeyInfo {
    key_type: String,
    key: String,
    fp_input: Vec<u8>,
    bits: u32,
    algorithm: String,
    full_key: String,
}

/// Parse SSH public host key from binary format.
fn parse_ssh_host_key(data: &[u8]) -> mlua::Result<HostKeyInfo> {
    debug!(
        "ssh2: parse_ssh_host_key called with data_len={}",
        data.len()
    );

    let mut offset = 0;

    // Parse key type string
    let (key_type, new_offset) = parse_string(data, offset)?;
    offset = new_offset;

    debug!(
        "ssh2: parse_ssh_host_key: key_type={}, offset={}, data_len={}",
        key_type,
        offset,
        data.len()
    );

    // For DSA keys, dump more info to debug the issue
    if key_type == "ssh-dss" && data.len() < 1000 {
        let preview: Vec<String> = data.iter().take(100).map(|b| format!("{b:02x}")).collect();
        debug!(
            "ssh2: DSA key data (first 100 bytes): {}",
            preview.join(" ")
        );
    }

    let (bits, algorithm) = match key_type.as_str() {
        "ssh-rsa" => {
            // RSA: e (mpint) + n (mpint)
            let (_e, new_off) = parse_mpint(data, offset)?;
            let (n, _new_off) = parse_mpint(data, new_off)?;

            let n_bytes = n.to_bytes_be();
            // Remove leading zero bytes for bit count
            let leading_zeros = n_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_bits =
                u32::try_from((n_bytes.len() - leading_zeros) * 8).unwrap_or(u32::MAX);

            (actual_bits, "RSA".to_string())
        }
        "ssh-dss" => {
            // DSA: p (mpint) + q (mpint) + g (mpint) + y (mpint)
            let (p, new_off) = parse_mpint(data, offset)?;
            debug!(
                "ssh2: DSA p parsed, offset={}, data_len={}",
                new_off,
                data.len()
            );
            let (_q, new_off) = parse_mpint(data, new_off).map_err(|e| {
                debug!(
                    "ssh2: failed to parse DSA q parameter at offset {}: {}",
                    new_off, e
                );
                e
            })?;
            let (_g, _new_off) = parse_mpint(data, new_off).map_err(|e| {
                debug!("ssh2: failed to parse DSA g parameter: {}", e);
                e
            })?;
            let bits = u32::try_from(p.bits()).unwrap_or(u32::MAX);
            (bits, "DSA".to_string())
        }
        "ecdsa-sha2-nistp256" => (256, "ECDSA".to_string()),
        "ecdsa-sha2-nistp384" => (384, "ECDSA".to_string()),
        "ecdsa-sha2-nistp521" => (521, "ECDSA".to_string()),
        "ssh-ed25519" => (256, "ED25519".to_string()),
        _ => {
            return Err(mlua::Error::RuntimeError(format!(
                "Unsupported key type: {key_type}"
            )))
        }
    };

    let fp_input = data.to_vec();
    let key = base64_encode(data);
    let full_key = format!("{key_type} {key}");

    Ok(HostKeyInfo {
        key_type,
        key,
        fp_input,
        bits,
        algorithm,
        full_key,
    })
}

/// Register the ssh2 library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the ssh2 table
    let ssh2_table = lua.create_table()?;

    // Register fetch_host_key function
    let fetch_host_key_fn = lua.create_function(
        |lua, (host, port, key_type): (Value, Value, Option<String>)| {
            let (host_str, port_num) = extract_host_port(host, port);
            let key_type_str = key_type.as_deref().unwrap_or("ssh-rsa");

            debug!(
                "ssh2.fetch_host_key({}, {}, {})",
                host_str, port_num, key_type_str
            );

            match fetch_host_key_impl(&host_str, port_num, key_type_str) {
                Ok(key_info) => {
                    // Create result table
                    let table = lua.create_table()?;
                    table.set("key_type", key_info.key_type.as_str())?;
                    table.set("key", key_info.key.as_str())?;
                    table.set("fp_input", lua.create_string(&key_info.fp_input)?)?;
                    table.set("bits", i64::from(key_info.bits))?;
                    table.set("algorithm", key_info.algorithm.as_str())?;
                    table.set("full_key", key_info.full_key.as_str())?;
                    let fp = calculate_md5_fingerprint(&key_info.fp_input);
                    table.set("fingerprint", lua.create_string(fp)?)?;
                    table.set(
                        "fp_sha256",
                        calculate_sha256_fingerprint(&key_info.fp_input),
                    )?;

                    Ok(Value::Table(table))
                }
                Err(e) => {
                    debug!("ssh2.fetch_host_key failed: {}", e);
                    Ok(Value::Nil)
                }
            }
        },
    )?;
    ssh2_table.set("fetch_host_key", fetch_host_key_fn)?;

    // Register banner function
    let banner_fn = lua.create_function(|lua, (host, port): (Value, Value)| {
        let (host_str, port_num) = extract_host_port(host, port);

        debug!("ssh2.banner({}, {})", host_str, port_num);

        match read_ssh_banner(&host_str, port_num, DEFAULT_TIMEOUT_MS) {
            Ok(banner) => Ok(Value::String(lua.create_string(&banner)?)),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    ssh2_table.set("banner", banner_fn)?;

    // Register the ssh2 library globally
    lua.globals().set("ssh2", ssh2_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let input = b"hello";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn test_calculate_md5_fingerprint() {
        let data = b"test data";
        let fp = calculate_md5_fingerprint(data);
        assert_eq!(fp.len(), 16); // MD5 is 16 bytes
                                  // Known MD5 of "test data": eb733a00c0c9d336e65691a37ab54293
        assert_eq!(fp[0], 0xeb);
        assert_eq!(fp[1], 0x73);
        assert_eq!(fp[2], 0x3a);
    }

    #[test]
    fn test_calculate_sha256_fingerprint() {
        let data = b"test data";
        let fp = calculate_sha256_fingerprint(data);
        assert!(fp.starts_with("SHA256:"));
    }

    #[test]
    fn test_extract_host_port() {
        let (host, port) = extract_host_port(Value::Nil, Value::Integer(22));
        assert_eq!(host, "");
        assert_eq!(port, 22);
    }

    #[test]
    fn test_pack_mpint() {
        let value = BigUint::from(12345u32);
        let packed = pack_mpint(&value);
        assert!(!packed.is_empty());
        assert_eq!(packed[0], 0); // Length bytes
        assert_eq!(packed[1], 0);
        assert_eq!(packed[2], 0);
        assert_eq!(packed[3], 2); // 2 bytes
    }

    #[test]
    fn test_build_ssh2_packet() {
        let payload = b"test payload";
        let packet = build_ssh2_packet(payload);

        // Packet should have: 4 bytes length + 1 byte padding + payload + padding
        assert!(packet.len() >= payload.len() + 5);

        // Per RFC 4253 Section 6: total length INCLUDING the 4-byte packet_length field
        // must be a multiple of 8 (block size)
        assert_eq!(packet.len() % 8, 0);
    }
}
