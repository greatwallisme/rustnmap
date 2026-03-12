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

use md5::{Md5, Digest as Md5Digest};
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
#[expect(dead_code, reason = "Available for future group1 support")]
const PRIME_GROUP1: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
    FFFFFFFFFFFFFFFF";

/// Oakley group 14 prime (2048-bit) from RFC 3526.
#[expect(dead_code, reason = "Used for group14 selection")]
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
#[expect(dead_code, reason = "Available for future group16 support")]
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

/// Read SSH banner from server.
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

    Ok(String::from_utf8_lossy(&line).to_string())
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

/// Calculate MD5 fingerprint.
fn calculate_md5_fingerprint(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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
    let bytes = bn.to_bytes_be();

    // SSH-2 mpint format requires that the high bit be zero for positive numbers
    // If the high bit is set, we need to prepend a zero byte
    let data = if bytes.first().map_or(false, |b| *b & 0x80 != 0) {
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(0);
        padded.extend_from_slice(&bytes);
        padded
    } else {
        bytes
    };

    let len = data.len();
    let mut result = Vec::with_capacity(4 + data.len());
    result.extend_from_slice(&u32::to_be_bytes(len as u32));
    result.extend_from_slice(&data);
    result
}

/// Build SSH-2 packet with payload and padding.
fn build_ssh2_packet(payload: &[u8]) -> Vec<u8> {
    // Padding length must be at least 4 bytes and total packet size must be multiple of 8
    let padding_length = (8 - ((payload.len() + 1 + 4) % 8)) + 4;
    let packet_length = payload.len() + padding_length + 1;

    let mut packet = Vec::with_capacity(4 + packet_length);
    packet.extend_from_slice(&u32::to_be_bytes(packet_length as u32));
    packet.push(padding_length as u8);
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
    payload.extend_from_slice(&u32::to_be_bytes(kex_algorithms.len() as u32));
    payload.extend_from_slice(kex_algorithms.as_bytes());

    // Server host key algorithms
    payload.extend_from_slice(&u32::to_be_bytes(key_type.len() as u32));
    payload.extend_from_slice(key_type.as_bytes());

    // Encryption algorithms (client->server)
    let enc_algos = "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,\
        aes128-ctr,aes192-ctr,aes256-ctr";
    payload.extend_from_slice(&u32::to_be_bytes(enc_algos.len() as u32));
    payload.extend_from_slice(enc_algos.as_bytes());

    // Encryption algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(enc_algos.len() as u32));
    payload.extend_from_slice(enc_algos.as_bytes());

    // MAC algorithms (client->server)
    let mac_algos = "hmac-md5,hmac-sha1,hmac-ripemd160";
    payload.extend_from_slice(&u32::to_be_bytes(mac_algos.len() as u32));
    payload.extend_from_slice(mac_algos.as_bytes());

    // MAC algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(mac_algos.len() as u32));
    payload.extend_from_slice(mac_algos.as_bytes());

    // Compression algorithms (client->server)
    let comp_algos = "none";
    payload.extend_from_slice(&u32::to_be_bytes(comp_algos.len() as u32));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Compression algorithms (server->client)
    payload.extend_from_slice(&u32::to_be_bytes(comp_algos.len() as u32));
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
        return Err(mlua::Error::RuntimeError("Invalid padding length".to_string()));
    }

    let payload_length = packet.len() - padding_length - 1;

    Ok(packet[1..1 + payload_length].to_vec())
}

/// Parse mpint from SSH packet data.
fn parse_mpint(data: &[u8], offset: usize) -> mlua::Result<(BigUint, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError("Data too short for mpint".to_string()));
    }

    let len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError("Data too short for mpint value".to_string()));
    }

    let value_bytes = &data[new_offset..new_offset + len];
    let value = BigUint::from_bytes_be(value_bytes);

    Ok((value, new_offset + len))
}

/// Parse string from SSH packet data.
fn parse_string(data: &[u8], offset: usize) -> mlua::Result<(String, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError("Data too short for string".to_string()));
    }

    let len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError("Data too short for string value".to_string()));
    }

    let value = String::from_utf8_lossy(&data[new_offset..new_offset + len]).to_string();
    Ok((value, new_offset + len))
}

/// Fetch SSH host key with proper key exchange.
fn fetch_host_key_impl(host: &str, port: u16, key_type: &str) -> mlua::Result<HostKeyInfo> {
    let addr = format!("{host}:{port}");

    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    // Exchange banners
    let _banner = read_ssh_banner(host, port, DEFAULT_TIMEOUT_MS)?;
    let client_banner = "SSH-2.0-rustnmap_1.0\r\n";
    stream
        .write_all(client_banner.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send banner: {e}")))?;

    // Send KEXINIT
    let kex_init_payload = build_kex_init(key_type);
    let kex_init_packet = build_ssh2_packet(&kex_init_payload);
    stream
        .write_all(&kex_init_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXINIT: {e}")))?;

    // Receive server KEXINIT
    let _server_kex_packet = receive_ssh_packet(&mut stream)?;
    let _server_kex_payload = extract_payload(&_server_kex_packet)?;

    // Determine which Diffie-Hellman group to use
    // For simplicity, we'll try group14 first (2048-bit), then group1 (1024-bit)
    let (prime_hex, group_bits) = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
        29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
        EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
        E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
        EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
        C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
        83655D23DCA3AD961C62F356208552BB9ED529077096966D\
        670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
        E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
        DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
        15728E5A8AACAA68FFFFFFFFFFFFFFFF", 2048);

    // Parse prime and create DH values
    let p = BigUint::parse_bytes(prime_hex.as_bytes(), 16)
        .ok_or_else(|| mlua::Error::RuntimeError("Failed to parse prime".to_string()))?;
    let g = BigUint::from(DH_GENERATOR);

    // Generate random private key x
    let mut rng = rand::thread_rng();
    let x = rng.gen_biguint(group_bits);
    let e = g.modpow(&x, &p); // e = g^x mod p

    // Build and send KEXDH_INIT
    let mut kexdh_payload = Vec::new();
    kexdh_payload.push(SSH_MSG_KEXDH_INIT);
    kexdh_payload.extend_from_slice(&pack_mpint(&e));

    let kexdh_packet = build_ssh2_packet(&kexdh_payload);
    stream
        .write_all(&kexdh_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXDH_INIT: {e}")))?;

    // Receive KEXDH_REPLY
    let kexdh_reply_packet = receive_ssh_packet(&mut stream)?;
    let kexdh_reply_payload = extract_payload(&kexdh_reply_packet)?;

    // Check message type
    if kexdh_reply_payload.is_empty() || kexdh_reply_payload[0] != SSH_MSG_KEXDH_REPLY {
        return Err(mlua::Error::RuntimeError(
            "Expected KEXDH_REPLY message".to_string(),
        ));
    }

    // Parse KEXDH_REPLY: host key (string), f (mpint), signature (string)
    let offset = 1;

    // Parse public host key
    let (host_key, _new_offset) = parse_string(&kexdh_reply_payload, offset)?;

    // The host key is in SSH format: type + key data
    // For ssh-rsa: string "ssh-rsa" + mpint e + mpint n
    // For ssh-dss: string "ssh-dss" + mpint p + mpint q + mpint g + mpint y
    let parsed_key = parse_ssh_host_key(&host_key.as_bytes())?;

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
    let mut offset = 0;

    // Parse key type string
    let (key_type, new_offset) = parse_string(data, offset)?;
    offset = new_offset;

    let (bits, algorithm) = match key_type.as_str() {
        "ssh-rsa" => {
            // RSA: e (mpint) + n (mpint)
            let (_e, new_off) = parse_mpint(data, offset)?;
            let (n, _new_off) = parse_mpint(data, new_off)?;

            let n_bytes = n.to_bytes_be();
            // Remove leading zero bytes for bit count
            let leading_zeros = n_bytes.iter().take_while(|&&b| b == 0).count();
            let actual_bits = ((n_bytes.len() - leading_zeros) * 8) as u32;

            (actual_bits, "RSA".to_string())
        }
        "ssh-dss" => {
            // DSA: p (mpint) + q (mpint) + g (mpint) + y (mpint)
            let (p, new_off) = parse_mpint(data, offset)?;
            let _q = parse_mpint(data, new_off)?.0;
            let bits = p.bits() as u32;
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
    let fetch_host_key_fn = lua.create_function(|lua, (host, port, key_type): (Value, Value, Option<String>)| {
        let (host_str, port_num) = extract_host_port(host, port);
        let key_type_str = key_type.as_deref().unwrap_or("ssh-rsa");

        debug!("ssh2.fetch_host_key({}, {}, {})", host_str, port_num, key_type_str);

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
                table.set("fingerprint", calculate_md5_fingerprint(&key_info.fp_input))?;
                table.set("fp_sha256", calculate_sha256_fingerprint(&key_info.fp_input))?;

                Ok(Value::Table(table))
            }
            Err(e) => {
                debug!("ssh2.fetch_host_key failed: {}", e);
                Ok(Value::Nil)
            }
        }
    })?;
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
        assert_eq!(fp.len(), 47);
        assert!(fp.contains(':'));
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

        // Total length should be multiple of 8 (block size)
        assert_eq!((packet.len() - 4) % 8, 0);
    }
}
