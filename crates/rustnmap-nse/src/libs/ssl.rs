//! SSL Certificate library for NSE.
//!
//! This module provides the `sslcert` library which contains SSL/TLS certificate
//! functions for NSE scripts. It corresponds to Nmap's sslcert NSE library.
//!
//! # Available Functions
//!
//! - `sslcert.getCertificate(host, port, [options])` - Retrieve SSL/TLS certificate
//! - `sslcert.parse_ssl_certificate(der_data)` - Parse DER-encoded certificate
//!
//! # STARTTLS Support
//!
//! The library supports STARTTLS for multiple protocols:
//! - ftp (port 21)
//! - imap (port 143)
//! - ldap (port 389)
//! - mysql (port 3306)
//! - nntp (port 119)
//! - pop3 (port 110)
//! - postgres / postgresql (port 5432)
//! - smtp (port 25, 587)
//! - tds / ms-sql-s (port 1433)
//! - vnc (port 5900) - `VeNCrypt`
//! - xmpp (port 5222)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local sslcert = require "sslcert"
//!
//! local cert = sslcert.getCertificate(host, port)
//! if cert then
//!     print("Subject: " .. cert.subject)
//!     print("Issuer: " .. cert.issuer)
//! end
//! ```

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[cfg(feature = "openssl")]
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

use mlua::{String as LuaString, Table, UserData, UserDataMethods, Value};
use sha2::{Digest as Sha256Digest, Sha256};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for SSL connections in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// Maximum bytes to read in a single receive call.
const MAX_RECEIVE_BYTES: usize = 4096;

/// Direct TLS ports where TLS is used from the start (no STARTTLS).
const DIRECT_TLS_PORTS: [u16; 8] = [443, 636, 853, 993, 995, 5061, 6697, 8443];

/// STARTTLS service names recognized by the library.
const STARTTLS_SERVICES: &[&str] = &[
    "ftp",
    "smtp",
    "pop3",
    "imap",
    "ldap",
    "nntp",
    "xmpp",
    "postgres",
    "postgresql",
    "mysql",
    "vnc",
    "lmtp",
    "tds",
    "ms-sql-s",
];

/// STARTTLS port numbers recognized by the library.
const STARTTLS_PORTS: [u16; 13] = [
    21, 25, 110, 119, 143, 389, 587, 3306, 5222, 5269, 5432, 5900, 1433,
];

/// Connect via TLS using the `openssl` crate's `SslConnector` and extract the peer certificate DER data.
///
/// This performs a proper TLS 1.2/1.3 handshake with full cipher suite negotiation,
/// SNI (Server Name Indication), and all required extensions.
#[cfg(feature = "openssl")]
fn tls_connect_and_get_cert(hostname: &str, addr: std::net::SocketAddr) -> mlua::Result<Vec<u8>> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to create SSL connector: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .map_err(|e| mlua::Error::RuntimeError(format!("TLS connect failed to {addr}: {e}")))?;

    let ssl_stream = connector.connect(hostname, stream).map_err(|e| {
        mlua::Error::RuntimeError(format!("SSL handshake failed for {hostname}: {e}"))
    })?;

    let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| {
        mlua::Error::RuntimeError("Server did not present a certificate".to_string())
    })?;

    cert.to_der()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to encode certificate as DER: {e}")))
}

#[cfg(not(feature = "openssl"))]
fn tls_connect_and_get_cert(_hostname: &str, _addr: std::net::SocketAddr) -> mlua::Result<Vec<u8>> {
    Err(mlua::Error::RuntimeError(
        "SSL support not available (openssl feature not enabled)".to_string(),
    ))
}

/// Connect raw TCP, perform STARTTLS negotiation, then upgrade to TLS and extract certificate.
///
/// This is used for protocols that require plaintext negotiation before TLS upgrade
/// (e.g., SMTP, POP3, IMAP, FTP, XMPP, LDAP, `PostgreSQL`).
#[cfg(feature = "openssl")]
fn starttls_and_get_cert(
    hostname: &str,
    addr: std::net::SocketAddr,
    protocol: &str,
) -> mlua::Result<Vec<u8>> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(DEFAULT_TIMEOUT_MS))
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set write timeout: {e}")))?;
    let mut stream = stream;

    perform_starttls(&mut stream, protocol)?;

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to create SSL connector: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let ssl_stream = connector.connect(hostname, stream).map_err(|e| {
        mlua::Error::RuntimeError(format!(
            "SSL handshake failed for {hostname} (STARTTLS {protocol}): {e}"
        ))
    })?;
    let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| {
        mlua::Error::RuntimeError("Server did not present a certificate".to_string())
    })?;
    cert.to_der()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to encode certificate as DER: {e}")))
}

#[cfg(not(feature = "openssl"))]
fn starttls_and_get_cert(
    _hostname: &str,
    _addr: std::net::SocketAddr,
    _protocol: &str,
) -> mlua::Result<Vec<u8>> {
    Err(mlua::Error::RuntimeError(
        "SSL support not available (openssl feature not enabled)".to_string(),
    ))
}

/// Convert DER to PEM format.
fn der_to_pem(der_data: &[u8]) -> String {
    let base64 = base64_encode(der_data);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");

    for (i, c) in base64.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            pem.push('\n');
        }
        pem.push(c);
    }

    pem.push_str("\n-----END CERTIFICATE-----\n");
    pem
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

    result
}

/// Extract distinguished name field from DER certificate.
fn extract_dn_field(der_data: &[u8]) -> Option<String> {
    let len = der_data.len().min(512);

    for i in 0..len.saturating_sub(10) {
        if der_data[i] == 0x55 && der_data[i + 1] == 0x04 && der_data[i + 2] == 0x03 {
            let str_len = der_data.get(i + 5).copied().unwrap_or(0) as usize;
            if i + 6 + str_len <= der_data.len() {
                return Some(
                    String::from_utf8_lossy(&der_data[i + 6..i + 6 + str_len]).to_string(),
                );
            }
        }
    }

    None
}

/// Extract serial number from DER certificate.
fn extract_serial(der_data: &[u8]) -> String {
    if der_data.len() > 20 {
        let serial_len = der_data.get(15).copied().unwrap_or(0) as usize;
        if serial_len > 0 && serial_len < 32 && 16 + serial_len <= der_data.len() {
            return der_data[16..16 + serial_len]
                .iter()
                .fold(String::new(), |mut s, b| {
                    let _ = write!(s, "{b:02X}");
                    s
                });
        }
    }
    "Unknown".to_string()
}

/// Calculate SHA256 fingerprint.
fn calculate_fingerprint(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    result
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Extract validity period from DER certificate.
fn extract_validity(der_data: &[u8]) -> (String, String) {
    let mut not_before = String::new();
    let mut not_after = String::new();
    let mut found_times = 0;

    for i in 0..der_data.len().saturating_sub(20) {
        if der_data[i] == 0x17 || der_data[i] == 0x18 {
            let time_type = der_data[i];
            if let Some(&len) = der_data.get(i + 1) {
                if len > 0 && len < 20 && i + 2 + len as usize <= der_data.len() {
                    let time_bytes = &der_data[i + 2..i + 2 + len as usize];
                    if let Ok(time_str) = std::str::from_utf8(time_bytes) {
                        let formatted = if time_type == 0x17 {
                            format_utctime(time_str)
                        } else {
                            format_generalized_time(time_str)
                        };

                        if found_times == 0 {
                            not_before = formatted;
                            found_times = 1;
                        } else if found_times == 1 {
                            not_after = formatted;
                            break;
                        }
                    }
                }
            }
        }
    }

    if not_before.is_empty() {
        not_before = "1970-01-01T00:00:00Z".to_string();
    }
    if not_after.is_empty() {
        not_after = "1970-01-01T00:00:00Z".to_string();
    }

    (not_before, not_after)
}

/// Format `UTCTime` string to ISO 8601 format.
fn format_utctime(time: &str) -> String {
    if time.len() >= 12 {
        let yy: u32 = time[0..2].parse().unwrap_or(70);
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        format!(
            "{:04}-{}-{}T{}:{}:{}Z",
            year,
            &time[2..4],
            &time[4..6],
            &time[6..8],
            &time[8..10],
            &time[10..12]
        )
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

/// Format `GeneralizedTime` string to ISO 8601 format.
fn format_generalized_time(time: &str) -> String {
    if time.len() >= 14 {
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &time[0..4],
            &time[4..6],
            &time[6..8],
            &time[8..10],
            &time[10..12],
            &time[12..14]
        )
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
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
        Value::Integer(n) => u16::try_from(n).unwrap_or(443),
        Value::Table(t) => t
            .get::<Option<i64>>("number")
            .ok()
            .flatten()
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(443),
        _ => 443,
    };

    (host_str, port_num)
}

/// Perform STARTTLS handshake.
#[allow(
    clippy::too_many_lines,
    reason = "STARTTLS handshake protocol requires many state transitions"
)]
fn perform_starttls(stream: &mut TcpStream, protocol: &str) -> mlua::Result<()> {
    let mut buffer = [0u8; 1024];

    // Read initial banner
    let n = stream
        .read(&mut buffer)
        .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS read failed: {e}")))?;
    let _response = String::from_utf8_lossy(&buffer[..n]);

    match protocol {
        "smtp" => {
            stream
                .write_all(b"EHLO localhost\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("250") {
                return Err(mlua::Error::RuntimeError("EHLO failed".to_string()));
            }

            stream
                .write_all(b"STARTTLS\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("220") {
                return Err(mlua::Error::RuntimeError(
                    "STARTTLS command failed".to_string(),
                ));
            }
        }
        "pop3" => {
            stream
                .write_all(b"STLS\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("STLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("STLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("+OK") {
                return Err(mlua::Error::RuntimeError("STLS command failed".to_string()));
            }
        }
        "imap" => {
            stream
                .write_all(b"A001 STARTTLS\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("OK") {
                return Err(mlua::Error::RuntimeError(
                    "STARTTLS command failed".to_string(),
                ));
            }
        }
        "ftp" => {
            stream
                .write_all(b"AUTH TLS\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("AUTH TLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("AUTH TLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("234") {
                return Err(mlua::Error::RuntimeError(
                    "AUTH TLS command failed".to_string(),
                ));
            }
        }
        "nntp" => {
            // Check server capabilities first
            stream
                .write_all(b"STARTTLS\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS write failed: {e}")))?;
            let n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("STARTTLS response failed: {e}")))?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            // NNTP responds with "382 Continue with TLS negotiation" on success
            if !response.contains("382") {
                return Err(mlua::Error::RuntimeError(
                    "STARTTLS not supported or failed".to_string(),
                ));
            }
        }
        "postgres" | "postgresql" => {
            // PostgreSQL SSLRequest: 8 bytes: [length, 80877103]
            // length = 8, SSLRequest code = 80877103 (0x04D2162F)
            let ssl_request: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];
            stream.write_all(&ssl_request).map_err(|e| {
                mlua::Error::RuntimeError(format!("PostgreSQL SSLRequest failed: {e}"))
            })?;
            let n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("PostgreSQL SSL response failed: {e}"))
            })?;
            // Server responds with 'S' for SSL supported, 'N' for not supported
            if n == 0 || buffer[0] != b'S' {
                return Err(mlua::Error::RuntimeError(
                    "PostgreSQL server does not support SSL".to_string(),
                ));
            }
        }
        "xmpp" => {
            // XMPP STARTTLS via stream:features
            stream
                .write_all(b"<stream:stream xmlns='stream:ns' to='localhost' version='1.0'>\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("XMPP stream open failed: {e}")))?;
            let n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("XMPP stream response failed: {e}"))
            })?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("stream:features") {
                return Err(mlua::Error::RuntimeError(
                    "XMPP stream initialization failed".to_string(),
                ));
            }
            stream
                .write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("XMPP STARTTLS failed: {e}")))?;
            let n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("XMPP STARTTLS response failed: {e}"))
            })?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            if !response.contains("proceed") {
                return Err(mlua::Error::RuntimeError(
                    "XMPP STARTTLS negotiation failed".to_string(),
                ));
            }
        }
        "ldap" => {
            // LDAP STARTTLS via extended operation
            // OID 1.3.6.1.4.1.1466.20037 for startTLS
            // Build LDAP ExtendedRequest packet for startTLS
            // BER-encoded OID for startTLS
            let oid_bytes: [u8; 14] = [
                0x06, 0x0d, // OID tag, length 13
                0x2b, // 1*40 + 3 = 43 = 0x2b
                0x03, // 3
                0x06, // 6
                0x01, // 1
                0x04, // 4
                0x01, // 1
                0x86, 0xba, 0x72, // 1466 (encoded)
                0x86, 0xf5, 0x45, // 20037 (encoded)
            ];

            // LDAPMessage wrapper
            let mut ldap_packet = Vec::new();
            ldap_packet.push(0x60); // [CONTEXT 0] constructed
            ldap_packet.push(0x0f); // length = 15
            ldap_packet.extend_from_slice(&oid_bytes);

            let ldap_packet_len = ldap_packet.len() + 3;
            let complete_packet = vec![
                0x30,                                         // SEQUENCE tag
                u8::try_from(ldap_packet_len).unwrap_or(255), // total length
                0x02,                                         // INTEGER tag
                0x01,                                         // length
                0x01,                                         // messageID = 1
            ];
            let mut complete_packet = complete_packet;
            complete_packet.extend_from_slice(&ldap_packet);

            stream.write_all(&complete_packet).map_err(|e| {
                mlua::Error::RuntimeError(format!("LDAP STARTTLS write failed: {e}"))
            })?;

            let n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("LDAP STARTTLS response failed: {e}"))
            })?;

            if n == 0 || buffer[0] != 0x30 {
                return Err(mlua::Error::RuntimeError(
                    "LDAP server does not support STARTTLS".to_string(),
                ));
            }
        }
        "mysql" => {
            // MySQL STARTTLS - set SSL flag in handshake response
            let n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("MySQL greeting read failed: {e}"))
            })?;

            if n == 0 {
                return Err(mlua::Error::RuntimeError(
                    "MySQL server greeting failed".to_string(),
                ));
            }

            // MySQL handshake response with SSL flag
            let capabilities: u32 = 0x0000_A200; // SSL + PROTOCOL_41 + SECURE_CONNECTION
            let mut ssl_request = Vec::new();

            ssl_request.extend_from_slice(&[0x00, 0x00, 0x01, 0x01, 0x05]);
            ssl_request.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // Max packet size
            ssl_request.push(33); // Charset
            ssl_request.extend_from_slice(&[0u8; 23]); // Reserved
            ssl_request.extend_from_slice(capabilities.to_le_bytes().as_ref());

            stream
                .write_all(&ssl_request)
                .map_err(|e| mlua::Error::RuntimeError(format!("MySQL SSL request failed: {e}")))?;

            let _n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("MySQL SSL response failed: {e}"))
            })?;
        }
        "tds" => {
            // TDS (MS SQL Server) STARTTLS - PreLogin with encryption
            let mut packet = Vec::new();

            // PreLogin option tokens
            packet.extend_from_slice(&[0x00, 0x08, 0x00, 0x06, 0x00]); // Version
            packet.extend_from_slice(&[0x01, 0x0E, 0x00, 0x01, 0x00]); // Encryption
            packet.extend_from_slice(&[0xFF]); // Terminator

            // Header
            let mut header = Vec::new();
            let data_len: u32 = 8 + 4 + 1 + 1;
            header.extend_from_slice(&[
                (data_len & 0xFF) as u8,
                ((data_len >> 8) & 0xFF) as u8,
                ((data_len >> 16) & 0xFF) as u8,
                0x00,
                0x04,
            ]);

            let mut full_packet = Vec::new();
            full_packet.extend_from_slice(&header);
            full_packet.extend_from_slice(&packet);
            full_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Version
            full_packet.push(0x01); // ENCRYPT_ON

            stream
                .write_all(&full_packet)
                .map_err(|e| mlua::Error::RuntimeError(format!("TDS PreLogin failed: {e}")))?;

            let _n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("TDS PreLogin response failed: {e}"))
            })?;
        }
        "vnc" => {
            // VNC VeNCrypt STARTTLS
            stream
                .write_all(b"RFB 003.008\n")
                .map_err(|e| mlua::Error::RuntimeError(format!("VNC version write failed: {e}")))?;

            let _n = stream
                .read(&mut buffer)
                .map_err(|e| mlua::Error::RuntimeError(format!("VNC version read failed: {e}")))?;

            // Send security types - VeNCrypt (19)
            stream.write_all(&[1, 19]).map_err(|e| {
                mlua::Error::RuntimeError(format!("VNC security types failed: {e}"))
            })?;

            let _n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("VNC security response failed: {e}"))
            })?;

            // VeNCrypt handshake
            stream
                .write_all(&[0x01, 0x00]) // Version 1.0
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("VNC VeNCrypt version failed: {e}"))
                })?;

            let _n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("VNC VeNCrypt version response failed: {e}"))
            })?;

            stream
                .write_all(&[0x01, 0x01]) // 1 type, X509None (1)
                .map_err(|e| mlua::Error::RuntimeError(format!("VNC VeNCrypt type failed: {e}")))?;

            let _n = stream.read(&mut buffer).map_err(|e| {
                mlua::Error::RuntimeError(format!("VNC VeNCrypt type response failed: {e}"))
            })?;
        }
        _ => {}
    }

    Ok(())
}
// ---------------------------------------------------------------------------
// SslSocket - Lua UserData wrapper for a TCP stream used after STARTTLS
// ---------------------------------------------------------------------------

/// TCP stream wrapper exposed as Lua `UserData` after STARTTLS negotiation.
///
/// Provides `send`, `receive`, `close`, `set_timeout`, and `get_ssl_certificate`
/// methods that NSE scripts call to interact with the TLS-ready connection.
#[derive(Debug)]
struct SslSocket {
    stream: Option<TcpStream>,
    hostname: String,
    timeout_ms: u64,
}

impl SslSocket {
    fn new(stream: TcpStream, hostname: String) -> Self {
        Self {
            stream: Some(stream),
            hostname,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "UserData impl requires many method registrations with non-trivial bodies"
)]
impl UserData for SslSocket {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // send(data) -> true | nil, err
        methods.add_method_mut("send", |_, this, data: LuaString| {
            let stream = this
                .stream
                .as_mut()
                .ok_or_else(|| mlua::Error::RuntimeError("socket not connected".to_string()))?;
            stream
                .write_all(&data.as_bytes())
                .map_err(|e| mlua::Error::RuntimeError(format!("send failed: {e}")))?;
            Ok(true)
        });

        // receive([pattern]) -> data | nil, err
        //
        // Patterns:
        //   "*l"  - read one line (up to and including \n)
        //   "*a"  - read until EOF / timeout
        //   <integer> - read exactly N bytes
        //   nil   - default read up to 4096 bytes
        methods.add_method_mut("receive", |lua, this, pattern: Option<Value>| {
            let stream = this
                .stream
                .as_mut()
                .ok_or_else(|| mlua::Error::RuntimeError("socket not connected".to_string()))?;

            match pattern {
                // "*l" - read until newline
                Some(Value::String(s)) if s.to_str()? == "*l" => {
                    let mut buf = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                buf.push(byte[0]);
                                if byte[0] == b'\n' {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(lua.create_string(&buf)?)
                }
                // "*a" - read all available data
                Some(Value::String(s)) if s.to_str()? == "*a" => {
                    let mut buf = Vec::new();
                    loop {
                        let mut temp = [0u8; MAX_RECEIVE_BYTES];
                        match stream.read(&mut temp) {
                            Ok(0) => break,
                            Ok(n) => buf.extend_from_slice(&temp[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    Ok(lua.create_string(&buf)?)
                }
                // Integer count - read exactly N bytes
                Some(Value::Integer(n)) => {
                    let count = usize::try_from(n).map_err(|e| {
                        mlua::Error::RuntimeError(format!("invalid byte count: {e}"))
                    })?;
                    let mut buf = vec![0u8; count];
                    stream
                        .read_exact(&mut buf)
                        .map_err(|e| mlua::Error::RuntimeError(format!("receive failed: {e}")))?;
                    Ok(lua.create_string(&buf)?)
                }
                // Default / unhandled pattern - single read
                _ => {
                    let mut buf = [0u8; MAX_RECEIVE_BYTES];
                    match stream.read(&mut buf) {
                        Ok(0) => Ok(lua.create_string("")?),
                        Ok(n) => Ok(lua.create_string(&buf[..n])?),
                        Err(e) => Err(mlua::Error::RuntimeError(format!("receive failed: {e}"))),
                    }
                }
            }
        });

        // close() -> true
        methods.add_method_mut("close", |_, this, ()| {
            if let Some(stream) = this.stream.take() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            Ok(true)
        });

        // set_timeout(ms) -> true
        methods.add_method_mut("set_timeout", |_, this, ms: u64| {
            this.timeout_ms = ms;
            if let Some(ref mut stream) = this.stream {
                let timeout = Duration::from_millis(ms);
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|e| mlua::Error::RuntimeError(format!("set_timeout failed: {e}")))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|e| mlua::Error::RuntimeError(format!("set_timeout failed: {e}")))?;
            }
            Ok(true)
        });

        // get_ssl_certificate() -> cert_table
        //
        // Creates a new TLS connection to the same peer and retrieves the certificate.
        // This matches nmap behavior of reconnecting for cert retrieval.
        methods.add_method_mut("get_ssl_certificate", |lua, this, ()| {
            let stream = this
                .stream
                .as_ref()
                .ok_or_else(|| mlua::Error::RuntimeError("socket not connected".to_string()))?;

            let peer_addr = stream.peer_addr().map_err(|e| {
                mlua::Error::RuntimeError(format!("Failed to get peer address: {e}"))
            })?;

            // Use hostname for SNI, but fall back to IP if hostname is empty
            let hostname = if this.hostname.is_empty() {
                peer_addr.ip().to_string()
            } else {
                this.hostname.clone()
            };
            let cert_der = tls_connect_and_get_cert(&hostname, peer_addr)?;

            let table = lua.create_table()?;
            table.set("pem", der_to_pem(&cert_der))?;
            table.set(
                "subject",
                extract_dn_field(&cert_der).unwrap_or_else(|| "Unknown".to_string()),
            )?;
            table.set("issuer", "Unknown".to_string())?;
            table.set("serial", extract_serial(&cert_der))?;
            table.set("fingerprint", calculate_fingerprint(&cert_der))?;

            let pubkey = lua.create_table()?;
            pubkey.set("type", "RSA")?;
            pubkey.set("bits", 2048)?;
            table.set("pubkey", pubkey)?;

            let (notbefore, notafter) = extract_validity(&cert_der);
            table.set("notbefore", notbefore)?;
            table.set("notafter", notafter)?;
            table.set("version", 3)?;

            Ok(Value::Table(table))
        });
    }
}

// ---------------------------------------------------------------------------
// Port classification helpers
// ---------------------------------------------------------------------------

/// Check if a Lua port value indicates UDP protocol.
fn is_port_udp(port: &Value) -> bool {
    if let Value::Table(t) = port {
        t.get::<Option<String>>("protocol")
            .ok()
            .flatten()
            .is_some_and(|p| p == "udp")
    } else {
        false
    }
}

/// Check if a Lua port table has `version.service_tunnel == "ssl"`.
fn has_ssl_tunnel(port: &Value) -> bool {
    let Value::Table(t) = port else {
        return false;
    };
    let Ok(version) = t.get::<Table>("version") else {
        return false;
    };
    let Ok(tunnel) = version.get::<String>("service_tunnel") else {
        return false;
    };
    tunnel == "ssl"
}

/// Extract `(service, port_number)` from a Lua port value.
fn extract_port_info(port: &Value) -> (String, i64) {
    match port {
        Value::Table(t) => (
            t.get::<String>("service").ok().unwrap_or_default(),
            t.get::<i64>("number").ok().unwrap_or(443),
        ),
        Value::Integer(n) => (String::new(), *n),
        _ => (String::new(), 443),
    }
}

/// Check if a port number is a known direct-TLS port.
fn is_direct_tls_port(port_number: i64) -> bool {
    DIRECT_TLS_PORTS.contains(&u16::try_from(port_number).unwrap_or(0))
}

/// Check if a service name or port number is a known STARTTLS target.
fn is_starttls_service(service: &str, port_number: i64) -> bool {
    STARTTLS_SERVICES.contains(&service)
        || STARTTLS_PORTS.contains(&u16::try_from(port_number).unwrap_or(0))
}

/// Extract `(host_ip, targetname)` from a Lua host value.
fn extract_host_info(host: &Value) -> (String, String) {
    let host_str = match host {
        Value::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        Value::Table(t) => t
            .get::<Option<String>>("ip")
            .ok()
            .flatten()
            .unwrap_or_default(),
        _ => String::new(),
    };
    let targetname = match host {
        Value::Table(t) => t
            .get::<Option<String>>("targetname")
            .ok()
            .flatten()
            .unwrap_or_else(|| host_str.clone()),
        _ => host_str.clone(),
    };
    (host_str, targetname)
}

/// Extract port number from a Lua port value.
fn extract_port_number(port: &Value) -> u16 {
    match port {
        Value::Table(t) => u16::try_from(t.get::<i64>("number").ok().unwrap_or(443)).unwrap_or(443),
        Value::Integer(n) => u16::try_from(*n).unwrap_or(443),
        _ => 443,
    }
}

/// Extract service name from a Lua port value.
fn extract_port_service(port: &Value) -> String {
    match port {
        Value::Table(t) => t.get::<String>("service").ok().unwrap_or_default(),
        _ => String::new(),
    }
}

/// Register the sslcert library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
#[expect(
    clippy::too_many_lines,
    reason = "Lua library registration requires inline closures that cannot be factored out"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the sslcert table
    let sslcert_table = lua.create_table()?;

    // Register getCertificate function
    let get_cert_fn = lua.create_function(
        |lua, (host, port, options): (Value, Value, Option<Table>)| {
            let (host_str, port_num) = extract_host_port(host, port);

            let protocol = options
                .as_ref()
                .and_then(|t| t.get::<Option<String>>("protocol").ok().flatten());

            debug!(
                "sslcert.getCertificate({}, {}, protocol={:?})",
                host_str, port_num, protocol
            );

            // Resolve address
            let addr_str = format!("{host_str}:{port_num}");
            let socket_addr: std::net::SocketAddr = addr_str
                .to_socket_addrs()
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("DNS resolution failed for {addr_str}: {e}"))
                })?
                .next()
                .ok_or_else(|| mlua::Error::RuntimeError(format!("Cannot resolve {addr_str}")))?;

            // Get certificate DER via proper TLS handshake
            let cert_der = if let Some(proto) = protocol {
                starttls_and_get_cert(&host_str, socket_addr, proto.as_str())?
            } else {
                tls_connect_and_get_cert(&host_str, socket_addr)?
            };

            // Parse certificate using OpenSSL for full field extraction
            let cert = openssl::x509::X509::from_der(&cert_der).map_err(|e| {
                mlua::Error::RuntimeError(format!("Failed to parse certificate: {e}"))
            })?;

            // Build certificate table using the same structure as nmap.rs cert_to_table
            let table = lua.create_table()?;

            // PEM encoding
            let pem = cert
                .to_pem()
                .map_err(|e| mlua::Error::RuntimeError(format!("Failed to encode PEM: {e}")))?;
            table.set("pem", String::from_utf8_lossy(&pem).as_ref())?;

            // Subject
            let subject = cert.subject_name();
            let subject_table = lua.create_table()?;
            for entry in subject.entries() {
                let key = entry
                    .object()
                    .nid()
                    .long_name()
                    .unwrap_or("unknown")
                    .to_string();
                let value = entry
                    .data()
                    .as_utf8()
                    .map_or_else(|_| "unknown".to_string(), |s| s.to_string());
                subject_table.set(key.as_str(), value.as_str())?;
            }
            table.set("subject", subject_table)?;

            // Issuer
            let issuer = cert.issuer_name();
            let issuer_table = lua.create_table()?;
            for entry in issuer.entries() {
                let key = entry
                    .object()
                    .nid()
                    .long_name()
                    .unwrap_or("unknown")
                    .to_string();
                let value = entry
                    .data()
                    .as_utf8()
                    .map_or_else(|_| "unknown".to_string(), |s| s.to_string());
                issuer_table.set(key.as_str(), value.as_str())?;
            }
            table.set("issuer", issuer_table)?;

            // Serial number
            let serial_hex = cert
                .serial_number()
                .to_bn()
                .and_then(|bn| bn.to_hex_str())
                .map_or_else(|_| "unknown".to_string(), |s| s.to_string());
            table.set("serial", serial_hex.as_str())?;

            // Validity - pass numeric Unix timestamps so ssl-cert.nse can
            // format them via datetime.format_timestamp
            let validity_table = lua.create_table()?;
            validity_table.set("notBefore", asn1_time_to_unix(cert.not_before()))?;
            validity_table.set("notAfter", asn1_time_to_unix(cert.not_after()))?;
            table.set("validity", validity_table)?;

            // Signature algorithm
            let sig_alg = cert
                .signature_algorithm()
                .object()
                .nid()
                .long_name()
                .unwrap_or("unknown")
                .to_string();
            table.set("sig_algorithm", sig_alg.as_str())?;

            // Public key
            let pkey = cert
                .public_key()
                .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get public key: {e}")))?;
            let pubkey_table = lua.create_table()?;
            let key_type = match pkey.id() {
                openssl::pkey::Id::RSA => "rsa",
                openssl::pkey::Id::DSA => "dsa",
                openssl::pkey::Id::DH => "dh",
                openssl::pkey::Id::EC => "ec",
                _ => "unknown",
            };
            pubkey_table.set("type", key_type)?;
            pubkey_table.set("bits", pkey.bits())?;

            // RSA-specific fields
            if pkey.id() == openssl::pkey::Id::RSA {
                let rsa = pkey.rsa().map_err(|e| {
                    mlua::Error::RuntimeError(format!("Failed to get RSA key: {e}"))
                })?;
                let exponent_bytes = rsa.e().to_vec();
                pubkey_table.set("exponent", hex::encode(&exponent_bytes))?;
                let modulus_bytes = rsa.n().to_vec();
                pubkey_table.set("modulus", hex::encode(&modulus_bytes))?;
            }

            // EC-specific fields: add ecdhparams with curve info
            if pkey.id() == openssl::pkey::Id::EC {
                let ec_key = pkey
                    .ec_key()
                    .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get EC key: {e}")))?;
                let ecdhparams = lua.create_table()?;
                let curve_params = lua.create_table()?;

                let group = ec_key.group();
                curve_params.set("ec_curve_type", "namedcurve")?;
                let curve_name = group.curve_name().map_or_else(
                    || "unknown".to_string(),
                    |nid| nid.long_name().unwrap_or("unknown").to_string(),
                );
                curve_params.set("curve", curve_name.as_str())?;
                ecdhparams.set("curve_params", curve_params)?;
                pubkey_table.set("ecdhparams", ecdhparams)?;
            }
            table.set("pubkey", pubkey_table)?;

            // Extensions
            let extensions_table = lua.create_table()?;
            if let Some(san) = cert.subject_alt_names() {
                let ext_table = lua.create_table()?;
                ext_table.set("name", "X509v3 Subject Alternative Name")?;
                let san_values: Vec<String> = san
                    .iter()
                    .filter_map(|name| {
                        name.dnsname()
                            .map(|dns| format!("DNS:{dns}"))
                            .or_else(|| name.ipaddress().map(|ip| format!("IP:{ip:?}")))
                    })
                    .collect();
                ext_table.set("value", san_values.join(", "))?;
                extensions_table.set(1, ext_table)?;
            }
            table.set("extensions", extensions_table)?;

            // Add digest function
            let cert_clone = cert.clone();
            let digest_fn =
                lua.create_function(move |lua, (_self, algo): (mlua::Table, String)| {
                    use openssl::hash::MessageDigest;

                    let message_digest = match algo.to_lowercase().as_str() {
                        "md5" => MessageDigest::md5(),
                        "sha1" => MessageDigest::sha1(),
                        "sha256" => MessageDigest::sha256(),
                        _ => {
                            return Err(mlua::Error::RuntimeError(format!(
                                "Unknown digest algorithm: {algo}"
                            )))
                        }
                    };

                    match cert_clone.digest(message_digest) {
                        Ok(digest_bytes) => {
                            Ok(mlua::Value::String(lua.create_string(digest_bytes)?))
                        }
                        Err(e) => Err(mlua::Error::RuntimeError(format!(
                            "Digest calculation failed: {e}"
                        ))),
                    }
                })?;
            table.set("digest", digest_fn)?;

            table.set("version", 3)?;

            // Fingerprint (SHA-256 of DER)
            let fingerprint = {
                use sha2::Digest as Sha256Digest;
                let mut hasher = Sha256::new();
                hasher.update(&cert_der);
                let result = hasher.finalize();
                result
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            table.set("fingerprint", fingerprint.as_str())?;

            Ok((true, Value::Table(table)))
        },
    )?;
    sslcert_table.set("getCertificate", get_cert_fn)?;

    // Register parse_ssl_certificate function
    let parse_cert_fn = lua.create_function(|lua, der_data: LuaString| {
        let der_bytes = der_data.as_bytes();

        let cert = openssl::x509::X509::from_der(&der_bytes)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to parse certificate: {e}")))?;

        let cert_table = build_cert_table(lua, &cert)?;

        Ok(Value::Table(cert_table))
    })?;
    sslcert_table.set("parse_ssl_certificate", parse_cert_fn)?;

    // -------------------------------------------------------------------------
    // sslcert.getPrepareTLSWithoutReconnect(port)
    //
    // Returns:
    //   nil  - if the port is a direct TLS port (443, 993, ...) or UDP or
    //          already has an SSL tunnel. The script should use
    //          `nmap.new_socket()` + connect directly.
    //   function(host, port) -> (true, socket) | (false, err)
    //        - if the port supports STARTTLS. The returned function connects,
    //          performs STARTTLS negotiation, and returns a `SslSocket` userdata
    //          with send/receive/close/set_timeout/get_ssl_certificate methods.
    // -------------------------------------------------------------------------
    let get_prepare_tls_fn = lua.create_function(|lua, port: Value| {
        // Skip UDP ports entirely
        if is_port_udp(&port) {
            return Ok(Value::Nil);
        }
        // Skip ports that already have an SSL tunnel
        if has_ssl_tunnel(&port) {
            return Ok(Value::Nil);
        }

        let (service, port_number) = extract_port_info(&port);

        // Direct TLS ports do not need STARTTLS
        if is_direct_tls_port(port_number) {
            return Ok(Value::Nil);
        }

        // Only return a function for known STARTTLS services/ports
        if !is_starttls_service(&service, port_number) {
            return Ok(Value::Nil);
        }

        // Create the STARTTLS helper function.
        // It captures nothing from this scope (all state comes from its args).
        let starttls_fn = lua.create_function(move |lua, (host, port): (Value, Value)| {
            let (host_str, targetname) = extract_host_info(&host);
            let port_num = extract_port_number(&port);
            let service_name = extract_port_service(&port);

            debug!(
                "sslcert.getPrepareTLSWithoutReconnect: connecting to \
                         {host_str}:{port_num} (service={service_name})"
            );

            let addr = format!("{host_str}:{port_num}");
            let mut stream = TcpStream::connect(&addr).map_err(|e| {
                mlua::Error::RuntimeError(format!("STARTTLS connect failed to {addr}: {e}"))
            })?;

            let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
            stream.set_read_timeout(Some(timeout)).map_err(|e| {
                mlua::Error::RuntimeError(format!("Failed to set read timeout: {e}"))
            })?;
            stream.set_write_timeout(Some(timeout)).map_err(|e| {
                mlua::Error::RuntimeError(format!("Failed to set write timeout: {e}"))
            })?;

            // Perform STARTTLS handshake for the detected protocol
            perform_starttls(&mut stream, &service_name)?;

            let socket = SslSocket::new(stream, targetname.clone());
            let socket_ud = lua.create_userdata(socket)?;

            debug!(
                "sslcert.getPrepareTLSWithoutReconnect: STARTTLS done for \
                         {host_str}:{port_num}"
            );

            Ok((true, Value::UserData(socket_ud)))
        })?;

        Ok(Value::Function(starttls_fn))
    })?;
    sslcert_table.set("getPrepareTLSWithoutReconnect", get_prepare_tls_fn)?;

    // -------------------------------------------------------------------------
    // sslcert.isPortSupported(port)
    //
    // Returns:
    //   true  - if the port supports TLS (direct TLS or STARTTLS)
    //   nil   - if the port does not support TLS (UDP, unknown service/port)
    // -------------------------------------------------------------------------
    let is_port_supported_fn = lua.create_function(|_lua, port: Value| {
        // UDP ports are never TLS-supported
        if is_port_udp(&port) {
            return Ok(Value::Nil);
        }

        // Ports with an existing SSL tunnel are supported
        if has_ssl_tunnel(&port) {
            return Ok(Value::Boolean(true));
        }

        let (service, port_number) = extract_port_info(&port);

        let supported =
            is_starttls_service(&service, port_number) || is_direct_tls_port(port_number);

        if supported {
            Ok(Value::Boolean(true))
        } else {
            Ok(Value::Nil)
        }
    })?;
    sslcert_table.set("isPortSupported", is_port_supported_fn)?;

    // Register the sslcert library globally
    lua.globals().set("sslcert", sslcert_table)?;

    Ok(())
}

/// Build a full certificate Lua table from a parsed X509 certificate.
///
/// This creates a table with the same structure as `cert_to_table` in `nmap.rs`,
/// including subject, issuer, serial, fingerprint, pubkey (with ecdhparams for EC),
/// validity dates, extensions, and digest function.
#[cfg(feature = "openssl")]
#[expect(
    clippy::too_many_lines,
    reason = "Certificate table construction requires inline field extraction"
)]
pub(crate) fn build_cert_table(
    lua: &mlua::Lua,
    cert: &openssl::x509::X509,
) -> mlua::Result<mlua::Table> {
    use openssl::hash::MessageDigest;

    let cert_table = lua.create_table()?;

    // PEM encoding
    let pem = cert
        .to_pem()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to encode PEM: {e}")))?;
    let pem_str = String::from_utf8_lossy(&pem);
    cert_table.set("pem", pem_str.as_ref())?;

    // Subject
    let subject = cert.subject_name();
    let subject_table = x509_name_to_table(lua, subject)?;
    cert_table.set("subject", subject_table)?;

    // Issuer
    let issuer = cert.issuer_name();
    let issuer_table = x509_name_to_table(lua, issuer)?;
    cert_table.set("issuer", issuer_table)?;

    // Validity
    let validity_table = lua.create_table()?;
    let not_before = cert.not_before();
    let not_after = cert.not_after();
    validity_table.set("notBefore", asn1_time_to_unix(not_before))?;
    validity_table.set("notAfter", asn1_time_to_unix(not_after))?;
    cert_table.set("validity", validity_table)?;

    // Serial number
    let serial_hex = cert
        .serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map_or_else(|_| "unknown".to_string(), |s| s.to_string());
    cert_table.set("serialNumber", serial_hex.as_str())?;

    // Version
    cert_table.set("version", i64::from(cert.version()))?;

    // Signature algorithm
    let sig_alg = cert.signature_algorithm();
    let algo = sig_alg.object();
    cert_table.set("sig_algorithm", algo.nid().long_name().unwrap_or("unknown"))?;

    // Public key
    let pubkey_table = lua.create_table()?;
    let pkey = cert
        .public_key()
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get public key: {e}")))?;

    let key_type = match pkey.id() {
        openssl::pkey::Id::RSA => "rsa",
        openssl::pkey::Id::DSA => "dsa",
        openssl::pkey::Id::DH => "dh",
        openssl::pkey::Id::EC => "ec",
        _ => "unknown",
    };
    pubkey_table.set("type", key_type)?;
    pubkey_table.set("bits", pkey.bits())?;

    // RSA-specific fields
    if pkey.id() == openssl::pkey::Id::RSA {
        let rsa = pkey
            .rsa()
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get RSA key: {e}")))?;
        let e = rsa.e();
        let exponent_bytes = e.to_vec();
        let exponent_hex = hex::encode(&exponent_bytes);
        pubkey_table.set("exponent", exponent_hex)?;

        let n = rsa.n();
        let modulus_bytes = n.to_vec();
        let modulus_hex = hex::encode(&modulus_bytes);
        pubkey_table.set("modulus", modulus_hex)?;
    }

    // EC key type: add ecdhparams with curve info
    if pkey.id() == openssl::pkey::Id::EC {
        let ec_key = pkey
            .ec_key()
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to get EC key: {e}")))?;
        let ecdhparams = lua.create_table()?;
        let curve_params = lua.create_table()?;

        let group = ec_key.group();
        curve_params.set("ec_curve_type", "namedcurve")?;
        let curve_name = group.curve_name().map_or_else(
            || "unknown".to_string(),
            |nid| nid.long_name().unwrap_or("unknown").to_string(),
        );
        curve_params.set("curve", curve_name)?;
        ecdhparams.set("curve_params", curve_params)?;
        pubkey_table.set("ecdhparams", ecdhparams)?;
    }
    cert_table.set("pubkey", pubkey_table)?;

    // Extensions
    let extensions_table = lua.create_table()?;
    if let Some(san) = cert.subject_alt_names() {
        let san_values: Vec<String> = san
            .iter()
            .filter_map(|name| {
                name.dnsname()
                    .map(|dns| format!("DNS:{dns}"))
                    .or_else(|| name.ipaddress().map(|ip| format!("IP:{ip:?}")))
            })
            .collect();
        if !san_values.is_empty() {
            let ext_table = lua.create_table()?;
            ext_table.set("name", "X509v3 Subject Alternative Name")?;
            ext_table.set("value", san_values.join(", "))?;
            extensions_table.set(1, ext_table)?;
        }
    }
    cert_table.set("extensions", extensions_table)?;

    // Digest function
    let cert_clone = cert.clone();
    let digest_fn = lua.create_function(move |lua, (_self, algo): (mlua::Table, String)| {
        let message_digest = match algo.to_lowercase().as_str() {
            "md5" => MessageDigest::md5(),
            "sha1" => MessageDigest::sha1(),
            "sha256" => MessageDigest::sha256(),
            _ => {
                return Err(mlua::Error::RuntimeError(format!(
                    "Unknown digest algorithm: {algo}"
                )))
            }
        };

        match cert_clone.digest(message_digest) {
            Ok(digest_bytes) => Ok(mlua::Value::String(lua.create_string(digest_bytes)?)),
            Err(e) => Err(mlua::Error::RuntimeError(format!(
                "Digest calculation failed: {e}"
            ))),
        }
    })?;
    cert_table.set("digest", digest_fn)?;

    // Fingerprint (SHA-256 of DER)
    let der_bytes = cert.to_der().unwrap_or_default();
    let fingerprint = calculate_fingerprint(&der_bytes);
    cert_table.set("fingerprint", fingerprint.as_str())?;

    Ok(cert_table)
}

/// Convert X509 name entries to a Lua table.
#[cfg(feature = "openssl")]
pub(crate) fn x509_name_to_table(
    lua: &mlua::Lua,
    name: &openssl::x509::X509NameRef,
) -> mlua::Result<mlua::Table> {
    let table = lua.create_table()?;

    for entry in name.entries() {
        let obj = entry.object();
        let data = entry.data();

        let key = if obj.nid() == openssl::nid::Nid::UNDEF {
            format!("{obj:?}")
        } else {
            openssl::nid::Nid::from_raw(obj.nid().as_raw())
                .long_name()
                .unwrap_or("unknown")
                .to_string()
        };

        let value = data
            .as_utf8()
            .map_or_else(|_| format!("{data:?}"), |s| s.to_string());

        table.set(key, value)?;
    }

    Ok(table)
}

/// Convert `ASN1_TIME` to Unix epoch seconds.
///
/// Nmap stores certificate validity dates as numeric timestamps that
/// `ssl-cert.nse` passes to `datetime.format_timestamp`. The `ASN1_TIME`
/// `Display` implementation produces strings like `"Mar  6 00:00:00 2026 GMT"`
/// which we parse back into a Unix timestamp.
#[cfg(feature = "openssl")]
pub(crate) fn asn1_time_to_unix(time: &openssl::asn1::Asn1TimeRef) -> i64 {
    // Cumulative days per month (non-leap year)
    const MONTH_DAYS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    // Parse the Display output: "Mon DD HH:MM:SS YYYY GMT"
    let s = time.to_string();
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 5 {
        return 0;
    }

    // parts: ["Mar", "6", "00:00:00", "2026", "GMT"]
    let month_num: i64 = match parts[0] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return 0,
    };

    let day: i64 = parts[1].trim_end_matches(',').parse().unwrap_or(1);

    let time_parts: Vec<&str> = parts[2].split(':').collect();
    let hour: i64 = time_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minute: i64 = time_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let second: i64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let year: i64 = parts[3].parse().unwrap_or(1970);

    // Compute Unix timestamp using calendar math (no chrono dependency needed)
    // Days from 1970-01-01 to start of given year
    let y = year - 1;
    let days_from_years =
        y * 365 + y / 4 - y / 100 + y / 400 - (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400);

    // Days from month within the year
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_from_months = MONTH_DAYS
        .get(usize::try_from(month_num).map_or(0, |m| m.saturating_sub(1)))
        .copied()
        .unwrap_or(0)
        + i64::from(is_leap && month_num > 2);

    let total_days = days_from_years + days_from_months + day - 1;
    total_days * 86_400 + hour * 3600 + minute * 60 + second
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let input = b"hello";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_der_to_pem() {
        let der = b"test certificate data";
        let pem = der_to_pem(der);

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_calculate_fingerprint() {
        let data = b"test data";
        let fp = calculate_fingerprint(data);

        assert!(fp.contains(':'));
    }
}
