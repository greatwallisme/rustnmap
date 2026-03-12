//! DNS library for NSE.
//!
//! This module provides the `dns` library which contains DNS protocol functions
//! for NSE scripts. It corresponds to Nmap's dns NSE library.
//!
//! # Available Functions
//!
//! - `dns.query(domain, [options])` - Perform DNS query
//! - `dns.reverse(ip)` - Perform reverse DNS lookup
//!
//! # DNS Record Type Constants
//!
//! The library provides these constants for record types:
//! - `dns.TYPE_A` = 1 (IPv4 address)
//! - `dns.TYPE_NS` = 2 (Name server)
//! - `dns.TYPE_CNAME` = 5 (Canonical name)
//! - `dns.TYPE_SOA` = 6 (Start of authority)
//! - `dns.TYPE_PTR` = 12 (Pointer record)
//! - `dns.TYPE_MX` = 15 (Mail exchange)
//! - `dns.TYPE_TXT` = 16 (Text record)
//! - `dns.TYPE_AAAA` = 28 (IPv6 address)
//! - `dns.TYPE_SRV` = 33 (Service record)
//! - `dns.TYPE_ANY` = 255 (Any record)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local dns = require "dns"
//!
//! -- Query A record
//! local records = dns.query("example.com", {dtype = dns.TYPE_A})
//! if records then
//!     for _, record in ipairs(records) do
//!         print("IP: " .. record.data)
//!     end
//! end
//!
//! -- Reverse lookup
//! local hostname = dns.reverse("8.8.8.8")
//! if hostname then
//!     print("Hostname: " .. hostname)
//! end
//! ```

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use mlua::{Table, Value};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default DNS server port.
const DNS_PORT: u16 = 53;

/// Default timeout for DNS queries in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Build a DNS query packet.
fn build_query(domain: &str, qtype: u16, txn_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header (12 bytes)
    packet.extend_from_slice(&txn_id.to_be_bytes()); // Transaction ID
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: recursion desired
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional: 0

    // Question section
    for label in domain.split('.') {
        let label_len = u8::try_from(label.len()).unwrap_or(63); // Max DNS label is 63
        packet.push(label_len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of domain

    packet.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

    packet
}

/// Parse DNS header from response.
fn parse_header(data: &[u8]) -> std::io::Result<(u16, u8, u16, u16, usize)> {
    if data.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS response too short",
        ));
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let rcode = data[3] & 0x0F;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);

    Ok((id, rcode, qdcount, ancount, 12))
}

/// Skip a domain name in DNS packet.
fn skip_name(data: &[u8], offset: usize) -> usize {
    let mut pos = offset;
    loop {
        if pos >= data.len() {
            return pos;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            return pos + 2;
        }
        pos += len + 1;
    }
}

/// Parse resource record from DNS response.
fn parse_rr(data: &[u8], offset: usize) -> std::io::Result<(String, u16, u32, Vec<u8>, usize)> {
    let name_end = skip_name(data, offset);
    if name_end + 10 > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RR truncated",
        ));
    }

    let rtype = u16::from_be_bytes([data[name_end], data[name_end + 1]]);
    // let rclass = u16::from_be_bytes([data[name_end + 2], data[name_end + 3]]);
    let ttl = u32::from_be_bytes([
        data[name_end + 4],
        data[name_end + 5],
        data[name_end + 6],
        data[name_end + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[name_end + 8], data[name_end + 9]]) as usize;

    let rdata_start = name_end + 10;
    if rdata_start + rdlength > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "RDATA truncated",
        ));
    }

    let rdata = data[rdata_start..rdata_start + rdlength].to_vec();

    Ok((String::new(), rtype, ttl, rdata, rdata_start + rdlength))
}

/// Perform DNS query over UDP.
fn dns_query_impl(domain: &str, qtype: u16, dns_server: &str, timeout_ms: u64) -> std::io::Result<Vec<u8>> {
    let txn_id = rand::random::<u16>();
    let query = build_query(domain, qtype, txn_id);

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let server_addr = format!("{dns_server}:{DNS_PORT}");
    socket.send_to(&query, &server_addr)?;

    let mut response = vec![0u8; 4096];
    let (len, _) = socket.recv_from(&mut response)?;
    response.truncate(len);

    // Verify transaction ID matches
    if response.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Response too short",
        ));
    }

    let resp_id = u16::from_be_bytes([response[0], response[1]]);
    if resp_id != txn_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Transaction ID mismatch",
        ));
    }

    Ok(response)
}

/// Format DNS record data based on type.
fn format_rdata(rtype: u16, rdata: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => {
            format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
        }
        28 if rdata.len() == 16 => rdata
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.join(":"))
            .collect::<Vec<_>>()
            .join("::"),
        _ => String::from_utf8_lossy(rdata).to_string(),
    }
}

/// Build PTR domain from IPv4 address.
fn build_ptr_domain(ip: &str) -> Option<String> {
    let ipv4 = ip.parse::<Ipv4Addr>().ok()?;
    let octets = ipv4.octets();
    Some(format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    ))
}

/// Register the dns library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the dns table
    let dns_table = lua.create_table()?;

    // Register constants
    dns_table.set("TYPE_A", 1i64)?;
    dns_table.set("TYPE_NS", 2i64)?;
    dns_table.set("TYPE_CNAME", 5i64)?;
    dns_table.set("TYPE_SOA", 6i64)?;
    dns_table.set("TYPE_PTR", 12i64)?;
    dns_table.set("TYPE_MX", 15i64)?;
    dns_table.set("TYPE_TXT", 16i64)?;
    dns_table.set("TYPE_AAAA", 28i64)?;
    dns_table.set("TYPE_SRV", 33i64)?;
    dns_table.set("TYPE_ANY", 255i64)?;

    // Register query function
    let query_fn = lua.create_function(|lua, (domain, options): (String, Option<Table>)| {
        debug!("dns.query({})", domain);

        // Parse options
        let dtype: u16 = options
            .as_ref()
            .and_then(|t| t.get::<Option<i64>>("dtype").ok().flatten())
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(1);

        let timeout: u64 = options
            .as_ref()
            .and_then(|t| t.get::<Option<u64>>("timeout").ok().flatten())
            .unwrap_or(DEFAULT_TIMEOUT_MS);

        let dns_server: String = options
            .as_ref()
            .and_then(|t| t.get::<Option<String>>("host").ok().flatten())
            .unwrap_or_else(|| "8.8.8.8".to_string());

        // Perform query
        match dns_query_impl(&domain, dtype, &dns_server, timeout) {
            Ok(response) => {
                // Parse response
                match parse_header(&response) {
                    Ok((_id, rcode, _qdcount, ancount, header_end)) => {
                        if rcode != 0 {
                            return Ok(Value::Nil);
                        }

                        let results = lua.create_table()?;
                        let mut offset = header_end;

                        // Skip question section
                        for _ in 0..1 {
                            offset = skip_name(&response, offset);
                            offset += 4; // QTYPE + QCLASS
                        }

                        // Parse answers
                        for i in 0..ancount {
                            match parse_rr(&response, offset) {
                                Ok((_name, rtype, ttl, rdata, new_offset)) => {
                                    offset = new_offset;

                                    let record = lua.create_table()?;
                                    record.set("type", i64::from(rtype))?;
                                    record.set("ttl", i64::from(ttl))?;
                                    record.set("data", format_rdata(rtype, &rdata))?;

                                    results.set(i64::from(i + 1), record)?;
                                }
                                Err(_) => break,
                            }
                        }

                        Ok(Value::Table(results))
                    }
                    Err(_) => Ok(Value::Nil),
                }
            }
            Err(_) => Ok(Value::Nil),
        }
    })?;
    dns_table.set("query", query_fn)?;

    // Register reverse function
    let reverse_fn = lua.create_function(|lua, ip: String| {
        debug!("dns.reverse({})", ip);

        // Build PTR domain from IP
        let Some(ptr_domain) = build_ptr_domain(&ip) else {
            return Ok(Value::Nil);
        };

        // Query PTR record
        match dns_query_impl(&ptr_domain, 12, "8.8.8.8", DEFAULT_TIMEOUT_MS) {
            Ok(response) => {
                match parse_header(&response) {
                    Ok((_id, rcode, _qdcount, ancount, header_end)) => {
                        if rcode != 0 || ancount == 0 {
                            return Ok(Value::Nil);
                        }

                        let mut offset = header_end;

                        // Skip question section
                        offset = skip_name(&response, offset);
                        offset += 4;

                        // Parse first answer
                        match parse_rr(&response, offset) {
                            Ok((_name, _rtype, _ttl, rdata, _new_offset)) => {
                                // PTR record data is a domain name
                                let hostname = parse_domain_name(&response, &rdata);
                                Ok(Value::String(lua.create_string(&hostname)?))
                            }
                            Err(_) => Ok(Value::Nil),
                        }
                    }
                    Err(_) => Ok(Value::Nil),
                }
            }
            Err(_) => Ok(Value::Nil),
        }
    })?;
    dns_table.set("reverse", reverse_fn)?;

    // Register the dns library globally
    lua.globals().set("dns", dns_table)?;

    Ok(())
}

/// Parse a domain name from DNS packet data.
fn parse_domain_name(data: &[u8], rdata: &[u8]) -> String {
    let mut name = String::new();
    let mut pos = 0;

    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer - resolve from original data
            if pos + 1 < rdata.len() {
                let ptr_offset = (((rdata[pos] as usize) & 0x3F) << 8) | (rdata[pos + 1] as usize);
                if ptr_offset < data.len() {
                    return parse_domain_name(data, &data[ptr_offset..]);
                }
            }
            break;
        }
        if pos + len + 1 > rdata.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&rdata[pos + 1..pos + 1 + len]));
        pos += len + 1;
    }

    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query() {
        let packet = build_query("example.com", 1, 0x1234);
        assert!(!packet.is_empty());
        assert_eq!(packet[0], 0x12);
        assert_eq!(packet[1], 0x34);
    }

    #[test]
    fn test_parse_header() {
        let data = [
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags: QR, RD, RA
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];

        let (id, rcode, qdcount, ancount, offset) = parse_header(&data).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(rcode, 0);
        assert_eq!(qdcount, 1);
        assert_eq!(ancount, 1);
        assert_eq!(offset, 12);
    }

    #[test]
    fn test_skip_name() {
        let data = b"\x07example\x03com\x00rest";
        let end = skip_name(data, 0);
        assert_eq!(end, 13);
    }
}
