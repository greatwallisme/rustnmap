//! HTTP library for NSE.
//!
//! This module provides the `http` library which contains HTTP protocol functions
//! for NSE scripts. It corresponds to Nmap's http NSE library.
//!
//! # Available Functions
//!
//! - `http.get(host, port, path, [options])` - Perform HTTP GET request
//! - `http.post(host, port, path, [options], [ignored], [postdata])` - Perform HTTP POST request
//! - `http.head(host, port, path, [options])` - Perform HTTP HEAD request
//! - `http.generic_request(host, port, method, path, [options], [ignored], [body])` - Generic HTTP request
//! - `http.get_url(url, [options])` - Fetch URL directly
//!
//! # Response Table Structure
//!
//! The HTTP functions return a response table with:
//! - `status` - HTTP status code (e.g., 200, 404)
//! - `version` - HTTP version (e.g., "1.1")
//! - `header` - Response headers table (lowercase keys)
//! - `body` - Response body string
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local http = require "http"
//!
//! local response = http.get(host, port, "/")
//! if response and response.status == 200 then
//!     print(response.body)
//! end
//! ```

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use mlua::{Lua, Table, Value};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for HTTP requests in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default maximum body size (1MB).
const DEFAULT_MAX_BODY_SIZE: usize = 1_048_576;

/// HTTP response structure.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// HTTP version.
    pub version: String,
    /// Status line.
    pub status_line: String,
    /// Response headers.
    pub header: HashMap<String, String>,
    /// Raw headers.
    pub rawheader: Vec<String>,
    /// Response body.
    pub body: Vec<u8>,
}

/// Build HTTP request.
#[expect(clippy::format_push_string, reason = "HTTP request building is not performance-critical")]
fn build_request(method: &str, host: &str, port: u16, path: &str, headers: &HashMap<String, String>, body: Option<&str>) -> String {
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    request.push_str(&format!("Host: {host}:{port}\r\n"));
    request.push_str("Connection: close\r\n");
    request.push_str("User-Agent: Mozilla/5.0 (compatible; Nmap NSE)\r\n");

    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }

    if let Some(content) = body {
        request.push_str(&format!("Content-Length: {}\r\n", content.len()));
        if !headers.contains_key("content-type") {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
    }

    request.push_str("\r\n");

    if let Some(content) = body {
        request.push_str(content);
    }

    request
}

/// Parse HTTP response.
fn parse_response(response_bytes: &[u8]) -> mlua::Result<HttpResponse> {
    let header_end = response_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| mlua::Error::RuntimeError("Invalid HTTP response".to_string()))?;

    let header_bytes = &response_bytes[..header_end];
    let body = response_bytes[header_end + 4..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid UTF-8 in headers: {e}")))?;

    let mut lines = header_str.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| mlua::Error::RuntimeError("Empty response".to_string()))?
        .to_string();

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let version = parts.first().and_then(|s| s.strip_prefix("HTTP/")).unwrap_or("1.1").to_string();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut header = HashMap::new();
    let mut rawheader = Vec::new();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        rawheader.push(line.to_string());
        if let Some((key, value)) = line.split_once(':') {
            header.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    Ok(HttpResponse {
        status,
        version,
        status_line: format!("{}\r\n", status_line.trim_end_matches('\r')),
        header,
        rawheader,
        body,
    })
}

/// Perform HTTP request over TCP.
fn perform_request(host: &str, port: u16, request: &str, timeout_ms: u64) -> mlua::Result<HttpResponse> {
    let addr = format!("{host}:{port}");

    let stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    let mut stream = stream;

    stream
        .write_all(request.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send request: {e}")))?;

    let mut response_bytes = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = stream
            .read(&mut buffer)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to read response: {e}")))?;

        if n == 0 {
            break;
        }

        response_bytes.extend_from_slice(&buffer[..n]);

        if response_bytes.len() > DEFAULT_MAX_BODY_SIZE + 8192 {
            break;
        }
    }

    parse_response(&response_bytes)
}

/// Convert HTTP response to Lua table.
fn response_to_table(lua: &Lua, response: &HttpResponse) -> mlua::Result<Table> {
    let table = lua.create_table()?;

    table.set("status", i64::from(response.status))?;
    table.set("version", response.version.as_str())?;
    table.set("status-line", response.status_line.as_str())?;

    let header_table = lua.create_table()?;
    for (key, value) in &response.header {
        header_table.set(key.as_str(), value.as_str())?;
    }
    table.set("header", header_table)?;

    let rawheader_table = lua.create_table()?;
    for (i, h) in response.rawheader.iter().enumerate() {
        rawheader_table.set(i64::try_from(i + 1).unwrap_or(1), h.as_str())?;
    }
    table.set("rawheader", rawheader_table)?;

    let body_str = String::from_utf8_lossy(&response.body).to_string();
    table.set("body", body_str.as_str())?;

    Ok(table)
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
        Value::Integer(n) => u16::try_from(n).unwrap_or(80),
        Value::Table(t) => t
            .get::<Option<i64>>("number")
            .ok()
            .flatten()
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(80),
        _ => 80,
    };

    (host_str, port_num)
}

/// Parse HTTP options from Lua table.
fn parse_options(options: Option<Table>) -> (u64, HashMap<String, String>) {
    let timeout = options
        .as_ref()
        .and_then(|t| t.get::<Option<u64>>("timeout").ok().flatten())
        .unwrap_or(DEFAULT_TIMEOUT_MS);

    let mut headers = HashMap::new();
    if let Some(opts) = options {
        if let Ok(Some(ht)) = opts.get::<Option<Table>>("header") {
            for (key, value) in ht.pairs::<String, String>().flatten() {
                headers.insert(key.to_lowercase(), value);
            }
        }
    }

    (timeout, headers)
}

/// Register the http library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the http table
    let http_table = lua.create_table()?;

    // Register GET function
    let get_fn = lua.create_function(|lua, (host, port, path, options): (Value, Value, String, Option<Table>)| {
        let (host_str, port_num) = extract_host_port(host, port);
        let (timeout, headers) = parse_options(options);

        debug!("http.get({}, {}, {})", host_str, port_num, path);

        let request = build_request("GET", &host_str, port_num, &path, &headers, None);

        match perform_request(&host_str, port_num, &request, timeout) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(e) => {
                debug!("http.get failed: {}", e);
                Ok(Value::Nil)
            }
        }
    })?;
    http_table.set("get", get_fn)?;

    // Register POST function
    let post_fn = lua.create_function(|lua, (host, port, path, options, _ignored, postdata): (Value, Value, String, Option<Table>, Option<Value>, Option<Value>)| {
        let (host_str, port_num) = extract_host_port(host, port);
        let (timeout, mut headers) = parse_options(options.clone());

        let body = match postdata {
            Some(Value::String(s)) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
            Some(Value::Table(t)) => {
                let mut pairs = Vec::new();
                for (key, value) in t.pairs::<String, String>().flatten() {
                    pairs.push(format!("{}={}", url_encode(&key), url_encode(&value)));
                }
                pairs.join("&")
            }
            _ => String::new(),
        };

        debug!("http.post({}, {}, {})", host_str, port_num, path);

        if !headers.contains_key("content-type") {
            headers.insert("content-type".to_string(), "application/x-www-form-urlencoded".to_string());
        }

        let request = build_request("POST", &host_str, port_num, &path, &headers, Some(&body));

        match perform_request(&host_str, port_num, &request, timeout) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    http_table.set("post", post_fn)?;

    // Register HEAD function
    let head_fn = lua.create_function(|lua, (host, port, path, options): (Value, Value, String, Option<Table>)| {
        let (host_str, port_num) = extract_host_port(host, port);
        let (timeout, headers) = parse_options(options);

        debug!("http.head({}, {}, {})", host_str, port_num, path);

        let request = build_request("HEAD", &host_str, port_num, &path, &headers, None);

        match perform_request(&host_str, port_num, &request, timeout) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    http_table.set("head", head_fn)?;

    // Register generic_request function
    let generic_fn = lua.create_function(|lua, (host, port, method, path, options, _ignored, body): (Value, Value, String, String, Option<Table>, Option<Value>, Option<String>)| {
        let (host_str, port_num) = extract_host_port(host, port);
        let (timeout, headers) = parse_options(options);

        debug!("http.generic_request({}, {}, {}, {})", host_str, port_num, method, path);

        let request = build_request(&method, &host_str, port_num, &path, &headers, body.as_deref());

        match perform_request(&host_str, port_num, &request, timeout) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    http_table.set("generic_request", generic_fn)?;

    // Register get_url function
    let get_url_fn = lua.create_function(|lua, (url, options): (String, Option<Table>)| {
        debug!("http.get_url({})", url);

        let (host, port, path) = parse_url(&url);
        let (timeout, headers) = parse_options(options);

        let request = build_request("GET", &host, port, &path, &headers, None);

        match perform_request(&host, port, &request, timeout) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    http_table.set("get_url", get_url_fn)?;

    // Register the http library globally
    lua.globals().set("http", http_table)?;

    Ok(())
}

/// Parse URL into components.
fn parse_url(url: &str) -> (String, u16, String) {
    let url_lower = url.to_lowercase();

    let (scheme, rest) = if url_lower.starts_with("https://") {
        ("https", &url[8..])
    } else if url_lower.starts_with("http://") {
        ("http", &url[7..])
    } else {
        ("http", url)
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let h = &host_port[..idx];
            let p: u16 = host_port[idx + 1..].parse().unwrap_or(80);
            (h, p)
        }
        None => (host_port, if scheme == "https" { 443 } else { 80 }),
    };

    (host.to_string(), port, path.to_string())
}

/// URL encode a string.
fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                for byte in c.to_string().as_bytes() {
                    let _ = write!(result, "%{byte:02X}");
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (host, port, path) = parse_url("http://example.com:8080/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/path");

        let (host, port, path) = parse_url("https://example.com/path");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("a=b"), "a%3Db");
    }

    #[test]
    fn test_build_request() {
        let headers = HashMap::new();
        let request = build_request("GET", "example.com", 80, "/path", &headers, None);

        assert!(request.contains("GET /path HTTP/1.1"));
        assert!(request.contains("Host: example.com:80"));
    }
}
