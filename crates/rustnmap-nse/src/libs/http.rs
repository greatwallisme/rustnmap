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
//! - `http.pipeline_add(path, [options], all_requests, [method])` - Queue a pipeline request
//! - `http.pipeline_go(host, port, all_requests)` - Execute pipeline
//!
//! # Response Table Structure
//!
//! The HTTP functions return a response table with:
//! - `status` - HTTP status code (e.g., 200, 404)
//! - `version` - HTTP version (e.g., "1.1")
//! - `status-line` - Full status line
//! - `header` - Response headers table (lowercase keys)
//! - `rawheader` - Array of raw header strings
//! - `cookies` - Array of cookie tables with name, value, path, domain, expires
//! - `rawbody` - Response body before Content-Encoding processing
//! - `body` - Response body after Content-Encoding processing
//! - `decoded` - Array of processed encodings (e.g., "gzip")
//! - `undecoded` - Array of unsupported encodings
//! - `location` - Array of redirect URLs followed
//! - `incomplete` - Partial response on error
//! - `truncated` - Body was truncated due to size limit
//!
//! # Options Table Reference
//!
//! - `timeout` - Socket timeout in milliseconds
//! - `header` - Additional headers table
//! - `content` - Request body (string or form table)
//! - `cookies` - Cookies array or string
//! - `auth` - Basic auth table {username, password}
//! - `digestauth` - Digest auth table (computed)
//! - `bypass_cache` - Skip cache lookup
//! - `no_cache` - Skip cache storage
//! - `redirect_ok` - Redirect limit or function
//! - `max_body_size` - Body size limit
//! - `truncated_ok` - Allow body truncation
//! - `scheme` - Force HTTP or HTTPS
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local http = require "http"
//!
//! -- Basic GET
//! local response = http.get(host, port, "/")
//! if response and response.status == 200 then
//!     print(response.body)
//!     print(response.header["content-type"])
//! end
//!
//! -- Pipeline requests
//! local all = nil
//! all = http.pipeline_add("/path1", nil, all)
//! all = http.pipeline_add("/path2", nil, all)
//! local results = http.pipeline_go(host, port, all)
//! ```

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use flate2::read::{DeflateDecoder, GzDecoder};

use mlua::{Lua, Table, Value};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for HTTP requests in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default maximum body size (2MB).
const DEFAULT_MAX_BODY_SIZE: usize = 2_097_152;
/// Default maximum redirect count.
const MAX_REDIRECT_COUNT: u32 = 5;

/// HTTP response structure.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g., 200, 404).
    pub status: u16,
    /// HTTP version (e.g., "1.1").
    pub version: String,
    /// Full status line (e.g., "HTTP/1.1 200 OK").
    pub status_line: String,
    /// Response headers (lowercase keys).
    pub header: HashMap<String, String>,
    /// Raw header lines.
    pub rawheader: Vec<String>,
    /// Response body (after Content-Encoding decoding).
    pub body: Vec<u8>,
    /// Raw response body (before Content-Encoding decoding).
    pub rawbody: Vec<u8>,
    /// Cookies from Set-Cookie headers.
    pub cookies: Vec<Cookie>,
    /// Successfully processed encodings (e.g., `["gzip"]`).
    pub decoded: Vec<String>,
    /// Unsupported/undecoded encodings.
    pub undecoded: Vec<String>,
    /// Redirect URLs followed.
    pub location: Vec<String>,
    /// True if response is incomplete.
    pub incomplete: bool,
    /// True if body was truncated due to size limit.
    pub truncated: bool,
}

/// Cookie structure.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Cookie path scope.
    pub path: Option<String>,
    /// Cookie domain scope.
    pub domain: Option<String>,
    /// Cookie expiration timestamp.
    pub expires: Option<String>,
}

/// Pipeline request structure.
#[derive(Debug, Clone)]
pub struct PipelineRequest {
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request body.
    pub body: Option<Vec<u8>>,
    /// Request options.
    pub options: RequestOptions,
}

/// Request options.
#[derive(Debug, Clone)]
pub struct RequestOptions {
    /// Request timeout in milliseconds.
    pub timeout: u64,
    /// Request headers.
    pub headers: HashMap<String, String>,
    /// Request cookies as structured objects.
    pub cookies: Option<Vec<Cookie>>,
    /// Request cookies as raw string.
    pub cookies_raw: Option<String>,
    /// Authentication information.
    pub auth: Option<AuthInfo>,
    /// Bypass cache flag.
    pub bypass_cache: bool,
    /// Disable cache storage flag.
    pub no_cache: bool,
    /// Redirect handling policy.
    pub redirect_ok: Option<RedirectOk>,
    /// Maximum response body size.
    pub max_body_size: usize,
    /// Allow truncated responses flag.
    pub truncated_ok: bool,
    /// URL scheme override.
    pub scheme: Option<String>,
}

/// Authentication information.
#[derive(Debug, Clone)]
pub enum AuthInfo {
    /// Basic authentication.
    Basic {
        /// Username.
        username: String,
        /// Password.
        password: String,
    },
    /// Digest authentication.
    Digest {
        /// Username.
        username: String,
        /// Password.
        password: String,
        /// Authentication realm.
        realm: String,
        /// Server nonce.
        nonce: String,
        /// Request URI.
        uri: String,
        /// Computed response hash.
        response: String,
    },
}

/// Redirect behavior.
#[derive(Debug, Clone)]
pub enum RedirectOk {
    /// Redirects disabled.
    Disabled,
    /// Maximum redirect count.
    Count(u32),
    /// Custom redirect function (not implemented).
    Function,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT_MS,
            headers: HashMap::new(),
            cookies: None,
            cookies_raw: None,
            auth: None,
            bypass_cache: false,
            no_cache: false,
            redirect_ok: Some(RedirectOk::Count(MAX_REDIRECT_COUNT)),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            truncated_ok: false,
            scheme: None,
        }
    }
}

/// Build HTTP request.
#[expect(
    clippy::format_push_string,
    reason = "HTTP request building is not performance-critical"
)]
fn build_request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    options: &RequestOptions,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    request.push_str(&format!("Host: {host}:{port}\r\n"));
    request.push_str("Connection: close\r\n");
    request.push_str("User-Agent: Mozilla/5.0 (compatible; Nmap NSE)\r\n");

    // Add custom headers
    for (key, value) in &options.headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }

    // Add cookies
    if let Some(cookies) = &options.cookies {
        let cookie_str = cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");
        request.push_str("Cookie: ");
        request.push_str(&cookie_str);
        request.push_str("\r\n");
    } else if let Some(cookie_raw) = &options.cookies_raw {
        request.push_str("Cookie: ");
        request.push_str(cookie_raw);
        request.push_str("\r\n");
    }

    // Add authentication
    if let Some(auth) = &options.auth {
        match auth {
            AuthInfo::Basic { username, password } => {
                let creds = format!("{username}:{password}");
                let encoded = base64_encode(creds.as_bytes());
                request.push_str(&format!("Authorization: Basic {encoded}\r\n"));
            }
            AuthInfo::Digest {
                username,
                realm,
                nonce,
                uri,
                response,
                ..
            } => {
                request.push_str(&format!(
                    "Authorization: Digest username=\"{username}\", realm=\"{realm}\", \
                     nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\"\r\n"
                ));
            }
        }
    }

    if let Some(content) = body {
        request.push_str(&format!("Content-Length: {}\r\n", content.len()));
        if !options.headers.contains_key("content-type") {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
    }

    request.push_str("\r\n");

    let mut bytes = request.into_bytes();

    if let Some(content) = body {
        bytes.extend_from_slice(content);
    }

    bytes
}

/// Parse HTTP response.
fn parse_response(
    response_bytes: &[u8],
    max_body_size: usize,
    truncated_ok: bool,
) -> mlua::Result<HttpResponse> {
    let header_end = response_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| mlua::Error::RuntimeError("Invalid HTTP response".to_string()))?;

    let header_bytes = &response_bytes[..header_end];
    let full_body = response_bytes[header_end + 4..].to_vec();

    // Check if body exceeds max size
    let (rawbody, truncated) = if full_body.len() > max_body_size {
        if truncated_ok {
            (full_body[..max_body_size].to_vec(), true)
        } else {
            return Err(mlua::Error::RuntimeError(
                "response body too large".to_string(),
            ));
        }
    } else {
        (full_body, false)
    };

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid UTF-8 in headers: {e}")))?;

    let mut lines = header_str.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| mlua::Error::RuntimeError("Empty response".to_string()))?
        .to_string();

    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let version = parts
        .first()
        .and_then(|s| s.strip_prefix("HTTP/"))
        .unwrap_or("1.1")
        .to_string();
    let status: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut header = HashMap::new();
    let mut rawheader = Vec::new();
    let mut cookies = Vec::new();
    let mut content_encoding: Option<String> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        rawheader.push(line.to_string());
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_lowercase();
            let value_trimmed = value.trim().to_string();

            // Handle Set-Cookie headers
            if key_lower == "set-cookie" {
                if let Ok(cookie) = parse_set_cookie(&value_trimmed) {
                    cookies.push(cookie);
                }
            }

            // Track Content-Encoding
            if key_lower == "content-encoding" {
                content_encoding = Some(value_trimmed.clone());
            }

            header.insert(key_lower, value_trimmed);
        }
    }

    // Process body according to Content-Encoding
    let (decoded, undecoded, body) = if let Some(encoding) = content_encoding {
        match encoding.as_str() {
            "gzip" | "x-gzip" => match decompress_gzip(&rawbody) {
                Ok(decompressed) => (vec!["gzip".to_string()], Vec::new(), decompressed),
                Err(_) => (Vec::new(), vec![encoding], rawbody.clone()),
            },
            "deflate" => match decompress_deflate(&rawbody) {
                Ok(decompressed) => (vec!["deflate".to_string()], Vec::new(), decompressed),
                Err(_) => (Vec::new(), vec![encoding], rawbody.clone()),
            },
            "identity" | "" => (Vec::new(), Vec::new(), rawbody.clone()),
            _ => (Vec::new(), vec![encoding], rawbody.clone()),
        }
    } else {
        (Vec::new(), Vec::new(), rawbody.clone())
    };

    Ok(HttpResponse {
        status,
        version,
        status_line: format!("{}\r\n", status_line.trim_end_matches('\r')),
        header,
        rawheader,
        body,
        rawbody,
        cookies,
        decoded,
        undecoded,
        location: Vec::new(),
        incomplete: false,
        truncated,
    })
}

/// Decompress gzip data.
fn decompress_gzip(data: &[u8]) -> mlua::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| mlua::Error::RuntimeError(format!("gzip decompression failed: {e}")))?;

    Ok(decompressed)
}

/// Decompress deflate data.
fn decompress_deflate(data: &[u8]) -> mlua::Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| mlua::Error::RuntimeError(format!("deflate decompression failed: {e}")))?;

    Ok(decompressed)
}

/// Parse Set-Cookie header value.
fn parse_set_cookie(value: &str) -> mlua::Result<Cookie> {
    let mut parts = value.split(';');

    let name_value = parts
        .next()
        .ok_or_else(|| mlua::Error::RuntimeError("Empty cookie".to_string()))?;

    let (name, cookie_val) = name_value
        .split_once('=')
        .ok_or_else(|| mlua::Error::RuntimeError("Invalid cookie format".to_string()))?;

    let mut cookie = Cookie {
        name: name.trim().to_string(),
        value: cookie_val.trim().to_string(),
        path: None,
        domain: None,
        expires: None,
    };

    for part in parts {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            let key_lower = key.trim().to_lowercase();
            match key_lower.as_str() {
                "path" => cookie.path = Some(val.trim().to_string()),
                "domain" => cookie.domain = Some(val.trim().to_string()),
                "expires" => cookie.expires = Some(val.trim().to_string()),
                "max-age" => {
                    // Convert max-age to expires format
                    cookie.expires = Some(val.trim().to_string());
                }
                _ => {}
            }
        }
    }

    Ok(cookie)
}

/// Perform HTTP request over TCP.
fn perform_request(
    host: &str,
    port: u16,
    request: &[u8],
    options: &RequestOptions,
) -> mlua::Result<HttpResponse> {
    let addr = format!("{host}:{port}");

    let stream = TcpStream::connect(&addr)
        .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(options.timeout)))
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set timeout: {e}")))?;

    let mut stream = stream;

    stream
        .write_all(request)
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

        if response_bytes.len() > options.max_body_size + 8192 {
            break;
        }
    }

    parse_response(&response_bytes, options.max_body_size, options.truncated_ok)
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

    // Raw body (before decoding)
    let rawbody_str = String::from_utf8_lossy(&response.rawbody).to_string();
    table.set("rawbody", rawbody_str.as_str())?;

    // Cookies
    let cookies_table = lua.create_table()?;
    for (i, cookie) in response.cookies.iter().enumerate() {
        let cookie_tbl = lua.create_table()?;
        cookie_tbl.set("name", cookie.name.as_str())?;
        cookie_tbl.set("value", cookie.value.as_str())?;
        if let Some(path) = &cookie.path {
            cookie_tbl.set("path", path.as_str())?;
        }
        if let Some(domain) = &cookie.domain {
            cookie_tbl.set("domain", domain.as_str())?;
        }
        if let Some(expires) = &cookie.expires {
            cookie_tbl.set("expires", expires.as_str())?;
        }
        cookies_table.set(i64::try_from(i + 1).unwrap_or(1), cookie_tbl)?;
    }
    table.set("cookies", cookies_table)?;

    // Decoding info
    if !response.decoded.is_empty() {
        let decoded_table = lua.create_table()?;
        for (i, enc) in response.decoded.iter().enumerate() {
            decoded_table.set(i64::try_from(i + 1).unwrap_or(1), enc.as_str())?;
        }
        table.set("decoded", decoded_table)?;
    }

    if !response.undecoded.is_empty() {
        let undecoded_table = lua.create_table()?;
        for (i, enc) in response.undecoded.iter().enumerate() {
            undecoded_table.set(i64::try_from(i + 1).unwrap_or(1), enc.as_str())?;
        }
        table.set("undecoded", undecoded_table)?;
    }

    // Location (redirects)
    if !response.location.is_empty() {
        let location_table = lua.create_table()?;
        for (i, loc) in response.location.iter().enumerate() {
            location_table.set(i64::try_from(i + 1).unwrap_or(1), loc.as_str())?;
        }
        table.set("location", location_table)?;
    }

    // Error states
    if response.incomplete {
        table.set("incomplete", true)?;
    }

    if response.truncated {
        table.set("truncated", true)?;
    }

    Ok(table)
}

/// Extract host and port from Lua values.
///
/// For HTTP requests, we use the hostname (not IP) for the Host header.
/// Priority order:
/// 1. `targetname` - Original target specification (e.g., "example.com")
/// 2. `name` - Hostname from DNS reverse lookup
/// 3. `ip` - IP address (fallback)
fn extract_host_port(host: Value, port: Value) -> (String, u16) {
    let host_str = match host {
        Value::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
        Value::Table(t) => t
            // Use targetname first for HTTP Host header (critical for virtual hosting)
            .get::<Option<String>>("targetname")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                t.get::<Option<String>>("name")
                    .ok()
                    .flatten()
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| t.get::<Option<String>>("ip").ok().flatten())
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
fn parse_options(options: Option<Table>) -> RequestOptions {
    let mut opts = RequestOptions::default();

    let Some(table) = options else {
        return opts;
    };

    // Timeout
    if let Ok(Some(timeout)) = table.get::<Option<u64>>("timeout") {
        opts.timeout = timeout;
    }

    // Headers
    if let Ok(Some(ht)) = table.get::<Option<Table>>("header") {
        for (key, value) in ht.pairs::<String, String>().flatten() {
            opts.headers.insert(key.to_lowercase(), value);
        }
    }

    // Cookies (as table)
    if let Ok(Some(cookie_tbl)) = table.get::<Option<Table>>("cookies") {
        let mut cookies_vec = Vec::new();
        for (_, cookie_value) in cookie_tbl.pairs::<Value, Value>().flatten() {
            if let Value::Table(cookie) = cookie_value {
                let Some(name) = cookie.get::<Option<String>>("name").ok().flatten() else {
                    continue;
                };
                let Some(value) = cookie.get::<Option<String>>("value").ok().flatten() else {
                    continue;
                };
                let c = Cookie {
                    name,
                    value,
                    path: None,
                    domain: None,
                    expires: None,
                };
                cookies_vec.push(c);
            }
        }
        if !cookies_vec.is_empty() {
            opts.cookies = Some(cookies_vec);
        }
    } else if let Ok(Some(cookie_str)) = table.get::<Option<String>>("cookies") {
        opts.cookies_raw = Some(cookie_str);
    }

    // Auth (Basic)
    if let Ok(Some(auth_tbl)) = table.get::<Option<Table>>("auth") {
        if let (Ok(Some(username)), Ok(Some(password))) = (
            auth_tbl.get::<Option<String>>("username"),
            auth_tbl.get::<Option<String>>("password"),
        ) {
            opts.auth = Some(AuthInfo::Basic { username, password });
        }
    }

    // Bypass cache
    if let Ok(Some(bypass)) = table.get::<Option<bool>>("bypass_cache") {
        opts.bypass_cache = bypass;
    }

    // No cache
    if let Ok(Some(no_cache)) = table.get::<Option<bool>>("no_cache") {
        opts.no_cache = no_cache;
    }

    // Redirect OK
    if let Ok(Some(redirect_ok)) = table.get::<Option<Value>>("redirect_ok") {
        match redirect_ok {
            Value::Boolean(false) => opts.redirect_ok = Some(RedirectOk::Disabled),
            Value::Integer(n) => {
                if let Ok(count) = u32::try_from(n) {
                    opts.redirect_ok = Some(RedirectOk::Count(count));
                }
            }
            _ => {}
        }
    }

    // Max body size
    if let Ok(Some(size)) = table.get::<Option<usize>>("max_body_size") {
        opts.max_body_size = size;
    }

    // Truncated OK
    if let Ok(Some(truncated)) = table.get::<Option<bool>>("truncated_ok") {
        opts.truncated_ok = truncated;
    }

    // Scheme
    if let Ok(Some(scheme)) = table.get::<Option<String>>("scheme") {
        opts.scheme = Some(scheme);
    }

    opts
}

/// Register the http library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
// HTTP library registration requires registering many Lua functions for full nmap compatibility.
// Splitting would require passing complex state through multiple functions.
#[expect(
    clippy::too_many_lines,
    reason = "HTTP library requires many function registrations"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the http table
    let http_table = lua.create_table()?;

    // Register GET function
    let get_fn = lua.create_function(
        |lua, (host, port, path, options): (Value, Value, String, Option<Table>)| {
            let (host_str, port_num) = extract_host_port(host, port);
            let opts = parse_options(options);

            debug!("http.get({}, {}, {})", host_str, port_num, path);

            let request = build_request("GET", &host_str, port_num, &path, &opts, None);

            match perform_request(&host_str, port_num, &request, &opts) {
                Ok(response) => response_to_table(lua, &response).map(Value::Table),
                Err(e) => {
                    debug!("http.get failed: {}", e);
                    Ok(Value::Nil)
                }
            }
        },
    )?;
    http_table.set("get", get_fn)?;

    // Register POST function
    let post_fn = lua.create_function(
        |lua,
         (host, port, path, options, _ignored, postdata): (
            Value,
            Value,
            String,
            Option<Table>,
            Option<Value>,
            Option<Value>,
        )| {
            let (host_str, port_num) = extract_host_port(host, port);
            let mut opts = parse_options(options.clone());

            let body = match postdata {
                Some(Value::String(s)) => s.as_bytes().to_vec(),
                Some(Value::Table(t)) => {
                    let mut pairs = Vec::new();
                    for (key, value) in t.pairs::<String, String>().flatten() {
                        pairs.push(format!("{}={}", url_encode(&key), url_encode(&value)));
                    }
                    pairs.join("&").into_bytes()
                }
                _ => Vec::new(),
            };

            debug!("http.post({}, {}, {})", host_str, port_num, path);

            if !opts.headers.contains_key("content-type") {
                opts.headers.insert(
                    "content-type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                );
            }

            let request = build_request("POST", &host_str, port_num, &path, &opts, Some(&body));

            match perform_request(&host_str, port_num, &request, &opts) {
                Ok(response) => response_to_table(lua, &response).map(Value::Table),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
    http_table.set("post", post_fn)?;

    // Register HEAD function
    let head_fn = lua.create_function(
        |lua, (host, port, path, options): (Value, Value, String, Option<Table>)| {
            let (host_str, port_num) = extract_host_port(host, port);
            let opts = parse_options(options);

            debug!("http.head({}, {}, {})", host_str, port_num, path);

            let request = build_request("HEAD", &host_str, port_num, &path, &opts, None);

            match perform_request(&host_str, port_num, &request, &opts) {
                Ok(response) => response_to_table(lua, &response).map(Value::Table),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
    http_table.set("head", head_fn)?;

    // Register generic_request function
    let generic_fn = lua.create_function(
        |lua,
         (host, port, method, path, options, _ignored, body): (
            Value,
            Value,
            String,
            String,
            Option<Table>,
            Option<Value>,
            Option<String>,
        )| {
            let (host_str, port_num) = extract_host_port(host, port);
            let opts = parse_options(options);

            debug!(
                "http.generic_request({}, {}, {}, {})",
                host_str, port_num, method, path
            );

            let body_bytes = body.as_deref().map(|s| s.as_bytes().to_vec());
            let request = build_request(
                &method,
                &host_str,
                port_num,
                &path,
                &opts,
                body_bytes.as_deref(),
            );

            match perform_request(&host_str, port_num, &request, &opts) {
                Ok(response) => response_to_table(lua, &response).map(Value::Table),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
    http_table.set("generic_request", generic_fn)?;

    // Register get_url function
    let get_url_fn = lua.create_function(|lua, (url, options): (String, Option<Table>)| {
        debug!("http.get_url({})", url);

        let (host, port, path) = parse_url(&url);
        let opts = parse_options(options);

        let request = build_request("GET", &host, port, &path, &opts, None);

        match perform_request(&host, port, &request, &opts) {
            Ok(response) => response_to_table(lua, &response).map(Value::Table),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    http_table.set("get_url", get_url_fn)?;

    // Register pipeline_add function
    let pipeline_add_fn = lua.create_function(
        |lua,
         (path, options, all_requests, method): (
            String,
            Option<Table>,
            Option<Table>,
            Option<String>,
        )| {
            debug!("http.pipeline_add({})", path);

            let opts = parse_options(options);
            let method_ref = method.as_deref().unwrap_or("GET");

            // Create or get pipeline table
            let pipeline = match all_requests {
                Some(t) => t,
                None => lua.create_table()?,
            };

            // Add request to pipeline
            let len = pipeline
                .len()
                .map(|n: i64| usize::try_from(n).unwrap_or(0) + 1)
                .unwrap_or(1);
            let len_idx = i64::try_from(len).unwrap_or(1);

            let request = lua.create_table()?;
            request.set("method", method_ref)?;
            request.set("path", path.as_str())?;

            if !opts.headers.is_empty() {
                let headers = lua.create_table()?;
                for (key, value) in &opts.headers {
                    headers.set(key.as_str(), value.as_str())?;
                }
                request.set("headers", headers)?;
            }

            pipeline.set(len_idx, request)?;

            Ok(Value::Table(pipeline))
        },
    )?;
    http_table.set("pipeline_add", pipeline_add_fn)?;

    // Register pipeline_go function
    let pipeline_go_fn = lua.create_function(
        |lua, (host, port, all_requests): (Value, Value, Option<Table>)| {
            let (host_str, port_num) = extract_host_port(host, port);

            let Some(pipeline) = all_requests else {
                return Ok(Value::Nil);
            };

            let pipeline_len = pipeline.len().unwrap_or(0);
            debug!(
                "http.pipeline_go({}, {}, {})",
                host_str, port_num, pipeline_len
            );

            let results = lua.create_table()?;

            // Execute each request in pipeline
            for i in 1..=pipeline_len {
                let request_opt: Option<Table> = pipeline.get(i).ok();
                let Some(request) = request_opt else {
                    continue;
                };

                let method: String = request
                    .get("method")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "GET".to_string());
                let path: String = request
                    .get("path")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "/".to_string());
                let opts = parse_options(request.get("options").ok());

                let req = build_request(&method, &host_str, port_num, &path, &opts, None);

                if let Ok(response) = perform_request(&host_str, port_num, &req, &opts) {
                    if let Ok(tbl) = response_to_table(lua, &response) {
                        let _ = results.set(i, tbl);
                    }
                }
            }

            Ok(Value::Table(results))
        },
    )?;
    http_table.set("pipeline_go", pipeline_go_fn)?;

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

/// Base64 encoding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    for chunk in input.chunks(3) {
        let b0 = usize::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, usize::from);
        let b2 = chunk.get(2).copied().map_or(0, usize::from);

        result.push(char::from(ALPHABET[b0 >> 2]));
        result.push(char::from(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]));

        if chunk.len() > 1 {
            result.push(char::from(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]));
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(char::from(ALPHABET[b2 & 0x3f]));
        } else {
            result.push('=');
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
    fn test_base64_encode() {
        let input = b"hello";
        let encoded = base64_encode(input);
        assert_eq!(encoded, "aGVsbG8=");
    }

    #[test]
    fn test_parse_set_cookie() {
        let cookie_str = "session=abc123; Path=/; Domain=example.com";
        let cookie = parse_set_cookie(cookie_str).unwrap();
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert_eq!(cookie.path, Some("/".to_string()));
        assert_eq!(cookie.domain, Some("example.com".to_string()));
    }
}
