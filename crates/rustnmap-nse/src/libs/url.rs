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

//! URL library for NSE.
//!
//! This module provides the `url` library which contains functions for
//! URL parsing, composition, and relative URL resolution following RFC 3986.
//!
//! # Available Functions
//!
//! - `url.escape(s)` - URL encode a string
//! - `url.unescape(s)` - URL decode a string
//! - `url.parse(url, default)` - Parse URL into components
//! - `url.build(parsed)` - Build URL from components
//! - `url.absolute(base_url, relative_url)` - Build absolute URL from base and relative
//! - `url.parse_path(path)` - Parse path into segments
//! - `url.build_path(parsed, unsafe)` - Build path from segments
//! - `url.parse_query(query)` - Parse query string into table
//! - `url.build_query(query)` - Build query string from table
//! - `url.get_default_port(scheme)` - Get default port for scheme
//! - `url.get_default_scheme(port)` - Get default scheme for port
//! - `url.ascii_hostname(host)` - Convert hostname to ASCII (Punycode)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local url = require "url"
//!
//! -- Parse a URL
//! local parsed = url.parse("https://example.com:8080/path/to/file?query=value#fragment")
//! -- Returns table with scheme, authority, userinfo, user, password, host, port, path, query, fragment
//!
//! -- Build a URL from components
//! local built = url.build({
//!     scheme = "https",
//!     host = "example.com",
//!     port = 8080,
//!     path = "/api/v1",
//!     query = "key=value"
//! })
//!
//! -- URL encode/decode
//! local encoded = url.escape("hello world")  -- "hello%20world"
//! local decoded = url.unescape(encoded)      -- "hello world"
//!
//! -- Parse and build query strings
//! local query = url.parse_query("name=John&age=30")
//! -- Returns {name = "John", age = "30"}
//!
//! -- Build absolute URL from base and relative
//! local absolute = url.absolute("https://example.com/api/", "../v2/resource")
//! -- Returns "https://example.com/v2/resource"
//! ```

use mlua::{IntoLua, Lua, Table, Value};
use punycode::encode;

use crate::error::Result;
use crate::lua::NseLua;

/// Register the url library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the url table
    let url_table = lua.create_table()?;

    // Register escape function
    let escape_fn = lua.create_function(|_lua, s: String| Ok(escape(&s)))?;
    url_table.set("escape", escape_fn)?;

    // Register unescape function
    let unescape_fn =
        lua.create_function(|_lua, s: String| unescape(&s).map_err(mlua::Error::external))?;
    url_table.set("unescape", unescape_fn)?;

    // Register parse function
    let parse_fn = lua.create_function(|lua, (url, default): (String, Option<Value>)| {
        parse(&url, default, lua).map_err(mlua::Error::external)
    })?;
    url_table.set("parse", parse_fn)?;

    // Register build function
    let build_fn =
        lua.create_function(|_lua, parsed: Value| build(&parsed).map_err(mlua::Error::external))?;
    url_table.set("build", build_fn)?;

    // Register absolute function
    let absolute_fn = lua.create_function(|lua, (base, relative): (Value, String)| {
        absolute(base, &relative, lua).map_err(mlua::Error::external)
    })?;
    url_table.set("absolute", absolute_fn)?;

    // Register parse_path function
    let parse_path_fn = lua.create_function(|lua, path: Option<String>| parse_path(path, lua))?;
    url_table.set("parse_path", parse_path_fn)?;

    // Register build_path function
    let build_path_fn =
        lua.create_function(|lua, (parsed, unsafe_flag): (Value, Option<bool>)| {
            build_path(&parsed, unsafe_flag.unwrap_or(false), lua).map_err(mlua::Error::external)
        })?;
    url_table.set("build_path", build_path_fn)?;

    // Register parse_query function
    let parse_query_fn = lua.create_function(|lua, query: String| parse_query(&query, lua))?;
    url_table.set("parse_query", parse_query_fn)?;

    // Register build_query function
    let build_query_fn = lua
        .create_function(|_lua, query: Value| build_query(&query).map_err(mlua::Error::external))?;
    url_table.set("build_query", build_query_fn)?;

    // Register get_default_port function
    let get_default_port_fn = lua
        .create_function(|_lua, scheme: Option<String>| Ok(get_default_port(scheme.as_deref())))?;
    url_table.set("get_default_port", get_default_port_fn)?;

    // Register get_default_scheme function
    let get_default_scheme_fn =
        lua.create_function(|lua, port: Value| get_default_scheme(&port, lua))?;
    url_table.set("get_default_scheme", get_default_scheme_fn)?;

    // Register ascii_hostname function
    let ascii_hostname_fn = lua.create_function(|_lua, host: Value| {
        ascii_hostname(&host).map_err(mlua::Error::external)
    })?;
    url_table.set("ascii_hostname", ascii_hostname_fn)?;

    // Set the url table in globals
    lua.globals().set("url", url_table)?;

    Ok(())
}

/// URL-encode a string.
///
/// Encodes all characters except alphanumeric and `-`, `_`, `.`, `!`, `~`, `*`, `'`, `(`, `)`,
/// `:`, `@`, `&`, `=`, `+`, `$`, `,` using percent-encoding (`%XX`).
///
/// # Arguments
///
/// * `s` - The string to encode
///
/// # Returns
///
/// The URL-encoded string
#[must_use]
pub fn escape(s: &str) -> String {
    s.chars().map(char_to_percent_encoded).collect()
}

/// Convert a character to its percent-encoded representation if needed.
fn char_to_percent_encoded(c: char) -> String {
    if c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '_'
                | '.'
                | '!'
                | '~'
                | '*'
                | '\''
                | '('
                | ')'
                | ':'
                | '@'
                | '&'
                | '='
                | '+'
                | '$'
                | ','
        )
    {
        c.to_string()
    } else {
        // URL encoding uses low byte for non-ASCII chars per RFC 3986
        // This matches Nmap's behavior which takes string.byte(c)
        #[expect(
            clippy::cast_possible_truncation,
            reason = "URL encoding uses low byte per RFC 3986 and Nmap behavior"
        )]
        let byte = u32::from(c) as u8;
        format!("%{byte:02X}")
    }
}

/// Decode a percent-encoded string.
///
/// Decodes all `%XX` escape sequences to their original characters.
///
/// # Arguments
///
/// * `s` - The encoded string
///
/// # Errors
///
/// Returns an error if an invalid percent encoding is encountered.
///
/// # Returns
///
/// The decoded string
pub fn unescape(s: &str) -> std::result::Result<String, String> {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex1 = chars
                .next()
                .ok_or_else(|| "Incomplete escape sequence".to_string())?;
            let hex2 = chars
                .next()
                .ok_or_else(|| "Incomplete escape sequence".to_string())?;

            if !hex1.is_ascii_hexdigit() || !hex2.is_ascii_hexdigit() {
                return Err("Invalid hex digit in escape sequence".to_string());
            }

            let byte = u8::from_str_radix(&format!("{hex1}{hex2}"), 16)
                .map_err(|_e| "Invalid escape sequence".to_string())?;

            result.push(byte as char);
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

/// Normalize escape sequences (decode then re-encode).
///
/// This ensures consistent percent-encoding format.
///
/// # Arguments
///
/// * `s` - The string to normalize
///
/// # Returns
///
/// The normalized string
#[must_use]
fn normalize_escape(s: &str) -> String {
    unescape(s).map_or_else(|_| s.to_string(), |decoded| escape(&decoded))
}

/// Parse a URL into its components.
///
/// Parses a URL according to RFC 3986 and returns a table with the following fields:
/// - `scheme` - The URL scheme (e.g., "https")
/// - `authority` - The authority part (e.g., "user@example.com:8080")
/// - `userinfo` - The userinfo part (e.g., "user:pass")
/// - `user` - The username
/// - `password` - The password
/// - `host` - The hostname
/// - `ascii_host` - The Punycode-encoded ASCII hostname (for international domains)
/// - `port` - The port number
/// - `path` - The path
/// - `params` - The parameters (after `;`)
/// - `query` - The query string (after `?`)
/// - `fragment` - The fragment (after `#`)
/// - `is_folder` - Whether the path ends with `/`
/// - `extension` - The file extension (if any)
///
/// # Arguments
///
/// * `url` - The URL string to parse
/// * `default` - Optional table with default values for each field
/// * `lua` - The Lua runtime
///
/// # Errors
///
/// Returns an error if URL parsing fails.
///
/// # Returns
///
/// A Lua table containing the parsed URL components
pub fn parse(url: &str, default: Option<Value>, lua: &Lua) -> mlua::Result<Table> {
    let parsed = lua.create_table()?;

    // Copy default values if provided
    if let Some(Value::Table(default_tbl)) = default {
        for pair in default_tbl.pairs::<String, Value>() {
            let (k, v) = pair?;
            parsed.set(k, v)?;
        }
    }

    let mut remaining = url.to_string();

    // Decode and normalize escape sequences
    remaining = normalize_escape(&remaining);

    // Extract fragment
    if let Some(pos) = remaining.find('#') {
        let fragment = remaining[pos + 1..].to_string();
        parsed.set("fragment", fragment)?;
        remaining = remaining[..pos].to_string();
    }

    // Extract scheme (lowercase per RFC 3986 section 3.1)
    if let Some(pos) = remaining.find("://") {
        let scheme = remaining[..pos].to_lowercase();
        parsed.set("scheme", scheme)?;
        remaining = remaining[pos + 3..].to_string();
    } else if let Some(end) = remaining.find(':') {
        // Scheme without :// (like mailto:)
        let scheme = remaining[..end].to_lowercase();
        parsed.set("scheme", scheme)?;
        remaining = remaining[end + 1..].to_string();
    }

    // Extract authority (after //)
    if remaining.starts_with("//") {
        if let Some(end) = remaining.find('/') {
            let authority = remaining[2..end].to_string();
            parsed.set("authority", authority)?;
            remaining = remaining[end..].to_string();
        } else {
            let authority = remaining[2..].to_string();
            parsed.set("authority", authority)?;
            remaining = String::new();
        }
    }

    // Extract query string
    if let Some(pos) = remaining.find('?') {
        let query = remaining[pos + 1..].to_string();
        parsed.set("query", query)?;
        remaining = remaining[..pos].to_string();
    }

    // Extract params
    if let Some(pos) = remaining.find(';') {
        let params = remaining[pos + 1..].to_string();
        parsed.set("params", params)?;
        remaining = remaining[..pos].to_string();
    }

    // Path is whatever is left
    parsed.set("path", remaining.clone())?;

    // Check for folder route and extension
    if remaining.ends_with('/') {
        parsed.set("is_folder", true)?;
    } else {
        parsed.set("is_folder", false)?;
        // Extract extension (everything after last . before / or end)
        if let Some(last_slash) = remaining.rfind('/') {
            let after_slash = &remaining[last_slash + 1..];
            if let Some(dot_pos) = after_slash.rfind('.') {
                let ext = &after_slash[dot_pos + 1..];
                if !ext.contains(';') {
                    parsed.set("extension", ext)?;
                }
            }
        } else if let Some(dot_pos) = remaining.rfind('.') {
            let ext = &remaining[dot_pos + 1..];
            if !ext.contains(';') {
                parsed.set("extension", ext)?;
            }
        }
    }

    // Parse authority into userinfo, host, port
    let authority: Value = parsed.get("authority")?;
    if let Value::String(auth_str) = authority {
        let authority = auth_str.to_string_lossy().to_string();
        let mut auth_remaining = authority;

        // Extract userinfo
        if let Some(pos) = auth_remaining.find('@') {
            let userinfo = auth_remaining[..pos].to_string();

            // Extract password from userinfo before moving
            if let Some(colon_pos) = userinfo.rfind(':') {
                parsed.set("user", userinfo[..colon_pos].to_string())?;
                parsed.set("password", userinfo[colon_pos + 1..].to_string())?;
            } else {
                parsed.set("user", userinfo.clone())?;
            }
            parsed.set("userinfo", userinfo)?;
            auth_remaining = auth_remaining[pos + 1..].to_string();
        }

        // Extract port
        if let Some(colon_pos) = auth_remaining.rfind(':') {
            let after_colon = &auth_remaining[colon_pos + 1..];
            if let Ok(port_num) = after_colon.parse::<u16>() {
                parsed.set("port", port_num)?;
                auth_remaining = auth_remaining[..colon_pos].to_string();
            }
        }

        // Host is whatever remains
        if !auth_remaining.is_empty() {
            parsed.set("host", auth_remaining.clone())?;

            // Convert to ASCII hostname using punycode
            if let Some(ascii_host) = ascii_hostname_str(&auth_remaining) {
                parsed.set("ascii_host", ascii_host)?;
            }
        }
    }

    Ok(parsed)
}

/// Build a URL from its components.
///
/// Takes a table with URL components and builds a URL string.
/// Components are percent-encoded if necessary.
///
/// # Arguments
///
/// * `parsed` - A Lua table containing URL components
///
/// # Errors
///
/// Returns an error if URL building fails.
///
/// # Returns
///
/// The built URL string
pub fn build(parsed: &Value) -> std::result::Result<String, String> {
    let Value::Table(table) = parsed else {
        return Err("Parsed URL must be a table".to_string());
    };

    let mut url = String::new();

    // Extract fields from the table
    let scheme: Option<String> = get_field_opt_string(table, "scheme")?;
    let host: Option<String> = get_field_opt_string(table, "host")?;
    let port: Option<u16> = get_field_opt_u16(table, "port")?;
    let user: Option<String> = get_field_opt_string(table, "user")?;
    let password: Option<String> = get_field_opt_string(table, "password")?;
    let userinfo: Option<String> = get_field_opt_string(table, "userinfo")?;
    let path: Option<String> = get_field_opt_string(table, "path")?;
    let params: Option<String> = get_field_opt_string(table, "params")?;
    let query: Option<String> = get_field_opt_string(table, "query")?;
    let fragment: Option<String> = get_field_opt_string(table, "fragment")?;

    // Build path
    let ppath = if let Some(p) = path {
        parse_path_impl(&p)
    } else {
        PathSegments::default()
    };
    let path_str = build_path_impl(&ppath, false);

    // Add params and query
    let mut path_with_params = path_str;
    if let Some(p) = params {
        path_with_params.push(';');
        path_with_params.push_str(&p);
    }
    if let Some(q) = query {
        path_with_params.push('?');
        path_with_params.push_str(&q);
    }

    // Build authority
    let final_authority = if let Some(h) = host {
        let mut auth = h.clone();
        if let Some(p) = port {
            auth.push(':');
            auth.push_str(&p.to_string());
        }

        let userinfo_str = if let Some(u) = user {
            let mut ui = u.clone();
            if let Some(pass) = &password {
                ui.push(':');
                ui.push_str(pass);
            }
            Some(ui)
        } else {
            userinfo
        };

        if let Some(ui) = userinfo_str {
            auth = format!("{ui}@{auth}");
        }

        Some(auth)
    } else {
        None
    };

    // Assemble URL
    if let Some(a) = final_authority {
        url.push_str("//");
        url.push_str(&a);
    }
    url.push_str(&path_with_params);

    if let Some(s) = scheme {
        url = format!("{s}:{url}");
    }

    if let Some(f) = fragment {
        url.push('#');
        url.push_str(&f);
    }

    Ok(url)
}

/// Build an absolute URL from a base and a relative URL.
///
/// Follows RFC 3986 section 5.2 for resolving relative URLs.
///
/// # Arguments
///
/// * `base` - The base URL (table or string)
/// * `relative` - The relative URL string
/// * `lua` - The Lua runtime
///
/// # Errors
///
/// Returns an error if URL resolution fails.
///
/// # Returns
///
/// The absolute URL string
pub fn absolute(base: Value, relative: &str, lua: &Lua) -> std::result::Result<String, String> {
    let base_table = if let Value::Table(t) = base {
        t
    } else {
        let base_str = value_to_string(&base)?;
        parse(&base_str, None, lua).map_err(|e| e.to_string())?
    };

    let relative_parsed = parse(relative, None, lua).map_err(|e| e.to_string())?;

    // If relative URL has a scheme, return as-is
    if has_field(&relative_parsed, "scheme") {
        return Ok(relative.to_string());
    }

    let result = lua.create_table().map_err(|e| e.to_string())?;

    // Copy scheme from base
    if let Some(scheme) = get_field_opt_string(&base_table, "scheme")? {
        result.set("scheme", scheme).map_err(|e| e.to_string())?;
    }

    // If relative has authority, use it
    let has_authority = has_field(&relative_parsed, "authority");
    if has_authority {
        copy_fields(
            &Value::Table(relative_parsed),
            &result,
            &["authority", "path", "params", "query", "fragment"],
        )?;
    } else {
        // Copy authority from base
        if let Some(auth) = get_field_opt_string(&base_table, "authority")? {
            result.set("authority", auth).map_err(|e| e.to_string())?;
        }

        let has_path = has_field(&relative_parsed, "path");
        if has_path {
            let base_path: Option<String> = get_field_opt_string(&base_table, "path")?;
            let rel_path: Option<String> = get_field_opt_string(&relative_parsed, "path")?;
            let abs_path = absolute_path(
                base_path.as_deref().unwrap_or(""),
                rel_path.as_deref().unwrap_or(""),
            );
            result.set("path", abs_path).map_err(|e| e.to_string())?;
        } else if let Some(p) = get_field_opt_string(&base_table, "path")? {
            result.set("path", p).map_err(|e| e.to_string())?;
        }

        // Copy params, query, fragment from base if not in relative
        let has_params = has_field(&relative_parsed, "params");
        if has_params {
            if let Some(p) = get_field_opt_string(&relative_parsed, "params")? {
                result.set("params", p).map_err(|e| e.to_string())?;
            }
        } else if let Some(p) = get_field_opt_string(&base_table, "params")? {
            result.set("params", p).map_err(|e| e.to_string())?;
        }

        let has_query = has_field(&relative_parsed, "query");
        if has_query {
            if let Some(q) = get_field_opt_string(&relative_parsed, "query")? {
                result.set("query", q).map_err(|e| e.to_string())?;
            }
        } else if let Some(q) = get_field_opt_string(&base_table, "query")? {
            result.set("query", q).map_err(|e| e.to_string())?;
        }
    }

    build(&Value::Table(result))
}

/// Parse a path into its segments.
///
/// Breaks a path into segments, unescaping each segment.
///
/// # Arguments
///
/// * `path` - The path to parse (optional)
/// * `lua` - The Lua runtime
///
/// # Errors
///
/// Returns an error if the path has too many segments.
///
/// # Returns
///
/// A Lua table with one entry per segment, plus `is_absolute` and `is_directory` flags
pub fn parse_path(path: Option<String>, lua: &Lua) -> mlua::Result<Table> {
    let parsed = lua.create_table()?;
    let path_str = path.unwrap_or_default();

    let mut index = 1_usize;
    for segment in path_str.split('/') {
        parsed.set(
            index,
            unescape(segment).unwrap_or_else(|_| segment.to_string()),
        )?;
        index = index
            .checked_add(1)
            .ok_or_else(|| mlua::Error::RuntimeError("Too many path segments".to_string()))?;
    }

    if path_str.starts_with('/') {
        parsed.set("is_absolute", 1)?;
    }
    if path_str.ends_with('/') {
        parsed.set("is_directory", 1)?;
    }

    Ok(parsed)
}

/// Build a path from segments.
///
/// Takes a table of path segments and builds a path string.
///
/// # Arguments
///
/// * `parsed` - A Lua table containing path segments
/// * `unsafe_flag` - If true, don't protect segments (don't escape)
/// * `lua` - The Lua runtime
///
/// # Errors
///
/// Returns an error if path building fails.
///
/// # Returns
///
/// The built path string
pub fn build_path(
    parsed: &Value,
    unsafe_flag: bool,
    _lua: &Lua,
) -> std::result::Result<String, String> {
    let Value::Table(table) = parsed else {
        return Ok(String::new());
    };

    let mut parts = Vec::new();

    // Check for is_absolute flag
    let is_absolute = if let Ok(Value::Integer(i)) = table.get("is_absolute") {
        i != 0
    } else {
        false
    };
    if is_absolute {
        parts.push("/".to_string());
    }

    // Collect segments (skip non-numeric keys like is_absolute, is_directory)
    let mut segments = Vec::new();
    for pair in table.pairs::<i64, Value>() {
        let (k, v) = pair.map_err(|e| e.to_string())?;
        // Skip negative keys and special marker keys
        if k <= 0 || k > 10000 {
            continue;
        }
        if let Value::String(s) = v {
            // k is checked to be > 0 and <= 10000, so it fits in usize
            #[expect(clippy::cast_sign_loss, reason = "k is validated to be positive")]
            #[expect(
                clippy::cast_possible_truncation,
                reason = "k is validated to be <= 10000"
            )]
            segments.push((k as usize, s.to_string_lossy().to_string()));
        }
    }

    // Sort by key to maintain order
    segments.sort_by_key(|(k, _)| *k);

    // Build path
    let n = segments.len();
    for (i, (_k, segment)) in segments.iter().enumerate() {
        if unsafe_flag {
            parts.push(segment.clone());
        } else {
            parts.push(protect_segment(segment));
        }

        // Add trailing slash for all but last, or for directory
        if i < n.saturating_sub(1) {
            parts.push("/".to_string());
        } else {
            let is_directory = if let Ok(Value::Integer(idx)) = table.get("is_directory") {
                idx != 0
            } else {
                false
            };
            if is_directory {
                parts.push("/".to_string());
            }
        }
    }

    Ok(parts.concat())
}

/// Parse a query string into name/value pairs.
///
/// Parses a query string like `name1=value1&name2=value2` into a table.
/// Handles HTML entities (`&amp;`, `&lt;`, `&gt;`) and URL decoding.
///
/// # Arguments
///
/// * `query` - The query string to parse
/// * `lua` - The Lua runtime
///
/// # Errors
///
/// Returns an error if table creation or setting values fails.
///
/// # Returns
///
/// A Lua table with name-value pairs
pub fn parse_query(query: &str, lua: &Lua) -> mlua::Result<Table> {
    let parsed = lua.create_table()?;

    // Handle HTML entities first
    let query = query
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (name, value) = if let Some(pos) = pair.find('=') {
            let name = unescape(&pair[..pos]).unwrap_or_else(|_| pair[..pos].to_string());
            let value = unescape(&pair[pos + 1..]).unwrap_or_else(|_| pair[pos + 1..].to_string());
            (name, value)
        } else {
            let name = unescape(pair).unwrap_or_else(|_| pair.to_string());
            (name, String::new())
        };

        parsed.set(name, value)?;
    }

    Ok(parsed)
}

/// Build a query string from a table.
///
/// Inverse of `parse_query`. Both parameter names and values are URL-encoded.
///
/// # Arguments
///
/// * `query` - A Lua table with name-value pairs
///
/// # Errors
///
/// Returns an error if query building fails.
///
/// # Returns
///
/// The query string (e.g., "name=value1&name2=value2")
pub fn build_query(query: &Value) -> std::result::Result<String, String> {
    let Value::Table(table) = query else {
        return Ok(String::new());
    };

    let mut parts = Vec::new();

    for pair in table.pairs::<String, Value>() {
        let (name, value) = pair.map_err(|e| e.to_string())?;
        let value_str = value_to_string(&value)?;
        parts.push(format!("{}={}", escape(&name), escape(&value_str)));
    }

    Ok(parts.join("&"))
}

/// Get the default port for a given scheme.
///
/// Returns the default port for common schemes:
/// - `http` -> 80
/// - `https` -> 443
///
/// # Arguments
///
/// * `scheme` - The URL scheme (e.g., "http", "https")
///
/// # Returns
///
/// The default port number, or `nil` if unknown
#[must_use]
pub fn get_default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme.and_then(|s| s.split(':').next()) {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

/// Get the default scheme for a given port.
///
/// Returns the default scheme for common ports:
/// - `80` -> "http"
/// - `443` -> "https"
///
/// # Arguments
///
/// * `port` - A port number (number or port table)
///
/// # Errors
///
/// Returns an error if the port value cannot be converted to a valid port number.
///
/// # Returns
///
/// The default scheme, or `nil` if unknown
pub fn get_default_scheme(port: &Value, lua: &Lua) -> mlua::Result<Value> {
    let port_num = if let Value::Integer(n) = port {
        u16::try_from(*n).unwrap_or(0)
    } else if let Value::Number(n) = port {
        // Convert f64 to u16 safely - value is already validated to be in range
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Value is validated to be in u16 range before cast"
        )]
        #[expect(
            clippy::cast_sign_loss,
            reason = "Value is validated to be non-negative"
        )]
        if *n >= 0.0 && *n <= u16::MAX.into() {
            *n as u16
        } else {
            0
        }
    } else if let Value::Table(t) = port {
        let num: mlua::Result<u16> = t.get("number");
        match num {
            Ok(n) => n,
            Err(_) => return Ok(Value::Nil),
        }
    } else {
        return Ok(Value::Nil);
    };

    match port_num {
        80 => Ok("http".into_lua(lua)?),
        443 => Ok("https".into_lua(lua)?),
        _ => Ok(Value::Nil),
    }
}

/// Convert a hostname to ASCII using Punycode.
///
/// If the hostname contains non-ASCII characters (international domain name),
/// converts it to Punycode representation.
///
/// # Arguments
///
/// * `host` - A hostname value (string or port table)
///
/// # Errors
///
/// Returns an error if hostname extraction or conversion fails.
///
/// # Returns
///
/// The ASCII hostname (Punycode-encoded if needed)
pub fn ascii_hostname(host: &Value) -> std::result::Result<String, String> {
    let hostname = if let Value::String(s) = host {
        s.to_string_lossy().to_string()
    } else if let Value::Table(t) = host {
        let host_str: mlua::Result<Option<String>> = t.get("host");
        match host_str.map_err(|e| e.to_string())? {
            Some(h) => h,
            None => return Err("No host field in table".to_string()),
        }
    } else {
        return Err("Invalid host type".to_string());
    };

    // Check if hostname contains non-ASCII characters
    if !hostname.bytes().all(|b| b.is_ascii()) {
        // Decode UTF-8 to string (hostname is valid UTF-8 since we got it from Lua)
        let decoded = hostname.clone();
        // Split by labels and convert each
        let labels: Vec<&str> = decoded.split('.').collect();
        let mut ascii_labels = Vec::new();
        for label in labels {
            if label.as_bytes().iter().any(|b| !b.is_ascii()) {
                let encoded = encode(label).map_err(|e| format!("punycode encode error: {e:?}"))?;
                ascii_labels.push(encoded);
            } else {
                ascii_labels.push(label.to_string());
            }
        }
        return Ok(ascii_labels.join("."));
    }

    Ok(hostname)
}

/// Internal: Convert hostname to ASCII using punycode.
#[must_use]
fn ascii_hostname_str(host: &str) -> Option<String> {
    if !host.bytes().all(|b| b.is_ascii()) {
        if let Ok(decoded) = String::from_utf8(host.to_string().into_bytes()) {
            let labels: Vec<&str> = decoded.split('.').collect();
            let mut ascii_labels = Vec::new();
            for label in labels {
                if label.as_bytes().iter().any(|b| !b.is_ascii()) {
                    if let Ok(encoded) = encode(label) {
                        ascii_labels.push(encoded);
                    } else {
                        return None;
                    }
                } else {
                    ascii_labels.push(label.to_string());
                }
            }
            return Some(ascii_labels.join("."));
        }
    }
    Some(host.to_string())
}

/// Protect a path segment (escape special characters).
///
/// Escapes characters that are not allowed in path segments.
#[must_use]
fn protect_segment(s: &str) -> String {
    s.chars().map(char_to_percent_encoded).collect()
}

/// Build absolute path from base and relative paths.
///
/// Follows RFC 3986 section 5.2 for path resolution.
#[must_use]
fn absolute_path(base_path: &str, relative_path: &str) -> String {
    // Apply fixdots: add trailing / to paths ending with . or ..
    // This normalizes trailing dot and dot-dot by ensuring the final /
    let fixdots = |s: &str| -> String {
        if s.ends_with("/.") {
            // /path/. -> /path/
            let base = &s[..s.len() - 1]; // Remove the "."
            if base.ends_with('/') {
                base.to_string()
            } else {
                format!("{base}/")
            }
        } else if s == "." {
            "./".to_string()
        } else if s.ends_with("/..") {
            // /path/.. -> /path/../
            let base = &s[..s.len() - 2]; // Remove the ".."
            if base.ends_with('/') {
                format!("{base}../")
            } else {
                format!("{base}/../")
            }
        } else if s == ".." {
            "../".to_string()
        } else {
            s.to_string()
        }
    };

    let mut path = relative_path.to_string();

    if !path.starts_with('/') {
        // Apply fixdots to base_path FIRST (Nmap's behavior)
        let fixed_base = fixdots(base_path);
        // Replace everything after the last / with relative path
        // Nmap's gsub("[^/]*$", ...) replaces the last segment
        if let Some(last_slash) = fixed_base.rfind('/') {
            path = format!("{}{}", &fixed_base[..=last_slash], relative_path);
        }
        // If no / in fixed_base, just use relative as-is
    }

    // Apply fixdots to the merged path
    let fixed_path = fixdots(&path);

    // Break into segments and process . and ..
    // Nmap's gmatch("[^/]*") matches zero or more non-/ characters, including empty
    let mut segs = Vec::new();
    for segment in fixed_path.split('/') {
        if segment == "." {
            // ignore . segments
        } else if segment == ".." {
            // remove previous segment
            let last_is_non_empty = segs.last().is_some_and(|s: &String| !s.is_empty());
            if !segs.is_empty() && (segs.len() > 1 || last_is_non_empty) {
                segs.pop();
            }
        } else {
            // add regular segment (including empty segments from //)
            segs.push(segment.to_string());
        }
    }

    segs.join("/")
}

/// Parse path into segments (internal representation).
#[must_use]
fn parse_path_impl(path: &str) -> PathSegments {
    let mut segments = PathSegments::default();
    for segment in path.split('/') {
        if !segment.is_empty() || path.starts_with('/') {
            segments
                .segments
                .push(unescape(segment).unwrap_or_else(|_| segment.to_string()));
        }
    }
    if path.starts_with('/') {
        segments.is_absolute = true;
    }
    if path.ends_with('/') {
        segments.is_directory = true;
    }
    segments
}

/// Build path from segments (internal).
#[must_use]
fn build_path_impl(parsed: &PathSegments, unsafe_flag: bool) -> String {
    let mut result = String::new();

    if parsed.is_absolute {
        result.push('/');
    }

    let n = parsed.segments.len();
    for (i, segment) in parsed.segments.iter().enumerate() {
        if unsafe_flag {
            result.push_str(segment);
        } else {
            result.push_str(&protect_segment(segment));
        }

        // Add slash between segments or at end for directories
        if i < n.saturating_sub(1) || parsed.is_directory {
            result.push('/');
        }
    }

    result
}

/// Copy fields from one table to another.
fn copy_fields(src: &Value, dst: &Table, fields: &[&str]) -> std::result::Result<(), String> {
    let Value::Table(src_table) = src else {
        return Ok(());
    };

    for field in fields {
        let value: Value = src_table.get(*field).map_err(|e| e.to_string())?;
        if !matches!(value, Value::Nil) {
            dst.set(*field, value).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

/// Convert a Value to String.
fn value_to_string(value: &Value) -> std::result::Result<String, String> {
    match value {
        Value::String(s) => Ok(s.to_string_lossy().to_string()),
        Value::Integer(n) => Ok(n.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Boolean(b) => Ok(b.to_string()),
        _ => Err("Cannot convert to string".to_string()),
    }
}

/// Check if a table has a specific field.
fn has_field(table: &Table, key: &str) -> bool {
    table
        .get::<Value>(key)
        .map(|v| !matches!(v, Value::Nil))
        .unwrap_or(false)
}

/// Get an optional string field from a table.
fn get_field_opt_string(table: &Table, key: &str) -> std::result::Result<Option<String>, String> {
    let value: Value = table.get(key).map_err(|e| e.to_string())?;
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        match value {
            Value::String(s) => Ok(Some(s.to_string_lossy().to_string())),
            Value::Integer(n) => Ok(Some(n.to_string())),
            Value::Number(n) => Ok(Some(n.to_string())),
            Value::Boolean(b) => Ok(Some(b.to_string())),
            _ => Err(format!("Invalid value type for field '{key}'")),
        }
    }
}

/// Get an optional u16 field from a table.
fn get_field_opt_u16(table: &Table, key: &str) -> std::result::Result<Option<u16>, String> {
    let value: Value = table.get(key).map_err(|e| e.to_string())?;
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        match value {
            Value::Integer(n) => {
                Ok(Some(u16::try_from(n).map_err(|_e| {
                    "Integer value too large for u16".to_string()
                })?))
            }
            Value::Number(n) => {
                // Convert f64 to u16 safely - value is already validated to be in range
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "Value is validated to be in u16 range before cast"
                )]
                #[expect(
                    clippy::cast_sign_loss,
                    reason = "Value is validated to be non-negative"
                )]
                if n >= 0.0 && n <= u16::MAX.into() {
                    Ok(Some(n as u16))
                } else {
                    Err("Number value out of range for u16".to_string())
                }
            }
            _ => Err(format!(
                "Invalid value type for field '{key}', expected number"
            )),
        }
    }
}

/// Internal representation of parsed path segments.
#[derive(Debug, Default, Clone)]
struct PathSegments {
    segments: Vec<String>,
    is_absolute: bool,
    is_directory: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape() {
        assert_eq!(escape("hello world"), "hello%20world");
        assert_eq!(escape("test@example.com"), "test@example.com"); // @ is allowed in RFC 3986
        assert_eq!(escape("a*b_c-d"), "a*b_c-d");
        assert_eq!(escape("test space"), "test%20space"); // space should be encoded
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescape("hello%20world").unwrap(), "hello world");
        assert_eq!(unescape("test%40example.com").unwrap(), "test@example.com");
        assert_eq!(unescape("abc").unwrap(), "abc");
    }

    #[test]
    fn test_get_default_port() {
        assert_eq!(get_default_port(Some("http")), Some(80));
        assert_eq!(get_default_port(Some("https")), Some(443));
        assert_eq!(get_default_port(Some("ftp")), None);
    }

    #[test]
    fn test_absolute_path() {
        // Test case 1: base = "/", relative = "relative"
        let result = absolute_path("/", "relative");
        assert_eq!(result, "/relative", "base='/', relative='relative'");

        // Test case 2: base = "/base/", relative = "relative"
        let result = absolute_path("/base/", "relative");
        assert_eq!(result, "/base/relative");

        // Test case 3: base = "/base/path", relative = "../other"
        // According to RFC 3986: merge gives "/base/../other", then .. removes "base"
        let result = absolute_path("/base/path", "../other");
        assert_eq!(result, "/other");

        // Test case 4: base = "/base/", relative = "."
        let result = absolute_path("/base/", ".");
        assert_eq!(result, "/base/");

        // Test case 5: base = "/base/", relative = ".."
        let result = absolute_path("/base/", "..");
        assert_eq!(result, "/");

        // Nmap compatibility tests from reference:
        // {'a',     '.',      ''    }
        let result = absolute_path("a", ".");
        assert_eq!(result, "");

        // {'/',     '..',     '/'   }
        let result = absolute_path("/", "..");
        assert_eq!(result, "/");

        // {'/../',  '..',     '/'   }
        let result = absolute_path("/../", "..");
        assert_eq!(result, "/");

        // {'a/..',  'b',      'b'   }
        let result = absolute_path("a/..", "b");
        assert_eq!(result, "b");

        // {'',      '/a/..',  '/'   }
        let result = absolute_path("", "/a/..");
        assert_eq!(result, "/");
    }

    #[test]
    fn test_ascii_hostname() {
        let lua = mlua::Lua::new();
        let s = lua.create_string("example.com").unwrap();
        let ascii = ascii_hostname(&Value::String(s)).unwrap();
        assert_eq!(ascii, "example.com");
    }
}
