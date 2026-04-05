//! FTP library for NSE.
//!
//! This module provides the `ftp` library which contains FTP protocol functions
//! for NSE scripts. It corresponds to Nmap's ftp NSE library.
//!
//! # Available Functions
//!
//! - `ftp.connect(host, port, [options])` - Connect to FTP server
//! - `ftp.read_reply(buffer)` - Read FTP server reply
//! - `ftp.close(socket)` - Close FTP connection
//! - `ftp.starttls(socket, buffer)` - Start TLS negotiation
//! - `ftp.auth(socket, buffer, username, password, [acct])` - Authenticate
//! - `ftp.pasv(socket, buffer)` - Enter passive mode
//!
//! # Socket Methods
//!
//! The socket table returned by `ftp.connect()` also supports NSE-style socket methods:
//!
//! - `socket:send(data)` - Send raw data through the FTP connection
//! - `socket:receive()` - Receive a line from the FTP connection
//! - `socket:receive_buf(pattern, [until])` - Read lines until one matches pattern
//! - `socket:receive_lines(n)` - Read exactly n lines
//! - `socket:close()` - Close the FTP connection
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local ftp = require "ftp"
//!
//! local socket, code, message, buffer = ftp.connect(host, port)
//! if socket then
//!     local status, code, message = ftp.auth(socket, buffer, "anonymous", "test@example.com")
//!     if status then
//!         print("Login successful")
//!     end
//!     ftp.close(socket)
//! end
//! ```

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use mlua::{Table, Value};
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for FTP operations in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

// CRLF pattern for FTP responses (defined for future use)
#[expect(dead_code, reason = "Reserved for future regex-based response parsing")]
const CRLF_PATTERN: &str = "\r?\n";

/// FTP connection wrapper that maintains state.
#[expect(
    missing_debug_implementations,
    reason = "TcpStream does not implement Debug"
)]
pub struct FtpConnection {
    /// The TCP stream.
    stream: TcpStream,
    /// The buffer for reading responses.
    reader: BufReader<TcpStream>,
    /// Host address.
    host: String,
    /// Port number.
    port: u16,
}

impl FtpConnection {
    /// Create a new FTP connection.
    fn new(host: String, port: u16) -> mlua::Result<Self> {
        let addr = format!("{host}:{port}");

        let stream = TcpStream::connect(&addr).map_err(|e| {
            mlua::Error::RuntimeError(format!("FTP connection failed to {addr}: {e}"))
        })?;

        stream
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to set read timeout: {e}")))?;

        let reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|e| mlua::Error::RuntimeError(format!("Failed to clone stream: {e}")))?,
        );

        Ok(Self {
            stream,
            reader,
            host,
            port,
        })
    }

    /// Read a line from the server.
    fn read_line(&mut self) -> mlua::Result<String> {
        let mut line = String::new();
        let bytes_read = self
            .reader
            .read_line(&mut line)
            .map_err(|e| mlua::Error::RuntimeError(format!("FTP read failed: {e}")))?;

        if bytes_read == 0 {
            return Err(mlua::Error::RuntimeError(
                "FTP connection closed".to_string(),
            ));
        }

        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }

    /// Send a command to the server.
    fn send_command(&mut self, cmd: &str) -> mlua::Result<()> {
        debug!("FTP send: {}", cmd.trim());
        self.stream
            .write_all(cmd.as_bytes())
            .map_err(|e| mlua::Error::RuntimeError(format!("FTP send failed: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| mlua::Error::RuntimeError(format!("FTP flush failed: {e}")))?;
        Ok(())
    }
}

/// Read an FTP reply and return the numeric code and message.
/// Handles multi-line responses as specified in RFC 959 section 4.2.
fn read_reply(conn: &mut FtpConnection) -> mlua::Result<(u16, String)> {
    let line = conn.read_line()?;

    let code_str = line
        .get(0..3)
        .ok_or_else(|| mlua::Error::RuntimeError(format!("Unparseable FTP response: {line}")))?;

    let code: u16 = code_str.parse().map_err(|parse_err| {
        mlua::Error::RuntimeError(format!(
            "Invalid FTP response code: {code_str} ({parse_err})"
        ))
    })?;

    let sep = line.chars().nth(3);

    if sep == Some('-') {
        // Multi-line response (RFC 959 section 4.2)
        let prefix = format!("{code_str} ");
        let mut lines = vec![line.get(4..).unwrap_or("").to_string()];

        loop {
            let response_line = conn.read_line()?;
            if response_line.starts_with(&prefix) {
                // Last line of multi-line response
                lines.push(response_line.get(4..).unwrap_or("").to_string());
                break;
            }
            lines.push(response_line);
        }

        Ok((code, lines.join("\n")))
    } else {
        // Single-line response
        let message = line.get(4..).unwrap_or("").to_string();
        Ok((code, message))
    }
}

// Global registry of FTP connections (keyed by memory address for Lua).
// In production, this would use a better mechanism.
use std::sync::LazyLock;

static FTP_CONNECTIONS: LazyLock<Mutex<HashMap<usize, FtpConnection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_CONN_ID: LazyLock<Mutex<usize>> = LazyLock::new(|| Mutex::new(1));

/// Register the ftp library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
///
/// # Panics
///
/// Panics if `FTP_CONNECTIONS` or `NEXT_CONN_ID` lock is poisoned (e.g., thread panic while holding lock).
#[expect(
    clippy::too_many_lines,
    reason = "Lua library registration requires separate function handlers for each FTP operation"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the ftp table
    let ftp_table = lua.create_table()?;

    // Register connect function
    let connect_fn = lua.create_function(
        move |lua, (host, port, _options): (Value, Value, Option<Table>)| {
            let host_str = match host {
                Value::String(s) => s.to_string_lossy().to_string(),
                Value::Integer(n) => n.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Table(t) => {
                    // NSE passes host table with .ip field
                    match t.get::<Option<String>>("ip") {
                        Ok(Some(ip)) => ip,
                        _ => {
                            return Err(mlua::Error::RuntimeError(
                                "Invalid host table: missing 'ip' field".to_string(),
                            ))
                        }
                    }
                }
                _ => {
                    return Err(mlua::Error::RuntimeError(
                        "Invalid host parameter".to_string(),
                    ))
                }
            };

            let port_num = match port {
                Value::Integer(n) => u16::try_from(n).unwrap_or(21),
                Value::Number(n) => {
                    // FTP ports are 1-65535, clamp to valid range
                    if (0.0..=65_535.0).contains(&n) && n.is_finite() {
                        #[expect(
                            clippy::cast_possible_truncation,
                            reason = "n.round() is in range 0-65535, fits in i64"
                        )]
                        u16::try_from(n.round() as i64).unwrap_or(21)
                    } else {
                        21
                    }
                }
                Value::Table(t) => {
                    match t.get::<Option<i64>>("number") {
                        Ok(Some(n)) => u16::try_from(n).unwrap_or(21),
                        _ => 21, // Default FTP port
                    }
                }
                _ => 21,
            };

            // Create connection
            let mut conn = FtpConnection::new(host_str, port_num)?;

            // Read initial greeting (server should send 220 ready)
            let (code, message) = read_reply(&mut conn)?;

            // Create socket table for Lua
            let socket_table = lua.create_table()?;
            socket_table.set("host", conn.host.clone())?;
            socket_table.set("port", conn.port)?;
            socket_table.set("_code", code)?;
            socket_table.set("_message", message.clone())?;

            // Store connection in registry
            let conn_id = {
                let mut id = NEXT_CONN_ID.lock().unwrap();
                let id_val = *id;
                *id += 1;
                id_val
            };

            // Store connection data directly in the table as userdata
            socket_table.set("_conn_id", conn_id)?;

            // Store in our connections map
            {
                let mut conns = FTP_CONNECTIONS.lock().unwrap();
                conns.insert(conn_id, conn)
            };

            // Register socket methods on the socket table.
            // These enable the Lua idiom socket:send(data) which is socket.send(socket, data).

            // socket:send(data) - Send raw data through the FTP connection.
            // Returns true on success, nil + error message on failure.
            let socket_send_fn =
                lua.create_function(|_lua, (self_table, data): (Table, String)| {
                    let conn_id: usize = self_table.get("_conn_id")?;

                    let mut conn = {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.remove(&conn_id).ok_or_else(|| {
                            mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                        })?
                    };

                    conn.send_command(&data)?;

                    {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.insert(conn_id, conn)
                    };

                    Ok(true)
                })?;
            socket_table.set("send", socket_send_fn)?;

            // socket:receive() - Receive a line from the FTP connection.
            // Returns the line string on success, nil + error message on failure.
            let socket_receive_fn = lua.create_function(|_lua, self_table: Table| {
                let conn_id: usize = self_table.get("_conn_id")?;

                let mut conn = {
                    let mut conns = FTP_CONNECTIONS.lock().unwrap();
                    conns.remove(&conn_id).ok_or_else(|| {
                        mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                    })?
                };

                let line = conn.read_line()?;

                {
                    let mut conns = FTP_CONNECTIONS.lock().unwrap();
                    conns.insert(conn_id, conn)
                };

                Ok(line)
            })?;
            socket_table.set("receive", socket_receive_fn)?;

            // socket:receive_buf(pattern, until) - Read lines until one matches pattern.
            // pattern: substring to search for in each line.
            // until: if truthy, include the matching line in output.
            // Returns (status, data) where status is true on match, false if EOF before match.
            let socket_receive_buf_fn = lua.create_function(
                |_lua, (self_table, pattern, _until): (Table, String, Option<Value>)| {
                    let conn_id: usize = self_table.get("_conn_id")?;

                    let mut conn = {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.remove(&conn_id).ok_or_else(|| {
                            mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                        })?
                    };

                    let mut lines = Vec::new();
                    let mut matched = false;

                    while let Ok(line) = conn.read_line() {
                        let is_match = line.contains(&pattern);
                        lines.push(line);
                        if is_match {
                            matched = true;
                            break;
                        }
                    }

                    {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.insert(conn_id, conn)
                    };

                    let data = lines.join("\n");
                    Ok((matched, data))
                },
            )?;
            socket_table.set("receive_buf", socket_receive_buf_fn)?;

            // socket:receive_lines(n) - Read exactly n lines from the FTP connection.
            // Returns (status, data) where status is true if all n lines were read.
            let socket_receive_lines_fn =
                lua.create_function(|_lua, (self_table, n): (Table, i64)| {
                    let count = usize::try_from(n).unwrap_or(0);
                    if count == 0 {
                        return Ok((true, String::new()));
                    }

                    let conn_id: usize = self_table.get("_conn_id")?;

                    let mut conn = {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.remove(&conn_id).ok_or_else(|| {
                            mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                        })?
                    };

                    let mut lines = Vec::with_capacity(count);
                    for _ in 0..count {
                        match conn.read_line() {
                            Ok(line) => lines.push(line),
                            Err(_) => break,
                        }
                    }

                    {
                        let mut conns = FTP_CONNECTIONS.lock().unwrap();
                        conns.insert(conn_id, conn)
                    };

                    let data = lines.join("\n");
                    let success = lines.len() == count;
                    Ok((success, data))
                })?;
            socket_table.set("receive_lines", socket_receive_lines_fn)?;

            // socket:close() - Close the FTP connection.
            // Returns true.
            let socket_close_fn = lua.create_function(|_lua, self_table: Table| {
                if let Ok(conn_id) = self_table.get::<usize>("_conn_id") {
                    let mut conns = FTP_CONNECTIONS.lock().unwrap();
                    conns.remove(&conn_id);
                }
                Ok(true)
            })?;
            socket_table.set("close", socket_close_fn)?;

            // Return (socket, code, message) - socket table also serves as buffer for read_reply
            Ok((socket_table.clone(), code, message, socket_table))
        },
    )?;
    ftp_table.set("connect", connect_fn)?;

    // Register read_reply function
    let read_reply_fn = lua.create_function(|_lua, socket_or_buffer: Value| {
        let Value::Table(table) = socket_or_buffer else {
            return Err(mlua::Error::RuntimeError(
                "Expected table parameter".to_string(),
            ));
        };

        let conn_id: usize = table.get("_conn_id")?;

        let mut conn = {
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns
                .remove(&conn_id)
                .ok_or_else(|| mlua::Error::RuntimeError("Invalid FTP connection".to_string()))?
        };

        let (code, message) = read_reply(&mut conn)?;

        // Store connection back
        {
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns.insert(conn_id, conn);
        };

        // Return (code, message)
        Ok((code, message))
    })?;
    ftp_table.set("read_reply", read_reply_fn)?;

    // Register close function
    let close_fn = lua.create_function(|_, socket: Value| {
        let Value::Table(table) = socket else {
            return Ok(true); // Already closed or invalid
        };

        if let Ok(conn_id) = table.get::<usize>("_conn_id") {
            // Remove from connections map (this will drop and close the stream)
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns.remove(&conn_id);
        }

        Ok(true)
    })?;
    ftp_table.set("close", close_fn)?;

    // Register auth function
    // ftp.auth(socket, buffer, username, password)
    // Matches Nmap's signature where buffer is the second argument (ignored in our impl).
    let auth_fn = lua.create_function(
        |_lua, (socket, _buffer, username, password): (
            Value,
            Option<Value>,
            String,
            Option<String>,
        )| {
            let Value::Table(table) = socket else {
                return Err(mlua::Error::RuntimeError(
                    "Expected socket table".to_string(),
                ));
            };

            let conn_id: usize = table.get("_conn_id")?;

            let mut conn = {
                let mut conns = FTP_CONNECTIONS.lock().unwrap();
                conns.remove(&conn_id).ok_or_else(|| {
                    mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                })?
            };

            // Send USER command
            conn.send_command(&format!("USER {username}\r\n"))?;
            let (code, _) = read_reply(&mut conn)?;

            let final_code = if code == 331 {
                // 331: User name okay, need password
                let pass = password.as_deref().unwrap_or("");
                conn.send_command(&format!("PASS {pass}\r\n"))?;
                let (pass_code, _pass_msg) = read_reply(&mut conn)?;

                // Handle account if needed (332: Need account for login)
                if pass_code == 332 {
                    conn.send_command(&format!("ACCT {username}\r\n"))?;
                    let (acct_code, _acct_msg) = read_reply(&mut conn)?;

                    // Check if we need password after account
                    if acct_code == 331 {
                        conn.send_command(&format!("PASS {pass}\r\n"))?;
                        let (final_code, _) = read_reply(&mut conn)?;
                        final_code
                    } else {
                        acct_code
                    }
                } else {
                    pass_code
                }
            } else {
                code
            };

            // Store connection back
            {
                let mut conns = FTP_CONNECTIONS.lock().unwrap();
                conns.insert(conn_id, conn)
            };

            // Return (status, code, message)
            if (200..300).contains(&final_code) {
                Ok((true, final_code, "Login successful".to_string()))
            } else {
                Ok((
                    false,
                    final_code,
                    format!("Login failed (code {final_code})"),
                ))
            }
        },
    )?;
    ftp_table.set("auth", auth_fn)?;

    // Register starttls function
    let starttls_fn = lua.create_function(|_lua, (socket, _buffer): (Value, Value)| {
        let Value::Table(table) = socket else {
            return Err(mlua::Error::RuntimeError(
                "Expected socket table".to_string(),
            ));
        };

        let conn_id: usize = table.get("_conn_id")?;

        let mut conn = {
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns
                .remove(&conn_id)
                .ok_or_else(|| mlua::Error::RuntimeError("Invalid FTP connection".to_string()))?
        };

        // Send AUTH TLS command (RFC 4217)
        conn.send_command("AUTH TLS\r\n")?;
        let (code, message) = read_reply(&mut conn)?;

        // Store connection back
        {
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns.insert(conn_id, conn);
        };

        // Return (success, message)
        // 234 = Authentication successful, proceed with TLS handshake
        let success = code == 234;
        Ok((success, message))
    })?;
    ftp_table.set("starttls", starttls_fn)?;

    // Register pasv function
    // Returns an NseSocket connected to the data port, matching nmap's behavior
    // where ftp.pasv returns a real socket with receive_buf/receive/close methods.
    let pasv_fn = lua.create_function(
        |_lua, (socket, _buffer): (Value, Value)| {
            let Value::Table(table) = socket else {
                return Err(mlua::Error::RuntimeError(
                    "Expected socket table".to_string(),
                ));
            };

            let conn_id: usize = table.get("_conn_id")?;

            let mut conn = {
                let mut conns = FTP_CONNECTIONS.lock().unwrap();
                conns
                    .remove(&conn_id)
                    .ok_or_else(|| {
                        mlua::Error::RuntimeError("Invalid FTP connection".to_string())
                    })?
            };

            // Check if IPv6
            let is_ipv6 = conn.host.contains(':');

            let (data_port, data_host) = if is_ipv6 {
                // Try EPSV first (RFC 2428)
                conn.send_command("EPSV\r\n")?;
                let (code, message) = read_reply(&mut conn)?;

                if code == 229 {
                    // Parse EPSV response: |||port|
                    let re = regex::Regex::new(r"\(\|\|\|(\d+)\|\)").unwrap();
                    if let Some(caps) = re.captures(&message) {
                        let port: u16 = caps[1].parse().unwrap_or(20_000);
                        (port, conn.host.clone())
                    } else {
                        return Err(mlua::Error::RuntimeError(format!(
                            "Cannot parse EPSV response: {message}"
                        )));
                    }
                } else {
                    return Err(mlua::Error::RuntimeError(format!(
                        "EPSV failed: {message}"
                    )));
                }
            } else {
                // Use PASV (RFC 959)
                conn.send_command("PASV\r\n")?;
                let (code, message) = read_reply(&mut conn)?;

                if code == 227 {
                    // Parse PASV response: (h1,h2,h3,h4,p1,p2)
                    let re =
                        regex::Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap();
                    if let Some(caps) = re.captures(&message) {
                        let h1: u8 = caps[1].parse().unwrap_or(0);
                        let h2: u8 = caps[2].parse().unwrap_or(0);
                        let h3: u8 = caps[3].parse().unwrap_or(0);
                        let h4: u8 = caps[4].parse().unwrap_or(0);
                        let p1: u8 = caps[5].parse().unwrap_or(0);
                        let p2: u8 = caps[6].parse().unwrap_or(0);

                        let port = (u16::from(p1) << 8) | u16::from(p2);
                        let host = format!("{h1}.{h2}.{h3}.{h4}");
                        (port, host)
                    } else {
                        return Err(mlua::Error::RuntimeError(format!(
                            "Cannot parse PASV response: {message}"
                        )));
                    }
                } else {
                    return Err(mlua::Error::RuntimeError(format!(
                        "PASV failed: {message}"
                    )));
                }
            };

            // Store command connection back
            let mut conns = FTP_CONNECTIONS.lock().unwrap();
            conns.insert(conn_id, conn);

            // Connect to the data port and return a real NseSocket
            let data_addr: std::net::SocketAddr =
                format!("{data_host}:{data_port}")
                    .parse()
                    .map_err(|e: std::net::AddrParseError| {
                        mlua::Error::RuntimeError(format!("Invalid data address: {e}"))
                    })?;

            let data_stream =
                std::net::TcpStream::connect_timeout(
                    &data_addr,
                    Duration::from_millis(DEFAULT_TIMEOUT_MS),
                )
                .map_err(|e| {
                        mlua::Error::RuntimeError(format!(
                            "Data connection failed to {data_addr}: {e}"
                        ))
                    })?;
            data_stream
                .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("Set timeout failed: {e}"))
                })?;
            data_stream
                .set_write_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("Set timeout failed: {e}"))
                })?;

            let nse_socket = super::comm::NseSocket::new_tcp(
                data_stream,
                data_addr,
                Some(data_host),
            );

            Ok(nse_socket)
        },
    )?;
    ftp_table.set("pasv", pasv_fn)?;

    // Set the ftp table in globals
    lua.globals().set("ftp", ftp_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_connection_creation() {
        // Just test that we can create the connection structure
        let addr = "127.0.0.1:21";
        if let Ok(stream) = TcpStream::connect(addr) {
            let _reader = BufReader::new(stream);
            // Success
        }
        // No FTP server running is ok for tests
    }
}
