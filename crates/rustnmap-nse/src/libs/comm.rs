//! Communication library (comm) for NSE.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::explicit_auto_deref,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unnecessary_wraps,
    reason = "NSE library implementation requires these patterns"
)]
//!
//! This module provides the `comm` library which contains network communication
//! functions for NSE scripts. It corresponds to Nmap's comm NSE library.
//!
//! # Available Functions
//!
//! - `comm.opencon(host, port, [opts])` - Open a TCP connection to host:port
//! - `comm.tryssl(host, port, [opts])` - Try to connect with SSL/TLS
//! - `comm.read_response(socket, [opts])` - Read banner/response from socket
//! - `comm.exchange(socket, data, [opts])` - Send data and receive response
//! - `comm.get_banner(host, port, [opts])` - Get service banner
//! - `comm.send_request(socket, request, [opts])` - Send HTTP request
//!
//! # Example Usage in Lua
//!
//! ```lua
//! -- Open a connection
//! local socket = comm.opencon(host, 80)
//! if socket then
//!     -- Send HTTP request
//!     local response = comm.send_request(socket, "GET / HTTP/1.0\r\n\r\n")
//!     socket:close()
//! end
//!
//! -- Get banner quickly
//! local banner = comm.get_banner(host, 22)
//! ```

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use mlua::{Table, UserData, UserDataMethods, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Default connection timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Default banner read timeout in milliseconds.
const DEFAULT_BANNER_TIMEOUT_MS: u64 = 5_000;

/// Socket wrapper for Lua userdata.
#[derive(Debug)]
pub struct NseSocket {
    /// The underlying TCP stream.
    stream: Option<TcpStream>,
    /// Connection timeout.
    timeout: Duration,
    /// Whether the socket uses SSL/TLS.
    is_ssl: bool,
    /// Remote address.
    peer_addr: SocketAddr,
}

impl NseSocket {
    /// Create a new socket from a TCP stream.
    fn new(stream: TcpStream, peer_addr: SocketAddr) -> Self {
        Self {
            stream: Some(stream),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            is_ssl: false,
            peer_addr,
        }
    }

    /// Check if the socket is connected.
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Send data over the socket.
    fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut stream) = self.stream {
            stream.write(data)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            ))
        }
    }

    /// Receive data from the socket.
    fn receive(&mut self, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            let mut buffer = vec![0u8; max_bytes];
            let n = stream.read(&mut buffer)?;
            buffer.truncate(n);
            Ok(buffer)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            ))
        }
    }

    /// Receive all available data until timeout or closure.
    fn receive_all(&mut self) -> std::io::Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            let mut result = Vec::new();
            let mut buffer = [0u8; 4096];

            stream.set_read_timeout(Some(self.timeout))?;

            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break, // Connection closed
                    Ok(n) => result.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(result)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            ))
        }
    }

    /// Close the socket.
    fn close(&mut self) -> std::io::Result<()> {
        if let Some(stream) = self.stream.take() {
            stream.shutdown(std::net::Shutdown::Both)?;
        }
        Ok(())
    }
}

impl UserData for NseSocket {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("is_connected", |_, this, ()| Ok(this.is_connected()));

        methods.add_method_mut("send", |_, this, data: mlua::String| {
            match this.send(&data.as_bytes()) {
                Ok(n) => Ok(Value::Integer(n as i64)),
                Err(e) => Err(mlua::Error::RuntimeError(format!("send failed: {e}"))),
            }
        });

        methods.add_method_mut("receive", |lua, this, max_bytes: Option<usize>| {
            let max = max_bytes.unwrap_or(4096);
            match this.receive(max) {
                Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
                Err(e) => Err(mlua::Error::RuntimeError(format!("receive failed: {e}"))),
            }
        });

        methods.add_method_mut("receive_all", |lua, this, ()| match this.receive_all() {
            Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
            Err(e) => Err(mlua::Error::RuntimeError(format!("receive failed: {e}"))),
        });

        methods.add_method_mut("close", |_, this, ()| match this.close() {
            Ok(()) => Ok(Value::Boolean(true)),
            Err(e) => Err(mlua::Error::RuntimeError(format!("close failed: {e}"))),
        });

        methods.add_method("get_peer_addr", |_, this, ()| {
            Ok(this.peer_addr.to_string())
        });

        methods.add_method("is_ssl", |_, this, ()| Ok(this.is_ssl));
    }
}

/// Parse connection options from Lua table.
fn parse_opts(opts: Option<Table>) -> mlua::Result<ConnectionOpts> {
    let mut options = ConnectionOpts::default();

    if let Some(opts) = opts {
        if let Ok(timeout) = opts.get("timeout") {
            let timeout: i64 = timeout;
            options.timeout = Duration::from_millis(timeout.max(0) as u64);
        }
        if let Ok(bytes) = opts.get("bytes") {
            let bytes: i64 = bytes;
            options.bytes = Some(bytes.max(0) as usize);
        }
        if let Ok(lines) = opts.get("lines") {
            let lines: i64 = lines;
            options.lines = Some(lines.max(0) as usize);
        }
        if let Ok(ssl) = opts.get("ssl") {
            let ssl: bool = ssl;
            options.ssl = ssl;
        }
        if let Ok(proto) = opts.get("proto") {
            let proto: String = proto;
            options.proto = proto;
        }
    }

    Ok(options)
}

/// Connection options.
#[derive(Debug, Clone)]
struct ConnectionOpts {
    /// Connection/read timeout.
    timeout: Duration,
    /// Number of bytes to read.
    bytes: Option<usize>,
    /// Number of lines to read.
    lines: Option<usize>,
    /// Use SSL/TLS.
    ssl: bool,
    /// Protocol ("tcp", "udp").
    proto: String,
}

impl Default for ConnectionOpts {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            bytes: None,
            lines: None,
            ssl: false,
            proto: "tcp".to_string(),
        }
    }
}

/// Open a connection to host:port.
fn opencon_impl(host: &str, port: u16, opts: ConnectionOpts) -> std::io::Result<NseSocket> {
    let addr = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "could not resolve address",
        ));
    }

    let stream = TcpStream::connect_timeout(&addrs[0], opts.timeout)?;
    stream.set_read_timeout(Some(opts.timeout))?;
    stream.set_write_timeout(Some(opts.timeout))?;

    let mut socket = NseSocket::new(stream, addrs[0]);

    if opts.ssl {
        // In a real implementation, this would wrap the stream with TLS
        // For now, we just mark it as SSL requested
        socket.is_ssl = true;
    }

    Ok(socket)
}

/// Get service banner from host:port.
fn get_banner_impl(host: &str, port: u16, opts: ConnectionOpts) -> std::io::Result<String> {
    let mut socket = opencon_impl(host, port, opts.clone())?;

    // Set a shorter timeout for banner grabbing
    let banner_timeout = Duration::from_millis(DEFAULT_BANNER_TIMEOUT_MS);

    if let Some(ref mut stream) = socket.stream {
        stream.set_read_timeout(Some(banner_timeout.min(opts.timeout)))?;

        let mut buffer = vec![0u8; opts.bytes.unwrap_or(1024)];
        let n = stream.read(&mut buffer)?;
        buffer.truncate(n);

        socket.close()?;

        // Try to convert to string, fall back to lossy conversion
        Ok(String::from_utf8_lossy(&buffer).to_string())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "socket not connected",
        ))
    }
}

/// Exchange data with host:port (send then receive).
fn exchange_impl(
    host: &str,
    port: u16,
    data: &[u8],
    opts: ConnectionOpts,
) -> std::io::Result<Vec<u8>> {
    let mut socket = opencon_impl(host, port, opts.clone())?;

    // Send data
    socket.send(data)?;

    // Receive response
    let result = if let Some(bytes) = opts.bytes {
        socket.receive(bytes)?
    } else {
        socket.receive_all()?
    };

    socket.close()?;

    Ok(result)
}

/// Read response from socket.
fn read_response_impl(socket: &mut NseSocket, opts: ConnectionOpts) -> std::io::Result<Vec<u8>> {
    if let Some(bytes) = opts.bytes {
        socket.receive(bytes)
    } else {
        socket.receive_all()
    }
}

/// Register the comm library with the Lua runtime.
///
/// # Arguments
///
/// * `nse_lua` - The NSE Lua runtime to register with
///
/// # Errors
///
/// Returns an error if registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the comm table
    let comm_table = lua.create_table()?;

    // Register opencon(host, port, [opts]) function
    let opencon_fn = lua.create_function(|lua, (host, port, opts): (String, u16, Option<Table>)| {
        let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

        match opencon_impl(&host, port, options) {
            Ok(socket) => Ok(Value::UserData(lua.create_userdata(socket)?)),
            Err(_e) => Ok(Value::Nil),
        }
    })?;
    comm_table.set("opencon", opencon_fn)?;

    // Register tryssl(host, port, [opts]) function
    let tryssl_fn = lua.create_function(|lua, (host, port, opts): (String, u16, Option<Table>)| {
        let mut options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        options.ssl = true;

        match opencon_impl(&host, port, options) {
            Ok(socket) => Ok(Value::UserData(lua.create_userdata(socket)?)),
            Err(_) => Ok(Value::Nil),
        }
    })?;
    comm_table.set("tryssl", tryssl_fn)?;

    // Register get_banner(host, port, [opts]) function
    let get_banner_fn = lua.create_function(
        |lua, (host, port, opts): (String, u16, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match get_banner_impl(&host, port, options) {
                Ok(banner) => Ok(Value::String(lua.create_string(&banner)?)),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
    comm_table.set("get_banner", get_banner_fn)?;

    // Register exchange(host, port, data, [opts]) function
    let exchange_fn = lua.create_function(
        |lua, (host, port, data, opts): (String, u16, mlua::String, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match exchange_impl(&host, port, &data.as_bytes(), options) {
                Ok(response) => Ok(Value::String(lua.create_string(&response)?)),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
    comm_table.set("exchange", exchange_fn)?;

    // Register read_response(socket, [opts]) function
    let read_response_fn =
        lua.create_function(|lua, (socket, opts): (mlua::AnyUserData, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            let mut socket_ref = socket.borrow_mut::<NseSocket>()?;

            match read_response_impl(&mut *socket_ref, options) {
                Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
                Err(_) => Ok(Value::Nil),
            }
        })?;
    comm_table.set("read_response", read_response_fn)?;

    // Register send_request(socket, request, [opts]) function
    let send_request_fn =
        lua.create_function(|lua, (socket, request, opts): (mlua::AnyUserData, mlua::String, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            let mut socket_ref = socket.borrow_mut::<NseSocket>()?;

            // Send the request
            if socket_ref.send(&request.as_bytes()).is_err() {
                return Ok(Value::Nil);
            }

            // Read the response
            match read_response_impl(&mut *socket_ref, options) {
                Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
                Err(_) => Ok(Value::Nil),
            }
        })?;
    comm_table.set("send_request", send_request_fn)?;

    // Set the comm table as a global
    lua.globals().set("comm", comm_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_comm_library() {
        let mut lua = NseLua::new_default().unwrap();
        let result = register(&mut lua);
        assert!(result.is_ok());

        // Check that comm table exists
        let comm: mlua::Table = lua.lua().globals().get("comm").unwrap();

        // Check that functions exist
        let _opencon_fn: mlua::Function = comm.get("opencon").unwrap();
    }

    #[test]
    fn test_parse_opts_default() {
        let _lua = NseLua::new_default().unwrap();
        let opts = parse_opts(None).unwrap();

        assert_eq!(opts.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(opts.bytes, None);
        assert_eq!(opts.lines, None);
        assert!(!opts.ssl);
        assert_eq!(opts.proto, "tcp");
    }

    #[test]
    fn test_parse_opts_custom() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("timeout", 5000i64).unwrap();
        table.set("bytes", 1024i64).unwrap();
        table.set("ssl", true).unwrap();
        table.set("proto", "udp").unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        assert_eq!(opts.timeout, Duration::from_millis(5000));
        assert_eq!(opts.bytes, Some(1024));
        assert!(opts.ssl);
        assert_eq!(opts.proto, "udp");
    }

    #[test]
    fn test_nse_socket_userdata() {
        let lua = NseLua::new_default().unwrap();

        // Create a mock socket (we can't actually connect in unit tests)
        // Just verify the userdata type is registered correctly
        let socket = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
        };

        let _ud = lua.lua().create_userdata(socket).unwrap();
    }

    #[test]
    fn test_connection_opts_default() {
        let opts = ConnectionOpts::default();
        assert_eq!(opts.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(opts.bytes, None);
        assert_eq!(opts.lines, None);
        assert!(!opts.ssl);
        assert_eq!(opts.proto, "tcp");
    }
}
