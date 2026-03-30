//! Communication library (comm) for NSE.
//!
//! This module provides the `comm` library which contains network communication
//! functions for NSE scripts. It corresponds to Nmap's comm NSE library.
//!
//! # Available Functions
//!
//! - `comm.opencon(host, port, [opts])` - Open a TCP connection to host:port
//! - `comm.tryssl(host, port, [data], [opts])` - Try to connect with SSL/TLS, optionally send data
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
    /// Original hostname for SNI (Server Name Indication).
    hostname: Option<String>,
}

impl NseSocket {
    /// Create a new socket from a TCP stream.
    fn new(stream: TcpStream, peer_addr: SocketAddr, hostname: Option<String>) -> Self {
        Self {
            stream: Some(stream),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            is_ssl: false,
            peer_addr,
            hostname,
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

#[expect(
    clippy::cast_possible_wrap,
    reason = "usize to i64 cast for Lua FFI; truncation impossible on 64-bit systems"
)]
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

        // get_ssl_certificate() -> certificate_table
        //
        // Performs a TLS handshake on a new connection to the same peer and
        // returns the SSL/TLS certificate. The returned table contains:
        // - pem: PEM-encoded certificate
        // - subject: Subject distinguished name
        // - issuer: Issuer distinguished name
        // - serial: Serial number
        // - fingerprint: SHA256 fingerprint
        // - pubkey: Public key info table (type, bits)
        // - notbefore: Validity start (ISO 8601)
        // - notafter: Validity end (ISO 8601)
        methods.add_method_mut("get_ssl_certificate", |lua, this, ()| {
            // Check if this socket was opened with SSL
            if !this.is_ssl {
                return Ok(Value::Nil);
            }

            // Use stored hostname or fall back to IP for SNI
            let hostname = this
                .hostname
                .clone()
                .unwrap_or_else(|| this.peer_addr.ip().to_string());

            // Perform a new TLS connection to retrieve the peer certificate DER
            let cert_der = tls_connect_and_get_cert(&hostname, this.peer_addr)?;

            // Parse DER into an X509 object and build the certificate table
            // using the shared implementation (includes ecdhparams for EC keys)
            let cert = openssl::x509::X509::from_der(&cert_der).map_err(|e| {
                mlua::Error::RuntimeError(format!("Failed to parse certificate: {e}"))
            })?;
            let cert_table = super::ssl::build_cert_table(lua, &cert)?;

            Ok(Value::Table(cert_table))
        });
    }
}

/// Parse connection options from Lua table.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::unnecessary_wraps,
    reason = "Lua numbers are i64; clamped casts to usize/u64 are safe; Result required for Lua API consistency"
)]
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
            if proto == "ssl" {
                options.ssl = true;
            }
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
fn opencon_impl(host: &str, port: u16, opts: &ConnectionOpts, sni_hostname: Option<&str>) -> std::io::Result<NseSocket> {
    // Use block_in_place to yield to the async runtime during blocking network operations
    tokio::task::block_in_place(|| {
        let mut socket = opencon_impl_blocking(host, port, opts)?;
        socket.hostname = Some(sni_hostname.unwrap_or(host).to_string());
        Ok(socket)
    })
}/// Blocking implementation of TCP connection.
///
/// This function performs the actual blocking DNS resolution and TCP connection.
/// It is called within `block_in_place` to avoid blocking the async runtime.
fn opencon_impl_blocking(
    host: &str,
    port: u16,
    opts: &ConnectionOpts,
) -> std::io::Result<NseSocket> {
    let addr = format!("{host}:{port}");
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

    let mut socket = NseSocket::new(stream, addrs[0], Some(host.to_string()));

    if opts.ssl {
        // Mark the socket as SSL requested
        // Full TLS/SSL implementation would wrap the stream with native_tls or rustls
        socket.is_ssl = true;
    }

    Ok(socket)
}

/// Get service banner from host:port.
fn get_banner_impl(host: &str, port: u16, opts: &ConnectionOpts) -> std::io::Result<String> {
    let mut socket = opencon_impl(host, port, opts, None)?;

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
    opts: &ConnectionOpts,
) -> std::io::Result<Vec<u8>> {
    let mut socket = opencon_impl(host, port, opts, None)?;

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
fn read_response_impl(socket: &mut NseSocket, opts: &ConnectionOpts) -> std::io::Result<Vec<u8>> {
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
#[expect(
    clippy::too_many_lines,
    reason = "Register function contains multiple Lua bindings"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the comm table
    let comm_table = lua.create_table()?;

    // Register opencon(host, port, [data], [opts]) function
    //
    // Accepts host as string or table (with host.ip), port as number or table (with port.number),
    // optional data string to send after connection, and optional opts table.
    // Matches Nmap's comm.opencon signature: opencon(host, port, data, opts)
    let opencon_fn = lua.create_function(
        |lua, (host_param, port_param, _data, opts): (Value, Value, Option<mlua::String>, Option<Table>)| {
            // Extract host string from either string or host table
            let host = match &host_param {
                Value::String(s) => s.to_str()?.to_string(),
                Value::Table(t) => {
                    let ip: Value = t.get("ip").map_err(|e| {
                        mlua::Error::RuntimeError(format!("host table missing 'ip' field: {e}"))
                    })?;
                    match ip {
                        Value::String(s) => s.to_str()?.to_string(),
                        other => {
                            return Err(mlua::Error::RuntimeError(format!(
                                "host.ip must be a string, got: {:?}",
                                other.type_name()
                            )));
                        }
                    }
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "host must be a string or table, got: {:?}",
                        other.type_name()
                    )));
                }
            };

            // Extract SNI hostname from host table (targetname or name field)
            let sni_hostname: Option<String> = match &host_param {
                Value::Table(t) => t
                    .get::<Option<String>>("targetname")
                    .ok()
                    .flatten()
                    .or_else(|| t.get::<Option<String>>("name").ok().flatten()),
                _ => None,
            };

            // Extract port number from either integer or port table
            let port = match port_param {
                Value::Integer(n) => u16::try_from(n).map_err(|e| {
                    mlua::Error::RuntimeError(format!("port number out of range: {e}"))
                })?,
                Value::Table(ref t) => {
                    let number: i64 = t.get("number").map_err(|e| {
                        mlua::Error::RuntimeError(format!("port table missing 'number' field: {e}"))
                    })?;
                    u16::try_from(number).map_err(|e| {
                        mlua::Error::RuntimeError(format!("port.number out of range: {e}"))
                    })?
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "port must be a number or table, got: {:?}",
                        other.type_name()
                    )));
                }
            };

            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match opencon_impl(&host, port, &options, sni_hostname.as_deref()) {
                Ok(socket) => {
                    // NSE returns: socket, nil (or just socket)
                    let socket_val = Value::UserData(lua.create_userdata(socket)?);
                    Ok(mlua::MultiValue::from_vec(vec![socket_val, Value::Nil]))
                }
                Err(e) => {
                    // NSE returns: nil, error_message
                    Ok(mlua::MultiValue::from_vec(vec![
                        Value::Nil,
                        Value::String(lua.create_string(format!("{e}"))?),
                    ]))
                }
            }
        },
    )?;
    comm_table.set("opencon", opencon_fn)?;

    // Register tryssl(host, port, [data], [opts]) function
    // Accepts host as string or table (with host.ip), port as number or table (with port.number),
    // optional data string to send after connection, and optional opts table
    let tryssl_fn = lua.create_function(
        |lua,
         (host_param, port_param, data_param, opts): (
            Value,
            Value,
            Option<mlua::String>,
            Option<Table>,
        )| {
            // Extract host string from either string or host table
            let host = match &host_param {
                Value::String(s) => s.to_str()?.to_string(),
                Value::Table(t) => {
                    let ip: Value = t.get("ip").map_err(|e| {
                        mlua::Error::RuntimeError(format!("host table missing 'ip' field: {e}"))
                    })?;
                    match ip {
                        Value::String(s) => s.to_str()?.to_string(),
                        other => {
                            return Err(mlua::Error::RuntimeError(format!(
                                "host.ip must be a string, got: {:?}",
                                other.type_name()
                            )));
                        }
                    }
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "host must be a string or table, got: {:?}",
                        other.type_name()
                    )));
                }
            };

            // Extract SNI hostname from host table (targetname or name field)
            let sni_hostname: Option<String> = match &host_param {
                Value::Table(t) => t
                    .get::<Option<String>>("targetname")
                    .ok()
                    .flatten()
                    .or_else(|| t.get::<Option<String>>("name").ok().flatten()),
                _ => None,
            };

            // Extract port number from either integer or port table
            let port = match port_param {
                Value::Integer(n) => u16::try_from(n).map_err(|e| {
                    mlua::Error::RuntimeError(format!("port number out of range: {e}"))
                })?,
                Value::Table(ref t) => {
                    let number: i64 = t.get("number").map_err(|e| {
                        mlua::Error::RuntimeError(format!("port table missing 'number' field: {e}"))
                    })?;
                    u16::try_from(number).map_err(|e| {
                        mlua::Error::RuntimeError(format!("port.number out of range: {e}"))
                    })?
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "port must be a number or table, got: {:?}",
                        other.type_name()
                    )));
                }
            };

            let mut options =
                parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            options.ssl = true;

            match opencon_impl(&host, port, &options, sni_hostname.as_deref()) {
                Ok(mut socket) => {
                    // Determine protocol string
                    let proto = if socket.is_ssl { "ssl" } else { "tcp" };

                    // If data is provided, send it and read response
                    // Nmap's tryssl returns: socket, response, proto, early_response
                    let response: Option<Vec<u8>> = if let Some(ref data) = data_param {
                        if socket.send(&data.as_bytes()).is_err() {
                            return Ok(mlua::MultiValue::new()); // Return empty on error
                        }
                        // Read response after sending data
                        read_response_impl(&mut socket, &options).ok()
                    } else {
                        None
                    };

                    // Return multiple values: socket, response, proto, early_response (nil)
                    // Nmap scripts expect: local socket, response = comm.tryssl(...)
                    let socket_val = Value::UserData(lua.create_userdata(socket)?);
                    let response_val = match response {
                        Some(ref r) => {
                            let s = String::from_utf8_lossy(r).into_owned();
                            Value::String(lua.create_string(&s)?)
                        }
                        None => Value::Nil,
                    };
                    let proto_val = Value::String(lua.create_string(proto)?);

                    Ok(mlua::MultiValue::from_vec(vec![
                        socket_val,
                        response_val,
                        proto_val,
                        Value::Nil, // early_response not implemented
                    ]))
                }
                Err(_) => Ok(mlua::MultiValue::new()), // Return empty MultiValue on error
            }
        },
    )?;
    comm_table.set("tryssl", tryssl_fn)?;

    // Register get_banner(host, port, [opts]) function
    let get_banner_fn =
        lua.create_function(|lua, (host, port, opts): (String, u16, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match get_banner_impl(&host, port, &options) {
                Ok(banner) => Ok(Value::String(lua.create_string(&banner)?)),
                Err(_) => Ok(Value::Nil),
            }
        })?;
    comm_table.set("get_banner", get_banner_fn)?;

    // Register exchange(host, port, data, [opts]) function
    let exchange_fn = lua.create_function(
        |lua, (host, port, data, opts): (String, u16, mlua::String, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match exchange_impl(&host, port, &data.as_bytes(), &options) {
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

            match read_response_impl(&mut socket_ref, &options) {
                Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
                Err(_) => Ok(Value::Nil),
            }
        })?;
    comm_table.set("read_response", read_response_fn)?;

    // Register send_request(socket, request, [opts]) function
    let send_request_fn = lua.create_function(
        |lua, (socket, request, opts): (mlua::AnyUserData, mlua::String, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            let mut socket_ref = socket.borrow_mut::<NseSocket>()?;

            // Send the request
            if socket_ref.send(&request.as_bytes()).is_err() {
                return Ok(Value::Nil);
            }

            // Read the response
            match read_response_impl(&mut socket_ref, &options) {
                Ok(data) => Ok(Value::String(lua.create_string(&data)?)),
                Err(_) => Ok(Value::Nil),
            }
        },
    )?;
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
        result.unwrap();

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
            hostname: None,
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

    #[test]
    fn test_parse_opts_with_lines() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("lines", 10i64).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        assert_eq!(opts.lines, Some(10));
    }

    #[test]
    fn test_parse_opts_zero_timeout() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("timeout", 0i64).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        assert_eq!(opts.timeout, Duration::from_millis(0));
    }

    #[test]
    fn test_parse_opts_negative_values() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("timeout", -1000i64).unwrap();
        table.set("bytes", -500i64).unwrap();
        table.set("lines", -5i64).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        // Negative values should be clamped to 0
        assert_eq!(opts.timeout, Duration::from_millis(0));
        assert_eq!(opts.bytes, Some(0));
        assert_eq!(opts.lines, Some(0));
    }

    #[test]
    fn test_nse_socket_with_ssl() {
        let lua = NseLua::new_default().unwrap();

        let socket = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: true,
            peer_addr: "127.0.0.1:443".parse().unwrap(),
            hostname: None,
        };

        let _ud = lua.lua().create_userdata(socket).unwrap();
    }

    #[test]
    fn test_nse_socket_different_addresses() {
        let lua = NseLua::new_default().unwrap();

        // IPv4 address
        let socket_v4 = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "192.168.1.1:80".parse().unwrap(),
            hostname: None,
        };
        let _ud = lua.lua().create_userdata(socket_v4).unwrap();

        // IPv6 loopback
        let socket_v6 = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "[::1]:8080".parse().unwrap(),
            hostname: None,
        };
        let _ud = lua.lua().create_userdata(socket_v6).unwrap();
    }

    #[test]
    fn test_connection_opts_clone() {
        let opts = ConnectionOpts {
            timeout: Duration::from_secs(10),
            bytes: Some(2048),
            lines: Some(5),
            ssl: true,
            proto: "udp".to_string(),
        };

        let cloned = opts.clone();
        assert_eq!(opts.timeout, cloned.timeout);
        assert_eq!(opts.bytes, cloned.bytes);
        assert_eq!(opts.lines, cloned.lines);
        assert_eq!(opts.ssl, cloned.ssl);
        assert_eq!(opts.proto, cloned.proto);
    }

    #[test]
    fn test_nse_socket_debug() {
        let socket = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
            hostname: None,
        };

        let debug_str = format!("{socket:?}");
        assert!(debug_str.contains("NseSocket"));
    }

    #[test]
    fn test_connection_opts_debug() {
        let opts = ConnectionOpts::default();
        let debug_str = format!("{opts:?}");
        assert!(debug_str.contains("ConnectionOpts"));
    }

    #[test]
    fn test_register_comm_all_functions() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let comm: mlua::Table = lua.lua().globals().get("comm").unwrap();

        // Verify all functions are registered
        let _opencon: mlua::Function = comm.get("opencon").unwrap();
        let _tryssl: mlua::Function = comm.get("tryssl").unwrap();
        let _get_banner: mlua::Function = comm.get("get_banner").unwrap();
        let _exchange: mlua::Function = comm.get("exchange").unwrap();
        let _read_response: mlua::Function = comm.get("read_response").unwrap();
        let _send_request: mlua::Function = comm.get("send_request").unwrap();
    }

    #[test]
    fn test_nse_socket_is_connected() {
        let socket = NseSocket {
            stream: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
            hostname: None,
        };

        assert!(!socket.is_connected());
    }

    #[test]
    fn test_parse_opts_partial() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        // Only set some options
        table.set("ssl", true).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        // Defaults should be preserved for unset options
        assert_eq!(opts.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert!(opts.lines.is_none());
        assert!(opts.ssl);
    }
}

// ---------------------------------------------------------------------------
// SSL Certificate Helper Functions
// ---------------------------------------------------------------------------

/// Connect via TLS using the `openssl` crate's `SslConnector` and extract the peer certificate DER data.
///
/// This performs a proper TLS 1.2/1.3 handshake with full cipher suite negotiation,
/// SNI (Server Name Indication), support, and all required extensions. Unlike the previous
/// hand-crafted `ClientHello` which only offered a single cipher suite (`TLS_RSA_WITH_AES_128_CBC_SHA`),
/// this uses the system's OpenSSL library which supports all modern cipher suites.
#[cfg(feature = "openssl")]
fn tls_connect_and_get_cert(hostname: &str, addr: SocketAddr) -> mlua::Result<Vec<u8>> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create SSL connector: {e}"))
        })?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let stream =
        TcpStream::connect_timeout(&addr, Duration::from_millis(DEFAULT_TIMEOUT_MS)).map_err(|e| {
            mlua::Error::RuntimeError(format!("TLS connect failed to {addr}: {e}"))
        })?;

    let ssl_stream = connector.connect(hostname, stream).map_err(|e| {
        mlua::Error::RuntimeError(format!("SSL handshake failed for {hostname}: {e}"))
    })?;

    let cert = ssl_stream.ssl().peer_certificate().ok_or_else(|| {
        mlua::Error::RuntimeError("Server did not present a certificate".to_string())
    })?;

    cert.to_der().map_err(|e| {
        mlua::Error::RuntimeError(format!("Failed to encode certificate as DER: {e}"))
    })
}

#[cfg(not(feature = "openssl"))]
fn tls_connect_and_get_cert(_hostname: &str, _addr: SocketAddr) -> mlua::Result<Vec<u8>> {
    Err(mlua::Error::RuntimeError(
        "SSL support not available (openssl feature not enabled)".to_string(),
    ))
}

