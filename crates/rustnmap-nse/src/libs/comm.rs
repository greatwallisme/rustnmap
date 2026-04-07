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
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use mlua::{Table, UserData, UserDataMethods, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Default maximum socket timeout in milliseconds.
///
/// Upper bound for all operations. Individual timeouts are calculated from
/// timing template via `stdnse.get_timeout()`.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Request timeout added on top of connect timeout (milliseconds).
///
/// Matches nmap's `REQUEST_TIMEOUT` in `nselib/comm.lua:35`.
/// For justification, see `totalwaitms` in `nmap-service-probes`.
const REQUEST_TIMEOUT_MS: u64 = 6_000;

/// Default connect timeout in milliseconds when no host times are available.
///
/// Matches nmap's `stdnse.get_timeout()` default behavior:
/// `host.times.timeout * (max_timeout + 6000) / 7`
/// With default `timeout=3.0` and `max_timeout=8000`: `3.0 * 14000/7 = 6000ms`
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 6_000;

/// Default banner read timeout in milliseconds.
///
/// Matches nmap behavior: banner timeout is capped at `connect_timeout`.
const DEFAULT_BANNER_TIMEOUT_MS: u64 = 6_000;

/// Linger timeout after first successful read in `receive_all()`.
///
/// After reading the first chunk of data, nmap's nsock event loop detects
/// "no more data" quickly via non-blocking I/O callbacks. We approximate
/// this by switching to a short timeout after the first read:
/// if no more data arrives within 30ms, the server has finished sending.
///
/// This is safe because:
/// - Initial wait still uses the full socket timeout (e.g. 5s for banner)
/// - Only the *subsequent* reads use the short linger timeout
/// - If the server is still sending data, it will arrive within RTT (<<30ms on LAN)
const LINGER_TIMEOUT_MS: u64 = 30;

/// Underlying transport for an NSE socket.
#[derive(Debug)]
enum SocketTransport {
    /// TCP connection.
    Tcp(TcpStream),
    /// UDP socket with a connected remote address.
    Udp(UdpSocket),
}

/// Socket wrapper for Lua userdata.
#[derive(Debug)]
pub struct NseSocket {
    /// The underlying transport (TCP or UDP).
    transport: Option<SocketTransport>,
    /// Connection timeout.
    timeout: Duration,
    /// Whether the socket uses SSL/TLS.
    is_ssl: bool,
    /// Remote address.
    peer_addr: SocketAddr,
    /// Original hostname for SNI (Server Name Indication).
    hostname: Option<String>,
    /// Protocol string ("tcp" or "udp").
    proto: String,
    /// Internal read buffer for `receive_buf` pattern matching.
    /// Stores leftover data after a successful pattern match.
    buffer: Vec<u8>,
}

impl NseSocket {
    /// Create a new TCP socket from a stream.
    #[expect(
        clippy::must_use_candidate,
        reason = "Constructor returns new socket instance"
    )]
    pub fn new_tcp(stream: TcpStream, peer_addr: SocketAddr, hostname: Option<String>) -> Self {
        Self {
            transport: Some(SocketTransport::Tcp(stream)),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            is_ssl: false,
            peer_addr,
            hostname,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
        }
    }

    /// Create a new UDP socket.
    fn new_udp(udp: UdpSocket, peer_addr: SocketAddr, hostname: Option<String>) -> Self {
        Self {
            transport: Some(SocketTransport::Udp(udp)),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            is_ssl: false,
            peer_addr,
            hostname,
            proto: "udp".to_string(),
            buffer: Vec::new(),
        }
    }

    /// Check if the socket is connected.
    fn is_connected(&self) -> bool {
        self.transport.is_some()
    }

    /// Send data over the socket.
    fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self.transport {
            Some(SocketTransport::Tcp(ref mut stream)) => stream.write(data),
            Some(SocketTransport::Udp(ref udp)) => udp.send(data),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            )),
        }
    }

    /// Receive data from the socket.
    fn receive(&mut self, max_bytes: usize) -> std::io::Result<Vec<u8>> {
        match self.transport {
            Some(SocketTransport::Tcp(ref mut stream)) => {
                let mut buffer = vec![0u8; max_bytes];
                let n = stream.read(&mut buffer)?;
                buffer.truncate(n);
                Ok(buffer)
            }
            Some(SocketTransport::Udp(ref udp)) => {
                let mut buffer = vec![0u8; max_bytes];
                let n = udp.recv(&mut buffer)?;
                buffer.truncate(n);
                Ok(buffer)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            )),
        }
    }

    /// Receive data with a temporary timeout override.
    ///
    /// Temporarily changes the socket read timeout, performs a single receive,
    /// then restores the original timeout. Used for banner linger reads.
    fn receive_with_timeout(
        &mut self,
        max_bytes: usize,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        match self.transport {
            Some(SocketTransport::Tcp(ref mut stream)) => {
                let original = stream.read_timeout()?;
                stream.set_read_timeout(Some(timeout))?;
                let mut buffer = vec![0u8; max_bytes];
                let result = stream.read(&mut buffer);
                stream.set_read_timeout(original)?;
                let n = result?;
                buffer.truncate(n);
                Ok(buffer)
            }
            Some(SocketTransport::Udp(ref udp)) => {
                let original = udp.read_timeout()?;
                udp.set_read_timeout(Some(timeout))?;
                let mut buffer = vec![0u8; max_bytes];
                let result = udp.recv(&mut buffer);
                udp.set_read_timeout(original)?;
                let n = result?;
                buffer.truncate(n);
                Ok(buffer)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            )),
        }
    }

    /// Receive all available data until timeout or closure.
    ///
    /// Matches nmap's nsock event-driven behavior: after the first successful
    /// read, switches to a short linger timeout to detect "no more data" quickly.
    /// Without this, banner scripts wait the full socket timeout (5-30s) after
    /// reading the initial banner data.
    fn receive_all(&mut self) -> std::io::Result<Vec<u8>> {
        match self.transport {
            Some(SocketTransport::Tcp(ref mut stream)) => {
                let mut result = Vec::new();
                let mut buffer = [0u8; 4096];
                let linger = Duration::from_millis(LINGER_TIMEOUT_MS);

                stream.set_read_timeout(Some(self.timeout))?;

                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break, // Connection closed
                        Ok(n) => {
                            result.extend_from_slice(&buffer[..n]);
                            // After first read, switch to short linger timeout.
                            // nmap's nsock detects "no more data" via non-blocking
                            // callbacks almost instantly. We approximate this with
                            // a short timeout: if no data arrives in 150ms, the
                            // server has finished sending.
                            stream.set_read_timeout(Some(linger))?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }

                Ok(result)
            }
            Some(SocketTransport::Udp(ref udp)) => {
                // For UDP, receive a single datagram (up to 64KB)
                udp.set_read_timeout(Some(self.timeout))?;
                let mut buffer = vec![0u8; 65535];
                let n = udp.recv(&mut buffer)?;
                buffer.truncate(n);
                Ok(buffer)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "socket not connected",
            )),
        }
    }

    /// Set the read/write timeout on the socket.
    fn set_timeout(&mut self, timeout: Duration) -> std::io::Result<()> {
        self.timeout = timeout;
        match self.transport {
            Some(SocketTransport::Tcp(ref mut stream)) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
            }
            Some(SocketTransport::Udp(ref udp)) => {
                udp.set_read_timeout(Some(timeout))?;
                udp.set_write_timeout(Some(timeout))?;
            }
            None => {}
        }
        Ok(())
    }

    /// Reconnect to the stored peer address.
    fn connect(&mut self, timeout: Duration) -> std::io::Result<()> {
        // Close existing transport first
        self.close();
        self.buffer.clear();

        let stream = TcpStream::connect_timeout(&self.peer_addr, timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        self.transport = Some(SocketTransport::Tcp(stream));
        Ok(())
    }

    /// Get connection info table (mimics nsock's `socket:get_info()`).
    /// Returns (`local_ip`, `local_port`, `remote_ip`, `remote_port`, `proto`) or nil
    fn get_info(&self) -> Option<(String, u16, String, u16, String)> {
        match self.transport {
            Some(SocketTransport::Tcp(ref stream)) => {
                let local = stream.local_addr().ok()?;
                let remote = stream.peer_addr().ok()?;
                Some((
                    local.ip().to_string(),
                    local.port(),
                    remote.ip().to_string(),
                    remote.port(),
                    self.proto.clone(),
                ))
            }
            Some(SocketTransport::Udp(ref udp)) => {
                let local = udp.local_addr().ok()?;
                Some((
                    local.ip().to_string(),
                    local.port(),
                    self.peer_addr.ip().to_string(),
                    self.peer_addr.port(),
                    self.proto.clone(),
                ))
            }
            None => None,
        }
    }

    /// Close the socket.
    fn close(&mut self) {
        if let Some(transport) = self.transport.take() {
            match transport {
                SocketTransport::Tcp(stream) => {
                    // Ignore "not connected" errors -- the peer may have already
                    // closed the connection, which is normal during script cleanup.
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                SocketTransport::Udp(_) => {
                    // UDP sockets don't need shutdown; drop handles it
                }
            }
        }
    }
}

#[expect(
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    reason = "NSE socket protocol handling requires sequential connection/SSL/read/write logic; usize to i64 cast for Lua FFI is safe on 64-bit"
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

        // socket:receive([max_bytes])
        //
        // Nsock-compatible return: (true, data) on success, (false, error) on failure.
        // This two-value return is required by http.lua's recv_line, recv_all,
        // recv_length, and dozens of other nselib callers that do:
        //   local status, data = socket:receive()
        //   if not status then ... end
        methods.add_method_mut("receive", |lua, this, max_bytes: Option<usize>| {
            let max = max_bytes.unwrap_or(4096);
            match this.receive(max) {
                Ok(data) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(true),
                    Value::String(lua.create_string(&data)?),
                ])),
                Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string(format!("receive failed: {e}"))?),
                ])),
            }
        });

        // socket:receive_all()
        //
        // Same nsock-compatible return pattern as receive().
        methods.add_method_mut("receive_all", |lua, this, ()| match this.receive_all() {
            Ok(data) => Ok(mlua::MultiValue::from_vec(vec![
                Value::Boolean(true),
                Value::String(lua.create_string(&data)?),
            ])),
            Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                Value::Boolean(false),
                Value::String(lua.create_string(format!("receive failed: {e}"))?),
            ])),
        });

        // receive_lines(n) - read n lines (delimited by \r\n or \n)
        // Nmap scripts like smtp.lua call socket:receive_lines(1) to read a response
        // Returns (true, data) on success, (nil, err_msg) on failure
        methods.add_method_mut("receive_lines", |lua, this, n: Option<usize>| {
            let lines_to_read = n.unwrap_or(1);
            let mut lines_read = 0usize;
            let mut result = Vec::new();
            let mut tmp = [0u8; 8192];

            match this.transport {
                Some(SocketTransport::Tcp(ref mut stream)) => {
                    stream.set_read_timeout(Some(this.timeout)).map_err(|e| {
                        mlua::Error::RuntimeError(format!("set timeout failed: {e}"))
                    })?;

                    while lines_read < lines_to_read {
                        let count = match stream.read(&mut tmp) {
                            Ok(0) => break, // EOF
                            Ok(n) => n,
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                return Err(mlua::Error::RuntimeError(format!(
                                    "receive_lines failed: {e}"
                                )));
                            }
                        };
                        result.extend_from_slice(&tmp[..count]);
                        // Count complete lines
                        lines_read = String::from_utf8_lossy(&result).matches('\n').count();
                    }
                }
                Some(SocketTransport::Udp(ref udp)) => {
                    udp.set_read_timeout(Some(this.timeout)).map_err(|e| {
                        mlua::Error::RuntimeError(format!("set timeout failed: {e}"))
                    })?;
                    // For UDP, receive a single datagram (line-based read doesn't apply well)
                    let mut buf = vec![0u8; 65535];
                    let n = udp.recv(&mut buf).map_err(|e| {
                        mlua::Error::RuntimeError(format!("receive_lines (udp) failed: {e}"))
                    })?;
                    result.extend_from_slice(&buf[..n]);
                }
                None => {}
            }

            if result.is_empty() {
                return Ok(mlua::MultiValue::from_vec(vec![
                    Value::Nil,
                    Value::String(lua.create_string("EOF")?),
                ]));
            }

            Ok(mlua::MultiValue::from_vec(vec![
                Value::Boolean(true),
                Value::String(lua.create_string(&result)?),
            ]))
        });

        // receive_buf(pattern, keep_or_drop) - pattern-based buffered receive.
        //
        // Reads data from the socket into an internal buffer and applies a pattern
        // match to delimit the returned data. This is the primary buffered I/O
        // method used by many NSE scripts (redis, imap, vnc, mqtt, etc.).
        //
        // # Parameters
        //
        // * `pattern` - Either a Lua string pattern (passed to `string.find`) or a
        //   function that takes the buffer string and returns (start, end) on match
        //   or nil on no match (e.g. `match.numbytes(n)` or `match.pattern_limit(...)`).
        // * `keep_or_drop` - If true, include the matched delimiter in the returned
        //   data. If false, return data up to (but not including) the match start.
        //
        // # Returns
        //
        // On success: `true, data_string`
        // On failure: `false, error_message`
        //
        // # Behavior
        //
        // Maintains an internal buffer. On each call, new data is appended to the
        // buffer and the pattern is tested. If the pattern matches, the relevant
        // portion of the buffer is returned and the remainder is kept for the next
        // call. If no match, more data is read (up to the socket timeout).
        methods.add_method_mut(
            "receive_buf",
            |lua, this, (pattern, keep_or_drop): (mlua::Value, Option<bool>)| {
                let include_delimiter = keep_or_drop.unwrap_or(false);

                if this.transport.is_none() {
                    return Ok(mlua::MultiValue::from_vec(vec![
                        Value::Boolean(false),
                        Value::String(lua.create_string("socket not connected")?),
                    ]));
                }

                let max_iterations = 128usize;
                for _ in 0..max_iterations {
                    // Try matching the pattern against the current buffer
                    let buf_str = String::from_utf8_lossy(&this.buffer);
                    let match_result = match &pattern {
                        Value::Function(func) => {
                            // Call the Lua matcher function with the buffer string
                            let result: mlua::MultiValue =
                                func.call::<mlua::MultiValue>(buf_str.as_ref()).map_err(
                                    |e| {
                                        mlua::Error::RuntimeError(format!(
                                        "receive_buf: pattern function error: {e}"
                                    ))
                                    },
                                )?;
                            let mut iter = result.into_iter();
                            let first = iter.next();
                            let second = iter.next();
                            match (first, second) {
                                (Some(Value::Integer(s)), Some(Value::Integer(e))) => {
                                    Some((
                                        usize::try_from(s).unwrap_or(0),
                                        usize::try_from(e).unwrap_or(0),
                                    ))
                                }
                                (Some(Value::Number(s)), Some(Value::Number(e))) => {
                                    // Lua pattern functions may return f64 byte
                                    // positions; convert via i64 safely.
                                    #[expect(
                                        clippy::cast_possible_truncation,
                                        reason = "Lua string indices fit in i64; clamped non-negative"
                                    )]
                                    let s_idx = usize::try_from(s.max(0.0) as i64).unwrap_or(0);
                                    #[expect(
                                        clippy::cast_possible_truncation,
                                        reason = "Lua string indices fit in i64; clamped non-negative"
                                    )]
                                    let e_idx = usize::try_from(e.max(0.0) as i64).unwrap_or(0);
                                    Some((s_idx, e_idx))
                                }
                                _ => None,
                            }
                        }
                        Value::String(pat) => {
                            // Use string.find on the buffer
                            let find_fn: mlua::Function =
                                lua.globals().get::<mlua::Table>("string")?.get("find")?;
                            let result: mlua::MultiValue = find_fn
                                .call::<mlua::MultiValue>((buf_str.as_ref(), pat))
                                .map_err(|e| {
                                    mlua::Error::RuntimeError(format!(
                                        "receive_buf: string.find error: {e}"
                                    ))
                                })?;
                            let mut iter = result.into_iter();
                            let first = iter.next();
                            let second = iter.next();
                            match (first, second) {
                                (Some(Value::Integer(s)), Some(Value::Integer(e))) => {
                                    Some((
                                        usize::try_from(s).unwrap_or(0),
                                        usize::try_from(e).unwrap_or(0),
                                    ))
                                }
                                _ => None,
                            }
                        }
                        _ => {
                            return Err(mlua::Error::RuntimeError(
                                "receive_buf: pattern must be a string or function".to_string(),
                            ));
                        }
                    };

                    if let Some((start, end)) = match_result {
                        // Pattern matched - extract the data and remainder
                        let buf_len = this.buffer.len();

                        // Validate indices
                        if start == 0 || start > buf_len || end > buf_len {
                            return Err(mlua::Error::RuntimeError(format!(
                                "receive_buf: invalid match indices ({start}, {end}) for buffer of length {buf_len}"
                            )));
                        }

                        // Lua indices are 1-based, convert to 0-based
                        let cut_point = if include_delimiter { end } else { start - 1 };
                        let result_data = this.buffer[..cut_point].to_vec();
                        this.buffer = this.buffer[end..].to_vec();

                        return Ok(mlua::MultiValue::from_vec(vec![
                            Value::Boolean(true),
                            Value::String(lua.create_string(&result_data)?),
                        ]));
                    }

                    // No match - read more data from socket
                    let mut tmp = [0u8; 8192];
                    let bytes_read = match this.transport {
                        Some(SocketTransport::Tcp(ref mut stream)) => {
                            stream
                                .set_read_timeout(Some(this.timeout))
                                .map_err(|e| {
                                    mlua::Error::RuntimeError(format!(
                                        "receive_buf: set timeout failed: {e}"
                                    ))
                                })?;
                            match stream.read(&mut tmp) {
                                Ok(0) => {
                                    // EOF - return whatever is in the buffer
                                    if this.buffer.is_empty() {
                                        return Ok(mlua::MultiValue::from_vec(vec![
                                            Value::Boolean(false),
                                            Value::String(lua.create_string("EOF")?),
                                        ]));
                                    }
                                    let result_data =
                                        std::mem::take(&mut this.buffer);
                                    return Ok(mlua::MultiValue::from_vec(vec![
                                        Value::Boolean(true),
                                        Value::String(lua.create_string(&result_data)?),
                                    ]));
                                }
                                Ok(n) => n,
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::TimedOut
                                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                                {
                                    // Timeout - return whatever is in the buffer
                                    if this.buffer.is_empty() {
                                        return Ok(mlua::MultiValue::from_vec(vec![
                                            Value::Boolean(false),
                                            Value::String(lua.create_string("TIMEOUT")?),
                                        ]));
                                    }
                                    let result_data =
                                        std::mem::take(&mut this.buffer);
                                    return Ok(mlua::MultiValue::from_vec(vec![
                                        Value::Boolean(true),
                                        Value::String(lua.create_string(&result_data)?),
                                    ]));
                                }
                                Err(e) => {
                                    return Err(mlua::Error::RuntimeError(format!(
                                        "receive_buf: read failed: {e}"
                                    )));
                                }
                            }
                        }
                        Some(SocketTransport::Udp(ref udp)) => {
                            udp.set_read_timeout(Some(this.timeout))
                                .map_err(|e| {
                                    mlua::Error::RuntimeError(format!(
                                        "receive_buf: set timeout failed: {e}"
                                    ))
                                })?;
                            match udp.recv(&mut tmp) {
                                Ok(0) => {
                                    if this.buffer.is_empty() {
                                        return Ok(mlua::MultiValue::from_vec(vec![
                                            Value::Boolean(false),
                                            Value::String(lua.create_string("EOF")?),
                                        ]));
                                    }
                                    let result_data =
                                        std::mem::take(&mut this.buffer);
                                    return Ok(mlua::MultiValue::from_vec(vec![
                                        Value::Boolean(true),
                                        Value::String(lua.create_string(&result_data)?),
                                    ]));
                                }
                                Ok(n) => n,
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::TimedOut
                                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                                {
                                    if this.buffer.is_empty() {
                                        return Ok(mlua::MultiValue::from_vec(vec![
                                            Value::Boolean(false),
                                            Value::String(lua.create_string("TIMEOUT")?),
                                        ]));
                                    }
                                    let result_data =
                                        std::mem::take(&mut this.buffer);
                                    return Ok(mlua::MultiValue::from_vec(vec![
                                        Value::Boolean(true),
                                        Value::String(lua.create_string(&result_data)?),
                                    ]));
                                }
                                Err(e) => {
                                    return Err(mlua::Error::RuntimeError(format!(
                                        "receive_buf: udp recv failed: {e}"
                                    )));
                                }
                            }
                        }
                        None => {
                            return Ok(mlua::MultiValue::from_vec(vec![
                                Value::Boolean(false),
                                Value::String(lua.create_string("socket not connected")?),
                            ]));
                        }
                    };

                    this.buffer.extend_from_slice(&tmp[..bytes_read]);
                }

                // Exceeded max iterations - return buffer contents to prevent infinite loop
                let result_data = std::mem::take(&mut this.buffer);
                if result_data.is_empty() {
                    Ok(mlua::MultiValue::from_vec(vec![
                        Value::Boolean(false),
                        Value::String(lua.create_string("receive_buf: max iterations exceeded")?),
                    ]))
                } else {
                    Ok(mlua::MultiValue::from_vec(vec![
                        Value::Boolean(true),
                        Value::String(lua.create_string(&result_data)?),
                    ]))
                }
            },
        );

        methods.add_method_mut("close", |_, this, ()| {
            this.close();
            Ok(Value::Boolean(true))
        });

        methods.add_method("get_peer_addr", |_, this, ()| {
            Ok(this.peer_addr.to_string())
        });

        methods.add_method("is_ssl", |_, this, ()| Ok(this.is_ssl));

        methods.add_method("get_proto", |_, this, ()| Ok(this.proto.clone()));

        // set_timeout(timeout_ms) - set socket read/write timeout
        // Matches nsock's socket:set_timeout()
        methods.add_method_mut("set_timeout", |_, this, timeout_ms: Option<u64>| {
            let ms = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
            this.set_timeout(Duration::from_millis(ms))
                .map_err(|e| mlua::Error::RuntimeError(format!("set_timeout failed: {e}")))?;
            Ok(true)
        });

        // get_info() - returns (local_ip, local_port, remote_ip, remote_port, proto)
        // Matches nsock's socket:get_info() used by pipeline_go to check connection state
        methods.add_method("get_info", |lua, this, ()| match this.get_info() {
            Some((local_ip, local_port, remote_ip, remote_port, proto)) => {
                let result = lua.create_table()?;
                result.set("local_ip", local_ip)?;
                result.set("local_port", local_port)?;
                result.set("remote_ip", remote_ip)?;
                result.set("remote_port", remote_port)?;
                result.set("proto", proto)?;
                Ok(Value::Table(result))
            }
            None => Ok(Value::Nil),
        });

        // connect(host, port, proto) - reconnect to host:port
        // Matches nsock's socket:connect() used by pipeline_go for reconnection
        methods.add_method_mut(
            "connect",
            |_, this, (host_param, port_param, proto_param): (Value, Value, Option<String>)| {
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

                let port = match port_param {
                    Value::Integer(n) => u16::try_from(n).map_err(|e| {
                        mlua::Error::RuntimeError(format!("port number out of range: {e}"))
                    })?,
                    Value::Table(ref t) => {
                        let number: i64 = t.get("number").map_err(|e| {
                            mlua::Error::RuntimeError(format!(
                                "port table missing 'number' field: {e}"
                            ))
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

                if let Some(proto) = proto_param {
                    this.proto = proto;
                }
                this.hostname = Some(host.clone());

                tokio::task::block_in_place(|| {
                    let addr = format!("{host}:{port}");
                    let addrs: Vec<SocketAddr> = addr
                        .to_socket_addrs()
                        .map_err(|e| {
                            mlua::Error::RuntimeError(format!("DNS resolution failed: {e}"))
                        })?
                        .collect();

                    if addrs.is_empty() {
                        return Err(mlua::Error::RuntimeError(
                            "could not resolve address".to_string(),
                        ));
                    }

                    this.peer_addr = addrs[0];
                    this.connect(this.timeout)
                        .map_err(|e| mlua::Error::RuntimeError(format!("connect failed: {e}")))?;

                    Ok(true)
                })
            },
        );

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

            // Use stored hostname or fall back to IP for SNI.
            // Filter out empty strings to avoid OpenSSL SNI errors.
            let hostname = this
                .hostname
                .as_deref()
                .filter(|s| !s.is_empty())
                .map_or_else(
                    || this.peer_addr.ip().to_string(),
                    std::string::ToString::to_string,
                );

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
        // Match nmap's comm.lua get_timeouts() logic:
        // 1. opts.timeout overrides both connect and request timeouts
        // 2. opts.connect_timeout overrides just connect timeout
        // 3. opts.request_timeout overrides just request timeout
        // 4. Otherwise use defaults (connect=8s, request=connect+6s)
        if let Ok(timeout) = opts.get("timeout") {
            let timeout: i64 = timeout;
            let ms = timeout.max(0) as u64;
            options.connect_timeout = Duration::from_millis(ms);
            // When timeout is specified, request_timeout = timeout (not timeout + 6s)
            options.request_timeout = Duration::from_millis(ms);
        }
        if let Ok(connect_timeout) = opts.get("connect_timeout") {
            let ct: i64 = connect_timeout;
            options.connect_timeout = Duration::from_millis(ct.max(0) as u64);
        }
        if let Ok(request_timeout) = opts.get("request_timeout") {
            let rt: i64 = request_timeout;
            // nmap: request_timeout is added to connect_timeout
            // Unless opts.timeout was specified (which overrides both)
            options.request_timeout =
                options.connect_timeout + Duration::from_millis(rt.max(0) as u64);
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
        if let Ok(recv_before) = opts.get("recv_before") {
            let recv_before: bool = recv_before;
            options.recv_before = recv_before;
        }
    }

    Ok(options)
}

/// Connection options.
///
/// Mirrors nmap's `nselib/comm.lua` timeout model:
/// - `connect_timeout`: Socket timeout during connection. Default: `stdnse.get_timeout(host)` = 8s (T3).
/// - `request_timeout`: Socket timeout for request/response after connect.
///   Default: `connect_timeout + REQUEST_TIMEOUT` = 8s + 6s = 14s (T3).
#[derive(Debug, Clone)]
struct ConnectionOpts {
    /// Timeout for the connection phase.
    connect_timeout: Duration,
    /// Timeout for request/response phase (after connect).
    request_timeout: Duration,
    /// Number of bytes to read.
    bytes: Option<usize>,
    /// Number of lines to read.
    lines: Option<usize>,
    /// Use SSL/TLS.
    ssl: bool,
    /// Protocol ("tcp", "udp").
    proto: String,
    /// Receive data before sending first payload.
    /// When true, the connection reads a banner/greeting before sending any data.
    recv_before: bool,
}

impl Default for ConnectionOpts {
    fn default() -> Self {
        let connect_timeout = Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS);
        let request_timeout = connect_timeout + Duration::from_millis(REQUEST_TIMEOUT_MS);
        Self {
            connect_timeout,
            request_timeout,
            bytes: None,
            lines: None,
            ssl: false,
            proto: "tcp".to_string(),
            recv_before: false,
        }
    }
}

/// Open a connection to host:port.
fn opencon_impl(
    host: &str,
    port: u16,
    opts: &ConnectionOpts,
    sni_hostname: Option<&str>,
) -> std::io::Result<NseSocket> {
    // Use block_in_place to yield to the async runtime during blocking network operations
    tokio::task::block_in_place(|| {
        let mut socket = opencon_impl_blocking(host, port, opts)?;
        // Use provided SNI hostname, but fall back to the connection host.
        // Treat empty string as absent to avoid OpenSSL SNI errors.
        let effective_hostname = sni_hostname.filter(|s| !s.is_empty()).unwrap_or(host);
        socket.hostname = Some(effective_hostname.to_string());
        Ok(socket)
    })
}
/// Blocking implementation of TCP connection.
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

    let target = addrs[0];

    let mut socket = if opts.proto == "udp" {
        // UDP: bind to any local port, then connect to target
        let udp = if target.is_ipv6() {
            UdpSocket::bind("[::]:0")?
        } else {
            UdpSocket::bind("0.0.0.0:0")?
        };
        // Connection phase uses connect_timeout
        udp.set_read_timeout(Some(opts.connect_timeout))?;
        udp.set_write_timeout(Some(opts.connect_timeout))?;
        udp.connect(target)?;
        // Switch to request_timeout after connect (nmap pattern)
        udp.set_read_timeout(Some(opts.request_timeout))?;
        udp.set_write_timeout(Some(opts.request_timeout))?;
        let mut sock = NseSocket::new_udp(udp, target, Some(host.to_string()));
        sock.timeout = opts.request_timeout;
        sock
    } else {
        // TCP (default)
        // Connection phase uses connect_timeout
        let stream = TcpStream::connect_timeout(&target, opts.connect_timeout)?;
        // Switch to request_timeout after connect (nmap: sock:set_timeout(request_timeout))
        stream.set_read_timeout(Some(opts.request_timeout))?;
        stream.set_write_timeout(Some(opts.request_timeout))?;
        let mut sock = NseSocket::new_tcp(stream, target, Some(host.to_string()));
        sock.timeout = opts.request_timeout;
        sock
    };

    if opts.ssl {
        socket.is_ssl = true;
    }

    Ok(socket)
}

/// Get service banner from host:port.
/// Returns raw bytes to preserve binary data (telnet negotiation, etc.)
fn get_banner_impl(host: &str, port: u16, opts: &ConnectionOpts) -> std::io::Result<Vec<u8>> {
    let mut socket = opencon_impl(host, port, opts, None)?;

    // Set a shorter timeout for banner grabbing.
    // nmap uses connect_timeout for banner phase, capped at DEFAULT_BANNER_TIMEOUT_MS.
    let banner_timeout = Duration::from_millis(DEFAULT_BANNER_TIMEOUT_MS);
    socket.timeout = banner_timeout.min(opts.connect_timeout);

    // Banner grabbing: read initial data from the service.
    // nmap's nsock uses non-blocking I/O with event callbacks that return
    // as soon as the first chunk arrives. We approximate this with a single
    // receive() call - most banners (SSH, SMTP, FTP, POP3) arrive in one packet.
    // If the first read returns data, we do one more short read to catch any
    // trailing data, using a minimal linger timeout.
    let mut result = socket.receive(8192)?;
    if !result.is_empty() {
        // Try one more read with a very short timeout to catch split banners.
        let linger = Duration::from_millis(LINGER_TIMEOUT_MS);
        match socket.receive_with_timeout(8192, linger) {
            Ok(more) if !more.is_empty() => result.extend_from_slice(&more),
            _ => {}
        }
    }
    socket.close();

    Ok(result)
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

    socket.close();

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

/// Extract host string from a Lua value (string or host table with `ip` field).
fn extract_host(value: &Value) -> mlua::Result<String> {
    match value {
        Value::String(s) => s
            .to_str()
            .map(|s| s.to_string())
            .map_err(|e| mlua::Error::RuntimeError(format!("host string conversion failed: {e}"))),
        Value::Table(t) => {
            let ip: Value = t.get("ip").map_err(|e| {
                mlua::Error::RuntimeError(format!("host table missing 'ip' field: {e}"))
            })?;
            match ip {
                Value::String(s) => s.to_str().map(|s| s.to_string()).map_err(|e| {
                    mlua::Error::RuntimeError(format!("host.ip conversion failed: {e}"))
                }),
                other => Err(mlua::Error::RuntimeError(format!(
                    "host.ip must be a string, got: {:?}",
                    other.type_name()
                ))),
            }
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "host must be a string or table, got: {:?}",
            other.type_name()
        ))),
    }
}

/// Extract port number from a Lua value (integer or port table with `number` field).
fn extract_port(value: Value) -> mlua::Result<u16> {
    match value {
        Value::Integer(n) => u16::try_from(n)
            .map_err(|e| mlua::Error::RuntimeError(format!("port number out of range: {e}"))),
        Value::Table(ref t) => {
            let number: i64 = t.get("number").map_err(|e| {
                mlua::Error::RuntimeError(format!("port table missing 'number' field: {e}"))
            })?;
            u16::try_from(number)
                .map_err(|e| mlua::Error::RuntimeError(format!("port.number out of range: {e}")))
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "port must be a number or table, got: {:?}",
            other.type_name()
        ))),
    }
}

/// Extract port number and optional protocol from a Lua value.
///
/// When the port is a table with a `protocol` field (e.g. `"udp"`), the protocol
/// is returned as `Some(String)` so callers can propagate it to `ConnectionOpts`.
fn extract_port_and_proto(value: &Value) -> mlua::Result<(u16, Option<String>)> {
    match value {
        Value::Integer(n) => {
            let port = u16::try_from(*n)
                .map_err(|e| mlua::Error::RuntimeError(format!("port number out of range: {e}")))?;
            Ok((port, None))
        }
        Value::Table(t) => {
            let number: i64 = t.get("number").map_err(|e| {
                mlua::Error::RuntimeError(format!("port table missing 'number' field: {e}"))
            })?;
            let port = u16::try_from(number)
                .map_err(|e| mlua::Error::RuntimeError(format!("port.number out of range: {e}")))?;
            let proto: Option<String> = t.get("protocol").ok().flatten();
            Ok((port, proto))
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "port must be a number or table, got: {:?}",
            other.type_name()
        ))),
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

            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match opencon_impl(&host, port, &options, sni_hostname.as_deref()) {
                Ok(mut socket) => {
                    // Match nmap's comm.lua opencon behavior:
                    // 1. If recv_before: read banner/greeting BEFORE sending any data
                    // 2. If data is non-empty: send data, then read response
                    // 3. If data is empty/nil: response = early_resp (the banner)
                    // Returns: socket, response, early_response
                    let early_resp: Option<Vec<u8>> = if options.recv_before {
                        socket.receive(8192).ok()
                    } else {
                        None
                    };

                    let response: Option<Vec<u8>> = if let Some(ref data) = data_param {
                        if data.as_bytes().is_empty() {
                            early_resp.clone()
                        } else {
                            if socket.send(&data.as_bytes()).is_err() {
                                return Ok(mlua::MultiValue::from_vec(vec![
                                    Value::Nil,
                                    Value::String(lua.create_string("send failed")?),
                                ]));
                            }
                            socket.receive(8192).ok()
                        }
                    } else {
                        early_resp.clone()
                    };

                    let socket_val = Value::UserData(lua.create_userdata(socket)?);
                    let response_val = match response {
                        Some(ref r) => {
                            let s = String::from_utf8_lossy(r).into_owned();
                            Value::String(lua.create_string(&s)?)
                        }
                        None => Value::Nil,
                    };
                    let early_resp_val = match early_resp {
                        Some(ref r) => {
                            let s = String::from_utf8_lossy(r).into_owned();
                            Value::String(lua.create_string(&s)?)
                        }
                        None => Value::Nil,
                    };
                    // Nmap's opencon returns: status_and_socket, response, early_response
                    Ok(mlua::MultiValue::from_vec(vec![
                        socket_val,
                        response_val,
                        early_resp_val,
                    ]))
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
    //
    // Implements nmap's comm.tryssl behavior:
    //   1. Determine protocol order via bestoption logic (try port.protocol first, then "ssl")
    //   2. Try each protocol in order until one succeeds
    //   3. Return (socket, response, proto_used, early_resp)
    //
    // This differs from opencon which just uses the given proto directly.
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

            // Extract port number and port protocol from port parameter
            let (port, port_protocol) = match &port_param {
                Value::Integer(n) => {
                    let p = u16::try_from(*n).map_err(|e| {
                        mlua::Error::RuntimeError(format!("port number out of range: {e}"))
                    })?;
                    (p, None)
                }
                Value::Table(t) => {
                    let number: i64 = t.get("number").map_err(|e| {
                        mlua::Error::RuntimeError(format!("port table missing 'number' field: {e}"))
                    })?;
                    let p = u16::try_from(number).map_err(|e| {
                        mlua::Error::RuntimeError(format!("port.number out of range: {e}"))
                    })?;
                    let proto: Option<String> = t.get("protocol").ok().flatten();
                    (p, proto)
                }
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "port must be a number or table, got: {:?}",
                        other.type_name()
                    )));
                }
            };

            let options =
                parse_opts(opts.clone()).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            // Determine protocol order (nmap's bestoption logic):
            //   - For SSL ports (443, 995, 993, etc.): try "ssl" first, then "tcp"
            //   - For non-SSL ports: try port.protocol (usually "tcp") first, then "ssl"
            let is_ssl_port = matches!(port, 443 | 465 | 585 | 636 | 853 | 993 | 995 | 5061 | 8443);

            let proto_order: Vec<&str> = if is_ssl_port || options.ssl {
                vec!["ssl", "tcp"]
            } else {
                let primary = port_protocol.as_deref().unwrap_or("tcp");
                if primary == "ssl" {
                    vec!["ssl", "tcp"]
                } else {
                    vec![primary, "ssl"]
                }
            };

            // Try each protocol in order until one succeeds
            for proto in &proto_order {
                let mut try_opts = options.clone();
                try_opts.proto = (*proto).to_string();
                try_opts.ssl = proto == &"ssl";

                if let Ok(mut socket) =
                    opencon_impl(&host, port, &try_opts, sni_hostname.as_deref())
                {
                    let proto_str = if socket.is_ssl { "ssl" } else { "tcp" };

                    // Match nmap's comm.lua opencon behavior:
                    // 1. If recv_before: read banner/greeting BEFORE sending any data
                    // 2. If data is non-empty: send data, then read response
                    // 3. If data is empty/nil: response = early_resp (the banner)
                    let early_resp: Option<Vec<u8>> = if try_opts.recv_before {
                        socket.receive(8192).ok()
                    } else {
                        None
                    };

                    let response: Option<Vec<u8>> = if let Some(ref data) = data_param {
                        if data.as_bytes().is_empty() {
                            early_resp.clone()
                        } else {
                            if socket.send(&data.as_bytes()).is_err() {
                                continue; // Try next protocol
                            }
                            socket.receive(8192).ok()
                        }
                    } else {
                        early_resp.clone()
                    };

                    let socket_val = Value::UserData(lua.create_userdata(socket)?);
                    let response_val = match response {
                        Some(ref r) => {
                            let s = String::from_utf8_lossy(r).into_owned();
                            Value::String(lua.create_string(&s)?)
                        }
                        None => Value::Nil,
                    };
                    let proto_val = Value::String(lua.create_string(proto_str)?);
                    let early_resp_val = match early_resp {
                        Some(ref r) => {
                            let s = String::from_utf8_lossy(r).into_owned();
                            Value::String(lua.create_string(&s)?)
                        }
                        None => Value::Nil,
                    };

                    return Ok(mlua::MultiValue::from_vec(vec![
                        socket_val,
                        response_val,
                        proto_val,
                        early_resp_val,
                    ]));
                }
            }

            // All protocols failed
            Ok(mlua::MultiValue::new())
        },
    )?;
    comm_table.set("tryssl", tryssl_fn)?;

    // Register get_banner(host, port, [opts]) function
    // NSE pattern: returns (true, banner) on success, (false, errmsg) on failure
    // Accepts host as string or table (with host.ip), port as number or table (with port.number)
    let get_banner_fn = lua.create_function(
        |lua, (host_param, port_param, opts): (Value, Value, Option<Table>)| {
            let host = extract_host(&host_param)?;
            let port = extract_port(port_param)?;
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            match get_banner_impl(&host, port, &options) {
                Ok(banner_bytes) => {
                    // Use BString to preserve raw bytes including binary data
                    let banner = mlua::BString::from(banner_bytes);
                    Ok(mlua::MultiValue::from_vec(vec![
                        Value::Boolean(true),
                        Value::String(lua.create_string(banner)?),
                    ]))
                }
                Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string(format!("{e}"))?),
                ])),
            }
        },
    )?;
    comm_table.set("get_banner", get_banner_fn)?;

    // Register exchange(host, port, data, [opts]) function
    // NSE pattern: returns (true, response) on success, (false, errmsg) on failure
    // Accepts host as string or table (with host.ip), port as number or table (with port.number)
    let exchange_fn = lua.create_function(
        |lua, (host_param, port_param, data, opts): (Value, Value, mlua::String, Option<Table>)| {
            let host = extract_host(&host_param)?;
            let (port, port_proto) = extract_port_and_proto(&port_param)?;
            let mut options =
                parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            // If port table has a protocol field and opts doesn't already specify proto, use it
            if let Some(proto) = port_proto {
                if options.proto == "tcp" {
                    options.proto = proto;
                }
            }

            match exchange_impl(&host, port, &data.as_bytes(), &options) {
                Ok(response) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(true),
                    Value::String(lua.create_string(&response)?),
                ])),
                Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string(format!("{e}"))?),
                ])),
            }
        },
    )?;
    comm_table.set("exchange", exchange_fn)?;

    // Register read_response(socket, [opts]) function
    // NSE pattern: returns (true, data) on success, (false, errmsg) on failure
    let read_response_fn =
        lua.create_function(|lua, (socket, opts): (mlua::AnyUserData, Option<Table>)| {
            let options = parse_opts(opts).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            let mut socket_ref = socket.borrow_mut::<NseSocket>()?;

            match read_response_impl(&mut socket_ref, &options) {
                Ok(data) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(true),
                    Value::String(lua.create_string(&data)?),
                ])),
                Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string(format!("{e}"))?),
                ])),
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
                return Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string("Send failed")?),
                ]));
            }

            // Read the response
            match read_response_impl(&mut socket_ref, &options) {
                Ok(data) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(true),
                    Value::String(lua.create_string(&data)?),
                ])),
                Err(e) => Ok(mlua::MultiValue::from_vec(vec![
                    Value::Boolean(false),
                    Value::String(lua.create_string(format!("{e}"))?),
                ])),
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

        assert_eq!(
            opts.connect_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            opts.request_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS + REQUEST_TIMEOUT_MS)
        );
        assert_eq!(opts.bytes, None);
        assert_eq!(opts.lines, None);
        assert!(!opts.ssl);
        assert_eq!(opts.proto, "tcp");
        assert!(!opts.recv_before);
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

        // When opts.timeout is set,5000, it overrides both connect and request timeouts
        assert_eq!(opts.connect_timeout, Duration::from_millis(5000));
        assert_eq!(opts.request_timeout, Duration::from_millis(5000));
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
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
        };

        let _ud = lua.lua().create_userdata(socket).unwrap();
    }

    #[test]
    fn test_connection_opts_default() {
        let opts = ConnectionOpts::default();
        assert_eq!(
            opts.connect_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
        assert_eq!(
            opts.request_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS + REQUEST_TIMEOUT_MS)
        );
        assert_eq!(opts.bytes, None);
        assert_eq!(opts.lines, None);
        assert!(!opts.ssl);
        assert_eq!(opts.proto, "tcp");
        assert!(!opts.recv_before);
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
    fn test_parse_opts_recv_before() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("recv_before", true).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        assert!(opts.recv_before);
    }

    #[test]
    fn test_parse_opts_recv_before_default_false() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        // Table without recv_before set
        table.set("timeout", 5000i64).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        assert!(!opts.recv_before);
    }

    #[test]
    fn test_parse_opts_zero_timeout() {
        let lua = NseLua::new_default().unwrap();
        let table = lua.lua().create_table().unwrap();
        table.set("timeout", 0i64).unwrap();

        let opts = parse_opts(Some(table)).unwrap();

        // When timeout=0, both connect and request timeouts should be 0
        assert_eq!(opts.connect_timeout, Duration::from_millis(0));
        assert_eq!(opts.request_timeout, Duration::from_millis(0));
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
        assert_eq!(opts.connect_timeout, Duration::from_millis(0));
        assert_eq!(opts.request_timeout, Duration::from_millis(0));
        assert_eq!(opts.bytes, Some(0));
        assert_eq!(opts.lines, Some(0));
    }

    #[test]
    fn test_nse_socket_with_ssl() {
        let lua = NseLua::new_default().unwrap();

        let socket = NseSocket {
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: true,
            peer_addr: "127.0.0.1:443".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
        };

        let _ud = lua.lua().create_userdata(socket).unwrap();
    }

    #[test]
    fn test_nse_socket_different_addresses() {
        let lua = NseLua::new_default().unwrap();

        // IPv4 address
        let socket_v4 = NseSocket {
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "192.168.1.1:80".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
        };
        let _ud = lua.lua().create_userdata(socket_v4).unwrap();

        // IPv6 loopback
        let socket_v6 = NseSocket {
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "[::1]:8080".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
        };
        let _ud = lua.lua().create_userdata(socket_v6).unwrap();
    }

    #[test]
    fn test_connection_opts_clone() {
        let opts = ConnectionOpts {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(16),
            bytes: Some(2048),
            lines: Some(5),
            ssl: true,
            proto: "udp".to_string(),
            recv_before: false,
        };

        let cloned = opts.clone();
        assert_eq!(opts.connect_timeout, cloned.connect_timeout);
        assert_eq!(opts.request_timeout, cloned.request_timeout);
        assert_eq!(opts.bytes, cloned.bytes);
        assert_eq!(opts.lines, cloned.lines);
        assert_eq!(opts.ssl, cloned.ssl);
        assert_eq!(opts.proto, cloned.proto);
    }

    #[test]
    fn test_nse_socket_debug() {
        let socket = NseSocket {
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
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
            transport: None,
            timeout: Duration::from_secs(30),
            is_ssl: false,
            peer_addr: "127.0.0.1:80".parse().unwrap(),
            hostname: None,
            proto: "tcp".to_string(),
            buffer: Vec::new(),
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
        assert_eq!(
            opts.connect_timeout,
            Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS)
        );
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
fn tls_connect_and_get_cert(_hostname: &str, _addr: SocketAddr) -> mlua::Result<Vec<u8>> {
    Err(mlua::Error::RuntimeError(
        "SSL support not available (openssl feature not enabled)".to_string(),
    ))
}
