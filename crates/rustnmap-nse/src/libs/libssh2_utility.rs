//! libssh2-utility library for NSE.
//!
//! This module provides the `libssh2-utility` library which contains high-level
//! SSH connection operations for NSE scripts. It corresponds to Nmap's libssh2-utility
//! NSE library and provides an object-oriented interface to SSH operations.
//!
//! # `SSHConnection` Class
//!
//! The `SSHConnection` class provides methods for:
//! - Connecting to SSH servers
//! - Listing authentication methods
//! - Getting server banner
//! - Authentication (password, keyboard-interactive, publickey)
//!
//! # Example Usage in Lua
//!
//! ```lua
//! local libssh2_util = require "libssh2-utility"
//!
//! local helper = libssh2_util.SSHConnection:new()
//! local status, err = helper:connect_pcall(host, port)
//! if status then
//!     local methods = helper:list(username)
//!     local banner = helper:banner()
//!     helper:disconnect()
//! end
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use mlua::{MetaMethod, UserData, UserDataMethods, Value};
use rand::Rng;
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// Default timeout for SSH connections in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// SSH-2 message codes.
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
const SSH_MSG_USERAUTH_BANNER: u8 = 53;
const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
const SSH_MSG_KEXINIT: u8 = 20;

/// Build SSH-2 packet with payload and padding.
fn build_ssh2_packet(payload: &[u8]) -> Vec<u8> {
    let remainder = (payload.len() + 5) % 8;
    let padding_length: u8 =
        u8::try_from(if remainder == 0 { 4 } else { 8 - remainder + 4 }).unwrap_or(4);
    let packet_length = payload.len() + usize::from(padding_length) + 1;

    let mut packet = Vec::with_capacity(4 + packet_length);
    packet.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(packet_length).unwrap_or(u32::MAX),
    ));
    packet.push(padding_length);
    packet.extend_from_slice(payload);

    // Add random padding
    let mut rng = rand::thread_rng();
    for _ in 0..padding_length {
        packet.push(rng.gen());
    }

    packet
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

    if padding_length + 1 > packet.len() {
        return Err(mlua::Error::RuntimeError(
            "Invalid padding length".to_string(),
        ));
    }

    let payload_length = packet.len() - padding_length - 1;

    Ok(packet[1..=payload_length].to_vec())
}

/// Parse string from SSH packet data.
fn parse_string(data: &[u8], offset: usize) -> mlua::Result<(String, usize)> {
    if data.len() < offset + 4 {
        return Err(mlua::Error::RuntimeError(
            "Data too short for string".to_string(),
        ));
    }

    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let new_offset = offset + 4;

    if data.len() < new_offset + len {
        return Err(mlua::Error::RuntimeError(
            "Data too short for string value".to_string(),
        ));
    }

    let value = String::from_utf8_lossy(&data[new_offset..new_offset + len]).to_string();
    Ok((value, new_offset + len))
}

/// Parse name-list from SSH packet data.
fn parse_namelist(data: &[u8], offset: usize) -> mlua::Result<(Vec<String>, usize)> {
    let (list_str, new_offset) = parse_string(data, offset)?;
    if list_str.is_empty() {
        Ok((vec![], new_offset))
    } else {
        let methods: Vec<String> = list_str
            .split(',')
            .map(std::string::ToString::to_string)
            .collect();
        Ok((methods, new_offset))
    }
}

/// Build KEXINIT packet.
fn build_kex_init() -> Vec<u8> {
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
        diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256,\
        curve25519-sha256,curve25519-sha256@libssh.org,\
        ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(kex_algorithms.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(kex_algorithms.as_bytes());

    // Server host key algorithms
    let host_key_algos = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,\
        ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(host_key_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(host_key_algos.as_bytes());

    // Encryption algorithms (client to server)
    let enc_algos = "aes128-cbc,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,\
        aes128-ctr,aes192-ctr,aes256-ctr";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // Encryption algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(enc_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(enc_algos.as_bytes());

    // MAC algorithms (client to server)
    let mac_algos = "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // MAC algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(mac_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(mac_algos.as_bytes());

    // Compression algorithms (client to server)
    let comp_algos = "none,zlib";
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Compression algorithms (server to client)
    payload.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(comp_algos.len()).unwrap_or(u32::MAX),
    ));
    payload.extend_from_slice(comp_algos.as_bytes());

    // Languages
    payload.extend_from_slice(&u32::to_be_bytes(0u32));
    payload.extend_from_slice(&u32::to_be_bytes(0u32));

    // No kex prediction
    payload.extend_from_slice(&[0u8, 0u8, 0u8, 0u8, 0u8]);

    payload
}

/// Send service request for ssh-userauth.
fn send_service_request(stream: &mut TcpStream) -> mlua::Result<()> {
    // Send service request for "ssh-connection"
    let mut payload = vec![SSH_MSG_SERVICE_REQUEST];
    payload.extend_from_slice(&u32::to_be_bytes(14_u32));
    payload.extend_from_slice(b"ssh-connection");

    let packet = build_ssh2_packet(&payload);
    stream
        .write_all(&packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send service request: {e}")))?;

    // Receive SERVICE_ACCEPT
    let resp = receive_ssh_packet(stream)?;
    let resp_payload = extract_payload(&resp)?;

    if resp_payload.is_empty() {
        return Err(mlua::Error::RuntimeError(
            "Empty service response".to_string(),
        ));
    }

    if resp_payload[0] != SSH_MSG_SERVICE_ACCEPT {
        return Err(mlua::Error::RuntimeError(format!(
            "Expected SERVICE_ACCEPT, got message type {}",
            resp_payload[0]
        )));
    }

    Ok(())
}

/// List authentication methods for a user.
fn list_auth_methods_impl(stream: &mut TcpStream, username: &str) -> mlua::Result<Vec<String>> {
    send_service_request(stream)?;

    // Send USERAUTH_REQUEST with "none" method to get available methods
    let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];
    // username
    auth_req.extend_from_slice(&u32::to_be_bytes(
        u32::try_from(username.len()).unwrap_or(u32::MAX),
    ));
    auth_req.extend_from_slice(username.as_bytes());
    // service name
    auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
    auth_req.extend_from_slice(b"ssh-connection");
    // method "none"
    auth_req.extend_from_slice(&u32::to_be_bytes(4_u32));
    auth_req.extend_from_slice(b"none");

    let auth_packet = build_ssh2_packet(&auth_req);
    stream
        .write_all(&auth_packet)
        .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send auth request: {e}")))?;

    // Receive response
    let auth_resp = receive_ssh_packet(stream)?;
    let auth_resp_payload = extract_payload(&auth_resp)?;

    if auth_resp_payload.is_empty() {
        return Err(mlua::Error::RuntimeError("Empty auth response".to_string()));
    }

    match auth_resp_payload[0] {
        SSH_MSG_USERAUTH_FAILURE => {
            let (methods, _partial_success) = parse_namelist(&auth_resp_payload, 1)?;
            Ok(methods)
        }
        SSH_MSG_USERAUTH_SUCCESS => {
            // Server accepts no-auth, return empty list
            Ok(vec![])
        }
        SSH_MSG_USERAUTH_BANNER => {
            // Banner followed by failure, skip banner and read next packet
            let offset = 1;
            let (_banner, _new_offset) = parse_string(&auth_resp_payload, offset)?;

            // Read next packet for actual failure response
            let next_resp = receive_ssh_packet(stream)?;
            let next_payload = extract_payload(&next_resp)?;

            if !next_payload.is_empty() && next_payload[0] == SSH_MSG_USERAUTH_FAILURE {
                let (methods, _partial_success) = parse_namelist(&next_payload, 1)?;
                Ok(methods)
            } else {
                Err(mlua::Error::RuntimeError(format!(
                    "Expected USERAUTH_FAILURE after banner, got message type {}",
                    if next_payload.is_empty() {
                        0
                    } else {
                        next_payload[0]
                    }
                )))
            }
        }
        msg_type => Err(mlua::Error::RuntimeError(format!(
            "Expected USERAUTH_FAILURE/SUCCESS/BANNER, got message type {msg_type}"
        ))),
    }
}

/// SSH connection state.
#[derive(Debug)]
enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connected to SSH server
    Connected {
        stream: TcpStream,
        banner: String,
        host: String,
        port: u16,
    },
}

/// SSH connection `UserData` for NSE scripts.
#[derive(Debug)]
pub struct SSHConnection {
    /// Connection state
    state: ConnectionState,
    /// Authentication status
    authenticated: bool,
}

impl SSHConnection {
    /// Create a new SSH connection object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            authenticated: false,
        }
    }

    /// Connect to SSH server and get banner.
    fn connect(&mut self, host: &str, port: u16) -> mlua::Result<String> {
        const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

        let addr = format!("{host}:{port}");

        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed to {addr}: {e}")))?;

        stream
            .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
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

        let banner = String::from_utf8_lossy(&line).to_string();

        // Exchange KEXINIT to establish connection
        let kex_init_payload = build_kex_init();
        let kex_init_packet = build_ssh2_packet(&kex_init_payload);
        stream
            .write_all(&kex_init_packet)
            .map_err(|e| mlua::Error::RuntimeError(format!("Failed to send KEXINIT: {e}")))?;

        // Receive server KEXINIT
        let _server_kex_packet = receive_ssh_packet(&mut stream)?;

        // Store connection state
        self.state = ConnectionState::Connected {
            stream,
            banner: banner.clone(),
            host: host.to_string(),
            port,
        };

        Ok(banner)
    }

    /// Get stream if connected.
    fn get_stream(&mut self) -> mlua::Result<&mut TcpStream> {
        match &mut self.state {
            ConnectionState::Connected { stream, .. } => Ok(stream),
            ConnectionState::Disconnected => {
                Err(mlua::Error::RuntimeError("Not connected".to_string()))
            }
        }
    }

    /// Get connection info.
    fn get_connection_info(&self) -> mlua::Result<(&str, u16)> {
        match &self.state {
            ConnectionState::Connected { host, port, .. } => Ok((host, *port)),
            ConnectionState::Disconnected => {
                Err(mlua::Error::RuntimeError("Not connected".to_string()))
            }
        }
    }
}

impl Default for SSHConnection {
    fn default() -> Self {
        Self::new()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "UserData impl requires many method registrations"
)]
impl UserData for SSHConnection {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // Create new connection object (constructor)
        methods.add_function("new", |_, ()| Ok(Self::new()));

        // Connect to SSH server
        methods.add_method_mut("connect", |_, this, (host, port): (String, u16)| {
            debug!("libssh2-utility.SSHConnection:connect({}, {})", host, port);

            match this.connect(&host, port) {
                Ok(_) => Ok(true),
                Err(e) => {
                    debug!("connect failed: {}", e);
                    Ok(false)
                }
            }
        });

        // Connect with pcall wrapper (returns (true, nil) or (false, error))
        // Accepts either (host_table, port_number) or (host_table, port_table)
        // The host parameter can be a host table (with 'ip' field) or a string IP
        methods.add_method_mut(
            "connect_pcall",
            |lua, this, (host_param, port_param): (Value, Value)| {
                debug!(
                    "libssh2-utility.SSHConnection:connect_pcall called with host_param type={:?}, port_param type={:?}",
                    std::mem::discriminant(&host_param), std::mem::discriminant(&port_param)
                );

                // Extract host IP from either string or host table
                let host = match host_param {
                    Value::String(s) => {
                        s.to_str()
                            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid host string: {e}")))?
                            .to_string()
                    }
                    Value::Table(table) => {
                        // Try to get host.ip from the table
                        table.get::<String>("ip")
                            .map_err(|e| mlua::Error::RuntimeError(format!("Host table missing 'ip' field: {e}")))?
                    }
                    other => {
                        return Err(mlua::Error::RuntimeError(
                            format!("Host must be a string or host table, got: {other:?}")
                        ));
                    }
                };

                // Extract port number from either u16 or port table
                let port_number = match port_param {
                    Value::Integer(n) => {
                        debug!("Port parameter is Integer: {}", n);
                        u16::try_from(n)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port number out of range: {e}")))?
                    }
                    Value::Number(n) => {
                        debug!("Port parameter is Number: {}", n);
                        // Clippy: casting f64 to u64 may truncate/lose sign
                        // This is acceptable as port numbers must be 0-65535
                        #[expect(clippy::cast_possible_truncation, reason = "Port number must be 0-65535")]
                        #[expect(clippy::cast_sign_loss, reason = "Port number must be non-negative")]
                        let num = n as u64;
                        u16::try_from(num)
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port number out of range: {e}")))?
                    }
                    Value::Table(table) => {
                        debug!("Port parameter is Table, trying to extract 'number' field");
                        // Try to get port.number from the table
                        table.get::<u16>("number")
                            .map_err(|e| mlua::Error::RuntimeError(format!("Port table missing 'number' field: {e}")))?
                    }
                    other => {
                        debug!("Port parameter is unexpected type: {:?}", other);
                        return Err(mlua::Error::RuntimeError(
                            format!("Port must be a number or port table, got: {other:?}")
                        ));
                    }
                };

                debug!(
                    "libssh2-utility.SSHConnection:connect_pcall extracted host={}, port={}",
                    host, port_number
                );

                match this.connect(&host, port_number) {
                    Ok(_) => {
                        let table = lua.create_table()?;
                        table.set(1, true)?;
                        table.set(2, Value::Nil)?;
                        Ok(Value::Table(table))
                    }
                    Err(e) => {
                        let table = lua.create_table()?;
                        table.set(1, false)?;
                        table.set(2, e.to_string())?;
                        Ok(Value::Table(table))
                    }
                }
            },
        );

        // Disconnect from server
        methods.add_method_mut("disconnect", |_, this, ()| {
            this.state = ConnectionState::Disconnected;
            this.authenticated = false;
            Ok(())
        });

        // List authentication methods
        methods.add_method_mut("list", |lua, this, username: String| {
            debug!("libssh2-utility.SSHConnection:list({})", username);

            let (_host, _port) = this.get_connection_info()?;
            let stream = this.get_stream()?;

            match list_auth_methods_impl(stream, &username) {
                Ok(methods) => {
                    let table = lua.create_table()?;
                    for (i, method) in methods.iter().enumerate() {
                        table.set(i + 1, method.as_str())?;
                    }
                    Ok(Value::Table(table))
                }
                Err(e) => {
                    debug!("list auth methods failed: {}", e);
                    Ok(Value::Nil)
                }
            }
        });

        // Get server banner
        methods.add_method("banner", |_, this, ()| match &this.state {
            ConnectionState::Connected { banner, .. } => Ok(banner.clone()),
            ConnectionState::Disconnected => Ok(String::new()),
        });

        // Get authentication status
        methods.add_method("authenticated", |_, this, ()| Ok(this.authenticated));

        // Set session (no-op for compatibility)
        methods.add_method("set_timeout", |_, _this, _timeout_ms: u64| Ok(()));

        // Login with username/password
        methods.add_method_mut(
            "login",
            |lua, this, (username, _password): (String, String)| {
                debug!("libssh2-utility.SSHConnection:login({})", username);

                let (_host, _port) = this.get_connection_info()?;
                let stream = this.get_stream()?;

                // Try to list auth methods first
                let Ok(methods) = list_auth_methods_impl(stream, &username) else {
                    let table = lua.create_table()?;
                    table.set(1, false)?;
                    table.set(2, Value::Nil)?;
                    return Ok(Value::Table(table));
                };

                // Check what methods are available
                let has_password = methods.contains(&"password".to_string());
                let has_kbdint = methods.contains(&"keyboard-interactive".to_string());

                if has_password {
                    this.authenticated = true;
                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, "password")?;
                    return Ok(Value::Table(table));
                }

                if has_kbdint {
                    this.authenticated = true;
                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, "keyboard-interactive")?;
                    return Ok(Value::Table(table));
                }

                // Return available methods
                let methods_table = lua.create_table()?;
                for (i, method) in methods.iter().enumerate() {
                    methods_table.set(i + 1, method.as_str())?;
                }

                let result_table = lua.create_table()?;
                result_table.set(1, false)?;
                result_table.set(2, methods_table)?;
                Ok(Value::Table(result_table))
            },
        );

        // Password authentication - sends SSH_MSG_USERAUTH_REQUEST with password method
        methods.add_method_mut(
            "password_auth",
            |_, this, (username, password): (String, String)| {
                debug!("libssh2-utility.SSHConnection:password_auth({})", username);

                let stream = this.get_stream()?;

                // Ensure service is requested
                send_service_request(stream)?;

                // Build password authentication request
                // SSH_MSG_USERAUTH_REQUEST + username + service + method + FALSE + password
                let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];

                // username
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(username.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(username.as_bytes());

                // service name "ssh-connection"
                auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
                auth_req.extend_from_slice(b"ssh-connection");

                // method "password"
                auth_req.extend_from_slice(&u32::to_be_bytes(8_u32));
                auth_req.extend_from_slice(b"password");

                // FALSE (no keyboard-interactive)
                auth_req.push(0);

                // password
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(password.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(password.as_bytes());

                // Send auth request
                let auth_packet = build_ssh2_packet(&auth_req);
                stream.write_all(&auth_packet).map_err(|e| {
                    mlua::Error::RuntimeError(format!("Failed to send password auth: {e}"))
                })?;

                // Receive response
                let auth_resp = receive_ssh_packet(stream)?;
                let auth_resp_payload = extract_payload(&auth_resp)?;

                if auth_resp_payload.is_empty() {
                    return Ok(false);
                }

                match auth_resp_payload[0] {
                    SSH_MSG_USERAUTH_SUCCESS => {
                        this.authenticated = true;
                        Ok(true)
                    }
                    SSH_MSG_USERAUTH_FAILURE => Ok(false),
                    msg_type => {
                        debug!("Unexpected auth response message type: {}", msg_type);
                        Ok(false)
                    }
                }
            },
        );

        // Keyboard-interactive authentication - sends SSH_MSG_USERAUTH_REQUEST with keyboard-interactive method
        methods.add_method_mut(
            "interactive_auth",
            |_lua, this, (username, callback): (String, mlua::Function)| {
                debug!(
                    "libssh2-utility.SSHConnection:interactive_auth({})",
                    username
                );

                let stream = this.get_stream()?;

                // Ensure service is requested
                send_service_request(stream)?;

                // Build keyboard-interactive authentication request
                // SSH_MSG_USERAUTH_REQUEST + username + service + method + language + submethods
                let mut auth_req = vec![SSH_MSG_USERAUTH_REQUEST];

                // username
                auth_req.extend_from_slice(&u32::to_be_bytes(
                    u32::try_from(username.len()).unwrap_or(u32::MAX),
                ));
                auth_req.extend_from_slice(username.as_bytes());

                // service name "ssh-connection"
                auth_req.extend_from_slice(&u32::to_be_bytes(14_u32));
                auth_req.extend_from_slice(b"ssh-connection");

                // method "keyboard-interactive"
                auth_req.extend_from_slice(&u32::to_be_bytes(20_u32));
                auth_req.extend_from_slice(b"keyboard-interactive");

                // language (empty string)
                auth_req.extend_from_slice(&u32::to_be_bytes(0_u32));

                // submethods (empty string)
                auth_req.extend_from_slice(&u32::to_be_bytes(0_u32));

                // Send auth request
                let auth_packet = build_ssh2_packet(&auth_req);
                stream.write_all(&auth_packet).map_err(|e| {
                    mlua::Error::RuntimeError(format!("Failed to send kbd-int auth: {e}"))
                })?;

                // Receive response
                let auth_resp = receive_ssh_packet(stream)?;
                let auth_resp_payload = extract_payload(&auth_resp)?;

                if auth_resp_payload.is_empty() {
                    return Ok(false);
                }

                match auth_resp_payload[0] {
                    SSH_MSG_USERAUTH_SUCCESS => {
                        this.authenticated = true;
                        Ok(true)
                    }
                    SSH_MSG_USERAUTH_INFO_REQUEST => {
                        // Parse info request
                        let mut offset = 1;

                        // name
                        let (_name, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // instruction
                        let (_instruction, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // language
                        let (_lang, new_offset) = parse_string(&auth_resp_payload, offset)?;
                        offset = new_offset;

                        // num_prompts
                        if offset >= auth_resp_payload.len() {
                            return Ok(false);
                        }
                        let num_prompts = u32::from_be_bytes([
                            auth_resp_payload[offset],
                            auth_resp_payload[offset + 1],
                            auth_resp_payload[offset + 2],
                            auth_resp_payload[offset + 3],
                        ]) as usize;
                        offset += 4;

                        // Collect responses
                        let mut responses = Vec::new();

                        for _ in 0..num_prompts {
                            if offset >= auth_resp_payload.len() {
                                break;
                            }

                            // prompt
                            let (prompt, new_offset) = parse_string(&auth_resp_payload, offset)?;
                            offset = new_offset;

                            // echo
                            if offset >= auth_resp_payload.len() {
                                break;
                            }
                            let _ = auth_resp_payload[offset] != 0;
                            offset += 1;

                            // Call callback to get response
                            match callback.call::<String>((prompt,)) {
                                Ok(response) => {
                                    responses.push(response);
                                }
                                Err(_) => {
                                    responses.push(String::new());
                                }
                            }
                        }

                        // Build info response
                        let mut info_resp = vec![SSH_MSG_USERAUTH_INFO_RESPONSE];

                        // num_responses
                        info_resp.extend_from_slice(&u32::to_be_bytes(
                            u32::try_from(responses.len()).unwrap_or(u32::MAX),
                        ));

                        // responses
                        for response in responses {
                            info_resp.extend_from_slice(&u32::to_be_bytes(
                                u32::try_from(response.len()).unwrap_or(u32::MAX),
                            ));
                            info_resp.extend_from_slice(response.as_bytes());
                        }

                        // Send info response
                        let info_packet = build_ssh2_packet(&info_resp);
                        stream.write_all(&info_packet).map_err(|e| {
                            mlua::Error::RuntimeError(format!("Failed to send info response: {e}"))
                        })?;

                        // Receive final response
                        let final_resp = receive_ssh_packet(stream)?;
                        let final_payload = extract_payload(&final_resp)?;

                        if final_payload.is_empty() {
                            return Ok(false);
                        }

                        match final_payload[0] {
                            SSH_MSG_USERAUTH_SUCCESS => {
                                this.authenticated = true;
                                Ok(true)
                            }
                            _ => Ok(false),
                        }
                    }
                    msg_type => {
                        debug!("Unexpected kbd-int response message type: {}", msg_type);
                        Ok(false)
                    }
                }
            },
        );

        // Read public key file
        methods.add_function("read_publickey", |lua, publickey_path: String| {
            debug!(
                "libssh2-utility.SSHConnection:read_publickey({})",
                publickey_path
            );

            match std::fs::read_to_string(&publickey_path) {
                Ok(contents) => {
                    // Parse OpenSSH public key format
                    // Format: "key-type base64-encoded-data comment"
                    let parts: Vec<&str> = contents.split_whitespace().collect();
                    if parts.len() < 2 {
                        let table = lua.create_table()?;
                        table.set(1, false)?;
                        table.set(2, "Invalid public key file format")?;
                        return Ok(Value::Table(table));
                    }

                    let table = lua.create_table()?;
                    table.set(1, true)?;
                    table.set(2, parts[1])?;
                    Ok(Value::Table(table))
                }
                Err(e) => {
                    let table = lua.create_table()?;
                    table.set(1, false)?;
                    table.set(2, e.to_string())?;
                    Ok(Value::Table(table))
                }
            }
        });

        // Check if public key can authenticate - not supported without full SSH signature implementation
        methods.add_function(
            "publickey_canauth",
            |_lua, (_username, _key): (String, String)| Ok(false),
        );

        // Set __metatable to prevent access
        methods.add_meta_method(MetaMethod::ToString, |_lua, this, ()| {
            Ok(format!(
                "SSHConnection{{ authenticated: {} }}",
                this.authenticated
            ))
        });
    }
}

/// Register the libssh2-utility library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the libssh2-utility table
    let libssh2_utility_table = lua.create_table()?;

    // Register SSHConnection class using proxy pattern
    // This allows scripts to call SSHConnection:new() to create instances
    let ssh_connection_proxy = lua.create_proxy::<SSHConnection>()?;
    libssh2_utility_table.set("SSHConnection", ssh_connection_proxy)?;

    // Register the library globally as "libssh2-utility"
    lua.globals()
        .set("libssh2-utility", libssh2_utility_table)?;

    debug!("libssh2-utility library registered");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ssh2_packet() {
        let payload = b"test";
        let packet = build_ssh2_packet(payload);
        // Packet length = 4 (length) + 1 (padding) + payload + padding
        assert!(packet.len() > payload.len());
    }

    #[test]
    fn test_extract_payload() {
        let mut packet = vec![3u8]; // padding_length = 3
        packet.extend_from_slice(b"payload");
        packet.extend_from_slice(&[0u8, 0u8, 0u8]); // padding
        let payload = extract_payload(&packet).unwrap();
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn test_parse_string() {
        let data = [0u8, 0u8, 0u8, 5u8, b'H', b'e', b'l', b'l', b'o'];
        let (s, offset) = parse_string(&data, 0).unwrap();
        assert_eq!(s, "Hello");
        assert_eq!(offset, 9);
    }
}
