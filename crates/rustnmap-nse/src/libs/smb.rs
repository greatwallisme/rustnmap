//! SMB (Server Message Block) library for NSE.
//!
//! This module provides the `smb` library which implements the Windows file-sharing
//! protocol (SMB1/CIFS). It corresponds to Nmap's smb NSE library.
//!
//! # Protocol Overview
//!
//! SMB is a client-server protocol for file, printer, and resource sharing.
//! The protocol flow is:
//!
//! 1. NEGOTIATE - Client and server agree on protocol dialect
//! 2. `SESSION_SETUP` - Authentication (NTLMv1/v2 or Kerberos)
//! 3. `TREE_CONNECT` - Connect to a share (IPC$, C$, etc.)
//! 4. File operations (CREATE, READ, WRITE, etc.)
//! 5. `TREE_DISCONNECT` - Disconnect from share
//! 6. `LOGOFF` - End session
//!
//! # Connection Methods
//!
//! - Port 445: Raw SMB over TCP
//! - Port 139: SMB over `NetBIOS` (requires session request)
//!
//! # Available Functions
//!
//! - `smb.get_port(host)` - Determine best SMB port
//! - `smb.start(host)` - Begin SMB session
//! - `smb.negotiate_protocol(state, overrides)` - Protocol negotiation
//! - `smb.start_session(state, overrides)` - Authenticate
//! - `smb.tree_connect(state, path, overrides)` - Connect to share
//! - `smb.create_file(state, path, overrides)` - Open file/pipe
//! - `smb.tree_disconnect(state)` - Disconnect from share
//! - `smb.logoff(state)` - End session
//! - `smb.stop(state)` - Clean up connection

use crate::error::Result;
use crate::libs::netbios;
use crate::libs::smbauth;
use crate::libs::unicode;
use crate::lua::NseLua;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

// SMB Commands
const SMB_COM_NEGOTIATE: u8 = 0x72;
const SMB_COM_SESSION_SETUP_ANDX: u8 = 0x73;
const SMB_COM_LOGOFF_ANDX: u8 = 0x74;
const SMB_COM_TREE_CONNECT_ANDX: u8 = 0x75;
const SMB_COM_TREE_DISCONNECT: u8 = 0x71;
const SMB_COM_NT_CREATE_ANDX: u8 = 0xA2;
const SMB_COM_CLOSE: u8 = 0x04;
const SMB_COM_READ_ANDX: u8 = 0x2E;
const SMB_COM_WRITE_ANDX: u8 = 0x2F;
#[allow(dead_code, reason = "Reserved for SMB TRANSACTION command support")]
const SMB_COM_TRANSACTION: u8 = 0x25;

// SMB Flags
#[allow(dead_code, reason = "Reserved for SMB canonical path support")]
const SMB_FLAGS_CANONICAL_PATHNAMES: u8 = 0x10;
const SMB_FLAGS_CASELESS_PATHNAMES: u8 = 0x08;
#[allow(dead_code, reason = "Reserved for SMB reply flag handling")]
const SMB_FLAGS_REPLY: u8 = 0x80;

// SMB Flags2
const SMB_FLAGS2_LONG_NAMES: u16 = 0x0001;
#[allow(dead_code, reason = "Reserved for extended attributes support")]
const SMB_FLAGS2_EAS: u16 = 0x0002;
#[allow(dead_code, reason = "Reserved for security signature support")]
const SMB_FLAGS2_SECURITY_SIGNATURE: u16 = 0x0004;
#[allow(dead_code, reason = "Reserved for long name support")]
const SMB_FLAGS2_IS_LONG_NAME: u16 = 0x0040;
const SMB_FLAGS2_EXTENDED_SECURITY: u16 = 0x0800;
#[allow(dead_code, reason = "Reserved for DFS support")]
const SMB_FLAGS2_DFS: u16 = 0x1000;
const SMB_FLAGS2_UNICODE: u16 = 0x8000;

// SMB Capabilities
#[allow(dead_code, reason = "Reserved for raw mode support")]
const CAP_RAW_MODE: u32 = 0x0001;
#[allow(dead_code, reason = "Reserved for MPX mode support")]
const CAP_MPX_MODE: u32 = 0x0002;
const CAP_UNICODE: u32 = 0x0004;
#[allow(dead_code, reason = "Reserved for large file support")]
const CAP_LARGE_FILES: u32 = 0x0008;
const CAP_NT_SMBS: u32 = 0x0040;
#[allow(dead_code, reason = "Reserved for RPC remote APIs support")]
const CAP_RPC_REMOTE_APIS: u32 = 0x0080;
const CAP_STATUS32: u32 = 0x0100;
#[allow(dead_code, reason = "Reserved for Level II oplocks support")]
const CAP_LEVEL_II_OPLOCKS: u32 = 0x0200;
#[allow(dead_code, reason = "Reserved for lock and read support")]
const CAP_LOCK_AND_READ: u32 = 0x0400;
#[allow(dead_code, reason = "Reserved for NT find support")]
const CAP_NT_FIND: u32 = 0x0800;
const CAP_EXTENDED_SECURITY: u32 = 0x1000;

// Security Mode flags
#[allow(dead_code, reason = "Reserved for user-level security mode")]
const SECURITY_MODE_USER: u16 = 0x01;
#[allow(dead_code, reason = "Reserved for password encryption mode")]
const SECURITY_MODE_ENCRYPT_PASSWORDS: u16 = 0x02;
#[allow(dead_code, reason = "Reserved for security signatures mode")]
const SECURITY_MODE_SECURITY_SIGNATURES: u16 = 0x04;
#[allow(dead_code, reason = "Reserved for required security signatures mode")]
const SECURITY_MODE_SECURITY_SIGNATURES_REQUIRED: u16 = 0x08;

// Default timeout in milliseconds
const DEFAULT_TIMEOUT_MS: u64 = 10_000;

// SMB header size
const SMB_HEADER_SIZE: usize = 32;

// SMB signature
const SMB_SIGNATURE: &[u8; 4] = b"\xFFSMB";

/// SMB state object (managed by Lua as a table)
#[derive(Debug, Clone)]
pub struct SmbState {
    /// Target host
    pub host: String,
    /// IP address
    pub ip: IpAddr,
    /// Port number
    pub port: u16,
    /// User ID from session setup
    pub uid: u16,
    /// Tree ID from tree connect
    pub tid: u16,
    /// Message ID (incrementing)
    pub mid: u16,
    /// Process ID (random at start)
    pub pid: u16,
    /// Signature sequence (-1 = disabled)
    pub sequence: i64,
    /// Use extended security (`NTLMv2`)
    pub extended_security: bool,
    /// Security mode from negotiate
    pub security_mode: u16,
    /// Max multiplexed requests
    pub max_mpx: u16,
    /// Max virtual circuits
    pub max_vcs: u16,
    /// Max buffer size
    pub max_buffer: u32,
    /// Session key from negotiate
    pub session_key: Vec<u8>,
    /// Server name
    pub server_name: String,
    /// Domain name
    pub domain_name: String,
    /// MAC key for signing
    pub mac_key: Option<Vec<u8>>,
    /// Capabilities
    pub capabilities: u32,
}

impl Default for SmbState {
    fn default() -> Self {
        Self {
            host: String::new(),
            ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 445,
            uid: 0,
            tid: 0,
            mid: 0,
            pid: rand::random(),
            sequence: -1,
            extended_security: false,
            security_mode: 0,
            max_mpx: 50,
            max_vcs: 1,
            max_buffer: 65536,
            session_key: Vec::new(),
            server_name: String::new(),
            domain_name: String::new(),
            mac_key: None,
            capabilities: 0,
        }
    }
}

/// Register the smb library with the Lua runtime.
///
/// # Errors
///
/// Returns an error if library registration fails.
#[expect(
    clippy::too_many_lines,
    reason = "SMB protocol implementation requires handling multiple message types and session states"
)]
pub fn register(nse_lua: &mut NseLua) -> Result<()> {
    let lua = nse_lua.lua_mut();

    // Create the smb table
    let smb_table = lua.create_table()?;

    // Register get_port function
    let get_port_fn = lua.create_function(|_lua, host: mlua::Value| {
        let port = determine_smb_port(&host);
        Ok(port)
    })?;
    smb_table.set("get_port", get_port_fn)?;

    // Register start function
    let start_fn = lua.create_function(|lua, host: mlua::Value| match smb_start(&host) {
        Ok(state) => {
            let table = smb_state_to_table(lua, &state)?;
            Ok((true, mlua::Value::Table(table)))
        }
        Err(e) => Ok((
            false,
            mlua::Value::String(lua.create_string(e.to_string())?),
        )),
    })?;
    smb_table.set("start", start_fn)?;

    // Register negotiate_protocol function
    let negotiate_fn = lua.create_function(|lua, state_table: mlua::Table| {
        let state = table_to_smb_state(&state_table)?;
        match smb_negotiate_protocol(&state) {
            Ok(new_state) => {
                update_state_table(&state_table, &new_state)?;
                Ok((true, mlua::Value::Nil))
            }
            Err(e) => Ok((
                false,
                mlua::Value::String(lua.create_string(e.to_string())?),
            )),
        }
    })?;
    smb_table.set("negotiate_protocol", negotiate_fn)?;

    // Register start_session function
    let start_session_fn = lua.create_function(
        |lua, (state_table, overrides): (mlua::Table, Option<mlua::Table>)| {
            let state = table_to_smb_state(&state_table)?;
            let username = overrides
                .as_ref()
                .and_then(|o| o.get::<Option<String>>("username").ok().flatten());
            let password = overrides
                .as_ref()
                .and_then(|o| o.get::<Option<String>>("password").ok().flatten());
            let domain = overrides
                .as_ref()
                .and_then(|o| o.get::<Option<String>>("domain").ok().flatten());
            match smb_start_session(
                &state,
                username.as_deref(),
                password.as_deref(),
                domain.as_deref(),
            ) {
                Ok(new_state) => {
                    update_state_table(&state_table, &new_state)?;
                    Ok((true, mlua::Value::Nil))
                }
                Err(e) => Ok((
                    false,
                    mlua::Value::String(lua.create_string(e.to_string())?),
                )),
            }
        },
    )?;
    smb_table.set("start_session", start_session_fn)?;

    // Register tree_connect function
    let tree_connect_fn = lua.create_function(
        |lua, (state_table, path, _overrides): (mlua::Table, String, Option<mlua::Table>)| {
            let state = table_to_smb_state(&state_table)?;
            match smb_tree_connect(&state, &path) {
                Ok(new_state) => {
                    update_state_table(&state_table, &new_state)?;
                    Ok((true, mlua::Value::Nil))
                }
                Err(e) => Ok((
                    false,
                    mlua::Value::String(lua.create_string(e.to_string())?),
                )),
            }
        },
    )?;
    smb_table.set("tree_connect", tree_connect_fn)?;

    // Register create_file function
    let create_file_fn = lua.create_function(
        |lua, (state_table, path, _overrides): (mlua::Table, String, Option<mlua::Table>)| {
            let state = table_to_smb_state(&state_table)?;
            match smb_create_file(&state, &path) {
                Ok(_fid) => Ok((true, mlua::Value::Nil)),
                Err(e) => Ok((
                    false,
                    mlua::Value::String(lua.create_string(e.to_string())?),
                )),
            }
        },
    )?;
    smb_table.set("create_file", create_file_fn)?;

    // Register tree_disconnect function
    let tree_disconnect_fn = lua.create_function(|lua, state_table: mlua::Table| {
        let state = table_to_smb_state(&state_table)?;
        match smb_tree_disconnect(&state) {
            Ok(new_state) => {
                update_state_table(&state_table, &new_state)?;
                Ok((true, mlua::Value::Nil))
            }
            Err(e) => Ok((
                false,
                mlua::Value::String(lua.create_string(e.to_string())?),
            )),
        }
    })?;
    smb_table.set("tree_disconnect", tree_disconnect_fn)?;

    // Register logoff function
    let logoff_fn = lua.create_function(|lua, state_table: mlua::Table| {
        let state = table_to_smb_state(&state_table)?;
        match smb_logoff(&state) {
            Ok(new_state) => {
                update_state_table(&state_table, &new_state)?;
                Ok((true, mlua::Value::Nil))
            }
            Err(e) => Ok((
                false,
                mlua::Value::String(lua.create_string(e.to_string())?),
            )),
        }
    })?;
    smb_table.set("logoff", logoff_fn)?;

    // Register stop function
    let stop_fn = lua.create_function(|lua, state_table: mlua::Table| {
        let state = table_to_smb_state(&state_table)?;
        match smb_stop(&state) {
            Ok(()) => Ok((true, mlua::Value::Nil)),
            Err(e) => Ok((
                false,
                mlua::Value::String(lua.create_string(e.to_string())?),
            )),
        }
    })?;
    smb_table.set("stop", stop_fn)?;

    // Set constants
    smb_table.set("COMMAND_NEGOTIATE", SMB_COM_NEGOTIATE)?;
    smb_table.set("COMMAND_SESSION_SETUP", SMB_COM_SESSION_SETUP_ANDX)?;
    smb_table.set("COMMAND_TREE_CONNECT", SMB_COM_TREE_CONNECT_ANDX)?;
    smb_table.set("COMMAND_TREE_DISCONNECT", SMB_COM_TREE_DISCONNECT)?;
    smb_table.set("COMMAND_NT_CREATE", SMB_COM_NT_CREATE_ANDX)?;
    smb_table.set("COMMAND_CLOSE", SMB_COM_CLOSE)?;
    smb_table.set("COMMAND_READ", SMB_COM_READ_ANDX)?;
    smb_table.set("COMMAND_WRITE", SMB_COM_WRITE_ANDX)?;

    // Set the smb table in globals
    lua.globals().set("smb", smb_table)?;

    Ok(())
}

/// Determine the best SMB port to use.
///
/// This function examines the host table to find the appropriate SMB port.
/// It returns the port if found, otherwise returns `445` (default).
#[must_use]
fn determine_smb_port(host: &mlua::Value) -> u16 {
    // Try to extract port from host table
    if let mlua::Value::Table(t) = host {
        // Check for explicit smbport script argument
        if let Ok(Some(port)) = t.get::<Option<u16>>("smbport") {
            return port;
        }

        // Check ports table
        if let Ok(ports) = t.get::<mlua::Table>("ports") {
            // Prefer port 445 (raw SMB)
            for pair in ports.pairs::<mlua::Value, mlua::Value>() {
                if let Ok((mlua::Value::Table(port_table), _)) = pair {
                    if let (Ok(Some(number)), Ok(Some(protocol))) = (
                        port_table.get::<Option<u16>>("number"),
                        port_table.get::<Option<String>>("protocol"),
                    ) {
                        if number == 445 && protocol.to_lowercase() == "tcp" {
                            return 445;
                        }
                    }
                }
            }
            // Fall back to port 139 (NetBIOS)
            for pair in ports.pairs::<mlua::Value, mlua::Value>() {
                if let Ok((mlua::Value::Table(port_table), _)) = pair {
                    if let (Ok(Some(number)), Ok(Some(protocol))) = (
                        port_table.get::<Option<u16>>("number"),
                        port_table.get::<Option<String>>("protocol"),
                    ) {
                        if number == 139 && protocol.to_lowercase() == "tcp" {
                            return 139;
                        }
                    }
                }
            }
        }
    }

    // Default to 445
    445
}

/// Convert `SmbState` to Lua table.
fn smb_state_to_table(lua: &mlua::Lua, state: &SmbState) -> mlua::Result<mlua::Table> {
    let table = lua.create_table()?;
    table.set("host", state.host.clone())?;
    table.set("ip", state.ip.to_string())?;
    table.set("port", state.port)?;
    table.set("uid", state.uid)?;
    table.set("tid", state.tid)?;
    table.set("mid", state.mid)?;
    table.set("pid", state.pid)?;
    table.set("sequence", state.sequence)?;
    table.set("extended_security", state.extended_security)?;
    table.set("security_mode", state.security_mode)?;
    table.set("max_mpx", state.max_mpx)?;
    table.set("max_vcs", state.max_vcs)?;
    table.set("max_buffer", state.max_buffer)?;
    table.set("session_key", state.session_key.clone())?;
    table.set("server_name", state.server_name.clone())?;
    table.set("domain_name", state.domain_name.clone())?;
    table.set("capabilities", state.capabilities)?;
    Ok(table)
}

/// Convert Lua table to `SmbState`.
fn table_to_smb_state(table: &mlua::Table) -> mlua::Result<SmbState> {
    let host: String = table.get("host")?;
    let ip_str: String = table.get("ip")?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|e| mlua::Error::RuntimeError(format!("Invalid IP address '{ip_str}': {e}")))?;
    let port: u16 = table.get("port").unwrap_or(445);
    let uid: u16 = table.get("uid").unwrap_or(0);
    let tid: u16 = table.get("tid").unwrap_or(0);
    let mid: u16 = table.get("mid").unwrap_or(0);
    let pid: u16 = table.get("pid").unwrap_or_else(|_| rand::random());
    let sequence: i64 = table.get("sequence").unwrap_or(-1);
    let extended_security: bool = table.get("extended_security").unwrap_or(false);
    let security_mode: u16 = table.get("security_mode").unwrap_or(0);
    let max_mpx: u16 = table.get("max_mpx").unwrap_or(50);
    let max_vcs: u16 = table.get("max_vcs").unwrap_or(1);
    let max_buffer: u32 = table.get("max_buffer").unwrap_or(65536);
    let session_key: Vec<u8> = table.get("session_key").unwrap_or_default();
    let server_name: String = table.get("server_name").unwrap_or_default();
    let domain_name: String = table.get("domain_name").unwrap_or_default();
    let capabilities: u32 = table.get("capabilities").unwrap_or(0);

    Ok(SmbState {
        host,
        ip,
        port,
        uid,
        tid,
        mid,
        pid,
        sequence,
        extended_security,
        security_mode,
        max_mpx,
        max_vcs,
        max_buffer,
        session_key,
        server_name,
        domain_name,
        mac_key: None,
        capabilities,
    })
}

/// Update `Lua` table with new `SmbState` values.
fn update_state_table(table: &mlua::Table, state: &SmbState) -> mlua::Result<()> {
    table.set("uid", state.uid)?;
    table.set("tid", state.tid)?;
    table.set("mid", state.mid)?;
    table.set("sequence", state.sequence)?;
    table.set("extended_security", state.extended_security)?;
    table.set("security_mode", state.security_mode)?;
    table.set("max_mpx", state.max_mpx)?;
    table.set("max_vcs", state.max_vcs)?;
    table.set("max_buffer", state.max_buffer)?;
    table.set("session_key", state.session_key.clone())?;
    table.set("server_name", state.server_name.clone())?;
    table.set("domain_name", state.domain_name.clone())?;
    table.set("capabilities", state.capabilities)?;
    Ok(())
}

/// Start SMB session - connect to server.
fn smb_start(host: &mlua::Value) -> Result<SmbState> {
    let port = determine_smb_port(host);

    // Extract IP address from host
    let ip: IpAddr = if let mlua::Value::Table(t) = host {
        let ip_str: String = t
            .get("ip")
            .or_else(|_| t.get("address"))
            .unwrap_or_else(|_| "0.0.0.0".to_string());
        ip_str
            .parse()
            .map_err(|e| crate::error::Error::NetworkError(format!("Invalid IP address: {e}")))?
    } else {
        return Err(crate::error::Error::NetworkError(
            "Invalid host parameter".to_string(),
        ));
    };

    let host = if let mlua::Value::Table(t) = host {
        t.get("name").unwrap_or_else(|_| ip.to_string())
    } else {
        ip.to_string()
    };

    let state = SmbState {
        host,
        ip,
        port,
        ..SmbState::default()
    };

    // Connect to server
    let addr = SocketAddr::new(ip, port);
    let mut socket =
        TcpStream::connect_timeout(&addr, Duration::from_millis(DEFAULT_TIMEOUT_MS))
            .map_err(|e| crate::error::Error::NetworkError(format!("Connection failed: {e}")))?;

    socket
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .map_err(|e| crate::error::Error::NetworkError(format!("Failed to set timeout: {e}")))?;

    // If using NetBIOS (port 139), send session request
    if port == 139 {
        send_netbios_session_request(&mut socket, &state)?;
    }

    // Store socket reference in state (we'll use a global store for sockets)
    store_socket(&state, socket)?;

    Ok(state)
}

/// Send `NetBIOS` session request for port 139 connections.
fn send_netbios_session_request(socket: &mut TcpStream, state: &SmbState) -> Result<()> {
    // Use server name from state or default to *SMBSERVER
    let server_name = if state.server_name.is_empty() {
        "*SMBSERVER".to_string()
    } else {
        state.server_name.clone()
    };

    // Encode NetBIOS names
    let called_name = netbios::name_encode(&server_name, Some("0x20"));
    let calling_name = netbios::name_encode("RUSTNMAP", None);

    // Build session request
    let session_len = called_name.len() + calling_name.len();
    let mut request = Vec::with_capacity(4 + session_len);
    request.push(0x81); // Session request
    request.push(0x00); // Flags
    #[expect(
        clippy::map_err_ignore,
        reason = "Custom error message is more informative than TryFromIntError"
    )]
    let session_len_u16 = u16::try_from(session_len)
        .map_err(|_| crate::error::Error::NetworkError("Session length too large".to_string()))?;
    request.extend_from_slice(&session_len_u16.to_be_bytes());
    request.extend(called_name);
    request.extend(calling_name);

    socket.write_all(&request).map_err(|e| {
        crate::error::Error::NetworkError(format!("NetBIOS session request failed: {e}"))
    })?;

    // Read response
    let mut response = [0u8; 4];
    socket.read_exact(&mut response).map_err(|e| {
        crate::error::Error::NetworkError(format!("NetBIOS session response failed: {e}"))
    })?;

    if response[0] != 0x82 {
        return Err(crate::error::Error::NetworkError(
            "NetBIOS session request rejected".to_string(),
        ));
    }

    Ok(())
}

/// SMB negotiate protocol.
fn smb_negotiate_protocol(state: &SmbState) -> Result<SmbState> {
    let mut new_state = state.clone();
    new_state.mid += 1;

    // Build NEGOTIATE request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_NEGOTIATE);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(
        &(SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY).to_le_bytes(),
    );
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&new_state.tid.to_le_bytes());
    request.extend_from_slice(&new_state.pid.to_le_bytes());
    request.extend_from_slice(&new_state.uid.to_le_bytes());
    request.extend_from_slice(&new_state.mid.to_le_bytes());

    // NEGOTIATE parameters
    request.push(0); // WordCount
    let dialects = b"\x02NT LM 0.12\x00"; // Dialect string
    request.extend_from_slice(&(u16::try_from(dialects.len()).unwrap()).to_le_bytes()); // ByteCount
    request.extend_from_slice(dialects);

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let response = recv_smb_message(&socket)?;

    // Parse response
    if response.len() < SMB_HEADER_SIZE + 35 {
        return Err(crate::error::Error::NetworkError(
            "NEGOTIATE response too short".to_string(),
        ));
    }

    // Check status
    let status = u32::from_le_bytes([response[5], response[6], response[7], response[8]]);
    if status != 0 {
        return Err(crate::error::Error::NetworkError(format!(
            "NEGOTIATE failed with status 0x{status:08X}"
        )));
    }

    // Parse negotiate response
    let word_count = response[SMB_HEADER_SIZE];
    if word_count != 17 {
        return Err(crate::error::Error::NetworkError(format!(
            "Unexpected NEGOTIATE word count: {word_count}"
        )));
    }

    let offset = SMB_HEADER_SIZE + 1;
    let _dialect_index = u16::from_le_bytes([response[offset], response[offset + 1]]);
    new_state.security_mode = u16::from_le_bytes([response[offset + 2], response[offset + 3]]);
    new_state.max_mpx = u16::from_le_bytes([response[offset + 4], response[offset + 5]]);
    new_state.max_vcs = u16::from_le_bytes([response[offset + 6], response[offset + 7]]);
    new_state.max_buffer = u32::from_le_bytes([
        response[offset + 8],
        response[offset + 9],
        response[offset + 10],
        response[offset + 11],
    ]);
    let session_key = u32::from_le_bytes([
        response[offset + 16],
        response[offset + 17],
        response[offset + 18],
        response[offset + 19],
    ]);
    new_state.session_key = session_key.to_le_bytes().to_vec();
    new_state.capabilities = u32::from_le_bytes([
        response[offset + 20],
        response[offset + 21],
        response[offset + 22],
        response[offset + 23],
    ]);

    // Check for extended security
    new_state.extended_security = (new_state.capabilities & CAP_EXTENDED_SECURITY) != 0;

    // Extract server name and domain name if present
    let byte_count = u16::from_le_bytes([response[offset + 32], response[offset + 33]]) as usize;
    let data_offset = offset + 34;
    if data_offset + byte_count <= response.len() && byte_count > 0 {
        // Server name is after domain name in the blob
        // For extended security, this is server name only
        if let Ok(name) = unicode::utf16le_to_utf8(&response[data_offset..data_offset + byte_count])
        {
            new_state.server_name = name;
        }
    }

    Ok(new_state)
}

/// SMB start session (authenticate).
///
/// # Panics
///
/// Does not panic
#[allow(
    clippy::too_many_lines,
    reason = "NTLM authentication handshake requires multiple steps per protocol spec"
)]
fn smb_start_session(
    state: &SmbState,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<SmbState> {
    // Build SESSION_SETUP request with security blob
    let mut new_state = state.clone();
    new_state.mid += 1;

    let username = username.unwrap_or("");
    let password = password.unwrap_or("");
    let domain = domain.unwrap_or("");

    // Build SESSION_SETUP request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_SESSION_SETUP_ANDX);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(
        &(SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY).to_le_bytes(),
    );
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&new_state.tid.to_le_bytes());
    request.extend_from_slice(&new_state.pid.to_le_bytes());
    request.extend_from_slice(&new_state.uid.to_le_bytes());
    request.extend_from_slice(&new_state.mid.to_le_bytes());

    // Get security blob using smbauth
    let security_blob = if new_state.extended_security {
        smbauth::build_negotiate_message(
            0x0008_0200, // NTLM | UNICODE
            Some(&unicode::utf8_to_utf16le(domain)),
            Some(&unicode::utf8_to_utf16le("RUSTNMAP")),
        )
    } else {
        // Basic security - not commonly used
        Vec::new()
    };

    // SESSION_SETUP parameters
    request.push(13); // WordCount (13 for extended security)
    request.push(0xFF); // AndXCommand (none)
    request.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    request.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset

    // Max buffer, max mpx, vc number
    #[expect(
        clippy::map_err_ignore,
        reason = "Custom error message is more informative than TryFromIntError"
    )]
    let max_buffer_u16 = u16::try_from(new_state.max_buffer)
        .map_err(|_| crate::error::Error::NetworkError("Max buffer too large".to_string()))?;
    request.extend_from_slice(&max_buffer_u16.to_le_bytes());
    request.extend_from_slice(&new_state.max_mpx.to_le_bytes());
    request.extend_from_slice(&1u16.to_le_bytes()); // VcNumber

    // Session key
    let session_key = if new_state.session_key.len() >= 4 {
        u32::from_le_bytes([
            new_state.session_key[0],
            new_state.session_key[1],
            new_state.session_key[2],
            new_state.session_key[3],
        ])
    } else {
        0
    };
    request.extend_from_slice(&session_key.to_le_bytes());

    // Security blob length
    #[expect(
        clippy::map_err_ignore,
        reason = "Custom error message is more informative than TryFromIntError"
    )]
    let blob_len = u16::try_from(security_blob.len())
        .map_err(|_| crate::error::Error::NetworkError("Security blob too large".to_string()))?;
    request.extend_from_slice(&blob_len.to_le_bytes());

    // Reserved
    request.extend_from_slice(&0u32.to_le_bytes());

    // Capabilities
    let capabilities = CAP_UNICODE | CAP_NT_SMBS | CAP_STATUS32 | CAP_EXTENDED_SECURITY;
    request.extend_from_slice(&capabilities.to_le_bytes());

    // Byte count
    let native_os = b"Windows 5.1\x00\x00";
    let native_lanman = b"Windows 2000 LAN Manager\x00\x00";
    let byte_count = security_blob.len() + native_os.len() + native_lanman.len();
    #[expect(
        clippy::map_err_ignore,
        reason = "Custom error message is more informative than TryFromIntError"
    )]
    let byte_count_u16_1 = u16::try_from(byte_count)
        .map_err(|_| crate::error::Error::NetworkError("Byte count too large".to_string()))?;
    request.extend_from_slice(&byte_count_u16_1.to_le_bytes());

    // Payload
    request.extend(security_blob);
    request.extend_from_slice(native_os);
    request.extend_from_slice(native_lanman);

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let response = recv_smb_message(&socket)?;

    // Parse response - this should contain the NTLMSSP_CHALLENGE
    if response.len() < SMB_HEADER_SIZE + 4 {
        return Err(crate::error::Error::NetworkError(
            "SESSION_SETUP response too short".to_string(),
        ));
    }

    // Check status - expect MORE_PROCESSING_REQUIRED (0xC0000016) for extended security
    let status = u32::from_le_bytes([response[5], response[6], response[7], response[8]]);

    // For extended security, we need a second SESSION_SETUP with the AUTHENTICATE message
    if status == 0xC000_0016 {
        // More processing required - parse the challenge and send AUTHENTICATE
        let word_count = response[SMB_HEADER_SIZE];
        if word_count < 4 {
            return Err(crate::error::Error::NetworkError(
                "Invalid SESSION_SETUP response".to_string(),
            ));
        }

        let offset = SMB_HEADER_SIZE + 1;
        let andx_offset = u16::from_le_bytes([response[offset + 2], response[offset + 3]]);
        let security_blob_len =
            u16::from_le_bytes([response[offset + 7], response[offset + 8]]) as usize;

        // Extract server challenge blob
        let blob_offset = SMB_HEADER_SIZE + 2 + (andx_offset as usize);
        if blob_offset + security_blob_len > response.len() {
            return Err(crate::error::Error::NetworkError(
                "Security blob exceeds response length".to_string(),
            ));
        }
        let server_blob = &response[blob_offset..blob_offset + security_blob_len];

        // Parse the NTLMSSP CHALLENGE message and generate AUTHENTICATE message
        let challenge = smbauth::parse_challenge_message(server_blob).map_err(|e| {
            crate::error::Error::NetworkError(format!("Failed to parse challenge: {e}"))
        })?;

        // Compute LM and NT responses
        let (lm_response, nt_response) =
            smbauth::compute_responses(&challenge, Some(username), Some(password), Some("ntlmv2"))
                .map_err(|e| {
                    crate::error::Error::NetworkError(format!("Failed to compute responses: {e}"))
                })?;

        // Build AUTHENTICATE message
        let domain_utf16 = unicode::utf8_to_utf16le(domain);
        let username_utf16 = unicode::utf8_to_utf16le(username);
        let workstation_utf16 = unicode::utf8_to_utf16le("RUSTNMAP");

        let auth_blob = smbauth::build_authenticate_message(
            &lm_response,
            &nt_response,
            &domain_utf16,
            &username_utf16,
            &workstation_utf16,
            None,
            challenge.flags,
        );

        // Send second SESSION_SETUP with AUTHENTICATE
        new_state.mid += 1;
        let mut request2 = Vec::new();

        // SMB Header
        request2.extend_from_slice(SMB_SIGNATURE);
        request2.push(SMB_COM_SESSION_SETUP_ANDX);
        request2.extend_from_slice(&0u32.to_le_bytes()); // Status
        request2.push(SMB_FLAGS_CASELESS_PATHNAMES);
        request2.extend_from_slice(
            &(SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE | SMB_FLAGS2_EXTENDED_SECURITY)
                .to_le_bytes(),
        );
        request2.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
        request2.extend_from_slice(&new_state.tid.to_le_bytes());
        request2.extend_from_slice(&new_state.pid.to_le_bytes());
        request2.extend_from_slice(&new_state.uid.to_le_bytes());
        request2.extend_from_slice(&new_state.mid.to_le_bytes());

        // SESSION_SETUP parameters
        request2.push(13); // WordCount
        request2.push(0xFF); // AndXCommand (none)
        request2.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        request2.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
        #[expect(
            clippy::map_err_ignore,
            reason = "Custom error message is more informative than TryFromIntError"
        )]
        let max_buffer_u16 = u16::try_from(new_state.max_buffer)
            .map_err(|_| crate::error::Error::NetworkError("Max buffer too large".to_string()))?;
        request2.extend_from_slice(&max_buffer_u16.to_le_bytes());
        request2.extend_from_slice(&new_state.max_mpx.to_le_bytes());
        request2.extend_from_slice(&1u16.to_le_bytes()); // VcNumber
        request2.extend_from_slice(&session_key.to_le_bytes());
        #[expect(
            clippy::map_err_ignore,
            reason = "Custom error message is more informative than TryFromIntError"
        )]
        let auth_blob_len = u16::try_from(auth_blob.len())
            .map_err(|_| crate::error::Error::NetworkError("Auth blob too large".to_string()))?;
        request2.extend_from_slice(&auth_blob_len.to_le_bytes());
        request2.extend_from_slice(&0u32.to_le_bytes());
        request2.extend_from_slice(&capabilities.to_le_bytes());

        // Byte count
        let byte_count2 = auth_blob.len() + native_os.len() + native_lanman.len();
        #[expect(
            clippy::map_err_ignore,
            reason = "Custom error message is more informative than TryFromIntError"
        )]
        let byte_count2_u16 = u16::try_from(byte_count2)
            .map_err(|_| crate::error::Error::NetworkError("Byte count too large".to_string()))?;
        request2.extend_from_slice(&byte_count2_u16.to_le_bytes());

        // Payload
        request2.extend(auth_blob);
        request2.extend_from_slice(native_os);
        request2.extend_from_slice(native_lanman);

        send_smb_message(&socket, &request2)?;
        let response2 = recv_smb_message(&socket)?;

        // Check final status
        let status2 = u32::from_le_bytes([response2[5], response2[6], response2[7], response2[8]]);
        if status2 != 0 {
            return Err(crate::error::Error::NetworkError(format!(
                "SESSION_SETUP authentication failed with status 0x{status2:08X}"
            )));
        }

        // Extract UID from response
        new_state.uid = u16::from_le_bytes([response2[20], response2[21]]);
    } else if status != 0 {
        return Err(crate::error::Error::NetworkError(format!(
            "SESSION_SETUP failed with status 0x{status:08X}"
        )));
    }

    Ok(new_state)
}

/// SMB tree connect.
fn smb_tree_connect(state: &SmbState, path: &str) -> Result<SmbState> {
    let mut new_state = state.clone();
    new_state.mid += 1;

    // Build TREE_CONNECT request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_TREE_CONNECT_ANDX);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(&(SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE).to_le_bytes());
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&new_state.tid.to_le_bytes());
    request.extend_from_slice(&new_state.pid.to_le_bytes());
    request.extend_from_slice(&new_state.uid.to_le_bytes());
    request.extend_from_slice(&new_state.mid.to_le_bytes());

    // TREE_CONNECT parameters
    request.push(4); // WordCount
    request.push(0xFF); // AndXCommand (none)
    request.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    request.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    request.extend_from_slice(&0u16.to_le_bytes()); // Flags
    request.extend_from_slice(&0u16.to_le_bytes()); // PasswordLength

    // Build path: \\SERVER\share
    let full_path = format!(
        "\\\\{server_name}\\{path}",
        server_name = new_state.server_name,
        path = path
    );
    let path_utf16 = unicode::utf8_to_utf16le(&full_path);
    let service = b"?????\x00"; // IPC$ service

    // Byte count
    let byte_count = path_utf16.len() + service.len();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "SMB byte count fits in u16"
    )]
    request.extend_from_slice(&(byte_count as u16).to_le_bytes());

    // Payload
    request.extend(path_utf16);
    request.extend_from_slice(service);

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let response = recv_smb_message(&socket)?;

    // Check status
    let status = u32::from_le_bytes([response[5], response[6], response[7], response[8]]);
    if status != 0 {
        return Err(crate::error::Error::NetworkError(format!(
            "TREE_CONNECT failed with status 0x{status:08X}"
        )));
    }

    // Extract TID from response
    new_state.tid = u16::from_le_bytes([response[16], response[17]]);

    Ok(new_state)
}

/// SMB create file (open named pipe or file).
fn smb_create_file(state: &SmbState, path: &str) -> Result<u16> {
    let mid = state.mid + 1;

    // Build NT_CREATE request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_NT_CREATE_ANDX);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(&(SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_UNICODE).to_le_bytes());
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&state.tid.to_le_bytes());
    request.extend_from_slice(&state.pid.to_le_bytes());
    request.extend_from_slice(&state.uid.to_le_bytes());
    request.extend_from_slice(&mid.to_le_bytes());

    // NT_CREATE parameters (24 words)
    request.push(24); // WordCount
    request.push(0xFF); // AndXCommand (none)
    request.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    request.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    request.extend_from_slice(&0u16.to_le_bytes()); // Reserved2

    // FileNameLength
    let path_utf16 = unicode::utf8_to_utf16le(path);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "UTF-16 path length fits in u16"
    )]
    request.extend_from_slice(&((path_utf16.len() - 2) as u16).to_le_bytes());

    // CreateFlags
    request.extend_from_slice(&0x0000_0020u32.to_le_bytes());

    // RootDirectoryFid
    request.extend_from_slice(&0u32.to_le_bytes());

    // DesiredAccess (FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE)
    request.extend_from_slice(&0x0012_019Fu32.to_le_bytes());

    // AllocationSize (8 bytes)
    request.extend_from_slice(&0u64.to_le_bytes());

    // ExtFileAttributes
    request.extend_from_slice(&0x80u32.to_le_bytes());

    // ShareAccess
    request.extend_from_slice(&0x03u32.to_le_bytes());

    // CreateDisposition (FILE_OPEN)
    request.extend_from_slice(&0x01u32.to_le_bytes());

    // CreateOptions
    request.extend_from_slice(&0x0040_0000u32.to_le_bytes());

    // ImpersonationLevel
    request.extend_from_slice(&0x02u32.to_le_bytes());

    // SecurityFlags
    request.extend_from_slice(&0x03u16.to_le_bytes());

    // Byte count
    #[expect(
        clippy::cast_possible_truncation,
        reason = "UTF-16 path length fits in u16"
    )]
    request.extend_from_slice(&((path_utf16.len()) as u16).to_le_bytes());

    // Payload (filename)
    request.extend(path_utf16);

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let response = recv_smb_message(&socket)?;

    // Check status
    let status = u32::from_le_bytes([response[5], response[6], response[7], response[8]]);
    if status != 0 {
        return Err(crate::error::Error::NetworkError(format!(
            "NT_CREATE failed with status 0x{status:08X}"
        )));
    }

    // Extract FID from response
    if response.len() < SMB_HEADER_SIZE + 10 {
        return Err(crate::error::Error::NetworkError(
            "NT_CREATE response too short".to_string(),
        ));
    }
    let fid = u16::from_le_bytes([response[SMB_HEADER_SIZE + 7], response[SMB_HEADER_SIZE + 8]]);

    Ok(fid)
}

/// SMB tree disconnect.
fn smb_tree_disconnect(state: &SmbState) -> Result<SmbState> {
    let mut new_state = state.clone();
    new_state.mid += 1;

    // Build TREE_DISCONNECT request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_TREE_DISCONNECT);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(&SMB_FLAGS2_LONG_NAMES.to_le_bytes());
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&new_state.tid.to_le_bytes());
    request.extend_from_slice(&new_state.pid.to_le_bytes());
    request.extend_from_slice(&new_state.uid.to_le_bytes());
    request.extend_from_slice(&new_state.mid.to_le_bytes());

    // TREE_DISCONNECT parameters
    request.push(0); // WordCount
    request.extend_from_slice(&0u16.to_le_bytes()); // ByteCount

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let _response = recv_smb_message(&socket)?;

    new_state.tid = 0;

    Ok(new_state)
}

/// SMB logoff.
fn smb_logoff(state: &SmbState) -> Result<SmbState> {
    let mut new_state = state.clone();
    new_state.mid += 1;

    // Build LOGOFF request
    let mut request = Vec::new();

    // SMB Header
    request.extend_from_slice(SMB_SIGNATURE);
    request.push(SMB_COM_LOGOFF_ANDX);
    request.extend_from_slice(&0u32.to_le_bytes()); // Status
    request.push(SMB_FLAGS_CASELESS_PATHNAMES);
    request.extend_from_slice(&SMB_FLAGS2_LONG_NAMES.to_le_bytes());
    request.extend_from_slice(&[0u8; 12]); // PID High + Signature + Reserved
    request.extend_from_slice(&new_state.tid.to_le_bytes());
    request.extend_from_slice(&new_state.pid.to_le_bytes());
    request.extend_from_slice(&new_state.uid.to_le_bytes());
    request.extend_from_slice(&new_state.mid.to_le_bytes());

    // LOGOFF parameters
    request.push(2); // WordCount
    request.push(0xFF); // AndXCommand (none)
    request.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    request.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    request.extend_from_slice(&0u16.to_le_bytes()); // ByteCount

    // Send request
    let socket = get_socket(state)?;
    send_smb_message(&socket, &request)?;

    // Receive response
    let _response = recv_smb_message(&socket)?;

    new_state.uid = 0;

    Ok(new_state)
}

/// SMB stop - clean up connection.
fn smb_stop(state: &SmbState) -> Result<()> {
    // Close socket
    remove_socket(state)?;

    Ok(())
}

// ============================================================================
// Socket management (using thread-local storage for simplicity)
// ============================================================================

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;

static SOCKETS: LazyLock<Mutex<HashMap<String, TcpStream>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn socket_key(state: &SmbState) -> String {
    format!(
        "{}:{port}:{pid}",
        state.ip,
        port = state.port,
        pid = state.pid
    )
}

fn store_socket(state: &SmbState, socket: TcpStream) -> Result<()> {
    let key = socket_key(state);
    let mut sockets = SOCKETS
        .lock()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket lock failed: {e}")))?;
    sockets.insert(key, socket);
    Ok(())
}

fn get_socket(state: &SmbState) -> Result<TcpStream> {
    let key = socket_key(state);
    let sockets = SOCKETS
        .lock()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket lock failed: {e}")))?;
    sockets
        .get(&key)
        .ok_or_else(|| crate::error::Error::NetworkError("Socket not found".to_string()))?
        .try_clone()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket clone failed: {e}")))
}

fn remove_socket(state: &SmbState) -> Result<()> {
    let key = socket_key(state);
    let mut sockets = SOCKETS
        .lock()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket lock failed: {e}")))?;
    sockets.remove(&key);
    Ok(())
}

// ============================================================================
// SMB message handling
// ============================================================================

/// Send `SMB` message with `NetBIOS` header.
fn send_smb_message(socket: &TcpStream, data: &[u8]) -> Result<()> {
    let mut stream = socket
        .try_clone()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket clone failed: {e}")))?;

    // NetBIOS header: type (1) + flags (1) + length (2)
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.push(0x00); // Message type
    packet.push(0x00); // Flags
    #[expect(
        clippy::cast_possible_truncation,
        reason = "SMB message length fits in 24-bit NetBIOS field"
    )]
    let len = data.len() as u32;
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push((len & 0xFF) as u8);
    packet.extend_from_slice(data);

    stream
        .write_all(&packet)
        .map_err(|e| crate::error::Error::NetworkError(format!("Send failed: {e}")))?;

    Ok(())
}

/// Receive `SMB` message with `NetBIOS` header.
fn recv_smb_message(socket: &TcpStream) -> Result<Vec<u8>> {
    let mut stream = socket
        .try_clone()
        .map_err(|e| crate::error::Error::NetworkError(format!("Socket clone failed: {e}")))?;

    // Read NetBIOS header
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .map_err(|e| crate::error::Error::NetworkError(format!("Receive header failed: {e}")))?;

    // Extract length (24-bit big endian)
    let len = (u32::from(header[2]) << 16) | (u32::from(header[3]) << 8) | u32::from(header[4]);

    if len > 1024 * 1024 {
        return Err(crate::error::Error::NetworkError(format!(
            "SMB message too large: {len} bytes"
        )));
    }

    // Read payload
    let mut payload = vec![0u8; len as usize];
    stream
        .read_exact(&mut payload)
        .map_err(|e| crate::error::Error::NetworkError(format!("Receive payload failed: {e}")))?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_state_default() {
        let state = SmbState::default();
        assert_eq!(state.port, 445);
        assert_eq!(state.uid, 0);
        assert_eq!(state.tid, 0);
    }
}
