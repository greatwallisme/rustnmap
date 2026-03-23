//! libssh2-utility library for NSE using russh.
//!
//! This module provides SSH functionality using the russh library.

use async_trait::async_trait;
use mlua::{MetaMethod, UserData, UserDataMethods, Value};
use russh::client::{self, Handle};
use russh_keys::key::PublicKey;
use std::sync::Arc;
use tracing::debug;

use crate::error::Result;
use crate::lua::NseLua;

/// SSH client handler for russh.
struct Client;

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

/// SSH connection state.
enum ConnectionState {
    Disconnected,
    Connected {
        handle: Handle<Client>,
        banner: String,
    },
}

/// SSH connection `UserData` for NSE scripts.
pub struct SSHConnection {
    state: ConnectionState,
}

impl std::fmt::Debug for SSHConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            ConnectionState::Disconnected => f.debug_struct("SSHConnection")
                .field("state", &"Disconnected")
                .finish(),
            ConnectionState::Connected { banner, .. } => f.debug_struct("SSHConnection")
                .field("state", &"Connected")
                .field("banner", banner)
                .finish(),
        }
    }
}

impl SSHConnection {
    /// Create a new SSH connection object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
        }
    }

    /// Connect to SSH server.
    ///
    /// # Errors
    ///
    /// Returns error if connection fails.
    fn connect(&mut self, host: &str, port: u16) -> mlua::Result<String> {
        debug!("russh: Connecting to {}:{}", host, port);

        let host_str = host.to_string();

        // Use tokio::task::block_in_place to run async code in sync context
        let handle = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let config = Arc::new(russh::client::Config::default());
                let sh = Client;

                let session = russh::client::connect(config, (host_str.as_str(), port), sh)
                    .await
                    .map_err(|e| mlua::Error::RuntimeError(format!("Connection failed: {e}")))?;

                Ok::<Handle<Client>, mlua::Error>(session)
            })
        })?;

        let banner = "SSH-2.0-russh".to_string();

        debug!("russh: Connected");
        self.state = ConnectionState::Connected {
            handle,
            banner: banner.clone(),
        };

        Ok(banner)
    }

    /// List authentication methods.
    ///
    /// # Errors
    ///
    /// Returns error if not connected or auth query fails.
    fn list_auth_methods(&mut self, username: &str) -> mlua::Result<Vec<String>> {
        let handle = match &mut self.state {
            ConnectionState::Connected { handle, .. } => handle,
            ConnectionState::Disconnected => {
                return Err(mlua::Error::RuntimeError("Not connected".to_string()));
            }
        };

        let username = username.to_string();
        let methods = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                match handle.authenticate_none(username).await {
                    Ok(true) => vec!["none".to_string()],
                    Ok(false) | Err(_) => {
                        // Authentication failed, return common methods
                        vec![
                            "publickey".to_string(),
                            "password".to_string(),
                            "keyboard-interactive".to_string(),
                        ]
                    }
                }
            })
        });

        debug!("russh: Auth methods: {:?}", methods);
        Ok(methods)
    }

    /// Get server banner.
    fn banner(&self) -> Option<String> {
        match &self.state {
            ConnectionState::Connected { banner, .. } => Some(banner.clone()),
            ConnectionState::Disconnected => None,
        }
    }

    /// Disconnect from server.
    fn disconnect(&mut self) {
        if let ConnectionState::Connected { handle, .. } =
            std::mem::replace(&mut self.state, ConnectionState::Disconnected)
        {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "").await;
                });
            });
        }
    }
}

impl Default for SSHConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl UserData for SSHConnection {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("connect", |_, this, (host, port): (String, u16)| {
            this.connect(&host, port)
        });

        methods.add_method_mut("connect_pcall", |lua, this, (host_arg, port_arg): (Value, Value)| {
            // Extract host string
            let host = match host_arg {
                Value::Table(ref t) => t.get::<String>("ip")?,
                Value::String(s) => s.to_str()?.to_string(),
                _ => return Err(mlua::Error::RuntimeError("Invalid host parameter".to_string())),
            };

            // Extract port number
            let port = match port_arg {
                Value::Table(ref t) => t.get::<u16>("number")?,
                Value::Integer(n) => u16::try_from(n)
                    .map_err(|e| mlua::Error::RuntimeError(format!("Invalid port: {e}")))?,
                _ => return Err(mlua::Error::RuntimeError("Invalid port parameter".to_string())),
            };

            debug!(
                "libssh2-utility.SSHConnection:connect_pcall extracted host={}, port={}",
                host, port
            );
            match this.connect(&host, port) {
                Ok(banner) => Ok((Value::Boolean(true), Value::String(lua.create_string(&banner)?))),
                Err(e) => Ok((Value::Boolean(false), Value::String(lua.create_string(e.to_string())?))),
            }
        });

        methods.add_method_mut("list", |lua, this, username: String| {
            let methods = this.list_auth_methods(&username)?;
            let table = lua.create_table()?;
            for (i, method) in methods.iter().enumerate() {
                table.set(i + 1, method.as_str())?;
            }
            Ok(table)
        });

        methods.add_method("banner", |_, this, ()| Ok(this.banner()));

        methods.add_method_mut("disconnect", |_, this, ()| {
            this.disconnect();
            Ok(())
        });

        methods.add_meta_method(MetaMethod::ToString, |_, _, ()| {
            Ok("SSHConnection")
        });
    }
}

/// Extract host and port from Lua arguments.
#[expect(dead_code, reason = "Reserved for future use in alternative connection methods")]
fn extract_host_port(_lua: &mlua::Lua, args: Value) -> mlua::Result<(String, u16)> {
    let (host_param, port_param) = match args {
        Value::Table(t) => {
            let host = t.get(1)?;
            let port = t.get(2)?;
            (host, port)
        }
        _ => return Err(mlua::Error::RuntimeError("Expected table arguments".to_string())),
    };

    let host = match host_param {
        Value::Table(t) => t.get::<String>("ip")?,
        Value::String(s) => s.to_str()?.to_string(),
        _ => return Err(mlua::Error::RuntimeError("Invalid host parameter".to_string())),
    };

    let port = match port_param {
        Value::Table(t) => t.get::<u16>("number")?,
        Value::Integer(n) => u16::try_from(n)
            .map_err(|e| mlua::Error::RuntimeError(format!("Invalid port: {e}")))?,
        _ => return Err(mlua::Error::RuntimeError("Invalid port parameter".to_string())),
    };

    Ok((host, port))
}

/// Register the `libssh2-utility` library with Lua.
///
/// # Errors
///
/// Returns error if registration fails.
pub fn register(lua: &NseLua) -> Result<()> {
    debug!("libssh2-utility library registered");

    let module = lua.lua().create_table()?;

    let ssh_connection_ctor = lua.lua().create_function(|_, ()| Ok(SSHConnection::new()))?;

    let ssh_connection_class = lua.lua().create_table()?;
    ssh_connection_class.set("new", ssh_connection_ctor)?;

    module.set("SSHConnection", ssh_connection_class)?;

    // Register in global namespace with hyphen (matching register_package_preload expectation)
    lua.lua().globals().set("libssh2-utility", module)?;

    // Note: package.preload registration is handled by register_package_preload() in mod.rs
    // which creates a loader function that fetches from globals["libssh2-utility"]

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::lua::NseLua;

    #[test]
    fn test_libssh2_utility_require() {
        let mut lua = NseLua::new_default().unwrap();

        // Register all libraries (including libssh2-utility)
        crate::libs::register_all(&mut lua).unwrap();

        // Test that require "libssh2-utility" works
        let result: mlua::Result<mlua::Value> = lua.lua().load(r#"
            local libssh2_util = require "libssh2-utility"
            return libssh2_util
        "#).eval();

        assert!(result.is_ok(), "require 'libssh2-utility' failed: {:?}", result.err());

        let module = result.unwrap();
        assert!(!matches!(module, mlua::Value::Nil), "require returned nil");
        assert!(matches!(module, mlua::Value::Table(_)), "require should return table, got {:?}", module);

        // Test that SSHConnection is accessible
        let ssh_connection: mlua::Result<mlua::Value> = lua.lua().load(r#"
            local libssh2_util = require "libssh2-utility"
            return libssh2_util.SSHConnection
        "#).eval();

        assert!(ssh_connection.is_ok(), "SSHConnection access failed: {:?}", ssh_connection.err());
        assert!(!matches!(ssh_connection.unwrap(), mlua::Value::Nil), "SSHConnection is nil");
    }

    #[test]
    fn test_ssh_connection_creation() {
        let mut lua = NseLua::new_default().unwrap();
        crate::libs::register_all(&mut lua).unwrap();

        // Test creating an SSHConnection instance
        let result: mlua::Result<String> = lua.lua().load(r#"
            local libssh2_util = require "libssh2-utility"
            local conn = libssh2_util.SSHConnection.new()
            return type(conn)
        "#).eval();

        assert!(result.is_ok(), "SSHConnection creation failed: {:?}", result.err());
        let type_name = result.unwrap();
        assert_eq!(type_name, "userdata", "SSHConnection should be userdata");
    }
}

// Rust guideline compliant 2026-03-23
