//! Shortport library for NSE.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::get_first,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unnecessary_map_or,
    reason = "NSE library implementation requires these patterns"
)]
//!
//! This module provides the `shortport` library which contains port rule
//! definitions and helpers for NSE scripts. It corresponds to Nmap's shortport
//! NSE library.
//!
//! # Available Functions and Constants
//!
//! ## Port Rule Functions
//! - `shortport.http` - Matches HTTP ports (80, 443, 8080, 8443, etc.)
//! - `shortport.ftp` - Matches FTP ports (21, 990)
//! - `shortport.ssh` - Matches SSH ports (22)
//! - `shortport.smtp` - Matches SMTP ports (25, 465, 587)
//! - `shortport.dns` - Matches DNS ports (53)
//! - `shortport.pop3` - Matches POP3 ports (110, 995)
//! - `shortport.imap` - Matches IMAP ports (143, 993)
//! - `shortport.telnet` - Matches Telnet ports (23)
//! - `shortport.ssl` - Matches SSL/TLS ports (443, 465, 636, 993, 995, etc.)
//!
//! ## Generic Matching Functions
//! - `shortport.port_or_service(ports, [services], [proto], [state])` - Match by port number or service name
//! - `shortport.service(services, [state])` - Match by service name
//! - `shortport.portnumber(ports, [proto], [state])` - Match by port number
//! - `shortport.version_port_or_service(ports, [services], [proto], [state])` - Match for version detection
//!
//! # Example Usage in Lua
//!
//! ```lua
//! -- Use predefined port rules
//! portrule = shortport.http
//!
//! -- Match specific ports
//! portrule = shortport.port_or_service({80, 8080}, "http", "tcp", "open")
//!
//! -- Match by service name
//! portrule = shortport.service("ssh")
//! ```

use mlua::{Function, Table, Value};

use crate::error::Result;
use crate::lua::NseLua;

/// Common HTTP ports.
const HTTP_PORTS: [u16; 15] = [
    80, 280, 443, 591, 593, 832, 8080, 8888, 8880, 8010, 8443, 8081, 8082, 9000, 9090,
];

/// Common HTTPS/SSL ports.
const SSL_PORTS: [u16; 12] = [
    443, 465, 563, 636, 853, 990, 993, 995, 2083, 2087, 2096, 8443,
];

/// Common FTP ports.
const FTP_PORTS: [u16; 2] = [21, 990];

/// Common SSH ports.
const SSH_PORTS: [u16; 1] = [22];

/// Common SMTP ports.
const SMTP_PORTS: [u16; 3] = [25, 465, 587];

/// Common DNS ports.
const DNS_PORTS: [u16; 2] = [53, 853];

/// Common POP3 ports.
const POP3_PORTS: [u16; 2] = [110, 995];

/// Common IMAP ports.
const IMAP_PORTS: [u16; 2] = [143, 993];

/// Common Telnet ports.
const TELNET_PORTS: [u16; 1] = [23];

/// Create a port rule function that matches by port number.
fn create_portnumber_rule(
    lua: &mlua::Lua,
    ports: Vec<u16>,
    proto: Option<String>,
    state: Option<String>,
) -> mlua::Result<Function> {
    let ports_clone = ports.clone();
    lua.create_function(move |_, (_, port_table): (Value, Table)| {
        let port_num: u16 = port_table.get("number")?;
        let port_proto: String = port_table
            .get("protocol")
            .unwrap_or_else(|_| "tcp".to_string());
        let port_state: String = port_table
            .get("state")
            .unwrap_or_else(|_| "open".to_string());

        // Check port number
        let port_matches = ports_clone.contains(&port_num);

        // Check protocol if specified
        let proto_matches = proto
            .as_ref()
            .map_or(true, |p| port_proto.eq_ignore_ascii_case(p));

        // Check state if specified
        let state_matches = state
            .as_ref()
            .map_or(true, |s| port_state.eq_ignore_ascii_case(s));

        Ok(port_matches && proto_matches && state_matches)
    })
}

/// Create a port rule function that matches by service name.
fn create_service_rule(
    lua: &mlua::Lua,
    services: Vec<String>,
    state: Option<String>,
) -> mlua::Result<Function> {
    let services_lower: Vec<String> = services.iter().map(|s| s.to_lowercase()).collect();

    lua.create_function(move |_, (_, port_table): (Value, Table)| {
        let port_service: String = port_table.get("service").unwrap_or_default();
        let port_state: String = port_table
            .get("state")
            .unwrap_or_else(|_| "open".to_string());

        // Check service name (case-insensitive)
        let service_matches = services_lower
            .iter()
            .any(|s| port_service.eq_ignore_ascii_case(s));

        // Check state if specified
        let state_matches = state
            .as_ref()
            .map_or(true, |s| port_state.eq_ignore_ascii_case(s));

        Ok(service_matches && state_matches)
    })
}

/// Create a port rule function that matches by port number or service name.
fn create_port_or_service_rule(
    lua: &mlua::Lua,
    ports: Vec<u16>,
    services: Vec<String>,
    proto: Option<String>,
    state: Option<String>,
) -> mlua::Result<Function> {
    let services_lower: Vec<String> = services.iter().map(|s| s.to_lowercase()).collect();

    lua.create_function(move |_, (_, port_table): (Value, Table)| {
        let port_num: u16 = port_table.get("number")?;
        let port_proto: String = port_table
            .get("protocol")
            .unwrap_or_else(|_| "tcp".to_string());
        let port_state: String = port_table
            .get("state")
            .unwrap_or_else(|_| "open".to_string());
        let port_service: String = port_table.get("service").unwrap_or_default();

        // Check port number
        let port_matches = ports.contains(&port_num);

        // Check service name (case-insensitive)
        let service_matches = services_lower
            .iter()
            .any(|s| port_service.eq_ignore_ascii_case(s));

        // Check protocol if specified
        let proto_matches = proto
            .as_ref()
            .map_or(true, |p| port_proto.eq_ignore_ascii_case(p));

        // Check state if specified
        let state_matches = state
            .as_ref()
            .map_or(true, |s| port_state.eq_ignore_ascii_case(s));

        Ok((port_matches || service_matches) && proto_matches && state_matches)
    })
}

/// Parse port argument (can be number, table of numbers, or nil).
fn parse_ports_arg(_lua: &mlua::Lua, arg: Value) -> mlua::Result<Vec<u16>> {
    match arg {
        Value::Integer(n) => Ok(vec![n as u16]),
        Value::Number(n) => Ok(vec![n as u16]),
        Value::Table(t) => {
            let mut ports = Vec::new();
            for pair in t.pairs::<Value, Value>() {
                let (_, v) = pair?;
                match v {
                    Value::Integer(n) => ports.push(n as u16),
                    Value::Number(n) => ports.push(n as u16),
                    _ => {}
                }
            }
            Ok(ports)
        }
        _ => Ok(Vec::new()),
    }
}

/// Parse services argument (can be string, table of strings, or nil).
fn parse_services_arg(_lua: &mlua::Lua, arg: Value) -> mlua::Result<Vec<String>> {
    match arg {
        Value::String(s) => Ok(vec![s.to_str()?.to_string()]),
        Value::Table(t) => {
            let mut services = Vec::new();
            for pair in t.pairs::<Value, Value>() {
                let (_, v) = pair?;
                if let Value::String(s) = v {
                    services.push(s.to_str()?.to_string());
                }
            }
            Ok(services)
        }
        _ => Ok(Vec::new()),
    }
}

/// Register the shortport library with the Lua runtime.
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

    // Create the shortport table
    let shortport_table = lua.create_table()?;

    // Create http port rule
    let http_rule = create_portnumber_rule(lua, HTTP_PORTS.to_vec(), None, None)?;
    shortport_table.set("http", http_rule)?;

    // Create ssl port rule
    let ssl_rule = create_portnumber_rule(lua, SSL_PORTS.to_vec(), None, None)?;
    shortport_table.set("ssl", ssl_rule)?;

    // Create ftp port rule
    let ftp_rule = create_portnumber_rule(lua, FTP_PORTS.to_vec(), None, None)?;
    shortport_table.set("ftp", ftp_rule)?;

    // Create ssh port rule
    let ssh_rule = create_portnumber_rule(lua, SSH_PORTS.to_vec(), None, None)?;
    shortport_table.set("ssh", ssh_rule)?;

    // Create smtp port rule
    let smtp_rule = create_portnumber_rule(lua, SMTP_PORTS.to_vec(), None, None)?;
    shortport_table.set("smtp", smtp_rule)?;

    // Create dns port rule
    let dns_rule = create_portnumber_rule(lua, DNS_PORTS.to_vec(), None, None)?;
    shortport_table.set("dns", dns_rule)?;

    // Create pop3 port rule
    let pop3_rule = create_portnumber_rule(lua, POP3_PORTS.to_vec(), None, None)?;
    shortport_table.set("pop3", pop3_rule)?;

    // Create imap port rule
    let imap_rule = create_portnumber_rule(lua, IMAP_PORTS.to_vec(), None, None)?;
    shortport_table.set("imap", imap_rule)?;

    // Create telnet port rule
    let telnet_rule = create_portnumber_rule(lua, TELNET_PORTS.to_vec(), None, None)?;
    shortport_table.set("telnet", telnet_rule)?;

    // Register portnumber(ports, [proto], [state]) function
    let portnumber_fn = lua.create_function(|lua, args: mlua::Variadic<Value>| {
        let ports = if let Some(arg) = args.get(0) {
            parse_ports_arg(lua, arg.clone())?
        } else {
            Vec::new()
        };

        let proto = args.get(1).and_then(|v| {
            if let Value::String(s) = v {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            }
        });

        let state = args.get(2).and_then(|v| {
            if let Value::String(s) = v {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            }
        });

        create_portnumber_rule(lua, ports, proto, state)
    })?;
    shortport_table.set("portnumber", portnumber_fn)?;

    // Register service(services, [state]) function
    let service_fn = lua.create_function(|lua, args: mlua::Variadic<Value>| {
        let services = if let Some(arg) = args.get(0) {
            parse_services_arg(lua, arg.clone())?
        } else {
            Vec::new()
        };

        let state = args.get(1).and_then(|v| {
            if let Value::String(s) = v {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            }
        });

        create_service_rule(lua, services, state)
    })?;
    shortport_table.set("service", service_fn)?;

    // Register port_or_service(ports, [services], [proto], [state]) function
    let port_or_service_fn = lua.create_function(|lua, args: mlua::Variadic<Value>| {
        let ports = if let Some(arg) = args.get(0) {
            parse_ports_arg(lua, arg.clone())?
        } else {
            Vec::new()
        };

        let services = if let Some(arg) = args.get(1) {
            parse_services_arg(lua, arg.clone())?
        } else {
            Vec::new()
        };

        let proto = args.get(2).and_then(|v| {
            if let Value::String(s) = v {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            }
        });

        let state = args.get(3).and_then(|v| {
            if let Value::String(s) = v {
                s.to_str().ok().map(|s| s.to_string())
            } else {
                None
            }
        });

        create_port_or_service_rule(lua, ports, services, proto, state)
    })?;
    shortport_table.set("port_or_service", port_or_service_fn)?;

    // Set the shortport table as a global
    lua.globals().set("shortport", shortport_table)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    fn create_test_port_table(
        lua: &Lua,
        number: u16,
        protocol: &str,
        state: &str,
        service: &str,
    ) -> mlua::Table {
        let table = lua.create_table().unwrap();
        table.set("number", number).unwrap();
        table.set("protocol", protocol).unwrap();
        table.set("state", state).unwrap();
        table.set("service", service).unwrap();
        table
    }

    #[test]
    fn test_register_shortport_library() {
        let mut lua = NseLua::new_default().unwrap();
        let result = register(&mut lua);
        result.unwrap();

        // Check that shortport table exists
        let shortport: Table = lua.lua().globals().get("shortport").unwrap();

        // Check predefined rules exist
        let _http: Function = shortport.get("http").unwrap();
        let _ssh: Function = shortport.get("ssh").unwrap();
    }

    #[test]
    fn test_http_port_rule() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let shortport: Table = lua.lua().globals().get("shortport").unwrap();
        let http_rule: Function = shortport.get("http").unwrap();

        // Test port 80 (HTTP)
        let port80 = create_test_port_table(lua.lua(), 80, "tcp", "open", "http");
        let result: bool = http_rule.call((Value::Nil, port80)).unwrap();
        assert!(result);

        // Test port 443 (HTTPS)
        let port443 = create_test_port_table(lua.lua(), 443, "tcp", "open", "https");
        let result: bool = http_rule.call((Value::Nil, port443)).unwrap();
        assert!(result);

        // Test port 8080 (HTTP alternate)
        let port8080 = create_test_port_table(lua.lua(), 8080, "tcp", "open", "http-proxy");
        let result: bool = http_rule.call((Value::Nil, port8080)).unwrap();
        assert!(result);

        // Test port 22 (SSH) - should not match
        let port22 = create_test_port_table(lua.lua(), 22, "tcp", "open", "ssh");
        let result: bool = http_rule.call((Value::Nil, port22)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_ssh_port_rule() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let shortport: Table = lua.lua().globals().get("shortport").unwrap();
        let ssh_rule: Function = shortport.get("ssh").unwrap();

        // Test port 22 (SSH)
        let port22 = create_test_port_table(lua.lua(), 22, "tcp", "open", "ssh");
        let result: bool = ssh_rule.call((Value::Nil, port22)).unwrap();
        assert!(result);

        // Test port 80 (HTTP) - should not match
        let port80 = create_test_port_table(lua.lua(), 80, "tcp", "open", "http");
        let result: bool = ssh_rule.call((Value::Nil, port80)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_portnumber_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Create a port rule for port 1234
        let rule: Function = lua
            .lua()
            .load("return shortport.portnumber(1234)")
            .eval()
            .unwrap();

        // Test matching port
        let port1234 = create_test_port_table(lua.lua(), 1234, "tcp", "open", "unknown");
        let result: bool = rule.call((Value::Nil, port1234)).unwrap();
        assert!(result);

        // Test non-matching port
        let port5678 = create_test_port_table(lua.lua(), 5678, "tcp", "open", "unknown");
        let result: bool = rule.call((Value::Nil, port5678)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_portnumber_with_proto() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Create a port rule for UDP port 53
        let rule: Function = lua
            .lua()
            .load("return shortport.portnumber(53, 'udp')")
            .eval()
            .unwrap();

        // Test matching port and protocol
        let port53udp = create_test_port_table(lua.lua(), 53, "udp", "open", "dns");
        let result: bool = rule.call((Value::Nil, port53udp)).unwrap();
        assert!(result);

        // Test matching port but wrong protocol
        let port53tcp = create_test_port_table(lua.lua(), 53, "tcp", "open", "dns");
        let result: bool = rule.call((Value::Nil, port53tcp)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_service_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Create a service rule for "http"
        let rule: Function = lua
            .lua()
            .load("return shortport.service('http')")
            .eval()
            .unwrap();

        // Test matching service
        let port80 = create_test_port_table(lua.lua(), 80, "tcp", "open", "http");
        let result: bool = rule.call((Value::Nil, port80)).unwrap();
        assert!(result);

        // Test non-matching service
        let port22 = create_test_port_table(lua.lua(), 22, "tcp", "open", "ssh");
        let result: bool = rule.call((Value::Nil, port22)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_port_or_service_function() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Create a rule that matches port 8080 or service "http"
        let rule: Function = lua
            .lua()
            .load("return shortport.port_or_service(8080, 'http')")
            .eval()
            .unwrap();

        // Test matching by port number
        let port8080 = create_test_port_table(lua.lua(), 8080, "tcp", "open", "unknown");
        let result: bool = rule.call((Value::Nil, port8080)).unwrap();
        assert!(result);

        // Test matching by service name
        let port80 = create_test_port_table(lua.lua(), 80, "tcp", "open", "http");
        let result: bool = rule.call((Value::Nil, port80)).unwrap();
        assert!(result);

        // Test non-matching
        let port22 = create_test_port_table(lua.lua(), 22, "tcp", "open", "ssh");
        let result: bool = rule.call((Value::Nil, port22)).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_port_or_service_with_table_args() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        // Create a rule that matches multiple ports or services
        let rule: Function = lua
            .lua()
            .load("return shortport.port_or_service({80, 443, 8080}, {'http', 'https'})")
            .eval()
            .unwrap();

        // Test port 443
        let port443 = create_test_port_table(lua.lua(), 443, "tcp", "open", "https");
        let result: bool = rule.call((Value::Nil, port443)).unwrap();
        assert!(result);

        // Test service https on non-standard port
        let port8443 = create_test_port_table(lua.lua(), 8443, "tcp", "open", "https");
        let result: bool = rule.call((Value::Nil, port8443)).unwrap();
        assert!(result);
    }

    #[test]
    fn test_port_in_list() {
        // Test that ports are in the expected lists
        assert!(HTTP_PORTS.contains(&80));
        assert!(HTTP_PORTS.contains(&443));
        assert!(!HTTP_PORTS.contains(&22));
        assert!(SSH_PORTS.contains(&22));
    }

    #[test]
    fn test_all_predefined_rules() {
        let mut lua = NseLua::new_default().unwrap();
        register(&mut lua).unwrap();

        let shortport: Table = lua.lua().globals().get("shortport").unwrap();

        // Test all predefined rules exist
        let rules = [
            "http", "ssl", "ftp", "ssh", "smtp", "dns", "pop3", "imap", "telnet",
        ];
        for rule_name in &rules {
            let _rule: Function = shortport.get(*rule_name).unwrap();
        }
    }
}
