//! NSE Script Runner Binary
//!
//! Isolated process for executing NSE scripts with resource limits.
//! This binary is spawned by the main rustnmap process to ensure that
//! misbehaving scripts (infinite loops, memory leaks) can be reliably
//! terminated via OS-level process killing.
//!
//! # Exit Codes
//!
//! - 0: Script executed successfully
//! - 1: Script execution error
//! - 2: Script timeout (killed by resource limit)
//! - 3: Invalid arguments

use std::io::{self, Read, Write as IoWrite};
use std::net::IpAddr;
use std::process::ExitCode;

use mlua::Lua;
use serde::{Deserialize, Serialize};

// NSE 库由 Rust 实现，需要注册到 Lua 运行时
use rustnmap_nse::libs;
use rustnmap_nse::lua::{LuaConfig, NseLua};

/// Runner process execution status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum RunnerStatus {
    /// Script executed successfully.
    Success,
    /// Script execution failed.
    Failed,
    /// Script timed out.
    Timeout,
    /// Script skipped (e.g., missing required library).
    Skipped,
}

/// Runner process output.
#[derive(Debug, Serialize, Deserialize)]
struct RunnerOutput {
    /// Execution status.
    status: RunnerStatus,
    /// Script output (if successful).
    output: Option<String>,
    /// Error message (if failed).
    error: Option<String>,
}

/// Parsed command line arguments.
struct RunnerArgs {
    target_ip: IpAddr,
    timeout_ms: Option<u64>,
    script_file: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    service: Option<String>,
}

/// Parse command line arguments.
fn parse_args() -> Option<RunnerArgs> {
    let args: Vec<String> = std::env::args().collect();

    let mut target_ip: Option<String> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut script_file: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut protocol: Option<String> = None;
    let mut service: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target_ip = args.get(i).cloned();
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).and_then(|s| s.parse().ok());
            }
            "--file" => {
                i += 1;
                script_file = args.get(i).cloned();
            }
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok());
            }
            "--protocol" => {
                i += 1;
                protocol = args.get(i).cloned();
            }
            "--service" => {
                i += 1;
                service = args.get(i).cloned();
            }
            "--help" | "-h" => {
                let usage = "Usage: rustnmap-nse-runner --target IP [--timeout-ms MS] [--file SCRIPT] [--port PORT] [--protocol PROTO] [--service SVC]\n       Reads script from stdin if --file not specified.\n";
                let _ = io::stderr().write_all(usage.as_bytes());
                return None;
            }
            _ => {}
        }
        i += 1;
    }

    let target = target_ip?;
    let ip: IpAddr = target.parse().ok()?;
    Some(RunnerArgs {
        target_ip: ip,
        timeout_ms,
        script_file,
        port,
        protocol,
        service,
    })
}

/// Set CPU time limit for the process.
fn set_cpu_limit(timeout_ms: u64) {
    let cpu_limit: u64 = timeout_ms / 1000 + 5;
    // SAFETY: setrlimit is a POSIX system call that sets resource limits.
    // We use it to limit CPU time to prevent runaway scripts from
    // consuming unlimited CPU resources.
    #[expect(clippy::borrow_as_ptr, reason = "libc::setrlimit requires raw pointer")]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: cpu_limit,
            rlim_max: cpu_limit,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &rlim) != 0 {
            let _ = io::stderr().write_all(b"Warning: Failed to set CPU time limit\n");
        }
    }
}

/// Read script source from file or stdin.
fn read_script_source(script_file: Option<&String>) -> io::Result<String> {
    if let Some(file) = script_file {
        std::fs::read_to_string(file)
    } else {
        let mut source = String::new();
        io::stdin().read_to_string(&mut source)?;
        Ok(source)
    }
}

/// Output result as JSON to stdout.
fn output_result(result: &RunnerOutput) {
    match serde_json::to_string(result) {
        Ok(json) => {
            let mut out = json;
            out.push('\n');
            let _ = io::stdout().write_all(out.as_bytes());
        }
        Err(e) => {
            let msg = format!("Failed to serialize result: {e}\n");
            let _ = io::stderr().write_all(msg.as_bytes());
        }
    }
}

/// Check if an error is a `silent_require` error (script should be skipped).
fn is_silent_require_error(error: &str) -> bool {
    error.contains("NSE_REQUIRE_ERROR:")
}

/// Lua source for nmap-compatible `format_table` function.
///
/// Mirrors `nse_main.lua:format_table` which handles `__tostring` metamethods,
/// `ipairs` for integer keys, and `pairs` for string keys (respecting `__pairs`).
const FORMAT_TABLE_LUA: &str = r#"
local function format_table(obj, indent)
  indent = indent or "  "
  if type(obj) == "table" then
    local mt = getmetatable(obj)
    if mt and mt["__tostring"] then
      return tostring(obj)
    end
    local lines = {}
    for _, v in ipairs(obj) do
      lines[#lines + 1] = "\n"
      lines[#lines + 1] = indent
      lines[#lines + 1] = format_table(v, indent .. "  ")
    end
    for k, v in pairs(obj) do
      if type(k) == "string" then
        lines[#lines + 1] = "\n"
        lines[#lines + 1] = indent
        lines[#lines + 1] = k .. ": "
        lines[#lines + 1] = format_table(v, indent .. "  ")
      end
    end
    return table.concat(lines)
  else
    return tostring(obj)
  end
end
return format_table
"#;

/// Convert a simple Lua value to a display string.
fn lua_value_to_string(val: &mlua::Value) -> String {
    match val {
        mlua::Value::String(s) => s.to_str().map_or_else(|_| String::new(), |s| s.to_string()),
        mlua::Value::Integer(n) => n.to_string(),
        mlua::Value::Number(n) => n.to_string(),
        mlua::Value::Boolean(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Port information for port-rule scripts.
struct PortInfo {
    number: u16,
    protocol: String,
    service: String,
}

/// Execute an NSE script and Returns output string on success.
fn execute_script(
    source: &str,
    script_id: &str,
    target_ip: IpAddr,
    port_info: Option<&PortInfo>,
) -> Result<String, String> {
    // Create NSE Lua runtime wrapper
    let mut nse_lua =
        NseLua::new(LuaConfig::default()).map_err(|e| format!("Failed to create NSE Lua: {e}"))?;

    // Register NSE standard libraries (nmap, stdnse, comm, shortport)
    libs::register_all(&mut nse_lua)
        .map_err(|e| format!("Failed to register NSE libraries: {e}"))?;

    let lua = nse_lua.lua_mut();

    // Set SCRIPT_NAME global BEFORE loading the script, since some scripts
    // reference SCRIPT_NAME at module level (e.g., http-title uses it in action)
    lua.globals()
        .set("SCRIPT_NAME", script_id)
        .map_err(|e| format!("Failed to set SCRIPT_NAME: {e}"))?;

    // Load the script
    lua.load(source)
        .set_name(script_id)
        .exec()
        .map_err(|e| format!("Failed to load script: {e}"))?;

    // Create host table
    let host_table = create_host_table(lua, target_ip)?;
    lua.globals()
        .set("host", host_table)
        .map_err(|e| format!("Failed to set host table: {e}"))?;

    // Set SCRIPT_TYPE global used by scripts with ActionsTable dispatch pattern
    // (e.g., ssh-hostkey, http-git) that route based on portrule/hostrule/postrule
    let script_type = if port_info.is_some() {
        "portrule"
    } else if source.contains("hostrule") {
        "hostrule"
    } else {
        "portrule"
    };
    lua.globals()
        .set("SCRIPT_TYPE", script_type)
        .map_err(|e| format!("Failed to set SCRIPT_TYPE: {e}"))?;

    // Create port table if port info is provided, and call action(host, port)
    // Otherwise call action(host) for host-only scripts
    let action_code = if port_info.is_some() {
        let port_table = create_port_table(lua, port_info.unwrap())?;
        lua.globals()
            .set("port", port_table)
            .map_err(|e| format!("Failed to set port table: {e}"))?;
        "return action(host, port)"
    } else {
        "return action(host)"
    };

    // Check if action function exists
    let has_action = source.contains("action")
        && (source.contains("action =") || source.contains("function action"));

    if !has_action {
        return Ok(String::new());
    }

    // Execute action function
    let func = lua
        .load(action_code)
        .set_name("action_wrapper")
        .into_function()
        .map_err(|e| format!("Failed to load action function: {e}"))?;

    let result: mlua::MultiValue = func
        .call(())
        .map_err(|e| format!("Script execution failed: {e}"))?;

    // Install Lua-side format_table function that respects __pairs and __tostring
    let format_fn: mlua::Function = lua
        .load(FORMAT_TABLE_LUA)
        .set_name("format_table")
        .eval()
        .map_err(|e| format!("Failed to load format_table: {e}"))?;

    // Nmap two-return-value convention:
    //   r1 = structured data (table for XML output)
    //   r2 = display text (string for terminal output)
    let values: Vec<mlua::Value> = result.into_iter().collect();
    let output = if values.len() >= 2 {
        lua_value_to_string(&values[1])
    } else if values.len() == 1 {
        match &values[0] {
            mlua::Value::Nil => String::new(),
            mlua::Value::String(s) => s.to_str().map_or_else(|_| String::new(), |s| s.to_string()),
            mlua::Value::Table(_) => format_fn
                .call::<String>((values[0].clone(), "  "))
                .unwrap_or_default(),
            _ => lua_value_to_string(&values[0]),
        }
    } else {
        String::new()
    };

    Ok(output)
}

/// Create the NSE port table.
fn create_port_table(lua: &Lua, info: &PortInfo) -> Result<mlua::Table, String> {
    let port_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create port table: {e}"))?;

    port_table
        .set("number", info.number)
        .map_err(|e| format!("Failed to set port.number: {e}"))?;
    port_table
        .set("protocol", info.protocol.as_str())
        .map_err(|e| format!("Failed to set port.protocol: {e}"))?;
    port_table
        .set("state", "open")
        .map_err(|e| format!("Failed to set port.state: {e}"))?;
    port_table
        .set("service", info.service.as_str())
        .map_err(|e| format!("Failed to set port.service: {e}"))?;

    let reason = if info.protocol == "udp" {
        "udp-response"
    } else {
        "syn-ack"
    };
    port_table
        .set("reason", reason)
        .map_err(|e| format!("Failed to set port.reason: {e}"))?;

    let version_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create version table: {e}"))?;
    version_table
        .set("name", info.service.as_str())
        .map_err(|e| format!("Failed to set version.name: {e}"))?;
    version_table
        .set("name_confidence", 8)
        .map_err(|e| format!("Failed to set version.name_confidence: {e}"))?;
    port_table
        .set("version", version_table)
        .map_err(|e| format!("Failed to set port.version: {e}"))?;

    Ok(port_table)
}

/// Create the NSE host table.
fn create_host_table(lua: &Lua, target_ip: IpAddr) -> Result<mlua::Table, String> {
    let host_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create host table: {e}"))?;

    let ip_str = target_ip.to_string();
    host_table
        .set("ip", ip_str.clone())
        .map_err(|e| format!("Failed to set host.ip: {e}"))?;
    host_table
        .set("canonical_ip", ip_str)
        .map_err(|e| format!("Failed to set host.canonical_ip: {e}"))?;

    let target_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create target table: {e}"))?;
    target_table
        .set("ip", target_ip.to_string())
        .map_err(|e| format!("Failed to set target.ip: {e}"))?;
    host_table
        .set("target", target_table)
        .map_err(|e| format!("Failed to set host.target: {e}"))?;
    host_table
        .set("name", "")
        .map_err(|e| format!("Failed to set host.name: {e}"))?;

    // Binary IP representation used by address-info and similar scripts.
    // For IPv4: 4 bytes, for IPv6: 16 bytes. Uses string.char() to create
    // an 8-bit clean Lua string from raw byte values.
    let bin_ip_octets: Vec<String> = match target_ip {
        IpAddr::V4(v4) => v4.octets().iter().map(ToString::to_string).collect(),
        IpAddr::V6(v6) => v6.octets().iter().map(ToString::to_string).collect(),
    };
    let bin_ip_lua: mlua::String = lua
        .load(format!("return string.char({})", bin_ip_octets.join(", ")))
        .eval()
        .map_err(|e| format!("Failed to create bin_ip: {e}"))?;
    host_table
        .set("bin_ip", bin_ip_lua)
        .map_err(|e| format!("Failed to set host.bin_ip: {e}"))?;

    // Scripts use host.registry for cross-script caching (e.g., sslcert caches
    // certificates, smb caches netbios names)
    let registry_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create host.registry table: {e}"))?;
    host_table
        .set("registry", registry_table)
        .map_err(|e| format!("Failed to set host.registry: {e}"))?;

    // host.times - Timing statistics (T3 defaults, used by stdnse.get_timeout)
    let times_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create host.times table: {e}"))?;
    times_table
        .set("srtt", 1000)
        .map_err(|e| format!("Failed to set times.srtt: {e}"))?;
    times_table
        .set("rttvar", 500)
        .map_err(|e| format!("Failed to set times.rttvar: {e}"))?;
    times_table
        .set("to", 3000)
        .map_err(|e| format!("Failed to set times.to: {e}"))?;
    times_table
        .set("timeout", 3.0)
        .map_err(|e| format!("Failed to set times.timeout: {e}"))?;
    host_table
        .set("times", times_table)
        .map_err(|e| format!("Failed to set host.times: {e}"))?;

    // Interface table for address-info and similar scripts
    let iface_table = lua
        .create_table()
        .map_err(|e| format!("Failed to create interface table: {e}"))?;
    let addr_entry = lua
        .create_table()
        .map_err(|e| format!("Failed to create address entry: {e}"))?;
    addr_entry
        .set("address", target_ip.to_string())
        .map_err(|e| format!("Failed to set address: {e}"))?;
    iface_table
        .push(addr_entry)
        .map_err(|e| format!("Failed to push address entry: {e}"))?;
    let interface = lua
        .create_table()
        .map_err(|e| format!("Failed to create interface table: {e}"))?;
    interface
        .set("address", target_ip.to_string())
        .map_err(|e| format!("Failed to set interface.address: {e}"))?;
    interface
        .set("addresses", iface_table)
        .map_err(|e| format!("Failed to set interface.addresses: {e}"))?;
    let interfaces = lua
        .create_table()
        .map_err(|e| format!("Failed to create interfaces table: {e}"))?;
    interfaces
        .push(interface)
        .map_err(|e| format!("Failed to push interface: {e}"))?;
    host_table
        .set("interface", target_ip.to_string())
        .map_err(|e| format!("Failed to set host.interface: {e}"))?;
    host_table
        .set("interfaces", interfaces)
        .map_err(|e| format!("Failed to set host.interfaces: {e}"))?;

    Ok(host_table)
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else {
        return ExitCode::from(3);
    };

    if let Some(timeout) = args.timeout_ms {
        set_cpu_limit(timeout);
    }

    let script_source = match read_script_source(args.script_file.as_ref()) {
        Ok(source) => source,
        Err(e) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Failed,
                output: None,
                error: Some(format!("Failed to read script: {e}")),
            });
            return ExitCode::from(1);
        }
    };

    let port_info = args.port.map(|p| PortInfo {
        number: p,
        protocol: args.protocol.clone().unwrap_or_else(|| "tcp".to_string()),
        service: args.service.clone().unwrap_or_default(),
    });

    // Execute inside a Tokio runtime since NSE library functions (stdnse.sleep,
    // stdnse.mutex, etc.) require a Tokio runtime handle
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Failed,
                output: None,
                error: Some(format!("Failed to create Tokio runtime: {e}")),
            });
            return ExitCode::from(1);
        }
    };
    let result = rt.block_on(async {
        execute_script(
            &script_source,
            "runner_script",
            args.target_ip,
            port_info.as_ref(),
        )
    });

    match result {
        Ok(output) => {
            output_result(&RunnerOutput {
                status: RunnerStatus::Success,
                output: Some(output),
                error: None,
            });
            ExitCode::SUCCESS
        }
        Err(e) => {
            if is_silent_require_error(&e) {
                output_result(&RunnerOutput {
                    status: RunnerStatus::Skipped,
                    output: None,
                    error: Some(e),
                });
                ExitCode::from(2)
            } else {
                output_result(&RunnerOutput {
                    status: RunnerStatus::Failed,
                    output: None,
                    error: Some(e),
                });
                ExitCode::from(1)
            }
        }
    }
}
