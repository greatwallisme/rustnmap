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

//! Shared NSE Lua VM with baseline snapshot isolation.
//!
//! This module implements nmap's single-`lua_State` pattern where one Lua VM
//! is created per scan and reused across all script executions. Library
//! registration happens once at creation; per-script state is cleared between
//! runs by resetting globals that were not present at baseline.
//!
//! # nmap Reference
//!
//! nmap creates a single `lua_State *L_NSE` in `nse_main.cc:820` and reuses it
//! for all script operations. Scripts share the global namespace; the engine
//! does NOT recreate the VM between scripts. Our approach mirrors this:
//!
//! 1. `NseVm::new()` creates the Lua state and registers all NSE libraries once
//! 2. `NseVm::reset_for_script()` clears per-script globals while preserving
//!    library registrations
//! 3. Each script execution acquires the VM, loads script source, executes, and
//!    the next invocation resets before proceeding

use std::collections::HashSet;

use tracing::debug;

use crate::error::{Error, Result};
use crate::lua::NseLua;

/// Shared NSE Lua VM with baseline-snapshot isolation.
///
/// Created once per `ScriptEngine` and reused for all synchronous script
/// operations (rule evaluation, script execution). The VM preserves library
/// registrations across script executions while clearing per-script state
/// (`host`, `port`, `SCRIPT_NAME`, action, portrule, etc.) between runs.
///
/// # Thread Safety
///
/// `NseVm` is not `Send`/`Sync` (Lua state is thread-local). It is wrapped
/// in a `Mutex` inside `ScriptEngine` to serialize access.
///
/// # Example
///
/// ```no_run
/// use rustnmap_nse::vm::NseVm;
///
/// let mut vm = NseVm::new().unwrap();
///
/// // Run script A
/// vm.reset_for_script().unwrap();
/// vm.lua().lua().globals().set("SCRIPT_NAME", "script-a").unwrap();
/// vm.lua().load_script("action = function() return 'A' end", "script-a").unwrap();
/// // ... execute ...
///
/// // Run script B - script A's globals are cleared
/// vm.reset_for_script().unwrap();
/// vm.lua().lua().globals().set("SCRIPT_NAME", "script-b").unwrap();
/// vm.lua().load_script("action = function() return 'B' end", "script-b").unwrap();
/// // ... execute ...
/// ```
#[derive(Debug)]
pub struct NseVm {
    /// The underlying Lua runtime with NSE libraries registered.
    lua: NseLua,

    /// Global variable names present after library registration.
    ///
    /// These are the "permanent" globals (nmap, stdnse, http, etc.) that
    /// survive `reset_for_script()`. Any global NOT in this set is considered
    /// per-script state and will be removed during reset.
    baseline_globals: HashSet<String>,
}

impl NseVm {
    /// Create a new shared NSE VM with all libraries registered.
    ///
    /// This performs the one-time initialization that nmap does in
    /// `init_main()` (`nse_main.cc:586`): creates the Lua state, opens
    /// standard libraries, registers all NSE protocol/utility libraries,
    /// and takes a baseline snapshot of global names.
    ///
    /// # Errors
    ///
    /// Returns an error if Lua state creation or library registration fails.
    pub fn new() -> Result<Self> {
        let mut lua = NseLua::new_default()?;
        crate::libs::register_all(&mut lua)?;

        let baseline_globals = Self::snapshot_globals(&lua);
        debug!(
            "NseVm initialized with {} baseline globals",
            baseline_globals.len()
        );

        Ok(Self {
            lua,
            baseline_globals,
        })
    }

    /// Reset the VM state for a new script execution.
    ///
    /// Clears all globals that were NOT present at baseline (i.e., globals
    /// added by the previous script such as `action`, `portrule`, `host`,
    /// `port`, `SCRIPT_NAME`, etc.), then runs garbage collection to reclaim
    /// memory.
    ///
    /// This matches nmap's behavior where scripts share the global namespace
    /// but each script's top-level code overwrites the previous script's
    /// globals. We explicitly nil out globals that the previous script set
    /// but the current one might not, preventing state leakage.
    ///
    /// # Errors
    ///
    /// Returns an error if global cleanup or garbage collection fails.
    pub fn reset_for_script(&mut self) -> Result<()> {
        let current = Self::snapshot_globals(&self.lua);

        // Collect non-baseline globals to remove
        let to_remove: Vec<String> = current
            .into_iter()
            .filter(|name| !self.baseline_globals.contains(name))
            .collect();

        if !to_remove.is_empty() {
            debug!("Resetting {} per-script globals", to_remove.len());
            let globals = self.lua.lua().globals();
            for name in &to_remove {
                globals
                    .set(name.as_str(), mlua::Value::Nil)
                    .map_err(|e| Error::LuaError {
                        script: "vm_reset".to_string(),
                        message: format!("failed to clear global '{name}': {e}"),
                    })?;
            }
        }

        // Force garbage collection to reclaim memory from previous script
        self.lua.gc_collect()?;

        Ok(())
    }

    /// Get a mutable reference to the underlying `NseLua` runtime.
    ///
    /// Use this to access the Lua state for script loading, global setting,
    /// function calling, etc.
    #[must_use]
    pub fn lua(&mut self) -> &mut NseLua {
        &mut self.lua
    }

    /// Snapshot all global variable names from the Lua state.
    ///
    /// Returns a `HashSet` of all keys in `_G` at the time of the call.
    /// Used to establish the baseline after library registration and to
    /// identify per-script globals for cleanup.
    fn snapshot_globals(lua: &NseLua) -> HashSet<String> {
        lua.snapshot_global_names()
            .map(|names| names.into_iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nse_vm_new() {
        let vm = NseVm::new();
        assert!(vm.is_ok(), "NseVm creation should succeed");
        let vm = vm.unwrap();

        // Baseline should include library globals
        assert!(
            vm.baseline_globals.contains("nmap"),
            "baseline should contain 'nmap' library"
        );
        assert!(
            vm.baseline_globals.contains("stdnse"),
            "baseline should contain 'stdnse' library"
        );
        assert!(
            vm.baseline_globals.contains("http"),
            "baseline should contain 'http' library"
        );
    }

    #[test]
    fn test_reset_for_script_clears_non_baseline() {
        let mut vm = NseVm::new().unwrap();

        // Simulate script A setting globals
        vm.lua()
            .lua()
            .globals()
            .set("SCRIPT_NAME", "test-script")
            .unwrap();
        vm.lua()
            .lua()
            .globals()
            .set("action", mlua::Value::Nil)
            .unwrap();

        // Verify globals exist
        let script_name: mlua::Value = vm.lua().lua().globals().get("SCRIPT_NAME").unwrap();
        assert!(
            !matches!(script_name, mlua::Value::Nil),
            "SCRIPT_NAME should be set"
        );

        // Reset
        vm.reset_for_script().unwrap();

        // Verify per-script globals are cleared
        let script_name: mlua::Value = vm.lua().lua().globals().get("SCRIPT_NAME").unwrap();
        assert!(
            matches!(script_name, mlua::Value::Nil),
            "SCRIPT_NAME should be nil after reset"
        );

        let action: mlua::Value = vm.lua().lua().globals().get("action").unwrap();
        assert!(
            matches!(action, mlua::Value::Nil),
            "action should be nil after reset"
        );
    }

    #[test]
    fn test_reset_preserves_baseline_globals() {
        let mut vm = NseVm::new().unwrap();

        // Reset should not clear library globals
        vm.reset_for_script().unwrap();

        let nmap: mlua::Value = vm.lua().lua().globals().get("nmap").unwrap();
        assert!(
            !matches!(nmap, mlua::Value::Nil),
            "nmap library should survive reset"
        );

        let stdnse: mlua::Value = vm.lua().lua().globals().get("stdnse").unwrap();
        assert!(
            !matches!(stdnse, mlua::Value::Nil),
            "stdnse library should survive reset"
        );

        let http: mlua::Value = vm.lua().lua().globals().get("http").unwrap();
        assert!(
            !matches!(http, mlua::Value::Nil),
            "http library should survive reset"
        );
    }

    #[test]
    fn test_state_isolation_between_scripts() {
        let mut vm = NseVm::new().unwrap();

        // Script A: defines action and sets a custom global
        vm.reset_for_script().unwrap();
        vm.lua()
            .load_script(
                r#"custom_global_a = "from_script_a"; action = function() return "A" end"#,
                "script-a",
            )
            .unwrap();

        // Verify script A's globals exist
        let val: String = vm.lua().lua().globals().get("custom_global_a").unwrap();
        assert_eq!(val, "from_script_a");

        // Script B: does NOT define custom_global_a
        vm.reset_for_script().unwrap();
        vm.lua()
            .load_script(r#"action = function() return "B" end"#, "script-b")
            .unwrap();

        // Verify script A's custom global is gone
        let val: mlua::Value = vm.lua().lua().globals().get("custom_global_a").unwrap();
        assert!(
            matches!(val, mlua::Value::Nil),
            "Script A's custom_global_a should not leak to Script B"
        );
    }
}
