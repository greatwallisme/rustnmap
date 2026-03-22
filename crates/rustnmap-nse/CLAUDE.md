# rustnmap-nse

Nmap Script Engine (NSE) implementation for RustNmap - Lua 5.4 script runtime.

## Purpose

Full Lua 5.4 scripting engine compatible with Nmap NSE scripts. Supports host scripts, port scripts, and all standard NSE libraries.

## Key Components

### Script Management

- `ScriptEngine` - Main script execution engine
- `ScriptRegistry` - Script database and discovery
- `Script` - Individual script representation
- `ScriptMetadata` - Script categories, dependencies, etc.

### NSE Libraries

| Library | Module | Status |
|---------|--------|--------|
| nmap | `libs/nmap.rs` | Complete |
| stdnse | `libs/stdnse.rs` | Complete |
| comm | `libs/comm.rs` | Complete |
| shortport | `libs/shortport.rs` | Complete |
| ssh2 | `libs/ssh2.rs` | Complete |
| libssh2_utility | `libs/libssh2_utility.rs` | Complete (SSH key exchange implemented) |

### Script Execution

- `ScriptScheduler` - Concurrent script execution
- `ExecutionContext` - Runtime context for scripts
- `HostRule` / `PortRule` - Script matching rules

## Dependencies

| Crate | Purpose |
|-------|---------|
| rustnmap-common | Common types |
| mlua | Lua 5.4 runtime |
| tokio | Async runtime |
| serde | Data serialization |
| regex | Pattern matching |

## Testing

```bash
cargo test -p rustnmap-nse
```

## Usage

```rust
use rustnmap_nse::{ScriptEngine, ScriptRegistry};

let registry = ScriptRegistry::load_from_directory("./scripts")?;
let engine = ScriptEngine::new(registry);
let results = engine.execute_scripts(target).await?;
```

## Script Example

```lua
local shortport = require "shortport"

description = [[
  Example script description
]]

categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  return "Found HTTP service"
end
```

## Safety

- Scripts run in isolated Lua sandboxes
- Timeout enforcement on all script execution
- Resource limits (memory, execution time)
