# Database Integration Design

> **Purpose**: Integrate ServiceDatabase, ProtocolDatabase, and RpcDatabase into output system

---

## Overview

RustNmap currently loads three databases (ServiceDatabase, ProtocolDatabase, RpcDatabase) but immediately discards them. This document describes how to integrate these databases into the output system to display friendly names instead of numbers.

## Current State

### Existing Implementation

All three databases are fully implemented in `crates/rustnmap-fingerprint/src/database/`:

1. **ServiceDatabase** (`services.rs`)
   - Maps port+protocol → service name
   - Example: `(80, "tcp")` → `"http"`
   - API: `lookup(port: u16, protocol: &str) -> Option<&str>`

2. **ProtocolDatabase** (`protocols.rs`)
   - Maps protocol number → protocol name
   - Example: `6` → `"tcp"`
   - API: `lookup(number: u8) -> Option<&str>`

3. **RpcDatabase** (`rpc.rs`)
   - Maps RPC program number → RPC service name
   - Example: `100003` → `"nfs"`
   - API: `lookup(number: u32) -> Option<&str>`

### Problem

In `crates/rustnmap-cli/src/cli.rs`, databases are loaded but discarded:

```rust
match ServiceDatabase::load_from_file(&path).await {
    Ok(_db) => {  // <- Database immediately discarded
        info!("Services database loaded successfully");
        // Note: Service database is available but not yet used in output
    }
    ...
}
```

This occurs in two functions:
- `handle_profile_scan()` (lines 501-553)
- `run_normal_scan()` (lines 921-973)

---

## Nmap Reference Implementation

### How Nmap Uses Databases

From `reference/nmap/services.cc` and `services.h`:

```c
// Global service map
static ServiceMap service_table;

// Lookup function used in output
const struct nservent *nmap_getservbyport(u16 port, u16 proto) {
    // Returns service entry from service_table
}
```

**Usage in output:**
```c
// In output.cc (conceptual)
if (service_name = nmap_getservbyport(port, proto)) {
    printf("%d/%s open %s\n", port, proto_str, service_name);
} else {
    printf("%d/%s open\n", port, proto_str);
}
```

**Result:**
```
80/tcp open http      <- With database
80/tcp open           <- Without database
```

---

## Design Solution

### Architecture

```
+-----------------+
|   CLI Layer     |
|  (cli.rs)       |
+--------+--------+
         | Load databases
         v
+-----------------+
| DatabaseContext | <- New structure
|  - services     |
|  - protocols    |
|  - rpc          |
+--------+--------+
         | Pass to output
         v
+-----------------+
| Output Layer    |
| (formatters)    |
+-----------------+
```

### Implementation Plan

#### Phase 1: Create DatabaseContext

Create new structure in `crates/rustnmap-output/src/database_context.rs`:

```rust
pub struct DatabaseContext {
    pub services: Option<Arc<ServiceDatabase>>,
    pub protocols: Option<Arc<ProtocolDatabase>>,
    pub rpc: Option<Arc<RpcDatabase>>,
}

impl DatabaseContext {
    pub fn empty() -> Self {
        Self {
            services: None,
            protocols: None,
            rpc: None,
        }
    }

    pub fn lookup_service(&self, port: u16, protocol: &str) -> Option<&str> {
        self.services.as_ref()?.lookup(port, protocol)
    }

    pub fn lookup_protocol(&self, number: u8) -> Option<&str> {
        self.protocols.as_ref()?.lookup(number)
    }

    pub fn lookup_rpc(&self, number: u32) -> Option<&str> {
        self.rpc.as_ref()?.lookup(number)
    }
}
```

#### Phase 2: Store Databases in CLI

Modify `cli.rs` to store loaded databases:

```rust
// In handle_profile_scan() and run_normal_scan()
let mut db_context = DatabaseContext::empty();

// Load services database
if services_db_path.exists() {
    match ServiceDatabase::load_from_file(&services_db_path).await {
        Ok(db) => {
            info!("Services database loaded successfully");
            db_context.services = Some(Arc::new(db));
        }
        Err(e) => warn!("Failed to load services database: {e}"),
    }
}

// Similar for protocols and rpc...
```

#### Phase 3: Pass to Output Functions

Modify output function signatures:

```rust
// Before
fn write_normal_output(result: &ScanResult, path: &Path, append: bool) -> Result<()>

// After
fn write_normal_output(
    result: &ScanResult,
    path: &Path,
    append: bool,
    db_context: &DatabaseContext  // <- Add parameter
) -> Result<()>
```

#### Phase 4: Use in Output

Modify output functions to use databases:

```rust
// In write_normal_output()
for port in &host.ports {
    let protocol_str = match port.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
    };

    let state_str = match port.state {
        PortState::Open => "open",
        // ...
    };

    // Use database to get service name
    let service_str = db_context
        .lookup_service(port.number, protocol_str)
        .unwrap_or("");

    if service_str.is_empty() {
        writeln!(handle, "{}/{} {}", port.number, protocol_str, state_str)?;
    } else {
        writeln!(handle, "{}/{} {} {}", port.number, protocol_str, state_str, service_str)?;
    }
}
```

---

## Output Format Changes

### Before (Current)

```
PORT     STATE SERVICE
80/tcp   open
443/tcp  open
22/tcp   open
```

### After (With Databases)

```
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
22/tcp   open  ssh
```

---

## Implementation Checklist

- [ ] Create `DatabaseContext` structure
- [ ] Modify `cli.rs` to store loaded databases (remove `_db` discards)
- [ ] Update output function signatures to accept `DatabaseContext`
- [ ] Implement database lookups in `write_normal_output()`
- [ ] Implement database lookups in `write_grepable_output()`
- [ ] Implement database lookups in `write_xml_output()`
- [ ] Add tests for database integration
- [ ] Update documentation

---

## Testing Strategy

1. **Unit Tests**: Test `DatabaseContext` lookup methods
2. **Integration Tests**: Compare output with/without databases
3. **Compatibility Tests**: Verify output matches nmap format

---

## Performance Considerations

- Databases loaded once at startup (no performance impact)
- Lookups are O(1) HashMap operations
- Optional `Arc` wrapping allows sharing without cloning

---

## Backward Compatibility

- If databases not found, output shows numbers only (current behavior)
- No breaking changes to existing functionality
- Graceful degradation when databases unavailable

---

## References

- Nmap source: `reference/nmap/services.cc`, `reference/nmap/protocols.cc`
- RustNmap databases: `crates/rustnmap-fingerprint/src/database/`
- Output layer: `crates/rustnmap-output/src/`

---
