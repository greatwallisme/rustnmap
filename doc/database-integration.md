# Database Integration Design

> **Status**: ⚠️ Implementation Complete with Issues
> **Created**: 2026-03-09
> **Updated**: 2026-03-09 (Implementation Analysis)
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
    Ok(_db) => {  // ← Database immediately discarded
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
80/tcp open http      ← With database
80/tcp open           ← Without database
```

---

## Design Solution

### Architecture

```
┌─────────────────┐
│   CLI Layer     │
│  (cli.rs)       │
└────────┬────────┘
         │ Load databases
         ↓
┌─────────────────┐
│ DatabaseContext │ ← New structure
│  - services     │
│  - protocols    │
│  - rpc          │
└────────┬────────┘
         │ Pass to output
         ↓
┌─────────────────┐
│ Output Layer    │
│ (formatters)    │
└─────────────────┘
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
    db_context: &DatabaseContext  // ← Add parameter
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

## Implementation Status (2026-03-09)

### ✅ Completed

DatabaseContext 已实现并集成到 CLI：
- **Location**: `crates/rustnmap-output/src/database_context.rs`
- **Usage**: 在 `handle_profile_scan()` 和 `run_normal_scan()` 中加载
- **Integration**: 传递给所有输出函数

### ⚠️ Issues Discovered

经过深入的代码审查，发现了以下架构问题：

#### Issue 1: ServiceDatabase 重复定义（严重）

**问题**: `ServiceDatabase` 被定义了两次

| 位置 | 使用情况 | 详情 |
|------|----------|------|
| `rustnmap-common::ServiceDatabase` | ✅ 广泛使用 | 全局单例 `ServiceDatabase::global()`，扫描阶段使用 |
| `rustnmap-fingerprint::database::ServiceDatabase` | ⚠️ 几乎不使用 | 仅在 `DatabaseContext.services` 中，90% 未使用 |

**影响**:
- 代码重复，维护成本翻倍
- 潜在的不一致性风险
- API 混淆

**根因分析**:
```rust
// 扫描时实际使用的是 rustnmap-common 的全局单例
fn service_info_from_db(port: u16, protocol: ServiceProtocol) -> Option<ServiceInfo> {
    let db = rustnmap_common::ServiceDatabase::global();  // ← 这里
    // ...
}

// DatabaseContext 中的 services 字段几乎不被使用
let mut db_context = DatabaseContext::new();
db_context.services = Some(Arc::new(rustnmap_fingerprint::ServiceDatabase::load_from_file(&path).await?));
// ↑ 这里的数据 90% 情况下被忽略
```

**建议修复**:
1. 删除 `rustnmap-fingerprint::database::ServiceDatabase`
2. 全部使用 `rustnmap_common::ServiceDatabase::global()`
3. `DatabaseContext` 不再持有 `services` 字段

#### Issue 2: DatabaseContext 过度设计（中等）

**问题**: `DatabaseContext.services` 字段 90% 未使用

| 函数 | db_context 参数 | services 字段使用 |
|------|----------------|------------------|
| `print_normal_output` | `_db_context` | ❌ 未使用 |
| `write_normal_output` | `_db_context` | ❌ 未使用 |
| `write_xml_output` | `_db_context` | ❌ 未使用 |
| `write_grepable_output` | `_db_context` | ✅ **唯一使用** |

**唯一使用位置**:
```rust
// crates/rustnmap-cli/src/cli.rs:2007
let service_name = _db_context.lookup_service(p.number, protocol_str).unwrap_or("");
```

**但是**: 服务名在扫描时已经通过 `rustnmap_common::ServiceDatabase::global()` 填充到 `PortResult.service` 中，输出时直接使用即可。

**建议修复**:
- `grepable` 输出直接使用 `port.service.as_ref().map(|s| &s.name)`
- 移除 `DatabaseContext.services` 字段

#### Issue 3: 服务名填充时机混淆（轻微）

**设计文档中的假设**:
> 在输出时查找服务名（像 nmap 一样）

**实际实现**:
```rust
// 扫描时就已经填充了服务名
let port_result = PortResult {
    service: service_info_from_db(port, service_proto),  // ← 扫描时填充
};
```

**评估**: RustNmap 的实现是**正确的优化**，避免在输出时重复查找。但与设计文档描述不一致。

### 实际使用的数据流

```
┌─────────────────────────────────────────────────────────────┐
│  Scanning Phase (rustnmap_core::orchestrator)              │
│                                                             │
│  1. Port scan completes                                     │
│  2. Immediately fill service name:                         │
│     rustnmap_common::ServiceDatabase::global().lookup(...)  │
│  3. Store in PortResult.service                             │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Service Detection Phase (if -sV enabled)                  │
│                                                             │
│  4. Probe service                                          │
│  5. Override PortResult.service with detected info         │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Output Phase (rustnmap_cli::output functions)             │
│                                                             │
│  6. Directly use port.service (already filled)             │
│  7. No database lookup needed                              │
└─────────────────────────────────────────────────────────────┘
```

### 与 Nmap 的对比

| 方面 | Nmap | RustNmap | 评估 |
|------|------|----------|------|
| 服务名查找时机 | 输出时查找 | 扫描时填充 | ✅ RustNmap 优化 |
| 服务探测覆盖 | 探测结果覆盖 | 探测结果覆盖 | ✅ 一致 |
| ServiceDatabase 定义 | 单一定义 | **重复定义** | ❌ 问题 |
| 数据库使用方式 | 输出时查找 | 扫描时填充 + 输出直接使用 | ✅ 合理 |

### 更新建议

1. **更新设计文档**:
   - 说明服务名在扫描时填充（而非输出时查找）
   - 添加 DatabaseContext 使用限制说明

2. **重构代码** (单独任务):
   - 删除 `rustnmap-fingerprint::database::ServiceDatabase`
   - 简化 `DatabaseContext` 结构
   - 更新 `grepable` 输出使用已填充的服务名

3. **文档一致性**:
   - 确保 `doc/database.md`、`doc/database-integration.md`、`doc/architecture.md` 描述一致
   - 添加架构分析文档链接

---
