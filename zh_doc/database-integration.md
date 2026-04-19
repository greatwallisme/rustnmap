# 数据库集成设计

> **目的**：将 ServiceDatabase、ProtocolDatabase 和 RpcDatabase 集成到输出系统中

---

## 概述

RustNmap 当前加载了三个数据库（ServiceDatabase、ProtocolDatabase、RpcDatabase），但加载后立即丢弃。本文档描述如何将这些数据库集成到输出系统中，以显示友好的名称而非数字。

## 当前状态

### 现有实现

三个数据库均已在 `crates/rustnmap-fingerprint/src/database/` 中完整实现：

1. **ServiceDatabase**（`services.rs`）
   - 端口+协议 → 服务名称的映射
   - 示例：`(80, "tcp")` → `"http"`
   - API：`lookup(port: u16, protocol: &str) -> Option<&str>`

2. **ProtocolDatabase**（`protocols.rs`）
   - 协议号 → 协议名称的映射
   - 示例：`6` → `"tcp"`
   - API：`lookup(number: u8) -> Option<&str>`

3. **RpcDatabase**（`rpc.rs`）
   - RPC 程序号 → RPC 服务名称的映射
   - 示例：`100003` → `"nfs"`
   - API：`lookup(number: u32) -> Option<&str>`

### 问题

在 `crates/rustnmap-cli/src/cli.rs` 中，数据库被加载后即被丢弃：

```rust
match ServiceDatabase::load_from_file(&path).await {
    Ok(_db) => {  // <- 数据库立即被丢弃
        info!("Services database loaded successfully");
        // Note: Service database is available but not yet used in output
    }
    ...
}
```

此问题出现在以下两个函数中：
- `handle_profile_scan()`（第 501-553 行）
- `run_normal_scan()`（第 921-973 行）

---

## Nmap 参考实现

### Nmap 如何使用数据库

参考 `reference/nmap/services.cc` 和 `services.h`：

```c
// Global service map
static ServiceMap service_table;

// Lookup function used in output
const struct nservent *nmap_getservbyport(u16 port, u16 proto) {
    // Returns service entry from service_table
}
```

**输出中的使用：**
```c
// In output.cc (conceptual)
if (service_name = nmap_getservbyport(port, proto)) {
    printf("%d/%s open %s\n", port, proto_str, service_name);
} else {
    printf("%d/%s open\n", port, proto_str);
}
```

**结果：**
```
80/tcp open http      <- 有数据库
80/tcp open           <- 无数据库
```

---

## 设计方案

### 架构

```
+-----------------+
|   CLI 层        |
|  (cli.rs)       |
+--------+--------+
         | 加载数据库
         v
+-----------------+
| DatabaseContext | <- 新结构体
|  - services     |
|  - protocols    |
|  - rpc          |
+--------+--------+
         | 传递给输出层
         v
+-----------------+
| 输出层          |
| (formatters)    |
+-----------------+
```

### 实现计划

#### 阶段 1：创建 DatabaseContext

在 `crates/rustnmap-output/src/database_context.rs` 中创建新结构体：

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

#### 阶段 2：在 CLI 中存储数据库

修改 `cli.rs` 以保存加载的数据库：

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

#### 阶段 3：传递给输出函数

修改输出函数签名：

```rust
// Before
fn write_normal_output(result: &ScanResult, path: &Path, append: bool) -> Result<()>

// After
fn write_normal_output(
    result: &ScanResult,
    path: &Path,
    append: bool,
    db_context: &DatabaseContext  // <- 新增参数
) -> Result<()>
```

#### 阶段 4：在输出中使用

修改输出函数以使用数据库：

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

## 输出格式变化

### 修改前（当前）

```
PORT     STATE SERVICE
80/tcp   open
443/tcp  open
22/tcp   open
```

### 修改后（集成数据库）

```
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
22/tcp   open  ssh
```

---

## 实现清单

- [ ] 创建 `DatabaseContext` 结构体
- [ ] 修改 `cli.rs` 以保存加载的数据库（移除 `_db` 丢弃）
- [ ] 更新输出函数签名以接收 `DatabaseContext`
- [ ] 在 `write_normal_output()` 中实现数据库查询
- [ ] 在 `write_grepable_output()` 中实现数据库查询
- [ ] 在 `write_xml_output()` 中实现数据库查询
- [ ] 添加数据库集成测试
- [ ] 更新文档

---

## 测试策略

1. **单元测试**：测试 `DatabaseContext` 的查询方法
2. **集成测试**：比较有/无数据库时的输出差异
3. **兼容性测试**：验证输出格式与 nmap 一致

---

## 性能考虑

- 数据库在启动时加载一次（无运行时性能影响）
- 查询为 O(1) HashMap 操作
- 可选的 `Arc` 包装允许共享而无需克隆

---

## 向后兼容性

- 若未找到数据库，输出仅显示数字（当前行为）
- 不对现有功能造成破坏性变更
- 数据库不可用时优雅降级

---

## 参考资料

- Nmap 源码：`reference/nmap/services.cc`、`reference/nmap/protocols.cc`
- RustNmap 数据库：`crates/rustnmap-fingerprint/src/database/`
- 输出层：`crates/rustnmap-output/src/`

---
