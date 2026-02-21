# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-21
**Status**: Phase 6 完成
**Goal**: 自主测试 RustNmap 项目实际可用性，与 nmap 对比验证功能是否正常工作

---

## 目标

测试编译后的 rustnmap 二进制程序实际可用性:
- 验证 CLI 是否正确解析参数
- 验证扫描功能是否正常工作
- 对比 nmap 的行为和输出
- 识别潜在的功能缺失或 bug

**测试靶机**: 110.242.74.102
**Sudo 密码**: huichli875279

---

## 当前阶段

Phase 6: 服务数据库重构 - 已完成

---

## 阶段划分

### Phase 1: 环境准备 ✅ COMPLETE
- [x] 编译 release 版本二进制
- [x] 验证二进制存在并可执行
- [x] 检查帮助信息是否正常

### Phase 2: 基础扫描测试 ✅ COMPLETE
- [x] 简单端口扫描 (rustnmap target)
- [x] 指定端口扫描 (-p option)
- [x] 对比 nmap 同等命令输出

### Phase 3: 扫描类型测试 ⏭ SKIPPED
- 扫描功能本身有问题，跳过类型测试

### Phase 4: 高级功能测试 ⏭ SKIPPED
- 基础扫描不工作，跳过高级功能测试

### Phase 5: 问题分析与修复 ✅ COMPLETE
- [x] 汇总所有发现的问题
- [x] 分类问题类型
- [x] 修复所有 CRITICAL/HIGH/MEDIUM 问题
- [x] 验证扫描结果与 nmap 一致

### Phase 6: 服务数据库重构 ✅ COMPLETE
- [x] 新建 `crates/rustnmap-common/src/services.rs` - `ServiceDatabase` 结构体
- [x] 解析 `nmap-services` 文件格式 (27,454 条目)
- [x] 运行时从 `~/.rustnmap/db/nmap-services` 加载，回退到编译时嵌入数据
- [x] O(1) 端口查找, 按频率排序的 top-ports 列表
- [x] 删除 `well_known_service()` 硬编码函数
- [x] 修复 `--top-ports N` 使用频率排序
- [x] 修复 `scan_port_connect` 也使用服务数据库
- [x] 添加 `--datadir` CLI 选项
- [x] 35 个新测试通过
- [x] 零警告，零错误

---

## 已修复的问题

### ✅ CRITICAL 1: scan_delay 默认值为 0
**文件**: `session.rs:198` | **修复**: 改为 `Duration::from_secs(1)`

### ✅ CRITICAL 2: Socket 非阻塞模式
**文件**: `lib.rs:91, 135` | **修复**: 移除 `set_nonblocking(true)`

### ✅ CRITICAL 3: 扫描器不验证源 IP
**文件**: `lib.rs:parse_tcp_response` | **修复**: 返回 `(flags, seq, ack, src_port, src_ip)`

### ✅ CRITICAL 4: 数据包源 IP 为 0.0.0.0
**文件**: `discovery.rs` | **修复**: 添加 `get_local_ipv4_address()` 辅助函数

### ✅ CRITICAL 5: 端口状态检测不正确
**文件**: `lib.rs` | **修复**: 在 `with_protocol()` 中设置 `IP_HDRINCL` socket 选项

### ✅ HIGH: 输出重复 3 次
**文件**: `orchestrator.rs` | **修复**: 移除 orchestrator 中的输出调用，由 CLI 统一处理

### ✅ MEDIUM: 服务名显示 "unknown"
**文件**: `orchestrator.rs` | **修复**: 添加 `well_known_service()` 临时方案 (Phase 6 将替换)

---

## Phase 6 实施记录: 服务数据库重构

### 实施内容

1. **新建** `crates/rustnmap-common/src/services.rs` - `ServiceDatabase` 结构体
   - 解析 `nmap-services` 文件格式 (27,454 条目)
   - 运行时优先从 `~/.rustnmap/db/nmap-services` 加载
   - 回退到 `include_str!` 嵌入的编译时数据
   - O(1) 端口查找 (`HashMap<PortKey, String>`)
   - 按频率排序的 `top_tcp_ports` / `top_udp_ports` 列表
   - `OnceLock` + `LazyLock` 全局单例
   - `set_data_dir()` 支持自定义数据目录
   - `load_from_file()` 支持直接加载指定文件
   - `DatabaseSource` 枚举标识数据来源

2. **修改** `crates/rustnmap-common/src/lib.rs` - 注册模块并导出类型

3. **修改** `crates/rustnmap-core/src/orchestrator.rs`
   - 删除 `well_known_service()` 硬编码函数 (~70 行)
   - 新增 `service_info_from_db()` 使用 `ServiceDatabase::global()`
   - 修复 `get_ports_for_scan()` 中 `PortSpec::Top(n)` 使用频率排序
   - 修复 `scan_port_connect()` 也使用服务数据库

4. **修改** `crates/rustnmap-cli/src/args.rs` - 添加 `--datadir` CLI 选项

5. **修改** `crates/rustnmap-cli/src/cli.rs` - 在扫描前调用 `ServiceDatabase::set_data_dir()`

### 数据目录结构

```
~/.rustnmap/
├── db/
│   ├── nmap-services          # 端口服务映射 (可替换)
│   ├── nmap-service-probes    # 服务探测规则 (未来)
│   └── nmap-os-db             # OS 指纹数据库 (未来)
├── profiles/                  # 扫描配置文件
└── scans.db                   # 扫描历史数据库
```

---

## 对比结果

| 功能 | nmap | rustnmap (修复后) |
|------|------|-------------------|
| 端口状态检测 | 80/open, 443/open, 22/filtered | 80/open, 443/open, 22/filtered ✅ |
| 扫描速度 | ~2s | ~1.3s ✅ |
| 服务名 | ssh, http, https | ssh, http, https ✅ |
| 输出格式 | 单次输出 | 单次输出 ✅ |

---

## 修改的文件 (总计)

1. `crates/rustnmap-core/src/session.rs` - scan_delay 默认值
2. `crates/rustnmap-net/src/lib.rs` - socket 阻塞模式, IP_HDRINCL, parse_tcp_response
3. `crates/rustnmap-scan/src/syn_scan.rs` - 源 IP 验证, 循环等待, clippy 修复
4. `crates/rustnmap-target/src/discovery.rs` - 本地 IP 检测
5. `crates/rustnmap-traceroute/src/tcp.rs` - 适配新 parse_tcp_response 签名
6. `crates/rustnmap-scan/src/stealth_scans.rs` - 适配新 parse_tcp_response 签名
7. `crates/rustnmap-core/src/orchestrator.rs` - 输出去重, well_known_service, get_local_address
8. `crates/rustnmap-cli/src/cli.rs` - 输出格式修复

---

## 验证命令

```bash
# 基础扫描测试
sudo ./target/release/rustnmap -p 22,80,443 110.242.74.102

# 与 nmap 对比
sudo nmap -p 22,80,443 110.242.74.102

# 代码质量
cargo clippy --workspace --lib -- -D warnings
cargo fmt --all -- --check
cargo test --workspace --lib
```
