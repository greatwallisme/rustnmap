# RustNmap 测试失败分析与改进计划

**Created**: 2026-02-23
**Based on**: Comparison Test Report (41 tests, 14 passed, 27 failed)

---

## 执行摘要

| 指标 | 数值 |
|------|------|
| 总测试数 | 41 |
| 通过 | 14 (34.1%) |
| 失败 | 27 (65.9%) |
| 失败分类 | 3 类 |

---

## 失败分类与根因分析

### 类别 1: 端口状态分类错误 (11个失败)

**现象**: rustnmap 报告 `filtered` vs nmap 报告 `closed`
**影响端口**: 443/tcp, 113/tcp, 8080/tcp
**影响测试**: SYN Scan, 所有 Timing Template 测试, 部分多目标测试

#### 根因分析

**文件**: `crates/rustnmap-scan/src/syn_scan.rs:151-161`

```rust
let total_timeout = self.config.initial_rtt;
let start_time = std::time::Instant::now();

loop {
    let elapsed = start_time.elapsed();
    if elapsed >= total_timeout {
        // Total timeout expired - port is filtered or host is down
        return Ok(PortState::Filtered);  // ❌ 错误分类
    }
```

**问题**:
1. 当总超时到期且没有收到响应时，rustnmap 返回 `PortState::Filtered`
2. Nmap 区分 `closed` (收到RST) 和 `filtered` (无响应/ICMP不可达)
3. 一些响应 (RST包) 可能在初始超时后但在实际网络超时前到达
4. `initial_rtt` 默认值可能太短

**优先级**: **HIGH**
**工作量**: 中等

#### 解决方案

1. **增加重试逻辑** (类似 Nmap):
   ```rust
   let mut retry_count = 0;
   let max_retries = 3;

   loop {
       // ... 接收逻辑 ...

       if elapsed >= total_timeout {
           if retry_count < max_retries {
               retry_count += 1;
               total_timeout *= 2;  // 指数退避
               continue;
           }
           // 区分: 完全无响应 vs 收到无关包
           if packets_received == 0 {
               return Ok(PortState::Filtered);
           } else {
               return Ok(PortState::Closed);  // 收到了一些包但没有匹配的RST
           }
       }
   }
   ```

2. **增加默认超时值**:
   - 当前 `initial_rtt` 可能太短
   - 考虑使用 Nmap 的默认值: 1000ms (Normal timing)

3. **改进状态分类逻辑**:
   - `Filtered`: 完全无响应 (无任何包收到)
   - `Closed`: 收到非相关包但超时 (可能有RST延迟到达)

---

### 类别 2: 不支持的功能 (6个失败)

#### 2a. ACK 扫描 (`--scan-ack` / `-sA`) - Exit Code 2

**文件**: `crates/rustnmap-cli/src/args.rs`

**根因**: CLI 参数中未定义 `scan_ack` 字段

**分析**:
- Lines 88-149 定义了扫描类型 (syn, connect, udp, fin, null, xmas, maimon)
- **缺失**: `scan_ack` 和 `scan_window` 字段
- 底层实现**已存在**: `TcpAckScanner` 在 `rustnmap-scan/src/stealth_scans.rs:727+`
- `ScanType` 枚举包含 `TcpAck` (`session.rs:228`)
- orchestrator 已有处理 ACK 扫描的代码 (`orchestrator.rs:902`)

**优先级**: **HIGH**
**工作量**: 低 (只需 CLI 粘合代码)

#### 解决方案

1. 在 `args.rs` 添加字段:
   ```rust
   #[arg(
       long = "scan-ack",
       help_heading = "Scan Techniques",
       conflicts_with = "scan_type"
   )]
   pub scan_ack: bool,

   #[arg(
       long = "scan-window",
       help_heading = "Scan Techniques",
       conflicts_with = "scan_type"
   )]
   pub scan_window: bool,
   ```

2. 在 `map_scan_type()` 函数添加 case:
   ```rust
   if args.scan_ack {
       return Ok(ScanType::TcpAck);
   }
   if args.scan_window {
       return Ok(ScanType::TcpWindow);
   }
   ```

---

#### 2b. Window 扫描 (`--scan-window` / `-sW`) - Exit Code 2

**同上** - 底层实现存在, CLI 参数缺失

**优先级**: **HIGH**
**工作量**: 低

---

#### 2c. Decoy 扫描 (`-D RND:10`) - Exit Code 1

**文件**: `crates/rustnmap-cli/src/args.rs:271-272`

**根因**: Decoy 选项存在但未完全集成

**分析**:
- `decoys` 字段在 Args 结构体中存在
- `rustnmap-evasion` crate 存在
- 验证逻辑存在 (lines 659-667)
- 但实际扫描执行可能未使用 decoy 功能

**优先级**: **MEDIUM**
**工作量**: 中等

---

#### 2d. 排除端口 (`--exclude-port 22`) - Exit Code 2

**根因**: 此选项未在 Args 结构体中实现

**分析**:
- `args.rs` 中没有 `exclude_port` 字段
- Nmap 支持 `--exclude-port` 但 rustnmap 不支持

**优先级**: **MEDIUM**
**工作量**: 低

#### 解决方案

1. 添加 `exclude_ports: Option<String>` 字段
2. 解析并验证端口列表
3. 在端口规格阶段过滤排除的端口

---

#### 2e. JSON 输出 (`--output-json`) - nmap Exit Code 255

**根因**: 这**不是** rustnmap 失败 - nmap 不支持 `--output-json`

**分析**:
- 测试期望两个扫描器都支持此标志
- rustnmap 支持 (args.rs:352-359)
- nmap 返回 255 (未知选项)
- 这是测试配置问题

**优先级**: **LOW**
**工作量**: 无 (测试应该修复, 不是代码)

---

### 类别 3: 输出格式差异 (10个失败)

#### 3a. 服务检测 - VERSION 字段未找到

**文件**: `crates/rustnmap-output/src/formatter.rs`

**根因**: 服务版本信息未在正常格式输出中显示

**分析**:
- `ServiceInfo` 模型有 `version` 字段
- 正常输出格式化程序可能不在默认端口表输出中包含版本
- 需要匹配 nmap 格式: `22/tcp open ssh OpenSSH 8.4p1 Debian 5+deb11u3`

**优先级**: **MEDIUM**
**工作量**: 低

#### 3b. OS 检测 - OS details/OS guesses 字段未找到

**文件**: `crates/rustnmap-output/src/formatter.rs:436-438`

**根因**: OS 检测输出格式与 nmap 不同

**分析**:
- 代码存在: `writeln!(output, "OS details: {}", best_match.name)`
- 测试可能查找不匹配的确切字段名
- 期望字段: "OS details", "OS guesses"
- 测试比较原始 stdout 文本, 不是解析的字段

**优先级**: **MEDIUM**
**工作量**: 低

#### 3c. 输出格式 - expected_fields 验证失败

**文件**: `crates/rustnmap-output/src/formatter.rs`

**分析**:
- XML 输出: 缺少 `<?xml` 和 `<nmaprun>` 标签
- Grepable 输出: 缺少 `Host:` 和 `Status:` 字段
- JSON 输出: 实际工作但 nmap 不支持

**优先级**: **MEDIUM**
**工作量**: 低

---

## 实施优先级顺序

### Phase 1 (关键 - 优先)

| 任务 | 文件 | 优先级 | 工作量 |
|------|------|--------|--------|
| 1. 修复 SYN 扫描超时/分类逻辑 | `rustnmap-scan/src/syn_scan.rs` | HIGH | 中 |
| 2. 添加 `--scan-ack` CLI 参数 | `rustnmap-cli/src/args.rs` | HIGH | 低 |
| 3. 添加 `--scan-window` CLI 参数 | `rustnmap-cli/src/args.rs` | HIGH | 低 |

### Phase 2 (重要)

| 任务 | 文件 | 优先级 | 工作量 |
|------|------|--------|--------|
| 4. 添加 `--exclude-port` 支持 | `rustnmap-cli/src/args.rs` | MEDIUM | 低 |
| 5. 修复服务 VERSION 字段输出 | `rustnmap-output/src/formatter.rs` | MEDIUM | 低 |
| 6. 修复 OS 检测输出格式 | `rustnmap-output/src/formatter.rs` | MEDIUM | 低 |

### Phase 3 (改进)

| 任务 | 文件 | 优先级 | 工作量 |
|------|------|--------|--------|
| 7. 完全集成 decoy 扫描 | `rustnmap-cli/src/cli.rs` | MEDIUM | 中 |
| 8. 修复 XML/Grepable 输出格式 | `rustnmap-output/src/formatter.rs` | MEDIUM | 低 |
| 9. 更新 JSON 输出测试 | `benchmarks/comparison_test.py` | LOW | 无 |

---

## 预期结果

修复后预期通过率: **34.1% -> 85%+**

| 类别 | 当前 | 预期 | 改进 |
|------|------|------|------|
| 端口状态 | 受影响 | 完全修复 | +11 通过 |
| 不支持功能 | 6个失败 | 4个修复 | +4 通过 |
| 输出格式 | 10个失败 | 8个修复 | +8 通过 |

---

## 修改文件清单

| 文件 | 修改类型 | 描述 |
|------|----------|------|
| `rustnmap-scan/src/syn_scan.rs` | 修改 | 超时/分类逻辑 |
| `rustnmap-cli/src/args.rs` | 修改 | 添加 CLI 参数 |
| `rustnmap-cli/src/cli.rs` | 修改 | 扫描类型映射 |
| `rustnmap-output/src/formatter.rs` | 修改 | 输出格式修复 |
| `benchmarks/comparison_test.py` | 修改 | 测试期望调整 |
