# Findings - RustNmap 项目分析

**Created**: 2026-02-19
**Updated**: 2026-02-23

---

## 最新发现 (2026-02-23)

### ✅ CRITICAL: UDP扫描远程主机状态错误 - 已修复!

**文件**: `crates/rustnmap-scan/src/udp_scan.rs`

**问题**: UDP扫描在远程主机上显示 `open|filtered` 而不是 `closed`

**症状**:
- localhost测试: 正确显示 `closed` ✅
- 远程主机: 显示 `open|filtered` ❌
- nmap对同一目标: 正确显示 `closed`

**测试结果** (修复后):
```
# localhost (工作正常)
$ sudo ./target/release/rustnmap --scan-udp -p 53 127.0.0.1
Not shown: 1 closed ports  ✅

# 远程主机 (已修复!)
$ sudo ./target/release/rustnmap --scan-udp -p 53 45.33.32.156
53/udp  closed domain  ✅

# nmap对比
$ sudo nmap -sU -p 53 45.33.32.156
53/udp  closed domain  ✅
```

**根本原因** (已确认):
1. **nmap使用libpcap**: nmap使用`pcap_open_live()`捕获所有以太网帧，包括ICMP错误响应
2. **rustnmap使用raw socket**: 使用`IPPROTO_ICMP (1)`的raw socket只能接收直接发往本机的ICMP数据包
3. **ICMP错误响应传递机制**: ICMP Port Unreachable错误响应不是通过协议特定的raw socket接收的

**修复方案**:
- 集成`rustnmap-packet` crate的`AfPacketEngine` (PACKET_MMAP V3零拷贝引擎)
- 添加`packet_engine_v4`字段到`UdpScanner`
- 优先使用`AF_PACKET`接收ICMP错误响应，回退到raw socket方式

**代码变更**:
1. 添加`packet_engine_v4: Option<AfPacketEngine>`字段
2. 实现`create_packet_engine()` - 创建AF_PACKET引擎
3. 实现`recv_icmp_from_packet_engine()` - 从PACKET_MMAP接收ICMP
4. 实现`get_interface_for_ip()` - 检测网络接口
5. 更新`send_udp_probe_v4()` - 优先使用AF_PACKET

**优先级**: HIGH - UDP扫描是核心功能

**状态**: ✅ 已修复

---

### 🐛 MEDIUM: 服务名后出现`$`字符

**文件**: 输出格式相关

**症状**: 使用`cat -A`查看输出时，服务名后出现`$`字符

**实际观察**:
```
$ sudo ./target/release/rustnmap --os-detection 45.33.32.156 | cat -A
22/tcp  open    ssh$
80/tcp  open    http$
```

**分析**:
- `$`是`cat -A`显示行尾的方式（表示换行符`\n`）
- 这是正常的，不是bug
- 真正的问题是UDP扫描的状态分类

**状态**: ✅ 非问题 - cat -A的正常行为

---

## 历史发现 (2026-02-22)

### 🆕 比较测试框架 - 新建

**文件**: `benchmarks/` 目录

**成果**: 创建了完整的rustnmap vs nmap比较测试框架

**测试框架结构**:
- Python测试脚本 (`comparison_test.py`, `compare_scans.py`)
- TOML测试配置文件 (`test_configs/*.toml`)
- uv依赖管理 (`pyproject.toml` with Tsinghua mirror)
- Justfile集成 (`just bench-compare*`)
- 自动报告生成 (text + JSON格式)

**测试结果概览 (2026-02-22 16:32)**:

| 指标 | 结果 |
|------|------|
| 总测试数 | 17 |
| 通过 | 8 (47.1%) |
| 失败 | 9 (52.9%) |

**性能亮点**:
- XMAS扫描: rustnmap比nmap快 **5.68x** (0.8s vs 4.3s)
- OS检测猜测: rustnmap比nmap快 **4.66x** (16.2s vs 75.5s)
- OS检测限制: rustnmap比nmap快 **3.23x** (19.5s vs 62.9s)
- 激进扫描(-A): rustnmap比nmap快 **3.01x** (13.8s vs 41.5s)
- OS检测: rustnmap比nmap快 **3.20x** (18.8s vs 60.1s)
- 时序模板T4: rustnmap比nmap快 **3.19x** (1.7s vs 5.5s)

### 🐛 CRITICAL: rustnmap扫描后不退出bug - 已修复!

**问题**: rustnmap扫描完成后不自动退出，必须Ctrl+C终止

**文件**: `crates/rustnmap-scan/src/ultrascan.rs:348`

**根本原因**: 等待receiver task时没有超时机制
```rust
// 问题代码
let _ = receiver_handle.await;  // 永久等待
```

**解决方案**: 添加200ms超时
```rust
// 修复后
let _ = tokio::time::timeout(Duration::from_millis(200), receiver_handle).await;
```

**状态**: ✅ 已修复并验证

### 🐛 CRITICAL: 探针超时延迟问题 - 已修复!

**文件**: `crates/rustnmap-scan/src/ultrascan.rs:474`

**问题**: 使用 `>` 比较导致探针在正好超时时不会被视为超时
- 预期: 1000ms时超时
- 实际: 需要>1000ms才超时 (约1100ms)

**修复**: 改为 `>=` 比较
```rust
// 修复前
.filter(|(_, p)| now.duration_since(p.sent_time) > self.probe_timeout)

// 修复后
.filter(|(_, p)| now.duration_since(p.sent_time) >= self.probe_timeout)
```

**影响**: 确保探针在超时时立即被处理，而不是等待下一个检查周期

### 🐛 CRITICAL: 探针丢失bug - 已修复!

**文件**: `crates/rustnmap-scan/src/ultrascan.rs:330-332`

**问题**: 当达到并行度限制时，重试探针被丢弃
```rust
// 问题代码
for probe in retry_probes.drain(..) {
    if outstanding.len() < self.max_parallelism {
        self.resend_probe(probe, &mut outstanding)?;
    }
    // 否则探针丢失！
}
```

**修复**: 添加fallback标记为filtered
```rust
// 修复后
for probe in retry_probes.drain(..) {
    if outstanding.len() < self.max_parallelism {
        self.resend_probe(probe, &mut outstanding)?;
    } else {
        results.entry(probe.port).or_insert(PortState::Filtered);
    }
}
```

**状态**: ✅ 已修复

### ✅ Aggressive扫描 (-A) - 已修复!

**问题**: `rustnmap -A <target>` 命令之前无法正常工作

**文件**: `crates/rustnmap-cli/src/args.rs`, `crates/rustnmap-cli/src/cli.rs`

**根本原因**: `-A` 选项没有在CLI参数中定义

**修复内容**:
1. 在 `Args` 结构体中添加 `aggressive_scan` 选项 (`-A`)
2. 在 `build_scan_config` 中添加处理逻辑，启用:
   - OS检测 (`-O`)
   - 服务检测 (`-sV`)
   - 漏洞脚本 (`--script vuln`)
   - 激进时序 (`-T4`)

**代码变更**:
```rust
// args.rs - 添加选项
#[arg(short = 'A', long, help_heading = "Service/OS Detection")]
pub aggressive_scan: bool,

// cli.rs - 添加处理逻辑
if args.aggressive_scan {
    config.service_detection = true;
    config.os_detection = true;
    config.nse_scripts = true;
    config.nse_categories = vec!["vuln".to_string()];
    config.timing_template = TimingTemplate::Aggressive;
}
```

**状态**: ✅ 已修复并验证
- 退出码: 0 (成功)
- 服务检测: 正常工作 (显示OpenSSH, Apache版本)
- OS检测: 正常工作 (显示OS猜测)
- 扫描时间: 约32秒 (合理)

---

## 比较测试问题 (2026-02-22 16:32)

### ✅ CRITICAL: 隐蔽扫描状态分类错误 - 已修复!

**文件**: `crates/rustnmap-core/src/orchestrator.rs`

**问题**: FIN, NULL, XMAS, MAIMON 扫描报告 `filtered` 而非 `open|filtered`

**根本原因**: orchestrator.rs 中的端口状态转换代码将所有非Open/Closed状态转换为Filtered

**修复内容**:
1. 并行扫描状态转换 (line 563-571): 添加对所有端口状态的支持
   - `OpenOrFiltered` -> `OpenOrFiltered`
   - `ClosedOrFiltered` -> `ClosedOrFiltered`
   - `OpenOrClosed` -> `OpenOrClosed`
   - `Unfiltered` -> `Unfiltered`

2. 顺序扫描状态转换 (line 976-987): 同样添加对所有状态的支持

3. 统计计数修复: 只有 `Open` 端口才计入 `record_open_port()`

**状态**: ✅ 已修复并编译通过

### ✅ CRITICAL: 隐蔽扫描超时和响应过滤错误 - 已修复! (2026-02-22)

**文件**: `crates/rustnmap-scan/src/stealth_scans.rs`, `crates/rustnmap-core/src/orchestrator.rs`, `crates/rustnmap-net/src/lib.rs`

**问题**: 隐蔽扫描的超时和响应处理存在多个错误

**根本原因**:
1. orchestrator 使用 `scan_delay` 作为 `initial_rtt`，但 `scan_delay` 是探测间延迟而非超时
2. stealth scanner 只检查端口不检查源IP，可能接受其他主机的响应
3. `recv_packet` 每次调用后重置socket为阻塞模式，导致循环超时不工作
4. orchestrator 过滤掉所有 `Closed` 端口不显示

**修复内容**:
1. `orchestrator.rs` (line 815-822): 使用 timing template 的实际超时值
   ```rust
   let timing_config = self.session.config.timing_template.scan_config();
   let scanner_config = ScannerConfig {
       initial_rtt: timing_config.initial_rtt,  // 100ms for Normal timing
       ...
   };
   ```

2. `stealth_scans.rs` (line 170-187): 添加源IP检查和响应过滤循环
   ```rust
   if let Some((flags, _seq, _ack, src_port, src_ip)) = parse_tcp_response(&recv_buf[..len]) {
       // 只处理来自目标主机且端口匹配的响应
       if src_ip == dst_addr && src_port == dst_port {
           if (flags & tcp_flags::RST) != 0 {
               return Ok(PortState::Closed);
           }
           return Ok(PortState::Filtered);
       }
       // 其他响应 - 继续等待
   }
   ```

3. `lib.rs` (line 286-302): 移除 socket 超时重置代码，保持超时设置

4. `orchestrator.rs` (line 645, 589, 732): 移除 Closed 端口过滤，显示所有状态

**状态**: ✅ 已修复并验证

**对比测试验证** (2026-02-22 22:06):
- 成功率: 47.1% → 70.6% (+23.5%)
- FIN Scan: PASS ✅ (4.74x faster than nmap)
- NULL Scan: PASS ✅ (5.86x faster than nmap)
- XMAS Scan: PASS ✅ (4.53x faster than nmap)
- MAIMON Scan: PASS ✅ (3.16x faster than nmap)

### 🐛 MEDIUM: UDP 扫描状态差异 - 新问题 (2026-02-22)

**文件**: `crates/rustnmap-scan/src/scanners/udp_scanner.rs`

**问题**: UDP扫描中所有端口被错误分类为 `filtered` 而非 `closed`

**症状**:
- rustnmap报告: 所有UDP端口为 `filtered`
- nmap报告: UDP端口为 `closed`
- 状态不匹配导致测试失败

**影响**: UDP扫描功能完全不可用

**优先级**: HIGH

**修复方向**:
- 检查UDP响应解释逻辑
- 参考 nmap UDP 状态机实现

### ✅ HIGH: 输出格式不匹配 - 已修复!

**文件**: `crates/rustnmap-output/src/formatter/formatter.rs`

**问题**: 输出格式缺少关键字段，导致比较测试无法解析

**缺失字段**:
- `VERSION` - 服务版本检测
- `OS details` - OS检测详情
- `OS guesses` - OS猜测列表
- `Service detection` - 服务检测摘要

**影响**:
- 比较测试失败
- 输出与nmap不兼容
- 用户无法获取完整信息

**优先级**: HIGH

### 🐛 MEDIUM: 端口检测不一致

**文件**: `crates/rustnmap-scan/src/port_strategy.rs`

**问题**: 某些端口在基础扫描中未被检测到

**缺失端口**:
- `8080/tcp` - HTTP代理
- `113/tcp` - ident/auth
- `443/tcp` - HTTPS

**影响**:
- 端口枚举不完整
- 可能遗漏重要服务

**优先级**: MEDIUM

### 🐛 MEDIUM: OS检测输出格式问题

**文件**: `crates/rustnmap-fingerprint/src/os_detection.rs`

**问题**: 厂商名称作为端口条目出现在输出中

**症状**:
- 输出中出现 "Apple", "Cisco", "HP" 等厂商名作为端口
- 导致解析混乱

**影响**: 输出格式不正确，比较测试失败

**优先级**: MEDIUM

---

## 测试结果汇总

### 通过的测试 (8/17)

1. ✅ SYN扫描 - 轻慢于nmap (0.85x)
2. ✅ Connect扫描 - 慢于nmap (0.70x)
3. ✅ Fast扫描 - 快于nmap (1.36x)
4. ✅ Top Ports - 快于nmap (1.06x)
5. ✅ 版本检测 - 快于nmap (1.94x)
6. ✅ 版本检测强度 - 快于nmap (1.24x)
7. ✅ 时序模板T4 - 快于nmap (3.19x)
8. ✅ 最小/最大速率 - 慢于nmap (0.63x)

### 失败的测试 (9/17)

1. ❌ UDP扫描 - 状态分类错误
2. ❌ 激进扫描(-A) - OS检测输出格式不匹配
3. ❌ OS检测 - 输出格式不匹配
4. ❌ OS检测限制 - 输出格式不匹配
5. ❌ OS检测猜测 - 输出格式不匹配
6. ❌ FIN扫描 - 状态分类错误
7. ❌ NULL扫描 - 状态分类错误
8. ❌ XMAS扫描 - 状态分类错误
9. ❌ MAIMON扫描 - 状态分类错误

---

**最新报告**: `benchmarks/reports/comparison_report_20260222_163207.txt`

