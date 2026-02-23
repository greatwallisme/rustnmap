# Task Plan

**Created**: 2026-02-21
**Updated**: 2026-02-23 17:30
**Status**: Phase 13 修复 AF_PACKET 集成和 clippy 错误 - COMPLETE
**Goal**: 修复测试失败问题

**详细分析**: 见 `IMPROVEMENT_PLAN.md`

---

## 当前阶段

Phase 10: 更新测试框架适配CLI修改 - COMPLETE
Phase 11: 修复测试失败问题 - COMPLETE (被 Phase 13 取代)
Phase 12: SYN 扫描架构改进 - COMPLETE (被 Phase 13 取代)
Phase 13: 修复 AF_PACKET 集成和 clippy 错误 - COMPLETE
Phase 14: 性能优化和网络抖动处理 - PLANNED

---

## 阶段划分

### Phase 13: 修复 AF_PACKET 集成和 clippy 错误 - COMPLETE

**修复的 3 个 bug**:

| Bug | 文件 | 根因 | 影响 |
|-----|------|------|------|
| `get_if_index` 读错字段 | `ultrascan.rs:145` | 读 `ifru_addr.sa_family` 而非 `ifru_ifindex` | AF_PACKET 绑错接口，收不到任何包 |
| RST 验证过滤 seq=0 | `ultrascan.rs:539` | `packet.seq() != 0` 过滤掉所有 RST 包 | closed 端口全部误判为 filtered |
| 输出解析器误解析 OS 行 | `compare_scans.py:49-86` | 未验证端口格式，OS 指纹名被当端口 | Aggressive Scan 测试误报 FAIL |

**30 个 clippy 错误修复**: 全部在 `SimpleAfPacket` 代码中
- 12 个 `unsafe block missing a safety comment` (SAFETY 注释移到 unsafe 块前)
- 6 个 `doc_markdown` (AF_PACKET 等术语加反引号)
- 3 个 `allow without reason` (改为 `#[expect]` + reason)
- 2 个 `cast_possible_truncation` (改用 `u32::try_from`)
- 2 个 `cast_usize_to_u32` (同上)
- 1 个 `clone_on_ref_ptr` (改为 `Arc::clone()`)
- 1 个 `empty_drop` (删除空 Drop impl)
- 1 个 `struct field order` (修正构造器字段顺序)
- 1 个 `cast_sign_loss` (加 `#[expect]` + reason)
- 1 个 `cast_u8_to_i8` (加 `#[expect]` + reason)

**测试结果 (2026-02-23 17:24, 串行运行)**:

| 套件 | 通过/总数 | 之前 | 改善 |
|------|----------|------|------|
| Basic Port Scans | 5/5 | 4/5 | +1 |
| Advanced Scans | 6/6 | 0/6 | +6 |
| Service Detection | 3/3 | 0/3 | +3 |
| **合计** | **14/14** | **4/14** | **+10** |

---

### Phase 14: 性能优化和网络抖动处理 - PLANNED

**目标**: 解决 rustnmap 比 nmap 慢的场景，增加网络抖动容错

#### 性能劣势点 (需优化)

| 测试 | rustnmap | nmap | speedup | 分析 |
|------|----------|------|---------|------|
| SYN Scan (5 ports) | 589ms | 448ms | 0.76x | AF_PACKET 非阻塞轮询开销 |
| Connect Scan (5 ports) | 2995ms | 1781ms | 0.59x | 串行连接，缺少并行 |
| Fast Scan (100 ports) | 7241ms | 4915ms | 0.68x | 大量 closed 端口输出开销 |
| Top Ports (100 ports) | 5094ms | 4624ms | 0.91x | 接近持平 |
| Timing T4 (5 ports) | 723ms | 596ms | 0.82x | T4 模板参数未完全对齐 |
| Min/Max Rate | 1768ms | 1002ms | 0.57x | 速率控制实现差异 |
| Version Intensity | 10607ms | 8346ms | 0.79x | 服务探测效率 |

#### 性能优势点

| 测试 | rustnmap | nmap | speedup | 分析 |
|------|----------|------|---------|------|
| FIN Scan | 718ms | 3892ms | 5.42x | 更快的超时处理 |
| XMAS Scan | 815ms | 3444ms | 4.23x | 同上 |
| MAIMON Scan | 744ms | 3805ms | 5.11x | 同上 |
| NULL Scan | 1755ms | 3570ms | 2.03x | 同上 |
| UDP Scan | 3069ms | 4119ms | 1.34x | AF_PACKET 零拷贝 |
| Version Detection | 9181ms | 16320ms | 1.78x | 更快的端口扫描阶段 |
| Aggressive Scan | 15170ms | 45556ms | 3.0x | 综合优势 |

#### nmap 网络抖动应对机制 (rustnmap 缺失)

**1. 自适应 RTT 超时算法**
- nmap 使用 TCP 风格的 SRTT/RTTVAR 指数平滑
- `srtt += rttdelta/8`, `rttvar += (|rttdelta| - rttvar)/4`
- `timeout = srtt + 4*rttvar`
- 异常值过滤: `rttdelta > 1.5s AND rttdelta > 3*srtt + 2*rttvar` 时丢弃样本
- rustnmap 当前: 固定 1500ms 超时，无自适应

**2. 拥塞控制 (CWND)**
- 慢启动 + 拥塞避免，类似 TCP Reno
- 丢包时: `cwnd = low_cwnd`, `ssthresh = in_flight / divisor`
- 成功时: 慢启动阶段 `cwnd += slow_incr`，拥塞避免阶段 `cwnd += ca_incr/cwnd`
- rustnmap 当前: 固定并行度 (min=10, max=100)，无动态调整

**3. 速率限制检测 (RLD)**
- 检测目标是否在限速 ICMP/RST 响应
- 当连续超时时降低发送速率
- `pingtime = RLD_TIME_MS * 1000 / 4` 用于探测
- rustnmap 当前: 无 RLD 检测

**4. 重试机制**
- `tryno` 跟踪每个探针的重试次数
- 超时后指数退避: `timeout *= 2` (每次重试)
- `max_successful_tryno` 记录最高成功重试次数
- rustnmap 当前: 有基本重试但无指数退避

**5. 端口状态验证**
- 不允许从 closed 变回 open (防止误判)
- 不允许从 open 变为 filtered (防止网络抖动降级)
- 对 noresp_open_scan (FIN/NULL/XMAS) 不允许从 filtered 变为 open
- rustnmap 当前: 无状态转换验证

#### 优化计划

**P0 (关键)**:
1. 实现自适应 RTT 超时 (SRTT/RTTVAR)
2. 实现拥塞窗口动态调整

**P1 (重要)**:
3. Connect Scan 并行化
4. 输出优化: 默认隐藏 closed 端口 (与 nmap 一致)
5. 端口状态转换验证

**P2 (改进)**:
6. 速率限制检测 (RLD)
7. Timing Template 参数对齐
8. 指数退避重试

---

## 测试结果 (2026-02-23 14:30)

| 测试套件 | 通过/总数 | 状态 |
|---------|----------|------|
| Basic Port Scans | 4/5 | ⚠️ UDP 修复有效，SYN 仍失败 |
| Service Detection | 0/3 | ❌ |
| OS Detection | 0/3 | ❌ |

**通过的测试**: Connect, UDP, Fast Scan, Top Ports

#### 测试失败摘要

| 类别 | 数量 | 根因 | 优先级 |
|------|------|------|--------|
| 端口状态差异 | 11 | 超时逻辑分类错误 | HIGH |
| 不支持功能 | 6 | CLI参数缺失 | HIGH/MEDIUM |
| 输出格式差异 | 10 | 格式不匹配 | MEDIUM |

#### 实施计划

**Phase 1 (关键 - 优先)**:

1. **修复 SYN 扫描超时/分类逻辑** (HIGH, 中等工作量)
   - 文件: `rustnmap-scan/src/syn_scan.rs:151-161`
   - 问题: 超时后返回 `Filtered` 而非 `Closed`
   - 解决: 增加重试逻辑、指数退避、改进状态分类
   - 预期: 修复 11 个端口状态失败

2. **添加 `--scan-ack` CLI 参数** (HIGH, 低工作量)
   - 文件: `rustnmap-cli/src/args.rs`
   - 问题: CLI 参数缺失 (底层实现已存在)
   - 解决: 添加 `scan_ack` 字段和 `map_scan_type()` case
   - 预期: 修复 1 个失败

3. **添加 `--scan-window` CLI 参数** (HIGH, 低工作量)
   - 文件: `rustnmap-cli/src/args.rs`
   - 问题: CLI 参数缺失 (底层实现已存在)
   - 解决: 添加 `scan_window` 字段和 `map_scan_type()` case
   - 预期: 修复 1 个失败

**Phase 2 (重要)**:

4. **添加 `--exclude-port` 支持** (MEDIUM, 低工作量)
   - 文件: `rustnmap-cli/src/args.rs`
   - 解决: 添加 `exclude_ports: Option<String>` 字段

5. **修复服务 VERSION 字段输出** (MEDIUM, 低工作量)
   - 文件: `rustnmap-output/src/formatter.rs`
   - 解决: 确保 `format_port()` 包含版本信息

6. **修复 OS 检测输出格式** (MEDIUM, 低工作量)
   - 文件: `rustnmap-output/src/formatter.rs:436-438`
   - 解决: 确保 "OS details:" 和 "OS guesses:" 格式匹配

**Phase 3 (改进)**:

7. **完全集成 decoy 扫描** (MEDIUM, 中等工作量)
8. **修复 XML/Grepable 输出格式** (MEDIUM, 低工作量)
9. **更新 JSON 输出测试** (LOW, 无工作量 - 测试问题)

#### 预期结果

修复后预期通过率: **34.1% -> 85%+**

---

### Phase 10: 更新测试框架适配CLI修改 - COMPLETE ✅

(Phase 10 详情见上方或查看 progress.md/findings.md)

---

### Phase 9: 比较测试框架与bug修复 - COMPLETE

---

## 修改的文件 (Phase 11 计划)

| 文件 | 操作 | 描述 |
|------|------|------|
| `rustnmap-scan/src/syn_scan.rs` | 修改 | 超时/分类逻辑 |
| `rustnmap-cli/src/args.rs` | 修改 | 添加 CLI 参数 |
| `rustnmap-cli/src/cli.rs` | 修改 | 扫描类型映射 |
| `rustnmap-output/src/formatter.rs` | 修改 | 输出格式修复 |
| `benchmarks/comparison_test.py` | 修改 | 测试期望调整 |

---

## 验证命令

```bash
# 修复后验证
just build-release
just bench-compare
just clippy
just test
```

---

## 历史阶段

### Phase 1-9: 见 progress.md / findings.md

**Recent CLI Changes** (from session catchup):
1. **输出格式修复** (commit 7cdd880):
   - 修复UTC时间戳显示为本地时间
   - 修复targets显示（从placeholder变为实际目标）
   - 修复closed ports被过滤的问题

2. **测试脚本现状**:
   - 17个测试用例（基础扫描5、服务检测3、OS检测3、高级扫描6）
   - 70.6%通过率（12 passing, 5 failing）
   - 解析器需要适配新的输出格式

3. **测试覆盖缺口**:
   - 缺少ACK、Window、Idle、IP Protocol扫描测试
   - 缺少NSE脚本执行测试
   - 缺少输出格式验证（XML、JSON、Grepable、Script Kiddie）
   - 缺少IPv6、多目标、目标规格测试
   - 缺少规避技术测试

#### 实施计划

**Step 1: 审查当前测试脚本**

检查文件:
- `benchmarks/comparison_test.py` - 主测试运行器
- `benchmarks/compare_scans.py` - 扫描比较逻辑
- `benchmarks/test_configs/*.toml` - 测试配置

**Step 2: 更新输出解析器**

适配新的rustnmap输出格式:
- 本地时间戳格式
- 实际targets显示
- closed ports显示

**Step 3: 添加新测试用例**

新增测试配置:
- `output_formats.toml` - 输出格式测试（XML、JSON、Grepable、Script Kiddie）
- `stealth_scans.toml` - 扩展隐蔽扫描测试
- `timing_tests.toml` - 时序模板测试（T0-T5）
- `multi_target.toml` - 多目标扫描测试

**Step 4: 增强错误处理**

- 添加更详细的失败原因记录
- 改进port state比较逻辑
- 添加OS检测和服务检测的输出解析

**Step 5: 运行并验证**

```bash
just build-release      # 确保最新版本
just bench-compare      # 运行完整测试
just bench-compare-verbose  # 详细输出
```

#### 预期结果

- 测试通过率: 70.6% -> 85%+
- 新增测试用例: +10个
- 所有现有测试适配新的CLI输出格式

---

### Phase 9: 比较测试框架与bug修复 - COMPLETE

### Phase 8: 性能优化 - 实现 UltraScan 并行扫描架构 - COMPLETE

---

## 修改的文件 (Phase 10)

| 文件 | 操作 | 描述 |
|------|------|------|
| `benchmarks/comparison_test.py` | 修改 | 适配新CLI输出格式 |
| `benchmarks/compare_scans.py` | 修改 | 更新解析器逻辑 |
| `benchmarks/test_configs/output_formats.toml` | 新建 | 输出格式测试 |
| `benchmarks/test_configs/timing_tests.toml` | 新建 | 时序模板测试 |
| `benchmarks/test_configs/multi_target.toml` | 新建 | 多目标测试 |
| `benchmarks/test_configs/stealth_scans.toml` | 扩展 | 增强隐蔽扫描测试 |

---

## 验证命令

```bash
# 编译最新版本
just build-release

# 运行测试
just bench-compare
just bench-compare-verbose

# 检查代码质量
just clippy
just test
```
