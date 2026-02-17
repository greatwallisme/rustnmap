# 5. 项目结构与模块划分

> **版本**: 1.0.0 (2.0 开发中)
> **最后更新**: 2026-02-17

---

## 5.0 RustNmap 2.0 项目概览

### 5.0.1 Crate 列表 (1.0 + 2.0)

| Crate | 用途 | 状态 | 对应 Phase |
|-------|------|------|-----------|
| `rustnmap-common` | 公共类型、工具函数、错误处理 | 1.0 | - |
| `rustnmap-net` | 原始套接字、数据包构造 | 1.0 | - |
| `rustnmap-packet` | PACKET_MMAP V3 零拷贝引擎 | 1.0 | - |
| `rustnmap-target` | 目标解析、主机发现 | 1.0 | - |
| `rustnmap-scan` | 端口扫描实现 | 1.0 | - |
| `rustnmap-fingerprint` | OS/服务指纹匹配 | 1.0 | - |
| `rustnmap-nse` | Lua 脚本引擎 | 1.0 | - |
| `rustnmap-traceroute` | 网络路由追踪 | 1.0 | - |
| `rustnmap-evasion` | 防火墙/IDS 规避技术 | 1.0 | - |
| `rustnmap-cli` | 命令行界面 | 1.0 | - |
| `rustnmap-core` | 核心编排和状态管理 | 1.0 | - |
| `rustnmap-output` | 输出格式化 | 1.0 | - |
| `rustnmap-benchmarks` | 性能基准测试 | 1.0 | - |
| `rustnmap-macros` | 过程宏 | 1.0 | - |
| `rustnmap-vuln` | **漏洞情报 (CVE/CPE/EPSS/KEV)** | **2.0 NEW** | Phase 2 |
| `rustnmap-api` | **REST API / Daemon 模式** | **2.0 NEW** | Phase 5 |
| `rustnmap-sdk` | **Rust SDK (Builder API)** | **2.0 NEW** | Phase 5 |

**总计**: 14 个 (1.0) + 3 个 (2.0 新增) = **17 个 Crate**

---

## 5.1 Cargo Workspace 结构 (1.0 基线)

```
rustnmap/
├── Cargo.toml                 # Workspace 配置
├── README.md
├── LICENSE
├── .gitignore
│
├── crates/
│   ├── rustnmap-cli/          # 命令行入口
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── args.rs        # CLI 参数解析
│   │       └── output.rs      # 终端输出处理
│   │
│   ├── rustnmap-core/         # 核心扫描引擎
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── scan/
│   │       │   ├── mod.rs
│   │       │   ├── orchestrator.rs
│   │       │   ├── scheduler.rs
│   │       │   └── executor.rs
│   │       ├── discovery/
│   │       │   ├── mod.rs
│   │       │   ├── arp.rs
│   │       │   ├── icmp.rs
│   │       │   └── tcp.rs
│   │       ├── portscan/
│   │       │   ├── mod.rs
│   │       │   ├── tcp_syn.rs
│   │       │   ├── tcp_connect.rs
│   │       │   ├── tcp_stealth.rs
│   │       │   └── udp.rs
│   │       ├── service/
│   │       │   ├── mod.rs
│   │       │   ├── probe.rs
│   │       │   └── matcher.rs
│   │       ├── os/
│   │       │   ├── mod.rs
│   │       │   ├── fingerprint.rs
│   │       │   └── matcher.rs
│   │       └── result.rs
│   │
│   ├── rustnmap-nse/          # NSE 脚本引擎
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine/
│   │       │   ├── mod.rs
│   │       │   ├── lua_bridge.rs
│   │       │   ├── scheduler.rs
│   │       │   └── sandbox.rs
│   │       ├── libs/
│   │       │   ├── mod.rs
│   │       │   ├── nmap.rs
│   │       │   ├── stdnse.rs
│   │       │   ├── http.rs
│   │       │   ├── ssl.rs
│   │       │   ├── ssh.rs
│   │       │   ├── smb.rs
│   │       │   └── ... (其他协议库)
│   │       └── parser/
│   │           ├── mod.rs
│   │           └── script_parser.rs
│   │
│   ├── rustnmap-net/          # 网络层
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── socket/
│   │       │   ├── mod.rs
│   │       │   ├── raw_socket.rs
│   │       │   ├── tcp.rs
│   │       │   └── udp.rs
│   │       ├── packet/
│   │       │   ├── mod.rs
│   │       │   ├── builder.rs
│   │       │   ├── parser.rs
│   │       │   ├── ethernet.rs
│   │       │   ├── ip.rs
│   │       │   ├── tcp.rs
│   │       │   ├── udp.rs
│   │       │   └── icmp.rs
│   │       └── interface.rs
│   │
│   ├── rustnmap-db/           # 数据库
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── service_probes.rs
│   │       ├── os_fingerprints.rs
│   │       ├── mac_prefixes.rs
│   │       └── loader.rs
│   │
│   ├── rustnmap-output/       # 输出格式化
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── normal.rs
│   │       ├── xml.rs
│   │       ├── json.rs
│   │       ├── grepable.rs
│   │       └── html.rs
│   │
│   └── rustnmap-common/       # 公共类型
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── types.rs
│           ├── error.rs
│           └── utils.rs
│
├── scripts/                   # NSE 脚本库
│   ├── auth/
│   ├── broadcast/
│   ├── brute/
│   ├── default/
│   ├── discovery/
│   ├── exploit/
│   ├── safe/
│   ├── vuln/
│   └── script.db
│
├── data/                      # 数据库文件
│   ├── service-probes
│   ├── os-fingerprints
│   ├── mac-prefixes
│   ├── rpc-procedures
│   └── payloads
│
└── tests/                     # 集成测试
    ├── integration/
    ├── e2e/
    └── fixtures/
```

## 5.2 依赖关系图

### 5.2.1 1.0 基线依赖图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Dependency Graph                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│     ┌──────────────┐                                               │
│     │ rustnmap-cli │                                               │
│     └──────┬───────┘                                               │
│            │ uses                                                   │
│            ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              rustnmap-core (扫描编排)                        │   │
│  └───────┬─────────────────┬──────────────────┬────────────────┘   │
│          │ uses             │ uses             │ uses                │
│          ▼                  ▼                  ▼                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐          │
│  │ rustnmap-nse  │  │ rustnmap-net  │  │ rustnmap-db   │          │
│  │ (脚本引擎)    │  │ (网络层)      │  │ (数据库)      │          │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘          │
│          │                  │                  │                    │
│          └──────────────────┼──────────────────┘                    │
│                             │ uses                                  │
│                             ▼                                       │
│                    ┌─────────────────┐                             │
│                    │ rustnmap-common │                             │
│                    │ (公共类型)      │                             │
│                    └────────┬────────┘                             │
│                             │ uses                                  │
│                             ▼                                       │
│                    ┌─────────────────┐                             │
│                    │ rustnmap-output │                             │
│                    │ (输出格式化)    │                             │
│                    └─────────────────┘                             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  External Crates (关键依赖):                                        │
│  ─────────────────────────                                           │
│  ├── tokio (异步运行时)                                             │
│  ├── mlua (Lua 绑定)                                                │
│  ├── pnet (数据包处理)                                              │
│  ├── clap (CLI 解析)                                                │
│  ├── serde/serde_json (序列化)                                      │
│  ├── regex (正则匹配)                                               │
│  ├── trust-dns (DNS 解析)                                           │
│  ├── rustls (TLS/SSL)                                               │
│  └── chrono (时间处理)                                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2.2 2.0 新增依赖关系

```
┌─────────────────────────────────────────────────────────────────────┐
│                    RustNmap 2.0 New Dependencies                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │              rustnmap-sdk (2.0 NEW)                      │    │
│     │         (稳定高层 Builder API for Rust)                  │    │
│     └────────────────────┬────────────────────────────────────┘    │
│                          │ uses                                     │
│                          ▼                                          │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │              rustnmap-api (2.0 NEW)                      │    │
│     │         (REST API / Daemon Mode with axum)               │    │
│     │   POST /api/v1/scans, GET /api/v1/scans/{id}/stream     │    │
│     └────────────────────┬────────────────────────────────────┘    │
│                          │ uses                                     │
│          ┌───────────────┼───────────────┐                         │
│          │               │               │                         │
│          ▼               ▼               ▼                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │
│  │rustnmap-core │ │rustnmap-vuln │ │rustnmap-output│              │
│  │ (编排器)     │ │ (2.0 NEW)    │ │ (扩展)        │              │
│  └──────────────┘ └──────┬───────┘ └──────────────┘              │
│                          │                                         │
│                          │ uses                                    │
│                          ▼                                         │
│                 ┌─────────────────┐                               │
│                 │  rusqlite       │                               │
│                 │  (SQLite ORM)   │                               │
│                 └─────────────────┘                               │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  2.0 External Crates (新增依赖):                                    │
│  ────────────────────────────                                        │
│  ├── axum (REST API Web 框架)                                       │
│  ├── tower (中间件支持)                                             │
│  ├── rusqlite (SQLite 数据库)                                       │
│  ├── reqwest (NVD API HTTP 客户端)                                  │
│  └── bincode (状态序列化，用于暂停/恢复)                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2.3 完整依赖链 (1.0 + 2.0)

```
rustnmap-cli ──> rustnmap-core ──> rustnmap-scan
                              │
                              ├──> rustnmap-nse
                              │
                              ├──> rustnmap-fingerprint
                              │
                              ├──> rustnmap-traceroute
                              │
                              └──> rustnmap-evasion

rustnmap-sdk (2.0) ──> rustnmap-api (2.0) ──> rustnmap-core
                                          │
                                          └──> rustnmap-vuln (2.0)
                                                   │
                                                   └──> rustnmap-output (extended)
```

