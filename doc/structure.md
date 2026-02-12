# 5. 项目结构与模块划分

## 5.1 Cargo Workspace 结构

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

---

