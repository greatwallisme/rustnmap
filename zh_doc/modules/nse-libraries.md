# NSE 协议库 - 技术设计

> **版本**: 1.1.0
> **目标**: Nmap 7.95
> **状态**: 阶段 11 完成 - 所有协议库已实现
> **最后更新**: 2026-03-17

## 完成状态

| 阶段 | 库 | 状态 |
|------|-----|------|
| **阶段 11.1** | http, ssh2, sslcert, dns | 已完成 |
| **阶段 11.2** | smb, netbios, smbauth, unicode, unpwdb, ftp | 已完成 |
| **阶段 11.3** | openssl, json, creds, url | 已完成 |
| **工具** | brute | 已完成 |

---

## 概述

本文档规定 NSE 协议库的技术设计。这些库向 Lua 脚本暴露协议特定功能，实现高级网络发现和漏洞检测。

**本设计基于对 Nmap 实际 NSE 库实现的分析**，源码位于 `reference/nmap/nselib/`。

## 设计原则

1. **Nmap 兼容性**：所有 API 必须完全匹配 Nmap 的 NSE 库行为
2. **错误处理**：失败时返回 `nil, error_message`（Lua 惯例）
3. **响应格式**：完全匹配 Nmap 的响应表结构
4. **资源管理**：正确清理套接字、连接和内存
5. **异步等待**：所有网络操作使用 Tokio
6. **mlua 集成**：Lua 5.4 绑定使用 mlua 0.9+

---

## 1. HTTP 库 (`http`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/http.rs
```

### 响应表结构

Nmap 的 HTTP 库返回包含以下字段的表：

```lua
{
    -- 状态信息
    ["status-line"] = "HTTP/1.1 200 OK\r\n",
    status = 200,
    version = "1.1",

    -- 头部（小写键名）
    header = {
        ["content-type"] = "text/html",
        ["content-length"] = "1234",
        ["server"] = "Apache",
    },

    -- 原始头部（编号数组）
    rawheader = {
        "Content-Type: text/html",
        "Content-Length: 1234",
        "Server: Apache",
    },

    -- Cookie
    cookies = {
        {name = "sessionid", value = "abc123", path = "/", domain = "example.com"},
    },

    -- 正文
    rawbody = "<html>...</html>",      -- Content-Encoding 处理前
    body = "<html>...</html>",         -- Content-Encoding 处理后

    -- 编码跟踪
    decoded = {"gzip"},                 -- 成功处理的编码
    undecoded = {},                     -- 失败或不支持的编码

    -- 重定向
    location = {"http://example.com/redirected"},

    -- 错误状态
    incomplete = nil,                    -- 错误时的部分响应
    truncated = false,                   -- 正文因大小限制被截断
}
```

### 主要函数

#### `http.get(host, port, path, options)`

```lua
-- 基本 GET 请求
local response = http.get(host, port, "/")

-- 带选项
local response = http.get(host, port, "/path", {
    timeout = 10000,                    -- 毫秒
    header = {
        ["User-Agent"] = "Custom",
        ["Authorization"] = "Bearer xyz",
    },
    cookies = {
        {name = "session", value = "abc123"},
    },
    auth = {username = "user", password = "pass"},
    redirect_ok = false,                 -- 不跟随重定向
    bypass_cache = true,
    no_cache = true,
    scheme = "https",                    -- 强制 HTTPS
})

-- 访问响应
if response and response.status == 200 then
    print(response.body)
    print(response.header["content-type"])
end
```

#### `http.post(host, port, path, options, ignored, postdata)`

```lua
-- 表单 POST（表内容变为 form-encoded）
local response = http.post(host, port, "/login", nil, nil, {
    username = "admin",
    password = "secret",
})

-- JSON POST（字符串内容）
local response = http.post(host, port, "/api", {
    header = {["Content-Type"] = "application/json"}
}, nil, '{"json": "data"}')

-- 原始二进制 POST
local response = http.post(host, port, "/upload", {
    header = {["Content-Type"] = "application/octet-stream"}
}, nil, binary_data)
```

#### `http.head(host, port, path, options)`

```lua
local response = http.head(host, port, "/path")
-- 相同的响应结构，但 body 为空/nil
```

#### `http.generic_request(host, port, method, path, options)`

```lua
-- 任意 HTTP 方法的通用接口
local response = http.generic_request(host, port, "PUT", "/resource", {
    header = {["Content-Type"] = "application/json"}
}, nil, '{"data": "value"}')

local response = http.generic_request(host, port, "DELETE", "/resource/123")
local response = http.generic_request(host, port, "OPTIONS", "*")
```

#### `http.get_url(url, options)`

```lua
-- 解析 URL 并获取
local response = http.get_url("https://example.com:8080/api/v1?key=value", {
    timeout = 10000,
})

-- URL 自动解析为 host、port、path、query
```

#### `http.pipeline_add(path, options, all_requests, method)`

```lua
-- 构建管道
local all = nil
all = http.pipeline_add("/path1", nil, all)
all = http.pipeline_add("/path2", nil, all)
all = http.pipeline_add("/path3", {header = {["X-Custom"] = "value"}}, all, "HEAD")

-- 执行管道
local results = http.pipeline_go(host, port, all)
-- results 是响应表的数组
```

#### `http.pipeline_go(host, port, all_requests)`

```lua
-- 执行排队的请求
local results = http.pipeline_go(host, port, all_requests)
for i, response in ipairs(results) do
    print(response.status)
end
```

### 选项表参考

```lua
local options = {
    -- 套接字超时
    timeout = 30000,

    -- 附加头部
    header = {["X-Custom"] = "value"},

    -- 请求正文（字符串或表，表会 form-encoded）
    content = "raw data",
    -- 或
    content = {key1 = "value1", key2 = "value2"},

    -- Cookie
    cookies = {
        {name = "session", value = "abc123", path = "/"},
        -- 或仅字符串
        "session=abc123; Path=/",
    },

    -- 认证
    auth = {username = "user", password = "pass", digest = true},
    -- 或
    digestauth = {
        username = "user",
        password = "pass",
        realm = "Protected Area",
        nonce = "abc123",
        ["digest-uri"] = "/path",
        response = "calculated_hash",
    },

    -- 缓存控制
    bypass_cache = true,
    no_cache = true,
    no_cache_body = true,

    -- 重定向控制
    redirect_ok = function(url) return true end,
    -- 或
    redirect_ok = 3,  -- 最多 3 次重定向

    -- 正文大小限制
    max_body_size = 1024 * 1024,  -- 1MB
    truncated_ok = true,

    -- 协议方案
    scheme = "https",

    -- 地址族
    any_af = true,
}
```

### 实现说明

1. **SSL/TLS 检测**：使用 `comm.tryssl()` 判断是否需要 SSL
2. **重定向处理**：跟随 301、302、303、307、308 并验证
3. **分块传输编码**：处理 `Transfer-Encoding: chunked`
4. **压缩**：支持 gzip、deflate 解码
5. **连接复用**：为管道化池化连接
6. **Cookie 处理**：解析 Set-Cookie 头，支持 Cookie 头
7. **认证**：支持 Basic 和 Digest 认证
8. **缓存**：实现内存响应缓存

### 依赖

```toml
[dependencies]
reqwest = { version = "0.12", features = ["cookies", "gzip", "brotli"] }
hyper = "1.0"
native-tls = "0.2"
url = "2.5"
```

---

## 2. SSH2 库 (`ssh2`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/ssh2.rs
```

### 主要函数

#### `ssh2.fetch_host_key(host, port, key_type)`

```lua
-- 获取 SSH 主机密钥指纹
-- key_type（可选）："ssh-rsa"、"ssh-dss"、"ecdsa-sha2-nistp256"、
--                   "ecdsa-sha2-nistp384"、"ecdsa-sha2-nistp521"、"ssh-ed25519"
local key = ssh2.fetch_host_key(host, port, "ssh-rsa")

-- 返回包含以下字段的表（需要 Nmap 兼容性）：
-- key.key: Base64 编码的公钥
-- key.key_type: "ssh-rsa"、"ssh-ed25519"、"ecdsa-sha2-nistp256" 等
-- key.fp_input: 原始公钥字节（用于指纹计算）
-- key.bits: 2048、256、384、521 等（密钥位数）
-- key.full_key: "ssh-rsa AAAAB3NzaC1yc2E..."（key_type + 空格 + base64 密钥）
-- key.algorithm: "RSA"、"DSA"、"ECDSA"、"ED25519"
-- key.fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"（MD5 hex）
-- key.fp_sha256: Base64 编码的 SHA256 指纹
```

#### `ssh2.banner(host, port)`

```lua
-- 获取 SSH 横幅字符串
local banner = ssh2.banner(host, port)
-- 返回: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
```

### 实现说明

1. **协议**：仅支持 SSH-2（SSH-1.x 已弃用且不安全）
2. **密钥类型**：支持 RSA、DSA、ECDSA（nistp256、nistp384、nistp521）、ED25519
3. **指纹**：同时支持 MD5（旧版）和 SHA256 格式
4. **超时**：默认 10 秒
5. **无需加密**：密钥交换在加密开始前以明文进行
6. **Diffie-Hellman 组**：支持 group1（1024 位）、group14（2048 位）、group16（4096 位）和 group-exchange（可变长度）

### SSH 密钥交换协议

本节描述 `libssh2_utility.rs` 支持认证方法枚举所需的完整 SSH-2 密钥交换实现。

#### 协议概述

SSH-2 密钥交换遵循 RFC 4253 第 8 节：

```
客户端                                    服务器
------                                    ------
  |                                         |
  |-------- SSH-2.0 客户端横幅 ---------->|
  |<-------- SSH-2.0 服务器横幅 -----------|
  |                                         |
  |-------- KEXINIT ---------------------->|
  |<-------- KEXINIT -----------------------|
  |                                         |
  |-------- KEXDH_INIT ------------------->|
  |<-------- KEXDH_REPLY ------------------|
  |                                         |
  |-------- NEWKEYS ---------------------->|
  |<-------- NEWKEYS -----------------------|
  |                                         |
  |-------- SERVICE_REQUEST (ssh-userauth)>|
  |<-------- SERVICE_ACCEPT ----------------|
  |                                         |
  |-------- USERAUTH_REQUEST (none) ------>|
  |<-------- USERAUTH_FAILURE -------------|
  | (返回可用的认证方法)                    |
```

#### 消息类型

```rust
// SSH 传输层协议消息类型
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEXDH_INIT: u8 = 30;
const SSH_MSG_KEXDH_REPLY: u8 = 31;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
```

#### KEXINIT 消息格式

```rust
struct KexInit {
    // 消息类型 (SSH_MSG_KEXINIT = 20)
    message_type: u8,
    // Cookie（16 字节随机数）
    cookie: [u8; 16],
    // 密钥交换算法（逗号分隔）
    kex_algorithms: String,  // "diffie-hellman-group14-sha256,..."
    // 服务器主机密钥算法
    server_host_key_algorithms: String,  // "ssh-rsa,ssh-ed25519,..."
    // 加密算法（客户端→服务器，服务器→客户端）
    encryption_algorithms_client_to_server: String,
    encryption_algorithms_server_to_client: String,
    // MAC 算法
    mac_algorithms_client_to_server: String,
    mac_algorithms_server_to_client: String,
    // 压缩算法
    compression_algorithms_client_to_server: String,
    compression_algorithms_server_to_client: String,
    // 语言
    languages_client_to_server: String,
    languages_server_to_client: String,
    // 第一个密钥交换包是否跟随
    first_kex_packet_follows: bool,
    // 保留（4 字节）
    reserved: u32,
}
```

#### KEXDH_INIT 消息（RFC 4253 第 8 节）

```rust
// 客户端发送 DH 公钥 (e)
struct KexDhInit {
    message_type: u8,  // SSH_MSG_KEXDH_INIT = 30
    e: Mpint,          // 客户端的 DH 公钥 (g^x mod p)
}
```

#### KEXDH_REPLY 消息（RFC 4253 第 8 节）

```rust
// 服务器响应主机密钥、DH 公钥和签名
struct KexDhReply {
    message_type: u8,          // SSH_MSG_KEXDH_REPLY = 31
    host_key: Bytes,           // 服务器公钥 (K_S)
    f: Mpint,                  // 服务器的 DH 公钥 (g^y mod p)
    signature_hash: Bytes,     // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
}
```

#### NEWKEYS 消息

```rust
// 双方发送以激活新密钥
struct NewKeys {
    message_type: u8,  // SSH_MSG_NEWKEYS = 21
}
```

#### Diffie-Hellman Group14 参数（RFC 3526）

```rust
// 2048 位 MODP 群
const DH_GROUP14_PRIME: &str = "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
";

const DH_GROUP14_GENERATOR: u32 = 2;
```

#### 密钥交换计算

```rust
// 客户端生成 x（随机数）并计算 e = g^x mod p
// 服务器生成 y（随机数）并计算 f = g^y mod p
// 共享密钥：K = f^x mod p = e^y mod p = g^(xy) mod p

use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;

fn generate_dh_key_pair() -> (BigUint, BigUint) {
    let p = BigUint::parse_bytes(DH_GROUP14_PRIME.as_bytes(), 16).unwrap();
    let g = BigUint::from(DH_GROUP14_GENERATOR);

    // 生成私钥 x (1 < x < p-1)
    let mut rng = rand::thread_rng();
    let p_minus_1 = &p - BigUint::one();
    let x = rng.gen_biguint_range(&BigUint::one(), &p_minus_1);

    // 计算公钥 e = g^x mod p
    let e = g.modpow(&x, &p);

    (e, x)  // 返回 (公钥, 私钥)
}

fn compute_shared_secret(f: &BigUint, x: &BigUint) -> BigUint {
    let p = BigUint::parse_bytes(DH_GROUP14_PRIME.as_bytes(), 16).unwrap();
    f.modpow(x, &p)  // K = f^x mod p
}
```

#### 交换哈希计算

交换哈希 H 的计算方式为：

```
H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
```

其中：
- `V_C`：客户端 SSH 版本字符串（如 "SSH-2.0-rustnmap_1.0"）
- `V_S`：服务器 SSH 版本字符串
- `I_C`：客户端 KEXINIT 载荷
- `I_S`：服务器 KEXINIT 载荷
- `K_S`：服务器公钥
- `e`：客户端 DH 公钥
- `f`：服务器 DH 公钥
- `K`：共享密钥

```rust
use sha2::{Sha256, Digest};
use encoding::Binary;

fn compute_exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e: &BigUint,
    f: &BigUint,
    k: &BigUint,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // 按顺序拼接所有组件
    hasher.update(u32::to_be_bytes(v_c.len() as u32));
    hasher.update(v_c);

    hasher.update(u32::to_be_bytes(v_s.len() as u32));
    hasher.update(v_s);

    hasher.update(u32::to_be_bytes(i_c.len() as u32));
    hasher.update(i_c);

    hasher.update(u32::to_be_bytes(i_s.len() as u32));
    hasher.update(i_s);

    hasher.update(u32::to_be_bytes(k_s.len() as u32));
    hasher.update(k_s);

    let e_bytes = e.to_bytes_be();
    hasher.update(u32::to_be_bytes(e_bytes.len() as u32));
    hasher.update(&e_bytes);

    let f_bytes = f.to_bytes_be();
    hasher.update(u32::to_be_bytes(f_bytes.len() as u32));
    hasher.update(&f_bytes);

    let k_bytes = k.to_bytes_be();
    hasher.update(u32::to_be_bytes(k_bytes.len() as u32));
    hasher.update(&k_bytes);

    hasher.finalize().to_vec()
}
```

#### 密钥派生

从交换哈希 H 和共享密钥 K 派生：

```rust
// 初始 IV（客户端→服务器，服务器→客户端）
// 加密密钥（客户端→服务器，服务器→客户端）
// MAC 密钥（客户端→服务器，服务器→客户端）

fn derive_keys(k: &[u8], h: &[u8], key_length: usize, iv_length: usize) -> Vec<[u8; 32]> {
    // K = hash(K || H || X || session_id) 用于不同的 X 值
    // 此为简化版 - 完整实现使用多轮
    todo!("完整密钥派生实现")
}
```

#### 实现位置

SSH 密钥交换实现在：
```rust
// crates/rustnmap-nse/src/libs/libssh2_utility.rs

pub struct SSHConnection {
    state: ConnectionState,
    authenticated: bool,
}

impl SSHConnection {
    // 阶段 1：KEXINIT 交换（已实现）
    fn connect(&mut self, host: &str, port: u16) -> mlua::Result<String>;

    // 阶段 2：DH 密钥交换（待实现）
    fn perform_key_exchange(&mut self) -> mlua::Result<()>;

    // 阶段 3：服务请求（已实现）
    fn send_service_request(&mut self) -> mlua::Result<()>;
}
```

#### 所需函数

```rust
// 构建 KEXDH_INIT 包
fn build_kexdh_init(e: &BigUint) -> Vec<u8>;

// 解析 KEXDH_REPLY 响应
fn parse_kexdh_reply(data: &[u8]) -> mlua::Result<(Vec<u8>, BigUint, Vec<u8>)>;

// 构建 NEWKEYS 包
fn build_newkeys() -> Vec<u8>;

// 完整密钥交换序列
fn perform_key_exchange(stream: &mut TcpStream) -> mlua::Result<KeyExchangeResult>;
```

#### 安全注意事项

1. **恒定时间操作**：DH 计算应使用恒定时间密码学
2. **随机数生成**：使用 `rand::thread_rng()` 生成 x
3. **密钥验证**：验证服务器主机密钥签名
4. **防止降级攻击**：验证接收的参数与 KEXINIT 提议匹配
5. **Group14 最低要求**：要求至少 2048 位 MODP 群（RFC 8270）

#### 依赖

```toml
[dependencies]
# 密码学原语
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"

# 编码
base64 = "0.22"
hex = "0.4"

# Diffie-Hellman 大整数运算
num-bigint = "0.4"
num-traits = "0.2"

# 随机数生成
rand = "0.8"

# 替代方案：完整 SSH 库（不推荐，可能存在兼容性问题）
# russh = "0.44" 实现完整 SSH 协议，但可能与期望特定 Nmap 行为的 NSE 脚本不兼容
```

#### SSH 密钥交换专用依赖

```toml
# 用于大整数 DH 计算
num-bigint = { version = "0.4", features = ["rand"] }

# 用于 SHA256/SHA512 哈希
sha2 = "0.10"

# 用于 MPINT 序列化
[dev-dependencies]
hex-literal = "0.4"
```

---

## 3. SSL 证书库 (`sslcert`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/sslcert.rs
```

### 主要函数

#### `sslcert.getCertificate(host, port)`

```lua
-- 获取 SSL/TLS 证书
local cert = sslcert.getCertificate(host, port)
-- 返回包含以下字段的表：
-- cert.pem: PEM 编码的证书
-- cert.subject: "CN=example.com, O=Example Inc"
-- cert.issuer: "CN=Let's Encrypt Authority X3"
-- cert.serial: 十六进制序列号字符串
-- cert.fingerprint: SHA256 指纹
-- cert.pubkey: {
--   type: "rsa",
--   bits: 2048,
-- }
-- cert.modulus: RSA 模数（十六进制字符串）
-- cert.exponent: RSA 指数（十六进制字符串）
-- cert.notbefore: 证书有效期开始
-- cert.notafter: 证书有效期结束
-- cert.version: 3
```

#### `sslcert.parse_ssl_certificate(der_data)`

```lua
-- 解析 DER 编码的证书
local cert = sslcert.parse_ssl_certificate(der_string)
-- 返回与 getCertificate 相同的表结构
```

### STARTTLS 支持

该库支持多种协议的 STARTTLS：

```lua
-- FTP（端口 21）
local cert = sslcert.getCertificate(host, port, {protocol = "ftp"})

-- SMTP（端口 25、587）
local cert = sslcert.getCertificate(host, port, {protocol = "smtp"})

-- IMAP（端口 143）
local cert = sslcert.getCertificate(host, port, {protocol = "imap"})

-- POP3（端口 110）
local cert = sslcert.getCertificate(host, port, {protocol = "pop3"})

-- LDAP（端口 389）
local cert = sslcert.getCertificate(host, port, {protocol = "ldap"})

-- MySQL（端口 3306）
local cert = sslcert.getCertificate(host, port, {protocol = "mysql"})

-- PostgreSQL（端口 5432）
local cert = sslcert.getCertificate(host, port, {protocol = "postgresql"})

-- NNTP（端口 119）
local cert = sslcert.getCertificate(host, port, {protocol = "nntp"})

-- TDS/MS SQL Server（端口 1433）
-- 注意：TDS 使用包装握手，可能不支持完整 SSL 重连
local cert = sslcert.getCertificate(host, port, {protocol = "tds"})

-- VNC/VeNCrypt（端口 5900）
local cert = sslcert.getCertificate(host, port, {protocol = "vnc"})

-- XMPP（端口 5222、5269）
local cert = sslcert.getCertificate(host, port, {protocol = "xmpp"})
```

### 支持的 STARTTLS 协议

| 协议 | 默认端口 | 备注 |
|------|----------|------|
| ftp | 21 | AUTH TLS 命令 |
| smtp | 25, 587 | STARTTLS 命令 |
| imap | 143 | CAPABILITY 后 STARTTLS |
| pop3 | 110 | STLS 命令 |
| ldap | 389 | 扩展请求 OID 1.3.6.1.4.1.1466.20037 |
| mysql | 3306 | 握手期间 SSL 切换 |
| postgresql | 5432 | SSLRequest 消息 80877103 |
| nntp | 119 | STARTTLS 命令 |
| tds | 1433 | PreLogin 包加密（包装） |
| vnc | 5900 | VeNCrypt 认证子类型 |
| xmpp | 5222, 5269 | XMPP TLS proceed |

### 实现说明

1. **TLS 版本**：支持 TLS 1.2 和 1.3，禁用 SSL 3.0、TLS 1.0、1.1
2. **SNI**：HTTPS 时始终发送 Server Name Indication
3. **证书解析**：使用 `x509-parser` crate
4. **密码枚举**：支持 `sslcert.cipher_preference()` 和 `sslcert.explore_cipher_suites()`
5. **超时**：默认 10 秒

### 依赖

```toml
[dependencies]
rustls = "0.23"
rustls-pemfile = "2.0"
x509-parser = "0.16"
webpki-roots = "0.26"
```

---

## 4. DNS 库 (`dns`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/dns.rs
```

### 常量

```lua
-- 记录类型常量
dns.TYPE_A = 1
dns.TYPE_NS = 2
dns.TYPE_CNAME = 5
dns.TYPE_SOA = 6
dns.TYPE_PTR = 12
dns.TYPE_MX = 15
dns.TYPE_TXT = 16
dns.TYPE_AAAA = 28
dns.TYPE_SRV = 33
dns.TYPE_ANY = 255
```

### 主要函数

#### `dns.query(domain, options)`

```lua
-- 基本 A 记录查询
local records = dns.query("example.com", {dtype = dns.TYPE_A})

-- 带选项查询
local records = dns.query("example.com", {
    dtype = dns.TYPE_MX,
    host = "8.8.8.8",      -- 使用指定 DNS 服务器
    port = 53,
    timeout = 5000,
    retAll = true,           -- 返回所有记录
    sendCount = 3,           -- 重试次数
})

-- 响应结构
for i, record in ipairs(records) do
    -- record.name: 域名
    -- record.type: 记录类型编号
    -- record.data: 记录数据（IP、文本等）
    -- record.ttl: 生存时间
end
```

#### `dns.reverse(ip)`

```lua
-- 反向 DNS 查询
local hostname = dns.reverse("8.8.8.8")
-- 返回: "dns.google" 或未找到时返回 nil
```

### 实现说明

1. **协议**：DNS-over-UDP，大响应时回退到 TCP
2. **EDNS0**：支持 OPT 伪记录以获取更大响应
3. **超时**：默认 5 秒
4. **重试**：默认 3 次尝试
5. **DNSSEC**：可用时验证 RRSIG

### 依赖

```toml
[dependencies]
trust-dns-client = "0.23"
trust-dns-proto = "0.23"
```

---

## 5. SMB 库 (`smb`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/smb.rs
```

### 主要函数

#### `smb.list_shares(host, port)`

```lua
-- 枚举 SMB 共享
local shares, err = smb.list_shares(host, port)
-- 返回共享表数组，包含：
-- share.name: 共享名（如 "C$"、"IPC$"）
-- share.comment: 共享描述
-- share.type: 共享类型（DISK、IPC、PRINTER）
```

#### `smb.connect(host, port, options)`

```lua
-- 建立 SMB 连接
local conn, err = smb.connect(host, port, {
    username = "user",
    password = "pass",
    domain = "WORKGROUP"
})
```

### 实现说明

1. **协议**：支持 SMB 1.0/2.0/3.0
2. **超时**：默认 10 秒
3. **依赖**：使用自定义 SMB 协议实现

### 依赖

```toml
[dependencies]
# 自定义 SMB 协议实现
md-5 = "0.10"
sha2 = "0.10"
```

---

## 6. NetBIOS 库 (`netbios`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/netbios.rs
```

### 主要函数

#### `netbios.get_name(host, port)`

```lua
-- 获取 NetBIOS 名称
local name, err = netbios.get_name(host, port)
-- 返回 NetBIOS 名称和工作站组
```

### 实现说明

1. **协议**：NetBIOS over TCP/IP
2. **超时**：默认 5 秒

---

## 7. SMBAuth 库 (`smbauth`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/smbauth.rs
```

### 主要函数

#### `smbauth.password_hash(password)`

```lua
-- 计算密码的 NTLM 哈希
local hash = smbauth.password_hash("password")
-- 返回用于认证的 NTLM 哈希
```

---

## 8. Unicode 库 (`unicode`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/unicode.rs
```

### 主要函数

#### `unicode.utf8_to_utf16(str)`

```lua
-- 将 UTF-8 字符串转换为 UTF-16LE（用于 SMB）
local utf16 = unicode.utf8_to_utf16("test")
-- 返回 UTF-16LE 编码的字节
```

---

## 9. UNPWDB 库 (`unpwdb`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/unpwdb.rs
```

### 主要函数

#### `unpwdb.usernames()`

```lua
-- 获取用户名迭代器
local usernames = unpwdb.usernames()
for username in usernames do
    -- 遍历常见用户名
end
```

#### `unpwdb.passwords()`

```lua
-- 获取密码迭代器
local passwords = unpwdb.passwords()
for password in passwords do
    -- 遍历常见密码
end
```

### 实现说明

1. **内置数据库**：来自 Nmap 的常见用户名和密码
2. **自定义文件**：支持外部字典文件

---

## 10. FTP 库 (`ftp`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/ftp.rs
```

### 主要函数

#### `ftp.connect(host, port, options)`

```lua
-- 连接 FTP 服务器
local conn, err = ftp.connect(host, port, {
    timeout = 10000,
    username = "anonymous",
    password = "anonymous@"
})
```

#### `ftp.list(conn, path)`

```lua
-- 列出目录内容
local files, err = ftp.list(conn, "/")
-- 返回文件表数组
```

---

## 11. OpenSSL 库 (`openssl`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/openssl.rs
```

### 主要函数

#### `openssl.bignum_hex_to_dec(hex)`

```lua
-- 将十六进制 BIGNUM 转换为十进制
local dec = openssl.bignum_hex_to_dec("A1B2C3")
-- 返回十进制字符串表示
```

#### `openssl.md5(data)`

```lua
-- 计算 MD5 哈希
local hash = openssl.md5("data")
-- 返回 MD5 摘要的十六进制字符串
```

#### `openssl.sha1(data)`

```lua
-- 计算 SHA1 哈希
local hash = openssl.sha1("data")
-- 返回 SHA1 摘要的十六进制字符串
```

### 实现说明

1. **用途**：NSE 脚本的底层密码学操作
2. **依赖**：使用 Rust 密码学原语

---

## 12. JSON 库 (`json`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/json.rs
```

### 主要函数

#### `json.encode(table)`

```lua
-- 将 Lua 表编码为 JSON 字符串
local json_str = json.encode({name = "John", age = 30})
-- 返回 '{"name":"John","age":30}'
```

#### `json.decode(json_string)`

```lua
-- 将 JSON 字符串解码为 Lua 表
local table = json.decode('{"name":"John","age":30}')
-- 返回 {name = "John", age = 30}
```

### 实现说明

1. **格式**：兼容 JSON 规范（RFC 8259）
2. **类型**：支持 null、boolean、number、string、array、object
3. **依赖**：使用 `serde_json` 进行解析

### 依赖

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

---

## 13. 凭据库 (`creds`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/creds.rs
```

### 主要函数

#### `creds.Credentials:new()`

```lua
-- 创建新的凭据对象
local c = creds.Credentials:new()
c.username = "admin"
c.password = "secret"
c.state = creds.STATE.VALID
```

#### `creds.Credentials:to_table()`

```lua
-- 将凭据转换为表
local t = c:to_table()
-- 返回 {username = "...", password = "...", state = "VALID"}
```

### 实现说明

1. **用途**：NSE 脚本的标准化凭据表示
2. **状态**：NEW、VALID、INVALID

---

## 14. URL 库 (`url`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/url.rs
```

### 主要函数

#### `url.escape(str)`

```lua
-- URL 编码字符串
local encoded = url.escape("hello world")
-- 返回 "hello%20world"
```

#### `url.unescape(str)`

```lua
-- URL 解码字符串
local decoded = url.unescape("hello%20world")
-- 返回 "hello world"
```

#### `url.parse(url, default)`

```lua
-- 将 URL 解析为各组件
local parsed = url.parse("https://example.com:8080/path?q=value#frag")
-- 返回包含以下字段的表：
-- parsed.scheme: "https"
-- parsed.host: "example.com"
-- parsed.port: 8080
-- parsed.path: "/path"
-- parsed.query: "q=value"
-- parsed.fragment: "frag"
-- parsed.userinfo: nil
-- parsed.ascii_host: "example.com"（IDN 的 Punycode）
```

#### `url.build(parsed)`

```lua
-- 从组件表构建 URL
local url_str = url.build({
    scheme = "https",
    host = "example.com",
    port = 8080,
    path = "/api/v1",
    query = "key=value"
})
-- 返回 "https://example.com:8080/api/v1?key=value"
```

#### `url.absolute(base, relative)`

```lua
-- 从基 URL 和相对路径构建绝对 URL
local abs = url.absolute("https://example.com/api/", "../v2/resource")
-- 返回 "https://example.com/v2/resource"
```

#### `url.parse_path(path)`

```lua
-- 将路径解析为段
local segments = url.parse_path("/api/v1/resource")
-- 返回 {1 = "api", 2 = "v1", 3 = "resource", is_absolute = 1, is_directory = nil}
```

#### `url.build_path(segments, unsafe)`

```lua
-- 从段构建路径
local path = url.build_path({1 = "api", 2 = "v1", is_absolute = 1}, false)
-- 返回 "/api/v1"
```

#### `url.parse_query(query)`

```lua
-- 将查询字符串解析为表
local params = url.parse_query("name=John&age=30")
-- 返回 {name = "John", age = "30"}
-- 处理 HTML 实体：&amp;、&lt;、&gt;
```

#### `url.build_query(table)`

```lua
-- 从表构建查询字符串
local query = url.build_query({name = "John", age = "30"})
-- 返回 "name=John&age=30"
```

#### `url.get_default_port(scheme)`

```lua
-- 获取方案的默认端口
local port = url.get_default_port("https")
-- 返回 443
```

#### `url.get_default_scheme(port)`

```lua
-- 获取端口的默认方案
local scheme = url.get_default_scheme(443)
-- 返回 "https"
```

#### `url.ascii_hostname(host)`

```lua
-- 将主机名转换为 ASCII（IDN 使用 Punycode）
local ascii = url.ascii_hostname("müller.example.com")
-- 返回 "xn--mller-kva.example.com"
```

### 实现说明

1. **RFC 3986 合规**：完整的 URL 解析和组合，符合 RFC 3986
2. **IDNA 支持**：国际化域名的 Punycode 编码
3. **HTML 实体**：`parse_query` 中特殊处理 `&amp;`、`&lt;`、`&gt;`
4. **路径解析**：RFC 3986 第 5.2 节相对 URL 解析
5. **默认端口**：http (80)、https (443)

### 依赖

```toml
[dependencies]
punycode = "0.1"  # IDNA/Punycode 支持
```

### 测试覆盖

所有 URL 库函数都有全面的单元测试，包括：
- 百分号编码/解码
- URL 解析和构建
- 相对路径解析
- 查询字符串解析
- Nmap 兼容性测试

---

## 15. 暴力破解库 (`brute`)

### 模块文件

```rust
// crates/rustnmap-nse/src/libs/brute.rs
```

### 主要函数

#### `brute.new_emulator(options)`

```lua
-- 创建暴力破解迭代器
local engine = brute.new_emulator({
    username = "admin",
    passwords = unpwdb.passwords(),
    max_retries = 3,
    delay = 2  -- 尝试间隔秒数
})
```

### 实现说明

1. **用途**：标准化暴力破解攻击框架
2. **速率限制**：内置延迟以防止锁定

---

## 16. 通用模式

### 错误处理模式

```lua
-- NSE 风格：失败时返回 nil, error_message
local result, err = some_lib.function(host, port)
if not result then
    return nil, "Function failed: " .. err
end
-- 使用 result
```

### 响应表验证

```lua
-- 始终检查 status 字段
local response = http.get(host, port, "/")
if response and response.status then
    -- 成功
    if response.status >= 200 and response.status < 300 then
        print("Success: " .. response.body)
    else
        print("HTTP " .. response.status)
    end
else
    -- 错误
    local err = response and response["status-line"] or "Unknown error"
    print("Failed: " .. err)
end
```

### 主机/端口约定

```lua
-- 所有协议库遵循此模式：
-- host: 字符串（IP 地址或主机名）
-- port: 数字 或 表 {number = 80, protocol = "tcp"}

-- 数字端口
local result = lib.function(host, 80)

-- 表端口（来自 Nmap 服务检测）
local result = lib.function(host, {number = 443, protocol = "tcp"})
```

---

## 实现顺序

### 阶段 11.1：高优先级协议库 - 已完成

1. **阶段 11.1.1**：http 库 - 最高优先级，500+ 脚本依赖
2. **阶段 11.1.2**：sslcert 库 - HTTPS 支持所需
3. **阶段 11.1.3**：ssh2 库 - 安全扫描脚本
4. **阶段 11.1.4**：dns 库 - 侦察脚本

### 阶段 11.2：中优先级网络库 - 已完成

5. **阶段 11.2.1**：smb 库 - SMB/CIFS 协议，用于 Windows 网络扫描
6. **阶段 11.2.2**：netbios 库 - NetBIOS 名称服务
7. **阶段 11.2.3**：smbauth 库 - SMB 认证
8. **阶段 11.2.4**：unicode 库 - SMB 的 Unicode 字符串处理
9. **阶段 11.2.5**：unpwdb 库 - 用户名/密码数据库
10. **阶段 11.2.6**：ftp 库 - FTP 协议

### 阶段 11.3：工具和密码学库 - 已完成

11. **阶段 11.3.1**：openssl 库 - OpenSSL 密码学操作
12. **阶段 11.3.2**：json 库 - JSON 编解码
13. **阶段 11.3.3**：creds 库 - 凭据管理
14. **阶段 11.3.4**：url 库 - RFC 3986 URL 解析和组合

### 附加库

15. **brute 库** - 暴力破解密码框架

---

## 测试策略

### 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_status_line() {
        let response = parse_status_line("HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.version, "1.1");
    }

    #[tokio::test]
    async fn test_http_get() {
        // 使用模拟服务器的集成测试
    }
}
```

### NSE 脚本测试

```lua
-- tests/nse_libraries_test.lua
local http = require "http"
local stdnse = require "stdnse"

description = [[Test NSE protocol libraries]]
categories = {"test"}

action = function(host, port)
    -- 测试 HTTP
    local response = http.get(host, port, "/")
    if response and response.status == 200 then
        return "HTTP library working"
    end

    -- 测试 SSL
    local cert = sslcert.getCertificate(host, port)
    if cert and cert.pem then
        return "SSL library working"
    end

    return nil
end
```

---

## 参考资料

### Nmap NSE 库源码：`reference/nmap/nselib/`

- `http.lua` - HTTP 协议实现
- `ssh2.lua` - SSH-2 协议实现
- `sslcert.lua` - SSL 证书函数
- `dns.lua` - DNS 协议实现
- `smb.lua` - SMB/CIFS 协议
- `netbios.lua` - NetBIOS 协议
- `smbauth.lua` - SMB 认证
- `unicode.lua` - Unicode 字符串处理
- `unpwdb.lua` - 用户名/密码数据库
- `ftp.lua` - FTP 协议
- `openssl.lua` - OpenSSL 绑定
- `json.lua` - JSON 编解码
- `creds.lua` - 凭据管理
- `url.lua` - URL 解析和组合
- `brute.lua` - 暴力破解框架

### RFC 标准

- **HTTP**：RFC 2616（HTTP/1.1）、RFC 7230-7235（HTTP/1.1 更新）
- **SSH**：RFC 4253（SSH 协议）、RFC 4252（SSH 认证）
- **TLS**：RFC 5246（TLS 1.2）、RFC 8446（TLS 1.3）
- **DNS**：RFC 1035（DNS 协议）、RFC 3596（DNS AAAA）
- **SMB**：[MS-SMB2] 规范
- **JSON**：RFC 8259（JSON 规范）
- **URL**：RFC 3986（URI 通用语法）、RFC 5891（IDNA）
- **FTP**：RFC 959（FTP 协议）
- **NetBIOS**：RFC 1001/1002（NetBIOS over TCP/IP）
- RFC 8446：TLS 1.3
- RFC 1035：DNS 协议
