# NSE Module Technical Findings

> **Updated**: 2026-04-01 (Root Cause Analysis Complete)

---

## Root Cause Analysis (2026-04-01) - Systematic Debugging Phase 1

### Methodology
逐个运行失败脚本，抓取实际 Lua 错误信息（不再猜测）。

### Root Causes Found (按优先级排序)

---

#### RC-1: `stdnse.parse_timespec` 不接受 nil 参数 [HIGH - 影响 banner 等脚本]

**Error**:
```
bad argument #1: error converting Lua nil to String (expected string or number)
stack: stdnse.parse_timespec -> banner:70 -> grab_banner -> action
```

**Root Cause**: Rust 实现签名是 `|lua, timespec: String|`，要求非 nil。但 Nmap 原始实现是：
```lua
-- nselib/stdnse.lua:413
function parse_timespec(timespec)
  if timespec == nil then return nil, "Can't parse nil timespec" end
```
Nmap 脚本普遍在没传参数时传入 nil（如 `stdnse.parse_timespec(stdnse.get_script_args("banner.timeout"))`），期望返回 nil 而非崩溃。

**Fix**: 修改 `parse_timespec` 签名为 `Option<String>`，nil 时返回 `(nil, err_msg)`。
**Affected Scripts**: banner, 以及所有使用 `parse_timespec` 的脚本（122个文件引用）

**File**: `crates/rustnmap-nse/src/libs/stdnse.rs:675`

---

#### RC-2: `nmap.socket:receive_lines` 方法缺失 [HIGH - 影响 SMTP/IMAP 脚本]

**Error**:
```
attempt to call a nil value (method 'receive_lines')
stack: smtp.lua:268 -> smtp.query -> smtp.ehlo -> smtp-commands:91 -> action
```

**Root Cause**: `NseSocket` UserData 实现中没有 `receive_lines` 方法。虽然之前在 `nmap.rs` 中添加了 `receive_lines`，但那是加在 `nmap` 模块的 socket 模拟上，不是加在 `comm.rs` 的 `NseSocket` UserData 上。

smtp.lua 调用的是 `socket:receive_lines()`，这个 socket 是由 `comm.opencon` 或 `nmap.new_socket` 创建的。

**Fix**: 在 `NseSocket` 的 `UserData` 实现中添加 `receive_lines` 方法。
**Affected Scripts**: smtp-commands, imap-capabilities, smtp-brute 等

**File**: `crates/rustnmap-nse/src/libs/comm.rs:144` (NseSocket UserData impl)

---

#### RC-3: `http.can_use_head` 函数缺失 [HIGH - 影响 HTTP 脚本]

**Error**:
```
attempt to call a nil value (field 'can_use_head')
stack: http-headers:49 -> action
```

**Root Cause**: http.lua 库中缺少 `can_use_head` 函数。这个函数检查目标是否支持 HEAD 请求。

**Fix**: 在 http 模块中实现 `can_use_head`。
**Affected Scripts**: http-headers, http-enum, http-git, http-date 等

**File**: `crates/rustnmap-nse/src/libs/http.rs` (或 nselib/http.lua)

---

#### RC-4: `dns.query` 不接受 nil 参数 [MEDIUM - 影响 fcrdns 等]

**Error**:
```
bad argument #1: error converting Lua nil to String (expected string or number)
stack: dns.query -> fcrdns:80 -> action
```

**Root Cause**: `dns.query` 函数签名不接受 nil。fcrdns.nse 调用 `dns.query(hostname)` 时，hostname 可能从某个返回 nil 的函数获取。

**Fix**: 检查 dns.query 的参数是否接受 Optional 值。
**Affected Scripts**: fcrdns, dns相关

**File**: `crates/rustnmap-nse/src/libs/dns.rs` (或 nselib/dns.lua)

---

#### RC-5: `smb.list_dialects` 函数缺失 [MEDIUM - SMB 脚本]

**Error**:
```
attempt to call a nil value (field 'list_dialects')
stack: smb-protocols:54 -> action
```

**Root Cause**: smb.lua 库中完全没有实现 `list_dialects`。

**Fix**: 在 smb 模块中实现。**复杂度高 - 需要完整 SMB 协议实现。**
**Affected Scripts**: smb-protocols

**File**: nselib/smb.lua

---

#### RC-6: `ldap.connect` 方法缺失 [MEDIUM - LDAP 脚本]

**Error**:
```
attempt to call a nil value (method 'connect')
stack: ldap-rootdse:130 -> action
```

**Root Cause**: ldap.lua 库中 `connect` 方法未实现或绑定不正确。

**Fix**: 需要检查 ldap 模块绑定。
**Affected Scripts**: ldap-rootdse, ldap-search

**File**: nselib/ldap.lua 或 Rust ldap 模块

---

#### RC-7: `redis.getCredentials` 方法缺失 [MEDIUM - Redis 脚本]

**Error**:
```
attempt to call a nil value (method 'getCredentials')
stack: redis-info:186 -> action
```

**Root Cause**: `getCredentials` 方法没有在相关对象上注册。

**Fix**: 检查 redis 模块的 creds 集成。
**Affected Scripts**: redis-info

---

#### RC-8: `stdnse.debug` 参数类型不匹配 [LOW - ssl-date]

**Error**:
```
bad argument #1: error converting Lua string to i64
stack: stdnse.debug -> ssl-date:100 -> client_hello -> get_time_sample -> action
```

**Root Cause**: `stdnse.debug(level, ...)` 的 `level` 参数在某些情况下收到非数字值。

**Fix**: 修改 `stdnse.debug` 的第一个参数为 `Option<i64>` 或接受 nil。
**Affected Scripts**: ssl-date

---

#### RC-9: UDP 脚本不执行 [LOW - DNS/NTP/SNMP]

**Error**: 无错误信息，脚本完全不执行（portrule 不匹配或 UDP socket 不工作）

**Root Cause**: dns-recursion, ntp-info 等 UDP 脚本没有被执行。可能是 portrule 匹配失败（UDP 端口状态问题）或 Lua 脚本不支持 UDP socket。

**Fix**: 需要进一步调查 UDP 脚本的 portrule 和 socket 支持。
**Affected Scripts**: dns-recursion, ntp-info, snmp-info, snmp-sysdescr

---

### Pattern Analysis (Phase 2)

#### 共同模式: Rust FFI 参数类型不接受 nil

Nmap Lua 代码大量使用这种模式：
```lua
local result = might_return_nil()
local parsed = stdnse.parse_timespec(result)  -- result 可能是 nil
```

Nmap 原始实现在收到 nil 时返回 `(nil, err)` 而非崩溃。我们的 Rust 绑定使用 `String` 类型不接受 nil。

**需要系统性修复的方向**: 所有接受 Lua 值的 Rust FFI 函数，都应该使用 `Option<String>` 或 `Value` 类型，然后在函数内部处理 nil 情况。

#### 共同模式: nselib 库函数缺失

http.can_use_head, smb.list_dialects, ldap.connect 等 - 这些是完整协议库级别的缺失，不是简单的类型问题。

---

### 修复优先级

| Priority | Root Cause | Fix Difficulty | Impact |
|----------|-----------|---------------|--------|
| P0 | RC-1: parse_timespec nil | LOW (改签名) | 122个脚本 |
| P0 | RC-2: receive_lines 缺失 | LOW (加方法) | SMTP/IMAP脚本 |
| P1 | RC-3: http.can_use_head | MEDIUM | HTTP脚本 |
| P1 | RC-8: stdnse.debug 类型 | LOW | ssl-date等 |
| P2 | RC-4: dns.query nil | LOW | DNS脚本 |
| P3 | RC-5: smb.list_dialects | HIGH | SMB脚本 |
| P3 | RC-6: ldap.connect | HIGH | LDAP脚本 |
| P3 | RC-7: redis.getCredentials | MEDIUM | Redis脚本 |
| P3 | RC-9: UDP scripts | HIGH | UDP脚本 |
