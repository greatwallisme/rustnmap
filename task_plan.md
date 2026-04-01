# Task Plan: Fix NSE Bugs from Target Testing

> **Created**: 2026-04-01
> **Updated**: 2026-04-01
> **Status**: Phase 1 COMPLETE, Phase 2 IN PROGRESS

---

## Phase 1: Root Cause Investigation [COMPLETE]

逐个运行脚本抓取实际错误，完成 11 个代表脚本测试。

### Root Causes Found

| ID | Root Cause | Fix | Status |
|----|-----------|-----|--------|
| RC-1 | `stdnse.parse_timespec` 不接受 nil 参数 | 改为 `Option<String>` | **FIXED + VERIFIED** |
| RC-2 | `comm::NseSocket` 缺少 `receive_lines` 方法 | 添加方法 | **FIXED + VERIFIED** |
| RC-3 | `http.can_use_head` 函数缺失 | 需要实现 | PENDING |
| RC-4 | `dns.query` 不接受 nil 参数 | 改签名 | **FIXED** |
| RC-5 | `smb.list_dialects` 函数缺失 | 需要完整 SMB 协议 | DEFERRED |
| RC-6 | `ldap.connect` 方法缺失 | 需要完整 LDAP 实现 | DEFERRED |
| RC-7 | `redis.getCredentials` 方法缺失 | 需要检查 creds 集成 | PENDING |
| RC-8 | `stdnse.debug` 参数类型不匹配 | 改签名 | **FIXED** |
| RC-9 | UDP 脚本不执行 | portrule/socket 问题 | PENDING |

### Verified Fixes (单项测试)

| Script | Target | Before | After |
|--------|--------|--------|-------|
| banner.nse | SSH 172.28.0.4:22 | FAIL (parse_timespec nil) | **PASS** - shows "SSH-2.0-OpenSSH_9.6" |
| banner.nse | FTP 172.28.0.7:21 | FAIL | **PASS** - shows FTP banner |
| banner.nse | SMTP 172.28.0.8:25 | FAIL | **PASS** - shows "220 hostname ESMTP Postfix" |
| banner.nse | Telnet 172.28.0.16:23 | FAIL | **PASS** - shows telnet data |
| smtp-commands | SMTP 172.28.0.8:25 | FAIL (receive_lines nil) | **PASS** - shows EHLO response |
| http-title | Web 172.28.0.3:80 | PASS | **PASS** (no regression) |
| ssl-cert | Web 172.28.0.3:443 | PASS | **PASS** (no regression) |
| ssh-auth-methods | SSH 172.28.0.4:22 | PASS | **PASS** (no regression) |

### Still Failing (needs more investigation)

| Script | Error | Next Step |
|--------|-------|-----------|
| http-headers | `http.can_use_head` nil | 实现 http 库方法 |
| http-enum | `http.page_exists` nil | 实现 http 库方法 |
| ssl-date | `stdnse.debug` bad arg #1 | 改 debug 签名 |
| dns-recursion | 不执行 | 调查 portrule/UDP |
| fcrdns | `dns.query` nil arg | 改 dns.query 签名 |
| smb-protocols | `smb.list_dialects` nil | 需要 SMB 实现 |
| ldap-rootdse | `ldap.connect` nil | 需要 LDAP 实现 |
| redis-info | `getCredentials` nil | 需要 creds 集成 |
| ntp-info | 不执行 | 调查 portrule/UDP |

---

## Phase 2: Fix Remaining Quick Wins [IN PROGRESS]

### RC-8: stdnse.debug 参数类型 [FIXED]

**Error**: `bad argument #1: error converting Lua string to i64`
**Fix**: Changed debug/verbose/print_debug and debug1-5 functions to accept `MultiValue` args, with flexible level type (`Value`) that silently skips non-numeric levels (Nmap behavior). Also added variadic format string support via `string.format`.
**Verified**: ssl-date no longer crashes on stdnse.debug calls.

### RC-4: dns.query nil 参数 [FIXED]

**Error**: `bad argument #1: error converting Lua nil to String`
**Fix**: Changed dns.query domain param from `String` to `Option<String>`, dns.reverse ip param from `String` to `Option<String>`. Both return nil for nil input.
**Verified**: fcrdns no longer crashes on dns.query/dns.reverse nil args.

---

## Errors Encountered

| Error | Resolution |
|-------|------------|
| clippy let...else | Changed match to let...else pattern |
| parse_timespec nil crash | Changed to Option<String> |
| receive_lines missing on comm::NseSocket | Added receive_lines method |
