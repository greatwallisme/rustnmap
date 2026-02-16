# RustNmap NSE Scripting Engine / NSE 脚本引擎

> **Complete guide to NSE scripting in RustNmap** / RustNmap 中 NSE 脚本的完整指南

---

## Overview / 概述

The Nmap Scripting Engine (NSE) is one of RustNmap's most powerful features. It allows you to write (and execute) scripts that automate a wide variety of networking tasks.

Nmap 脚本引擎（NSE）是 RustNmap 最强大的功能之一。它允许您编写（和执行）脚本来自动化各种网络任务。

### Key Features / 主要特性

- **6000+ scripts** available in Nmap's script database / Nmap 脚本数据库中有 **6000+ 脚本**
- **14 categories** of scripts organized by purpose / 按用途组织的 **14 个类别**脚本
- **Lua 5.4** scripting language / **Lua 5.4** 脚本语言
- **Custom libraries** for network operations / 用于网络操作的**自定义库**

---

## Running Scripts / 运行脚本

### Default Scripts / 默认脚本

```bash
# Run default scripts / 运行默认脚本
sudo rustnmap -sC 192.168.1.1

# Equivalent to / 等同于：
sudo rustnmap --script=default 192.168.1.1
```

### Specific Scripts / 特定脚本

```bash
# Single script / 单个脚本
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts / 多个脚本
sudo rustnmap --script http-title,http-headers,http-methods 192.168.1.1
```

### Script Categories / 脚本类别

```bash
# Safe scripts only / 仅安全脚本
sudo rustnmap --script "safe" 192.168.1.1

# Discovery scripts / 发现脚本
sudo rustnmap --script "discovery" 192.168.1.1

# Vulnerability scripts / 漏洞脚本
sudo rustnmap --script "vuln" 192.168.1.1

# Multiple categories / 多个类别
sudo rustnmap --script "safe,discovery" 192.168.1.1
```

### Pattern Matching / 模式匹配

```bash
# All HTTP scripts / 所有 HTTP 脚本
sudo rustnmap --script "http-*" 192.168.1.1

# All SMB scripts / 所有 SMB 脚本
sudo rustnmap --script "smb-*" 192.168.1.1

# All scripts with 'enum' in name / 名称中包含 'enum' 的所有脚本
sudo rustnmap --script "*enum*" 192.168.1.1
```

### Boolean Expressions / 布尔表达式

```bash
# Scripts in category A AND B / A 和 B 类别的脚本
sudo rustnmap --script "safe and intrusive" 192.168.1.1

# Scripts in category A OR B / A 或 B 类别的脚本
sudo rustnmap --script "discovery or version" 192.168.1.1

# Exclude category / 排除类别
sudo rustnmap --script "default and not intrusive" 192.168.1.1
```

---

## Script Categories / 脚本类别

| Category | Description | Use Case |
|----------|-------------|----------|
| `auth` | Authentication tests | Brute force, default credentials |
| `broadcast` | Broadcast discovery | Network discovery via broadcast |
| `brute` | Brute force attacks | Password guessing |
| `default` | Default set | Safe, useful scripts |
| `discovery` | Service discovery | Version detection, enumeration |
| `dos` | Denial of service | Testing DoS vulnerabilities |
| `exploit` | Exploits | Security testing |
| `external` | External resources | Whois, DNS lookups |
| `fuzzer` | Fuzzing | Protocol fuzzing |
| `intrusive` | Intrusive tests | May crash services |
| `malware` | Malware detection | Check for known backdoors |
| `safe` | Safe scripts | Read-only operations |
| `version` | Version detection | Service versioning |
| `vuln` | Vulnerability detection | CVE checks |

---

## Script Arguments / 脚本参数

### Passing Arguments / 传递参数

```bash
# Single argument / 单个参数
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# Multiple arguments / 多个参数
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1

# Arguments for different scripts / 不同脚本的参数
sudo rustnmap --script http-title,dns-brute \
  --script-args "http.useragent=Mozilla,dns-brute.domain=example.com" 192.168.1.1
```

### Common Arguments / 常见参数

#### HTTP Scripts / HTTP 脚本

```bash
# Set User-Agent / 设置 User-Agent
--script-args "http.useragent=Mozilla/5.0"

# Set timeout / 设置超时
--script-args "http.timeout=30"

# Set pipeline / 设置管道
--script-args "http.pipeline=10"

# Follow redirects / 跟随重定向
--script-args "http.max-redirects=3"
```

#### SMB Scripts / SMB 脚本

```bash
# Set credentials / 设置凭证
--script-args "smbuser=administrator,smbpass=password"

# Use hash / 使用哈希
--script-args "smbhash=aad3b435b51404eeaad3b435b51404ee"

# Set domain / 设置域
--script-args "smbdomain=WORKGROUP"
```

#### DNS Scripts / DNS 脚本

```bash
# Set DNS server / 设置 DNS 服务器
--script-args "dns-brute.srvlist=dns.txt"

# Set threads / 设置线程
--script-args "dns-brute.threads=20"
```

---

## Script Files / 脚本文件

### Script Locations / 脚本位置

```
/etc/rustnmap/scripts/           # System scripts / 系统脚本
/usr/share/rustnmap/scripts/     # Shared scripts / 共享脚本
~/.rustnmap/scripts/             # User scripts / 用户脚本
./scripts/                       # Local scripts / 本地脚本
```

### Script Database / 脚本数据库

```bash
# Update script database / 更新脚本数据库
rustnmap --script-updatedb

# List all scripts / 列出所有脚本
rustnmap --script-help

# Help for specific script / 特定脚本帮助
rustnmap --script-help http-title
```

---

## NSE Libraries / NSE 库

### Standard Libraries / 标准库

#### `nmap` Library

Core functions for scanning operations.

扫描操作的核心函数。

```lua
-- Get current time / 获取当前时间
local clock = nmap.clock()

-- Get address family / 获取地址族
local family = nmap.address_family()

-- Log message / 记录消息
nmap.log_write("stdout", "Scanning target...")

-- Create socket / 创建套接字
local socket = nmap.new_socket()
```

#### `stdnse` Library

Standard NSE utilities.

标准 NSE 工具。

```lua
-- Debug output / 调试输出
stdnse.debug1("Debug message: %s", variable)

-- Check if verbose / 检查是否详细
if stdnse.get_verbose_level() > 0 then
    print("Verbose output")
end

-- Format output table / 格式化输出表
local output = stdnse.format_output(true, results)

-- Get script arguments / 获取脚本参数
local arg = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
```

#### `comm` Library

Communication utilities.

通信工具。

```lua
-- Open connection / 打开连接
local socket, err = comm.opencon(host, port, "data")

-- Get banner / 获取 banner
local banner = comm.get_banner(host, port)

-- Exchange data / 交换数据
local response = comm.exchange(host, port, "request\r\n")
```

#### `shortport` Library

Port matching utilities.

端口匹配工具。

```lua
-- Match HTTP ports / 匹配 HTTP 端口
portrule = shortport.http

-- Match specific service / 匹配特定服务
portrule = shortport.port_or_service({80, 443}, "http")

-- Match version / 匹配版本
portrule = shortport.version_port_or_service(3306, "mysql")
```

---

## Common Scripts Reference / 常用脚本参考

### Web Scripts / Web 脚本

```bash
# Get page title / 获取页面标题
--script http-title

# Get HTTP headers / 获取 HTTP 头
--script http-headers

# Enumerate HTTP methods / 枚举 HTTP 方法
--script http-methods

# Find directories / 查找目录
--script http-enum

# Check for SQL injection / 检查 SQL 注入
--script http-sql-injection

# Check for XSS / 检查 XSS
--script http-stored-xss

# Check SSL/TLS / 检查 SSL/TLS
--script ssl-cert,ssl-enum-ciphers

# Check for Heartbleed / 检查 Heartbleed
--script ssl-heartbleed
```

### SMB Scripts / SMB 脚本

```bash
# Enumerate shares / 枚举共享
--script smb-enum-shares

# Enumerate users / 枚举用户
--script smb-enum-users

# Check for MS17-010 (EternalBlue) / 检查 MS17-010
--script smb-vuln-ms17-010

# Enumerate domains / 枚举域
--script smb-enum-domains

# OS discovery / 操作系统发现
--script smb-os-discovery
```

### SSH Scripts / SSH 脚本

```bash
# Get SSH host key / 获取 SSH 主机密钥
--script ssh-hostkey

# Enumerate algorithms / 枚举算法
--script ssh2-enum-algos

# Brute force / 暴力破解
--script ssh-brute

# Check version / 检查版本
--script sshv1
```

### Database Scripts / 数据库脚本

```bash
# MySQL enumeration / MySQL 枚举
--script mysql-info,mysql-empty-password

# MongoDB enumeration / MongoDB 枚举
--script mongodb-info

# Redis enumeration / Redis 枚举
--script redis-info

# MS SQL enumeration / MS SQL 枚举
--script ms-sql-info,ms-sql-empty-password
```

### Network Scripts / 网络脚本

```bash
# DNS enumeration / DNS 枚举
--script dns-brute

# Traceroute / 路由跟踪
--script traceroute-geolocation

# Whois lookup / Whois 查询
--script whois-domain,whois-ip

# Check for broadcast listeners / 检查广播监听器
--script broadcast-ping
```

### Vulnerability Scripts / 漏洞脚本

```bash
# Comprehensive vulnerability scan / 综合漏洞扫描
--script vuln

# Check for specific CVE / 检查特定 CVE
--script vulners

# Check for common vulnerabilities / 检查常见漏洞
--script http-vuln-cve2017-5638  # Apache Struts
--script http-vuln-cve2017-1001000  # WordPress REST API
```

---

## Writing NSE Scripts / 编写 NSE 脚本

### Script Structure / 脚本结构

```lua
-- description / 描述
description = [[
Short description of what the script does.
Script 功能的简短描述。
]]

-- categories / 类别
categories = {"discovery", "safe"}

-- author / 作者
author = "Your Name"

-- license / 许可证
license = "Same as RustNmap"

-- dependencies / 依赖
dependencies = {"other-script"}

-- rule function / 规则函数
hostrule = function(host)
    -- Return true if script should run against this host
    -- 如果脚本应针对此主机运行，返回 true
    return true
end

portrule = function(host, port)
    -- Return true if script should run against this port
    -- 如果脚本应针对此端口运行，返回 true
    return port.protocol == "tcp"
        and port.state == "open"
end

-- action function / 操作函数
action = function(host, port)
    -- Main script logic / 主脚本逻辑
    return "Script output"
end
```

### Complete Example / 完整示例

```lua
-- http-custom-check.nse
-- Custom HTTP check example

local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Checks for a custom HTTP header in responses.
检查响应中的自定义 HTTP 头。
]]

categories = {"discovery", "safe"}
author = "Your Name"
license = "Same as RustNmap"

-- Command line arguments / 命令行参数
local arg_header = stdnse.get_script_args(SCRIPT_NAME .. ".header") or "X-Custom-Header"

portrule = function(host, port)
    return port.protocol == "tcp"
        and (port.number == 80 or port.number == 443
             or port.service == "http"
             or port.service == "https")
end

action = function(host, port)
    local path = "/"
    local response = http.get(host, port, path)

    if not response then
        return nil
    end

    local header_value = response.header[arg_header]

    if header_value then
        return string.format("Found %s: %s", arg_header, header_value)
    else
        return string.format("Header %s not found", arg_header)
    end
end
```

### Host Rule Examples / 主机规则示例

```lua
-- Run against all hosts / 针对所有主机运行
hostrule = function(host)
    return true
end

-- Run only against local network / 仅针对本地网络运行
hostrule = function(host)
    return host.ip:match("^192%.168%.")
end

-- Run only if hostname resolved / 仅在主机名解析时运行
hostrule = function(host)
    return host.targetname ~= nil
end
```

### Port Rule Examples / 端口规则示例

```lua
-- Run against HTTP ports / 针对 HTTP 端口运行
portrule = function(host, port)
    return port.protocol == "tcp"
        and (port.number == 80 or port.number == 443)
end

-- Use shortport library / 使用 shortport 库
local shortport = require "shortport"
portrule = shortport.http

-- Run against specific services / 针对特定服务运行
portrule = function(host, port)
    return port.service == "ssh"
        or port.service == "telnet"
end
```

---

## Script Examples / 脚本示例

### Banner Grabbing Script / Banner 抓取脚本

```lua
local comm = require "comm"
local shortport = require "shortport"

description = [[
Grabs the banner from a TCP service.
从 TCP 服务抓取 banner。
]]

categories = {"discovery", "safe"}
author = "Security Team"

portrule = function(host, port)
    return port.protocol == "tcp"
        and port.state == "open"
end

action = function(host, port)
    local banner = comm.get_banner(host, port, {lines = 1})

    if banner then
        return "Service banner: " .. banner
    end

    return nil
end
```

### HTTP Authentication Check / HTTP 认证检查

```lua
local http = require "http"
local shortport = require "shortport"

description = [[
Checks if HTTP basic authentication is enabled.
检查是否启用了 HTTP 基本认证。
]]

categories = {"auth", "safe"}

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if response and response.status == 401 then
        return "HTTP Basic Authentication enabled"
    end

    return nil
end
```

---

## Best Practices / 最佳实践

### Script Selection / 脚本选择

```bash
# Start with safe scripts / 从安全脚本开始
sudo rustnmap -sC 192.168.1.1

# Add discovery scripts / 添加发现脚本
sudo rustnmap --script "default,discovery" 192.168.1.1

# Use vulnerability scripts carefully / 谨慎使用漏洞脚本
sudo rustnmap --script "vuln" 192.168.1.1

# Avoid intrusive scripts in production / 避免在生产环境使用侵入性脚本
```

### Performance Optimization / 性能优化

```bash
# Limit concurrent scripts / 限制并发脚本
--script-args "max-concurrency=10"

# Set script timeout / 设置脚本超时
--script-args "script-timeout=60"

# Disable DNS resolution for scripts / 禁用脚本 DNS 解析
-n
```

### Output Handling / 输出处理

```bash
# Save with normal output / 与普通输出一起保存
sudo rustnmap -sC -oN results.nmap 192.168.1.1

# Save as XML for parsing / 保存为 XML 以便解析
sudo rustnmap -sC -oX results.xml 192.168.1.1

# Quiet mode with script output / 安静模式带脚本输出
sudo rustnmap -sC -oN results.nmap --script-trace 192.168.1.1
```

---

## Troubleshooting / 故障排除

### Script Not Running / 脚本未运行

```bash
# Check if portrule matches / 检查 portrule 是否匹配
rustnmap --script-help script-name

# Run with debug output / 使用调试输出运行
sudo rustnmap --script script-name -d 192.168.1.1

# Check script dependencies / 检查脚本依赖
rustnmap --script-help script-name
```

### Script Errors / 脚本错误

```bash
# Run with verbose output / 使用详细输出运行
sudo rustnmap --script script-name -vv 192.168.1.1

# Check script arguments / 检查脚本参数
sudo rustnmap --script script-name --script-args "debug=true" 192.168.1.1
```

### Performance Issues / 性能问题

```bash
# Reduce script concurrency / 减少脚本并发
--script-args "max-concurrency=5"

# Set individual script timeout / 设置单个脚本超时
--script-args "script-timeout=30"

# Skip slow scripts / 跳过慢速脚本
--script "default and not brute"
```

---

## References / 参考

- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/)
- Nmap Script Library: `/usr/share/nmap/scripts/`
