# RustNmap NSE 脚本引擎

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的 NSE 脚本引擎。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> RustNmap 中 NSE 脚本的完整指南

---

## 概述

Nmap 脚本引擎（NSE）是 RustNmap 最强大的功能之一。它允许您编写（和执行）脚本来自动化各种网络任务。

### 主要特性

- Nmap 脚本数据库中有 **6000+ 脚本**
- 按用途组织的 **14 个类别**脚本
- **Lua 5.4** 脚本语言
- 用于网络操作的**自定义库**

---

## 运行脚本

### 默认脚本

```bash
# 运行默认脚本
sudo rustnmap -sC 192.168.1.1

# 等同于：
sudo rustnmap --script=default 192.168.1.1
```

### 特定脚本

```bash
# 单个脚本
sudo rustnmap --script http-title 192.168.1.1

# 多个脚本
sudo rustnmap --script http-title,http-headers,http-methods 192.168.1.1
```

### 脚本类别

```bash
# 仅安全脚本
sudo rustnmap --script "safe" 192.168.1.1

# 发现脚本
sudo rustnmap --script "discovery" 192.168.1.1

# 漏洞脚本
sudo rustnmap --script "vuln" 192.168.1.1

# 多个类别
sudo rustnmap --script "safe,discovery" 192.168.1.1
```

### 模式匹配

```bash
# 所有 HTTP 脚本
sudo rustnmap --script "http-*" 192.168.1.1

# 所有 SMB 脚本
sudo rustnmap --script "smb-*" 192.168.1.1

# 名称中包含 'enum' 的所有脚本
sudo rustnmap --script "*enum*" 192.168.1.1
```

### 布尔表达式

```bash
# A 和 B 类别的脚本
sudo rustnmap --script "safe and intrusive" 192.168.1.1

# A 或 B 类别的脚本
sudo rustnmap --script "discovery or version" 192.168.1.1

# 排除类别
sudo rustnmap --script "default and not intrusive" 192.168.1.1
```

---

## 脚本类别

| 类别 | 描述 | 用途 |
|------|------|------|
| `auth` | 认证测试 | 暴力破解、默认凭证 |
| `broadcast` | 广播发现 | 通过广播进行网络发现 |
| `brute` | 暴力破解攻击 | 密码猜测 |
| `default` | 默认集合 | 安全、有用的脚本 |
| `discovery` | 服务发现 | 版本检测、枚举 |
| `dos` | 拒绝服务 | 测试 DoS 漏洞 |
| `exploit` | 漏洞利用 | 安全测试 |
| `external` | 外部资源 | Whois、DNS 查询 |
| `fuzzer` | 模糊测试 | 协议模糊测试 |
| `intrusive` | 侵入性测试 | 可能导致服务崩溃 |
| `malware` | 恶意软件检测 | 检查已知后门 |
| `safe` | 安全脚本 | 只读操作 |
| `version` | 版本检测 | 服务版本识别 |
| `vuln` | 漏洞检测 | CVE 检查 |

---

## 脚本参数

### 传递参数

```bash
# 单个参数
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# 多个参数
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1

# 不同脚本的参数
sudo rustnmap --script http-title,dns-brute \
  --script-args "http.useragent=Mozilla,dns-brute.domain=example.com" 192.168.1.1
```

### 常见参数

#### HTTP 脚本

```bash
# 设置 User-Agent
--script-args "http.useragent=Mozilla/5.0"

# 设置超时
--script-args "http.timeout=30"

# 设置管道
--script-args "http.pipeline=10"

# 跟随重定向
--script-args "http.max-redirects=3"
```

#### SMB 脚本

```bash
# 设置凭证
--script-args "smbuser=administrator,smbpass=password"

# 使用哈希
--script-args "smbhash=aad3b435b51404eeaad3b435b51404ee"

# 设置域
--script-args "smbdomain=WORKGROUP"
```

#### DNS 脚本

```bash
# 设置 DNS 服务器
--script-args "dns-brute.srvlist=dns.txt"

# 设置线程
--script-args "dns-brute.threads=20"
```

---

## 脚本文件

### 脚本位置

```
/etc/rustnmap/scripts/           # 系统脚本
/usr/share/rustnmap/scripts/     # 共享脚本
~/.rustnmap/scripts/             # 用户脚本
./scripts/                       # 本地脚本
```

### 脚本数据库

```bash
# 更新脚本数据库
rustnmap --script-updatedb

# 特定脚本帮助
rustnmap --script-help http-title
```

---

## NSE 库

### 标准库

#### `nmap` 库

扫描操作的核心函数。

```lua
-- 获取当前时间
local clock = nmap.clock()

-- 获取地址族
local family = nmap.address_family()

-- 记录消息
nmap.log_write("stdout", "正在扫描目标...")

-- 创建套接字
local socket = nmap.new_socket()
```

#### `stdnse` 库

标准 NSE 工具。

```lua
-- 调试输出
stdnse.debug1("调试消息: %s", variable)

-- 检查是否详细
if stdnse.get_verbose_level() > 0 then
    print("详细输出")
end

-- 格式化输出表
local output = stdnse.format_output(true, results)

-- 获取脚本参数
local arg = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
```

#### `comm` 库

通信工具。

```lua
-- 打开连接
local socket, err = comm.opencon(host, port, "data")

-- 获取 banner
local banner = comm.get_banner(host, port)

-- 交换数据
local response = comm.exchange(host, port, "request\r\n")
```

#### `shortport` 库

端口匹配工具。

```lua
-- 匹配 HTTP 端口
portrule = shortport.http

-- 匹配特定服务
portrule = shortport.port_or_service({80, 443}, "http")

-- 匹配版本
portrule = shortport.version_port_or_service(3306, "mysql")
```

---

## 常用脚本参考

### Web 脚本

```bash
# 获取页面标题
--script http-title

# 获取 HTTP 头
--script http-headers

# 枚举 HTTP 方法
--script http-methods

# 查找目录
--script http-enum

# 检查 SQL 注入
--script http-sql-injection

# 检查 XSS
--script http-stored-xss

# 检查 SSL/TLS
--script ssl-cert,ssl-enum-ciphers

# 检查 Heartbleed
--script ssl-heartbleed
```

### SMB 脚本

```bash
# 枚举共享
--script smb-enum-shares

# 枚举用户
--script smb-enum-users

# 检查 MS17-010（EternalBlue）
--script smb-vuln-ms17-010

# 枚举域
--script smb-enum-domains

# 操作系统发现
--script smb-os-discovery
```

### SSH 脚本

```bash
# 获取 SSH 主机密钥
--script ssh-hostkey

# 枚举算法
--script ssh2-enum-algos

# 暴力破解
--script ssh-brute

# 检查版本
--script sshv1
```

### 数据库脚本

```bash
# MySQL 枚举
--script mysql-info,mysql-empty-password

# MongoDB 枚举
--script mongodb-info

# Redis 枚举
--script redis-info

# MS SQL 枚举
--script ms-sql-info,ms-sql-empty-password
```

### 网络脚本

```bash
# DNS 枚举
--script dns-brute

# 路由跟踪
--script traceroute-geolocation

# Whois 查询
--script whois-domain,whois-ip

# 检查广播监听器
--script broadcast-ping
```

### 漏洞脚本

```bash
# 综合漏洞扫描
--script vuln

# 检查特定 CVE
--script vulners

# 检查常见漏洞
--script http-vuln-cve2017-5638  # Apache Struts
--script http-vuln-cve2017-1001000  # WordPress REST API
```

---

## 编写 NSE 脚本

### 脚本结构

```lua
-- 描述
description = [[
脚本功能的简短描述。
]]

-- 类别
categories = {"discovery", "safe"}

-- 作者
author = "Your Name"

-- 许可证
license = "Same as RustNmap"

-- 依赖
dependencies = {"other-script"}

-- 规则函数
hostrule = function(host)
    -- 如果脚本应针对此主机运行，返回 true
    return true
end

portrule = function(host, port)
    -- 如果脚本应针对此端口运行，返回 true
    return port.protocol == "tcp"
        and port.state == "open"
end

-- 操作函数
action = function(host, port)
    -- 主脚本逻辑
    return "脚本输出"
end
```

### 完整示例

```lua
-- http-custom-check.nse
-- 自定义 HTTP 检查示例

local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
检查响应中的自定义 HTTP 头。
]]

categories = {"discovery", "safe"}
author = "Your Name"
license = "Same as RustNmap"

-- 命令行参数
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
        return string.format("找到 %s: %s", arg_header, header_value)
    else
        return string.format("未找到头 %s", arg_header)
    end
end
```

### 主机规则示例

```lua
-- 针对所有主机运行
hostrule = function(host)
    return true
end

-- 仅针对本地网络运行
hostrule = function(host)
    return host.ip:match("^192%.168%.")
end

-- 仅在主机名解析时运行
hostrule = function(host)
    return host.targetname ~= nil
end
```

### 端口规则示例

```lua
-- 针对 HTTP 端口运行
portrule = function(host, port)
    return port.protocol == "tcp"
        and (port.number == 80 or port.number == 443)
end

-- 使用 shortport 库
local shortport = require "shortport"
portrule = shortport.http

-- 针对特定服务运行
portrule = function(host, port)
    return port.service == "ssh"
        or port.service == "telnet"
end
```

---

## 脚本示例

### Banner 抓取脚本

```lua
local comm = require "comm"
local shortport = require "shortport"

description = [[
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
        return "服务 banner: " .. banner
    end

    return nil
end
```

### HTTP 认证检查

```lua
local http = require "http"
local shortport = require "shortport"

description = [[
检查是否启用了 HTTP 基本认证。
]]

categories = {"auth", "safe"}

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if response and response.status == 401 then
        return "HTTP 基本认证已启用"
    end

    return nil
end
```

---

## 最佳实践

### 脚本选择

```bash
# 从安全脚本开始
sudo rustnmap -sC 192.168.1.1

# 添加发现脚本
sudo rustnmap --script "default,discovery" 192.168.1.1

# 谨慎使用漏洞脚本
sudo rustnmap --script "vuln" 192.168.1.1

# 避免在生产环境使用侵入性脚本
```

### 性能优化

```bash
# 限制并发脚本
--script-args "max-concurrency=10"

# 设置脚本超时
--script-args "script-timeout=60"

# 禁用脚本 DNS 解析
-n
```

### 输出处理

```bash
# 与普通输出一起保存
sudo rustnmap -sC -oN results.nmap 192.168.1.1

# 保存为 XML 以便解析
sudo rustnmap -sC -oX results.xml 192.168.1.1

# 安静模式带脚本输出
sudo rustnmap -sC -oN results.nmap --script-trace 192.168.1.1
```

---

## 故障排除

### 脚本未运行

```bash
# 检查脚本详情
rustnmap --script-help script-name

# 使用调试输出运行
sudo rustnmap --script script-name -d 192.168.1.1

# 检查脚本详情
rustnmap --script-help script-name
```

### 脚本错误

```bash
# 使用详细输出运行
sudo rustnmap --script script-name -vv 192.168.1.1

# 检查脚本参数
sudo rustnmap --script script-name --script-args "debug=true" 192.168.1.1
```

### 性能问题

```bash
# 减少脚本并发
--script-args "max-concurrency=5"

# 设置单个脚本超时
--script-args "script-timeout=30"

# 跳过慢速脚本
--script "default and not brute"
```

---

## 参考

- [Nmap NSE 文档](https://nmap.org/book/nse.html)
- [Lua 5.4 参考手册](https://www.lua.org/manual/5.4/)
- Nmap 脚本库：`/usr/share/nmap/scripts/`
