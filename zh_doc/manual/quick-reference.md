# RustNmap 快速参考

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的快速参考。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

---

## 目标指定

```bash
# 单个 IP
rustnmap 192.168.1.1

# 多个 IP
rustnmap 192.168.1.1 192.168.1.2

# CIDR 表示法
rustnmap 192.168.1.0/24

# IP 范围
rustnmap 192.168.1.1-100

# 主机名
rustnmap example.com

# 从文件读取
rustnmap -iL targets.txt

# 排除主机
rustnmap 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

---

## 端口指定

```bash
# 单个端口
rustnmap -p 22 192.168.1.1

# 多个端口
rustnmap -p 22,80,443 192.168.1.1

# 端口范围
rustnmap -p 1-1000 192.168.1.1

# 所有端口
rustnmap -p- 192.168.1.1

# 快速扫描（前 100）
rustnmap -F 192.168.1.1

# 前 N 个端口
rustnmap --top-ports 100 192.168.1.1

# 特定协议
rustnmap -p T:80,U:53 192.168.1.1
```

---

## 扫描类型

| 标志 | 扫描类型 | 需要 Root | 用途 |
|------|----------|-----------|------|
| `-sS` | TCP SYN | 是 | 隐秘扫描 |
| `-sT` | TCP Connect | 否 | 标准扫描 |
| `-sU` | UDP | 是 | UDP 端口 |
| `-sF` | TCP FIN | 是 | 隐秘（UNIX） |
| `-sN` | TCP NULL | 是 | 隐秘（UNIX） |
| `-sX` | TCP XMAS | 是 | 隐秘（UNIX） |
| `-sA` | TCP ACK | 是 | 防火墙检测 |
| `-sM` | TCP Maimon | 是 | 隐秘变体 |
| `-sW` | TCP Window | 是 | 高级扫描 |
| `-b` | FTP 反弹 | 否 | FTP 代理扫描 |

---

## 主机发现

```bash
# 仅 Ping 扫描
sudo rustnmap -sn 192.168.1.0/24

# ICMP 回显
sudo rustnmap -PE 192.168.1.0/24

# TCP SYN Ping
sudo rustnmap -PS22,80,443 192.168.1.0/24

# TCP ACK Ping
sudo rustnmap -PA80 192.168.1.0/24

# UDP Ping
sudo rustnmap -PU53 192.168.1.0/24

# 跳过发现
sudo rustnmap -Pn 192.168.1.0/24
```

---

## 服务检测

```bash
# 基本服务检测
sudo rustnmap -sV 192.168.1.1

# 版本强度 0-9
sudo rustnmap -sV --version-intensity 5 192.168.1.1

# 轻量版本扫描
sudo rustnmap -sV --version-intensity 2 192.168.1.1

# 所有探针
sudo rustnmap -sV --version-intensity 9 192.168.1.1
```

---

## 操作系统检测

```bash
# 操作系统检测
sudo rustnmap -O 192.168.1.1

# 限制匹配数
sudo rustnmap -O --osscan-limit 192.168.1.1

# 激进猜测
sudo rustnmap -O --osscan-guess 192.168.1.1

# 组合扫描
sudo rustnmap -A 192.168.1.1  # -sV -sC -O --traceroute
```

---

## 计时模板

| 模板 | 标志 | 延迟 | 用途 |
|------|------|------|------|
| 偏执 | `-T0` | 5 分钟 | IDS 规避 |
| 鬼祟 | `-T1` | 15 秒 | IDS 规避 |
| 礼貌 | `-T2` | 0.4 秒 | 慢速网络 |
| 正常 | `-T3` | 默认 | 一般用途 |
| 激进 | `-T4` | 更快 | 快速网络 |
| 疯狂 | `-T5` | 极快 | 本地网络 |

```bash
# 示例
sudo rustnmap -T0 192.168.1.1   # 偏执
sudo rustnmap -T4 192.168.1.1   # 激进
```

---

## 输出格式

```bash
# 普通输出
sudo rustnmap -oN results.nmap 192.168.1.1

# XML 输出
sudo rustnmap -oX results.xml 192.168.1.1

# JSON 输出
sudo rustnmap -oJ results.json 192.168.1.1

# NDJSON 输出
sudo rustnmap --output-ndjson results.ndjson 192.168.1.1

# Markdown 输出
sudo rustnmap --output-markdown results.md 192.168.1.1

# Grepable 输出
sudo rustnmap -oG results.gnmap 192.168.1.1

# Script kiddie 格式（控制台）
sudo rustnmap --output-script-kiddie 192.168.1.1

# 所有格式
sudo rustnmap -oA results 192.168.1.1

# 追加输出
sudo rustnmap -oN results.nmap --append-output 192.168.1.2
```

---

## NSE 脚本

```bash
# 默认脚本
sudo rustnmap -sC 192.168.1.1

# 特定脚本
sudo rustnmap --script http-title 192.168.1.1

# 多个脚本
sudo rustnmap --script http-title,http-headers 192.168.1.1

# 脚本类别
sudo rustnmap --script "safe" 192.168.1.1
sudo rustnmap --script "vuln" 192.168.1.1
sudo rustnmap --script "discovery" 192.168.1.1

# 带参数的脚本
sudo rustnmap --script http-title --script-args "http.useragent=Mozilla" 192.168.1.1

# 列出脚本
rustnmap --script-help default
```

---

## 规避技术

```bash
# 分片数据包
sudo rustnmap -f 192.168.1.1
sudo rustnmap -f8 192.168.1.1

# 诱饵扫描
sudo rustnmap -D 192.168.1.2,192.168.1.3,ME 192.168.1.1
sudo rustnmap -D RND:10 192.168.1.1

# 源 IP 欺骗
sudo rustnmap -S 192.168.1.100 192.168.1.1

# 源端口
sudo rustnmap -g 53 192.168.1.1

# 自定义数据
sudo rustnmap --data-hex 48656c6c6f 192.168.1.1
sudo rustnmap --data-string "Hello" 192.168.1.1
sudo rustnmap --data-length 100 192.168.1.1
```

---

## 详细程度

```bash
# 详细
sudo rustnmap -v 192.168.1.1
sudo rustnmap -vv 192.168.1.1

# 调试
sudo rustnmap -d 192.168.1.1
sudo rustnmap -dd 192.168.1.1

# 安静
sudo rustnmap -q 192.168.1.1

# 显示原因
sudo rustnmap --reason 192.168.1.1

# 数据包跟踪
sudo rustnmap --packet-trace 192.168.1.1
```

---

## 常见场景

### 网络审计

```bash
# 完整网络扫描
sudo rustnmap -A -T4 -oA network-audit 192.168.1.0/24
```

### Web 服务器扫描

```bash
sudo rustnmap -sV -p 80,443,8080,8443 --script http-* 192.168.1.1
```

### 数据库发现

```bash
sudo rustnmap -sV -p 3306,5432,1433,27017,6379,9200 192.168.1.0/24
```

### 漏洞扫描

```bash
sudo rustnmap -sV --script vuln 192.168.1.1
```

### 隐秘扫描

```bash
sudo rustnmap -sS -T0 -f -D RND:10 --data-length 20 192.168.1.1
```

---

## 退出代码

| 代码 | 含义 |
|------|------|
| `0` | 成功 |
| `1` | 一般错误 |
| `2` | 无效参数 |
| `3` | 未指定目标 |
| `4` | 网络错误 |
| `5` | 权限被拒绝 |

---

## 帮助

```bash
# 一般帮助
rustnmap --help
```
