# RustNmap 退出代码

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的退出代码。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

---

## 概述

RustNmap 使用退出代码指示扫描结果。这些代码可用于脚本和自动化中，以确定扫描成功或失败。

---

## 退出代码参考

| 代码 | 名称 | 描述 |
|------|------|------|
| `0` | `EXIT_SUCCESS` | 扫描成功完成 |
| `1` | `EXIT_FAILURE` | 发生一般错误 |
| `2` | `EXIT_INVALID_ARGS` | 无效的命令行参数 |
| `3` | `EXIT_NO_TARGETS` | 未指定有效目标 |
| `4` | `EXIT_NETWORK_ERROR` | 发生网络错误 |
| `5` | `EXIT_PERMISSION_DENIED` | 权限被拒绝（需要 root） |
| `6` | `EXIT_SCAN_INTERRUPTED` | 扫描被中断 |
| `7` | `EXIT_RESOURCE_ERROR` | 资源错误（内存等） |
| `8` | `EXIT_OUTPUT_ERROR` | 输出文件错误 |

---

## 退出代码详情

### 0 - 成功

扫描成功完成无错误。至少扫描了一个主机。

```bash
rustnmap 192.168.1.1
echo $?  # 输出: 0
```

### 1 - 一般错误

扫描期间发生了未指定的错误。

```bash
# 可能返回 1 的示例：
rustnmap --invalid-option 192.168.1.1
rustnmap -p 999999 192.168.1.1  # 无效端口
echo $?  # 输出: 1
```

### 2 - 无效参数

命令行参数无效或相互排斥。

```bash
# 相互排斥的选项
rustnmap -sS -sT 192.168.1.1
echo $?  # 输出: 2

# 无效的计时值
rustnmap -T10 192.168.1.1
echo $?  # 输出: 2
```

### 3 - 无有效目标

未指定或解析到有效目标主机。

```bash
# 空目标列表
rustnmap -iL empty_file.txt
echo $?  # 输出: 3

# 无效的目标规格
rustnmap invalid-target
echo $?  # 输出: 3
```

### 4 - 网络错误

扫描期间发生网络错误。

```bash
# 网卡关闭
rustnmap -e eth0 192.168.1.1  # eth0 已关闭
echo $?  # 输出: 4

# 路由错误
rustnmap 10.999.999.999  # 不可达
echo $?  # 输出: 4
```

### 5 - 权限被拒绝

扫描需要 root 权限，但作为普通用户运行。

```bash
# 无 root 的 SYN 扫描
rustnmap -sS 192.168.1.1  # 以普通用户运行
echo $?  # 输出: 5

# 无 root 的 UDP 扫描
rustnmap -sU 192.168.1.1  # 以普通用户运行
echo $?  # 输出: 5
```

### 6 - 扫描被中断

扫描被用户（Ctrl+C）或信号中断。

```bash
# 扫描期间按 Ctrl+C
sudo rustnmap -p- 192.168.1.1
# [Ctrl+C]
echo $?  # 输出: 6
```

### 7 - 资源错误

系统资源耗尽（内存、文件描述符等）。

```bash
# 有限系统上的超大扫描
sudo rustnmap -p- 10.0.0.0/8  # 可能耗尽内存
echo $?  # 输出: 7
```

### 8 - 输出错误

写入输出文件时发生错误。

```bash
# 输出文件权限被拒绝
sudo rustnmap -oN /root/protected/file.nmap 192.168.1.1
echo $?  # 输出: 8

# 磁盘已满
sudo rustnmap -oN /full_disk/results.nmap 192.168.1.1
echo $?  # 输出: 8
```

---

## 在脚本中使用退出代码

### Bash 示例

```bash
#!/bin/bash

# 运行扫描并检查退出代码
rustnmap -sS 192.168.1.1
EXIT_CODE=$?

case $EXIT_CODE in
    0)
        echo "扫描成功完成"
        ;;
    1)
        echo "发生一般错误"
        ;;
    2)
        echo "提供了无效参数"
        ;;
    3)
        echo "无有效目标"
        ;;
    4)
        echo "网络错误"
        ;;
    5)
        echo "权限被拒绝 - 请使用 sudo"
        ;;
    6)
        echo "扫描被中断"
        ;;
    7)
        echo "资源错误"
        ;;
    8)
        echo "输出错误"
        ;;
    *)
        echo "未知退出代码: $EXIT_CODE"
        ;;
esac
```

### 条件执行

```bash
#!/bin/bash

# 仅在扫描成功时处理结果
if rustnmap -sS -oX results.xml 192.168.1.1; then
    echo "扫描成功，处理结果..."
    python3 process_results.py results.xml
else
    echo "扫描失败，退出代码 $?"
    exit 1
fi
```

### 重试逻辑

```bash
#!/bin/bash

# 最多重试 3 次扫描
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    rustnmap -sS 192.168.1.1
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "扫描成功"
        break
    elif [ $EXIT_CODE -eq 4 ]; then
        echo "网络错误，重试中..."
        RETRY_COUNT=$((RETRY_COUNT + 1))
        sleep 5
    else
        echo "致命错误: $EXIT_CODE"
        exit $EXIT_CODE
    fi
done
```

### CI/CD 集成

```yaml
# GitHub Actions 示例
- name: 运行安全扫描
  run: |
    rustnmap -sS -sV -oX scan-results.xml target.example.com
    EXIT_CODE=$?

    # 退出代码 0 = 成功
    # 退出代码 5 = 权限被拒绝（某些容器中可能预期）
    if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 5 ]; then
      echo "扫描失败，退出代码 $EXIT_CODE"
      exit $EXIT_CODE
    fi
```

---

## 错误消息

### 常见错误消息

| 消息 | 退出代码 | 解决方案 |
|------|----------|----------|
| "Permission denied (try using sudo)" | 5 | 使用 sudo 运行 |
| "No valid targets specified" | 3 | 检查目标规格 |
| "Invalid port number" | 2 | 使用有效端口范围 1-65535 |
| "Network is unreachable" | 4 | 检查网络连接 |
| "Failed to open output file" | 8 | 检查文件权限 |
| "Scan interrupted by user" | 6 | 扫描被取消 |

### 错误消息示例

```bash
# 权限错误
$ rustnmap -sS 192.168.1.1
Error: Permission denied. SYN scan requires root privileges.
       Try: sudo rustnmap -sS 192.168.1.1

# 无效目标
$ rustnmap invalid-target
Error: No valid targets specified: 'invalid-target' is not a valid IP or hostname

# 端口超出范围
$ rustnmap -p 999999 192.168.1.1
Error: Invalid port number: 999999 (must be 1-65535)
```

---

## 退出代码行为

### 多个目标

扫描多个目标时，退出代码反映整体扫描状态：

- `0` - 所有目标扫描成功
- `1` - 至少一个目标出错
- `3` - 无有效目标（全部解析失败）

### 部分扫描

如果扫描被中断但获得了一些结果：

- 输出文件将包含部分结果
- 退出代码将是 `6`（中断）

### 权限提升

某些扫描在没有完全权限时可能部分工作：

```bash
# Connect 扫描无需 root 即可工作
rustnmap -sT 192.168.1.1  # 退出: 0

# SYN 扫描无 root 时失败
rustnmap -sS 192.168.1.1  # 退出: 5
```

---

## 自动化中的退出代码

### Ansible Playbook

```yaml
- name: 运行 RustNmap 扫描
  command: rustnmap -sS -oX /tmp/results.xml 192.168.1.1
  register: scan_result
  ignore_errors: true
  changed_when: false

- name: 检查扫描结果
  debug:
    msg: "扫描成功完成"
  when: scan_result.rc == 0

- name: 处理权限错误
  debug:
    msg: "扫描需要 root 权限"
  when: scan_result.rc == 5

- name: 其他错误时失败
  fail:
    msg: "扫描失败，退出代码 {{ scan_result.rc }}"
  when: scan_result.rc not in [0, 5]
```

### Python 脚本

```python
import subprocess
import sys

def run_scan(target):
    result = subprocess.run(
        ['rustnmap', '-sS', '-oX', 'results.xml', target],
        capture_output=True,
        text=True
    )

    EXIT_CODES = {
        0: '成功',
        1: '一般错误',
        2: '无效参数',
        3: '无有效目标',
        4: '网络错误',
        5: '权限被拒绝',
        6: '被中断',
        7: '资源错误',
        8: '输出错误'
    }

    if result.returncode != 0:
        print(f"扫描失败: {EXIT_CODES.get(result.returncode, '未知')}")
        print(f"退出代码: {result.returncode}")
        print(f"错误: {result.stderr}")
        sys.exit(result.returncode)

    print("扫描成功完成")
    return result

if __name__ == '__main__':
    run_scan('192.168.1.1')
```

---

## 退出代码快速参考

```
0  成功
1  一般错误
2  无效参数
3  无目标
4  网络错误
5  权限被拒绝
6  中断
7  资源错误
8  输出错误
```

---

## 相关文档

- [选项参考](options.md) - 命令行选项
- [手册概览](README.md) - 手册概览
- [系统架构](../architecture.md) - 系统架构
