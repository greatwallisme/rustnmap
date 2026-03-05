# RustNmap Exit Codes / 退出代码

> **版本**: 1.0.0
> **状态**: 此文档描述 RustNmap 1.0.0 的退出代码。2.0 版本开发中，详见 [CHANGELOG.md](../CHANGELOG.md)。

> **Exit codes and error handling reference** / 退出代码和错误处理参考

---

## Overview / 概述

RustNmap uses exit codes to indicate the result of a scan. These codes can be used in scripts and automation to determine scan success or failure.

RustNmap 使用退出代码指示扫描结果。这些代码可用于脚本和自动化中，以确定扫描成功或失败。

---

## Exit Code Reference / 退出代码参考

| Code | Name | Description | Chinese |
|------|------|-------------|---------|
| `0` | `EXIT_SUCCESS` | Scan completed successfully | 扫描成功完成 |
| `1` | `EXIT_FAILURE` | General error occurred | 发生一般错误 |
| `2` | `EXIT_INVALID_ARGS` | Invalid command-line arguments | 无效的命令行参数 |
| `3` | `EXIT_NO_TARGETS` | No valid targets specified | 未指定有效目标 |
| `4` | `EXIT_NETWORK_ERROR` | Network error occurred | 发生网络错误 |
| `5` | `EXIT_PERMISSION_DENIED` | Permission denied (need root) | 权限被拒绝（需要 root） |
| `6` | `EXIT_SCAN_INTERRUPTED` | Scan was interrupted | 扫描被中断 |
| `7` | `EXIT_RESOURCE_ERROR` | Resource error (memory, etc.) | 资源错误（内存等） |
| `8` | `EXIT_OUTPUT_ERROR` | Output file error | 输出文件错误 |

---

## Exit Code Details / 退出代码详情

### 0 - Success / 成功

The scan completed without errors. At least one host was scanned.

扫描成功完成无错误。至少扫描了一个主机。

```bash
rustnmap 192.168.1.1
echo $?  # Output: 0
```

### 1 - General Error / 一般错误

An unspecified error occurred during the scan.

扫描期间发生了未指定的错误。

```bash
# Examples that might return 1:
rustnmap --invalid-option 192.168.1.1
rustnmap -p 999999 192.168.1.1  # Invalid port
echo $?  # Output: 1
```

### 2 - Invalid Arguments / 无效参数

Command-line arguments were invalid or mutually exclusive.

命令行参数无效或相互排斥。

```bash
# Mutually exclusive options
rustnmap -sS -sT 192.168.1.1
echo $?  # Output: 2

# Invalid timing value
rustnmap -T10 192.168.1.1
echo $?  # Output: 2
```

### 3 - No Valid Targets / 无有效目标

No valid target hosts were specified or resolved.

未指定或解析到有效目标主机。

```bash
# Empty target list
rustnmap -iL empty_file.txt
echo $?  # Output: 3

# Invalid target specification
rustnmap invalid-target
echo $?  # Output: 3
```

### 4 - Network Error / 网络错误

A network error occurred during scanning.

扫描期间发生网络错误。

```bash
# Interface down
rustnmap -e eth0 192.168.1.1  # eth0 down
echo $?  # Output: 4

# Routing error
rustnmap 10.999.999.999  # Unreachable
echo $?  # Output: 4
```

### 5 - Permission Denied / 权限被拒绝

The scan requires root privileges but was run as a regular user.

扫描需要 root 权限，但作为普通用户运行。

```bash
# SYN scan without root
rustnmap -sS 192.168.1.1  # As regular user
echo $?  # Output: 5

# UDP scan without root
rustnmap -sU 192.168.1.1  # As regular user
echo $?  # Output: 5
```

### 6 - Scan Interrupted / 扫描被中断

The scan was interrupted by the user (Ctrl+C) or a signal.

扫描被用户（Ctrl+C）或信号中断。

```bash
# Press Ctrl+C during scan
sudo rustnmap -p- 192.168.1.1
# [Ctrl+C]
echo $?  # Output: 6
```

### 7 - Resource Error / 资源错误

The system ran out of resources (memory, file descriptors, etc.).

系统资源耗尽（内存、文件描述符等）。

```bash
# Very large scan on limited system
sudo rustnmap -p- 10.0.0.0/8  # May exhaust memory
echo $?  # Output: 7
```

### 8 - Output Error / 输出错误

An error occurred writing to output files.

写入输出文件时发生错误。

```bash
# Permission denied on output file
sudo rustnmap -oN /root/protected/file.nmap 192.168.1.1
echo $?  # Output: 8

# Disk full
sudo rustnmap -oN /full_disk/results.nmap 192.168.1.1
echo $?  # Output: 8
```

---

## Using Exit Codes in Scripts / 在脚本中使用退出代码

### Bash Examples / Bash 示例

```bash
#!/bin/bash

# Run scan and check exit code / 运行扫描并检查退出代码
rustnmap -sS 192.168.1.1
EXIT_CODE=$?

case $EXIT_CODE in
    0)
        echo "Scan completed successfully"
        ;;
    1)
        echo "General error occurred"
        ;;
    2)
        echo "Invalid arguments provided"
        ;;
    3)
        echo "No valid targets"
        ;;
    4)
        echo "Network error"
        ;;
    5)
        echo "Permission denied - try with sudo"
        ;;
    6)
        echo "Scan interrupted"
        ;;
    7)
        echo "Resource error"
        ;;
    8)
        echo "Output error"
        ;;
    *)
        echo "Unknown exit code: $EXIT_CODE"
        ;;
esac
```

### Conditional Execution / 条件执行

```bash
#!/bin/bash

# Only process results if scan succeeded
if rustnmap -sS -oX results.xml 192.168.1.1; then
    echo "Scan successful, processing results..."
    python3 process_results.py results.xml
else
    echo "Scan failed with exit code $?"
    exit 1
fi
```

### Retry Logic / 重试逻辑

```bash
#!/bin/bash

# Retry scan up to 3 times
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    rustnmap -sS 192.168.1.1
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "Scan successful"
        break
    elif [ $EXIT_CODE -eq 4 ]; then
        echo "Network error, retrying..."
        RETRY_COUNT=$((RETRY_COUNT + 1))
        sleep 5
    else
        echo "Fatal error: $EXIT_CODE"
        exit $EXIT_CODE
    fi
done
```

### CI/CD Integration / CI/CD 集成

```yaml
# GitHub Actions example
- name: Run Security Scan
  run: |
    rustnmap -sS -sV -oX scan-results.xml target.example.com
    EXIT_CODE=$?

    # Exit code 0 = success
    # Exit code 5 = permission denied (expected in some containers)
    if [ $EXIT_CODE -ne 0 ] && [ $EXIT_CODE -ne 5 ]; then
      echo "Scan failed with exit code $EXIT_CODE"
      exit $EXIT_CODE
    fi
```

---

## Error Messages / 错误消息

### Common Error Messages / 常见错误消息

| Message | Exit Code | Solution |
|---------|-----------|----------|
| "Permission denied (try using sudo)" | 5 | Run with sudo |
| "No valid targets specified" | 3 | Check target specification |
| "Invalid port number" | 2 | Use valid port range 1-65535 |
| "Network is unreachable" | 4 | Check network connectivity |
| "Failed to open output file" | 8 | Check file permissions |
| "Scan interrupted by user" | 6 | Scan was cancelled |

### Error Message Examples / 错误消息示例

```bash
# Permission error
$ rustnmap -sS 192.168.1.1
Error: Permission denied. SYN scan requires root privileges.
       Try: sudo rustnmap -sS 192.168.1.1

# Invalid target
$ rustnmap invalid-target
Error: No valid targets specified: 'invalid-target' is not a valid IP or hostname

# Port out of range
$ rustnmap -p 999999 192.168.1.1
Error: Invalid port number: 999999 (must be 1-65535)
```

---

## Exit Code Behavior / 退出代码行为

### Multiple Targets / 多个目标

When scanning multiple targets, the exit code reflects the overall scan status:

扫描多个目标时，退出代码反映整体扫描状态：

- `0` - All targets scanned successfully / 所有目标扫描成功
- `1` - At least one target had an error / 至少一个目标出错
- `3` - No valid targets (all failed to resolve) / 无有效目标（全部解析失败）

### Partial Scans / 部分扫描

If a scan is interrupted but some results were obtained:

如果扫描被中断但获得了一些结果：

- Output files will contain partial results / 输出文件将包含部分结果
- Exit code will be `6` (interrupted) / 退出代码将是 `6`（中断）

### Privilege Escalation / 权限提升

Some scans may work partially without full privileges:

某些扫描在没有完全权限时可能部分工作：

```bash
# Connect scan works without root
rustnmap -sT 192.168.1.1  # Exit: 0

# SYN scan fails without root
rustnmap -sS 192.168.1.1  # Exit: 5
```

---

## Exit Codes in Automation / 自动化中的退出代码

### Ansible Playbook / Ansible Playbook

```yaml
- name: Run RustNmap scan
  command: rustnmap -sS -oX /tmp/results.xml 192.168.1.1
  register: scan_result
  ignore_errors: true
  changed_when: false

- name: Check scan result
  debug:
    msg: "Scan completed successfully"
  when: scan_result.rc == 0

- name: Handle permission error
  debug:
    msg: "Scan requires root privileges"
  when: scan_result.rc == 5

- name: Fail on other errors
  fail:
    msg: "Scan failed with exit code {{ scan_result.rc }}"
  when: scan_result.rc not in [0, 5]
```

### Python Script / Python 脚本

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
        0: 'Success',
        1: 'General error',
        2: 'Invalid arguments',
        3: 'No valid targets',
        4: 'Network error',
        5: 'Permission denied',
        6: 'Interrupted',
        7: 'Resource error',
        8: 'Output error'
    }

    if result.returncode != 0:
        print(f"Scan failed: {EXIT_CODES.get(result.returncode, 'Unknown')}")
        print(f"Exit code: {result.returncode}")
        print(f"Error: {result.stderr}")
        sys.exit(result.returncode)

    print("Scan completed successfully")
    return result

if __name__ == '__main__':
    run_scan('192.168.1.1')
```

---

## Exit Code Quick Reference / 退出代码快速参考

```
0  ✓ Success / 成功
1  ✗ General error / 一般错误
2  ⚠ Invalid arguments / 无效参数
3  ⚠ No targets / 无目标
4  ✗ Network error / 网络错误
5  ⚠ Permission denied / 权限被拒绝
6  ⚠ Interrupted / 中断
7  ✗ Resource error / 资源错误
8  ✗ Output error / 输出错误
```

---

## Related Documentation / 相关文档

- [Options Reference](options.md) - Command-line options / 命令行选项
- [Manual README](README.md) - Manual overview / 手册概览
- [Architecture](../architecture.md) - System architecture / 系统架构
