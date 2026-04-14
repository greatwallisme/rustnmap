# RustNmap Exit Codes

> **Version**: 1.0.0
> **Status**: This document describes RustNmap 1.0.0 exit codes. Version 2.0 is in development, see [CHANGELOG.md](../CHANGELOG.md).

> **Exit codes and error handling reference**

---

## Overview

RustNmap uses exit codes to indicate the result of a scan. These codes can be used in scripts and automation to determine scan success or failure.

---

## Exit Code Reference

| Code | Name | Description |
|------|------|-------------|
| `0` | `EXIT_SUCCESS` | Scan completed successfully |
| `1` | `EXIT_FAILURE` | General error occurred |
| `2` | `EXIT_INVALID_ARGS` | Invalid command-line arguments |
| `3` | `EXIT_NO_TARGETS` | No valid targets specified |
| `4` | `EXIT_NETWORK_ERROR` | Network error occurred |
| `5` | `EXIT_PERMISSION_DENIED` | Permission denied (need root) |
| `6` | `EXIT_SCAN_INTERRUPTED` | Scan was interrupted |
| `7` | `EXIT_RESOURCE_ERROR` | Resource error (memory, etc.) |
| `8` | `EXIT_OUTPUT_ERROR` | Output file error |

---

## Exit Code Details

### 0 - Success

The scan completed without errors. At least one host was scanned.

```bash
rustnmap 192.168.1.1
echo $?  # Output: 0
```

### 1 - General Error

An unspecified error occurred during the scan.

```bash
# Examples that might return 1:
rustnmap --invalid-option 192.168.1.1
rustnmap -p 999999 192.168.1.1  # Invalid port
echo $?  # Output: 1
```

### 2 - Invalid Arguments

Command-line arguments were invalid or mutually exclusive.

```bash
# Mutually exclusive options
rustnmap -sS -sT 192.168.1.1
echo $?  # Output: 2

# Invalid timing value
rustnmap -T10 192.168.1.1
echo $?  # Output: 2
```

### 3 - No Valid Targets

No valid target hosts were specified or resolved.

```bash
# Empty target list
rustnmap -iL empty_file.txt
echo $?  # Output: 3

# Invalid target specification
rustnmap invalid-target
echo $?  # Output: 3
```

### 4 - Network Error

A network error occurred during scanning.

```bash
# Interface down
rustnmap -e eth0 192.168.1.1  # eth0 down
echo $?  # Output: 4

# Routing error
rustnmap 10.999.999.999  # Unreachable
echo $?  # Output: 4
```

### 5 - Permission Denied

The scan requires root privileges but was run as a regular user.

```bash
# SYN scan without root
rustnmap -sS 192.168.1.1  # As regular user
echo $?  # Output: 5

# UDP scan without root
rustnmap -sU 192.168.1.1  # As regular user
echo $?  # Output: 5
```

### 6 - Scan Interrupted

The scan was interrupted by the user (Ctrl+C) or a signal.

```bash
# Press Ctrl+C during scan
sudo rustnmap -p- 192.168.1.1
# [Ctrl+C]
echo $?  # Output: 6
```

### 7 - Resource Error

The system ran out of resources (memory, file descriptors, etc.).

```bash
# Very large scan on limited system
sudo rustnmap -p- 10.0.0.0/8  # May exhaust memory
echo $?  # Output: 7
```

### 8 - Output Error

An error occurred writing to output files.

```bash
# Permission denied on output file
sudo rustnmap -oN /root/protected/file.nmap 192.168.1.1
echo $?  # Output: 8

# Disk full
sudo rustnmap -oN /full_disk/results.nmap 192.168.1.1
echo $?  # Output: 8
```

---

## Using Exit Codes in Scripts

### Bash Examples

```bash
#!/bin/bash

# Run scan and check exit code
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

### Conditional Execution

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

### Retry Logic

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

### CI/CD Integration

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

## Error Messages

### Common Error Messages

| Message | Exit Code | Solution |
|---------|-----------|----------|
| "Permission denied (try using sudo)" | 5 | Run with sudo |
| "No valid targets specified" | 3 | Check target specification |
| "Invalid port number" | 2 | Use valid port range 1-65535 |
| "Network is unreachable" | 4 | Check network connectivity |
| "Failed to open output file" | 8 | Check file permissions |
| "Scan interrupted by user" | 6 | Scan was cancelled |

### Error Message Examples

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

## Exit Code Behavior

### Multiple Targets

When scanning multiple targets, the exit code reflects the overall scan status:

- `0` - All targets scanned successfully
- `1` - At least one target had an error
- `3` - No valid targets (all failed to resolve)

### Partial Scans

If a scan is interrupted but some results were obtained:

- Output files will contain partial results
- Exit code will be `6` (interrupted)

### Privilege Escalation

Some scans may work partially without full privileges:

```bash
# Connect scan works without root
rustnmap -sT 192.168.1.1  # Exit: 0

# SYN scan fails without root
rustnmap -sS 192.168.1.1  # Exit: 5
```

---

## Exit Codes in Automation

### Ansible Playbook

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

### Python Script

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

## Exit Code Quick Reference

```
0  SUCCESS - Success
1  FAILURE - General error
2  ARGS    - Invalid arguments
3  TARGETS - No targets
4  NETWORK - Network error
5  PERM    - Permission denied
6  INTR    - Interrupted
7  RESOURCE - Resource error
8  OUTPUT  - Output error
```

---

## Related Documentation

- [Options Reference](options.md) - Command-line options
- [Manual README](README.md) - Manual overview
- [Architecture](../architecture.md) - System architecture
