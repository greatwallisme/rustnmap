# RustNmap NSE Scripting Engine

> **Version**: 1.0.0
> **Status**: This document describes the NSE scripting engine in RustNmap 1.0.0. Version 2.0 is under development; see [CHANGELOG.md](../CHANGELOG.md).

> **Complete guide to NSE scripting in RustNmap**

---

## Overview

The Nmap Scripting Engine (NSE) is one of RustNmap's most powerful features. It allows you to write (and execute) scripts that automate a wide variety of networking tasks.

### Key Features

- **6000+ scripts** available in Nmap's script database
- **14 categories** of scripts organized by purpose
- **Lua 5.4** scripting language
- **Custom libraries** for network operations

---

## Running Scripts

### Default Scripts

```bash
# Run default scripts
sudo rustnmap -sC 192.168.1.1

# Equivalent to:
sudo rustnmap --script=default 192.168.1.1
```

### Specific Scripts

```bash
# Single script
sudo rustnmap --script http-title 192.168.1.1

# Multiple scripts
sudo rustnmap --script http-title,http-headers,http-methods 192.168.1.1
```

### Script Categories

```bash
# Safe scripts only
sudo rustnmap --script "safe" 192.168.1.1

# Discovery scripts
sudo rustnmap --script "discovery" 192.168.1.1

# Vulnerability scripts
sudo rustnmap --script "vuln" 192.168.1.1

# Multiple categories
sudo rustnmap --script "safe,discovery" 192.168.1.1
```

### Pattern Matching

```bash
# All HTTP scripts
sudo rustnmap --script "http-*" 192.168.1.1

# All SMB scripts
sudo rustnmap --script "smb-*" 192.168.1.1

# All scripts with 'enum' in name
sudo rustnmap --script "*enum*" 192.168.1.1
```

### Boolean Expressions

```bash
# Scripts in category A AND B
sudo rustnmap --script "safe and intrusive" 192.168.1.1

# Scripts in category A OR B
sudo rustnmap --script "discovery or version" 192.168.1.1

# Exclude category
sudo rustnmap --script "default and not intrusive" 192.168.1.1
```

---

## Script Categories

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

## Script Arguments

### Passing Arguments

```bash
# Single argument
sudo rustnmap --script http-title \
  --script-args "http.useragent=Mozilla/5.0" 192.168.1.1

# Multiple arguments
sudo rustnmap --script smb-enum-shares \
  --script-args "smbuser=admin,smbpass=secret" 192.168.1.1

# Arguments for different scripts
sudo rustnmap --script http-title,dns-brute \
  --script-args "http.useragent=Mozilla,dns-brute.domain=example.com" 192.168.1.1
```

### Common Arguments

#### HTTP Scripts

```bash
# Set User-Agent
--script-args "http.useragent=Mozilla/5.0"

# Set timeout
--script-args "http.timeout=30"

# Set pipeline
--script-args "http.pipeline=10"

# Follow redirects
--script-args "http.max-redirects=3"
```

#### SMB Scripts

```bash
# Set credentials
--script-args "smbuser=administrator,smbpass=password"

# Use hash
--script-args "smbhash=aad3b435b51404eeaad3b435b51404ee"

# Set domain
--script-args "smbdomain=WORKGROUP"
```

#### DNS Scripts

```bash
# Set DNS server
--script-args "dns-brute.srvlist=dns.txt"

# Set threads
--script-args "dns-brute.threads=20"
```

---

## Script Files

### Script Locations

```
/etc/rustnmap/scripts/           # System scripts
/usr/share/rustnmap/scripts/     # Shared scripts
~/.rustnmap/scripts/             # User scripts
./scripts/                       # Local scripts
```

### Script Database

```bash
# Update script database
rustnmap --script-updatedb

# Help for specific script
rustnmap --script-help http-title
```

---

## NSE Libraries

### Standard Libraries

#### `nmap` Library

Core functions for scanning operations.

```lua
-- Get current time
local clock = nmap.clock()

-- Get address family
local family = nmap.address_family()

-- Log message
nmap.log_write("stdout", "Scanning target...")

-- Create socket
local socket = nmap.new_socket()
```

#### `stdnse` Library

Standard NSE utilities.

```lua
-- Debug output
stdnse.debug1("Debug message: %s", variable)

-- Check if verbose
if stdnse.get_verbose_level() > 0 then
    print("Verbose output")
end

-- Format output table
local output = stdnse.format_output(true, results)

-- Get script arguments
local arg = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
```

#### `comm` Library

Communication utilities.

```lua
-- Open connection
local socket, err = comm.opencon(host, port, "data")

-- Get banner
local banner = comm.get_banner(host, port)

-- Exchange data
local response = comm.exchange(host, port, "request\r\n")
```

#### `shortport` Library

Port matching utilities.

```lua
-- Match HTTP ports
portrule = shortport.http

-- Match specific service
portrule = shortport.port_or_service({80, 443}, "http")

-- Match version
portrule = shortport.version_port_or_service(3306, "mysql")
```

---

## Common Scripts Reference

### Web Scripts

```bash
# Get page title
--script http-title

# Get HTTP headers
--script http-headers

# Enumerate HTTP methods
--script http-methods

# Find directories
--script http-enum

# Check for SQL injection
--script http-sql-injection

# Check for XSS
--script http-stored-xss

# Check SSL/TLS
--script ssl-cert,ssl-enum-ciphers

# Check for Heartbleed
--script ssl-heartbleed
```

### SMB Scripts

```bash
# Enumerate shares
--script smb-enum-shares

# Enumerate users
--script smb-enum-users

# Check for MS17-010 (EternalBlue)
--script smb-vuln-ms17-010

# Enumerate domains
--script smb-enum-domains

# OS discovery
--script smb-os-discovery
```

### SSH Scripts

```bash
# Get SSH host key
--script ssh-hostkey

# Enumerate algorithms
--script ssh2-enum-algos

# Brute force
--script ssh-brute

# Check version
--script sshv1
```

### Database Scripts

```bash
# MySQL enumeration
--script mysql-info,mysql-empty-password

# MongoDB enumeration
--script mongodb-info

# Redis enumeration
--script redis-info

# MS SQL enumeration
--script ms-sql-info,ms-sql-empty-password
```

### Network Scripts

```bash
# DNS enumeration
--script dns-brute

# Traceroute
--script traceroute-geolocation

# Whois lookup
--script whois-domain,whois-ip

# Check for broadcast listeners
--script broadcast-ping
```

### Vulnerability Scripts

```bash
# Comprehensive vulnerability scan
--script vuln

# Check for specific CVE
--script vulners

# Check for common vulnerabilities
--script http-vuln-cve2017-5638  # Apache Struts
--script http-vuln-cve2017-1001000  # WordPress REST API
```

---

## Writing NSE Scripts

### Script Structure

```lua
-- description
description = [[
Short description of what the script does.
]]

-- categories
categories = {"discovery", "safe"}

-- author
author = "Your Name"

-- license
license = "Same as RustNmap"

-- dependencies
dependencies = {"other-script"}

-- rule function
hostrule = function(host)
    -- Return true if script should run against this host
    return true
end

portrule = function(host, port)
    -- Return true if script should run against this port
    return port.protocol == "tcp"
        and port.state == "open"
end

-- action function
action = function(host, port)
    -- Main script logic
    return "Script output"
end
```

### Complete Example

```lua
-- http-custom-check.nse
-- Custom HTTP check example

local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Checks for a custom HTTP header in responses.
]]

categories = {"discovery", "safe"}
author = "Your Name"
license = "Same as RustNmap"

-- Command line arguments
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

### Host Rule Examples

```lua
-- Run against all hosts
hostrule = function(host)
    return true
end

-- Run only against local network
hostrule = function(host)
    return host.ip:match("^192%.168%.")
end

-- Run only if hostname resolved
hostrule = function(host)
    return host.targetname ~= nil
end
```

### Port Rule Examples

```lua
-- Run against HTTP ports
portrule = function(host, port)
    return port.protocol == "tcp"
        and (port.number == 80 or port.number == 443)
end

-- Use shortport library
local shortport = require "shortport"
portrule = shortport.http

-- Run against specific services
portrule = function(host, port)
    return port.service == "ssh"
        or port.service == "telnet"
end
```

---

## Script Examples

### Banner Grabbing Script

```lua
local comm = require "comm"
local shortport = require "shortport"

description = [[
Grabs the banner from a TCP service.
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

### HTTP Authentication Check

```lua
local http = require "http"
local shortport = require "shortport"

description = [[
Checks if HTTP basic authentication is enabled.
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

## Best Practices

### Script Selection

```bash
# Start with safe scripts
sudo rustnmap -sC 192.168.1.1

# Add discovery scripts
sudo rustnmap --script "default,discovery" 192.168.1.1

# Use vulnerability scripts carefully
sudo rustnmap --script "vuln" 192.168.1.1

# Avoid intrusive scripts in production
```

### Performance Optimization

```bash
# Limit concurrent scripts
--script-args "max-concurrency=10"

# Set script timeout
--script-args "script-timeout=60"

# Disable DNS resolution for scripts
-n
```

### Output Handling

```bash
# Save with normal output
sudo rustnmap -sC -oN results.nmap 192.168.1.1

# Save as XML for parsing
sudo rustnmap -sC -oX results.xml 192.168.1.1

# Quiet mode with script output
sudo rustnmap -sC -oN results.nmap --script-trace 192.168.1.1
```

---

## Troubleshooting

### Script Not Running

```bash
# Check script details
rustnmap --script-help script-name

# Run with debug output
sudo rustnmap --script script-name -d 192.168.1.1

# Check script details
rustnmap --script-help script-name
```

### Script Errors

```bash
# Run with verbose output
sudo rustnmap --script script-name -vv 192.168.1.1

# Check script arguments
sudo rustnmap --script script-name --script-args "debug=true" 192.168.1.1
```

### Performance Issues

```bash
# Reduce script concurrency
--script-args "max-concurrency=5"

# Set individual script timeout
--script-args "script-timeout=30"

# Skip slow scripts
--script "default and not brute"
```

---

## References

- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/)
- Nmap Script Library: `/usr/share/nmap/scripts/`
