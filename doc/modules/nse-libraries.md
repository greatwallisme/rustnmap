# NSE Protocol Libraries - Technical Design

> **Version**: 1.0.2
> **Target**: Nmap 7.95
> **Status**: Phase 11.1 - High Priority Libraries (http, ssh2, sslcert, dns)
> **Last Updated**: 2026-03-11

---

## Overview

This document specifies the technical design for NSE protocol libraries. These libraries expose protocol-specific functionality to Lua scripts, enabling advanced network discovery and vulnerability detection.

**The design is based on analysis of Nmap's actual NSE library implementations** in `reference/nmap/nselib/`.

## Design Principles

1. **Nmap Compatibility**: All APIs must match Nmap's NSE library behavior exactly
2. **Error Handling**: Return `nil, error_message` on failure (Lua convention)
3. **Response Format**: Match Nmap's response table structure exactly
4. **Resource Management**: Proper cleanup of sockets, connections, and memory
5. **Async-Await**: Use Tokio for all network operations
6. **mlua Integration**: Use mlua 0.9+ for Lua 5.4 bindings

---

## 1. HTTP Library (`http`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/http.rs
```

### Response Table Structure

Nmap's HTTP library returns a table with these fields:

```lua
{
    -- Status information
    ["status-line"] = "HTTP/1.1 200 OK\r\n",
    status = 200,
    version = "1.1",

    -- Headers (lowercase keys)
    header = {
        ["content-type"] = "text/html",
        ["content-length"] = "1234",
        ["server"] = "Apache",
    },

    -- Raw headers (numbered array)
    rawheader = {
        "Content-Type: text/html",
        "Content-Length: 1234",
        "Server: Apache",
    },

    -- Cookies
    cookies = {
        {name = "sessionid", value = "abc123", path = "/", domain = "example.com"},
    },

    -- Body
    rawbody = "<html>...</html>",      -- Before Content-Encoding processing
    body = "<html>...</html>",         -- After Content-Encoding processing

    -- Encoding tracking
    decoded = {"gzip"},                 -- Successfully processed encodings
    undecoded = {},                     -- Failed or unsupported encodings

    -- Redirects
    location = {"http://example.com/redirected"},

    -- Error states
    incomplete = nil,                    -- Partial response on error
    truncated = false,                   -- Body was truncated due to size limit
}
```

### Main Functions

#### `http.get(host, port, path, options)`

```lua
-- Basic GET request
local response = http.get(host, port, "/")

-- With options
local response = http.get(host, port, "/path", {
    timeout = 10000,                    -- milliseconds
    header = {
        ["User-Agent"] = "Custom",
        ["Authorization"] = "Bearer xyz",
    },
    cookies = {
        {name = "session", value = "abc123"},
    },
    auth = {username = "user", password = "pass"},
    redirect_ok = false,                 -- Don't follow redirects
    bypass_cache = true,
    no_cache = true,
    scheme = "https",                    -- Force HTTPS
})

-- Access response
if response and response.status == 200 then
    print(response.body)
    print(response.header["content-type"])
end
```

#### `http.post(host, port, path, options, ignored, postdata)`

```lua
-- Form POST (table content becomes form-encoded)
local response = http.post(host, port, "/login", nil, nil, {
    username = "admin",
    password = "secret",
})

-- JSON POST (string content)
local response = http.post(host, port, "/api", {
    header = {["Content-Type"] = "application/json"}
}, nil, '{"json": "data"}')

-- Raw binary POST
local response = http.post(host, port, "/upload", {
    header = {["Content-Type"] = "application/octet-stream"}
}, nil, binary_data)
```

#### `http.head(host, port, path, options)`

```lua
local response = http.head(host, port, "/path")
-- Same response structure, but body is empty/nil
```

#### `http.generic_request(host, port, method, path, options)`

```lua
-- Generic method for any HTTP verb
local response = http.generic_request(host, port, "PUT", "/resource", {
    header = {["Content-Type"] = "application/json"}
}, nil, '{"data": "value"}')

local response = http.generic_request(host, port, "DELETE", "/resource/123")
local response = http.generic_request(host, port, "OPTIONS", "*")
```

#### `http.get_url(url, options)`

```lua
-- Parse and fetch from URL
local response = http.get_url("https://example.com:8080/api/v1?key=value", {
    timeout = 10000,
})

-- URL is automatically parsed into host, port, path, query
```

#### `http.pipeline_add(path, options, all_requests, method)`

```lua
-- Build pipeline
local all = nil
all = http.pipeline_add("/path1", nil, all)
all = http.pipeline_add("/path2", nil, all)
all = http.pipeline_add("/path3", {header = {["X-Custom"] = "value"}}, all, "HEAD")

-- Execute pipeline
local results = http.pipeline_go(host, port, all)
-- results is array of response tables
```

#### `http.pipeline_go(host, port, all_requests)`

```lua
-- Execute queued requests
local results = http.pipeline_go(host, port, all_requests)
for i, response in ipairs(results) do
    print(response.status)
end
```

### Options Table Reference

```lua
local options = {
    -- Socket timeout
    timeout = 30000,

    -- Additional headers
    header = {["X-Custom"] = "value"},

    -- Request body (string or table for form-encoding)
    content = "raw data",
    -- OR
    content = {key1 = "value1", key2 = "value2"},

    -- Cookies
    cookies = {
        {name = "session", value = "abc123", path = "/"},
        -- OR just a string
        "session=abc123; Path=/",
    },

    -- Authentication
    auth = {username = "user", password = "pass", digest = true},
    -- OR
    digestauth = {
        username = "user",
        password = "pass",
        realm = "Protected Area",
        nonce = "abc123",
        ["digest-uri"] = "/path",
        response = "calculated_hash",
    },

    -- Cache control
    bypass_cache = true,
    no_cache = true,
    no_cache_body = true,

    -- Redirect control
    redirect_ok = function(url) return true end,
    -- OR
    redirect_ok = 3,  -- Max 3 redirects

    -- Body size limit
    max_body_size = 1024 * 1024,  -- 1MB
    truncated_ok = true,

    -- Protocol scheme
    scheme = "https",

    -- Address family
    any_af = true,
}
```

### Implementation Notes

1. **SSL/TLS Detection**: Use `comm.tryssl()` to determine if SSL is needed
2. **Redirect Handling**: Follow 301, 302, 303, 307, 308 with validation
3. **Chunked Encoding**: Handle `Transfer-Encoding: chunked`
4. **Compression**: Support gzip, deflate decoding
5. **Connection Reuse**: Pool connections for pipelining
6. **Cookie Handling**: Parse Set-Cookie headers, support Cookie headers
7. **Authentication**: Support Basic and Digest auth
8. **Caching**: Implement in-memory response cache

### Dependencies

```toml
[dependencies]
reqwest = { version = "0.12", features = ["cookies", "gzip", "brotli"] }
hyper = "1.0"
native-tls = "0.2"
url = "2.5"
```

---

## 2. SSH2 Library (`ssh2`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/ssh2.rs
```

### Key Functions

#### `ssh2.fetch_host_key(host, port, key_type)`

```lua
-- Get SSH host key fingerprint
-- key_type (optional): "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256",
--                      "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed25519"
local key = ssh2.fetch_host_key(host, port, "ssh-rsa")

-- Returns table with these exact fields (Nmap compatibility required):
-- key.key: Base64-encoded public host key
-- key.key_type: "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", etc.
-- key.fp_input: Raw public key bytes (for fingerprint calculation)
-- key.bits: 2048, 256, 384, 521, etc. (key size in bits)
-- key.full_key: "ssh-rsa AAAAB3NzaC1yc2E..." (key_type + space + base64 key)
-- key.algorithm: "RSA", "DSA", "ECDSA", "ED25519"
-- key.fingerprint: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99" (MD5 hex)
-- key.fp_sha256: Base64-encoded SHA256 fingerprint
```

#### `ssh2.banner(host, port)`

```lua
-- Get SSH banner string
local banner = ssh2.banner(host, port)
-- Returns: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
```

### Implementation Notes

1. **Protocol**: SSH-2 only (SSH-1.x is deprecated and insecure)
2. **Key Types**: Support RSA, DSA, ECDSA (nistp256, nistp384, nistp521), ED25519
3. **Fingerprinting**: Both MD5 (legacy) and SHA256 formats
4. **Timeout**: Default 10 seconds
5. **No encryption needed**: Key exchange is done in clear before encryption starts
6. **Diffie-Hellman groups**: Support group1 (1024-bit), group14 (2048-bit),
   group16 (4096-bit), and group-exchange (variable)

### Dependencies

```toml
[dependencies]
# Custom minimal SSH-2 key exchange implementation recommended
# Nmap implements only the key exchange portion, not full SSH protocol
# Using full russh library may cause compatibility issues with NSE scripts
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"
base64 = "0.22"
num-bigint = "0.4"  # For Diffie-Hellman calculations
# Alternative: russh = "0.44" (full SSH client, may be overkill)
```

---

## 3. SSL Certificate Library (`sslcert`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/sslcert.rs
```

### Key Functions

#### `sslcert.getCertificate(host, port)`

```lua
-- Retrieve SSL/TLS certificate
local cert = sslcert.getCertificate(host, port)
-- Returns table with:
-- cert.pem: PEM-encoded certificate
-- cert.subject: "CN=example.com, O=Example Inc"
-- cert.issuer: "CN=Let's Encrypt Authority X3"
-- cert.serial: Hex serial number string
-- cert.fingerprint: SHA256 fingerprint
-- cert.pubkey: {
--   type: "rsa",
--   bits: 2048,
-- }
-- cert.modulus: RSA modulus (hex string)
-- cert.exponent: RSA exponent (hex string)
-- cert.notbefore: Certificate validity start
-- cert.notafter: Certificate validity end
-- cert.version: 3
```

#### `sslcert.parse_ssl_certificate(der_data)`

```lua
-- Parse DER-encoded certificate
local cert = sslcert.parse_ssl_certificate(der_string)
-- Returns same table structure as getCertificate
```

### STARTTLS Support

    library supports STARTTLS for multiple protocols:

```lua
-- FTP (port 21)
local cert = sslcert.getCertificate(host, port, {protocol = "ftp"})

-- SMTP (ports 25, 587)
local cert = sslcert.getCertificate(host, port, {protocol = "smtp"})

-- IMAP (port 143)
local cert = sslcert.getCertificate(host, port, {protocol = "imap"})

-- POP3 (port 110)
local cert = sslcert.getCertificate(host, port, {protocol = "pop3"})

-- LDAP (port 389)
local cert = sslcert.getCertificate(host, port, {protocol = "ldap"})

-- MySQL (port 3306)
local cert = sslcert.getCertificate(host, port, {protocol = "mysql"})

-- PostgreSQL (port 5432)
local cert = sslcert.getCertificate(host, port, {protocol = "postgresql"})

-- NNTP (port 119)
local cert = sslcert.getCertificate(host, port, {protocol = "nntp"})

-- TDS/MS SQL Server (port 1433)
-- Note: TDS uses wrapped handshake, may not support full SSL reconnect
local cert = sslcert.getCertificate(host, port, {protocol = "tds"})

-- VNC/VeNCrypt (port 5900)
local cert = sslcert.getCertificate(host, port, {protocol = "vnc"})

-- XMPP (ports 5222, 5269)
local cert = sslcert.getCertificate(host, port, {protocol = "xmpp"})
```

### Supported STARTTLS Protocols

| Protocol | Default Port | Notes |
|----------|---------------|-------|
| ftp | 21 | AUTH TLS command |
| smtp | 25, 587 | STARTTLS command |
| imap | 143 | STARTTLS after CAPABILITY |
| pop3 | 110 | STLS command |
| ldap | 389 | Extended Request OID 1.3.6.1.4.1.1466.20037 |
| mysql | 3306 | SSL switch during handshake |
| postgresql | 5432 | SSLRequest message 80877103 |
| nntp | 119 | STARTTLS command |
| tds | 1433 | PreLogin packet encryption (wrapped) |
| vnc | 5900 | VeNCrypt auth subtypes |
| xmpp | 5222, 5269 | XMPP TLS proceed |

### Implementation Notes

1. **TLS Versions**: Support TLS 1.2 and 1.3, disable SSL 3.0, TLS 1.0, 1.1
2. **SNI**: Always send Server Name Indication for HTTPS
3. **Certificate Parsing**: Use `x509-parser` crate
4. **Cipher Enumeration**: Support `sslcert.cipher_preference()` and `sslcert.explore_cipher_suites()`
5. **Timeout**: Default 10 seconds

### Dependencies

```toml
[dependencies]
rustls = "0.23"
rustls-pemfile = "2.0"
x509-parser = "0.16"
webpki-roots = "0.26"
```

---

## 4. DNS Library (`dns`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/dns.rs
```

### Constants

```lua
-- Record type constants
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

### Key Functions

#### `dns.query(domain, options)`

```lua
-- Basic A record query
local records = dns.query("example.com", {dtype = dns.TYPE_A})

-- Query with options
local records = dns.query("example.com", {
    dtype = dns.TYPE_MX,
    host = "8.8.8.8",      -- Use specific DNS server
    port = 53,
    timeout = 5000,
    retAll = true,           -- Return all records
    sendCount = 3,           -- Number of retries
})

-- Response structure
for i, record in ipairs(records) do
    -- record.name: Domain name
    -- record.type: Record type number
    -- record.data: Record data (IP, text, etc.)
    -- record.ttl: Time to live
end
```

#### `dns.reverse(ip)`

```lua
-- Reverse DNS lookup
local hostname = dns.reverse("8.8.8.8")
-- Returns: "dns.google" or nil if not found
```

### Implementation Notes

1. **Protocol**: DNS-over-UDP with TCP fallback for large responses
2. **EDNS0**: Support OPT pseudo-records for larger responses
3. **Timeout**: Default 5 seconds
4. **Retries**: Default 3 attempts
5. **DNSSEC**: Validate RRSIG when available

### Dependencies

```toml
[dependencies]
trust-dns-client = "0.23"
trust-dns-proto = "0.23"
```

---

## 5. Common Patterns

### Error Handling Pattern

```lua
-- NSE style: return nil, error_message on failure
local result, err = some_lib.function(host, port)
if not result then
    return nil, "Function failed: " .. err
end
-- Use result
```

### Response Table Validation

```lua
-- Always check status field
local response = http.get(host, port, "/")
if response and response.status then
    -- Success
    if response.status >= 200 and response.status < 300 then
        print("Success: " .. response.body)
    else
        print("HTTP " .. response.status)
    end
else
    -- Error
    local err = response and response["status-line"] or "Unknown error"
    print("Failed: " .. err)
end
```

### Host/Port Convention

```lua
-- All protocol libraries follow this pattern:
-- host: string (IP address or hostname)
-- port: number OR table {number = 80, protocol = "tcp"}

-- Number port
local result = lib.function(host, 80)

-- Table port (from Nmap service detection)
local result = lib.function(host, {number = 443, protocol = "tcp"})
```

---

## Implementation Order

1. **Phase 11.1.1**: http library (highest priority, 500+ scripts depend on it)
2. **Phase 11.1.2**: sslcert library (required for HTTPS support)
3. **Phase 11.1.3**: ssh2 library (security scanning scripts)
4. **Phase 11.1.4**: dns library (reconnaissance scripts)

---

## Testing Strategy

### Unit Tests

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
        // Integration test with mock server
    }
}
```

### NSE Script Tests

```lua
-- tests/nse_libraries_test.lua
local http = require "http"
local stdnse = require "stdnse"

description = [[Test NSE protocol libraries]]
categories = {"test"}

action = function(host, port)
    -- Test HTTP
    local response = http.get(host, port, "/")
    if response and response.status == 200 then
        return "HTTP library working"
    end

    -- Test SSL
    local cert = sslcert.getCertificate(host, port)
    if cert and cert.pem then
        return "SSL library working"
    end

    return nil
end
```

---

## References

- Nmap NSE Library Source: `reference/nmap/nselib/`
  - `http.lua` - HTTP protocol implementation
  - `ssh2.lua` - SSH-2 protocol implementation
  - `sslcert.lua` - SSL certificate functions
  - `dns.lua` - DNS protocol implementation
- RFC 2616: HTTP/1.1
- RFC 4253: SSH Protocol
- RFC 5246: TLS 1.2
- RFC 8446: TLS 1.3
- RFC 1035: DNS Protocol
