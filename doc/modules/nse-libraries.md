# NSE Protocol Libraries - Technical Design

> **Version**: 1.1.0
> **Target**: Nmap 7.95
> **Status**: Phase 11 COMPLETE - All protocol libraries implemented
> **Last Updated**: 2026-03-17

## Completion Status

| Phase | Libraries | Status |
|-------|-----------|--------|
| **Phase 11.1** | http, ssh2, sslcert, dns | ✅ Complete |
| **Phase 11.2** | smb, netbios, smbauth, unicode, unpwdb, ftp | ✅ Complete |
| **Phase 11.3** | openssl, json, creds, url | ✅ Complete |
| **Utilities** | brute | ✅ Complete |

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

### SSH Key Exchange Protocol

This section describes the complete SSH-2 key exchange implementation required
for `libssh2_utility.rs` to support authentication method enumeration.

#### Protocol Overview

SSH-2 key exchange follows RFC 4253 Section 8:

```
Client                                    Server
------                                    ------
  |                                         |
  |-------- SSH-2.0 Client Banner --------->|
  |<-------- SSH-2.0 Server Banner ---------|
  |                                         |
  |-------- KEXINIT ---------------------->|
  |<-------- KEXINIT -----------------------|
  |                                         |
  |-------- KEXDH_INIT ------------------->|
  |<-------- KEXDH_REPLY ------------------|
  |                                         |
  |-------- NEWKEYS ---------------------->|
  |<-------- NEWKEYS -----------------------|
  |                                         |
  |-------- SERVICE_REQUEST (ssh-userauth)>|
  |<-------- SERVICE_ACCEPT ----------------|
  |                                         |
  |-------- USERAUTH_REQUEST (none) ------>|
  |<-------- USERAUTH_FAILURE -------------|
  | (returns available auth methods)        |
```

#### Message Types

```rust
// SSH Transport Layer Protocol message types
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_NEWKEYS: u8 = 21;
const SSH_MSG_KEXDH_INIT: u8 = 30;
const SSH_MSG_KEXDH_REPLY: u8 = 31;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
```

#### KEXINIT Message Format

```rust
struct KexInit {
    // Message type (SSH_MSG_KEXINIT = 20)
    message_type: u8,
    // Cookie (16 random bytes)
    cookie: [u8; 16],
    // Key exchange algorithms (comma-separated)
    kex_algorithms: String,  // "diffie-hellman-group14-sha256,..."
    // Server host key algorithms
    server_host_key_algorithms: String,  // "ssh-rsa,ssh-ed25519,..."
    // Encryption algorithms (client->server, server->client)
    encryption_algorithms_client_to_server: String,
    encryption_algorithms_server_to_client: String,
    // MAC algorithms
    mac_algorithms_client_to_server: String,
    mac_algorithms_server_to_client: String,
    // Compression algorithms
    compression_algorithms_client_to_server: String,
    compression_algorithms_server_to_client: String,
    // Languages
    languages_client_to_server: String,
    languages_server_to_client: String,
    // First kex packet follows
    first_kex_packet_follows: bool,
    // Reserved (4 bytes)
    reserved: u32,
}
```

#### KEXDH_INIT Message (RFC 4253 Section 8)

```rust
// Client sends DH public key (e)
struct KexDhInit {
    message_type: u8,  // SSH_MSG_KEXDH_INIT = 30
    e: Mpint,          // Client's DH public key (g^x mod p)
}
```

#### KEXDH_REPLY Message (RFC 4253 Section 8)

```rust
// Server responds with host key, DH public key, and signature
struct KexDhReply {
    message_type: u8,          // SSH_MSG_KEXDH_REPLY = 31
    host_key: Bytes,           // Server's public host key (K_S)
    f: Mpint,                  // Server's DH public key (g^y mod p)
    signature_hash: Bytes,     // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
}
```

#### NEWKEYS Message

```rust
// Both sides send to activate new keys
struct NewKeys {
    message_type: u8,  // SSH_MSG_NEWKEYS = 21
}
```

#### Diffie-Hellman Group14 Parameters (RFC 3526)

```rust
// 2048-bit MODP Group
const DH_GROUP14_PRIME: &str = "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF
";

const DH_GROUP14_GENERATOR: u32 = 2;
```

#### Key Exchange Computation

```rust
// Client generates x (random) and computes e = g^x mod p
// Server generates y (random) and computes f = g^y mod p
// Shared secret: K = f^x mod p = e^y mod p = g^(xy) mod p

use num_bigint::BigUint;
use num_traits::One;
use rand::Rng;

fn generate_dh_key_pair() -> (BigUint, BigUint) {
    let p = BigUint::parse_bytes(DH_GROUP14_PRIME.as_bytes(), 16).unwrap();
    let g = BigUint::from(DH_GROUP14_GENERATOR);

    // Generate private key x (1 < x < p-1)
    let mut rng = rand::thread_rng();
    let p_minus_1 = &p - BigUint::one();
    let x = rng.gen_biguint_range(&BigUint::one(), &p_minus_1);

    // Compute public key e = g^x mod p
    let e = g.modpow(&x, &p);

    (e, x)  // Return (public, private)
}

fn compute_shared_secret(f: &BigUint, x: &BigUint) -> BigUint {
    let p = BigUint::parse_bytes(DH_GROUP14_PRIME.as_bytes(), 16).unwrap();
    f.modpow(x, &p)  // K = f^x mod p
}
```

#### Exchange Hash Calculation

The exchange hash H is computed as:

```
H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
```

Where:
- `V_C`: Client's SSH version string (e.g., "SSH-2.0-rustnmap_1.0")
- `V_S`: Server's SSH version string
- `I_C`: Client's KEXINIT payload
- `I_S`: Server's KEXINIT payload
- `K_S`: Server's public host key
- `e`: Client's DH public key
- `f`: Server's DH public key
- `K`: Shared secret

```rust
use sha2::{Sha256, Digest};
use encoding::Binary;

fn compute_exchange_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    e: &BigUint,
    f: &BigUint,
    k: &BigUint,
) -> Vec<u8> {
    let mut hasher = Sha256::new();

    // Concatenate all components in order
    hasher.update(u32::to_be_bytes(v_c.len() as u32));
    hasher.update(v_c);

    hasher.update(u32::to_be_bytes(v_s.len() as u32));
    hasher.update(v_s);

    hasher.update(u32::to_be_bytes(i_c.len() as u32));
    hasher.update(i_c);

    hasher.update(u32::to_be_bytes(i_s.len() as u32));
    hasher.update(i_s);

    hasher.update(u32::to_be_bytes(k_s.len() as u32));
    hasher.update(k_s);

    let e_bytes = e.to_bytes_be();
    hasher.update(u32::to_be_bytes(e_bytes.len() as u32));
    hasher.update(&e_bytes);

    let f_bytes = f.to_bytes_be();
    hasher.update(u32::to_be_bytes(f_bytes.len() as u32));
    hasher.update(&f_bytes);

    let k_bytes = k.to_bytes_be();
    hasher.update(u32::to_be_bytes(k_bytes.len() as u32));
    hasher.update(&k_bytes);

    hasher.finalize().to_vec()
}
```

#### Key Derivation

From the exchange hash H and shared secret K, derive:

```rust
// Initial IV (client->server, server->client)
// Encryption key (client->server, server->client)
// MAC key (client->server, server->client)

fn derive_keys(k: &[u8], h: &[u8], key_length: usize, iv_length: usize) -> Vec<[u8; 32]> {
    // K = hash(K || H || X || session_id) for different X values
    // This is simplified - full implementation uses multiple rounds
    todo!("Full key derivation implementation")
}
```

#### Implementation Location

The SSH key exchange implementation is in:
```rust
// crates/rustnmap-nse/src/libs/libssh2_utility.rs

pub struct SSHConnection {
    state: ConnectionState,
    authenticated: bool,
}

impl SSHConnection {
    // Phase 1: KEXINIT exchange (already implemented)
    fn connect(&mut self, host: &str, port: u16) -> mlua::Result<String>;

    // Phase 2: DH key exchange (TO BE IMPLEMENTED)
    fn perform_key_exchange(&mut self) -> mlua::Result<()>;

    // Phase 3: Service request (already implemented)
    fn send_service_request(&mut self) -> mlua::Result<()>;
}
```

#### Required Functions

```rust
// Build KEXDH_INIT packet
fn build_kexdh_init(e: &BigUint) -> Vec<u8>;

// Parse KEXDH_REPLY response
fn parse_kexdh_reply(data: &[u8]) -> mlua::Result<(Vec<u8>, BigUint, Vec<u8>)>;

// Build NEWKEYS packet
fn build_newkeys() -> Vec<u8>;

// Complete key exchange sequence
fn perform_key_exchange(stream: &mut TcpStream) -> mlua::Result<KeyExchangeResult>;
```

#### Security Considerations

1. **Constant-time operations**: DH computations should use constant-time crypto
2. **Random number generation**: Use `rand::thread_rng()` for x
3. **Key validation**: Verify server's host key signature
4. **No rollback attacks**: Verify received parameters match KEXINIT offer
5. **Group14 minimum**: Require at least 2048-bit MODP group (RFC 8270)

#### Dependencies

```toml
[dependencies]
# Cryptographic primitives
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"

# Encoding
base64 = "0.22"
hex = "0.4"

# Big integer arithmetic for Diffie-Hellman
num-bigint = "0.4"
num-traits = "0.2"

# Random number generation
rand = "0.8"

# Alternative: Full SSH library (NOT RECOMMENDED for compatibility)
# russh = "0.44" implements full SSH protocol but may cause compatibility
# issues with NSE scripts expecting specific Nmap behavior
```

#### SSH Key Exchange Dependencies

Specifically for SSH key exchange implementation:

```toml
# For DH computation with large integers
num-bigint = { version = "0.4", features = ["rand"] }

# For SHA256/SHA512 hash functions
sha2 = "0.10"

# For MPINT serialization
[dev-dependencies]
hex-literal = "0.4"
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

## 5. SMB Library (`smb`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/smb.rs
```

### Key Functions

#### `smb.list_shares(host, port)`

```lua
-- Enumerate SMB shares
local shares, err = smb.list_shares(host, port)
-- Returns array of share tables with:
-- share.name: Share name (e.g., "C$", "IPC$")
-- share.comment: Share description
-- share.type: Share type (DISK, IPC, PRINTER)
```

#### `smb.connect(host, port, options)`

```lua
-- Establish SMB connection
local conn, err = smb.connect(host, port, {
    username = "user",
    password = "pass",
    domain = "WORKGROUP"
})
```

### Implementation Notes

1. **Protocol**: SMB 1.0/2.0/3.0 support
2. **Timeout**: Default 10 seconds
3. **Dependencies**: Uses custom SMB protocol implementation

### Dependencies

```toml
[dependencies]
# Custom SMB protocol implementation
md-5 = "0.10"
sha2 = "0.10"
```

---

## 6. NetBIOS Library (`netbios`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/netbios.rs
```

### Key Functions

#### `netbios.get_name(host, port)`

```lua
-- Get NetBIOS name
local name, err = netbios.get_name(host, port)
-- Returns NetBIOS name and workstation group
```

### Implementation Notes

1. **Protocol**: NetBIOS over TCP/IP
2. **Timeout**: Default 5 seconds

---

## 7. SMBAuth Library (`smbauth`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/smbauth.rs
```

### Key Functions

#### `smbauth.password_hash(password)`

```lua
-- Compute NTLM hash of password
local hash = smbauth.password_hash("password")
-- Returns NTLM hash for authentication
```

---

## 8. Unicode Library (`unicode`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/unicode.rs
```

### Key Functions

#### `unicode.utf8_to_utf16(str)`

```lua
-- Convert UTF-8 string to UTF-16LE (for SMB)
local utf16 = unicode.utf8_to_utf16("test")
-- Returns UTF-16LE encoded bytes
```

---

## 9. UNPWDB Library (`unpwdb`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/unpwdb.rs
```

### Key Functions

#### `unpwdb.usernames()`

```lua
-- Get username iterator
local usernames = unpwdb.usernames()
for username in usernames do
    -- Iterate through common usernames
end
```

#### `unpwdb.passwords()`

```lua
-- Get password iterator
local passwords = unpwdb.passwords()
for password in passwords do
    -- Iterate through common passwords
end
```

### Implementation Notes

1. **Built-in Databases**: Common usernames and passwords from Nmap
2. **Custom Files**: Support for external wordlist files

---

## 10. FTP Library (`ftp`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/ftp.rs
```

### Key Functions

#### `ftp.connect(host, port, options)`

```lua
-- Connect to FTP server
local conn, err = ftp.connect(host, port, {
    timeout = 10000,
    username = "anonymous",
    password = "anonymous@"
})
```

#### `ftp.list(conn, path)`

```lua
-- List directory contents
local files, err = ftp.list(conn, "/")
-- Returns array of file tables
```

---

## 11. OpenSSL Library (`openssl`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/openssl.rs
```

### Key Functions

#### `openssl.bignum_hex_to_dec(hex)`

```lua
-- Convert hex BIGNUM to decimal
local dec = openssl.bignum_hex_to_dec("A1B2C3")
-- Returns decimal string representation
```

#### `openssl.md5(data)`

```lua
-- Compute MD5 hash
local hash = openssl.md5("data")
-- Returns MD5 digest as hex string
```

#### `openssl.sha1(data)`

```lua
-- Compute SHA1 hash
local hash = openssl.sha1("data")
-- Returns SHA1 digest as hex string
```

### Implementation Notes

1. **Purpose**: Low-level cryptographic operations for NSE scripts
2. **Dependencies**: Uses Rust cryptographic primitives

---

## 12. JSON Library (`json`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/json.rs
```

### Key Functions

#### `json.encode(table)`

```lua
-- Encode Lua table to JSON string
local json_str = json.encode({name = "John", age = 30})
-- Returns '{"name":"John","age":30}'
```

#### `json.decode(json_string)`

```lua
-- Decode JSON string to Lua table
local table = json.decode('{"name":"John","age":30}')
-- Returns {name = "John", age = 30}
```

### Implementation Notes

1. **Format**: Compatible with JSON specification (RFC 8259)
2. **Types**: Supports null, boolean, number, string, array, object
3. **Dependencies**: Uses `serde_json` for parsing

### Dependencies

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

---

## 13. Credentials Library (`creds`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/creds.rs
```

### Key Functions

#### `creds.Credentials:new()`

```lua
-- Create new credentials object
local c = creds.Credentials:new()
c.username = "admin"
c.password = "secret"
c.state = creds.STATE.VALID
```

#### `creds.Credentials:to_table()`

```lua
-- Convert credentials to table
local t = c:to_table()
-- Returns {username = "...", password = "...", state = "VALID"}
```

### Implementation Notes

1. **Purpose**: Standardized credential representation for NSE scripts
2. **States**: NEW, VALID, INVALID

---

## 14. URL Library (`url`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/url.rs
```

### Key Functions

#### `url.escape(str)`

```lua
-- URL encode a string
local encoded = url.escape("hello world")
-- Returns "hello%20world"
```

#### `url.unescape(str)`

```lua
-- URL decode a string
local decoded = url.unescape("hello%20world")
-- Returns "hello world"
```

#### `url.parse(url, default)`

```lua
-- Parse URL into components
local parsed = url.parse("https://example.com:8080/path?q=value#frag")
-- Returns table with:
-- parsed.scheme: "https"
-- parsed.host: "example.com"
-- parsed.port: 8080
-- parsed.path: "/path"
-- parsed.query: "q=value"
-- parsed.fragment: "frag"
-- parsed.userinfo: nil
-- parsed.ascii_host: "example.com" (Punycode for IDNs)
```

#### `url.build(parsed)`

```lua
-- Build URL from components table
local url_str = url.build({
    scheme = "https",
    host = "example.com",
    port = 8080,
    path = "/api/v1",
    query = "key=value"
})
-- Returns "https://example.com:8080/api/v1?key=value"
```

#### `url.absolute(base, relative)`

```lua
-- Build absolute URL from base and relative
local abs = url.absolute("https://example.com/api/", "../v2/resource")
-- Returns "https://example.com/v2/resource"
```

#### `url.parse_path(path)`

```lua
-- Parse path into segments
local segments = url.parse_path("/api/v1/resource")
-- Returns {1 = "api", 2 = "v1", 3 = "resource", is_absolute = 1, is_directory = nil}
```

#### `url.build_path(segments, unsafe)`

```lua
-- Build path from segments
local path = url.build_path({1 = "api", 2 = "v1", is_absolute = 1}, false)
-- Returns "/api/v1"
```

#### `url.parse_query(query)`

```lua
-- Parse query string into table
local params = url.parse_query("name=John&age=30")
-- Returns {name = "John", age = "30"}
-- Handles HTML entities: &amp;, &lt;, &gt;
```

#### `url.build_query(table)`

```lua
-- Build query string from table
local query = url.build_query({name = "John", age = "30"})
-- Returns "name=John&age=30"
```

#### `url.get_default_port(scheme)`

```lua
-- Get default port for scheme
local port = url.get_default_port("https")
-- Returns 443
```

#### `url.get_default_scheme(port)`

```lua
-- Get default scheme for port
local scheme = url.get_default_scheme(443)
-- Returns "https"
```

#### `url.ascii_hostname(host)`

```lua
-- Convert hostname to ASCII (Punycode for IDNs)
local ascii = url.ascii_hostname("müller.example.com")
-- Returns "xn--mller-kva.example.com"
```

### Implementation Notes

1. **RFC 3986 Compliance**: Full URL parsing and composition per RFC 3986
2. **IDNA Support**: Punycode encoding for international domain names
3. **HTML Entities**: Special handling in `parse_query` for `&amp;`, `&lt;`, `&gt;`
4. **Path Resolution**: RFC 3986 Section 5.2 relative URL resolution
5. **Default Ports**: http (80), https (443)

### Dependencies

```toml
[dependencies]
punycode = "0.1"  # IDNA/Punycode support
```

### Test Coverage

All URL library functions have comprehensive unit tests including:
- Percent encoding/decoding
- URL parsing and building
- Relative path resolution
- Query string parsing
- Nmap compatibility tests

---

## 15. Brute Library (`brute`)

### Module File

```rust
// crates/rustnmap-nse/src/libs/brute.rs
```

### Key Functions

#### `brute.new_emulator(options)`

```lua
-- Create brute force iterator
local engine = brute.new_emulator({
    username = "admin",
    passwords = unpwdb.passwords(),
    max_retries = 3,
    delay = 2  -- seconds between attempts
})
```

### Implementation Notes

1. **Purpose**: Standardized brute-force attack framework
2. **Rate Limiting**: Built-in delay to prevent lockouts

---

## 16. Common Patterns

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

### Phase 11.1: High Priority Protocol Libraries ✅ COMPLETE

1. **Phase 11.1.1**: http library ✅ (highest priority, 500+ scripts depend on it)
2. **Phase 11.1.2**: sslcert library ✅ (required for HTTPS support)
3. **Phase 11.1.3**: ssh2 library ✅ (security scanning scripts)
4. **Phase 11.1.4**: dns library ✅ (reconnaissance scripts)

### Phase 11.2: Medium Priority Network Libraries ✅ COMPLETE

5. **Phase 11.2.1**: smb library ✅ (SMB/CIFS protocol for Windows network scanning)
6. **Phase 11.2.2**: netbios library ✅ (NetBIOS name service)
7. **Phase 11.2.3**: smbauth library ✅ (SMB authentication)
8. **Phase 11.2.4**: unicode library ✅ (Unicode string handling for SMB)
9. **Phase 11.2.5**: unpwdb library ✅ (username/password database)
10. **Phase 11.2.6**: ftp library ✅ (FTP protocol)

### Phase 11.3: Utility and Cryptographic Libraries ✅ COMPLETE

11. **Phase 11.3.1**: openssl library ✅ (OpenSSL cryptographic operations)
12. **Phase 11.3.2**: json library ✅ (JSON encoding/decoding)
13. **Phase 11.3.3**: creds library ✅ (credential management)
14. **Phase 11.3.4**: url library ✅ (URL parsing and composition per RFC 3986)

### Additional Libraries

15. **brute library** ✅ (brute-force password cracking framework)

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

### Nmap NSE Library Source: `reference/nmap/nselib/`

- `http.lua` - HTTP protocol implementation
- `ssh2.lua` - SSH-2 protocol implementation
- `sslcert.lua` - SSL certificate functions
- `dns.lua` - DNS protocol implementation
- `smb.lua` - SMB/CIFS protocol
- `netbios.lua` - NetBIOS protocol
- `smbauth.lua` - SMB authentication
- `unicode.lua` - Unicode string handling
- `unpwdb.lua` - Username/password database
- `ftp.lua` - FTP protocol
- `openssl.lua` - OpenSSL bindings
- `json.lua` - JSON encoding/decoding
- `creds.lua` - Credential management
- `url.lua` - URL parsing and composition
- `brute.lua` - Brute-force framework

### RFC Standards

- **HTTP**: RFC 2616 (HTTP/1.1), RFC 7230-7235 (HTTP/1.1 update)
- **SSH**: RFC 4253 (SSH Protocol), RFC 4252 (SSH Authentication)
- **TLS**: RFC 5246 (TLS 1.2), RFC 8446 (TLS 1.3)
- **DNS**: RFC 1035 (DNS Protocol), RFC 3596 (DNS AAAA)
- **SMB**: [MS-SMB2] Specification
- **JSON**: RFC 8259 (JSON specification)
- **URL**: RFC 3986 (URI Generic Syntax), RFC 5891 (IDNA)
- **FTP**: RFC 959 (FTP Protocol)
- **NetBIOS**: RFC 1001/1002 (NetBIOS over TCP/IP)
- RFC 8446: TLS 1.3
- RFC 1035: DNS Protocol
