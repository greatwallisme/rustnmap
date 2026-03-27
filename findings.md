# NSE Module Technical Findings

> **Updated**: 2026-03-27

---

## UPDATED: SSL/TLS Scripts Complete (2026-03-27)

**Status**: ✅ COMPLETE - ssl-cert.nse script fully functional

### Progress Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Lua file loader | ✅ COMPLETE | nselib/ libraries load successfully |
| Socket connect | ✅ COMPLETE | Handles host, port, proto parameters |
| SSL certificate retrieval | ✅ COMPLETE | OpenSSL integration working |

### Test Result

```bash
$ ./target/release/rustnmap -p 443 --script ssl-cert www.qq.com

PORT     STATE SERVICE
443/tcp  open    https
| ssl-cert
|   Subject: commonName=*.ias.tencent-cloud.net/organizationName=Tencent Technology (Shenzhen) Company Limited/stateOrProvinceName=Guangdong Province/countryName=CN
|   Subject Alternative Name: DNS:*.ias.tencent-cloud.net, DNS:ias.tencent-cloud.net
|   Issuer: commonName=DigiCert Secure Site OV G2 TLS CN RSA4096 SHA256 2022 CA1/organizationName=DigiCert, Inc./countryName=US
|   Public Key type: rsa
|   Public Key bits: 2048
|   Signature Algorithm: sha256WithRSAEncryption
|   Not valid before: 2025-06-23T00:00:00
|   Not valid after:  2026-07-24T23:59:59
|   MD5:     590c a9a7 e8b2 36eb 87d5 63f8 6dc5 216e
|   SHA-1:   78f3 f716 8024 8710 c435 b5ef 09a6 5933 7d3a 45a3
|_  SHA-256: 8e4f 83b5 fcd2 2ab2 3a94 0d4c f170 7a5a 02ed eba5 abd9 3c4d de21 22d8 5bee e3ce
```

### Implementation Details

**Files Modified**:
- `crates/rustnmap-nse/src/libs/nmap.rs` - Added SSL support:
  - `get_ssl_certificate()` method on NseSocket
  - `cert_to_table()` function for certificate parsing
  - `x509_name_to_table()` for DN field conversion
  - `asn1_time_to_table()` for date parsing
  - `digest()` method returning raw bytes for fingerprint calculation

**Key Implementation Points**:
1. SSL handshake using OpenSSL's `SslConnector`
2. Certificate verification disabled (`SslVerifyMode::NONE`) matching Nmap behavior
3. Certificate table with subject, issuer, validity, extensions, pubkey info
4. Digest method returns raw binary (not hex) for `stdnse.tohex` compatibility

### Bugs Fixed

1. **Digest function signature**: Changed from `|lua, algo: String|` to `|lua, (_self, algo): (mlua::Table, String)|` to handle method call syntax (`cert:digest("md5")`)

2. **Date parsing**: OpenSSL returns "Mon DD HH:MM:SS YYYY GMT" format, not "YYYYMMDDhhmmssZ" as originally assumed

---

## CRITICAL: SSL/TLS Scripts Cannot Run - Missing Lua Library Loader (2026-03-26)

**Status**: ✅ FIXED - Lua file loader implemented

### Original Problem

SSL/TLS NSE scripts required pure Lua libraries that the NSE engine could not load.

### Solution Implemented

Added Lua file loader in `crates/rustnmap-nse/src/lua.rs`:
- `set_package_path()` - Configures Lua package path
- `add_file_searcher()` - Registers custom file loader

**Result**: Pure Lua libraries from `nselib/` now load successfully.

---

## CRITICAL: SSL/TLS Scripts Cannot Run - Missing Lua Library Loader (2026-03-26)

**Status**: CRITICAL BUG - BLOCKING ALL SSL SCRIPTS

### Problem

SSL/TLS NSE scripts require pure Lua libraries that the NSE engine cannot load.

### Root Cause

The NSE engine only registers **Rust** libraries in `libs/mod.rs::register_all()`. It does NOT support loading **pure Lua** files from the `nselib/` directory.

### Evidence

**Script Error**:
```
lua runtime error in 'ssl-cert': runtime error:
  module 'sslcert' not found:
  no field package.preload['sslcert']
  no file '/usr/local/share/lua/5.4/sslcert.lua'
  no file '/usr/local/share/lua/5.4/sslcert/init.lua'
  no file './sslcert.lua'
  no file './sslcert/init.lua'
```

**Libraries Exist But Not Loaded**:
```bash
$ ls -la nselib/*.lua | grep -E "(ssl|cert|date|time|outlib|unicode)"
-rw-r--r-- 1 root root   8257 datetime.lua
-rw-r--r-- 1 root root   2162 outlib.lua
-rw-r--r-- 1 root root  37031 sslcert.lua
-rw-r--r-- 1 root root  9909 sslv2.lua
-rw-r--r-- 1 root root  75467 tls.lua
-rw-r--r-- 1 root root  13996 unicode.lua
```

### Architecture Analysis

**Current NSE Engine Flow**:
```
1. NseLua::new() creates Lua instance
2. register_all() adds Rust libraries to globals
3. Script loads from .nse file
4. Script calls require("sslcert") ❌ FAILS
```

**Missing Infrastructure**:
1. No `package.path` setup (Lua's module search path)
2. No Lua file loader (to read .lua files)
3. No package searcher registration with mlua

### Impact

**All SSL/TLS scripts broken** (12+ scripts):
- ssl-cert.nse
- ssl-cert-intaddr.nse
- ssl-date.nse
- ssl-enum-ciphers.nse
- ssl-dh-params.nse
- ssl-heartbleed.nse
- tls-alpn.nse
- tls-nextprotoneg.nse
- tls-ticketbleed.nse

**Also broken**:
- Any script requiring `json.lua`
- Any script requiring `datafiles.lua`
- Any script requiring `asn1.lua`
- Many others

### Required Fix

**Implement Lua file loader** in `crates/rustnmap-nse/src/lua.rs`:

```rust
pub fn new(config: LuaConfig) -> Result<Self> {
    let lua = Lua::new();

    // Set package.path to search nselib/
    lua.load("package.path = './nselib/?.lua;./nselib/?/init.lua;'").exec()?;

    // Add custom searcher for nselib files
    lua.globals().get::<_, mlua::Table>("package")?
        .set("searchers", vec![...])?;

    Ok(Self { lua, config })
}
```

**Complexity**: Medium (2-3 hours)

### Test Evidence

**Command**:
```bash
./target/debug/rustnmap -p 443 --script ssl-cert www.example.com
```

**Result**: Script fails during portrule evaluation with module not found error.

**See**: `SSL_NSE_TEST_REPORT.md` for full test details.

---

## SSH Post-NEWKEYS Encryption: Critical RFC 4253 Violation Fixed (2026-03-22)

(Previous findings preserved...)

[Rest of previous findings.md content...]
