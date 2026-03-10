## 3.5 Nmap 脚本引擎 (NSE) - 核心设计

对应 Nmap 命令: `--script`, `--script-args`, `--script-trace`

这是本设计文档的**核心重点**，需要实现与 Nmap NSE 的完全兼容。

### 3.5.1 NSE 架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     RustNmap Script Engine (RNSE)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Script Manager                                │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐│  │
│  │  │   Script    │  │   Script    │  │    Script Scheduler         ││  │
│  │  │   Loader    │  │   Cache     │  │    (Parallel Execution)     ││  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────────┘│  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                     Lua Runtime Layer                              │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    mlua / rlua Binding                       │  │  │
│  │  │  (Rust-Lua FFI Interface)                                   │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                  Lua Standard Libraries                      │  │  │
│  │  │  base | string | table | math | io | os | coroutine         │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                   NSE API Layer (Lua Exposed)                      │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   nmap     │ │   stdnse   │ │    comm    │ │      http      │ │  │
│  │  │   library  │ │   library  │ │   library  │ │    library     │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   snmp     │ │   ssh      │ │    ssl     │ │     brute      │ │  │
│  │  │  library   │ │  library   │ │  library   │ │    library     │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────┐ │  │
│  │  │   ftp      │ │   smtp     │ │    ldap    │ │     mysql      │ │  │
│  │  │  library   │ │  library   │ │  library   │ │    library     │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                    │                                    │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │                   Script Execution Layer                           │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │  Rule Evaluation          Script Execution                   │  │  │
│  │  │  ├── hostrule            ├── action(host)                   │  │  │
│  │  │  └── portrule            └── action(host, port)             │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.2 Lua 与 Rust 的互操作设计

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Rust-Lua FFI Bridge Design                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Rust Side                          Lua Side                            │
│  ──────────                         ──────────                          │
│                                                                         │
│  ┌───────────────────┐              ┌───────────────────┐              │
│  │  NseHost struct   │◄───────────▶│  host table       │              │
│  │  ├── ip: IpAddr   │              │  ├── ip           │              │
│  │  ├── name: String │              │  ├── name         │              │
│  │  ├── os: Vec<Os>  │              │  ├── os           │              │
│  │  └── ports: Vec   │              │  └── ports        │              │
│  └───────────────────┘              └───────────────────┘              │
│                                                                         │
│  ┌───────────────────┐              ┌───────────────────┐              │
│  │  NsePort struct   │◄───────────▶│  port table       │              │
│  │  ├── number: u16  │              │  ├── number       │              │
│  │  ├── protocol     │              │  ├── protocol     │              │
│  │  ├── service      │              │  ├── service      │              │
│  │  ├── version      │              │  ├── version      │              │
│  │  └── state        │              │  └── state        │              │
│  └───────────────────┘              └───────────────────┘              │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                      Bridge Functions                              │ │
│  │                                                                    │ │
│  │  Rust fn -> Lua:                                                   │ │
│  │  ├── register_host_table(host: &NseHost) -> Table                 │ │
│  │  ├── register_port_table(port: &NsePort) -> Table                 │ │
│  │  ├── register_socket(socket: NseSocket) -> UserData               │ │
│  │  └── register_result(result: ScriptResult) -> Table               │ │
│  │                                                                    │ │
│  │  Lua fn -> Rust:                                                   │ │
│  │  ├── call_socket_connect(host, port) -> Result<Socket>            │ │
│  │  ├── call_socket_send(data) -> Result<()>                         │ │
│  │  ├── call_socket_receive(len) -> Result<Vec<u8>>                  │ │
│  │  └── call_output_table(data) -> ()                                │ │
│  │                                                                    │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.3 NSE 脚本格式解析器

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NSE Script Parser Design                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Script Structure (Example: http-vuln-cve.nse)                          │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                                                                   │ │
│  │  -- The HEAD block (metadata)                                    │ │
│  │  description = [[                                                 │ │
│  │    Detects CVE-XXXX-XXXX vulnerability in HTTP servers...        │ │
│  │  ]]                                                              │ │
│  │                                                                   │ │
│  │  categories = {"vuln", "exploit", "intrusive"}                   │ │
│  │                                                                   │ │
│  │  author = "Security Researcher"                                  │ │
│  │  license = "Same as Nmap"                                        │ │
│  │  dependencies = {"http"}                                         │ │
│  │                                                                   │ │
│  │  -- The RULE block                                               │ │
│  │  portrule = shortport.http                                       │ │
│  │  -- or                                                           │ │
│  │  portrule = function(host, port)                                 │ │
│  │    return port.service == "http" and port.state == "open"        │ │
│  │  end                                                             │ │
│  │                                                                   │ │
│  │  hostrule = function(host)                                       │ │
│  │    return host.os:match("Linux") ~= nil                          │ │
│  │  end                                                             │ │
│  │                                                                   │ │
│  │  -- The ACTION block                                             │ │
│  │  action = function(host, port)                                   │ │
│  │    local response = http.get(host, port, "/vuln-path")           │ │
│  │    if response.status == 200 then                                │ │
│  │      return "VULNERABLE: " .. response.body                      │ │
│  │    end                                                           │ │
│  │  end                                                             │ │
│  │                                                                   │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
│  ParsedScript Structure                                                 │
│  ├── id: String                    (Script filename without .nse)      │
│  ├── description: String           (Description text)                  │
│  ├── categories: Vec<Category>     (Script categories)                │
│  │   ├── auth                    (Authentication cracking)            │
│  │   ├── broadcast               (Network broadcast)                  │
│  │   ├── brute                   (Brute force)                        │
│  │   ├── default                 (Default scripts)                    │
│  │   ├── discovery               (Service discovery)                  │
│  │   ├── dos                     (Denial of Service)                  │
│  │   ├── exploit                 (Exploitation)                       │
│  │   ├── external                (External service queries)           │
│  │   ├── fuzzer                  (Fuzzing)                            │
│  │   ├── intrusive               (Intrusive checks)                   │
│  │   ├── malware                 (Malware detection)                  │
│  │   ├── safe                    (Safe checks)                        │
│  │   ├── version                 (Version detection)                  │
│  │   └── vuln                    (Vulnerability detection)            │
│  ├── author: String                                                    │
│  ├── license: String                                                   │
│  ├── dependencies: Vec<String>     (Required libraries)               │
│  ├── portrule: Option<LuaCode>     (Port rule function)               │
│  ├── hostrule: Option<LuaCode>     (Host rule function)               │
│  ├── action: LuaCode               (Main action function)             │
│  └── source: String                (Original Lua source)              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.4 NSE 标准库实现清单
完整 NSE 库实现清单 

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      NSE Standard Libraries                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Core Libraries (必须实现)                                              │
│  ───────────────────────────                                            │
│                                                                         │
│  1. nmap (核心库)                                                       │
│     ├── nmap.new_socket()           - 创建套接字                       │
│     ├── nmap.clock()                - 获取时间戳                       │
│     ├── nmap.log_write(level, msg)  - 日志输出                         │
│     ├── nmap.address_family()       - 地址族                           │
│     └── nmap.registry               - 全局注册表                       │
│                                                                         │
│  2. stdnse (标准扩展库)                                                 │
│     ├── stdnse.format_output(status, data) - 格式化输出                │
│     ├── stdnse.debug(level, fmt, ...) - 调试输出                       │
│     ├── stdnse.verbose(level, fmt, ...) - 详细输出                     │
│     ├── stdnse.sleep(seconds)           - 睡眠                         │
│     ├── stdnse.mutex(name)              - 互斥锁                       │
│     ├── stdnse.condition_variable(name) - 条件变量                     │
│     ├── stdnse.new_thread(fn, ...)      - 创建线程                     │
│     └── stdnse.get_script_args(...)    - 获取脚本参数                  │
│                                                                         │
│  3. comm (通信库)                                                       │
│     ├── comm.tryssl(host, port, data, opts) - SSL探测                  │
│     ├── comm.get_banner(host, port)         - 获取banner              │
│     └── comm.openconn(host, port, opts)     - 建立连接                 │
│                                                                         │
│  4. shortport (端口规则助手)                                           │
│     ├── shortport.portnumber(ports, proto, state)                       │
│     ├── shortport.service(services, state)                              │
│     ├── shortport.http()                                                │
│     ├── shortport.ssl()                                                 │
│     └── shortport.smb()                                                 │
│                                                                         │
│  ───────────────────────────────────────────────────────────────────   │
│                                                                         │
│  Protocol Libraries (协议库)                                            │
│  ─────────────────────────                                              │
│                                                                         │
│  5. http (HTTP协议) - 续                                               │
│     ├── http.pipeline_go(host, port, pipeline)                          │
│     ├── http.get_url(url, options)                                      │
│     ├── http.parse_url(url)                                             │
│     ├── http.parse_response(response)                                   │
│     ├── http.get_ssl_certificate(host, port)                            │
│     └── http.identify_404(host, port)                                   │
│                                                                         │
│  6. ssh (SSH协议)                                                       │
│     ├── ssh.connect(host, port)                                         │
│     ├── ssh.auth_none(socket)                                           │
│     ├── ssh.fetch_host_key(host, port)                                  │
│     ├── ssh.auth_password(socket, user, pass)                           │
│     └── ssh.auth_publickey(socket, user, key)                           │
│                                                                         │
│  7. ssl (SSL/TLS协议)                                                   │
│     ├── ssl.connect(host, port, options)                                │
│     ├── ssl.cert_to_pem(cert)                                           │
│     ├── ssl.parse_certificate(cert)                                     │
│     ├── ssl.cipher_preference(host, port)                               │
│     ├── ssl.explore_cipher_suites(host, port)                           │
│     └── ssl.get_certificate(host, port)                                 │
│                                                                         │
│  8. snmp (SNMP协议)                                                     │
│     ├── snmp.encode(pkt)                                                │
│     ├── snmp.decode(pkt)                                                │
│     ├── snmp.build_get_request(oid, options)                            │
│     ├── snmp.build_getnext_request(oid, options)                        │
│     └── snmp.walk(host, port, oid)                                      │
│                                                                         │
│  9. smb (SMB/CIFS协议)                                                  │
│     ├── smb.start(host)                                                 │
│     ├── smb.negotiate_session(socket)                                   │
│     ├── smb.start_session(socket)                                       │
│     ├── smb.tree_connect(socket, path)                                  │
│     ├── smb.file_read(socket, path)                                     │
│     ├── smb.list_shares(host)                                           │
│     └── smb.get_security_mode(host)                                     │
│                                                                         │
│  10. ftp (FTP协议)                                                      │
│      ├── ftp.connect(host, port)                                        │
│      ├── ftp.login(socket, user, pass)                                  │
│      ├── ftp.list(socket, path)                                         │
│      ├── ftp.retrieve(socket, path)                                     │
│      └── ftp.anonymous_login(host, port)                                │
│                                                                         │
│  11. smtp (SMTP协议)                                                    │
│      ├── smtp.connect(host, port)                                       │
│      ├── smtp.ehlo(socket, domain)                                      │
│      ├── smtp.starttls(socket)                                          │
│      ├── smtp.login(socket, user, pass)                                 │
│      ├── smtp.mail_from(socket, from)                                   │
│      ├── smtp.rcpt_to(socket, to)                                       │
│      └── smtp.quit(socket)                                              │
│                                                                         │
│  12. ldap (LDAP协议)                                                    │
│      ├── ldap.connect(host, port)                                       │
│      ├── ldap.bind(socket, dn, password)                                │
│      ├── ldap.search(socket, base, scope, filter, attrs)                │
│      └── ldap.close(socket)                                             │
│                                                                         │
│  13. mysql (MySQL协议)                                                  │
│      ├── mysql.connect(host, port, options)                             │
│      ├── mysql.login(socket, user, pass)                                │
│      ├── mysql.query(socket, sql)                                       │
│      ├── mysql.close(socket)                                            │
│      └── mysql.get_variable(socket, var)                                │
│                                                                         │
│  14. pgsql (PostgreSQL协议)                                             │
│      ├── pgsql.connect(host, port, options)                             │
│      ├── pgsql.login(socket, params)                                    │
│      ├── pgsql.query(socket, sql)                                       │
│      └── pgsql.close(socket)                                            │
│                                                                         │
│  15. msrpc (MS-RPC协议)                                                 │
│      ├── msrpc.bind(socket, uuid, version)                              │
│      ├── msrpc.call(socket, opnum, data)                                │
│      └── msrpc.unbind(socket)                                           │
│                                                                         │
│  16. dns (DNS协议)                                                      │
│      ├── dns.query(name, dtype, options)                                │
│      ├── dns.reverse(addr)                                              │
│      ├── dns.get_default_servers()                                      │
│      └── dns.update_table(host, name, addr)                             │
│                                                                         │
│  17. dhcp (DHCP协议)                                                    │
│      ├── dhcp.make_request(options)                                     │
│      └── dhcp.parse_response(response)                                  │
│                                                                         │
│  18. vnc (VNC协议)                                                      │
│      ├── vnc.connect(host, port)                                        │
│      ├── vnc.handshake(socket)                                          │
│      └── vnc.authenticate(socket, password)                             │
│                                                                         │
│  19. rdp (RDP协议)                                                      │
│      ├── rdp.connect(host, port)                                        │
│      ├── rdp.connect_req(socket)                                        │
│      └── rdp.parse_connect_response(data)                               │
│                                                                         │
│  20. mongodb (MongoDB协议)                                              │
│      ├── mongodb.connect(host, port)                                    │
│      ├── mongodb.query(socket, db, collection, query)                   │
│      └── mongodb.getServerStatus(socket)                                │

│  ───────────────────────────────────────────────────────────────────   │
│                                                                         │
│  Utility Libraries (工具库)                                             │
│  ─────────────────────────                                              │
│                                                                         │
│  21. brute (暴力破解框架)                                               │
│      ├── brute.Engine:new(driver, opts)                                 │
│      ├── brute:connect(host, port)                                      │
│      ├── brute:disconnect(socket)                                       │
│      ├── brute:check_user(user)                                         │
│      ├── brute:login(socket, user, pass)                                │
│      └── brute:start(host, port)                                        │
│                                                                         │
│  22. creds (凭据管理)                                                   │
│      ├── creds.Credentials:new()                                        │
│      ├── creds:add(state, user, pass, realm)                            │
│      ├── creds:get_all(state)                                           │
│      └── creds:get_table(state)                                         │
│                                                                         │
│  23. datafiles (数据文件)                                               │
│      ├── datafiles.read_file(filename)                                  │
│      └── datafiles.parse_file(filename, parser)                         │
│                                                                         │
│  24. target (目标管理)                                                  │
│      ├── target.add(host)                                               │
│      ├── target.addrs()                                                 │
│      └── target.is_local(host)                                          │
│                                                                         │
│  25. unpwdb (用户名密码数据库)                                          │
│      ├── unpwdb.usernames()                                             │
│      ├── unpwdb.passwords()                                             │
│      └── unpwdb.select_usernames(users)                                 │
│                                                                         │
│  26. stringaux (字符串辅助)                                             │
│      ├── stringaux.strsplit(sep, str)                                   │
│      ├── stringaux.filename_escape(str)                                 │
│      └── stringaux.to_xml(str)                                          │
│                                                                         │
│  27. tab (表格格式化)                                                   │
│      ├── tab.new(columns)                                               │
│      ├── tab.addrow(table, ...)                                         │
│      ├── tab.dump(table)                                                │
│      └── tab.sort(table, column)                                        │
│                                                                         │
│  28. json (JSON处理)                                                    │
│      ├── json.encode(data)                                              │
│      ├── json.decode(str)                                               │
│      └── json.generate(data)                                            │
│                                                                         │
│  29. base64 (Base64编码)                                                │
│      ├── base64.enc(data)                                               │
│      └── base64.dec(str)                                                │
│                                                                         │
│  30. bit (位操作)                                                       │
│      ├── bit.bxor(a, b)                                                 │
│      ├── bit.bor(a, b)                                                  │
│      ├── bit.band(a, b)                                                 │
│      └── bit.bnot(a)                                                    │
│                                                                         │
│  31. openssl (OpenSSL绑定)                                              │
│      ├── openssl.md5(data)                                              │
│      ├── openssl.sha1(data)                                             │
│      ├── openssl.sha256(data)                                           │
│      ├── openssl.bignum_new(num)                                        │
│      ├── openssl.encrypt(algo, key, data)                               │
│      └── openssl.decrypt(algo, key, data)                               │
│                                                                         │
│  32. packet (数据包构造)                                                │
│      ├── packet.Packet:new(data, force)                                 │
│      ├── packet.IP:new()                                                │
│      ├── packet.TCP:new()                                               │
│      ├── packet.UDP:new()                                               │
│      ├── packet.ICMP:new()                                              │
│      ├── packet.ARP:new()                                               │
│      └── packet.set_checksum(pkt)                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.5 NSE 脚本执行流程

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NSE Script Execution Pipeline                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: Script Loading & Parsing                                      │
│  ─────────────────────────────────                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                 │   │
│  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐   │   │
│  │   │   Script    │───▶│   Lua       │───▶│   Metadata      │   │   │
│  │   │   Files     │    │   Parser    │    │   Extraction    │   │   │
│  │   │   (*.nse)   │    │             │    │                 │   │   │
│  │   └─────────────┘    └─────────────┘    └─────────────────┘   │   │
│  │                                                 │               │   │
│  │                                                 ▼               │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │  ParsedScript {                                          │  │   │
│  │   │    id, description, categories,                          │  │   │
│  │   │    dependencies, portrule, hostrule, action              │  │   │
│  │   │  }                                                       │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Phase 2: Rule Evaluation & Filtering                                   │
│  ───────────────────────────────────                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                 │   │
│  │   Input: ScannedHost { ip, ports[], os[], ... }                │   │
│  │                                                                 │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │                Script Filter                             │  │   │
│  │   │                                                         │  │   │
│  │   │   For each script in scripts:                           │  │   │
│  │   │     if script.hostrule:                                 │  │   │
│  │   │       result = execute(script.hostrule, host)           │  │   │
│  │   │       if result == true: add to host_script_queue       │  │   │
│  │   │                                                         │  │   │
│  │   │     if script.portrule:                                 │  │   │
│  │   │       for port in host.ports:                           │  │   │
│  │   │        result = execute(script.portrule, host, port)    │  │   │
│  │   │        if result == true: add to port_script_queue      │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  │   Output: ScriptExecutionPlan                                  │   │
│  │   ├── host_scripts: Vec<(Script, Host)>                       │   │
│  │   └── port_scripts: Vec<(Script, Host, Port)>                 │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Phase 3: Script Execution                                              │
│  ─────────────────────────                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                                                                 │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │              Lua State Initialization                    │  │   │
│  │   │                                                         │  │   │
│  │   │   1. Create isolated Lua state                          │  │   │
│  │   │   2. Load standard libraries (base, table, string...)   │  │   │
│  │   │   3. Register NSE libraries (nmap, stdnse, http...)     │  │   │
│  │   │   4. Set script arguments (--script-args)               │  │   │
│  │   │   5. Load compiled script chunk                         │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                              │                                  │   │
│  │                              ▼                                  │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │                 Action Execution                         │  │   │
│  │   │                                                         │  │   │
│  │   │   For host scripts:                                     │  │   │
│  │   │     result = call(script.action, host)                  │  │   │
│  │   │                                                         │  │   │
│  │   │   For port scripts:                                     │  │   │
│  │   │     result = call(script.action, host, port)            │  │   │
│  │   │                                                         │  │   │
│  │   │   Timeout handling:                                     │  │   │
│  │   │     - Default timeout: script-timeout (default: 30s)    │  │   │
│  │   │     - Force terminate on timeout                        │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                              │                                  │   │
│  │                              ▼                                  │   │
│  │   ┌─────────────────────────────────────────────────────────┐  │   │
│  │   │                 Result Collection                        │  │   │
│  │   │                                                         │  │   │
│  │   │   ScriptResult {                                        │  │   │
│  │   │     script_id: String,                                  │  │   │
│  │   │     target: TargetInfo,                                 │  │   │
│  │   │     port: Option<Port>,                                 │  │   │
│  │   │     status: Status,  // Success, Failure, Timeout       │  │   │
│  │   │     output: String,                                     │  │   │
│  │   │     debug: Vec<String>,                                 │  │   │
│  │   │     duration: Duration,                                 │  │   │
│  │   │   }                                                     │  │   │
│  │   │                                                         │  │   │
│  │   └─────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.6 脚本调度器设计

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Script Scheduler Architecture                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Script Scheduler                              │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Priority Queue                            │  │  │
│  │  │                                                             │  │  │
│  │  │   Priority 1 (pre-scan scripts):                            │  │  │
│  │  │   ├── targets: IPv4 network discovery                       │  │  │
│  │  │   └── multicast/broadcast discovery                         │  │  │
│  │  │                                                             │  │  │
│  │  │   Priority 2 (host scripts):                                │  │  │
│  │  │   ├── Run after host discovery                             │  │  │
│  │  │   └── Examples: traceroute, asn-query                       │  │  │
│  │  │                                                             │  │  │
│  │  │   Priority 3 (port scripts):                                │  │  │
│  │  │   ├── Run after port scan complete                         │  │  │
│  │  │   └── Examples: http-vuln-*, ssh-auth-methods              │  │  │
│  │  │                                                             │  │  │
│  │  │   Priority 4 (post-scan scripts):                           │  │  │
│  │  │   ├── Run after all scans complete                         │  │  │
│  │  │   └── Examples: report generation, data aggregation         │  │  │
│  │  │                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                    │  │
│  │  ┌─────────────────────────────────────────────────────────────┐  │  │
│  │  │                  Thread Pool Executor                        │  │  │
│  │  │                                                             │  │  │
│  │  │   Config:                                                   │  │  │
│  │  │   ├── max_concurrent_scripts: usize                         │  │  │
│  │  │   ├── script_timeout: Duration                              │  │  │
│  │  │   ├── host_timeout: Duration                                │  │  │
│  │  │   └── max_retries: u8                                       │  │  │
│  │  │                                                             │  │  │
│  │  │   ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐        │  │  │
│  │  │   │Worker │ │Worker │ │Worker │ │Worker │ │Worker │        │  │  │
│  │  │   │  1    │ │  2    │ │  3    │ │  4    │ │  N    │        │  │  │
│  │  │   └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘        │  │  │
│  │  │       │         │         │         │         │             │  │  │
│  │  │       └─────────┴─────────┼─────────┴─────────┘             │  │  │
│  │  │                           │                                 │  │  │
│  │  │                     ┌─────▼─────┐                           │  │  │
│  │  │                     │  Result   │                           │  │  │
│  │  │                     │  Channel  │                           │  │  │
│  │  │                     └───────────┘                           │  │  │
│  │  │                                                             │  │  │
│  │  └─────────────────────────────────────────────────────────────┘  │  │
│  │                                                                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Dependency Resolution                                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   Script Dependency Graph:                                        │  │
│  │                                                                   │  │
│  │   ┌─────────┐     ┌─────────┐     ┌─────────┐                    │  │
│  │   │ http-   │────▶│ http-   │────▶│ http-   │                    │  │
│  │   │ headers │     │ auth   │     │ vuln-*  │                    │  │
│  │   └─────────┘     └─────────┘     └─────────┘                    │  │
│  │        │                                                          │  │
│  │        ▼          ┌─────────┐                                     │  │
│  │   ┌─────────┐     │ ssl-    │                                     │  │
│  │   │ http-   │────▶│ cert    │                                     │  │
│  │   │ enum    │     └─────────┘                                     │  │
│  │   └─────────┘                                                     │  │
│  │                                                                   │  │
│  │   Resolution Algorithm:                                           │  │
│  │   1. Build dependency DAG                                         │  │
│  │   2. Topological sort                                             │  │
│  │   3. Detect cycles (error on circular dependency)                │  │
│  │   4. Execute in dependency order                                  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5.7 NSE Rust 实现类型定义

```
// ============================================
// NSE Core Types (Rust Definition)
// ============================================

/// NSE 脚本元数据
pub struct NseScript {
    pub id: String,
    pub description: String,
    pub categories: Vec<ScriptCategory>,
    pub author: String,
    pub license: String,
    pub dependencies: Vec<String>,
    pub portrule: Option<LuaFunction>,
    pub hostrule: Option<LuaFunction>,
    pub action: LuaFunction,
    pub source: String,
    pub file_path: PathBuf,
}

/// 脚本分类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptCategory {
    Auth,       // 认证破解
    Broadcast,  // 广播发现
    Brute,      // 暴力破解
    Default,    // 默认脚本
    Discovery,  // 服务发现
    Dos,        // 拒绝服务
    Exploit,    // 漏洞利用
    External,   // 外部服务查询
    Fuzzer,     // 模糊测试
    Intrusive,  // 侵入性检查
    Malware,    // 恶意软件检测
    Safe,       // 安全检查
    Version,    // 版本检测
    Vuln,       // 漏洞检测
}

/// 脚本执行上下文
pub struct ScriptContext {
    pub host: Arc<HostInfo>,
    pub port: Option<Arc<PortInfo>>,
    pub registry: Arc<Mutex<LuaRegistry>>,
    pub script_args: HashMap<String, LuaValue>,
    pub timeout: Duration,
}

/// 脚本执行结果
pub struct ScriptResult {
    pub script_id: String,
    pub host_ip: IpAddr,
    pub port: Option<u16>,
    pub status: ExecutionStatus,
    pub output: ScriptOutput,
    pub start_time: Instant,
    pub duration: Duration,
    pub debug_log: Vec<String>,
}

/// 执行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Success,
    Failure,
    Timeout,
    Error,
}

/// 脚本输出（支持结构化数据）
pub enum ScriptOutput {
    Plain(String),
    Structured(LuaTable),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Xml(String),
    Json(serde_json::Value),
}

/// 脚本执行器
pub struct NseExecutor {
    lua: Lua,
    script: Arc<NseScript>,
    context: ScriptContext,
}

impl NseExecutor {
    /// 执行脚本
    pub async fn execute(&self) -> Result<ScriptResult, NseError> {
        // 1. 准备 Lua 环境
        self.prepare_lua_environment()?;
        
        // 2. 执行 action 函数
        let result = tokio::time::timeout(
            self.context.timeout,
            self.call_action()
        ).await;
        
        match result {
            Ok(Ok(output)) => Ok(ScriptResult {
                script_id: self.script.id.clone(),
                host_ip: self.context.host.ip,
                port: self.context.port.as_ref().map(|p| p.number),
                status: ExecutionStatus::Success,
                output,
                start_time: Instant::now(),
                duration: Duration::default(),
                debug_log: vec![],
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(NseError::Timeout),
        }
    }
}

/// 脚本调度器
pub struct ScriptScheduler {
    script_db: ScriptDatabase,
    thread_pool: ThreadPool,
    config: SchedulerConfig,
}

/// 脚本数据库
pub struct ScriptDatabase {
    scripts: HashMap<String, Arc<NseScript>>,
    by_category: HashMap<ScriptCategory, Vec<String>>,
    by_port: HashMap<u16, Vec<String>>,
    by_service: HashMap<String, Vec<String>>,
}

/// 调度器配置
pub struct SchedulerConfig {
    pub max_concurrent: usize,
    pub default_timeout: Duration,
    pub script_timings: ScriptTimings,
}

/// 脚本时序配置
pub struct ScriptTimings {
    pub pre_scan_timeout: Duration,
    pub host_script_timeout: Duration,
    pub port_script_timeout: Duration,
    pub post_scan_timeout: Duration,
}
```

### 3.5.5 NSE 实现细节

基于 Nmap `nse_main.cc/h`, `nse_nmaplib.cc` 的实现。

#### 3.5.5.1 核心数据结构 (Nmap 源码映射)

```rust
// 对应 Nmap nse_main.h 中的 ScriptResult
pub struct NseScriptResult {
    // 脚本标识符
    pub id: Cow<'static, str>,

    // 结构化输出表 (在 LUA_REGISTRYINDEX 中的引用)
    pub output_ref: i32,

    // 原始输出字符串
    pub output_str: String,
}

impl NseScriptResult {
    // 对应 get_output_str()
    pub fn get_output_string(&self) -> Cow<'static, str> {
        if self.output_ref != LUA_NOREF {
            // 从注册表获取输出
            get_registry_output(self.output_ref)
        } else {
            Cow::Borrowed(&self.output_str)
        }
    }

    // 对应 write_xml()
    pub fn write_xml(&self) {
        // 将脚本结果输出为 XML
        xml::start_element("script");
        xml::attribute("id", self.id);
        xml::attribute("output", self.get_output_string());
        xml::end_element();
    }

    // 对应 operator<
    impl Ord for NseScriptResult {
        fn cmp(&self, other: &Self) -> Ordering {
            strcmp(self.id, other.id) < 0
        }
    }
}

// 对应 ScriptResults = std::multiset<ScriptResult*>
pub struct NseScriptResults {
    results: BTreeSet<NseScriptResult>,
}

// 对应 nse_main.h 中的函数
impl NseScriptResults {
    // 对应 get_script_scan_results_obj()
    pub fn new() -> Self {
        Self {
            results: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, result: NseScriptResult) {
        self.results.insert(result);
    }

    pub fn iter(&self) -> impl Iterator<Item = &NseScriptResult> {
        self.results.iter()
    }
}
```

#### 3.5.5.2 Lua 状态管理

```rust
// 对应 nse_yield(), nse_restore() - 协程支持
pub struct NseCoroutine {
    lua_state: *mut lua_State,
    continuation_index: i32,
    saved_stack_top: i32,
}

impl NseCoroutine {
    // 对应 nse_yield()
    pub fn yield(&mut self, nresults: i32) -> Result<()> {
        unsafe {
            // 保存当前状态
            self.saved_stack_top = lua_gettop(self.lua_state);

            // 创建续体
            self.continuation_index = lua_getctx(
                self.lua_state,
                nresults,
            )?;

            // 返回给调用者
            lua_yield(self.lua_state, nresults);
        }

        Ok(())
    }

    // 对应 nse_restore()
    pub fn restore(&mut self, args: &[LuaValue]) -> Result<()> {
        unsafe {
            // 恢复栈
            lua_settop(self.lua_state, self.saved_stack_top);

            // 传递参数给续体
            for arg in args {
                lua_pushvalue(self.lua_state, arg);
            }

            // 恢复执行
            lua_resume(self.lua_state, args.len());
        }

        Ok(())
    }
}
```

#### 3.5.5.3 Nmap 库绑定 (nse_nmaplib.cc)

```rust
// 对应 set_version() - 暴露服务版本信息到 Lua
fn expose_service_version(lua: &mut LuaState,
                           sd: &ServiceDeductions) {
    let version_table = lua.create_table(0, NSE_NUM_VERSION_FIELDS);

    // name
    if let Some(name) = sd.name {
        lua.set_field("name", name);
    }

    // name_confidence (0-10)
    lua.set_field("name_confidence", sd.name_confidence);

    // product
    if let Some(product) = sd.product {
        lua.set_field("product", product);
    }

    // version
    if let Some(version) = sd.version {
        lua.set_field("version", version);
    }

    // extrainfo
    if let Some(extrainfo) = sd.extrainfo {
        lua.set_field("extrainfo", extrainfo);
    }

    // hostname
    if let Some(hostname) = sd.hostname {
        lua.set_field("hostname", hostname);
    }

    // ostype
    if let Some(ostype) = sd.ostype {
        lua.set_field("ostype", ostype);
    }

    // devicetype
    if let Some(devicetype) = sd.devicetype {
        lua.set_field("devicetype", devicetype);
    }

    // service_tunnel ("none" 或 "ssl")
    let tunnel = match sd.service_tunnel {
        SERVICE_TUNNEL_NONE => "none",
        SERVICE_TUNNEL_SSL => "ssl",
    };
    lua.set_field("service_tunnel", tunnel);

    // service_fp (用于提交的指纹)
    if let Some(fp) = sd.service_fp {
        lua.set_field("service_fp", fp);
    }

    // service_dtype ("table" 或 "probed")
    let dtype = match sd.dtype {
        SERVICE_DETECTION_TABLE => "table",
        SERVICE_DETECTION_PROBED => "probed",
    };
    lua.set_field("service_dtype", dtype);

    // cpe (数组)
    let cpe_table = lua.create_table(sd.cpe.len(), 0);
    for (i, cpe) in sd.cpe.iter().enumerate() {
        lua.push_string(cpe);
        lua.raw_set_i(cpe_table, (i + 1) as i32);
    }
    lua.set_field("cpe", cpe_table);
}

// 对应 set_portinfo() - 暴露端口信息到 Lua
fn expose_port_info(lua: &mut LuaState,
                     target: &Target,
                     port: &Port) {
    let port_table = lua.create_table(0, 4);

    // port number
    lua.set_field("number", port.portno);

    // service name
    let mut sd = ServiceDeductions::default();
    target.get_service_deductions(port.portno, port.proto, &mut sd);

    if let Some(name) = sd.name {
        lua.set_field("service", name);
    }

    // protocol
    let proto_str = ipproto2str(port.proto);
    lua.set_field("protocol", proto_str);

    // state
    let state_str = statenum2str(port.state);
    lua.set_field("state", state_str);

    // reason
    let reason_str = reason_str(port.reason.reason_id, true);
    lua.set_field("reason", reason_str);

    // reason_ttl
    lua.set_field("reason_ttl", port.reason.ttl);

    // version 子表
    let version_table = lua.create_table(0, NSE_NUM_VERSION_FIELDS);
    expose_service_version_to_table(lua, &sd, version_table);
    lua.set_field("version", version_table);
}
```

#### 3.5.5.4 套接字绑定 (nse_nsock.cc)

```rust
// 对应 nsock 库的 Rust 封装
pub struct NseSocket {
    inner: Socket,
    protocol: Protocol,
    timeout: Duration,
    address_family: AddressFamily,
}

// 套接字操作 (对应 NSE socket API)
impl NseSocket {
    // 对应 nsock_connect()
    pub async fn connect(addr: &SocketAddr) -> Result<Self> {
        Ok(Self {
            inner: Socket::connect(addr).await?,
            protocol: Protocol::detect(addr)?,
            timeout: Duration::from_secs(30),
            address_family: addr.family(),
        })
    }

    // 对应 nsock_send()
    pub async fn send(&mut self, data: &[u8]) -> Result<usize> {
        let n = self.inner.write(data).await?;
        Ok(n)
    }

    // 对应 nsock_receive()
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.read(buf).await?;
        Ok(n)
    }

    // 对应 nsock_close()
    pub fn close(mut self) -> Result<()> {
        self.inner.shutdown()?;
        Ok(())
    }
}

// 将套接字暴露给 Lua
fn register_socket_type(lua: &mut LuaState) {
    lua.register_type::<NseSocket>("nsock.Socket");

    // 方法: connect
    lua.register_method("connect", |lua, this| {
        let addr = lua.check_string(1)?;
        let socket = NseSocket::connect(&addr).await?;
        lua.push_userdata(socket);
        Ok(1)
    });

    // 方法: send
    lua.register_method("send", |lua, this| {
        let socket = lua.check_userdata::<NseSocket>(0)?;
        let data = lua.check_string(1)?;
        let n = socket.send(data.as_bytes()).await?;
        lua.push_integer(n as i64);
        Ok(1)
    });

    // 方法: receive
    lua.register_method("receive", |lua, this| {
        let socket = lua.check_userdata::<NseSocket>(0)?;
        let mut buf = vec![0u8; 4096];
        let n = socket.receive(&mut buf).await?;
        lua.push_lstring(&buf[..n]);
        Ok(1)
    });

    // 方法: close
    lua.register_method("close", |lua, this| {
        let mut socket = lua.check_userdata::<NseSocket>(0)?;
        socket.close()?;
        Ok(1)
    });
}
```

#### 3.5.5.5 脚本加载和选择

> **实现状态**: ⚠️ **部分实现** - 当前只支持类别选择，不支持脚本名/glob模式
>
> **当前限制**:
> - ✅ 支持: `--script discovery`, `--script vuln` (类别)
> - ❌ 不支持: `--script banner` (脚本名)
> - ❌ 不支持: `--script http*` (glob模式)
> - ❌ 不支持: `--script "/path/to/script.nse"` (文件路径)
>
> **实现位置**:
> - CLI: `crates/rustnmap-cli/src/cli.rs:1195-1197`
> - Orchestrator: `crates/rustnmap-core/src/orchestrator.rs:2393-2423`
>
> **设计规范** (参考 Nmap `nse_main.lua:724-812`):

```rust
// 对应 nse_selectedbyname() - 脚本选择
pub struct ScriptSelector {
    database: ScriptDatabase,
    selected: Vec<Arc<NseScript>>,
}

impl ScriptSelector {
    // 对应 Nmap 的 --script 参数处理
    pub fn select_scripts(&mut self,
                           patterns: Vec<String>,
                           categories: Vec<ScriptCategory>)
        -> Result<Vec<Arc<NseScript>>> {
        let mut result = Vec::new();

        // 处理文件名模式 (e.g., "vuln")
        for pattern in &patterns {
            if pattern.contains('/') || pattern.contains('.') {
                // 直接文件路径
                let script = self.database.load_script(pattern)?;
                result.push(script);
            } else {
                // 通配符匹配
                for script in self.database.find_by_name(pattern)? {
                    result.push(script.clone());
                }
            }
        }
        }

        // 处理类别选择 (e.g., "default", "vuln")
        if !categories.is_empty() {
            for script in self.database.all_scripts() {
                if script.categories.iter()
                    .any(|c| categories.contains(c)) {
                    if !result.contains(&script) {
                        result.push(script.clone());
                    }
                }
            }
        }
        }

        // 解析依赖关系
        self.resolve_dependencies(&mut result)?;

        Ok(result)
    }

    // 递归解析依赖
    fn resolve_dependencies(&self, scripts: &mut Vec<Arc<NseScript>>)
        -> Result<()> {
        let mut resolved = std::collections::HashSet::new();

        for script in scripts.iter() {
            self.resolve_script_dependencies(script, &mut resolved)?;
        }
    }
}
```

#### 3.5.5.6a NSE 库注册机制

NSE 标准库由 Rust 实现，通过 mlua FFI 暴露给 Lua 脚本。在执行任何脚本之前，必须先注册这些库。

```rust
// NSE 标准库注册
//
// rustnmap-nse/src/libs/mod.rs
pub fn register_all(lua: &mut NseLua) -> Result<()> {
    // 注册核心 NSE 库，使脚本可以通过 require() 访问
    nmap::register(lua)?;      // nmap 库 - 核心扫描功能
    stdnse::register(lua)?;    // stdnse 库 - 标准扩展函数
    comm::register(lua)?;      // comm 库 - 网络通信
    shortport::register(lua)?; // shortport 库 - 端口规则匹配
    Ok(())
}
```

**注册时机：**

库注册必须在 Lua 状态创建后、脚本加载前执行：

```
┌─────────────────────────────────────────────────────────────┐
│  1. Lua::new()          - 创建 Lua 状态                      │
│  2. register_all()      - 注册 NSE 库                        │
│  3. load(script)        - 加载脚本 (脚本中使用 require())    │
│  4. set_global(host)    - 设置 host 表                       │
│  5. call(action)        - 执行脚本                           │
└─────────────────────────────────────────────────────────────┘
```

**库依赖示例：**

脚本中使用这些库：
```lua
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"

portrule = shortport.http

action = function(host, port)
    return stdnse.format_output(true, { "test" })
end
```

**实现位置：**
- runner 二进制: `crates/rustnmap-nse/src/bin/runner.rs::execute_script()`
- 主执行引擎: `crates/rustnmap-nse/src/engine.rs::execute_script()`

#### 3.5.5.6 脚本执行引擎

```rust
// 对应 script_scan() - 主扫描函数
pub struct ScriptEngine {
    lua: Lua,
    scripts: Vec<Arc<NseScript>>,
    targets: Vec<Target>,
    config: EngineConfig,
}

impl ScriptEngine {
    // 对应 nse_main.cc::script_scan()
    pub async fn scan_targets(&mut self, targets: Vec<Target>)
        -> Result<Vec<NseScriptResults>> {
        let mut all_results = Vec::new();

        for target in targets {
            // 获取目标的所有端口
            let ports = target.get_ports();

            // Pre-scan scripts (hostrule)
            let pre_scripts = self.filter_pre_scan_scripts();
            for script in pre_scripts {
                let ctx = ScriptContext::new(target.clone(), None);
                let result = self.execute_script(script, ctx).await?;
                all_results.push(result);
            }

            // Port scripts (portrule)
            for port in ports {
                let port_scripts = self.filter_port_scripts(port)?;
                for script in port_scripts {
                    let ctx = ScriptContext::new(
                        target.clone(),
                        Some(port.clone())
                    );
                    let result = self.execute_script(script, ctx).await?;
                    all_results.push(result);
                }
            }

            // Post-scan scripts
            let post_scripts = self.filter_post_scan_scripts();
            for script in post_scripts {
                let ctx = ScriptContext::new(target.clone(), None);
                let result = self.execute_script(script, ctx).await?;
                all_results.push(result);
            }
        }

        Ok(all_results)
    }

    // 执行单个脚本
    async fn execute_script(&self,
                               script: &Arc<NseScript>,
                               context: ScriptContext)
        -> Result<NseScriptResult> {
        // 设置超时
        let timeout = context.timeout
            .max(script.specific_timeout)
            .unwrap_or(self.config.default_timeout);

        // 在协程中执行
        match tokio::time::timeout(timeout, self.run_lua(script)).await {
            Ok(Ok(output)) => Ok(NseScriptResult {
                id: script.id.clone(),
                output_ref: store_in_registry(output),
                output_str: String::new(),
            }),
            Ok(Err(NseError::Timeout)) => {
                Ok(NseScriptResult {
                    id: script.id.clone(),
                    output_ref: LUA_NOREF,
                    output_str: format!("TIMEOUT"),
                })
            }
            Err(e) => Err(e),
        }
    }

    // 准备 Lua 环境
    fn prepare_lua_environment(&self, context: &ScriptContext)
        -> Result<()> {
        // Step 1: 注册 NSE 标准库 (必须在加载脚本之前)
        // 这些库由 Rust 实现并通过 mlua FFI 暴露给 Lua
        rustnmap_nse::libs::register_all(&mut self.lua)?;

        // Step 2: 创建 host 表
        let host_table = create_host_table(&context.host)?;
        self.lua.set_global("host", host_table)?;

        // Step 3: 创建 port 表 (如果存在)
        if let Some(port) = &context.port {
            let port_table = create_port_table(port)?;
            self.lua.set_global("port", port_table)?;
        }

        // Step 4: 设置注册表
        self.lua.set_global("registry", context.registry.clone())?;

        Ok(())
    }
}
```

#### 3.5.5.7 常量定义 (Nmap 源码映射)

```rust
// 对应 nse_main.h
pub const SCRIPT_ENGINE: &str = "NSE";
pub const SCRIPT_ENGINE_LUA_DIR: &str = "scripts/";
pub const SCRIPT_ENGINE_LIB_DIR: &str = "nselib/";
pub const SCRIPT_ENGINE_DATABASE: &str = "scripts/script.db";
pub const SCRIPT_ENGINE_EXTENSION: &str = ".nse";

// 对应 nse_nmaplib.cc
pub const NSE_NUM_VERSION_FIELDS: i32 = 12;

// 对应 nse_main.h 中的协议定义
pub const NSE_PROTOCOL_OP: [&str] = ["tcp", "udp", "sctp"];
pub const NSE_PROTOCOL: [i32] = [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP];

// 对应 nse_lua.h
pub const LUA_REGISTRYINDEX: i32 = -10000;
pub const LUA_NOREF: i32 = -10001;
pub const LUA_OK: i32 = 0;
pub const LUA_YIELD: i32 = 1;
pub const LUA_ERRRUN: i32 = 2;
pub const LUA_ERRSYNTAX: i32 = 3;
pub const LUA_ERRMEM: i32 = 4;
pub const LUA_ERRERR: i32 = 5;
```

#### 3.5.5.8 资源限制与沙箱 (Deepseek 增强)

##### Lua 内存限制

```rust
use mlua::{Lua, Error as LuaError};

/// NSE 执行器配置
pub struct NseExecutorConfig {
    /// 最大内存使用量 (字节)
    pub memory_limit: usize,
    /// CPU 时间限制 (秒)
    pub cpu_timeout: Duration,
    /// 指令计数间隔 (每 N 条指令检查时间)
    pub instruction_check_interval: u32,
}

impl Default for NseExecutorConfig {
    fn default() -> Self {
        Self {
            memory_limit: 10 * 1024 * 1024,  // 10MB
            cpu_timeout: Duration::from_secs(5),
            instruction_check_interval: 1000,
        }
    }
}

impl NseExecutor {
    /// 创建受限的 Lua 环境
    pub fn new_with_limits(config: NseExecutorConfig) -> Result<Self, NseError> {
        // 创建 Lua 实例并启用沙箱
        let lua = Lua::new_with(
            mlua::LuaOptions {
                sandbox: true,  // 启用沙箱模式
                ..Default::default()
            }
        )?;

        // 设置内存限制
        #[cfg(feature = "lua_memory_limit")]
        lua.set_memory_limit(config.memory_limit)?;

        // 设置指令钩子 (CPU 时间限制)
        lua.set_hook(
            mlua::HookMask::COUNT,
            config.instruction_check_interval,
        )?;

        Ok(Self { lua, config })
    }

    /// 指令钩子 (检查 CPU 时间)
    fn hook_callback(&self, lua: &Lua) -> Result<(), mlua::Error> {
        static START_TIME: std::sync::Mutex<HashMap<usize, Instant>> =
            std::sync::Mutex::new(HashMap::new());

        let lua_id = lua.id();
        let mut times = START_TIME.lock().unwrap();
        let start = times.entry(lua_id).or_insert_with(Instant::now);

        if start.elapsed() > self.config.cpu_timeout {
            return Err(mlua::Error::RuntimeError(
                "Script CPU time limit exceeded".to_string()
            ));
        }

        Ok(())
    }
}
```

##### SELinux 策略集成

```bash
# /usr/share/selinux/packages/rustnmap.pp
# RustNmap SELinux 策略模块

policy_module(rustnmap, 1.0.0)

# 允许 rustnmap 使用网络套接字
allow rustnmap_t self:capabil2 { net_raw net_admin };

# 允许写入指纹库目录
allow rustnmap_t rustnmap_var_lib_t:file { create write setattr unlink };

# 允许读取系统指纹库
allow rustnmap_t fingerprint_file_t:file { read open getattr };

# 允许 systemd timer 管理
allow rustnmap_t systemd_unit_file_t:file { read open };
```

##### 脚本版本检查

```lua
-- NSE 脚本版本声明示例
-- @nse_version 1.0.0

description = [[Example script with version requirement]]

-- 脚本逻辑
action = function(host, port)
    -- 如果引擎版本 < 1.0.0，此脚本将拒绝加载
    return "Script executed successfully"
end
```

```rust
/// 脚本版本检查
pub fn check_script_compatibility(
    script: &NseScript,
    engine_version: &Version,
) -> Result<(), NseError> {
    if let Some(req_version) = &script.required_version {
        if req_version > &engine_version {
            return Err(NseError::IncompatibleVersion {
                script: script.id.clone(),
                required: req_version.clone(),
                current: engine_version.clone(),
            });
        }
    }
    Ok(())
}
```

#### 3.5.6 脚本自动更新机制

基于 Deepseek 设计文档的指纹库自动更新。

##### systemd Timer 配置

```ini
# /usr/lib/systemd/system/rustnmap-update-fingerprint.service
[Unit]
Description=RustNmap Fingerprint Database Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/rustnmap --fingerprint-update
User=rustnmap
Group=rustnmap
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
```

```ini
# /usr/lib/systemd/systemd/rustnmap-update-fingerprint.timer
[Unit]
Description=Weekly RustNmap Fingerprint Update
Requires=rustnmap-update-fingerprint.service

[Timer]
OnCalendar=Tue 03:00  # 每周二凌晨3点
Persistent=true

[Install]
WantedBy=timers.target
```

##### MVCC 存储模式

```rust
use std::path::{Path, PathBuf};
use std::fs;

/// MVCC 指纹库管理器
pub struct FingerprintStore {
    base_dir: PathBuf,
    current_symlink: PathBuf,
}

impl FingerprintStore {
    pub fn new(base_dir: PathBuf) -> Self {
        let current_symlink = base_dir.join("current");
        Self {
            base_dir,
            current_symlink,
        }
    }

    /// 安装新版本 (原子切换)
    pub fn install_version(&self, data: &[u8]) -> Result<(), StoreError> {
        // 1. 生成唯一版本标识 (时间戳 + 序列号)
        let version_id = format!(
            "r{}_{:02}",
            chrono::Utc::now().format("%Y%m%d"),
            fastrand::u16(0..=99)
        );
        let version_dir = self.base_dir.join(&version_id);

        // 2. 创建临时目录
        let tmp_dir = self.base_dir.join(format!("tmp_{}", version_id));
        fs::create_dir_all(&tmp_dir)?;

        // 3. 写入新数据
        let data_path = tmp_dir.join("nmap-os-db");
        fs::write(&data_path, data)?;

        // 4. 原子性重命名
        fs::rename(&tmp_dir, &version_dir)?;

        // 5. 创建备份 (硬链接)
        let backup = self.create_backup()?;

        // 6. 原子性切换符号链接
        let tmp_link = self.base_dir.join("current.tmp");
        self.create_symlink(&version_dir, &tmp_link)?;
        fs::rename(&tmp_link, &self.current_symlink)?;

        // 7. 验证新版本
        if let Err(e) = self.verify_version(&version_dir) {
            // 回滚到备份
            self.rollback_to_backup(&backup)?;
            return Err(e);
        }

        Ok(())
    }

    /// 创建版本符号链接
    fn create_symlink(&self, target: &Path, link: &Path) -> Result<(), StoreError> {
        use std::os::unix::fs::symlink;

        // 删除旧链接
        let _ = fs::remove_file(link);

        // 创建新链接
        symlink(target, link)?;
        Ok(())
    }

    /// 验证版本完整性
    fn verify_version(&self, version_dir: &Path) -> Result<(), StoreError> {
        let db_path = version_dir.join("nmap-os-db");

        // 检查文件存在
        if !db_path.exists() {
            return Err(StoreError::Corrupted);
        }

        // 计算 SHA256 校验和
        let hash = self.compute_sha256(&db_path)?;

        // 对比预期校验和 (从签名文件)
        let expected = self.load_expected_hash()?;

        if hash != expected {
            return Err(StoreError::ChecksumMismatch);
        }

        Ok(())
    }

    /// 回滚到备份版本
    fn rollback_to_backup(&self, backup: &Path) -> Result<(), StoreError> {
        let tmp_link = self.base_dir.join("current.tmp");
        self.create_symlink(backup, &tmp_link)?;
        fs::rename(&tmp_link, &self.current_symlink)?;
        Ok(())
    }
}
```

---
