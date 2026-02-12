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

---

