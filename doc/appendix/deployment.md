# 附录 C: Linux x86_64 部署指南

## C.1 系统要求

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Linux 系统要求 (x86_64)                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  操作系统:                                                              │
│  ├── Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS                          │
│  ├── Debian 11 (Bullseye) / 12 (Bookworm)                              │
│  ├── CentOS 7 / Rocky Linux 8+ / AlmaLinux 8+                           │
│  ├── Fedora 38+                                                         │
│  ├── Arch Linux                                                         │
│  └── 其他主流 Linux 发行版 (glibc 2.17+)                                │
│                                                                         │
│  架构:                                                                  │
│  └── x86_64 (AMD64)                                                    │
│                                                                         │
│  内核版本:                                                              │
│  ├── 基础功能: Linux 3.10+                                             │
│  ├── PACKET_MMAP: Linux 2.6.22+                                        │
│  ├── eBPF 过滤: Linux 3.18+                                             │
│  ├── AF_XDP: Linux 4.18+ (可选，高性能模式)                            │
│  └── MSG_ZEROCOPY: Linux 4.14+ (可选)                                  │
│                                                                         │
│  依赖库:                                                                │
│  ├── libpcap 0.8+ (可选，用于兼容性)                                   │
│  ├── Lua 5.4 / LuaJIT 2.1+                                             │
│  ├── glibc 2.17+                                                        │
│  └── libcap 2.22+ (用于 capabilities 支持)                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## C.2 编译安装

```bash
# 1. 安装编译依赖
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libpcap-dev \
    liblua5.4-dev \
    libcap-dev \
    libssl-dev

# Fedora/RHEL/CentOS:
sudo dnf install -y \
    gcc \
    gcc-c++ \
    pkg-config \
    libpcap-devel \
    lua-devel \
    libcap-devel \
    openssl-devel

# 2. 克隆源码
git clone https://github.com/example/rustnmap.git
cd rustnmap

# 3. 编译发布版本
cargo build --release

# 4. 安装到系统
sudo install -m 755 target/release/rustnmap /usr/local/bin/
sudo install -m 644 doc/rustnmap.1 /usr/local/share/man/man1/

# 5. 安装数据文件
sudo mkdir -p /usr/local/share/rustnmap
sudo cp -r data/* /usr/local/share/rustnmap/
sudo cp -r scripts/* /usr/local/share/rustnmap/scripts/
```

## C.3 权限配置

```bash
# 方案 A: 使用 Linux Capabilities (推荐)
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/rustnmap

# 验证权限
getcap /usr/local/bin/rustnmap
# 输出: /usr/local/bin/rustnmap = cap_net_admin,cap_net_raw+ep

# 方案 B: 配置 sudo (多用户环境)
sudo visudo
# 添加以下行:
# username ALL=(ALL) NOPASSWD: /usr/local/bin/rustnmap

# 方案 C: Docker 容器运行
docker run --rm \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --network=host \
    rustnmap/rustnmap:latest \
    rustnmap -sS target.example.com
```

## C.4 systemd 服务配置

```ini
# /etc/systemd/system/rustnmapd.service
[Unit]
Description=RustNmap Scanner Service
After=network.target
Documentation=man:rustnmap(1) https://github.com/example/rustnmap

[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/local/bin/rustnmapd --daemon
Restart=on-failure
RestartSec=5s

# 安全设置
# PrivateTmp=true
# NoNewPrivileges=true
# 注意: 需要保留网络能力，所以不能使用 NoNewPrivileges

# 赋予必要的 capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# 资源限制
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

## C.5 SELinux 配置

```bash
# 创建 SELinux 策略模块 (如果 SELinux 启用)
cat > rustnmap.te << 'EOF'
module rustnmap 1.0;

require {
    type net_raw_capability;
    type net_admin_capability;
    type usr_t;
    type proc_net_type;
    type sysctl_net_t;
    class capability { net_raw net_admin };
    class file { ioctl read open };
    class dir { read search };
}

# 允许使用 raw socket
allow usr_t self:capability net_raw;

# 允许网络管理
allow usr_t self:capability net_admin;

# 允许读取网络配置
allow usr_t proc_net_type:file { ioctl read open };
allow usr_t proc_net_type:dir { read search };
EOF

# 编译并加载策略
checkmodule -M -m -o rustnmap.mod rustnmap.te
semodule_package -o rustnmap.pp -m rustnmap.mod
sudo semodule -i rustnmap.pp
```

## C.6 性能调优

```bash
# 1. CPU 亲和性绑定
taskset -c 0-7 rustnmap -sS target  # 绑定到 CPU 0-7

# 2. 大页内存配置 (用于 PACKET_MMAP)
echo 100 > /proc/sys/vm/nr_hugepages
# 或在 /etc/sysctl.conf 中添加:
# vm.nr_hugepages = 100

# 3. 网络缓冲区调优
# 在 /etc/sysctl.conf 中添加:
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192

# 应用配置
sudo sysctl -p

# 4. 中断负载均衡
# 将网卡中断分散到多个 CPU
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > $i  # 使用 CPU 0-7
done
```

## C.7 故障排除

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    常见问题排查                                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  问题 1: "Permission denied" 或 "Operation not permitted"                │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 原因: 缺少 CAP_NET_RAW 权限                                       │  │
│  │ 解决:                                                           │  │
│  │   $ sudo setcap cap_net_raw+ep /usr/local/bin/rustnmap           │  │
│  │   $ getcap /usr/local/bin/rustnmap                               │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  问题 2: "Failed to create socket: AF_PACKET"                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 原因: 内核太旧或 CONFIG_PACKET 未编译                             │  │
│  │ 解决:                                                           │  │
│  │   $ uname -r  # 检查内核版本                                      │  │
│  │   $ zcat /proc/config.gz | grep CONFIG_PACKET  # 检查配置        │  │
│  │   如果未启用，需要重新编译内核或升级                              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  问题 3: "setcap: failed to set capabilities"                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 原因: 文件系统不支持 extended attributes 或没有权限              │  │
│  │ 解决:                                                           │  │
│  │   $ mount | grep /usr/local  # 检查文件系统挂载选项              │  │
│  │   确保没有 nosuid 选项                                           │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  问题 4: SELinux 阻止网络操作                                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 原因: SELinux 策略不允许                                           │  │
│  │ 解决:                                                           │  │
│  │   $ sudo ausearch -m avc -ts recent  # 查看 SELinux 审计日志     │  │
│  │   $ sudo setenforce 0  # 临时禁用 (仅用于测试)                   │  │
│  │   参考 C.5 节配置 SELinux 策略                                    │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  问题 5: 扫描速度慢                                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ 可能原因和解决方案:                                               │  │
│  │   1. 检查时序模板: 使用 -T4 或 -T5                                │  │
│  │   2. 检查并发数: --max-parallelism                                │  │
│  │   3. 启用 PACKET_MMAP: 检查内核版本 >= 2.6.22                    │  │
│  │   4. CPU 亲和性: 使用 taskset 绑定 CPU                            │  │
│  │   5. 网络缓冲区: 调整 net.core.* 参数                             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
