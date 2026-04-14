# Appendix C: Linux x86_64 Deployment Guide

## C.1 System Requirements

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Linux System Requirements (x86_64)                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Operating System:                                                      │
│  ├── Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS                          │
│  ├── Debian 11 (Bullseye) / 12 (Bookworm)                              │
│  ├── CentOS 7 / Rocky Linux 8+ / AlmaLinux 8+                           │
│  ├── Fedora 38+                                                         │
│  ├── Arch Linux                                                         │
│  └── Other mainstream Linux distributions (glibc 2.17+)                 │
│                                                                         │
│  Architecture:                                                          │
│  └── x86_64 (AMD64)                                                    │
│                                                                         │
│  Kernel Version:                                                        │
│  ├── Basic functionality: Linux 3.10+                                  │
│  ├── PACKET_MMAP: Linux 2.6.22+                                        │
│  ├── eBPF filtering: Linux 3.18+                                        │
│  ├── AF_XDP: Linux 4.18+ (optional, high-performance mode)             │
│  └── MSG_ZEROCOPY: Linux 4.14+ (optional)                              │
│                                                                         │
│  Dependencies:                                                          │
│  ├── libpcap 0.8+ (optional, for compatibility)                        │
│  ├── Lua 5.4 / LuaJIT 2.1+                                             │
│  ├── glibc 2.17+                                                        │
│  └── libcap 2.22+ (for capabilities support)                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## C.2 Build and Install

```bash
# 1. Install build dependencies
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

# 2. Clone source
git clone https://github.com/example/rustnmap.git
cd rustnmap

# 3. Build release version
cargo build --release

# 4. Install to system
sudo install -m 755 target/release/rustnmap /usr/local/bin/
sudo install -m 644 doc/rustnmap.1 /usr/local/share/man/man1/

# 5. Install data files
sudo mkdir -p /usr/local/share/rustnmap
sudo cp -r data/* /usr/local/share/rustnmap/
sudo cp -r scripts/* /usr/local/share/rustnmap/scripts/
```

## C.3 Permission Configuration

```bash
# Option A: Use Linux Capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/rustnmap

# Verify permissions
getcap /usr/local/bin/rustnmap
# Output: /usr/local/bin/rustnmap = cap_net_admin,cap_net_raw+ep

# Option B: Configure sudo (multi-user environment)
sudo visudo
# Add the following line:
# username ALL=(ALL) NOPASSWD: /usr/local/bin/rustnmap

# Option C: Run in Docker container
docker run --rm \
    --cap-add=NET_RAW \
    --cap-add=NET_ADMIN \
    --network=host \
    rustnmap/rustnmap:latest \
    rustnmap -sS target.example.com
```

## C.4 systemd Service Configuration

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

# Security settings
# PrivateTmp=true
# NoNewPrivileges=true
# Note: Network capabilities must be preserved, so NoNewPrivileges cannot be used

# Grant necessary capabilities
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

## C.5 SELinux Configuration

```bash
# Create SELinux policy module (if SELinux is enabled)
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

# Allow raw socket usage
allow usr_t self:capability net_raw;

# Allow network administration
allow usr_t self:capability net_admin;

# Allow reading network configuration
allow usr_t proc_net_type:file { ioctl read open };
allow usr_t proc_net_type:dir { read search };
EOF

# Compile and load policy
checkmodule -M -m -o rustnmap.mod rustnmap.te
semodule_package -o rustnmap.pp -m rustnmap.mod
sudo semodule -i rustnmap.pp
```

## C.6 Performance Tuning

```bash
# 1. CPU affinity binding
taskset -c 0-7 rustnmap -sS target  # Bind to CPU 0-7

# 2. Huge pages configuration (for PACKET_MMAP)
echo 100 > /proc/sys/vm/nr_hugepages
# Or add to /etc/sysctl.conf:
# vm.nr_hugepages = 100

# 3. Network buffer tuning
# Add to /etc/sysctl.conf:
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192

# Apply configuration
sudo sysctl -p

# 4. Interrupt load balancing
# Distribute NIC interrupts across multiple CPUs
for i in /sys/class/net/eth0/queues/rx-*/rps_cpus; do
    echo f > $i  # Use CPU 0-7
done
```

## C.7 Troubleshooting

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Common Issues Troubleshooting                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Issue 1: "Permission denied" or "Operation not permitted"              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Cause: Missing CAP_NET_RAW capability                             │  │
│  │ Solution:                                                         │  │
│  │   $ sudo setcap cap_net_raw+ep /usr/local/bin/rustnmap            │  │
│  │   $ getcap /usr/local/bin/rustnmap                                │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Issue 2: "Failed to create socket: AF_PACKET"                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Cause: Kernel too old or CONFIG_PACKET not compiled               │  │
│  │ Solution:                                                         │  │
│  │   $ uname -r  # Check kernel version                              │  │
│  │   $ zcat /proc/config.gz | grep CONFIG_PACKET  # Check config     │  │
│  │   If not enabled, recompile kernel or upgrade                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Issue 3: "setcap: failed to set capabilities"                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Cause: Filesystem does not support extended attributes or no      │  │
│  │        permission                                                 │  │
│  │ Solution:                                                         │  │
│  │   $ mount | grep /usr/local  # Check filesystem mount options    │  │
│  │   Ensure no nosuid option                                         │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Issue 4: SELinux blocking network operations                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Cause: SELinux policy does not allow                              │  │
│  │ Solution:                                                         │  │
│  │   $ sudo ausearch -m avc -ts recent  # View SELinux audit logs   │  │
│  │   $ sudo setenforce 0  # Temporarily disable (testing only)      │  │
│  │   See Section C.5 to configure SELinux policy                     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Issue 5: Slow scan speed                                               │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Possible causes and solutions:                                    │  │
│  │   1. Check timing template: use -T4 or -T5                        │  │
│  │   2. Check concurrency: --max-parallelism                         │  │
│  │   3. Enable PACKET_MMAP: check kernel version >= 2.6.22          │  │
│  │   4. CPU affinity: use taskset to bind CPU                        │  │
│  │   5. Network buffers: adjust net.core.* parameters                │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
