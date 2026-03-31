# RustNmap SSH Target - OpenSSH with pre-generated keys
# Covers: ssh-auth-methods, ssh-hostkey, ssh2-enum-algos, banner scripts
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    openssh-server \
    openssh-keygen \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Generate host keys (default types via -A, then add DSA separately)
RUN ssh-keygen -A && \
    ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N "" -C "rustnmap-test-dsa"

# Create test user
RUN adduser -D -s /bin/sh testuser && \
    echo "testuser:test123" | chpasswd && \
    echo "root:root" | chpasswd

# Configure SSHD
COPY <<'EOF' /etc/ssh/sshd_config
Port 22
Protocol 2

# Host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_dsa_key

# Banner
Banner /etc/ssh/banner

# Authentication
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication yes
KbdInteractiveAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# HostKeyAlgorithms - include ssh-rsa for fingerprint testing
HostKeyAlgorithms +ssh-rsa

# Logging
SyslogFacility AUTH
LogLevel INFO

# Keep alive
ClientAliveInterval 60
ClientAliveCountMax 3

# Subsystem
Subsystem sftp /usr/lib/ssh/sftp-server
EOF

# Create banner
RUN echo "SSH-2.0-OpenSSH_9.6 RustNmap-Test" > /etc/ssh/banner

# Create .ssh directory for testuser
RUN mkdir -p /home/testuser/.ssh && \
    chown -R testuser:testuser /home/testuser/.ssh && \
    chmod 700 /home/testuser/.ssh

# Create SSHD run directory
RUN mkdir -p /run/sshd

EXPOSE 22/tcp

CMD ["/usr/sbin/sshd", "-D", "-e"]
