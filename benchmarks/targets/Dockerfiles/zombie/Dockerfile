# RustNmap Zombie Target - Idle host with predictable IP ID for -sI testing
# Covers: -sI (Idle/Zombie) scan type
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    socat \
    netcat-openbsd \
    python3 \
    && rm -rf /var/cache/apk/*

# Set incremental IP ID for predictable zombie scan
# net.ipv4.inet_ip_id_size controls the IP ID generation:
#   0 = random (default), 16 = incremental, 32 = hashed
# Note: not all kernels support this sysctl, but we try

COPY <<'EOF' /usr/local/bin/start-zombie.sh
#!/bin/sh
set -e

# Try to set incremental IP ID (for zombie scan)
# This makes the host suitable as a zombie for -sI idle scan
sysctl -w net.ipv4.inet_ip_id_size=16 2>/dev/null || true

# identd (auth) service on port 113 - responds immediately
# This is what makes this host a good zombie:
# 1. identd responds quickly to SYN (for IP ID sampling)
# 2. Minimal services = mostly idle = IP ID increments predictably
socat TCP-LISTEN:113,reuseaddr,fork EXEC:'/bin/sh -c "read line; echo 0, 0 : USERID : UNIX : testuser"' &

# Daytime service on port 13
socat TCP-LISTEN:13,reuseaddr,fork EXEC:'/bin/sh -c "date"' &

# Simple echo service on port 7 for connectivity testing
socat TCP-LISTEN:7,reuseaddr,fork EXEC:/bin/true &

# Enable ICMP echo response
sysctl -w net.ipv4.icmp_echo_ignore_all=0 2>/dev/null || true

echo "Zombie host ready for idle scan testing"
echo "IP ID generation: $(cat /proc/sys/net/ipv4/inet_ip_id_size 2>/dev/null || echo 'unknown')"

wait
EOF

RUN chmod +x /usr/local/bin/start-zombie.sh

EXPOSE 7/tcp 13/tcp 113/tcp

CMD ["/usr/local/bin/start-zombie.sh"]
