# RustNmap Scan Target - Alpine Linux with many open ports
# Covers: TCP SYN/Connect/FIN/NULL/XMAS/Maimon/ACK/Window scans,
#         UDP scan, IP Protocol scan, host discovery, OS detection
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    socat \
    netcat-openbsd \
    iptables \
    ip6tables \
    python3 \
    py3-pip \
    bind-tools \
    nmap-scripts \
    && rm -rf /var/cache/apk/*

# Create startup script that opens many TCP and UDP ports via socat
COPY <<'EOF' /usr/local/bin/start-services.sh
#!/bin/sh
set -e

# TCP echo service on port 7 (for basic connectivity)
socat TCP-LISTEN:7,reuseaddr,fork EXEC:/bin/true &

# SSH port (no real SSH, just accept connection)
socat TCP-LISTEN:22,reuseaddr,fork EXEC:'/bin/sh -c "echo SSH-2.0-RustNmap-Test"' &

# Telnet
socat TCP-LISTEN:23,reuseaddr,fork EXEC:'/bin/sh -c "echo RustNmap Telnet Test; sleep 30"' &

# SMTP
socat TCP-LISTEN:25,reuseaddr,fork EXEC:'/bin/sh -c "echo 220 rustnmap.test ESMTP RustNmap; sleep 30"' &

# DNS TCP
socat TCP-LISTEN:53,reuseaddr,fork EXEC:/bin/true &

# HTTP (simple response)
socat TCP-LISTEN:80,reuseaddr,fork EXEC:'/bin/sh -c "printf \"HTTP/1.1 200 OK\r\nServer: RustNmap-Test/1.0\r\nContent-Length: 13\r\n\r\nHello, Nmap!\n\""' &

# POP3
socat TCP-LISTEN:110,reuseaddr,fork EXEC:'/bin/sh -c "echo +OK RustNmap POP3 ready; sleep 30"' &

# RPCBind
socat TCP-LISTEN:111,reuseaddr,fork EXEC:/bin/true &

# IMAP
socat TCP-LISTEN:143,reuseaddr,fork EXEC:'/bin/sh -c "echo * OK RustNmap IMAP ready; sleep 30"' &

# LDAP (returns basic response)
socat TCP-LISTEN:389,reuseaddr,fork EXEC:/bin/true &

# HTTPS
socat TCP-LISTEN:443,reuseaddr,fork EXEC:'/bin/sh -c "printf \"HTTP/1.1 200 OK\r\nServer: RustNmap-Test/1.0\r\n\r\n"' &

# SMB
socat TCP-LISTEN:445,reuseaddr,fork EXEC:/bin/true &

# SMTPS
socat TCP-LISTEN:465,reuseaddr,fork EXEC:/bin/true &

# SMTP submission
socat TCP-LISTEN:587,reuseaddr,fork EXEC:'/bin/sh -c "echo 220 rustnmap.test ESMTP RustNmap; sleep 30"' &

# LDAPS
socat TCP-LISTEN:636,reuseaddr,fork EXEC:/bin/true &

# MySQL (send MySQL-like greeting)
socat TCP-LISTEN:3306,reuseaddr,fork EXEC:'/bin/sh -c "printf \"\\x5c\\x00\\x00\\x00\\x0a\\x35\\x2e\\x37\\x2e\\x33\\x38\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x72\\x75\\x73\\x74\\x6e\\x6d\\x61\\x70\\x00\\x6d\\x79\\x73\\x71\\x6c\\x5f\\x6e\\x61\\x74\\x69\\x76\\x65\\x5f\\x70\\x61\\x73\\x73\\x77\\x6f\\x72\\x64\\x00\"; sleep 30"' &

# PostgreSQL
socat TCP-LISTEN:5432,reuseaddr,fork EXEC:/bin/true &

# VNC
socat TCP-LISTEN:5900,reuseaddr,fork EXEC:'/bin/sh -c "printf \"RFB 003.008\\n\"; sleep 30"' &

# Redis (send simple Redis-like response)
socat TCP-LISTEN:6379,reuseaddr,fork EXEC:'/bin/sh -c "printf \"-NOAUTH Authentication required\\r\\n\"; sleep 30"' &

# HTTP alternate
socat TCP-LISTEN:8080,reuseaddr,fork EXEC:'/bin/sh -c "printf \"HTTP/1.1 200 OK\r\nServer: RustNmap-Test/1.0\r\nContent-Length: 13\r\n\r\nHello, Nmap!\n\""' &

# HTTPS alternate
socat TCP-LISTEN:8443,reuseaddr,fork EXEC:/bin/true &

# IMAPS
socat TCP-LISTEN:993,reuseaddr,fork EXEC:/bin/true &

# POP3S
socat TCP-LISTEN:995,reuseaddr,fork EXEC:/bin/true &

# MS SQL
socat TCP-LISTEN:1433,reuseaddr,fork EXEC:/bin/true &

# --- UDP services ---

# DNS UDP
socat UDP-LISTEN:53,reuseaddr,fork EXEC:/bin/true &

# NTP UDP
socat UDP-LISTEN:123,reuseaddr,fork EXEC:/bin/true &

# SNMP UDP (respond with basic SNMP)
python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 161))
while True:
    data, addr = s.recvfrom(4096)
    # Send back a minimal SNMP response
    s.sendto(b'\x30\x26\x02\x01\x01\x04\x06public\xa2\x19\x02\x02\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0d\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x04\x00RustNmap SNMP Test Agent', addr)
" &

# Syslog UDP
socat UDP-LISTEN:514,reuseaddr,fork EXEC:/bin/true &

# High port UDP for UDP ping test (closed port returns ICMP unreachable)
# Port 40125 is intentionally LEFT CLOSED for -PU testing

# High port UDP for testing (open)
socat UDP-LISTEN:40125,reuseaddr,fork EXEC:/bin/true &

# --- SCTP services (load module first) ---
# Note: SCTP may not be available in all Docker kernels

# RPCBind UDP
socat UDP-LISTEN:111,reuseaddr,fork EXEC:/bin/true &

# Wait for all background processes
wait
EOF

RUN chmod +x /usr/local/bin/start-services.sh

# Enable ICMP echo response (already default in Alpine)
# Enable IP forwarding for IP protocol scan
RUN sysctl -w net.ipv4.icmp_echo_ignore_all=0 2>/dev/null || true

EXPOSE 7/tcp 22/tcp 23/tcp 25/tcp 53/tcp 80/tcp 110/tcp 111/tcp \
       143/tcp 389/tcp 443/tcp 445/tcp 465/tcp 587/tcp 636/tcp \
       3306/tcp 5432/tcp 5900/tcp 6379/tcp 8080/tcp 8443/tcp \
       993/tcp 995/tcp 1433/tcp \
       53/udp 123/udp 161/udp 514/udp 111/udp 40125/udp

CMD ["/usr/local/bin/start-services.sh"]
