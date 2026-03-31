# RustNmap Firewall Target - iptables DROP rules for filtered port states
# Covers: -sA (ACK scan firewall mapping), filtered port state testing
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    iptables \
    ip6tables \
    socat \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create startup script
COPY <<'EOF' /usr/local/bin/start-firewall.sh
#!/bin/sh
set -e

# Start a service on port 80 (unfiltered - for baseline)
socat TCP-LISTEN:80,reuseaddr,fork EXEC:/bin/true &

# Start service on port 22 (unfiltered)
socat TCP-LISTEN:22,reuseaddr,fork EXEC:/bin/true &

# Set up iptables DROP rules for filtered ports
# These ports will show as "filtered" in scans
iptables -A INPUT -p tcp --dport 8888 -j DROP
iptables -A INPUT -p tcp --dport 9999 -j DROP
iptables -A INPUT -p udp --dport 5555 -j DROP
iptables -A INPUT -p tcp --dport 6666 -j DROP
iptables -A INPUT -p udp --dport 7777 -j DROP

# Set up REJECT rule for closed|filtered testing
iptables -A INPUT -p tcp --dport 3333 -j REJECT --reject-with tcp-reset

# Allow established connections and loopback
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Log dropped packets for debugging
iptables -A INPUT -j LOG --log-prefix "RUSTNMAP-FW-DROP: " --log-level 7

# Show rules
echo "Firewall rules loaded:"
iptables -L INPUT -n -v

wait
EOF

RUN chmod +x /usr/local/bin/start-firewall.sh

EXPOSE 22/tcp 80/tcp

CMD ["/usr/local/bin/start-firewall.sh"]
