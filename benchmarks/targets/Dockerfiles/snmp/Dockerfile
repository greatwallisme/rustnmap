# RustNmap SNMP Target - net-snmp daemon
# Covers: snmp-info, snmp-sysdescr, snmp-interfaces scripts
FROM registry.cn-shanghai.aliyuncs.com/greatwallisme/alpine:3.19

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk add --no-cache \
    net-snmp \
    net-snmp-tools \
    net-snmp-libs \
    && rm -rf /var/cache/apk/*

# SNMP configuration
COPY <<'EOF' /etc/snmp/snmpd.conf
# Community strings
rocommunity public default
rwcommunity private default

# System information
sysDescr RustNmap SNMP Test Agent
sysContact admin@rustnmap.test
sysLocation RustNmap Test Lab
sysName rustnmap-snmp
sysObjectID 1.3.6.1.4.1.8072.3.2.10

# Full MIB tree access
view all included .1 80
access notConfigGroup "" any noauth exact all none none

# Allow all OIDs
rocommunity public default -V all
rwcommunity private default -V all

# Disk monitoring
disk / 10000

# Load average
load 12 10 5

# Process monitoring
proc sshd

# Engine ID
engineIDType 1

# Master agent
master agentx

# Listen on all interfaces
agentAddress udp:161,tcp:161

# Logging
logOption f /var/log/snmpd.log
EOF

RUN mkdir -p /var/log && \
    touch /var/log/snmpd.log

EXPOSE 161/udp 161/tcp

CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
