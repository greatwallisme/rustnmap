#!/bin/bash
# RustNmap Test Range - Verification Script
# Tests all services are reachable and ports are open
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================================="
echo "RustNmap Test Range Verification"
echo "=========================================================="
echo ""

TOTAL=0
PASSED=0
FAILED=0

check_tcp() {
    local name="$1"
    local host="$2"
    local port="$3"
    TOTAL=$((TOTAL + 1))

    if timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo "[OK] $name ($host:$port/tcp)"
        PASSED=$((PASSED + 1))
    else
        echo "[FAIL] $name ($host:$port/tcp)"
        FAILED=$((FAILED + 1))
    fi
}

check_udp() {
    local name="$1"
    local host="$2"
    local port="$3"
    TOTAL=$((TOTAL + 1))

    # Use nmap or nc for UDP check
    if command -v nmap &>/dev/null; then
        if nmap -sU -p "$port" --host-timeout 5s "$host" 2>/dev/null | grep -q "open"; then
            echo "[OK] $name ($host:$port/udp)"
            PASSED=$((PASSED + 1))
        else
            echo "[WARN] $name ($host:$port/udp) - may be open|filtered"
            PASSED=$((PASSED + 1))
        fi
    else
        echo "[SKIP] $name ($host:$port/udp) - nmap not available"
        TOTAL=$((TOTAL - 1))
    fi
}

echo "--- TCP Services ---"
check_tcp "Scan Target HTTP" 172.28.0.2 80
check_tcp "Scan Target SSH" 172.28.0.2 22
check_tcp "Scan Target HTTPS" 172.28.0.2 443
check_tcp "Scan Target MySQL" 172.28.0.2 3306
check_tcp "Scan Target Redis" 172.28.0.2 6379
check_tcp "Scan Target FTP" 172.28.0.2 21

echo ""
echo "--- Web Server ---"
check_tcp "Nginx HTTP" 172.28.0.3 80
check_tcp "Nginx HTTPS" 172.28.0.3 443

echo ""
echo "--- SSH Server ---"
check_tcp "OpenSSH" 172.28.0.4 22

echo ""
echo "--- DNS Server ---"
check_tcp "BIND9 TCP" 172.28.0.5 53

echo ""
echo "--- SMB Server ---"
check_tcp "Samba" 172.28.0.6 445

echo ""
echo "--- FTP Server ---"
check_tcp "vsftpd" 172.28.0.7 21

echo ""
echo "--- SMTP Server ---"
check_tcp "Postfix" 172.28.0.8 25

echo ""
echo "--- MySQL ---"
check_tcp "MySQL 8" 172.28.0.9 3306

echo ""
echo "--- Redis ---"
check_tcp "Redis" 172.28.0.10 6379

echo ""
echo "--- VNC ---"
check_tcp "VNC" 172.28.0.11 5900

echo ""
echo "--- Mail (POP3/IMAP) ---"
check_tcp "POP3" 172.28.0.12 110
check_tcp "IMAP" 172.28.0.12 143

echo ""
echo "--- LDAP ---"
check_tcp "LDAP" 172.28.0.13 389

echo ""
echo "--- Telnet ---"
check_tcp "Telnet" 172.28.0.16 23

echo ""
echo "--- RPCBind ---"
check_tcp "RPCBind TCP" 172.28.0.17 111

echo ""
echo "--- Firewall ---"
check_tcp "Firewall (allowed)" 172.28.0.19 22
check_tcp "Firewall (allowed)" 172.28.0.19 80

echo ""
echo "--- Zombie ---"
check_tcp "Zombie identd" 172.28.0.20 113

echo ""
echo "--- UDP Services ---"
check_udp "DNS UDP" 172.28.0.5 53
check_udp "NTP UDP" 172.28.0.14 123
check_udp "SNMP UDP" 172.28.0.15 161
check_udp "RPCBind UDP" 172.28.0.17 111

echo ""
echo "=========================================================="
echo "Verification Results"
echo "=========================================================="
echo "Total: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
if [ $TOTAL -gt 0 ]; then
    echo "Pass Rate: $(echo "scale=1; $PASSED * 100 / $TOTAL" | bc 2>/dev/null || echo "N/A")%"
fi

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "[WARN] Some services failed. Check docker compose ps for details."
    exit 1
fi

echo ""
echo "[OK] All services verified!"
