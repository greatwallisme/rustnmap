#!/bin/bash
# RustNmap Test Range - Setup Script
# Builds and starts all Docker containers, waits for healthy status
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_DIR="$(dirname "$SCRIPT_DIR")"

cd "$TARGETS_DIR"

echo "=========================================================="
echo "RustNmap Test Range Setup"
echo "=========================================================="

# Check Docker
if ! command -v docker &>/dev/null; then
    echo "[ERROR] Docker not found. Please install Docker first."
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo "[ERROR] Docker Compose v2 not found."
    exit 1
fi

# Generate SSL certs if not present
if [ ! -f configs/nginx/ssl/server.crt ]; then
    echo "[INFO] Generating SSL certificates..."
    sh configs/nginx/ssl/generate.sh
fi

# Build and start
echo "[INFO] Building and starting containers..."
docker compose up -d --build

echo ""
echo "[INFO] Waiting for all services to become healthy..."
echo "[INFO] This may take 2-3 minutes for first-time builds."

# Wait for healthy with timeout
TIMEOUT=300
ELAPSED=0
INTERVAL=10

while [ $ELAPSED -lt $TIMEOUT ]; do
    UNHEALTHY=$(docker compose ps --format json 2>/dev/null | \
        python3 -c "
import sys, json
services = []
for line in sys.stdin:
    try:
        svc = json.loads(line)
        health = svc.get('Health', svc.get('Status', ''))
        if 'healthy' not in health.lower() and 'running' not in health.lower():
            services.append(svc.get('Service', svc.get('Name', 'unknown')))
    except: pass
print('\n'.join(services))
" 2>/dev/null || echo "checking...")

    if [ -z "$UNHEALTHY" ] || [ "$UNHEALTHY" = "checking..." ]; then
        # Check if all services are running
        RUNNING=$(docker compose ps --services --filter "status=running" 2>/dev/null | wc -l)
        TOTAL=$(docker compose config --services 2>/dev/null | wc -l)
        if [ "$RUNNING" -ge "$TOTAL" ]; then
            echo ""
            echo "[OK] All $TOTAL services are running!"
            break
        fi
    fi

    echo "  Waiting... (${ELAPSED}s / ${TIMEOUT}s) unhealthy: $UNHEALTHY"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "[WARN] Timeout reached. Some services may not be fully healthy."
    echo "[INFO] Check status with: docker compose ps"
fi

# Show status
echo ""
echo "=========================================================="
echo "Service Status:"
echo "=========================================================="
docker compose ps

echo ""
echo "=========================================================="
echo "Test Range Ready!"
echo "=========================================================="
echo "Network: 172.28.0.0/16"
echo ""
echo "Key targets:"
echo "  scan-target:  172.28.0.2  (port scan + host discovery)"
echo "  web (nginx):  172.28.0.3  (HTTP 80, HTTPS 443)"
echo "  ssh:          172.28.0.4  (SSH 22)"
echo "  dns:          172.28.0.5  (DNS 53/tcp+udp)"
echo "  smb:          172.28.0.6  (SMB 445)"
echo "  ftp:          172.28.0.7  (FTP 21)"
echo "  smtp:         172.28.0.8  (SMTP 25)"
echo "  mysql:        172.28.0.9  (MySQL 3306)"
echo "  redis:        172.28.0.10 (Redis 6379)"
echo "  vnc:          172.28.0.11 (VNC 5900)"
echo "  mail:         172.28.0.12 (POP3 110, IMAP 143)"
echo "  ldap:         172.28.0.13 (LDAP 389)"
echo "  ntp:          172.28.0.14 (NTP 123/udp)"
echo "  snmp:         172.28.0.15 (SNMP 161/udp)"
echo "  telnet:       172.28.0.16 (Telnet 23)"
echo "  rpcbind:      172.28.0.17 (RPC 111)"
echo "  sctp:         172.28.0.18 (SCTP 7,80,36712)"
echo "  firewall:     172.28.0.19 (filtered ports 8888,9999)"
echo "  zombie:       172.28.0.20 (idle host for -sI)"
echo ""
echo "Verify with: $SCRIPT_DIR/verify.sh"
echo "Tear down:   $SCRIPT_DIR/teardown.sh"
