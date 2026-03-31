#!/bin/bash
# RustNmap Test Range - Teardown Script
# Stops and removes all containers, networks, and volumes
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_DIR="$(dirname "$SCRIPT_DIR")"

cd "$TARGETS_DIR"

echo "=========================================================="
echo "RustNmap Test Range Teardown"
echo "=========================================================="

echo "[INFO] Stopping all services..."
docker compose down -v --remove-orphans

echo ""
echo "[OK] All services stopped and cleaned up."
echo "     Volumes and networks removed."
