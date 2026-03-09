#!/bin/bash
# Quick check of previously failed tests

RUSTNMAP_BIN="/root/project/rust-nmap/target/release/rustnmap"
TARGET_IP="45.33.32.156"
ALT_TARGET="127.0.0.1"

echo "=== Quick Check of Previously Failed Tests ==="
echo ""

# 1. ACK Scan
echo "1. ACK Scan Test:"
nmap -sA -p 22,80,113,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
$RUSTNMAP_BIN -sA -p 22,80,113,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
echo ""

# 2. Window Scan
echo "2. Window Scan Test:"
nmap -sW -p 22,80,113,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
$RUSTNMAP_BIN -sW -p 22,80,113,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
echo ""

# 3. T5 Insane (Multi-port)
echo "3. T5 Insane Multi-port Test:"
nmap -T5 -sS -p 22,80,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
$RUSTNMAP_BIN -T5 -sS -p 22,80,443,8080 $TARGET_IP 2>&1 | grep -E "^[0-9]+/(tcp|udp)" | head -5
echo ""

# 4. Two Targets
echo "4. Two Targets Test (summary):"
nmap -sS -p 22,80,113,443,8080 $TARGET_IP $ALT_TARGET 2>&1 | grep -E "(Nmap scan report|^[0-9]+/(tcp|udp))" | head -10
$RUSTNMAP_BIN -sS -p 22,80,113,443,8080 $TARGET_IP $ALT_TARGET 2>&1 | grep -E "(RustNmap scan report|^[0-9]+/(tcp|udp))" | head -10
echo ""

echo "=== Quick Check Complete ==="
