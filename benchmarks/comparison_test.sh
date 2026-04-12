#!/bin/bash
# RustNmap vs Nmap Comprehensive Comparison Test Script
# Covers all test suites from the Python comparison test

set +e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration - Docker test range defaults (override with env vars for public targets)
TARGET_IP="${TARGET_IP:-172.28.0.2}"
ALT_TARGET="${ALT_TARGET:-172.28.0.3}"
TEST_PORTS="${TEST_PORTS:-22,80,443,3306,6379}"
NMAP_BIN="${NMAP_BIN:-/usr/bin/nmap}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"

# Docker test range IPs
IP_SCAN_TARGET="${IP_SCAN_TARGET:-172.28.0.2}"
IP_WEB="${IP_WEB:-172.28.0.3}"
IP_SSH="${IP_SSH:-172.28.0.4}"
IP_DNS="${IP_DNS:-172.28.0.5}"
IP_SMB="${IP_SMB:-172.28.0.6}"
IP_FTP="${IP_FTP:-172.28.0.7}"
IP_SMTP="${IP_SMTP:-172.28.0.8}"
IP_MYSQL="${IP_MYSQL:-172.28.0.9}"
IP_FIREWALL="${IP_FIREWALL:-172.28.0.19}"
IP_ZOMBIE="${IP_ZOMBIE:-172.28.0.20}"
IP_SCTP="${IP_SCTP:-172.28.0.18}"

# Output directories (separate logs and reports)
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/comparison_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/comparison_report_${TIMESTAMP}.md"

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
declare -a FAILED_TEST_NAMES
declare -a SKIPPED_TEST_NAMES
declare -a TEST_RESULTS

# Parse port states from scan output
parse_ports() {
    local output="$1"
    echo "$output" | grep -E '^[0-9]+/(tcp|udp)' | awk '{print $1, $2}' || true
}

# Compare scan results (following nse_comparison_test.sh patterns)
compare_scans() {
    local test_name="$1"
    local nmap_cmd="$2"
    local rustnmap_cmd="$3"
    local allow_nmap_failure="${4:-false}"

    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test: $test_name" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    # Run nmap
    echo "[INFO] Running nmap..." | tee -a "$LOG_FILE"
    local nmap_start=$(date +%s%3N)
    local nmap_output
    local nmap_exit=0
    local nmap_time_output
    nmap_output=$(/usr/bin/time -v sh -c "$nmap_cmd" 2>/tmp/nmap_time_$$) || nmap_exit=$?
    nmap_time_output=$(cat /tmp/nmap_time_$$ 2>/dev/null || echo "")
    rm -f /tmp/nmap_time_$$
    local nmap_end=$(date +%s%3N)
    local nmap_duration=$((nmap_end - nmap_start))

    # Extract nmap resource usage
    local nmap_maxrss="N/A"
    local nmap_cpu_pct="N/A"
    local nmap_user_cpu="N/A"
    local nmap_sys_cpu="N/A"
    if [ -n "$nmap_time_output" ]; then
        nmap_maxrss=$(echo "$nmap_time_output" | grep "Maximum resident set size" | awk '{print $NF}' | head -1)
        nmap_cpu_pct=$(echo "$nmap_time_output" | grep "Percent of CPU this job got" | awk '{print $NF}' | head -1)
        nmap_user_cpu=$(echo "$nmap_time_output" | grep "User time (seconds)" | awk '{print $NF}' | head -1)
        nmap_sys_cpu=$(echo "$nmap_time_output" | grep "System time (seconds)" | awk '{print $NF}' | head -1)
    fi
    # Convert maxrss from KB to MB
    if [[ "$nmap_maxrss" != "N/A" && -n "$nmap_maxrss" ]]; then
        nmap_maxrss=$(echo "scale=1; ${nmap_maxrss} / 1024" | bc 2>/dev/null || echo "$nmap_maxrss")"MB"
    fi

    echo "[INFO] nmap completed in ${nmap_duration}ms (exit: $nmap_exit)" | tee -a "$LOG_FILE"
    echo "[INFO] nmap resources: peak_mem=${nmap_maxrss}, cpu=${nmap_cpu_pct}%, user=${nmap_user_cpu}s, sys=${nmap_sys_cpu}s" | tee -a "$LOG_FILE"

    # Delay between scans to avoid ICMP rate-limit interference.
    # UDP scans trigger ICMP port-unreachable replies which are kernel
    # rate-limited (net.ipv4.icmp_ratelimit). A short gap causes the
    # second tool to be measured under rate-limiting conditions.
    if echo "$nmap_cmd" | grep -qE '\-sU\b'; then
        sleep 10
    else
        sleep 2
    fi

    # Run rustnmap
    echo "[INFO] Running rustnmap..." | tee -a "$LOG_FILE"
    local rustnmap_start=$(date +%s%3N)
    local rustnmap_output
    local rustnmap_exit=0
    local rustnmap_time_output
    rustnmap_output=$(/usr/bin/time -v sh -c "$rustnmap_cmd" 2>/tmp/rustnmap_time_$$) || rustnmap_exit=$?
    rustnmap_time_output=$(cat /tmp/rustnmap_time_$$ 2>/dev/null || echo "")
    rm -f /tmp/rustnmap_time_$$
    local rustnmap_end=$(date +%s%3N)
    local rustnmap_duration=$((rustnmap_end - rustnmap_start))

    # Extract rustnmap resource usage
    local rustnmap_maxrss="N/A"
    local rustnmap_cpu_pct="N/A"
    local rustnmap_user_cpu="N/A"
    local rustnmap_sys_cpu="N/A"
    if [ -n "$rustnmap_time_output" ]; then
        rustnmap_maxrss=$(echo "$rustnmap_time_output" | grep "Maximum resident set size" | awk '{print $NF}' | head -1)
        rustnmap_cpu_pct=$(echo "$rustnmap_time_output" | grep "Percent of CPU this job got" | awk '{print $NF}' | head -1)
        rustnmap_user_cpu=$(echo "$rustnmap_time_output" | grep "User time (seconds)" | awk '{print $NF}' | head -1)
        rustnmap_sys_cpu=$(echo "$rustnmap_time_output" | grep "System time (seconds)" | awk '{print $NF}' | head -1)
    fi
    # Convert maxrss from KB to MB
    if [[ "$rustnmap_maxrss" != "N/A" && -n "$rustnmap_maxrss" ]]; then
        rustnmap_maxrss=$(echo "scale=1; ${rustnmap_maxrss} / 1024" | bc 2>/dev/null || echo "$rustnmap_maxrss")"MB"
    fi

    echo "[INFO] rustnmap completed in ${rustnmap_duration}ms (exit: $rustnmap_exit)" | tee -a "$LOG_FILE"
    echo "[INFO] rustnmap resources: peak_mem=${rustnmap_maxrss}, cpu=${rustnmap_cpu_pct}%, user=${rustnmap_user_cpu}s, sys=${rustnmap_sys_cpu}s" | tee -a "$LOG_FILE"

    # Calculate speedup
    local speedup="N/A"
    if [[ $nmap_duration -gt 0 ]]; then
        speedup=$(echo "scale=2; ${nmap_duration} / ${rustnmap_duration}" | bc 2>/dev/null || echo "N/A")
    fi

    # Handle expected nmap failures
    if [[ $nmap_exit -ne 0 && "$allow_nmap_failure" == "true" ]]; then
        echo "[SKIP] $test_name (nmap failed as expected)" | tee -a "$LOG_FILE"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        SKIPPED_TEST_NAMES+=("$test_name")
        TEST_RESULTS+=("SKIP|$test_name|nmap failed as expected|N/A|N/A")
        echo "" | tee -a "$LOG_FILE"
        return
    fi

    # Parse ports from both outputs
    declare -A nmap_ports
    declare -A rustnmap_ports

    while IFS=' ' read -r proto state; do
        nmap_ports["$proto"]="$state"
    done < <(parse_ports "$nmap_output")

    while IFS=' ' read -r proto state; do
        rustnmap_ports["$proto"]="$state"
    done < <(parse_ports "$rustnmap_output")

    # Compare results
    local mismatches=()
    local all_ports=($(echo "${!nmap_ports[@]}" "${!rustnmap_ports[@]}" | sort -u))

    for port in "${all_ports[@]}"; do
        local nmap_state="${nmap_ports[$port]:-unknown}"
        local rustnmap_state="${rustnmap_ports[$port]:-unknown}"

        if [[ "$nmap_state" == "unknown" ]]; then
            continue
        fi

        if [[ "$nmap_state" != "$rustnmap_state" ]]; then
            mismatches+=("$port: rustnmap=$rustnmap_state, nmap=$nmap_state")
        fi
    done

    # Report results (following NSE script format)
    if [[ ${#mismatches[@]} -eq 0 ]]; then
        echo "[PASS] $test_name" | tee -a "$LOG_FILE"
        echo "  Speed: ${speedup}x (rustnmap=${rustnmap_duration}ms, nmap=${nmap_duration}ms)" | tee -a "$LOG_FILE"
        echo "  Resources (nmap):     peak_mem=${nmap_maxrss}, cpu=${nmap_cpu_pct}%, user=${nmap_user_cpu}s, sys=${nmap_sys_cpu}s" | tee -a "$LOG_FILE"
        echo "  Resources (rustnmap): peak_mem=${rustnmap_maxrss}, cpu=${rustnmap_cpu_pct}%, user=${rustnmap_user_cpu}s, sys=${rustnmap_sys_cpu}s" | tee -a "$LOG_FILE"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        # Show port output comparison (like NSE script shows script output comparison)
        echo "  --- NMAP OUTPUT (ports) ---" | tee -a "$LOG_FILE"
        echo "$nmap_output" | grep -E '^[0-9]+/(tcp|udp)|PORT.*STATE' | sed 's/^/  /' | tee -a "$LOG_FILE"
        echo "  --- RUSTNMAP OUTPUT (ports) ---" | tee -a "$LOG_FILE"
        echo "$rustnmap_output" | grep -E '^[0-9]+/(tcp|udp)|PORT.*STATE' | sed 's/^/  /' | tee -a "$LOG_FILE"
        TEST_RESULTS+=("PASS|$test_name|All ports match|${speedup}x|nmap_mem=${nmap_maxrss} nmap_cpu=${nmap_cpu_pct} rustnmap_mem=${rustnmap_maxrss} rustnmap_cpu=${rustnmap_cpu_pct}")
    else
        echo "[FAIL] $test_name" | tee -a "$LOG_FILE"
        echo "  Speed: ${speedup}x (rustnmap=${rustnmap_duration}ms, nmap=${nmap_duration}ms)" | tee -a "$LOG_FILE"
        echo "  Resources (nmap):     peak_mem=${nmap_maxrss}, cpu=${nmap_cpu_pct}%, user=${nmap_user_cpu}s, sys=${nmap_sys_cpu}s" | tee -a "$LOG_FILE"
        echo "  Resources (rustnmap): peak_mem=${rustnmap_maxrss}, cpu=${rustnmap_cpu_pct}%, user=${rustnmap_user_cpu}s, sys=${rustnmap_sys_cpu}s" | tee -a "$LOG_FILE"
        echo "  State mismatches:" | tee -a "$LOG_FILE"
        for mismatch in "${mismatches[@]}"; do
            echo "    - $mismatch" | tee -a "$LOG_FILE"
        done
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
        # Show full output on failure (like NSE script)
        echo "  === NMAP OUTPUT ===" | tee -a "$LOG_FILE"
        echo "$nmap_output" | sed 's/^/  /' | tee -a "$LOG_FILE"
        echo "  === END NMAP OUTPUT ===" | tee -a "$LOG_FILE"
        echo "  === RUSTNMAP OUTPUT ===" | tee -a "$LOG_FILE"
        echo "$rustnmap_output" | sed 's/^/  /' | tee -a "$LOG_FILE"
        echo "  === END RUSTNMAP OUTPUT ===" | tee -a "$LOG_FILE"
        local mismatch_summary=$(echo "${mismatches[*]}" | tr '\n' '; ')
        TEST_RESULTS+=("FAIL|$test_name|${mismatch_summary}|${speedup}x|nmap_mem=${nmap_maxrss} nmap_cpu=${nmap_cpu_pct} rustnmap_mem=${rustnmap_maxrss} rustnmap_cpu=${rustnmap_cpu_pct}")
    fi
    echo "" | tee -a "$LOG_FILE"
}

# Test Suite: Basic Port Scans (5 tests)
run_basic_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Basic Port Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "SYN Scan" \
        "$NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Connect Scan" \
        "$NMAP_BIN -sT -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sT -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "UDP Scan" \
        "$NMAP_BIN -sU -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sU -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Fast Scan" \
        "$NMAP_BIN -F $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -F $TARGET_IP"

    compare_scans \
        "Top Ports" \
        "$NMAP_BIN --top-ports 10 $TARGET_IP" \
        "$RUSTNMAP_BIN -sS --top-ports 10 $TARGET_IP"
}

# Test Suite: Extended Stealth Scans (7 tests)
run_stealth_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Extended Stealth Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "FIN Scan" \
        "$NMAP_BIN -sF -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sF -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "NULL Scan" \
        "$NMAP_BIN -sN -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sN -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XMAS Scan" \
        "$NMAP_BIN -sX -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sX -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "MAIMON Scan" \
        "$NMAP_BIN -sM -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sM -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "ACK Scan" \
        "$NMAP_BIN -sA -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sA -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Window Scan" \
        "$NMAP_BIN -sW -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sW -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Decoys Scan" \
        "$NMAP_BIN -sS -D RND:10 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -D RND:10 -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: Advanced Scans (6 tests)
run_advanced_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Advanced Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "FIN Scan (Advanced)" \
        "$NMAP_BIN -sF -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sF -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "NULL Scan (Advanced)" \
        "$NMAP_BIN -sN -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sN -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XMAS Scan (Advanced)" \
        "$NMAP_BIN -sX -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sX -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "MAIMON Scan (Advanced)" \
        "$NMAP_BIN -sM -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sM -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Timing Template T4" \
        "$NMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Min/Max Rate" \
        "$NMAP_BIN -sS --min-rate 100 --max-rate 500 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS --min-rate 100 --max-rate 500 -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: Timing Templates (7 tests - T0 Paranoid skipped)
run_timing_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Timing Templates" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Skip T0 Paranoid - takes 5+ minutes and often causes timeouts
    echo "[SKIP] T0 Paranoid (test takes 5+ minutes, use --timing 0 manually to test)" | tee -a "$LOG_FILE"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "T1 Sneaky" \
        "$NMAP_BIN -sS -T1 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T1 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T2 Polite" \
        "$NMAP_BIN -sS -T2 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T2 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T3 Normal" \
        "$NMAP_BIN -sS -T3 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T3 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T4 Aggressive" \
        "$NMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T5 Insane" \
        "$NMAP_BIN -sS -T5 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -T5 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Min/Max Rate Limiting" \
        "$NMAP_BIN -sS --min-rate 50 --max-rate 200 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS --min-rate 50 --max-rate 200 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Host Timeout" \
        "$NMAP_BIN -sS --host-timeout 30s -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS --host-timeout 30s -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: Output Formats (4 tests)
run_output_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Output Formats" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Normal Output" \
        "$NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XML Output" \
        "$NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oX /tmp/rustnmap_test_nmap.xml" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oX /tmp/rustnmap_test_rustnmap.xml"

    # JSON is rustnmap-only, skip comparison
    echo "[SKIP] JSON Output (rustnmap extension)" | tee -a "$LOG_FILE"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Grepable Output" \
        "$NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oG /tmp/rustnmap_test_nmap.gnmap" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oG /tmp/rustnmap_test_rustnmap.gnmap"
}

# Test Suite: Multi-Target Scans (5 tests)
run_multi_target_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Multi-Target Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Two Targets" \
        "$NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP $ALT_TARGET" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $TARGET_IP $ALT_TARGET"

    compare_scans \
        "Port Range" \
        "$NMAP_BIN -sS -p 1-100 $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -p 1-100 $TARGET_IP"

    compare_scans \
        "Exclude Port" \
        "$NMAP_BIN -sS -p $TEST_PORTS --exclude-ports 22 $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --exclude-ports 22 $TARGET_IP"

    compare_scans \
        "Fast Scan + Top Ports" \
        "$NMAP_BIN -sS -F --top-ports 50 $TARGET_IP" \
        "$RUSTNMAP_BIN -sS -F --top-ports 50 $TARGET_IP"

    # IPv6 test - skip if not supported
    if ping6 -c 1 ::1 >/dev/null 2>&1; then
        compare_scans \
            "IPv6 Target" \
            "$NMAP_BIN -sS -p $TEST_PORTS ::1" \
            "$RUSTNMAP_BIN -sS -p $TEST_PORTS ::1"
    else
        echo "[SKIP] IPv6 Target (not supported)" | tee -a "$LOG_FILE"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        echo "" | tee -a "$LOG_FILE"
    fi
}

# Test Suite: Service Detection (3 tests)
run_service_detection_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Service Detection" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Version Detection" \
        "$NMAP_BIN -sV -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sV -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Version Detection Intensity" \
        "$NMAP_BIN -sV --version-intensity 5 -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -sV --version-intensity 5 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Aggressive Scan" \
        "$NMAP_BIN -A -p $TEST_PORTS $TARGET_IP" \
        "$RUSTNMAP_BIN -A -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: OS Detection (3 tests)
run_os_detection_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: OS Detection" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "OS Detection" \
        "$NMAP_BIN -O $TARGET_IP" \
        "$RUSTNMAP_BIN -O $TARGET_IP"

    compare_scans \
        "OS Detection Limit" \
        "$NMAP_BIN -O --osscan-limit $TARGET_IP" \
        "$RUSTNMAP_BIN -O --osscan-limit $TARGET_IP"

    compare_scans \
        "OS Detection Guess" \
        "$NMAP_BIN -O --osscan-guess $TARGET_IP" \
        "$RUSTNMAP_BIN -O --osscan-guess $TARGET_IP"
}

# Test Suite: Host Discovery (8 tests)
run_host_discovery_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Host Discovery" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "ICMP Echo Ping" \
        "$NMAP_BIN -sn -PE $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PE $IP_SCAN_TARGET"

    compare_scans \
        "TCP SYN Ping" \
        "$NMAP_BIN -sn -PS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PS $IP_SCAN_TARGET"

    compare_scans \
        "TCP ACK Ping" \
        "$NMAP_BIN -sn -PA $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PA $IP_SCAN_TARGET"

    compare_scans \
        "UDP Ping" \
        "$NMAP_BIN -sn -PU $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PU $IP_SCAN_TARGET"

    compare_scans \
        "No Ping (Skip Discovery)" \
        "$NMAP_BIN -sn -Pn $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -Pn $IP_SCAN_TARGET"

    compare_scans \
        "ARP Ping" \
        "$NMAP_BIN -sn -PR $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PR $IP_SCAN_TARGET"

    compare_scans \
        "ICMP Timestamp Ping" \
        "$NMAP_BIN -sn -PP $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PP $IP_SCAN_TARGET"

    compare_scans \
        "ICMP Netmask Ping" \
        "$NMAP_BIN -sn -PM $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sn -PM $IP_SCAN_TARGET"
}

# Test Suite: Special Scans (5 tests)
run_special_scans_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Special Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # IP Protocol scan
    compare_scans \
        "IP Protocol Scan" \
        "$NMAP_BIN -sO $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sO $IP_SCAN_TARGET"

    # SCTP INIT scan
    compare_scans \
        "SCTP INIT Scan" \
        "$NMAP_BIN -sZ -p 7,80 $IP_SCTP" \
        "$RUSTNMAP_BIN -sZ -p 7,80 $IP_SCTP"

    # SCTP Cookie Echo scan
    compare_scans \
        "SCTP Cookie Echo Scan" \
        "$NMAP_BIN -sY -p 7,80 $IP_SCTP" \
        "$RUSTNMAP_BIN -sY -p 7,80 $IP_SCTP"

    # FTP Bounce scan (requires FTP server - use anonymous:password@host syntax)
    compare_scans \
        "FTP Bounce Scan" \
        "$NMAP_BIN -Pn -b anonymous:password@$IP_FTP:21 -p 80 $IP_WEB" \
        "$RUSTNMAP_BIN -Pn -b anonymous:password@$IP_FTP:21 -p 80 $IP_WEB" \
        "true"

    # Idle/Zombie scan (requires zombie host with predictable IP ID)
    compare_scans \
        "Idle/Zombie Scan" \
        "$NMAP_BIN -sI $IP_ZOMBIE -p 80 $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sI $IP_ZOMBIE -p 80 $IP_SCAN_TARGET" \
        "true"
}

# Test Suite: Firewall/IDS Evasion (5 tests)
run_evasion_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Firewall/IDS Evasion" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Fragmentation
    compare_scans \
        "Fragmentation Scan" \
        "$NMAP_BIN -sS -f -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sS -f -p $TEST_PORTS $IP_SCAN_TARGET"

    # Decoys
    compare_scans \
        "Decoy Scan" \
        "$NMAP_BIN -sS -D RND:5 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sS -D RND:5 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "true"

    # Source port spoofing
    compare_scans \
        "Source Port Spoofing" \
        "$NMAP_BIN -sS --source-port 53 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sS --source-port 53 -p $TEST_PORTS $IP_SCAN_TARGET"

    # Data length
    compare_scans \
        "Data Length Scan" \
        "$NMAP_BIN -sS --data-length 24 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sS --data-length 24 -p $TEST_PORTS $IP_SCAN_TARGET"

    # Bad checksum
    compare_scans \
        "Bad Checksum Scan" \
        "$NMAP_BIN -sS --badsum -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sS --badsum -p $TEST_PORTS $IP_SCAN_TARGET" \
        "true"
}

# Test Suite: Traceroute (2 tests)
run_traceroute_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Traceroute" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Traceroute" \
        "$NMAP_BIN -sS --traceroute -p 80 $IP_WEB" \
        "$RUSTNMAP_BIN -sS --traceroute -p 80 $IP_WEB"

    compare_scans \
        "Traceroute with Service" \
        "$NMAP_BIN -sS --traceroute -p 443 $IP_WEB" \
        "$RUSTNMAP_BIN -sS --traceroute -p 443 $IP_WEB"
}

# Test Suite: Firewall Detection (3 tests)
run_firewall_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Firewall Detection" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # ACK scan maps firewall rules
    compare_scans \
        "ACK Scan (Firewall Mapping)" \
        "$NMAP_BIN -sA -p 22,80,8888,9999 $IP_FIREWALL" \
        "$RUSTNMAP_BIN -sA -p 22,80,8888,9999 $IP_FIREWALL"

    # Window scan
    compare_scans \
        "Window Scan" \
        "$NMAP_BIN -sW -p 22,80,8888,9999 $IP_FIREWALL" \
        "$RUSTNMAP_BIN -sW -p 22,80,8888,9999 $IP_FIREWALL"

    # Maimon scan
    compare_scans \
        "Maimon Scan" \
        "$NMAP_BIN -sM -p $TEST_PORTS $IP_SCAN_TARGET" \
        "$RUSTNMAP_BIN -sM -p $TEST_PORTS $IP_SCAN_TARGET"
}

# Main function
main() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "RustNmap vs Nmap Comprehensive Comparison" | tee -a "$LOG_FILE"
    echo "Started: $(date)" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Run test suites in order of duration (shortest first)
    # This ensures maximum test coverage if the run is interrupted
    run_output_suite           # 4 tests - fastest (output format tests)
    run_basic_suite            # 5 tests - quick basic scans
    run_host_discovery_suite   # 8 tests - host discovery methods
    run_stealth_suite          # 7 tests - stealth scans
    run_advanced_suite         # 6 tests - advanced scans
    run_firewall_suite         # 3 tests - firewall detection
    run_multi_target_suite     # 5 tests - multi-target scans
    run_special_scans_suite    # 5 tests - SCTP, FTP bounce, idle scan
    run_evasion_suite          # 5 tests - firewall/IDS evasion
    run_traceroute_suite       # 2 tests - traceroute
    run_timing_suite           # 8 tests - timing templates (T0 can hang)
    run_service_detection_suite # 3 tests - service detection (slow)
    run_os_detection_suite     # 3 tests - OS detection (SLOWEST - ~43s)

    # Print summary
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "FINAL SUMMARY" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Total Tests: $TOTAL_TESTS" | tee -a "$LOG_FILE"
    echo "Passed: $PASSED_TESTS" | tee -a "$LOG_FILE"
    echo "Failed: $FAILED_TESTS" | tee -a "$LOG_FILE"
    echo "Skipped: $SKIPPED_TESTS" | tee -a "$LOG_FILE"

    local pass_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        pass_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "0")
    fi
    echo "Pass Rate: ${pass_rate}%" | tee -a "$LOG_FILE"

    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo "Failed tests:" | tee -a "$LOG_FILE"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            echo "  - $test_name" | tee -a "$LOG_FILE"
        done
    fi

    if [[ $SKIPPED_TESTS -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo "Skipped tests:" | tee -a "$LOG_FILE"
        for test_name in "${SKIPPED_TEST_NAMES[@]}"; do
            echo "  - $test_name" | tee -a "$LOG_FILE"
        done
    fi

    # Save report
    {
        echo "RustNmap vs Nmap Comparison Report"
        echo "Generated: $(date)"
        echo ""
        echo "Total Tests: $TOTAL_TESTS"
        echo "Passed: $PASSED_TESTS"
        echo "Failed: $FAILED_TESTS"
        echo "Skipped: $SKIPPED_TESTS"
        echo "Pass Rate: ${pass_rate}%"
        echo ""
        echo "Detailed Results:"
        echo "Status|Test Name|Notes|Speedup|Resources"
        echo "------|---------|------|--------|----------"
        for result in "${TEST_RESULTS[@]}"; do
            echo "$result"
        done
        echo ""
        if [[ $FAILED_TESTS -gt 0 ]]; then
            echo "Failed tests:"
            for test_name in "${FAILED_TEST_NAMES[@]}"; do
                echo "  - $test_name"
            done
        fi
        if [[ $SKIPPED_TESTS -gt 0 ]]; then
            echo ""
            echo "Skipped tests:"
            for test_name in "${SKIPPED_TEST_NAMES[@]}"; do
                echo "  - $test_name"
            done
        fi
    } > "$REPORT_FILE"

    echo "" | tee -a "$LOG_FILE"
    echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Report saved to: $REPORT_FILE" | tee -a "$LOG_FILE"

    # Exit with error code if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
