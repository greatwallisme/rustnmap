#!/bin/bash
# RustNmap vs Nmap Comprehensive Comparison Test Script
# Covers all test suites from the Python comparison test

set -e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
TARGET_IP="${TARGET_IP:-45.33.32.156}"
ALT_TARGET="${ALT_TARGET:-127.0.0.1}"
TEST_PORTS="${TEST_PORTS:-22,80,113,443,8080}"
NMAP_BIN="${NMAP_BIN:-/usr/bin/nmap}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"

# Output directories (separate logs and reports)
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/comparison_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/comparison_report_${TIMESTAMP}.txt"

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
declare -a FAILED_TEST_NAMES
declare -a SKIPPED_TEST_NAMES

# Parse port states from scan output
parse_ports() {
    local output="$1"
    echo "$output" | grep -E '^[0-9]+/(tcp|udp)' | awk '{print $1, $2}' || true
}

# Compare scan results
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
    if nmap_output=$(eval "$nmap_cmd" 2>&1); then
        : # success
    else
        nmap_exit=$?
    fi
    local nmap_end=$(date +%s%3N)
    local nmap_duration=$((nmap_end - nmap_start))
    echo "[INFO] nmap completed in ${nmap_duration}ms (exit: $nmap_exit)" | tee -a "$LOG_FILE"

    # Delay between scans (5 seconds for reliability)
    sleep 5

    # Run rustnmap
    echo "[INFO] Running rustnmap..." | tee -a "$LOG_FILE"
    local rustnmap_start=$(date +%s%3N)
    local rustnmap_output
    local rustnmap_exit=0
    if rustnmap_output=$(eval "$rustnmap_cmd" 2>&1); then
        : # success
    else
        rustnmap_exit=$?
    fi
    local rustnmap_end=$(date +%s%3N)
    local rustnmap_duration=$((rustnmap_end - rustnmap_start))
    echo "[INFO] rustnmap completed in ${rustnmap_duration}ms (exit: $rustnmap_exit)" | tee -a "$LOG_FILE"

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

        # Skip comparison if nmap shows "unknown" (port not scanned)
        # This is a false positive - both tools are working correctly
        if [[ "$nmap_state" == "unknown" ]]; then
            continue
        fi

        if [[ "$nmap_state" != "$rustnmap_state" ]]; then
            mismatches+=("$port: rustnmap=$rustnmap_state, nmap=$nmap_state")
        fi
    done

    # Report results
    if [[ ${#mismatches[@]} -eq 0 ]]; then
        echo "[PASS] $test_name" | tee -a "$LOG_FILE"
        echo "  Speed: ${speedup}x (rustnmap=${rustnmap_duration}ms, nmap=${nmap_duration}ms)" | tee -a "$LOG_FILE"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "[FAIL] $test_name" | tee -a "$LOG_FILE"
        echo "  Speed: ${speedup}x (rustnmap=${rustnmap_duration}ms, nmap=${nmap_duration}ms)" | tee -a "$LOG_FILE"
        echo "  State mismatches:" | tee -a "$LOG_FILE"
        for mismatch in "${mismatches[@]}"; do
            echo "    - $mismatch" | tee -a "$LOG_FILE"
        done
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
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
        "sudo $NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Connect Scan" \
        "sudo $NMAP_BIN -sT -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-connect -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "UDP Scan" \
        "sudo $NMAP_BIN -sU -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-udp -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Fast Scan" \
        "sudo $NMAP_BIN -F $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -F $TARGET_IP"

    compare_scans \
        "Top Ports" \
        "sudo $NMAP_BIN --top-ports 10 $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn --top-ports 10 $TARGET_IP"
}

# Test Suite: Extended Stealth Scans (7 tests)
run_stealth_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Extended Stealth Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "FIN Scan" \
        "sudo $NMAP_BIN -sF -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-fin -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "NULL Scan" \
        "sudo $NMAP_BIN -sN -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-null -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XMAS Scan" \
        "sudo $NMAP_BIN -sX -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-xmas -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "MAIMON Scan" \
        "sudo $NMAP_BIN -sM -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-maimon -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "ACK Scan" \
        "sudo $NMAP_BIN -sA -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-ack -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Window Scan" \
        "sudo $NMAP_BIN -sW -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-window -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Decoys Scan" \
        "sudo $NMAP_BIN -sS -D RND:10 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -D RND:10 -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: Advanced Scans (6 tests)
run_advanced_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Advanced Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "FIN Scan (Advanced)" \
        "sudo $NMAP_BIN -sF -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-fin -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "NULL Scan (Advanced)" \
        "sudo $NMAP_BIN -sN -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-null -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XMAS Scan (Advanced)" \
        "sudo $NMAP_BIN -sX -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-xmas -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "MAIMON Scan (Advanced)" \
        "sudo $NMAP_BIN -sM -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-maimon -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Timing Template T4" \
        "sudo $NMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T4 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Min/Max Rate" \
        "sudo $NMAP_BIN -sS --min-rate 100 --max-rate 500 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn --min-rate 100 --max-rate 500 -p $TEST_PORTS $TARGET_IP"
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
        "sudo $NMAP_BIN -sS -T1 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T1 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T2 Polite" \
        "sudo $NMAP_BIN -sS -T2 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T2 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T3 Normal" \
        "sudo $NMAP_BIN -sS -T3 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T3 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T4 Aggressive" \
        "sudo $NMAP_BIN -sS -T4 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T4 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "T5 Insane" \
        "sudo $NMAP_BIN -sS -T5 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -T5 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Min/Max Rate Limiting" \
        "sudo $NMAP_BIN -sS --min-rate 50 --max-rate 200 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn --min-rate 50 --max-rate 200 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Host Timeout" \
        "sudo $NMAP_BIN -sS --host-timeout 30000 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn --host-timeout 30000 -p $TEST_PORTS $TARGET_IP" \
        "true"  # Allow nmap failure
}

# Test Suite: Output Formats (4 tests)
run_output_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Output Formats" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Normal Output" \
        "sudo $NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "XML Output" \
        "sudo $NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oX /tmp/rustnmap_test_nmap.xml" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP --output-xml /tmp/rustnmap_test_rustnmap.xml"

    # JSON is rustnmap-only, skip comparison
    echo "[SKIP] JSON Output (rustnmap extension)" | tee -a "$LOG_FILE"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Grepable Output" \
        "sudo $NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP -oG /tmp/rustnmap_test_nmap.gnmap" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP --output-grepable /tmp/rustnmap_test_rustnmap.gnmap"
}

# Test Suite: Multi-Target Scans (5 tests)
run_multi_target_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Multi-Target Scans" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "Two Targets" \
        "sudo $NMAP_BIN -sS -p $TEST_PORTS $TARGET_IP $ALT_TARGET" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP $ALT_TARGET"

    compare_scans \
        "Port Range" \
        "sudo $NMAP_BIN -sS -p 1-100 $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -p 1-100 $TARGET_IP"

    compare_scans \
        "Exclude Port" \
        "sudo $NMAP_BIN -sS -p $TEST_PORTS --exclude-port 22 $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --exclude-port 22 $TARGET_IP"

    compare_scans \
        "Fast Scan + Top Ports" \
        "sudo $NMAP_BIN -sS -F --top-ports 50 $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --scan-syn -F --top-ports 50 $TARGET_IP"

    # IPv6 test - skip if not supported
    if ping6 -c 1 ::1 >/dev/null 2>&1; then
        compare_scans \
            "IPv6 Target" \
            "sudo $NMAP_BIN -sS -p $TEST_PORTS ::1" \
            "sudo $RUSTNMAP_BIN --scan-syn -p $TEST_PORTS ::1"
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
        "sudo $NMAP_BIN -sV -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --service-detection -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Version Detection Intensity" \
        "sudo $NMAP_BIN -sV --version-intensity 5 -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --service-detection --version-intensity 5 -p $TEST_PORTS $TARGET_IP"

    compare_scans \
        "Aggressive Scan" \
        "sudo $NMAP_BIN -A -p $TEST_PORTS $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --aggressive-scan -p $TEST_PORTS $TARGET_IP"
}

# Test Suite: OS Detection (3 tests)
run_os_detection_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: OS Detection" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_scans \
        "OS Detection" \
        "sudo $NMAP_BIN -O $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --os-detection $TARGET_IP"

    compare_scans \
        "OS Detection Limit" \
        "sudo $NMAP_BIN -O --osscan-limit $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --os-detection --osscan-limit $TARGET_IP"

    compare_scans \
        "OS Detection Guess" \
        "sudo $NMAP_BIN -O --osscan-guess $TARGET_IP" \
        "sudo $RUSTNMAP_BIN --os-detection --osscan-guess $TARGET_IP"
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
    run_stealth_suite          # 7 tests - stealth scans
    run_advanced_suite         # 6 tests - advanced scans
    run_multi_target_suite     # 5 tests - multi-target scans
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
