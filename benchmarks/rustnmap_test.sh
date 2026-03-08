#!/bin/bash
# RustNmap Comprehensive CLI Test Script
# Tests ALL 85 CLI options across all functional categories
# Default target: 45.33.32.156 (scanme.nmap.org)

set +e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
TARGET_IP="${TARGET_IP:-45.33.32.156}"
ALT_TARGET="${ALT_TARGET:-127.0.0.1}"
TEST_PORTS="${TEST_PORTS:-22,80,113,443,8080}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"

# Output directories
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
TEST_OUTPUT_DIR="${SCRIPT_DIR}/test_outputs"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/rustnmap_test_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/rustnmap_test_report_${TIMESTAMP}.txt"

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
declare -a FAILED_TEST_NAMES
declare -a PASSED_TEST_NAMES

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Test execution function
run_test() {
    local test_name="$1"
    local command="$2"
    local should_fail="${3:-false}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log "=========================================================="
    log "Test: $test_name"
    log "Command: $command"
    log "=========================================================="

    if eval "$command" >> "$LOG_FILE" 2>&1; then
        if [[ "$should_fail" == "true" ]]; then
            log "${RED}FAILED${NC}: Expected failure but succeeded"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_TEST_NAMES+=("$test_name")
            return 1
        else
            log "${GREEN}PASSED${NC}: Command executed successfully"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            PASSED_TEST_NAMES+=("$test_name")
            return 0
        fi
    else
        local exit_code=$?
        if [[ "$should_fail" == "true" ]]; then
            log "${GREEN}PASSED${NC}: Failed as expected (exit: $exit_code)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            PASSED_TEST_NAMES+=("$test_name")
            return 0
        else
            log "${RED}FAILED${NC}: Command failed with exit code $exit_code"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_TEST_NAMES+=("$test_name")
            return 1
        fi
    fi
}

# ============================================================
# Category 1: Target Specification Tests
# ============================================================
test_target_specification() {
    log "${YELLOW}Testing Target Specification${NC}"

    run_test "Target: Single IP" \
        "$RUSTNMAP_BIN $TARGET_IP"

    run_test "Target: Hostname" \
        "$RUSTNMAP_BIN scanme.nmap.org"

    run_test "Target: CIDR notation" \
        "$RUSTNMAP_BIN 192.168.1.0/24"

    run_test "Target: Range" \
        "$RUSTNMAP_BIN 192.168.1.1-10"

    run_test "Target: Multiple targets" \
        "$RUSTNMAP_BIN $TARGET_IP $ALT_TARGET"

    sleep 2
}

# ============================================================
# Category 2: Scan Types Tests (9 options)
# ============================================================
test_scan_types() {
    log "${YELLOW}Testing Scan Types${NC}"

    run_test "Scan: SYN scan (-sS)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: Connect scan (-sT)" \
        "$RUSTNMAP_BIN --scan-connect -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: UDP scan (-sU)" \
        "$RUSTNMAP_BIN --scan-udp -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: FIN scan (-sF)" \
        "$RUSTNMAP_BIN --scan-fin -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: NULL scan (-sN)" \
        "$RUSTNMAP_BIN --scan-null -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: XMAS scan (-sX)" \
        "$RUSTNMAP_BIN --scan-xmas -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: MAIMON scan (-sM)" \
        "$RUSTNMAP_BIN --scan-maimon -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: ACK scan (-sA)" \
        "$RUSTNMAP_BIN --scan-ack -p $TEST_PORTS $TARGET_IP"

    run_test "Scan: Window scan (-sW)" \
        "$RUSTNMAP_BIN --scan-window -p $TEST_PORTS $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 3: Port Specification Tests (6 options)
# ============================================================
test_port_specification() {
    log "${YELLOW}Testing Port Specification${NC}"

    run_test "Ports: Specific ports (-p)" \
        "$RUSTNMAP_BIN --scan-syn -p 22,80,443 $TARGET_IP"

    run_test "Ports: Port range" \
        "$RUSTNMAP_BIN --scan-syn -p 1-100 $TARGET_IP"

    run_test "Ports: All ports (-p-)" \
        "$RUSTNMAP_BIN --scan-syn -p- $ALT_TARGET"

    run_test "Ports: All ports long form (--port-range-all)" \
        "$RUSTNMAP_BIN --scan-syn --port-range-all $ALT_TARGET"

    run_test "Ports: Exclude ports" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --exclude-port 22 $TARGET_IP"

    run_test "Ports: Top ports" \
        "$RUSTNMAP_BIN --scan-syn --top-ports 10 $TARGET_IP"

    run_test "Ports: Fast scan (-F)" \
        "$RUSTNMAP_BIN --scan-syn -F $TARGET_IP"

    run_test "Ports: Protocol specification" \
        "$RUSTNMAP_BIN --scan-udp --protocol udp -p 53,67 $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 4: Service/OS Detection Tests (6 options)
# ============================================================
test_service_os_detection() {
    log "${YELLOW}Testing Service/OS Detection${NC}"

    run_test "Detection: Aggressive scan (-A)" \
        "$RUSTNMAP_BIN --aggressive-scan -p $TEST_PORTS $TARGET_IP"

    run_test "Detection: Service detection (-sV)" \
        "$RUSTNMAP_BIN --service-detection -p $TEST_PORTS $TARGET_IP"

    run_test "Detection: Version intensity (0)" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 0 -p $TEST_PORTS $TARGET_IP"

    run_test "Detection: Version intensity (5)" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 5 -p $TEST_PORTS $TARGET_IP"

    run_test "Detection: Version intensity (9)" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 9 -p $TEST_PORTS $TARGET_IP"

    run_test "Detection: OS detection (-O)" \
        "$RUSTNMAP_BIN --os-detection $TARGET_IP"

    run_test "Detection: OS scan limit" \
        "$RUSTNMAP_BIN --os-detection --osscan-limit $TARGET_IP"

    run_test "Detection: OS scan guess" \
        "$RUSTNMAP_BIN --os-detection --osscan-guess $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 5: Timing and Performance Tests (6 options)
# ============================================================
test_timing_performance() {
    log "${YELLOW}Testing Timing and Performance${NC}"

    run_test "Timing: T0 Paranoid" \
        "$RUSTNMAP_BIN --scan-syn -T0 -p $TEST_PORTS $TARGET_IP"

    run_test "Timing: T1 Sneaky" \
        "$RUSTNMAP_BIN --scan-syn -T1 -p $TEST_PORTS $TARGET_IP"

    run_test "Timing: T2 Polite" \
        "$RUSTNMAP_BIN --scan-syn -T2 -p $TEST_PORTS $TARGET_IP"

    run_test "Timing: T3 Normal" \
        "$RUSTNMAP_BIN --scan-syn -T3 -p $TEST_PORTS $TARGET_IP"

    run_test "Timing: T4 Aggressive" \
        "$RUSTNMAP_BIN --scan-syn -T4 -p $TEST_PORTS $TARGET_IP"

    run_test "Timing: T5 Insane" \
        "$RUSTNMAP_BIN --scan-syn -T5 -p $TEST_PORTS $TARGET_IP"

    run_test "Performance: Scan delay" \
        "$RUSTNMAP_BIN --scan-syn --scan-delay 100 -p $TEST_PORTS $TARGET_IP"

    run_test "Performance: Min parallelism" \
        "$RUSTNMAP_BIN --scan-syn --min-parallelism 10 -p $TEST_PORTS $TARGET_IP"

    run_test "Performance: Max parallelism" \
        "$RUSTNMAP_BIN --scan-syn --max-parallelism 50 -p $TEST_PORTS $TARGET_IP"

    run_test "Performance: Min rate" \
        "$RUSTNMAP_BIN --scan-syn --min-rate 50 -p $TEST_PORTS $TARGET_IP"

    run_test "Performance: Max rate" \
        "$RUSTNMAP_BIN --scan-syn --max-rate 500 -p $TEST_PORTS $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 6: Firewall/IDS Evasion Tests (9 options)
# ============================================================
test_evasion() {
    log "${YELLOW}Testing Firewall/IDS Evasion${NC}"

    run_test "Evasion: Decoy scan" \
        "$RUSTNMAP_BIN --scan-syn -D RND:10 -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Spoof IP" \
        "$RUSTNMAP_BIN --scan-syn -S 192.168.1.100 -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Interface specification" \
        "$RUSTNMAP_BIN --scan-syn -e lo -p $TEST_PORTS $ALT_TARGET"

    run_test "Evasion: Fragment packets (MTU)" \
        "$RUSTNMAP_BIN --scan-syn -f 24 -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Source port" \
        "$RUSTNMAP_BIN --scan-syn -g 53 -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Data length" \
        "$RUSTNMAP_BIN --scan-syn --data-length 50 -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Data hex" \
        "$RUSTNMAP_BIN --scan-syn --data-hex '48656c6c6f' -p $TEST_PORTS $TARGET_IP"

    run_test "Evasion: Data string" \
        "$RUSTNMAP_BIN --scan-syn --data-string 'HelloWorld' -p $TEST_PORTS $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 7: Output Format Tests (13+ options)
# ============================================================
test_output_formats() {
    log "${YELLOW}Testing Output Formats${NC}"

    local output_base="${TEST_OUTPUT_DIR}/test_output_${TIMESTAMP}"

    run_test "Output: Normal output (-oN)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oN ${output_base}.normal $TARGET_IP"

    run_test "Output: XML output (-oX)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oX ${output_base}.xml $TARGET_IP"

    run_test "Output: Grepable output (-oG)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oG ${output_base}.gnmap $TARGET_IP"

    run_test "Output: JSON output (-oJ)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oJ ${output_base}.json $TARGET_IP"

    run_test "Output: NDJSON output" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --output-ndjson ${output_base}.ndjson $TARGET_IP"

    run_test "Output: Markdown output" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --output-markdown ${output_base}.md $TARGET_IP"

    run_test "Output: All formats (-oA)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oA ${output_base}_all $TARGET_IP"

    run_test "Output: Script kiddie format" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --output-script-kiddie $TARGET_IP"

    run_test "Output: No output" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --no-output $TARGET_IP"

    run_test "Output: Streaming output" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --stream $TARGET_IP"

    run_test "Output: Append output" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -oN ${output_base}.append --append-output $TARGET_IP"

    run_test "Output: Verbose (-v)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -v $TARGET_IP"

    run_test "Output: Very verbose (-vv)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -vv $TARGET_IP"

    run_test "Output: Extra verbose (-vvv)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -vvv $TARGET_IP"

    run_test "Output: Quiet (-q)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -q $TARGET_IP"

    run_test "Output: Debug (-d)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -d $TARGET_IP"

    run_test "Output: Double debug (-dd)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -dd $TARGET_IP"

    run_test "Output: Triple debug (-ddd)" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS -ddd $TARGET_IP"

    run_test "Output: Reasons" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --reasons $TARGET_IP"

    run_test "Output: Open only" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --open $TARGET_IP"

    run_test "Output: Packet trace" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --packet-trace $TARGET_IP"

    run_test "Output: Interface list" \
        "$RUSTNMAP_BIN --if-list"

    sleep 2
}

# ============================================================
# Category 8: Scripting Tests (4 options)
# ============================================================
test_scripting() {
    log "${YELLOW}Testing Scripting (NSE)${NC}"

    run_test "Script: Default scripts" \
        "$RUSTNMAP_BIN --script default -p $TEST_PORTS $TARGET_IP"

    run_test "Script: Specific script" \
        "$RUSTNMAP_BIN --script http-title -p 80,443 $TARGET_IP"

    run_test "Script: Script arguments" \
        "$RUSTNMAP_BIN --script=http-title --script-args 'http.useragent=\"Mozilla\"' -p 80,443 $TARGET_IP"

    run_test "Script: Script help" \
        "$RUSTNMAP_BIN --script-help http-title"

    run_test "Script: Update database" \
        "$RUSTNMAP_BIN --script-updatedb"

    sleep 2
}

# ============================================================
# Category 9: Miscellaneous Tests (8 options)
# ============================================================
test_miscellaneous() {
    log "${YELLOW}Testing Miscellaneous Options${NC}"

    run_test "Misc: Traceroute" \
        "$RUSTNMAP_BIN --traceroute -p $TEST_PORTS $TARGET_IP"

    run_test "Misc: Traceroute with hops" \
        "$RUSTNMAP_BIN --traceroute --traceroute-hops 20 -p $TEST_PORTS $TARGET_IP"

    run_test "Misc: Input file" \
        "echo '$TARGET_IP' > /tmp/rustnmap_targets.txt && $RUSTNMAP_BIN -i /tmp/rustnmap_targets.txt -p $TEST_PORTS"

    run_test "Misc: Randomize hosts" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --randomize-hosts $TARGET_IP $ALT_TARGET"

    run_test "Misc: Host group size" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --host-group-size 5 $TARGET_IP"

    run_test "Misc: Ping type" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --ping-type ack $TARGET_IP"

    run_test "Misc: Disable ping" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --disable-ping $TARGET_IP"

    run_test "Misc: Host timeout" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --host-timeout 30000 $TARGET_IP"

    run_test "Misc: Print URLs" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --print-urls $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 10: Scan Management Tests (2.0 features, 15 options)
# ============================================================
test_scan_management() {
    log "${YELLOW}Testing Scan Management (2.0 Features)${NC}"

    run_test "Management: List profiles" \
        "$RUSTNMAP_BIN --list-profiles"

    run_test "Management: Generate profile" \
        "$RUSTNMAP_BIN --generate-profile > ${TEST_OUTPUT_DIR}/profile_template_${TIMESTAMP}.yaml"

    run_test "Management: Validate profile (invalid profile)" \
        "$RUSTNMAP_BIN --validate-profile /tmp/nonexistent.yaml" \
        "true"

    run_test "Management: Use profile (requires valid profile)" \
        "$RUSTNMAP_BIN --profile ${TEST_OUTPUT_DIR}/profile_template_${TIMESTAMP}.yaml $TARGET_IP" \
        "true"

    run_test "Management: Diff (requires two scan files)" \
        "$RUSTNMAP_BIN --diff /tmp/scan1.xml /tmp/scan2.xml" \
        "true"

    run_test "Management: From history (requires valid scan IDs)" \
        "$RUSTNMAP_BIN --from-history 1 2" \
        "true"

    run_test "Management: Diff format (text)" \
        "$RUSTNMAP_BIN --diff /tmp/scan1.xml /tmp/scan2.xml --diff-format text" \
        "true"

    run_test "Management: Diff format (json)" \
        "$RUSTNMAP_BIN --diff /tmp/scan1.xml /tmp/scan2.xml --diff-format json" \
        "true"

    run_test "Management: Vulns only filter" \
        "$RUSTNMAP_BIN --diff /tmp/scan1.xml /tmp/scan2.xml --vulns-only" \
        "true"

    run_test "Management: Scan ID lookup (requires valid scan ID)" \
        "$RUSTNMAP_BIN --scan-id 1" \
        "true"

    run_test "Management: Query history" \
        "$RUSTNMAP_BIN --history --limit 10"

    run_test "Management: History with target filter" \
        "$RUSTNMAP_BIN --history --target $TARGET_IP --limit 5"

    run_test "Management: History with type filter" \
        "$RUSTNMAP_BIN --history --scan-type-filter syn --limit 5"

    run_test "Management: History with date range" \
        "$RUSTNMAP_BIN --history --since '2025-01-01' --until '2025-12-31'"

    run_test "Management: Custom db path" \
        "$RUSTNMAP_BIN --history --db-path /tmp/test_rustnmap.db --limit 1"

    sleep 2
}

# ============================================================
# Category 11: Configuration Tests (2 options)
# ============================================================
test_configuration() {
    log "${YELLOW}Testing Configuration${NC}"

    run_test "Config: Custom datadir" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --datadir /tmp/rustnmap_test_data $TARGET_IP"

    run_test "Config: Custom DNS server" \
        "$RUSTNMAP_BIN --scan-syn -p $TEST_PORTS --dns-server 1.1.1.1:53 $TARGET_IP"

    sleep 2
}

# ============================================================
# Category 12: Edge Case and Validation Tests
# ============================================================
test_edge_cases() {
    log "${YELLOW}Testing Edge Cases and Validation${NC}"

    # Invalid timing level
    run_test "Edge: Invalid timing level (should fail)" \
        "$RUSTNMAP_BIN --scan-syn -T10 -p $TEST_PORTS $TARGET_IP" \
        "true"

    # Invalid version intensity
    run_test "Edge: Invalid version intensity (should fail)" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 15 -p $TEST_PORTS $TARGET_IP" \
        "true"

    # Invalid MTU
    run_test "Edge: Invalid MTU (should fail)" \
        "$RUSTNMAP_BIN --scan-syn -f 2000 -p $TEST_PORTS $TARGET_IP" \
        "true"

    # Conflicting port specifications
    run_test "Edge: Conflicting port specs (should fail)" \
        "$RUSTNMAP_BIN --scan-syn -p 22,80 -F $TARGET_IP" \
        "true"

    # Valid boundary timing levels
    run_test "Edge: Timing boundary T0" \
        "$RUSTNMAP_BIN --scan-syn -T0 -p $TEST_PORTS $TARGET_IP"

    run_test "Edge: Timing boundary T5" \
        "$RUSTNMAP_BIN --scan-syn -T5 -p $TEST_PORTS $TARGET_IP"

    # Valid boundary version intensity
    run_test "Edge: Version intensity boundary 0" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 0 -p $TEST_PORTS $TARGET_IP"

    run_test "Edge: Version intensity boundary 9" \
        "$RUSTNMAP_BIN --service-detection --version-intensity 9 -p $TEST_PORTS $TARGET_IP"

    # Valid boundary MTU
    run_test "Edge: MTU boundary 8" \
        "$RUSTNMAP_BIN --scan-syn -f 8 -p $TEST_PORTS $TARGET_IP"

    run_test "Edge: MTU boundary 1500" \
        "$RUSTNMAP_BIN --scan-syn -f 1500 -p $TEST_PORTS $TARGET_IP"

    sleep 2
}

# ============================================================
# Main Execution
# ============================================================
main() {
    log "=========================================================="
    log "RustNmap Comprehensive CLI Test Suite"
    log "Started: $(date)"
    log "Target: $TARGET_IP"
    log "=========================================================="
    log ""

    # Build rustnmap first
    log "Building rustnmap..."
    if ! cargo build --release --quiet 2>/dev/null; then
        log "${RED}ERROR: Failed to build rustnmap${NC}"
        exit 1
    fi
    log "${GREEN}Build successful${NC}"
    log ""

    # Check if binary exists
    if [[ ! -f "$RUSTNMAP_BIN" ]]; then
        log "${RED}ERROR: rustnmap binary not found at $RUSTNMAP_BIN${NC}"
        exit 1
    fi

    # Run all test categories
    test_target_specification
    test_scan_types
    test_port_specification
    test_service_os_detection
    test_timing_performance
    test_evasion
    test_output_formats
    test_scripting
    test_miscellaneous
    test_scan_management
    test_configuration
    test_edge_cases

    # Generate final report
    log ""
    log "=========================================================="
    log "FINAL SUMMARY"
    log "=========================================================="
    log "Total Tests: $TOTAL_TESTS"
    log "Passed: ${GREEN}$PASSED_TESTS${NC}"
    log "Failed: ${RED}$FAILED_TESTS${NC}"

    local pass_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        pass_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "0")
    fi
    log "Pass Rate: ${pass_rate}%"

    if [[ $FAILED_TESTS -gt 0 ]]; then
        log ""
        log "${RED}Failed tests:${NC}"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            log "  - $test_name"
        done
    fi

    # Save report to file
    {
        echo "RustNmap CLI Test Report"
        echo "Generated: $(date)"
        echo ""
        echo "Test Configuration:"
        echo "  Target IP: $TARGET_IP"
        echo "  Test Ports: $TEST_PORTS"
        echo "  Binary: $RUSTNMAP_BIN"
        echo ""
        echo "Test Results:"
        echo "  Total Tests: $TOTAL_TESTS"
        echo "  Passed: $PASSED_TESTS"
        echo "  Failed: $FAILED_TESTS"
        echo "  Pass Rate: ${pass_rate}%"
        echo ""
        if [[ $FAILED_TESTS -gt 0 ]]; then
            echo "Failed Tests:"
            for test_name in "${FAILED_TEST_NAMES[@]}"; do
                echo "  - $test_name"
            done
            echo ""
        fi
        if [[ $PASSED_TESTS -gt 0 ]]; then
            echo "Passed Tests:"
            for test_name in "${PASSED_TEST_NAMES[@]}"; do
                echo "  - $test_name"
            done
        fi
    } > "$REPORT_FILE"

    log ""
    log "Log saved to: $LOG_FILE"
    log "Report saved to: $REPORT_FILE"
    log "Test outputs saved to: $TEST_OUTPUT_DIR"

    # Exit with error code if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
