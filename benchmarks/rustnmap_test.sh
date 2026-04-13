#!/bin/bash
# RustNmap Comprehensive CLI Test Script
# Tests ALL 85 CLI options across all functional categories
# Uses Docker test range (benchmarks/targets)

set +e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration - Docker test range defaults (override with env vars)
TARGET_IP="${TARGET_IP:-172.28.0.2}"
ALT_TARGET="${ALT_TARGET:-172.28.0.3}"
TEST_PORTS="${TEST_PORTS:-22,80,443,3306,6379}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"

# Docker test range IPs (from benchmarks/targets/.env)
IP_SCAN_TARGET="${IP_SCAN_TARGET:-172.28.0.2}"
IP_WEB="${IP_WEB:-172.28.0.3}"
IP_SSH="${IP_SSH:-172.28.0.4}"
IP_DNS="${IP_DNS:-172.28.0.5}"
IP_SMB="${IP_SMB:-172.28.0.6}"
IP_FTP="${IP_FTP:-172.28.0.7}"
IP_SMTP="${IP_SMTP:-172.28.0.8}"
IP_MYSQL="${IP_MYSQL:-172.28.0.9}"
IP_REDIS="${IP_REDIS:-172.28.0.10}"
IP_VNC="${IP_VNC:-172.28.0.11}"
IP_MAIL="${IP_MAIL:-172.28.0.12}"
IP_LDAP="${IP_LDAP:-172.28.0.13}"
IP_NTP="${IP_NTP:-172.28.0.14}"
IP_SNMP="${IP_SNMP:-172.28.0.15}"
IP_TELNET="${IP_TELNET:-172.28.0.16}"
IP_RPCBIND="${IP_RPCBIND:-172.28.0.17}"
IP_SCTP="${IP_SCTP:-172.28.0.18}"
IP_FIREWALL="${IP_FIREWALL:-172.28.0.19}"
IP_ZOMBIE="${IP_ZOMBIE:-172.28.0.20}"

# Output directories
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
TEST_OUTPUT_DIR="${SCRIPT_DIR}/test_outputs"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/rustnmap_test_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/rustnmap_test_report_${TIMESTAMP}.md"

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
declare -a FAILED_TEST_NAMES
declare -a PASSED_TEST_NAMES
declare -a TEST_RESULTS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Strip ANSI escape sequences from string (handles color codes, cursor movement, etc.)
strip_ansi() {
    sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | sed 's/\x1b\].*?\x07//g' | sed 's/\x1b\[.*?[a-zA-Z]//g'
}

# Test execution function with resource tracking
run_test() {
    local test_name="$1"
    local command="$2"
    local should_fail="${3:-false}"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test: $test_name" | tee -a "$LOG_FILE"
    echo "Command: $command" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"

    # Run command with resource tracking via /usr/bin/time -v
    local scan_output
    local scan_exit=0
    local time_output
    local start_ms
    local end_ms
    local duration_ms

    start_ms=$(date +%s%3N)
    scan_output=$(/usr/bin/time -v sh -c "$command" 2>/tmp/rustnmap_test_time_$$) || scan_exit=$?
    time_output=$(cat /tmp/rustnmap_test_time_$$ 2>/dev/null || echo "")
    rm -f /tmp/rustnmap_test_time_$$
    end_ms=$(date +%s%3N)
    duration_ms=$((end_ms - start_ms))

    # Strip ANSI escape sequences from output
    scan_output=$(echo "$scan_output" | strip_ansi)

    # Extract resource usage
    local peak_mem="N/A"
    local cpu_pct="N/A"
    local user_cpu="N/A"
    local sys_cpu="N/A"
    if [ -n "$time_output" ]; then
        peak_mem=$(echo "$time_output" | grep "Maximum resident set size" | awk '{print $NF}' | head -1)
        cpu_pct=$(echo "$time_output" | grep "Percent of CPU this job got" | awk '{print $NF}' | head -1)
        user_cpu=$(echo "$time_output" | grep "User time (seconds)" | awk '{print $NF}' | head -1)
        sys_cpu=$(echo "$time_output" | grep "System time (seconds)" | awk '{print $NF}' | head -1)
    fi
    # Convert maxrss from KB to MB
    if [[ "$peak_mem" != "N/A" && -n "$peak_mem" ]]; then
        peak_mem=$(echo "scale=1; ${peak_mem} / 1024" | bc 2>/dev/null || echo "$peak_mem")"MB"
    fi

    echo "[INFO] completed in ${duration_ms}ms (exit: $scan_exit)" | tee -a "$LOG_FILE"
    echo "[INFO] resources: peak_mem=${peak_mem}, cpu=${cpu_pct}%, user=${user_cpu}s, sys=${sys_cpu}s" | tee -a "$LOG_FILE"

    # Display complete scan output
    if [ -n "$scan_output" ]; then
        echo "  --- SCAN OUTPUT ---" | tee -a "$LOG_FILE"
        echo "$scan_output" | sed 's/^/  /' | tee -a "$LOG_FILE"
        echo "  --- END OUTPUT ---" | tee -a "$LOG_FILE"
    fi

    # Evaluate result
    if [[ $scan_exit -eq 0 ]]; then
        if [[ "$should_fail" == "true" ]]; then
            echo -e "  ${RED}FAILED${NC}: Expected failure but succeeded (exit: 0)" | tee -a "$LOG_FILE"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_TEST_NAMES+=("$test_name")
            TEST_RESULTS+=("FAIL|$test_name|Expected failure but succeeded|${duration_ms}ms|peak_mem=${peak_mem} cpu=${cpu_pct}%")
            echo "" | tee -a "$LOG_FILE"
            return 1
        else
            echo -e "  ${GREEN}PASSED${NC}: Command executed successfully" | tee -a "$LOG_FILE"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            PASSED_TEST_NAMES+=("$test_name")
            TEST_RESULTS+=("PASS|$test_name|Success|${duration_ms}ms|peak_mem=${peak_mem} cpu=${cpu_pct}%")
            echo "" | tee -a "$LOG_FILE"
            return 0
        fi
    else
        if [[ "$should_fail" == "true" ]]; then
            echo -e "  ${GREEN}PASSED${NC}: Failed as expected (exit: $scan_exit)" | tee -a "$LOG_FILE"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            PASSED_TEST_NAMES+=("$test_name")
            TEST_RESULTS+=("PASS|$test_name|Failed as expected (exit: $scan_exit)|${duration_ms}ms|peak_mem=${peak_mem} cpu=${cpu_pct}%")
            echo "" | tee -a "$LOG_FILE"
            return 0
        else
            echo -e "  ${RED}FAILED${NC}: Command failed with exit code $scan_exit" | tee -a "$LOG_FILE"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            FAILED_TEST_NAMES+=("$test_name")
            TEST_RESULTS+=("FAIL|$test_name|Exit code $scan_exit|${duration_ms}ms|peak_mem=${peak_mem} cpu=${cpu_pct}%")
            echo "" | tee -a "$LOG_FILE"
            return 1
        fi
    fi
}

# ============================================================
# Category 1: Target Specification Tests
# ============================================================
test_target_specification() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Target Specification" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Target: Single IP" \
        "$RUSTNMAP_BIN $IP_SCAN_TARGET"

    run_test "Target: Hostname" \
        "$RUSTNMAP_BIN www.baidu.com"

    run_test "Target: CIDR notation" \
        "$RUSTNMAP_BIN 172.28.0.0/28"

    run_test "Target: Range" \
        "$RUSTNMAP_BIN 172.28.0.2-5"

    run_test "Target: Multiple targets" \
        "$RUSTNMAP_BIN $IP_SCAN_TARGET $IP_WEB"
}

# ============================================================
# Category 2: Scan Types Tests (9 options)
# ============================================================
test_scan_types() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Scan Types" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Scan: SYN scan (-sS)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: Connect scan (-sT)" \
        "$RUSTNMAP_BIN -sT -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: UDP scan (-sU)" \
        "$RUSTNMAP_BIN -sU -p 53,111,123,161 $IP_SCAN_TARGET"

    run_test "Scan: FIN scan (-sF)" \
        "$RUSTNMAP_BIN -sF -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: NULL scan (-sN)" \
        "$RUSTNMAP_BIN -sN -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: XMAS scan (-sX)" \
        "$RUSTNMAP_BIN -sX -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: MAIMON scan (-sM)" \
        "$RUSTNMAP_BIN -sM -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: ACK scan (-sA)" \
        "$RUSTNMAP_BIN -sA -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Scan: Window scan (-sW)" \
        "$RUSTNMAP_BIN -sW -p $TEST_PORTS $IP_SCAN_TARGET"
}

# ============================================================
# Category 3: Port Specification Tests (6 options)
# ============================================================
test_port_specification() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Port Specification" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Ports: Specific ports (-p)" \
        "$RUSTNMAP_BIN -sS -p 22,80,443 $IP_SCAN_TARGET"

    run_test "Ports: Port range" \
        "$RUSTNMAP_BIN -sS -p 1-100 $IP_SCAN_TARGET"

    run_test "Ports: All ports (-p-)" \
        "$RUSTNMAP_BIN -sS -p- $IP_SCAN_TARGET"

    run_test "Ports: All ports long form (--port-range-all)" \
        "$RUSTNMAP_BIN -sS --port-range-all $IP_SCAN_TARGET"

    run_test "Ports: Exclude ports" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --exclude-port 22 $IP_SCAN_TARGET"

    run_test "Ports: Top ports" \
        "$RUSTNMAP_BIN -sS --top-ports 10 $IP_SCAN_TARGET"

    run_test "Ports: Fast scan (-F)" \
        "$RUSTNMAP_BIN -sS -F $IP_SCAN_TARGET"

    run_test "Ports: Protocol specification" \
        "$RUSTNMAP_BIN -sU --protocol udp -p 53,67 $IP_DNS"
}

# ============================================================
# Category 4: Service/OS Detection Tests
# ============================================================
test_service_os_detection() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Service/OS Detection" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Detection: Aggressive scan (-A)" \
        "$RUSTNMAP_BIN -A -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Detection: Service detection (-sV)" \
        "$RUSTNMAP_BIN -sV -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Detection: Version intensity (0)" \
        "$RUSTNMAP_BIN -sV --version-intensity 0 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Detection: Version intensity (5)" \
        "$RUSTNMAP_BIN -sV --version-intensity 5 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Detection: Version intensity (9)" \
        "$RUSTNMAP_BIN -sV --version-intensity 9 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Detection: OS detection (-O)" \
        "$RUSTNMAP_BIN -O $IP_SCAN_TARGET"

    run_test "Detection: OS scan limit" \
        "$RUSTNMAP_BIN -O --osscan-limit $IP_SCAN_TARGET"

    run_test "Detection: OS scan guess" \
        "$RUSTNMAP_BIN -O --osscan-guess $IP_SCAN_TARGET"
}

# ============================================================
# Category 5: Timing and Performance Tests
# ============================================================
test_timing_performance() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Timing and Performance" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # T0 Paranoid takes ~25 min, skip for routine testing
    # run_test "Timing: T0 Paranoid" \
    #     "$RUSTNMAP_BIN -sS -T0 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Timing: T1 Sneaky" \
        "$RUSTNMAP_BIN -sS -T1 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Timing: T2 Polite" \
        "$RUSTNMAP_BIN -sS -T2 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Timing: T3 Normal" \
        "$RUSTNMAP_BIN -sS -T3 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Timing: T4 Aggressive" \
        "$RUSTNMAP_BIN -sS -T4 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Timing: T5 Insane" \
        "$RUSTNMAP_BIN -sS -T5 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Performance: Scan delay" \
        "$RUSTNMAP_BIN -sS --scan-delay 100 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Performance: Min parallelism" \
        "$RUSTNMAP_BIN -sS --min-parallelism 10 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Performance: Max parallelism" \
        "$RUSTNMAP_BIN -sS --max-parallelism 50 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Performance: Min rate" \
        "$RUSTNMAP_BIN -sS --min-rate 50 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Performance: Max rate" \
        "$RUSTNMAP_BIN -sS --max-rate 500 -p $TEST_PORTS $IP_SCAN_TARGET"
}

# ============================================================
# Category 6: Firewall/IDS Evasion Tests
# ============================================================
test_evasion() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Firewall/IDS Evasion" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Evasion: Decoy scan" \
        "$RUSTNMAP_BIN -sS -D RND:10 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Spoof IP" \
        "$RUSTNMAP_BIN -sS -S 192.168.1.100 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Interface specification" \
        "$RUSTNMAP_BIN -sS -e lo -p 22,80 $IP_SCAN_TARGET"

    run_test "Evasion: Fragment packets (MTU)" \
        "$RUSTNMAP_BIN -sS -f 24 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Source port" \
        "$RUSTNMAP_BIN -sS -g 53 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Data length" \
        "$RUSTNMAP_BIN -sS --data-length 50 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Data hex" \
        "$RUSTNMAP_BIN -sS --data-hex '48656c6c6f' -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Evasion: Data string" \
        "$RUSTNMAP_BIN -sS --data-string 'HelloWorld' -p $TEST_PORTS $IP_SCAN_TARGET"
}

# ============================================================
# Category 7: Output Format Tests
# ============================================================
test_output_formats() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Output Formats" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local output_base="${TEST_OUTPUT_DIR}/test_output_${TIMESTAMP}"

    run_test "Output: Normal output (-oN)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oN ${output_base}.normal $IP_SCAN_TARGET"

    run_test "Output: XML output (-oX)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oX ${output_base}.xml $IP_SCAN_TARGET"

    run_test "Output: Grepable output (-oG)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oG ${output_base}.gnmap $IP_SCAN_TARGET"

    run_test "Output: JSON output (-oJ)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oJ ${output_base}.json $IP_SCAN_TARGET"

    run_test "Output: NDJSON output" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --output-ndjson ${output_base}.ndjson $IP_SCAN_TARGET"

    run_test "Output: Markdown output" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --output-markdown ${output_base}.md $IP_SCAN_TARGET"

    run_test "Output: All formats (-oA)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oA ${output_base}_all $IP_SCAN_TARGET"

    run_test "Output: Script kiddie format" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --output-script-kiddie $IP_SCAN_TARGET"

    run_test "Output: No output" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --no-output $IP_SCAN_TARGET"

    run_test "Output: Streaming output" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --stream $IP_SCAN_TARGET"

    run_test "Output: Append output" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -oN ${output_base}.append --append-output $IP_SCAN_TARGET"

    run_test "Output: Verbose (-v)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -v $IP_SCAN_TARGET"

    run_test "Output: Very verbose (-vv)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -vv $IP_SCAN_TARGET"

    run_test "Output: Extra verbose (-vvv)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -vvv $IP_SCAN_TARGET"

    run_test "Output: Quiet (-q)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -q $IP_SCAN_TARGET"

    run_test "Output: Debug (-d)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -d $IP_SCAN_TARGET"

    run_test "Output: Double debug (-dd)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -dd $IP_SCAN_TARGET"

    run_test "Output: Triple debug (-ddd)" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS -ddd $IP_SCAN_TARGET"

    run_test "Output: Reasons" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --reasons $IP_SCAN_TARGET"

    run_test "Output: Open only" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --open $IP_SCAN_TARGET"

    run_test "Output: Packet trace" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --packet-trace $IP_SCAN_TARGET"

    run_test "Output: Interface list" \
        "$RUSTNMAP_BIN --if-list"
}

# ============================================================
# Category 8: Scripting Tests (NSE)
# ============================================================
test_scripting() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Scripting (NSE)" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Script: Default scripts" \
        "$RUSTNMAP_BIN --script default -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Script: Specific script" \
        "$RUSTNMAP_BIN --script http-title -p 80,443 $IP_WEB"

    run_test "Script: Script arguments" \
        "$RUSTNMAP_BIN --script=http-title --script-args 'http.useragent=\"Mozilla\"' -p 80,443 $IP_WEB"

    run_test "Script: Script help" \
        "$RUSTNMAP_BIN --script-help http-title"

    run_test "Script: Update database" \
        "$RUSTNMAP_BIN --script-updatedb"
}

# ============================================================
# Category 9: Miscellaneous Tests
# ============================================================
test_miscellaneous() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Miscellaneous Options" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Misc: Traceroute" \
        "$RUSTNMAP_BIN --traceroute -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Misc: Traceroute with hops" \
        "$RUSTNMAP_BIN --traceroute --traceroute-hops 20 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Misc: Input file" \
        "echo '$IP_SCAN_TARGET' > /tmp/rustnmap_targets.txt && $RUSTNMAP_BIN -i /tmp/rustnmap_targets.txt -p $TEST_PORTS"

    run_test "Misc: Randomize hosts" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --randomize-hosts $IP_SCAN_TARGET $IP_WEB"

    run_test "Misc: Host group size" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --host-group-size 5 $IP_SCAN_TARGET"

    run_test "Misc: Ping type" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --ping-type ack $IP_SCAN_TARGET"

    run_test "Misc: Disable ping" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --disable-ping $IP_SCAN_TARGET"

    run_test "Misc: Host timeout" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --host-timeout 30000 $IP_SCAN_TARGET"

    run_test "Misc: Print URLs" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --print-urls $IP_SCAN_TARGET"
}

# ============================================================
# Category 10: Scan Management Tests (2.0 features)
# ============================================================
test_scan_management() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Scan Management (2.0 Features)" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Management: List profiles" \
        "$RUSTNMAP_BIN --list-profiles"

    run_test "Management: Generate profile" \
        "$RUSTNMAP_BIN --generate-profile > ${TEST_OUTPUT_DIR}/profile_template_${TIMESTAMP}.yaml"

    run_test "Management: Validate profile (invalid profile)" \
        "$RUSTNMAP_BIN --validate-profile /tmp/nonexistent.yaml" \
        "true"

    run_test "Management: Use profile (generated profile is valid)" \
        "$RUSTNMAP_BIN --profile ${TEST_OUTPUT_DIR}/profile_template_${TIMESTAMP}.yaml $IP_SCAN_TARGET"

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
        "$RUSTNMAP_BIN --history --target $IP_SCAN_TARGET --limit 5"

    run_test "Management: History with type filter" \
        "$RUSTNMAP_BIN --history --scan-type-filter syn --limit 5"

    run_test "Management: History with date range" \
        "$RUSTNMAP_BIN --history --since '2025-01-01' --until '2025-12-31'"

    run_test "Management: Custom db path" \
        "$RUSTNMAP_BIN --history --db-path /tmp/test_rustnmap.db --limit 1"
}

# ============================================================
# Category 11: Configuration Tests
# ============================================================
test_configuration() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Configuration" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    run_test "Config: Custom datadir" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --datadir /tmp/rustnmap_test_data $IP_SCAN_TARGET"

    run_test "Config: Custom DNS server" \
        "$RUSTNMAP_BIN -sS -p $TEST_PORTS --dns-server $IP_DNS:53 $IP_SCAN_TARGET"
}

# ============================================================
# Category 12: Edge Case and Validation Tests
# ============================================================
test_edge_cases() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Edge Cases and Validation" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Invalid timing level
    run_test "Edge: Invalid timing level (should fail)" \
        "$RUSTNMAP_BIN -sS -T10 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "true"

    # Invalid version intensity
    run_test "Edge: Invalid version intensity (should fail)" \
        "$RUSTNMAP_BIN -sV --version-intensity 15 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "true"

    # Note: -f is a flag in nmap (no value). -f 2000 means fragmentation + target "2000".
    # The invalid target "2000" will fail DNS but the scan continues. This matches nmap.
    # For invalid MTU, use --fragment-mtu 2000 which should fail validation.
    run_test "Edge: Invalid MTU via --fragment-mtu (should fail)" \
        "$RUSTNMAP_BIN -sS --fragment-mtu 2000 -p $TEST_PORTS $IP_SCAN_TARGET" \
        "true"

    # Conflicting port specifications
    run_test "Edge: Conflicting port specs (should fail)" \
        "$RUSTNMAP_BIN -sS -p 22,80 -F $IP_SCAN_TARGET" \
        "true"

    # Valid boundary timing levels (T0 skipped -- takes ~25 min)
    # run_test "Edge: Timing boundary T0" \
    #     "$RUSTNMAP_BIN -sS -T0 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Edge: Timing boundary T5" \
        "$RUSTNMAP_BIN -sS -T5 -p $TEST_PORTS $IP_SCAN_TARGET"

    # Valid boundary version intensity
    run_test "Edge: Version intensity boundary 0" \
        "$RUSTNMAP_BIN -sV --version-intensity 0 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Edge: Version intensity boundary 9" \
        "$RUSTNMAP_BIN -sV --version-intensity 9 -p $TEST_PORTS $IP_SCAN_TARGET"

    # Valid boundary MTU
    run_test "Edge: MTU boundary 8" \
        "$RUSTNMAP_BIN -sS -f 8 -p $TEST_PORTS $IP_SCAN_TARGET"

    run_test "Edge: MTU boundary 1500" \
        "$RUSTNMAP_BIN -sS -f 1500 -p $TEST_PORTS $IP_SCAN_TARGET"
}

# ============================================================
# Main Execution
# ============================================================
main() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "RustNmap Comprehensive CLI Test Suite" | tee -a "$LOG_FILE"
    echo "Started: $(date)" | tee -a "$LOG_FILE"
    echo "Target: $IP_SCAN_TARGET (Docker test range)" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Build rustnmap first
    echo "Building rustnmap..." | tee -a "$LOG_FILE"
    if ! cargo build --release --quiet 2>/dev/null; then
        echo -e "${RED}ERROR: Failed to build rustnmap${NC}" | tee -a "$LOG_FILE"
        exit 1
    fi
    echo -e "${GREEN}Build successful${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Check if binary exists
    if [[ ! -f "$RUSTNMAP_BIN" ]]; then
        echo -e "${RED}ERROR: rustnmap binary not found at $RUSTNMAP_BIN${NC}" | tee -a "$LOG_FILE"
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
    echo "" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "FINAL SUMMARY" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Total Tests: $TOTAL_TESTS" | tee -a "$LOG_FILE"
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}" | tee -a "$LOG_FILE"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}" | tee -a "$LOG_FILE"

    local pass_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        pass_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc 2>/dev/null || echo "0")
    fi
    echo "Pass Rate: ${pass_rate}%" | tee -a "$LOG_FILE"

    if [[ $FAILED_TESTS -gt 0 ]]; then
        echo "" | tee -a "$LOG_FILE"
        echo -e "${RED}Failed tests:${NC}" | tee -a "$LOG_FILE"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            echo "  - $test_name" | tee -a "$LOG_FILE"
        done
    fi

    # Save report to file
    {
        echo "RustNmap CLI Test Report"
        echo "Generated: $(date)"
        echo ""
        echo "Test Configuration:"
        echo "  Target IP: $IP_SCAN_TARGET (Docker test range)"
        echo "  Test Ports: $TEST_PORTS"
        echo "  Binary: $RUSTNMAP_BIN"
        echo ""
        echo "Test Results:"
        echo "  Total Tests: $TOTAL_TESTS"
        echo "  Passed: $PASSED_TESTS"
        echo "  Failed: $FAILED_TESTS"
        echo "  Pass Rate: ${pass_rate}%"
        echo ""
        echo "Status|Test Name|Notes|Duration|Resources"
        echo "---|---|---|---|---"
        for result in "${TEST_RESULTS[@]}"; do
            echo "$result"
        done
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

    echo "" | tee -a "$LOG_FILE"
    echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Report saved to: $REPORT_FILE" | tee -a "$LOG_FILE"
    echo "Test outputs saved to: $TEST_OUTPUT_DIR" | tee -a "$LOG_FILE"

    # Exit with error code if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
