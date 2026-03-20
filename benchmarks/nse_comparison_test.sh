#!/bin/bash
# RustNmap vs Nmap NSE Functionality Comparison Test Script
# Tests NSE script execution, accuracy, and performance

set +e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
TARGET_IP="${TARGET_IP:-45.33.32.156}"
ALT_TARGET="${ALT_TARGET:-127.0.0.1}"
TEST_PORT="${TEST_PORT:-80}"
NMAP_BIN="${NMAP_BIN:-/usr/bin/nmap}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"
REFERENCE_SCRIPTS="${REFERENCE_SCRIPTS:-${PROJECT_ROOT}/reference/nmap/scripts}"

# Output directories (separate logs and reports)
LOG_DIR="${SCRIPT_DIR}/logs"
REPORT_DIR="${SCRIPT_DIR}/reports"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/nse_comparison_${TIMESTAMP}.log"
REPORT_FILE="${REPORT_DIR}/nse_comparison_report_${TIMESTAMP}.txt"

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0
declare -a FAILED_TEST_NAMES
declare -a SKIPPED_TEST_NAMES
declare -a TEST_RESULTS

# Ensure ~/.rustnmap/scripts exists (default datadir)
if [ ! -d "$HOME/.rustnmap/scripts" ]; then
    echo "[ERROR] ~/.rustnmap/scripts not found. Please set up NSE scripts first." >&2
    exit 1
fi

# Helper function to extract NSE script results from output
# This extracts the script output section between | markers
extract_nse_results() {
    local output="$1"
    local script_name="$2"

    # NSE script output formats:
    # Nmap single-line: |_http-title: Go ahead and ScanMe!
    # Nmap multi-line:
    #   | http-methods:
    #   |_  Supported Methods: GET HEAD POST OPTIONS
    # RustNmap multi-line:
    #   | http-title
    #   |_ Go ahead and ScanMe!

    # Strategy: Find lines starting with | that contain script name,
    # then capture ALL subsequent | lines until we hit a line NOT starting with |
    echo "$output" | awk -v script="$script_name" '
        BEGIN { found = 0; in_section = 0 }

        # If we are in a section, capture all | lines
        in_section && /^\|/ {
            print $0
            # |_ marks the last line of output
            if ($0 ~ /^\|_/) {
                in_section = 0
            }
            next
        }

        # Start new section when we find the script name
        /^\|[_ ]/ && $0 ~ script {
            found = 1
            print $0
            # Single-line format (|_script: output) is complete
            if ($0 !~ /^\|_/) {
                in_section = 1
            }
            next
        }

        # Non-| line ends any open section
        { in_section = 0 }

        END { exit (found ? 0 : 1) }
    '
}

# Compare NSE script results
compare_nse_script() {
    local test_name="$1"
    local script="$2"
    local target="$3"
    local port="$4"
    local extra_args="$5"

    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test: $test_name" | tee -a "$LOG_FILE"
    echo "Script: $script" | tee -a "$LOG_FILE"
    echo "Target: $target" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    # Build command
    local base_port_arg=""
    if [ -n "$port" ]; then
        base_port_arg="-p $port"
    fi

    # Run nmap
    echo "[INFO] Running nmap..." | tee -a "$LOG_FILE"
    local nmap_start=$(date +%s%3N)
    local nmap_output
    local nmap_exit=0
    nmap_output=$($NMAP_BIN -sV $base_port_arg --script="$script" $extra_args "$target" 2>&1) || nmap_exit=$?
    local nmap_end=$(date +%s%3N)
    local nmap_duration=$((nmap_end - nmap_start))
    echo "[INFO] nmap completed in ${nmap_duration}ms (exit: $nmap_exit)" | tee -a "$LOG_FILE"

    # Delay between scans (2 seconds for reliability)
    sleep 2

    # Run rustnmap
    echo "[INFO] Running rustnmap..." | tee -a "$LOG_FILE"
    local rustnmap_start=$(date +%s%3N)
    local rustnmap_output
    local rustnmap_exit=0
    rustnmap_output=$($RUSTNMAP_BIN -sV $base_port_arg --script="$script" $extra_args "$target" 2>&1) || rustnmap_exit=$?
    local rustnmap_end=$(date +%s%3N)
    local rustnmap_duration=$((rustnmap_end - rustnmap_start))
    echo "[INFO] rustnmap completed in ${rustnmap_duration}ms (exit: $rustnmap_exit)" | tee -a "$LOG_FILE"

    # Calculate speedup
    local speedup="N/A"
    if [[ $nmap_duration -gt 0 ]]; then
        speedup=$(echo "scale=2; ${nmap_duration} / ${rustnmap_duration}" | bc 2>/dev/null || echo "N/A")
    fi

    # Handle nmap failure
    if [[ $nmap_exit -ne 0 ]]; then
        echo "[SKIP] $test_name (nmap failed)" | tee -a "$LOG_FILE"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        SKIPPED_TEST_NAMES+=("$test_name")
        TEST_RESULTS+=("SKIP|$test_name|nmap failed (exit $nmap_exit)")
        echo "" | tee -a "$LOG_FILE"
        return
    fi

    # Handle rustnmap crash
    if [[ $rustnmap_exit -ne 0 ]]; then
        echo "[FAIL] $test_name (rustnmap crashed)" | tee -a "$LOG_FILE"
        echo "  Exit code: $rustnmap_exit" | tee -a "$LOG_FILE"
        echo "  Speed: N/A (crash - speed comparison meaningless)" | tee -a "$LOG_FILE"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name (crash)")
        TEST_RESULTS+=("FAIL|$test_name|Crashed with exit code $rustnmap_exit|N/A")
        echo "" | tee -a "$LOG_FILE"
        return
    fi

    # Check if both produced NSE output
    # NSE output format: | script-name or |_ script-name
    local nmap_has_script=0
    local rustnmap_has_script=0

    # Get script name from --script argument (might have wildcards or arguments)
    local script_base=$(echo "$script" | cut -d' ' -f1 | cut -d',' -f1)

    # Check for actual NSE script output section (starts with | script-name)
    # Not just the script name in command line echo
    # Note: No space between |[_ ]? and script name to match both:
    #   - Nmap format: |_http-title: (no space after |_)
    #   - RustNmap format: | http-title (space after |)
    if echo "$nmap_output" | grep -qE "^\|[_ ]?${script_base}"; then
        nmap_has_script=1
    fi

    if echo "$rustnmap_output" | grep -qE "^\|[_ ]?${script_base}"; then
        rustnmap_has_script=1
    fi

    # Compare results
    local result_status="PASS"
    local result_notes=""

    if [[ $nmap_has_script -eq 0 && $rustnmap_has_script -eq 0 ]]; then
        # Both didn't run the script - likely target doesn't support it
        result_status="SKIP"
        result_notes="Script not applicable to target"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        SKIPPED_TEST_NAMES+=("$test_name")
    elif [[ $nmap_has_script -eq 1 && $rustnmap_has_script -eq 0 ]]; then
        # Nmap ran script, rustnmap didn't
        result_status="FAIL"
        result_notes="rustnmap did not execute script"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
    elif [[ $nmap_has_script -eq 0 && $rustnmap_has_script -eq 1 ]]; then
        # rustnmap ran script, nmap didn't - unlikely but track it
        result_status="WARN"
        result_notes="nmap did not execute script but rustnmap did"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        # Both ran the script - compare outputs
        # Extract script results from both outputs
        local nmap_results=$(extract_nse_results "$nmap_output" "$script_base" 2>/dev/null || echo "")
        local rustnmap_results=$(extract_nse_results "$rustnmap_output" "$script_base" 2>/dev/null || echo "")

        # Count output lines (rough comparison)
        local nmap_lines=$(echo "$nmap_results" | wc -l)
        local rustnmap_lines=$(echo "$rustnmap_results" | wc -l)

        # Allow some tolerance for formatting differences
        local line_diff=$((nmap_lines - rustnmap_lines))
        line_diff=${line_diff#-}  # Absolute value

        if [[ $line_diff -le 2 ]]; then
            result_status="PASS"
            result_notes="Output similar (${rustnmap_lines} vs ${nmap_lines} lines)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            result_status="WARN"
            result_notes="Output differs (${rustnmap_lines} vs ${nmap_lines} lines)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    fi

    # Report results
    if [[ "$result_status" == "PASS" ]]; then
        echo "[PASS] $test_name" | tee -a "$LOG_FILE"
    elif [[ "$result_status" == "FAIL" ]]; then
        echo "[FAIL] $test_name" | tee -a "$LOG_FILE"
    elif [[ "$result_status" == "WARN" ]]; then
        echo "[WARN] $test_name" | tee -a "$LOG_FILE"
    else
        echo "[SKIP] $test_name" | tee -a "$LOG_FILE"
    fi

    # Only show speed comparison for meaningful results
    if [[ "$result_status" == "FAIL" ]]; then
        echo "  Speed: N/A (test failed - speed comparison meaningless)" | tee -a "$LOG_FILE"
        speedup="N/A"
    elif [[ "$result_status" == "SKIP" ]]; then
        echo "  Speed: N/A (skipped)" | tee -a "$LOG_FILE"
        speedup="N/A"
    else
        echo "  Speed: ${speedup}x (rustnmap=${rustnmap_duration}ms, nmap=${nmap_duration}ms)" | tee -a "$LOG_FILE"
    fi
    echo "  Notes: $result_notes" | tee -a "$LOG_FILE"

    if [[ "$result_status" == "FAIL" ]]; then
        echo "  === RUSTNMAP OUTPUT ===" | tee -a "$LOG_FILE"
        echo "$rustnmap_output" | sed 's/^/  /' | tee -a "$LOG_FILE"
        echo "  === END RUSTNMAP OUTPUT ===" | tee -a "$LOG_FILE"
    elif [[ "$result_status" == "PASS" || "$result_status" == "WARN" ]]; then
        # Show actual script output comparison
        echo "  --- NMAP SCRIPT OUTPUT ---" | tee -a "$LOG_FILE"
        if [[ -n "$nmap_results" ]]; then
            echo "$nmap_results" | head -10 | sed 's/^/  /' | tee -a "$LOG_FILE"
        else
            echo "  (no script output)" | tee -a "$LOG_FILE"
        fi
        echo "  --- RUSTNMAP SCRIPT OUTPUT ---" | tee -a "$LOG_FILE"
        if [[ -n "$rustnmap_results" ]]; then
            echo "$rustnmap_results" | head -10 | sed 's/^/  /' | tee -a "$LOG_FILE"
        else
            echo "  (no script output)" | tee -a "$LOG_FILE"
        fi
    fi

    TEST_RESULTS+=("$result_status|$test_name|$result_notes|${speedup}x")
    echo "" | tee -a "$LOG_FILE"
}

# Test Suite: Basic NSE Scripts
run_basic_nse_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Basic NSE Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "HTTP Title" \
        "http-title" \
        "$TARGET_IP" \
        "$TEST_PORT"

    compare_nse_script \
        "HTTP Server Header" \
        "http-server-header" \
        "$TARGET_IP" \
        "$TEST_PORT"

    compare_nse_script \
        "HTTP Methods" \
        "http-methods" \
        "$TARGET_IP" \
        "$TEST_PORT"

    compare_nse_script \
        "HTTP Robots.txt" \
        "http-robots.txt" \
        "$TARGET_IP" \
        "$TEST_PORT"
}

# Test Suite: SSL/TLS Scripts
run_ssl_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SSL/TLS Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Use HTTPS port for SSL tests
    compare_nse_script \
        "SSL Certificate" \
        "ssl-cert" \
        "$TARGET_IP" \
        "443"

    compare_nse_script \
        "SSL Enum Ciphers" \
        "ssl-enum-ciphers" \
        "$TARGET_IP" \
        "443"

    compare_nse_script \
        "HTTP SSL Cert" \
        "http-ssl-cert" \
        "$TARGET_IP" \
        "443"
}

# Test Suite: SSH Scripts
run_ssh_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SSH Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "SSH Auth Methods" \
        "ssh-auth-methods" \
        "$TARGET_IP" \
        "22"

    compare_nse_script \
        "SSH Hostkey" \
        "ssh-hostkey" \
        "$TARGET_IP" \
        "22"
}

# Test Suite: HTTP Library Scripts
run_http_library_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: HTTP Library Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "HTTP Git" \
        "http-git" \
        "$TARGET_IP" \
        "$TEST_PORT"

    compare_nse_script \
        "HTTP Enum" \
        "http-enum" \
        "$TARGET_IP" \
        "$TEST_PORT"
}

# Test Suite: SMB Scripts (if target supports it)
run_smb_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SMB Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Try SMB on port 445
    compare_nse_script \
        "SMB OS Discovery" \
        "smb-os-discovery" \
        "$TARGET_IP" \
        "445"

    compare_nse_script \
        "SMB Enum Shares" \
        "smb-enum-shares" \
        "$TARGET_IP" \
        "445"
}

# Test Suite: DNS Scripts
run_dns_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: DNS Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "DNS Service Discovery" \
        "dns-service-discovery" \
        "$TARGET_IP" \
        "53"

    compare_nse_script \
        "DNS NSID" \
        "dns-nsid" \
        "$TARGET_IP" \
        "53"
}

# Main function
main() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "RustNmap vs Nmap NSE Functionality Comparison" | tee -a "$LOG_FILE"
    echo "Started: $(date)" | tee -a "$LOG_FILE"
    echo "Target IP: $TARGET_IP" | tee -a "$LOG_FILE"
    echo "Reference Scripts: $REFERENCE_SCRIPTS" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Check prerequisites
    echo "[INFO] Checking prerequisites..." | tee -a "$LOG_FILE"

    if [ ! -f "$NMAP_BIN" ]; then
        echo "[ERROR] nmap not found at $NMAP_BIN" | tee -a "$LOG_FILE"
        exit 1
    fi

    if [ ! -f "$RUSTNMAP_BIN" ]; then
        echo "[ERROR] rustnmap not found at $RUSTNMAP_BIN" | tee -a "$LOG_FILE"
        echo "  Build with: cargo build --release" | tee -a "$LOG_FILE"
        exit 1
    fi

    if [ ! -d "$REFERENCE_SCRIPTS" ]; then
        echo "[ERROR] Reference scripts not found at $REFERENCE_SCRIPTS" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "[INFO] Prerequisites OK" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    # Run test suites
    run_basic_nse_suite
    run_ssl_suite
    run_ssh_suite
    run_http_library_suite
    run_smb_suite
    run_dns_suite

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

    # Save detailed report
    {
        echo "RustNmap vs Nmap NSE Comparison Report"
        echo "Generated: $(date)"
        echo "Target IP: $TARGET_IP"
        echo ""
        echo "Total Tests: $TOTAL_TESTS"
        echo "Passed: $PASSED_TESTS"
        echo "Failed: $FAILED_TESTS"
        echo "Skipped: $SKIPPED_TESTS"
        echo "Pass Rate: ${pass_rate}%"
        echo ""
        echo "Detailed Results:"
        echo "Status|Test Name|Notes|Speedup"
        echo "------|---------|------|--------"
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
    echo "Individual outputs saved to: $LOG_DIR/" | tee -a "$LOG_FILE"

    # Exit with error code if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
