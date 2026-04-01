#!/bin/bash
# RustNmap vs Nmap NSE Functionality Comparison Test Script
# Tests NSE script execution, accuracy, and performance

set +e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration - Docker test range defaults
TARGET_IP="${TARGET_IP:-172.28.0.2}"
ALT_TARGET="${ALT_TARGET:-127.0.0.1}"
TEST_PORT="${TEST_PORT:-80}"
NMAP_BIN="${NMAP_BIN:-/usr/bin/nmap}"
RUSTNMAP_BIN="${RUSTNMAP_BIN:-${PROJECT_ROOT}/target/release/rustnmap}"
REFERENCE_SCRIPTS="${REFERENCE_SCRIPTS:-${PROJECT_ROOT}/reference/nmap/scripts}"

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
    local nmap_time_output
    nmap_output=$(/usr/bin/time -v $NMAP_BIN -sV $base_port_arg --script="$script" $extra_args "$target" 2>/tmp/nmap_time_$$) || nmap_exit=$?
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

    # Delay between scans (2 seconds for reliability)
    sleep 2

    # Run rustnmap
    echo "[INFO] Running rustnmap..." | tee -a "$LOG_FILE"
    local rustnmap_start=$(date +%s%3N)
    local rustnmap_output
    local rustnmap_exit=0
    local rustnmap_time_output
    rustnmap_output=$(/usr/bin/time -v $RUSTNMAP_BIN -sV $base_port_arg --script="$script" $extra_args "$target" 2>/tmp/rustnmap_time_$$) || rustnmap_exit=$?
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
        echo "  Resources (nmap):     peak_mem=${nmap_maxrss}, cpu=${nmap_cpu_pct}%, user=${nmap_user_cpu}s, sys=${nmap_sys_cpu}s" | tee -a "$LOG_FILE"
        echo "  Resources (rustnmap): peak_mem=${rustnmap_maxrss}, cpu=${rustnmap_cpu_pct}%, user=${rustnmap_user_cpu}s, sys=${rustnmap_sys_cpu}s" | tee -a "$LOG_FILE"
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

    TEST_RESULTS+=("$result_status|$test_name|$result_notes|${speedup}x|nmap_mem=${nmap_maxrss} rustnmap_mem=${rustnmap_maxrss}")
    echo "" | tee -a "$LOG_FILE"
}

# Test Suite: Basic NSE Scripts
run_basic_nse_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Basic NSE Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local HTTP_TARGET="${HTTP_TARGET:-$IP_WEB}"

    compare_nse_script \
        "HTTP Title" \
        "http-title" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Server Header" \
        "http-server-header" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Methods" \
        "http-methods" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Robots.txt" \
        "http-robots.txt" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Default Accounts" \
        "http-default-accounts" \
        "$HTTP_TARGET" \
        "80"
}

# Test Suite: SSL/TLS Scripts
run_ssl_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SSL/TLS Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local SSL_TARGET="${SSL_TARGET:-$IP_WEB}"

    compare_nse_script \
        "SSL Certificate" \
        "ssl-cert" \
        "$SSL_TARGET" \
        "443"

    compare_nse_script \
        "SSL Date" \
        "ssl-date" \
        "$SSL_TARGET" \
        "443"

    compare_nse_script \
        "SSL Enum Ciphers" \
        "ssl-enum-ciphers" \
        "$SSL_TARGET" \
        "443"

    compare_nse_script \
        "TLS ALPN" \
        "tls-alpn" \
        "$SSL_TARGET" \
        "443"
}

# Test Suite: SSH Scripts
run_ssh_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SSH Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local SSH_TARGET="${SSH_TARGET:-$IP_SSH}"

    compare_nse_script \
        "SSH Auth Methods" \
        "ssh-auth-methods" \
        "$SSH_TARGET" \
        "22"

    compare_nse_script \
        "SSH Hostkey" \
        "ssh-hostkey" \
        "$SSH_TARGET" \
        "22"

    compare_nse_script \
        "Banner (SSH)" \
        "banner" \
        "$SSH_TARGET" \
        "22"
}

# Test Suite: DNS Scripts (requires -sU for UDP)
run_dns_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: DNS Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local DNS_TARGET="${DNS_TARGET:-$IP_DNS}"

    # DNS scripts need UDP scan
    compare_nse_script \
        "DNS Recursion" \
        "dns-recursion" \
        "$DNS_TARGET" \
        "53" \
        "-sU"
}

# Test Suite: Host Info Scripts
run_host_info_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Host Info Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "FCrDNS" \
        "fcrdns" \
        "$IP_SCAN_TARGET" \
        ""
}

# Test Suite: SMB Scripts (Docker smb target)
run_smb_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SMB Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "SMB OS Discovery" \
        "smb-os-discovery" \
        "$IP_SMB" \
        "445"

    compare_nse_script \
        "SMB Enum Shares" \
        "smb-enum-shares" \
        "$IP_SMB" \
        "445"

    compare_nse_script \
        "SMB Protocols" \
        "smb-protocols" \
        "$IP_SMB" \
        "445"

    compare_nse_script \
        "SMB Security Mode" \
        "smb-security-mode" \
        "$IP_SMB" \
        "445"
}

# Test Suite: FTP Scripts (Docker ftp target)
run_ftp_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: FTP Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "FTP Anon" \
        "ftp-anon" \
        "$IP_FTP" \
        "21"

    compare_nse_script \
        "FTP Syst" \
        "ftp-syst" \
        "$IP_FTP" \
        "21"

    compare_nse_script \
        "Banner (FTP)" \
        "banner" \
        "$IP_FTP" \
        "21"
}

# Test Suite: SMTP Scripts (Docker smtp target)
run_smtp_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SMTP Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "SMTP Commands" \
        "smtp-commands" \
        "$IP_SMTP" \
        "25"

    compare_nse_script \
        "Banner (SMTP)" \
        "banner" \
        "$IP_SMTP" \
        "25"
}

# Test Suite: MySQL Scripts (Docker mysql target)
run_mysql_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: MySQL Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "MySQL Info" \
        "mysql-info" \
        "$IP_MYSQL" \
        "3306"

    compare_nse_script \
        "MySQL Empty Password" \
        "mysql-empty-password" \
        "$IP_MYSQL" \
        "3306"
}

# Test Suite: Redis Scripts (Docker redis target)
run_redis_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Redis Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "Redis Info" \
        "redis-info" \
        "$IP_REDIS" \
        "6379"
}

# Test Suite: VNC Scripts (Docker vnc target)
run_vnc_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: VNC Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "VNC Info" \
        "vnc-info" \
        "$IP_VNC" \
        "5900"

    compare_nse_script \
        "VNC Title" \
        "vnc-title" \
        "$IP_VNC" \
        "5900"
}

# Test Suite: Mail Scripts (Docker mail target - POP3/IMAP)
run_mail_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Mail Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "Banner (POP3)" \
        "banner" \
        "$IP_MAIL" \
        "110"

    compare_nse_script \
        "Banner (IMAP)" \
        "banner" \
        "$IP_MAIL" \
        "143"

    compare_nse_script \
        "POP3 Capabilities" \
        "pop3-capabilities" \
        "$IP_MAIL" \
        "110"

    compare_nse_script \
        "IMAP Capabilities" \
        "imap-capabilities" \
        "$IP_MAIL" \
        "143"
}

# Test Suite: LDAP Scripts (Docker ldap target)
run_ldap_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: LDAP Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "LDAP RootDSE" \
        "ldap-rootdse" \
        "$IP_LDAP" \
        "389"

    compare_nse_script \
        "LDAP Search" \
        "ldap-search" \
        "$IP_LDAP" \
        "389"
}

# Test Suite: NTP Scripts (Docker ntp target)
run_ntp_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: NTP Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "NTP Info" \
        "ntp-info" \
        "$IP_NTP" \
        "123" \
        "-sU"
}

# Test Suite: SNMP Scripts (Docker snmp target)
run_snmp_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: SNMP Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "SNMP Info" \
        "snmp-info" \
        "$IP_SNMP" \
        "161" \
        "-sU"

    compare_nse_script \
        "SNMP SysDescr" \
        "snmp-sysdescr" \
        "$IP_SNMP" \
        "161" \
        "-sU"
}

# Test Suite: Telnet Scripts (Docker telnet target)
run_telnet_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: Telnet Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "Banner (Telnet)" \
        "banner" \
        "$IP_TELNET" \
        "23"
}

# Test Suite: RPC Scripts (Docker rpcbind target)
run_rpc_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: RPC Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    compare_nse_script \
        "RPC Info" \
        "rpcinfo" \
        "$IP_RPCBIND" \
        "111"
}

# Test Suite: HTTP Library Scripts (Docker web target with /git, /robots.txt etc)
run_http_lib_suite() {
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "Test Suite: HTTP Library Scripts" | tee -a "$LOG_FILE"
    echo "==========================================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"

    local HTTP_TARGET="${HTTP_TARGET:-$IP_WEB}"

    compare_nse_script \
        "HTTP Git" \
        "http-git" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Enum" \
        "http-enum" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Headers" \
        "http-headers" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Date" \
        "http-date" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP CORS" \
        "http-cors" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Cookie Flags" \
        "http-cookie-flags" \
        "$HTTP_TARGET" \
        "80"

    compare_nse_script \
        "HTTP Security Headers" \
        "http-security-headers" \
        "$HTTP_TARGET" \
        "80"
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

    # Run test suites - Docker test range targets
    run_basic_nse_suite       # HTTP scripts on web target
    run_ssl_suite             # SSL/TLS scripts on web target
    run_ssh_suite             # SSH scripts on ssh target
    run_dns_suite             # DNS scripts on dns target
    run_smb_suite             # SMB scripts on smb target
    run_ftp_suite             # FTP scripts on ftp target
    run_smtp_suite            # SMTP scripts on smtp target
    run_mysql_suite           # MySQL scripts on mysql target
    run_redis_suite           # Redis scripts on redis target
    run_vnc_suite             # VNC scripts on vnc target
    run_mail_suite            # POP3/IMAP scripts on mail target
    run_ldap_suite            # LDAP scripts on ldap target
    run_ntp_suite             # NTP scripts on ntp target
    run_snmp_suite            # SNMP scripts on snmp target
    run_telnet_suite          # Telnet scripts on telnet target
    run_rpc_suite             # RPC scripts on rpcbind target
    run_http_lib_suite        # HTTP library scripts on web target
    run_host_info_suite       # Host info scripts on scan target

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
    echo "Individual outputs saved to: $LOG_DIR/" | tee -a "$LOG_FILE"

    # Exit with error code if any tests failed
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
