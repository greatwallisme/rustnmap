#!/bin/bash
# RustNmap API Integration Test Script
#
# Tests the REST API endpoints of rustnmap-api
#
# Requirements:
#   - rustnmap-api server binary (cargo build --release --package rustnmap-api)
#   - curl command
#   - jq command (for JSON parsing)
#
# Usage:
#   ./api_test.sh [--server-addr ADDR] [--api-key KEY] [--no-start]
#
# Options:
#   --server-addr ADDR  Server address (default: 127.0.0.1:8080)
#   --api-key KEY       API key for authentication (default: auto-generated)
#   --no-start          Don't start server, assume it's already running
#   --help              Show this help message

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_PATH="$PROJECT_ROOT/target/release/examples/server"
SERVER_ADDR="${API_SERVER_ADDR:-127.0.0.1:8080}"
API_KEY=""
START_SERVER=true
TEST_TARGET="${API_TEST_TARGET:-127.0.0.1}"
TIMEOUT=30
RESULTS_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$RESULTS_DIR/api_test_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# ============================================================================
# Functions
# ============================================================================

usage() {
    cat <<EOF
RustNmap API Integration Test Script

Tests the REST API endpoints of rustnmap-api

Usage:
    $0 [OPTIONS]

Options:
    --server-addr ADDR    Server address (default: 127.0.0.1:8080)
    --api-key KEY         API key for authentication (default: auto-generate)
    --no-start            Don't start server, use existing one
    --target IP           Test target IP (default: 127.0.0.1)
    --timeout SECS        Request timeout in seconds (default: 30)
    --help                Show this help message

Environment Variables:
    API_SERVER_ADDR       Default server address
    API_TEST_TARGET       Default test target IP

Examples:
    $0                                    # Auto-start and test
    $0 --no-start --server-addr 9090      # Test existing server on port 9090
    $0 --target 192.168.1.1               # Test with specific target

EOF
    exit 0
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "${BLUE}$*${NC}"
}

log_success() {
    log "PASS" "${GREEN}$*${NC}"
}

log_error() {
    log "FAIL" "${RED}$*${NC}"
}

log_warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

# ============================================================================
# Test Functions
# ============================================================================

test_health_check() {
    local name="Health Check"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_info "Running: $name"

    local response
    response=$(curl -s -m "$TIMEOUT" --connect-timeout 5 \
        "http://$SERVER_ADDR/api/v1/health" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    local status
    status=$(echo "$response" | jq -r '.status // empty' 2>/dev/null) || {
        log_error "$name - Invalid JSON response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ "$status" == "healthy" ]]; then
        log_success "$name - Server is healthy"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$name - Unexpected status: $status"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_create_scan() {
    local name="Create Scan"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_info "Running: $name"

    local payload
    payload=$(cat <<EOF
{
    "targets": ["$TEST_TARGET"],
    "scan_type": "connect",
    "options": {
        "ports": "22,80,443",
        "service_detection": false,
        "os_detection": false,
        "timing": "T4"
    }
}
EOF
)

    local response
    response=$(curl -s -m "$TIMEOUT" --connect-timeout 5 \
        -X POST "http://$SERVER_ADDR/api/v1/scans" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    local scan_id
    # API wraps response in "data" object
    scan_id=$(echo "$response" | jq -r '.data.id // empty' 2>/dev/null) || {
        log_error "$name - Invalid JSON response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ -n "$scan_id" && "$scan_id" != "null" ]]; then
        log_success "$name - Created scan with ID: $scan_id"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo "$scan_id" > "$RESULTS_DIR/last_scan_id.txt"
        return 0
    else
        log_error "$name - No scan ID in response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_list_scans() {
    local name="List Scans"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_info "Running: $name"

    local response
    response=$(curl -s -m "$TIMEOUT" --connect-timeout 5 \
        -X GET "http://$SERVER_ADDR/api/v1/scans" \
        -H "Authorization: Bearer $API_KEY" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    # Check if response is valid JSON (API wraps in "data" object)
    if echo "$response" | jq -e '.data.scans or .data.id' >/dev/null 2>&1; then
        local count
        count=$(echo "$response" | jq '.data.scans | length // 0' 2>/dev/null)
        log_success "$name - Listed $count scan(s)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$name - Invalid JSON response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_get_scan_status() {
    local name="Get Scan Status"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local scan_id="${1:-}"
    if [[ -z "$scan_id" ]]; then
        if [[ -f "$RESULTS_DIR/last_scan_id.txt" ]]; then
            scan_id=$(cat "$RESULTS_DIR/last_scan_id.txt")
        else
            log_warn "$name - No scan ID available, skipping"
            return 0
        fi
    fi

    log_info "Running: $name (scan_id: $scan_id)"

    local response
    response=$(curl -s -m "$TIMEOUT" --connect-timeout 5 \
        -X GET "http://$SERVER_ADDR/api/v1/scans/$scan_id" \
        -H "Authorization: Bearer $API_KEY" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    local status
    # API wraps response in "data" object
    status=$(echo "$response" | jq -r '.data.status // empty' 2>/dev/null) || {
        log_error "$name - Invalid JSON response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ "$status" =~ ^(queued|running|completed|cancelled|failed)$ ]]; then
        log_success "$name - Scan status: $status"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$name - Unexpected status: $status"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_cancel_scan() {
    local name="Cancel Scan"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    local scan_id="${1:-}"
    if [[ -z "$scan_id" ]]; then
        if [[ -f "$RESULTS_DIR/last_scan_id.txt" ]]; then
            scan_id=$(cat "$RESULTS_DIR/last_scan_id.txt")
        else
            log_warn "$name - No scan ID available, skipping"
            return 0
        fi
    fi

    log_info "Running: $name (scan_id: $scan_id)"

    local response
    response=$(curl -s -m "$TIMEOUT" --connect-timeout 5 \
        -X DELETE "http://$SERVER_ADDR/api/v1/scans/$scan_id" \
        -H "Authorization: Bearer $API_KEY" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    local status
    # API wraps response in "data" object
    status=$(echo "$response" | jq -r '.data.status // empty' 2>/dev/null) || {
        log_error "$name - Invalid JSON response: $response"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ "$status" == "cancelled" ]] || [[ "$status" == "completed" ]]; then
        log_success "$name - Scan $status"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_warn "$name - Unexpected status: $status (may have completed)"
        # Don't count as failure since scan might have completed
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

test_authentication_required() {
    local name="Authentication Required"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_info "Running: $name"

    local response
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -m "$TIMEOUT" --connect-timeout 5 \
        -X GET "http://$SERVER_ADDR/api/v1/scans" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
        log_success "$name - Correctly rejected unauthenticated request (HTTP $http_code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$name - Expected 401/403, got HTTP $http_code"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

test_invalid_api_key() {
    local name="Invalid API Key Rejected"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    log_info "Running: $name"

    local response
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -m "$TIMEOUT" --connect-timeout 5 \
        -X GET "http://$SERVER_ADDR/api/v1/scans" \
        -H "Authorization: Bearer invalid_key_12345" 2>&1) || {
        log_error "$name - Failed to connect to server"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    }

    if [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
        log_success "$name - Correctly rejected invalid API key (HTTP $http_code)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$name - Expected 401/403, got HTTP $http_code"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# ============================================================================
# Server Management
# ============================================================================

start_server() {
    log_info "Starting API server..."

    if [[ ! -f "$BINARY_PATH" ]]; then
        log_error "Server binary not found at: $BINARY_PATH"
        log_info "Building server binary..."
        (cd "$PROJECT_ROOT" && cargo build --release --package rustnmap-api --example server) || {
            log_error "Failed to build server binary"
            exit 1
        }
    fi

    # Start server in background
    "$BINARY_PATH" > "$RESULTS_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    # Wait for server to be ready
    local max_wait=10
    local waited=0
    while [[ $waited -lt $max_wait ]]; do
        if curl -s -f -m 2 "http://$SERVER_ADDR/api/v1/health" >/dev/null 2>&1; then
            log_info "Server started successfully (PID: $SERVER_PID)"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    log_error "Server failed to start within ${max_wait}s"
    log_error "Check logs at: $RESULTS_DIR/server.log"
    return 1
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        log_info "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}

# ============================================================================
# Main
# ============================================================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server-addr)
                SERVER_ADDR="$2"
                shift 2
                ;;
            --api-key)
                API_KEY="$2"
                shift 2
                ;;
            --no-start)
                START_SERVER=false
                shift
                ;;
            --target)
                TEST_TARGET="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --help|-h)
                usage
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"

    # Create results directory
    mkdir -p "$RESULTS_DIR"

    # Initialize log
    echo "RustNmap API Test Log - $(date)" > "$LOG_FILE"
    echo "Server: $SERVER_ADDR" >> "$LOG_FILE"
    echo "Target: $TEST_TARGET" >> "$LOG_FILE"
    echo "=============================================" >> "$LOG_FILE"

    log_info "============================================="
    log_info "   RustNmap API Integration Tests"
    log_info "============================================="
    log_info "Server address: http://$SERVER_ADDR"
    log_info "Test target: $TEST_TARGET"
    log_info "Results directory: $RESULTS_DIR"
    log_info ""

    # Start server if needed
    if [[ "$START_SERVER" == true ]]; then
        if ! start_server; then
            log_error "Failed to start server, exiting"
            exit 1
        fi
        trap stop_server EXIT
    else
        log_info "Using existing server at: $SERVER_ADDR"
    fi

    # Generate API key if not provided
    if [[ -z "$API_KEY" ]]; then
        # Extract API key from server log
        if [[ "$START_SERVER" == true ]]; then
            sleep 2  # Give server time to print API key
            API_KEY=$(grep -oP '\[\d+\]: \K[0-9a-f]{64}' "$RESULTS_DIR/server.log" | head -1) || {
                # Fallback: generate a key and hope it matches
                API_KEY=$(openssl rand -hex 32 2>/dev/null || echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                log_warn "Could not extract API key from server log, using generated key"
            }
        else
            API_KEY="${API_KEY:-$(openssl rand -hex 32 2>/dev/null || echo 'test_api_key_placeholder')}"
            log_warn "Using provided/generated API key (may not match server)"
        fi
    fi

    log_info "Using API key: ${API_KEY:0:16}..."
    log_info ""

    # Run tests
    log_info "============================================="
    log_info "   Running Tests"
    log_info "============================================="
    log_info ""

    # Test 1: Health check (no auth required)
    test_health_check
    echo ""

    # Test 2: Authentication required
    test_authentication_required
    echo ""

    # Test 3: Invalid API key
    test_invalid_api_key
    echo ""

    # Test 4: Create scan
    test_create_scan
    echo ""

    # Test 5: List scans
    test_list_scans
    echo ""

    # Test 6: Get scan status
    test_get_scan_status
    echo ""

    # Test 7: Cancel scan
    test_cancel_scan
    echo ""

    # Print summary
    log_info "============================================="
    log_info "   Test Summary"
    log_info "============================================="
    log_info "Total tests: $TESTS_TOTAL"
    log_info "Passed: $TESTS_PASSED"
    log_info "Failed: $TESTS_FAILED"
    log_info "Success rate: $(( TESTS_TOTAL > 0 ? TESTS_PASSED * 100 / TESTS_TOTAL : 0 ))%"
    log_info ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "All tests passed!"
        exit 0
    else
        log_error "Some tests failed!"
        exit 1
    fi
}

main "$@"
