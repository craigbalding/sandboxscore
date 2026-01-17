#!/bin/bash
# SandboxScore - Coding Agents Module
# https://github.com/craigbalding/sandboxscore
#
# Usage: ./run.sh [options]
#   -p, --profile    Profile: personal (default), professional, sensitive
#   -f, --format     Output: human (default), json, raw
#   -h, --help       Show this help

# =============================================================================
# SECURITY HARDENING - must be first
# =============================================================================

# Strict mode
set -uo pipefail

# Sanitize environment to prevent injection via PATH, IFS, etc.
unset IFS
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"
export LC_ALL=C

# Ensure we're running in bash (not being source'd into another shell)
if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "ERROR: This script requires bash" >&2
    exit 1
fi

# =============================================================================
# Resolve script location (works even when piped via curl)
# =============================================================================
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    # Running from curl pipe - try to find ourselves
    # First check if we're in a git repo with agents/
    if [[ -d "./agents/lib" ]]; then
        SCRIPT_DIR="$(pwd)/agents"
    elif [[ -d "../agents/lib" ]]; then
        SCRIPT_DIR="$(cd .. && pwd)/agents"
    else
        echo "ERROR: Cannot determine script location. Run from repo root or clone first." >&2
        exit 1
    fi
fi

# =============================================================================
# Parse arguments
# =============================================================================
FORMAT="human"
PROFILE="${SANDBOXSCORE_PROFILE:-personal}"
NETWORK_TESTS_ENABLED="${SANDBOXSCORE_NETWORK_TESTS:-0}"
NETWORK_TARGET="${SANDBOXSCORE_NETWORK_TARGET:-}"
REDACT_ENABLED="${SANDBOXSCORE_REDACT:-1}"
OUTPUT_FILE=""
FAIL_ON=""
CATEGORIES="${SANDBOXSCORE_CATEGORIES:-}"
NO_WRITE_TESTS="${SANDBOXSCORE_NO_WRITE_TESTS:-0}"
TEST_TIMEOUT="${SANDBOXSCORE_TIMEOUT:-10}"

show_help() {
    cat <<EOF
SandboxScore: Coding Agents v1.1.0

Measures what an AI coding agent can actually access on your system.
Outputs statistics only - never extracts or displays actual data.

Usage: $0 [options]

Options:
  -p, --profile PROFILE   Set scan profile (default: personal)
                          personal     - Your own machine, own data
                          professional - Work machine, client data possible
                          sensitive    - Handles PII, financial, health data

  -f, --format FORMAT     Output format (default: human)
                          human - Readable report with grades
                          json  - Machine-readable JSON
                          raw   - Simple key:status lines

  -h, --help              Show this help message

Network options (outbound tests are disabled by default):
  --enable-network-tests  Enable outbound network connectivity tests
  --offline               Explicitly disable network tests (default)
  --network-target URL    Use custom endpoint instead of httpbin.org

Output options:
  --no-redact             Disable value redaction (shows IPs, paths, etc.)
                          Default: redaction ON (shows [IP], [PATH], etc.)
  --output-file PATH      Write output to file instead of stdout

CI/CD options:
  --fail-on POLICY        Exit with code 1 if policy fails. Policies:
                          grade<=GRADE  (e.g., grade<=C)
                          score>=N      (e.g., score>=50)
                          exposures>=N  (e.g., exposures>=10)
  --categories LIST       Only run specified categories (comma-separated)
                          Options: credentials,personal_data,system_visibility,
                                   persistence,network,intelligence
  --no-write-tests        Skip tests that write to filesystem
  --timeout SECONDS       Timeout per test (default: 10)

Environment:
  SANDBOXSCORE_PROFILE       Default profile (overridden by --profile)
  SANDBOXSCORE_NETWORK_TESTS Set to 1 to enable network tests by default

Examples:
  ./run.sh                           # Quick scan with defaults
  ./run.sh -p professional           # Professional profile
  ./run.sh -f json                   # JSON output
  ./run.sh -p sensitive -f json      # Sensitive profile, JSON output

Learn more: https://github.com/craigbalding/sandboxscore
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --enable-network-tests)
            NETWORK_TESTS_ENABLED=1
            shift
            ;;
        --offline)
            NETWORK_TESTS_ENABLED=0
            shift
            ;;
        --network-target)
            NETWORK_TARGET="$2"
            shift 2
            ;;
        --no-redact)
            REDACT_ENABLED=0
            shift
            ;;
        --output-file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --fail-on)
            FAIL_ON="$2"
            shift 2
            ;;
        --categories)
            CATEGORIES="$2"
            shift 2
            ;;
        --no-write-tests)
            NO_WRITE_TESTS=1
            shift
            ;;
        --timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# Export configuration for common.sh and modules
export SANDBOXSCORE_PROFILE="$PROFILE"
export SANDBOXSCORE_NETWORK_TESTS="$NETWORK_TESTS_ENABLED"
export SANDBOXSCORE_NETWORK_TARGET="$NETWORK_TARGET"
export SANDBOXSCORE_REDACT="$REDACT_ENABLED"
export SANDBOXSCORE_CATEGORIES="$CATEGORIES"
export SANDBOXSCORE_NO_WRITE_TESTS="$NO_WRITE_TESTS"
export SANDBOXSCORE_TIMEOUT="$TEST_TIMEOUT"

# =============================================================================
# Load library and platform modules
# =============================================================================
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/shared.sh"
source "$SCRIPT_DIR/lib/intel_common.sh"
source "$SCRIPT_DIR/lib/remediation.sh"

# Detect and load platform-specific tests
if ! init_scanner; then
    exit 1
fi

# Show progress header
progress_header

case "$PLATFORM" in
    darwin)
        source "$SCRIPT_DIR/platform/darwin/credentials.sh"
        source "$SCRIPT_DIR/platform/darwin/personal_data.sh"
        source "$SCRIPT_DIR/platform/darwin/system_visibility.sh"
        source "$SCRIPT_DIR/platform/darwin/persistence.sh"
        # Additional darwin test modules
        source "$SCRIPT_DIR/platform/darwin/security_state.sh"
        source "$SCRIPT_DIR/platform/darwin/ipc_mechanisms.sh"
        source "$SCRIPT_DIR/platform/darwin/vm_sandbox.sh"
        source "$SCRIPT_DIR/platform/darwin/macos_deep.sh"
        source "$SCRIPT_DIR/platform/darwin/apple_services.sh"
        source "$SCRIPT_DIR/platform/darwin/hardware_devices.sh"
        source "$SCRIPT_DIR/platform/darwin/clipboard_screen.sh"
        source "$SCRIPT_DIR/platform/darwin/privilege_access.sh"
        source "$SCRIPT_DIR/platform/darwin/process_memory.sh"
        # Intelligence module
        source "$SCRIPT_DIR/platform/darwin/intelligence.sh"
        ;;
    linux)
        source "$SCRIPT_DIR/platform/linux/credentials.sh"
        source "$SCRIPT_DIR/platform/linux/personal_data.sh"
        source "$SCRIPT_DIR/platform/linux/system_visibility.sh"
        source "$SCRIPT_DIR/platform/linux/persistence.sh"
        ;;
    *)
        echo "ERROR: Unsupported platform: $PLATFORM" >&2
        exit 1
        ;;
esac

# =============================================================================
# Category filtering helper
# =============================================================================
should_run_category() {
    local cat="$1"
    # If no categories specified, run all
    [[ -z "$CATEGORIES" ]] && return 0
    # Check if category is in comma-separated list
    [[ ",$CATEGORIES," == *",$cat,"* ]] && return 0
    return 1
}

# =============================================================================
# Run all tests
# =============================================================================

# Core categories
should_run_category "credentials" && run_credentials_tests
should_run_category "personal_data" && run_personal_data_tests
should_run_category "system_visibility" && run_system_visibility_tests
should_run_category "persistence" && run_persistence_tests

# Network tests are opt-in (outbound connections disabled by default)
if should_run_category "network"; then
    if [[ "$NETWORK_TESTS_ENABLED" == "1" ]]; then
        run_network_tests
    else
        # Emit skipped status for transparency
        progress_start "network"
        emit "network" "outbound_http" "skipped" "network_tests_disabled" "info"
        emit "network" "dns_resolution" "skipped" "network_tests_disabled" "info"
        emit "network" "cloud_metadata" "skipped" "network_tests_disabled" "info"
        emit "network" "local_services" "skipped" "network_tests_disabled" "info"
        progress_end "network"
    fi
fi

# Platform-specific additional tests
case "$PLATFORM" in
    darwin)
        run_security_state_tests
        run_ipc_tests
        run_vm_sandbox_tests
        run_macos_deep_tests
        run_apple_services_tests
        run_hardware_tests
        run_clipboard_screen_tests
        run_privilege_access_tests
        run_process_memory_tests
        # Intelligence module
        should_run_category "intelligence" && run_intelligence_tests
        ;;
esac

# =============================================================================
# Output results
# =============================================================================

# Show progress footer (summary line to stderr)
progress_footer

# Output full results to stdout or file
if [[ -n "$OUTPUT_FILE" ]]; then
    output_results "$FORMAT" > "$OUTPUT_FILE"
    echo "Output written to: $OUTPUT_FILE" >&2
else
    output_results "$FORMAT"
fi

# =============================================================================
# Check fail-on policy
# =============================================================================
if [[ -n "$FAIL_ON" ]]; then
    # Parse and check policy
    check_fail_policy "$FAIL_ON"
    policy_result=$?
    if [[ $policy_result -ne 0 ]]; then
        echo "Policy check failed: $FAIL_ON" >&2
        exit 1
    fi
fi
