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

show_help() {
    cat <<EOF
SandboxScore: Coding Agents v1.0.0

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

Environment:
  SANDBOXSCORE_PROFILE    Default profile (overridden by --profile)

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
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# Export profile for common.sh
export SANDBOXSCORE_PROFILE="$PROFILE"

# =============================================================================
# Load library and platform modules
# =============================================================================
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/shared.sh"
source "$SCRIPT_DIR/lib/intel_common.sh"

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
# Run all tests
# =============================================================================
run_credentials_tests
run_personal_data_tests
run_system_visibility_tests
run_persistence_tests
run_network_tests

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
        run_intelligence_tests
        ;;
esac

# =============================================================================
# Output results
# =============================================================================

# Show progress footer (summary line to stderr)
progress_footer

# Output full results to stdout
output_results "$FORMAT"
