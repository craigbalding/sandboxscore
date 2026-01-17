#!/bin/bash
# shellcheck disable=SC2034  # Variables used by sourced files
# SandboxScore - Agents Module - Common Library
# Version: 1.0.0
# Compatible with bash 3.2+ (macOS default)
#
# Provides core functionality for the exposure scanner:
# - Finding emission and accumulation
# - Profile and severity management
# - Grade calculation
# - Platform detection
# - Output formatting

# =============================================================================
# SECURITY HARDENING
# =============================================================================
# This library is sourced by run.sh which sets up the secure environment.
# We reinforce critical settings here in case this file is sourced directly.

set -uo pipefail

# Ensure sane defaults even if sourced directly
[[ -z "${IFS+x}" ]] || unset IFS
: "${LC_ALL:=C}"

# Verify we're in bash
if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "ERROR: This script requires bash" >&2
    # shellcheck disable=SC2317  # Intentional: return fails when executed (not sourced), then exit runs
    return 1 2>/dev/null || exit 1
fi

# Debug mode: set SANDBOXSCORE_DEBUG=1 to enable verbose logging
DEBUG="${SANDBOXSCORE_DEBUG:-0}"

# Progress output: enabled by default if stderr is a TTY
# Set SANDBOXSCORE_QUIET=1 to disable progress output
if [[ -t 2 && "${SANDBOXSCORE_QUIET:-0}" != "1" ]]; then
    PROGRESS_ENABLED=1
else
    PROGRESS_ENABLED=0
fi

# Elapsed time tracking (milliseconds)
START_TIME_MS=""

# Current category being scanned
CURRENT_CATEGORY=""
CURRENT_CATEGORY_COUNT=0
CURRENT_CATEGORY_EXPOSED=0

# Log to stderr (only in debug mode)
debug() {
    [[ "$DEBUG" == "1" ]] && echo "[DEBUG] $*" >&2
}

# Log errors to stderr
error() {
    echo "ERROR: $*" >&2
}

# Log warnings to stderr
warn() {
    echo "WARN: $*" >&2
}

# Die with error message
die() {
    error "$@"
    exit 1
}

# =============================================================================
# CONSTANTS
# =============================================================================

readonly SCANNER_VERSION="1.0.0"
readonly METHODOLOGY_VERSION="1.0"

# Field delimiter for findings storage
# Using ASCII Unit Separator (0x1F) - very unlikely to appear in values
readonly FIELD_SEP=$'\x1f'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Safely convert to integer, defaulting to 0 for empty/invalid
to_int() {
    local val="${1:-0}"
    # Strip leading/trailing whitespace and check if numeric
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    if [[ "$val" =~ ^-?[0-9]+$ ]]; then
        echo "$val"
    else
        echo "0"
    fi
}

# Escape string for JSON output
json_escape() {
    local str="$1"
    # Escape backslashes first, then quotes, then control characters
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

# Sanitize value for storage (remove field separator if present)
sanitize_value() {
    local val="$1"
    # Replace field separator with underscore
    echo "${val//$FIELD_SEP/_}"
}

# Check if a command exists
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Timeout command detection (cached)
TIMEOUT_CMD=""
detect_timeout_cmd() {
    if [[ -n "$TIMEOUT_CMD" ]]; then
        return 0
    fi
    if has_cmd timeout; then
        TIMEOUT_CMD="timeout"
    elif has_cmd gtimeout; then
        TIMEOUT_CMD="gtimeout"
    elif has_cmd perl; then
        TIMEOUT_CMD="perl"
    else
        TIMEOUT_CMD="none"
    fi
}

# Run a command with timeout
# Usage: with_timeout <seconds> <command> [args...]
# Returns: command exit code, or 124 on timeout (matching GNU timeout)
with_timeout() {
    local secs="$1"
    shift

    detect_timeout_cmd

    case "$TIMEOUT_CMD" in
        timeout|gtimeout)
            "$TIMEOUT_CMD" "$secs" "$@"
            ;;
        perl)
            # Perl fallback for macOS (no coreutils timeout)
            # Uses alarm() to kill after $secs seconds, returns 124 on timeout
            perl -e '
                $timeout = shift;
                $SIG{ALRM} = sub { exit 124 };
                alarm $timeout;
                system @ARGV;
                alarm 0;
                exit($? == -1 ? 127 : $? & 127 ? 128 + ($? & 127) : $? >> 8);
            ' "$secs" "$@"
            ;;
        *)
            # No timeout available - run directly (shouldn't happen, perl is everywhere)
            debug "with_timeout: no timeout method available, running without timeout"
            "$@"
            ;;
    esac
}

# Default timeout for external commands (seconds)
readonly DEFAULT_TIMEOUT=10
readonly SQLITE_TIMEOUT=5

# =============================================================================
# PROGRESS OUTPUT FUNCTIONS
# =============================================================================

# Get current time in milliseconds (portable)
time_ms() {
    perl -MTime::HiRes=time -e 'print int(time * 1000)'
}

# Get elapsed time in milliseconds
elapsed_time_ms() {
    if [[ -n "$START_TIME_MS" ]]; then
        local now
        now=$(time_ms)
        echo "$((now - START_TIME_MS))"
    else
        echo "0"
    fi
}

# Format elapsed time as M:SS.mmm
format_elapsed() {
    local ms="${1:-0}"
    local total_secs=$((ms / 1000))
    local mins=$((total_secs / 60))
    local secs=$((total_secs % 60))
    local millis=$((ms % 1000))
    printf "%d:%02d.%03d" "$mins" "$secs" "$millis"
}

# Handle SIGINT (Ctrl+C) gracefully
handle_interrupt() {
    echo "" >&2
    echo "Interrupted." >&2
    if [[ "$PROGRESS_ENABLED" == "1" && -n "$START_TIME_MS" ]]; then
        local elapsed
        elapsed=$(format_elapsed "$(elapsed_time_ms)")
        echo "Elapsed: ${elapsed}" >&2
    fi
    exit 130
}

# Print progress header (called once at start)
progress_header() {
    [[ "$PROGRESS_ENABLED" != "1" ]] && return
    START_TIME_MS=$(time_ms)
    # Set up interrupt handler
    trap handle_interrupt INT TERM
    echo "" >&2
    echo "sandboxscore ${SCANNER_VERSION} | read-only | profile: ${PROFILE}" >&2
    echo "" >&2
}

# Signal start of a category scan
# Usage: progress_start <category_name>
progress_start() {
    local category="$1"
    CURRENT_CATEGORY="$category"
    CURRENT_CATEGORY_COUNT=0
    CURRENT_CATEGORY_EXPOSED=0

    [[ "$PROGRESS_ENABLED" != "1" ]] && return
    echo "${category}" >&2
}

# Signal end of a category scan
# Usage: progress_end <category_name>
progress_end() {
    local category="$1"

    [[ "$PROGRESS_ENABLED" != "1" ]] && return

    local exposed_info=""
    if [[ "$CURRENT_CATEGORY_EXPOSED" -gt 0 ]]; then
        exposed_info=" (${CURRENT_CATEGORY_EXPOSED} exposed)"
    fi

    echo "${category} ${CURRENT_CATEGORY_COUNT}${exposed_info}" >&2
    echo "" >&2

    CURRENT_CATEGORY=""
    CURRENT_CATEGORY_COUNT=0
    CURRENT_CATEGORY_EXPOSED=0
}

# Stream a test result (called from emit)
progress_test() {
    local test_name="$1"
    local status="$2"
    local value="$3"

    [[ "$PROGRESS_ENABLED" != "1" ]] && return

    local elapsed
    elapsed=$(format_elapsed "$(elapsed_time_ms)")

    local detail=""
    if [[ "$status" == "exposed" && -n "$value" ]]; then
        detail=":${value}"
    fi

    # Show test with timestamp
    echo "  ${elapsed} ${test_name}${detail}" >&2
}

# Print final summary line
progress_footer() {
    [[ "$PROGRESS_ENABLED" != "1" ]] && return

    local elapsed
    elapsed=$(format_elapsed "$(elapsed_time_ms)")

    local summary
    summary=$(get_summary)
    local total exposed blocked
    total=$(echo "$summary" | cut -d'|' -f1)
    blocked=$(echo "$summary" | cut -d'|' -f2)
    exposed=$(echo "$summary" | cut -d'|' -f3)

    local grade
    grade=$(calculate_grade)

    echo "" >&2
    echo "GRADE: ${grade} | ${total} checks | ${elapsed}" >&2
    echo "" >&2
}

# =============================================================================
# LOOKUP FUNCTIONS (bash 3.2 compatible - no associative arrays)
# =============================================================================

# Get points for a severity level
severity_points() {
    case "${1:-}" in
        critical) echo 50 ;;
        high)     echo 20 ;;
        medium)   echo 5 ;;
        low)      echo 1 ;;
        info)     echo 0 ;;
        ignore)   echo 0 ;;
        *)        echo 0 ;;
    esac
}

# Compare grades: returns 0 if $1 is worse than or equal to $2
# Grade ordering: A+ < A < B < C < D < F (lower = better)
grade_worse_or_equal() {
    local grade1="$1"
    local grade2="$2"

    # Convert grades to numeric for comparison
    local num1 num2
    case "$grade1" in
        "A+") num1=0 ;;
        "A")  num1=1 ;;
        "B")  num1=2 ;;
        "C")  num1=3 ;;
        "D")  num1=4 ;;
        "F")  num1=5 ;;
        *)    num1=99 ;;
    esac
    case "$grade2" in
        "A+") num2=0 ;;
        "A")  num2=1 ;;
        "B")  num2=2 ;;
        "C")  num2=3 ;;
        "D")  num2=4 ;;
        "F")  num2=5 ;;
        *)    num2=99 ;;
    esac

    [[ $num1 -ge $num2 ]]
}

# =============================================================================
# GLOBAL STATE
# =============================================================================

# Findings accumulator (in-memory, no temp file needed)
# Format: newline-separated records with FIELD_SEP between fields
FINDINGS=""

# Current profile (default: personal)
PROFILE="${SANDBOXSCORE_PROFILE:-personal}"

# Platform (detected at runtime)
PLATFORM=""

# Track if we've been initialized
SCANNER_INITIALIZED=0

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

detect_platform() {
    local uname_out
    uname_out="$(uname -s 2>/dev/null)" || uname_out="unknown"

    case "$uname_out" in
        Darwin)  echo "darwin" ;;
        Linux)   echo "linux" ;;
        MINGW*|CYGWIN*|MSYS*) echo "windows" ;;
        *)       echo "unknown" ;;
    esac
}

get_os_version() {
    case "$PLATFORM" in
        darwin)
            if has_cmd sw_vers; then
                sw_vers -productVersion 2>/dev/null || echo "unknown"
            else
                echo "unknown"
            fi
            ;;
        linux)
            if [[ -f /etc/os-release ]]; then
                grep "^VERSION_ID" /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "unknown"
            elif has_cmd uname; then
                uname -r 2>/dev/null || echo "unknown"
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

get_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

# =============================================================================
# PROFILE MANAGEMENT
# =============================================================================

# Get severity for a test, considering profile overrides
# Usage: get_severity <test_name> <default_severity>
get_severity() {
    local test_name="${1:-}"
    local default_severity="${2:-medium}"

    # Profile-specific overrides
    case "$PROFILE" in
        personal)
            # Personal profile: ignore own data
            case "$test_name" in
                contacts|messages|browser_history|photos)
                    echo "ignore"
                    return
                    ;;
            esac
            ;;
        professional)
            # Professional: medium severity for personal data
            case "$test_name" in
                contacts|messages)
                    echo "medium"
                    return
                    ;;
            esac
            ;;
        sensitive)
            # Sensitive: no overrides, strictest defaults
            ;;
    esac

    echo "$default_severity"
}

# Validate profile name
validate_profile() {
    local profile="${1:-}"
    case "$profile" in
        personal|professional|sensitive)
            return 0
            ;;
        "")
            error "Profile not specified"
            return 1
            ;;
        *)
            error "Invalid profile '$profile'. Valid: personal, professional, sensitive"
            return 1
            ;;
    esac
}

# =============================================================================
# FINDINGS MANAGEMENT
# =============================================================================

# Initialize findings storage (in-memory, no filesystem needed)
init_findings() {
    FINDINGS=""
    debug "Initialized in-memory findings storage"
    return 0
}

# Record a finding
# Usage: emit <category> <test_name> <status> [value] [default_severity]
#   status: exposed, blocked, not_found, error
#   value: optional numeric or string value (for stats display)
#   default_severity: critical, high, medium, low, info (default: medium)
emit() {
    # Validate arguments
    if [[ $# -lt 3 ]]; then
        error "emit() requires at least 3 arguments: category, test_name, status"
        return 1
    fi

    local category="$1"
    local test_name="$2"
    local status="$3"
    local value="${4:-}"
    local default_severity="${5:-medium}"

    # Validate required fields
    if [[ -z "$category" || -z "$test_name" || -z "$status" ]]; then
        error "emit() got empty required field"
        return 1
    fi

    # Validate status
    case "$status" in
        exposed|blocked|not_found|error) ;;
        *)
            warn "Unknown status '$status' for $test_name, treating as error"
            status="error"
            ;;
    esac

    # Sanitize value (remove delimiter chars)
    value=$(sanitize_value "$value")

    # Get effective severity (may be overridden by profile)
    local severity
    if [[ "$status" == "exposed" ]]; then
        severity=$(get_severity "$test_name" "$default_severity")
    else
        severity="info"  # Blocked/not_found don't count against score
    fi

    # Calculate points
    local points=0
    if [[ "$status" == "exposed" ]]; then
        points=$(severity_points "$severity")
    fi

    # Update progress counters
    CURRENT_CATEGORY_COUNT=$((CURRENT_CATEGORY_COUNT + 1))
    if [[ "$status" == "exposed" ]]; then
        CURRENT_CATEGORY_EXPOSED=$((CURRENT_CATEGORY_EXPOSED + 1))
    fi

    # Stream test result with timestamp
    progress_test "$test_name" "$status" "$value"

    # Store finding in memory (append to FINDINGS variable)
    debug "emit: $category/$test_name=$status ($severity, ${points}pts)"
    local record="${category}${FIELD_SEP}${test_name}${FIELD_SEP}${status}${FIELD_SEP}${value}${FIELD_SEP}${severity}${FIELD_SEP}${points}"
    FINDINGS="${FINDINGS}${record}"$'\n'
}

# Iterate over findings, calling callback for each
# Usage: foreach_finding callback_function
# Callback receives: category test_name status value severity points
foreach_finding() {
    local callback="$1"

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        debug "No findings recorded"
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        # Skip empty lines
        [[ -z "$category" ]] && continue
        # Skip malformed lines
        if [[ -z "$test_name" || -z "$status" ]]; then
            warn "Skipping malformed finding line"
            continue
        fi
        # Ensure points is numeric
        points=$(to_int "$points")
        # Call the callback
        "$callback" "$category" "$test_name" "$status" "$value" "$severity" "$points"
    done <<< "$FINDINGS"
}

# =============================================================================
# GRADE CALCULATION
# =============================================================================

# Calculate total points lost
calculate_points() {
    local total=0

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo "0"
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        points=$(to_int "$points")
        total=$((total + points))
    done <<< "$FINDINGS"

    echo "$total"
}

# Calculate grade from points
points_to_grade() {
    local points
    points=$(to_int "${1:-0}")

    if [[ "$points" -eq 0 ]]; then
        echo "A+"
    elif [[ "$points" -le 10 ]]; then
        echo "A"
    elif [[ "$points" -le 30 ]]; then
        echo "B"
    elif [[ "$points" -le 60 ]]; then
        echo "C"
    elif [[ "$points" -le 100 ]]; then
        echo "D"
    else
        echo "F"
    fi
}

# Check for grade caps (critical findings that limit max grade)
# Returns: cap grade or empty if no cap
check_grade_caps() {
    local cap=""

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo ""
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        [[ "$status" != "exposed" ]] && continue

        case "$test_name" in
            ssh_keys)
                # SSH keys cap at B for all profiles
                if [[ -z "$cap" ]] || ! grade_worse_or_equal "B" "$cap"; then
                    cap="B"
                fi
                ;;
            cloud_creds)
                # Cloud creds cap at C for all profiles
                if [[ -z "$cap" ]] || ! grade_worse_or_equal "C" "$cap"; then
                    cap="C"
                fi
                ;;
            contacts)
                # Contacts cap at C for sensitive profile only
                if [[ "$PROFILE" == "sensitive" ]]; then
                    if [[ -z "$cap" ]] || ! grade_worse_or_equal "C" "$cap"; then
                        cap="C"
                    fi
                fi
                ;;
        esac
    done <<< "$FINDINGS"

    echo "$cap"
}

# Get the cap reason(s)
get_cap_reasons() {
    local reasons=""

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo ""
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        [[ "$status" != "exposed" ]] && continue

        case "$test_name" in
            ssh_keys)
                reasons="${reasons:+$reasons }ssh_keys"
                ;;
            cloud_creds)
                reasons="${reasons:+$reasons }cloud_creds"
                ;;
            contacts)
                if [[ "$PROFILE" == "sensitive" ]]; then
                    reasons="${reasons:+$reasons }contacts"
                fi
                ;;
        esac
    done <<< "$FINDINGS"

    echo "$reasons"
}

# Calculate final grade (considering caps)
calculate_grade() {
    local points
    points=$(calculate_points)

    local base_grade
    base_grade=$(points_to_grade "$points")

    local cap
    cap=$(check_grade_caps)

    # Apply cap if it's worse than base grade
    if [[ -n "$cap" ]] && grade_worse_or_equal "$cap" "$base_grade" && [[ "$cap" != "$base_grade" ]]; then
        # Cap is worse, but only apply if it's actually worse (not equal)
        if ! grade_worse_or_equal "$base_grade" "$cap"; then
            echo "$cap"
            return
        fi
    fi
    echo "$base_grade"
}

# Calculate grade for a specific category
calculate_category_grade() {
    local target_category="$1"
    local points=0

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo "A+"
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity cat_points; do
        [[ -z "$category" ]] && continue
        if [[ "$category" == "$target_category" ]]; then
            cat_points=$(to_int "$cat_points")
            points=$((points + cat_points))
        fi
    done <<< "$FINDINGS"

    points_to_grade "$points"
}

# =============================================================================
# CROSS-PROFILE GRADING
# =============================================================================

# Calculate what grade would be under a different profile
# Note: This recalculates severity for each finding under the new profile
calculate_grade_for_profile() {
    local target_profile="$1"
    local original_profile="$PROFILE"
    local total_points=0

    # Temporarily switch profile
    PROFILE="$target_profile"

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        PROFILE="$original_profile"
        echo "A+"
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value orig_severity _; do
        [[ -z "$category" ]] && continue
        if [[ "$status" == "exposed" ]]; then
            local new_severity
            new_severity=$(get_severity "$test_name" "$orig_severity")
            local new_points
            new_points=$(severity_points "$new_severity")
            total_points=$((total_points + new_points))
        fi
    done <<< "$FINDINGS"

    local base_grade
    base_grade=$(points_to_grade "$total_points")

    # Check caps under this profile
    local cap
    cap=$(check_grade_caps)

    # Restore profile BEFORE returning
    PROFILE="$original_profile"

    if [[ -n "$cap" ]] && ! grade_worse_or_equal "$base_grade" "$cap"; then
        echo "$cap"
    else
        echo "$base_grade"
    fi
}

# =============================================================================
# OUTPUT FUNCTIONS
# =============================================================================

# Get summary counts
get_summary() {
    local total=0
    local exposed=0
    local blocked=0

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo "0|0|0"
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        total=$((total + 1))
        case "$status" in
            exposed) exposed=$((exposed + 1)) ;;
            blocked) blocked=$((blocked + 1)) ;;
        esac
    done <<< "$FINDINGS"

    echo "${total}|${exposed}|${blocked}"
}

# Output findings in raw format (for machine parsing)
output_raw() {
    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        if [[ -n "$value" ]]; then
            echo "${category}:${test_name}:${status}:${value}"
        else
            echo "${category}:${test_name}:${status}"
        fi
    done <<< "$FINDINGS"
}

# Output findings JSON section
output_findings_json() {
    local first=true

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        return 0
    fi

    while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
        [[ -z "$category" ]] && continue
        if $first; then
            first=false
        else
            echo ","
        fi
        # Escape for JSON safety
        local escaped_name escaped_status
        escaped_name=$(json_escape "$test_name")
        escaped_status=$(json_escape "$status")
        echo -n "      \"$escaped_name\": \"$escaped_status\""
    done <<< "$FINDINGS"
    echo ""
}

# Output findings in JSON format
output_json() {
    local grade points cap_reasons summary
    grade=$(calculate_grade)
    points=$(calculate_points)
    cap_reasons=$(get_cap_reasons)
    summary=$(get_summary)

    local total exposed blocked
    total=$(echo "$summary" | cut -d'|' -f1)
    exposed=$(echo "$summary" | cut -d'|' -f2)
    blocked=$(echo "$summary" | cut -d'|' -f3)

    # Ensure numeric values
    total=$(to_int "$total")
    exposed=$(to_int "$exposed")
    blocked=$(to_int "$blocked")
    points=$(to_int "$points")

    # Build caps array
    local caps_json=""
    if [[ -n "$cap_reasons" ]]; then
        # Convert space-separated to JSON array
        local first_cap=true
        for cap in $cap_reasons; do
            if $first_cap; then
                first_cap=false
                caps_json="\"$(json_escape "$cap")\""
            else
                caps_json="$caps_json, \"$(json_escape "$cap")\""
            fi
        done
    fi

    # Escape profile for JSON
    local escaped_profile
    escaped_profile=$(json_escape "$PROFILE")

    # Get timestamps safely
    local timestamp
    timestamp=$(date +%Y-%m-%d 2>/dev/null || echo "unknown")

    local os_version arch_val
    os_version=$(json_escape "$(get_os_version)")
    arch_val=$(json_escape "$(get_arch)")

    cat <<EOF
{
  "v": "$METHODOLOGY_VERSION",
  "ts": "$timestamp",
  "scanner": "$SCANNER_VERSION",
  "methodology": "$METHODOLOGY_VERSION",
  "profile": "$escaped_profile",
  "env": {
    "platform": "$PLATFORM",
    "os": "$os_version",
    "arch": "$arch_val"
  },
  "results": {
    "grade": "$grade",
    "points_lost": $points,
    "categories": {
      "credentials": "$(calculate_category_grade credentials)",
      "personal_data": "$(calculate_category_grade personal_data)",
      "system_visibility": "$(calculate_category_grade system_visibility)",
      "persistence": "$(calculate_category_grade persistence)",
      "network": "$(calculate_category_grade network)"
    },
    "caps": [$caps_json],
    "summary": {"total": $total, "protected": $blocked, "exposed": $exposed},
    "cross_profile": {
      "personal": "$(calculate_grade_for_profile personal)",
      "professional": "$(calculate_grade_for_profile professional)",
      "sensitive": "$(calculate_grade_for_profile sensitive)"
    },
    "findings": {
$(output_findings_json)
    }
  }
}
EOF
}

# Output in human-readable format
output_human() {
    local grade points cap_reasons summary
    grade=$(calculate_grade)
    points=$(calculate_points)
    cap_reasons=$(get_cap_reasons)
    summary=$(get_summary)

    local total exposed blocked
    total=$(echo "$summary" | cut -d'|' -f1)
    exposed=$(echo "$summary" | cut -d'|' -f2)
    blocked=$(echo "$summary" | cut -d'|' -f3)

    echo "SANDBOXSCORE: Coding Agents"
    echo "================================================================"
    echo "Scanner: v${SCANNER_VERSION} | Methodology: v${METHODOLOGY_VERSION} | Profile: ${PROFILE}"
    echo ""
    echo "GRADE: $grade"
    echo ""
    echo "Categories:"
    printf "  %-20s %s\n" "Credentials:" "$(calculate_category_grade credentials)"
    printf "  %-20s %s\n" "Personal Data:" "$(calculate_category_grade personal_data)"
    printf "  %-20s %s\n" "System Visibility:" "$(calculate_category_grade system_visibility)"
    printf "  %-20s %s\n" "Persistence:" "$(calculate_category_grade persistence)"
    printf "  %-20s %s\n" "Network:" "$(calculate_category_grade network)"
    echo ""

    if [[ -n "$cap_reasons" ]]; then
        echo "Grade capped due to: $cap_reasons"
        echo ""
    fi

    echo "Findings:"

    # Handle empty findings
    if [[ -z "$FINDINGS" ]]; then
        echo "  (no findings)"
    else
        while IFS="$FIELD_SEP" read -r category test_name status value severity points; do
            [[ -z "$category" ]] && continue
            local icon
            case "$status" in
                exposed)
                    case "$severity" in
                        critical) icon="[CRIT]" ;;
                        high)     icon="[HIGH]" ;;
                        medium)   icon="[MED] " ;;
                        low)      icon="[LOW] " ;;
                        ignore)   icon="[IGN] " ;;
                        *)        icon="[----]" ;;
                    esac
                    ;;
                blocked)  icon="[SAFE]" ;;
                *)        icon="[----]" ;;
            esac

            if [[ -n "$value" && "$value" != "0" ]]; then
                printf "  %s %-20s %s (%s)\n" "$icon" "$test_name" "$status" "$value"
            else
                printf "  %s %-20s %s\n" "$icon" "$test_name" "$status"
            fi
        done <<< "$FINDINGS"
    fi

    echo ""
    echo "Against other profiles:"
    printf "  %-15s %s\n" "personal:" "$(calculate_grade_for_profile personal)"
    printf "  %-15s %s\n" "professional:" "$(calculate_grade_for_profile professional)"
    printf "  %-15s %s\n" "sensitive:" "$(calculate_grade_for_profile sensitive)"
    echo ""
    echo "Summary: ${total} tests | ${blocked} protected | ${exposed} exposed"
    echo "================================================================"
}

# Main output function
output_results() {
    local format="${1:-human}"

    case "$format" in
        raw)   output_raw ;;
        json)  output_json ;;
        human) output_human ;;
        *)
            error "Unknown format '$format'. Valid: human, json, raw"
            return 1
            ;;
    esac
}

# =============================================================================
# INITIALIZATION
# =============================================================================

# Check environment prerequisites
check_environment() {
    # Check HOME is set (many tests need it)
    if [[ -z "${HOME:-}" ]]; then
        warn "HOME environment variable not set - some tests may fail"
    fi

    # Check for required commands
    local missing=""
    for cmd in uname date cut; do
        if ! has_cmd "$cmd"; then
            missing="${missing:+$missing, }$cmd"
        fi
    done

    if [[ -n "$missing" ]]; then
        error "Missing required commands: $missing"
        return 1
    fi

    return 0
}

init_scanner() {
    # Prevent double initialization
    if [[ "$SCANNER_INITIALIZED" == "1" ]]; then
        debug "Scanner already initialized"
        return 0
    fi

    # Check environment
    if ! check_environment; then
        return 1
    fi

    # Detect platform
    PLATFORM=$(detect_platform)
    debug "Detected platform: $PLATFORM"

    if [[ "$PLATFORM" == "unknown" ]]; then
        error "Unsupported platform: $(uname -s 2>/dev/null || echo 'unknown')"
        return 1
    fi

    # Validate profile
    if ! validate_profile "$PROFILE"; then
        return 1
    fi
    debug "Using profile: $PROFILE"

    # Initialize findings storage
    if ! init_findings; then
        return 1
    fi

    SCANNER_INITIALIZED=1
    debug "Scanner initialized successfully"
    return 0
}
