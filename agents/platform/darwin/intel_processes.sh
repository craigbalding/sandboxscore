#!/bin/bash
# SandboxScore - Intelligence Module - Process Discovery (macOS)
#
# Extracts intelligence from process visibility:
# - What processes can we see? (own, other user, system)
# - What applications are running?
# - Can we see command lines? (may contain secrets)
# - Can we see environment variables?
#
# Requires: common.sh, intel_common.sh to be sourced first

# =============================================================================
# Process Visibility Analysis
# =============================================================================

# Analyze what processes are visible via ps
# Sets globals: PROC_OWN_COUNT, PROC_USER_COUNT, PROC_SYSTEM_COUNT
# Returns: 0 on success, 1 if ps blocked, 2 if ps works but no other processes visible
analyze_process_visibility() {
    debug "analyze_process_visibility: starting"

    PROC_OWN_COUNT=0
    PROC_USER_COUNT=0
    PROC_SYSTEM_COUNT=0

    local current_user="${USER:-$(whoami)}"

    # Get process list with user info
    local ps_output
    ps_output=$(with_timeout 5 ps aux 2>&1)
    local ps_exit=$?

    # Check if ps command itself is blocked
    if [[ $ps_exit -ne 0 ]] || echo "$ps_output" | grep -qi "not permitted\|operation not permitted\|denied"; then
        debug "analyze_process_visibility: ps command blocked"
        return 1
    fi

    # Check if output is essentially empty (header only)
    local line_count
    line_count=$(echo "$ps_output" | wc -l | tr -d ' ')
    if [[ "$line_count" -le 1 ]]; then
        debug "analyze_process_visibility: ps returned no processes"
        return 1
    fi

    # Skip header, analyze each line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local proc_user
        proc_user=$(echo "$line" | awk '{print $1}')
        [[ -z "$proc_user" ]] && continue

        local category
        category=$(classify_process_owner "$proc_user")

        case "$category" in
            own)
                PROC_OWN_COUNT=$((PROC_OWN_COUNT + 1))
                ;;
            other_user)
                PROC_USER_COUNT=$((PROC_USER_COUNT + 1))
                ;;
            system)
                PROC_SYSTEM_COUNT=$((PROC_SYSTEM_COUNT + 1))
                ;;
        esac
    done <<< "$(echo "$ps_output" | tail -n +2)"

    debug "analyze_process_visibility: own=$PROC_OWN_COUNT user=$PROC_USER_COUNT system=$PROC_SYSTEM_COUNT"
    return 0
}

# =============================================================================
# Fallback: Process Visibility via lsof
# When ps is blocked, lsof still reveals process names, PIDs, and users
# =============================================================================
analyze_process_visibility_via_lsof() {
    debug "analyze_process_visibility_via_lsof: starting"

    PROC_OWN_COUNT=0
    PROC_USER_COUNT=0
    PROC_SYSTEM_COUNT=0

    if ! has_cmd lsof; then
        debug "analyze_process_visibility_via_lsof: lsof not available"
        return 1
    fi

    # Get unique process/user combinations from lsof
    local lsof_output
    lsof_output=$(with_timeout 10 lsof 2>/dev/null | awk 'NR>1 {print $3}' | sort -u)

    if [[ -z "$lsof_output" ]]; then
        debug "analyze_process_visibility_via_lsof: no output"
        return 1
    fi

    # Count by category
    while IFS= read -r proc_user; do
        [[ -z "$proc_user" ]] && continue

        local category
        category=$(classify_process_owner "$proc_user")

        case "$category" in
            own)
                PROC_OWN_COUNT=$((PROC_OWN_COUNT + 1))
                ;;
            other_user)
                PROC_USER_COUNT=$((PROC_USER_COUNT + 1))
                ;;
            system)
                PROC_SYSTEM_COUNT=$((PROC_SYSTEM_COUNT + 1))
                ;;
        esac
    done <<< "$lsof_output"

    # Also count unique process names for a better estimate
    local proc_count
    proc_count=$(with_timeout 5 lsof 2>/dev/null | awk 'NR>1 {print $1}' | sort -u | wc -l | tr -d ' ')
    proc_count=$(to_int "$proc_count")

    debug "analyze_process_visibility_via_lsof: users own=$PROC_OWN_COUNT user=$PROC_USER_COUNT system=$PROC_SYSTEM_COUNT procs=$proc_count"

    # Store for later
    LSOF_PROC_COUNT="$proc_count"

    return 0
}

# =============================================================================
# Fallback: Session Info via w/who
# Reveals logged-in users, source IPs, and current commands
# =============================================================================
analyze_session_info() {
    debug "analyze_session_info: starting"

    SESSION_COUNT=0
    SESSION_REMOTE_COUNT=0
    SESSION_REMOTE_IPS=""
    SESSION_COMMANDS=""

    # Try 'w' command first (more info)
    if has_cmd w; then
        local w_output
        w_output=$(with_timeout 5 w 2>/dev/null)

        if [[ -n "$w_output" ]]; then
            # Count sessions (skip header lines)
            SESSION_COUNT=$(echo "$w_output" | tail -n +3 | wc -l | tr -d ' ')

            # Extract remote IPs (non-empty FROM field, not '-')
            SESSION_REMOTE_IPS=$(echo "$w_output" | tail -n +3 | awk '$3 != "-" && $3 != "" {print $3}' | sort -u | tr '\n' ',' | sed 's/,$//')

            # Count remote sessions
            SESSION_REMOTE_COUNT=$(echo "$w_output" | tail -n +3 | awk '$3 != "-" && $3 != "" {print}' | wc -l | tr -d ' ')

            # Extract what's running (WHAT column)
            SESSION_COMMANDS=$(echo "$w_output" | tail -n +3 | awk '{print $NF}' | sort -u | head -5 | tr '\n' ',' | sed 's/,$//')

            debug "analyze_session_info: sessions=$SESSION_COUNT remote=$SESSION_REMOTE_COUNT ips=$SESSION_REMOTE_IPS"
            return 0
        fi
    fi

    # Fallback to 'who'
    if has_cmd who; then
        local who_output
        who_output=$(with_timeout 5 who 2>/dev/null)

        if [[ -n "$who_output" ]]; then
            SESSION_COUNT=$(echo "$who_output" | wc -l | tr -d ' ')

            # Extract IPs from parentheses
            SESSION_REMOTE_IPS=$(echo "$who_output" | grep -oE '\([0-9.]+\)' | tr -d '()' | sort -u | tr '\n' ',' | sed 's/,$//')
            SESSION_REMOTE_COUNT=$(echo "$who_output" | grep -c '([0-9]')

            debug "analyze_session_info: sessions=$SESSION_COUNT remote=$SESSION_REMOTE_COUNT"
            return 0
        fi
    fi

    debug "analyze_session_info: no session info available"
    return 1
}

# =============================================================================
# Application Detection
# =============================================================================

# Detect notable applications from process list
# Returns: comma-separated list of detected apps
# Uses ps if available, falls back to lsof
detect_running_applications() {
    debug "detect_running_applications: starting"

    local proc_output

    # Try ps first, fall back to lsof
    proc_output=$(with_timeout 5 ps axo comm 2>/dev/null)
    if [[ -z "$proc_output" ]]; then
        proc_output=$(with_timeout 5 lsof 2>/dev/null | awk 'NR>1 {print $1}' | sort -u)
    fi

    [[ -z "$proc_output" ]] && return 1

    local detected=""

    # Development tools
    echo "$proc_output" | grep -qi "docker" && detected="${detected}docker,"
    echo "$proc_output" | grep -qi "ollama" && detected="${detected}ollama,"
    echo "$proc_output" | grep -qi "whisper" && detected="${detected}whisper,"
    echo "$proc_output" | grep -qi "orbstack" && detected="${detected}orbstack,"
    echo "$proc_output" | grep -qi "code\|vscode" && detected="${detected}vscode,"
    echo "$proc_output" | grep -qi "xcode" && detected="${detected}xcode,"
    echo "$proc_output" | grep -qi "claude" && detected="${detected}claude,"

    # Browsers
    echo "$proc_output" | grep -qi "safari" && detected="${detected}safari,"
    echo "$proc_output" | grep -qi "chrome" && detected="${detected}chrome,"
    echo "$proc_output" | grep -qi "brave" && detected="${detected}brave,"
    echo "$proc_output" | grep -qi "firefox" && detected="${detected}firefox,"

    # Communication
    echo "$proc_output" | grep -qi "slack" && detected="${detected}slack,"
    echo "$proc_output" | grep -qi "discord" && detected="${detected}discord,"
    echo "$proc_output" | grep -qi "teams" && detected="${detected}teams,"
    echo "$proc_output" | grep -qi "zoom" && detected="${detected}zoom,"

    # Security/VPN
    echo "$proc_output" | grep -qi "tailscale" && detected="${detected}tailscale,"
    echo "$proc_output" | grep -qi "wireguard" && detected="${detected}wireguard,"
    echo "$proc_output" | grep -qi "openvpn" && detected="${detected}openvpn,"
    echo "$proc_output" | grep -qi "1password" && detected="${detected}1password,"
    echo "$proc_output" | grep -qi "bitwarden" && detected="${detected}bitwarden,"

    # Cloud/Infrastructure
    echo "$proc_output" | grep -qi "aws" && detected="${detected}aws,"
    echo "$proc_output" | grep -qi "gcloud" && detected="${detected}gcloud,"
    echo "$proc_output" | grep -qi "kubectl" && detected="${detected}kubectl,"

    # Remove trailing comma
    detected="${detected%,}"

    debug "detect_running_applications: found $detected"
    echo "$detected"
}

# =============================================================================
# Command Line Visibility
# =============================================================================

# Check if we can see other processes' command lines
# Returns: 0 if visible (with potential secrets), 1 if blocked
check_cmdline_visibility() {
    debug "check_cmdline_visibility: starting"

    local current_user="${USER:-$(whoami)}"

    # Try ps with full command line for other users' processes
    local ps_output
    ps_output=$(with_timeout 5 ps auxww 2>/dev/null) || return 1

    # Look for command lines from other users that have arguments
    local other_cmdlines
    other_cmdlines=$(echo "$ps_output" | awk -v user="$current_user" \
        '$1 != user && NF > 11 {for(i=11;i<=NF;i++) printf "%s ", $i; print ""}' | \
        grep -v "^$" | head -5)

    if [[ -n "$other_cmdlines" ]]; then
        debug "check_cmdline_visibility: can see other users' command lines"

        # Check if any contain potential secrets
        if echo "$other_cmdlines" | grep -qiE 'password|token|key|secret|auth'; then
            debug "check_cmdline_visibility: found potential secrets in cmdlines"
            echo "secrets_visible"
            return 0
        fi

        echo "visible"
        return 0
    fi

    debug "check_cmdline_visibility: cannot see other users' command lines"
    return 1
}

# =============================================================================
# Environment Variable Visibility
# =============================================================================

# Check if we can see other processes' environment variables
# Returns: 0 if visible, 1 if blocked
check_environ_visibility() {
    debug "check_environ_visibility: starting"

    # On macOS, ps auxe shows environment, but usually blocked for other users
    local ps_output
    ps_output=$(with_timeout 5 ps auxe 2>/dev/null) || return 1

    local current_user="${USER:-$(whoami)}"

    # Look for environment variables (KEY=value patterns) from other users
    local other_environ
    other_environ=$(echo "$ps_output" | awk -v user="$current_user" \
        '$1 != user {print}' | grep -oE '[A-Z_]+=[^ ]+' | head -5)

    if [[ -n "$other_environ" ]]; then
        debug "check_environ_visibility: can see other users' environment"

        # Check for sensitive env vars
        if echo "$other_environ" | grep -qiE 'API_KEY|TOKEN|SECRET|PASSWORD|AWS_|GITHUB_'; then
            debug "check_environ_visibility: found sensitive env vars"
            echo "secrets_visible"
            return 0
        fi

        echo "visible"
        return 0
    fi

    debug "check_environ_visibility: cannot see other users' environment"
    return 1
}

# =============================================================================
# Main Scanner
# =============================================================================

scan_intel_processes() {
    debug "scan_intel_processes: starting"

    # Try ps first
    if has_cmd ps && analyze_process_visibility; then
        # ps works - use the full analysis
        debug "scan_intel_processes: ps works, using full analysis"
    else
        # ps blocked - try fallback methods
        debug "scan_intel_processes: ps blocked, trying fallbacks"

        if analyze_process_visibility_via_lsof; then
            debug "scan_intel_processes: lsof fallback succeeded"
        else
            # All methods blocked - properly sandboxed
            emit "intelligence" "processes" "blocked" "all_blocked" "low"
            return
        fi
    fi

    local details=""
    local severity="low"
    local status="blocked"

    # Check what we can see
    local total_other=$((PROC_USER_COUNT + PROC_SYSTEM_COUNT))

    # If using lsof fallback, check if we can see many processes
    # Even if they're all "own user", seeing 100+ processes is reconnaissance
    local lsof_proc_count="${LSOF_PROC_COUNT:-0}"
    lsof_proc_count=$(to_int "$lsof_proc_count")

    if [[ $total_other -eq 0 && $lsof_proc_count -lt 10 ]]; then
        # Can only see own processes and very few of them - properly isolated
        debug "scan_intel_processes: only own processes visible"
        emit "intelligence" "processes" "blocked" "own_only:$PROC_OWN_COUNT" "low"
        return
    fi

    # Seeing many processes (even same user) is reconnaissance exposure
    if [[ $total_other -eq 0 && $lsof_proc_count -ge 10 ]]; then
        # ps blocked but lsof reveals many processes - limited exposure
        status="exposed"
        details="ps:blocked,lsof_procs:$lsof_proc_count"
        severity="low"
        # Fall through to add apps/session info
    elif [[ $total_other -gt 0 ]]; then
        # We can see other users' processes - this is full exposure
        status="exposed"
        details="own:$PROC_OWN_COUNT"
    else
        # No other processes, few lsof procs - shouldn't reach here
        emit "intelligence" "processes" "blocked" "own_only:$PROC_OWN_COUNT" "low"
        return
    fi

    if [[ $PROC_USER_COUNT -gt 0 ]]; then
        details="${details},user:$PROC_USER_COUNT"
        severity="medium"
    fi

    if [[ $PROC_SYSTEM_COUNT -gt 0 ]]; then
        details="${details},system:$PROC_SYSTEM_COUNT"
        severity="medium"
    fi

    # Detect running applications (reconnaissance)
    local apps
    apps=$(detect_running_applications)
    if [[ -n "$apps" ]]; then
        # Count apps instead of listing all
        local app_count
        app_count=$(echo "$apps" | tr ',' '\n' | wc -l | tr -d ' ')
        details="${details},apps:$app_count"
    fi

    # Check command line visibility
    local cmdline_status
    cmdline_status=$(check_cmdline_visibility)
    if [[ -n "$cmdline_status" ]]; then
        details="${details},cmdline:$cmdline_status"
        if [[ "$cmdline_status" == "secrets_visible" ]]; then
            severity="high"
        fi
    fi

    # Check environment visibility
    local environ_status
    environ_status=$(check_environ_visibility)
    if [[ -n "$environ_status" ]]; then
        details="${details},environ:$environ_status"
        if [[ "$environ_status" == "secrets_visible" ]]; then
            severity="high"
        fi
    fi

    # Check session info (w/who) - reveals logged-in users and remote IPs
    if analyze_session_info; then
        if [[ $SESSION_COUNT -gt 0 ]]; then
            details="${details},sessions:$SESSION_COUNT"
        fi
        if [[ $SESSION_REMOTE_COUNT -gt 0 ]]; then
            details="${details},remote:$SESSION_REMOTE_COUNT"
            severity="medium"
            # Note: Could include IPs but that might be too verbose
            # SESSION_REMOTE_IPS has the actual addresses
        fi
    fi

    debug "scan_intel_processes: $status ($severity) - $details"
    emit "intelligence" "processes" "$status" "$details" "$severity"
}

# =============================================================================
# Run all process intelligence tests
# =============================================================================
run_intel_processes_tests() {
    debug "run_intel_processes_tests: starting (darwin)"
    progress_start "intel_processes"
    scan_intel_processes
    progress_end "intel_processes"
    debug "run_intel_processes_tests: complete"
}
