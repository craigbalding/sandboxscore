#!/bin/bash
# SandboxScore - Coding Agents Module - System Visibility Tests (macOS)
# Category: system_visibility (10% weight)
#
# macOS-specific visibility tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# User Enumeration - macOS specific (dscl)
# Severity: medium
# =============================================================================
scan_users() {
    debug "scan_users: starting (darwin)"

    local count=0
    local methods=""

    # Method 1: dscl (macOS Directory Services)
    if has_cmd dscl; then
        local dscl_output
        dscl_output=$(with_timeout "$DEFAULT_TIMEOUT" dscl . -list /Users 2>&1)
        local dscl_exit=$?

        if [[ $dscl_exit -eq 0 && -n "$dscl_output" ]]; then
            # Filter out system users (starting with _) and count
            local dscl_count
            dscl_count=$(echo "$dscl_output" | grep -v "^_" | wc -l) || dscl_count=0
            dscl_count=$(to_int "$dscl_count")
            if [[ "$dscl_count" -gt "$count" ]]; then
                count=$dscl_count
            fi
            methods="${methods}dscl,"
            debug "scan_users: dscl found $dscl_count users"
        fi
    fi

    # Method 2: ls /Users (fallback)
    if [[ -d "/Users" && -r "/Users" ]]; then
        local ls_count
        ls_count=$(ls -1 /Users 2>/dev/null | grep -v "^Shared$" | grep -v "^\." | wc -l) || ls_count=0
        ls_count=$(to_int "$ls_count")
        if [[ "$ls_count" -gt "$count" ]]; then
            count=$ls_count
        fi
        methods="${methods}ls,"
        debug "scan_users: ls /Users found $ls_count users"
    fi

    # Method 3: who (logged in users)
    if has_cmd who; then
        local who_output
        who_output=$(with_timeout "$DEFAULT_TIMEOUT" who 2>&1)
        if [[ -n "$who_output" ]]; then
            methods="${methods}who,"
            debug "scan_users: who shows logged in sessions"
        fi
    fi

    methods="${methods%,}"

    if [[ "$count" -gt 0 ]]; then
        emit "system_visibility" "users" "exposed" "${count}/${methods}" "medium"
    else
        emit "system_visibility" "users" "blocked" "" "medium"
    fi
}

# =============================================================================
# Network Listeners - macOS specific (lsof preferred)
# Severity: medium
# =============================================================================
scan_network_listeners() {
    debug "scan_network_listeners: starting (darwin)"

    local count=0

    # Try lsof (most reliable on macOS)
    if has_cmd lsof; then
        local lsof_output
        lsof_output=$(with_timeout "$DEFAULT_TIMEOUT" lsof -i -P -n 2>&1)
        local lsof_exit=$?

        if [[ $lsof_exit -eq 0 && -n "$lsof_output" ]]; then
            count=$(echo "$lsof_output" | grep -c "LISTEN") || count=0
            count=$(to_int "$count")
            debug "scan_network_listeners: lsof found $count listeners"
        fi
    fi

    # Fallback to netstat
    if [[ "$count" -eq 0 ]] && has_cmd netstat; then
        local netstat_output
        netstat_output=$(with_timeout "$DEFAULT_TIMEOUT" netstat -an 2>&1)
        local netstat_exit=$?

        if [[ $netstat_exit -eq 0 && -n "$netstat_output" ]]; then
            count=$(echo "$netstat_output" | grep -c "LISTEN") || count=0
            count=$(to_int "$count")
            debug "scan_network_listeners: netstat found $count listeners"
        fi
    fi

    if ! has_cmd lsof && ! has_cmd netstat; then
        emit "system_visibility" "network_listeners" "error" "no_cmd" "medium"
        return
    fi

    if [[ "$count" -gt 0 ]]; then
        emit "system_visibility" "network_listeners" "exposed" "$count" "medium"
    else
        emit "system_visibility" "network_listeners" "blocked" "" "medium"
    fi
}

# =============================================================================
# Installed Apps - macOS specific
# Severity: low
# =============================================================================
scan_installed_apps() {
    debug "scan_installed_apps: starting (darwin)"

    local count=0

    # Check /Applications
    if dir_readable "/Applications"; then
        count=$(ls -1 /Applications 2>/dev/null | grep -c "\.app$") || count=0
        count=$(to_int "$count")
        debug "scan_installed_apps: found $count apps in /Applications"
    fi

    # Also check user Applications
    if [[ -n "${HOME:-}" ]] && dir_readable "$HOME/Applications"; then
        local user_count
        user_count=$(ls -1 "$HOME/Applications" 2>/dev/null | grep -c "\.app$") || user_count=0
        user_count=$(to_int "$user_count")
        count=$((count + user_count))
        debug "scan_installed_apps: found $user_count apps in ~/Applications"
    fi

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "installed_apps" "exposed" "$count" "low"
    else
        emit "system_visibility" "installed_apps" "blocked" "" "low"
    fi
}

# =============================================================================
# Hardware IDs - macOS specific
# Severity: medium (serial numbers can be used for tracking)
# =============================================================================
scan_hardware_ids() {
    debug "scan_hardware_ids: starting (darwin)"

    local found=0
    local ids=""

    # Try system_profiler for hardware info
    if has_cmd system_profiler; then
        local hw_output
        hw_output=$(with_timeout "$DEFAULT_TIMEOUT" system_profiler SPHardwareDataType 2>/dev/null) || hw_output=""

        if [[ -n "$hw_output" ]]; then
            # Check if we can see serial number
            if echo "$hw_output" | grep -q "Serial Number"; then
                found=1
                ids="${ids}serial,"
                debug "scan_hardware_ids: serial number accessible"
            fi
            # Check if we can see hardware UUID
            if echo "$hw_output" | grep -q "Hardware UUID"; then
                found=1
                ids="${ids}uuid,"
                debug "scan_hardware_ids: hardware UUID accessible"
            fi
        fi
    fi

    # Try ioreg as fallback
    if [[ $found -eq 0 ]] && has_cmd ioreg; then
        local ioreg_output
        ioreg_output=$(with_timeout "$DEFAULT_TIMEOUT" ioreg -l 2>/dev/null | head -100) || ioreg_output=""

        if [[ -n "$ioreg_output" ]]; then
            found=1
            ids="ioreg"
            debug "scan_hardware_ids: ioreg accessible"
        fi
    fi

    ids="${ids%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "hardware_ids" "exposed" "$ids" "medium"
    else
        emit "system_visibility" "hardware_ids" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all system visibility tests
# =============================================================================
run_system_visibility_tests() {
    debug "run_system_visibility_tests: starting (darwin)"
    progress_start "system"
    # Cross-platform (from shared.sh)
    scan_processes
    scan_hostname
    scan_os_version
    # CI/CD detection (from shared.sh)
    scan_ci_environment   # CI/CD platform detection
    scan_ci_github_deep   # GitHub Actions deep enumeration
    scan_ci_gitlab_deep   # GitLab CI deep enumeration
    scan_ci_runner_type   # Self-hosted vs managed runner
    # macOS-specific
    scan_users
    scan_network_listeners
    scan_installed_apps
    scan_hardware_ids
    progress_end "system"
    debug "run_system_visibility_tests: complete"
}
