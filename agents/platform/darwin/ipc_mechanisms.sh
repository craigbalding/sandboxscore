#!/bin/bash
# SandboxScore - Coding Agents Module - IPC Mechanisms Tests (macOS)
# Category: system_visibility
#
# Tests for inter-process communication exposure:
# - Shared memory (ipcs)
# - Named pipes/FIFOs
# - Unix sockets enumeration
# - Mach IPC / XPC
# - /var/folders access
#
# Requires: common.sh to be sourced first

# =============================================================================
# Shared Memory Access (ipcs)
# Severity: medium (can reveal process communication)
# =============================================================================
scan_shared_memory() {
    debug "scan_shared_memory: starting"

    if ! has_cmd ipcs; then
        emit "system_visibility" "shared_memory" "error" "no_ipcs" "medium"
        return
    fi

    local ipcs_output
    ipcs_output=$(with_timeout "$DEFAULT_TIMEOUT" ipcs -a 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_shared_memory: ipcs failed (exit=$exit_code)"
        emit "system_visibility" "shared_memory" "blocked" "" "medium"
        return
    fi

    # Count shared memory segments
    local shm_count msg_count sem_count
    shm_count=$(echo "$ipcs_output" | grep -c "^m") || shm_count=0
    msg_count=$(echo "$ipcs_output" | grep -c "^q") || msg_count=0
    sem_count=$(echo "$ipcs_output" | grep -c "^s") || sem_count=0

    shm_count=$(to_int "$shm_count")
    msg_count=$(to_int "$msg_count")
    sem_count=$(to_int "$sem_count")

    local total=$((shm_count + msg_count + sem_count))
    local details=""

    if [[ $shm_count -gt 0 ]]; then
        details="${details}shm:$shm_count,"
    fi
    if [[ $msg_count -gt 0 ]]; then
        details="${details}msg:$msg_count,"
    fi
    if [[ $sem_count -gt 0 ]]; then
        details="${details}sem:$sem_count,"
    fi

    details="${details%,}"

    if [[ $total -gt 0 ]]; then
        emit "system_visibility" "shared_memory" "exposed" "$details" "medium"
    else
        # ipcs worked but nothing found - still exposed (can enumerate)
        emit "system_visibility" "shared_memory" "exposed" "empty" "low"
    fi
}

# =============================================================================
# FIFO Creation Capability
# Severity: low (IPC capability)
# =============================================================================
scan_fifo_creation() {
    debug "scan_fifo_creation: starting"

    local tmp_dir="${TMPDIR:-/tmp}"
    local fifo_path="$tmp_dir/.sandboxscore_fifo_$$"

    if ! has_cmd mkfifo; then
        emit "system_visibility" "fifo_creation" "error" "no_mkfifo" "low"
        return
    fi

    # Try to create a FIFO
    if mkfifo "$fifo_path" 2>/dev/null; then
        rm -f "$fifo_path" 2>/dev/null
        debug "scan_fifo_creation: can create FIFOs"
        emit "system_visibility" "fifo_creation" "exposed" "" "low"
    else
        debug "scan_fifo_creation: cannot create FIFOs"
        emit "system_visibility" "fifo_creation" "blocked" "" "low"
    fi
}

# =============================================================================
# Unix Socket Enumeration
# Severity: medium (reveals running services, potential attack surface)
# =============================================================================
scan_unix_sockets() {
    debug "scan_unix_sockets: starting"

    local total=0
    local locations=""

    # Check /tmp for sockets
    if [[ -d "/tmp" ]]; then
        local tmp_count
        tmp_count=$(find /tmp -type s 2>/dev/null | wc -l) || tmp_count=0
        tmp_count=$(to_int "$tmp_count")
        if [[ $tmp_count -gt 0 ]]; then
            total=$((total + tmp_count))
            locations="${locations}/tmp:$tmp_count,"
            debug "scan_unix_sockets: found $tmp_count sockets in /tmp"
        fi
    fi

    # Check /var/run for sockets
    if [[ -d "/var/run" ]]; then
        local varrun_count
        varrun_count=$(find /var/run -type s 2>/dev/null | wc -l) || varrun_count=0
        varrun_count=$(to_int "$varrun_count")
        if [[ $varrun_count -gt 0 ]]; then
            total=$((total + varrun_count))
            locations="${locations}/var/run:$varrun_count,"
            debug "scan_unix_sockets: found $varrun_count sockets in /var/run"
        fi
    fi

    # Check /private/tmp for sockets
    if [[ -d "/private/tmp" ]]; then
        local privatetmp_count
        privatetmp_count=$(find /private/tmp -type s 2>/dev/null | wc -l) || privatetmp_count=0
        privatetmp_count=$(to_int "$privatetmp_count")
        if [[ $privatetmp_count -gt 0 ]]; then
            total=$((total + privatetmp_count))
            locations="${locations}/private/tmp:$privatetmp_count,"
            debug "scan_unix_sockets: found $privatetmp_count sockets in /private/tmp"
        fi
    fi

    locations="${locations%,}"

    if [[ $total -gt 0 ]]; then
        emit "system_visibility" "unix_sockets" "exposed" "$total/$locations" "medium"
    else
        emit "system_visibility" "unix_sockets" "blocked" "" "medium"
    fi
}

# =============================================================================
# /var/folders Access (Per-user temp dirs, caches)
# Severity: medium (reveals user activity, contains sensitive data)
# =============================================================================
scan_var_folders() {
    debug "scan_var_folders: starting"

    if [[ ! -d "/var/folders" ]]; then
        emit "system_visibility" "var_folders" "not_found" "" "medium"
        return
    fi

    # Check if we can list /var/folders
    local can_list=0
    local can_access_own=0
    local can_access_others=0

    if ls /var/folders >/dev/null 2>&1; then
        can_list=1
        debug "scan_var_folders: can list /var/folders"
    fi

    # Check if we can find our own temp dir
    if [[ -n "${TMPDIR:-}" ]]; then
        if [[ -d "$TMPDIR" && -r "$TMPDIR" ]]; then
            can_access_own=1
            debug "scan_var_folders: can access own TMPDIR"
        fi
    fi

    # Check if we can access other users' temp dirs
    local other_temps
    other_temps=$(find /private/var/folders -maxdepth 4 -type d -name "T" 2>/dev/null | head -5)
    if [[ -n "$other_temps" ]]; then
        local count
        count=$(echo "$other_temps" | wc -l) || count=0
        count=$(to_int "$count")
        if [[ $count -gt 1 ]]; then
            can_access_others=1
            debug "scan_var_folders: can see $count temp dirs"
        fi
    fi

    local details=""
    if [[ $can_list -gt 0 ]]; then
        details="${details}list,"
    fi
    if [[ $can_access_own -gt 0 ]]; then
        details="${details}own,"
    fi
    if [[ $can_access_others -gt 0 ]]; then
        details="${details}others,"
    fi

    details="${details%,}"

    if [[ -n "$details" ]]; then
        emit "system_visibility" "var_folders" "exposed" "$details" "medium"
    else
        emit "system_visibility" "var_folders" "blocked" "" "medium"
    fi
}

# =============================================================================
# Mach IPC / launchctl print
# Severity: high (reveals system services, attack surface)
# =============================================================================
scan_mach_ipc() {
    debug "scan_mach_ipc: starting"

    if ! has_cmd launchctl; then
        emit "system_visibility" "mach_ipc" "error" "no_launchctl" "high"
        return
    fi

    local exposed=0
    local details=""

    # Try launchctl print system (requires privileges on modern macOS)
    local system_output
    system_output=$(with_timeout "$DEFAULT_TIMEOUT" launchctl print system 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$system_output" ]]; then
        # Count services/endpoints visible
        local endpoint_count
        endpoint_count=$(echo "$system_output" | grep -cE 'port|endpoint|service' 2>/dev/null) || endpoint_count=0
        endpoint_count=$(to_int "$endpoint_count")
        if [[ $endpoint_count -gt 0 ]]; then
            exposed=1
            details="${details}system:$endpoint_count,"
            debug "scan_mach_ipc: system domain has $endpoint_count endpoints"
        fi
    fi

    # Try launchctl print user/$(id -u)
    local uid
    uid=$(id -u 2>/dev/null) || uid=""
    if [[ -n "$uid" ]]; then
        local user_output
        user_output=$(with_timeout "$DEFAULT_TIMEOUT" launchctl print "user/$uid" 2>&1)
        if [[ $? -eq 0 && -n "$user_output" ]]; then
            local user_count
            user_count=$(echo "$user_output" | grep -cE 'port|endpoint|service' 2>/dev/null) || user_count=0
            user_count=$(to_int "$user_count")
            if [[ $user_count -gt 0 ]]; then
                exposed=1
                details="${details}user:$user_count,"
                debug "scan_mach_ipc: user domain has $user_count endpoints"
            fi
        fi
    fi

    # Try launchctl list (less detailed but more likely to work)
    local list_output
    list_output=$(with_timeout "$DEFAULT_TIMEOUT" launchctl list 2>&1)
    if [[ $? -eq 0 && -n "$list_output" ]]; then
        local list_count
        list_count=$(echo "$list_output" | wc -l) || list_count=0
        list_count=$(to_int "$list_count")
        if [[ $list_count -gt 1 ]]; then
            exposed=1
            details="${details}list:$((list_count - 1)),"
            debug "scan_mach_ipc: launchctl list shows $((list_count - 1)) services"
        fi
    fi

    details="${details%,}"

    if [[ $exposed -gt 0 ]]; then
        emit "system_visibility" "mach_ipc" "exposed" "$details" "high"
    else
        emit "system_visibility" "mach_ipc" "blocked" "" "high"
    fi
}

# =============================================================================
# XPC Services Enumeration
# Severity: medium (reveals system capabilities, attack surface)
# =============================================================================
scan_xpc_services() {
    debug "scan_xpc_services: starting"

    local total=0
    local locations=""

    # System XPC services
    if [[ -d "/System/Library/XPCServices" ]] && dir_readable "/System/Library/XPCServices"; then
        local sys_count
        sys_count=$(ls -1 /System/Library/XPCServices 2>/dev/null | grep -c "\.xpc$") || sys_count=0
        sys_count=$(to_int "$sys_count")
        if [[ $sys_count -gt 0 ]]; then
            total=$((total + sys_count))
            locations="${locations}system:$sys_count,"
            debug "scan_xpc_services: found $sys_count system XPC services"
        fi
    fi

    # Check app XPC services (reveals installed apps)
    if [[ -d "/Applications" ]]; then
        local app_xpc_count=0
        local app
        for app in /Applications/*.app/Contents/XPCServices; do
            [[ -d "$app" ]] || continue
            if dir_readable "$app"; then
                local count
                count=$(ls -1 "$app" 2>/dev/null | grep -c "\.xpc$") || count=0
                count=$(to_int "$count")
                app_xpc_count=$((app_xpc_count + count))
            fi
        done
        if [[ $app_xpc_count -gt 0 ]]; then
            total=$((total + app_xpc_count))
            locations="${locations}apps:$app_xpc_count,"
            debug "scan_xpc_services: found $app_xpc_count app XPC services"
        fi
    fi

    # PrivilegedHelperTools (elevated helpers)
    if [[ -d "/Library/PrivilegedHelperTools" ]] && dir_readable "/Library/PrivilegedHelperTools"; then
        local helper_count
        helper_count=$(ls -1 /Library/PrivilegedHelperTools 2>/dev/null | wc -l) || helper_count=0
        helper_count=$(to_int "$helper_count")
        if [[ $helper_count -gt 0 ]]; then
            total=$((total + helper_count))
            locations="${locations}helpers:$helper_count,"
            debug "scan_xpc_services: found $helper_count privileged helpers"
        fi
    fi

    locations="${locations%,}"

    if [[ $total -gt 0 ]]; then
        emit "system_visibility" "xpc_services" "exposed" "$total/$locations" "medium"
    else
        emit "system_visibility" "xpc_services" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all IPC mechanism tests
# =============================================================================
run_ipc_tests() {
    debug "run_ipc_tests: starting (darwin)"
    progress_start "ipc"
    scan_shared_memory
    scan_fifo_creation
    scan_unix_sockets
    scan_var_folders
    scan_mach_ipc
    scan_xpc_services
    progress_end "ipc"
    debug "run_ipc_tests: complete"
}
