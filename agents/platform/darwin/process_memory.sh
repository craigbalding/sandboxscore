#!/bin/bash
# SandboxScore - Coding Agents Module - Process/Memory Tests (macOS)
# Category: system_visibility
#
# Tests for process inspection and device access:
# - Process environment
# - Process memory (vmmap)
# - Memory statistics
# - Device access (/dev)
# - PTY access
#
# Requires: common.sh to be sourced first

# =============================================================================
# Process Environment Visibility
# Severity: high (process env often contains secrets)
# =============================================================================
scan_process_environment() {
    debug "scan_process_environment: starting"

    if ! has_cmd ps; then
        emit "system_visibility" "process_environment" "error" "no_ps" "high"
        return
    fi

    # Try ps auxe (shows environment)
    local ps_output
    ps_output=$(with_timeout "$DEFAULT_TIMEOUT" ps auxe 2>&1 | head -20)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$ps_output" ]]; then
        # Check if we can see environment variables
        if echo "$ps_output" | grep -q "="; then
            debug "scan_process_environment: process environments visible"
            emit "system_visibility" "process_environment" "exposed" "" "high"
            return
        fi
    fi

    # Fallback: check if we can read /proc-style info (not available on macOS, but check)
    emit "system_visibility" "process_environment" "blocked" "" "high"
}

# =============================================================================
# Process Tree
# Severity: medium (reveals process hierarchy)
# =============================================================================
scan_process_tree() {
    debug "scan_process_tree: starting"

    local found=0
    local details=""

    # Try pstree
    if has_cmd pstree; then
        local pstree_output
        pstree_output=$(with_timeout 5 pstree 2>/dev/null | head -30)
        if [[ $? -eq 0 && -n "$pstree_output" ]]; then
            found=1
            details="${details}pstree,"
        fi
    fi

    # Fallback to ps with parent info
    if has_cmd ps; then
        local ps_output
        ps_output=$(with_timeout 5 ps -axo ppid,pid,comm 2>/dev/null | head -30)
        if [[ $? -eq 0 && -n "$ps_output" ]]; then
            found=1
            local proc_count
            proc_count=$(echo "$ps_output" | wc -l) || proc_count=0
            proc_count=$(to_int "$proc_count")
            details="${details}ps:$proc_count,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "process_tree" "exposed" "$details" "medium"
    else
        emit "system_visibility" "process_tree" "blocked" "" "medium"
    fi
}

# =============================================================================
# Process Memory Access (vmmap)
# Severity: high (can reveal process internals)
# =============================================================================
scan_vmmap_access() {
    debug "scan_vmmap_access: starting"

    if ! has_cmd vmmap; then
        emit "system_visibility" "vmmap_access" "not_found" "" "high"
        return
    fi

    # Try vmmap on self
    local vmmap_output
    vmmap_output=$(with_timeout 10 vmmap $$ 2>&1 | head -30)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$vmmap_output" ]]; then
        # Check if we got actual memory map data
        if echo "$vmmap_output" | grep -qE "MALLOC|REGION|__TEXT"; then
            debug "scan_vmmap_access: vmmap works on self"
            emit "system_visibility" "vmmap_access" "exposed" "self" "high"
            return
        fi
    fi

    # Check if blocked due to SIP/debugging restrictions
    if echo "$vmmap_output" | grep -qi "not permitted\|denied"; then
        emit "system_visibility" "vmmap_access" "blocked" "sip" "high"
    else
        emit "system_visibility" "vmmap_access" "blocked" "" "high"
    fi
}

# =============================================================================
# Memory Statistics
# Severity: low (system memory info)
# =============================================================================
scan_memory_stats() {
    debug "scan_memory_stats: starting"

    local found=0
    local details=""

    # vm_stat
    if has_cmd vm_stat; then
        local vmstat_output
        vmstat_output=$(with_timeout 3 vm_stat 2>/dev/null)
        if [[ $? -eq 0 && -n "$vmstat_output" ]]; then
            found=1
            details="${details}vm_stat,"
        fi
    fi

    # memory_pressure
    if has_cmd memory_pressure; then
        local mp_output
        mp_output=$(with_timeout 3 memory_pressure 2>/dev/null)
        if [[ $? -eq 0 && -n "$mp_output" ]]; then
            found=1
            details="${details}memory_pressure,"
        fi
    fi

    # top snapshot
    if has_cmd top; then
        local top_output
        top_output=$(with_timeout 5 top -l 1 -n 5 2>/dev/null | tail -10)
        if [[ $? -eq 0 && -n "$top_output" ]]; then
            found=1
            details="${details}top,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "memory_stats" "exposed" "$details" "low"
    else
        emit "system_visibility" "memory_stats" "blocked" "" "low"
    fi
}

# =============================================================================
# Device Access (/dev) - PTY Security Check
# Severity: medium (output injection to other terminals)
# =============================================================================
scan_dev_access() {
    debug "scan_dev_access: starting"

    local details=""

    # Check /dev is readable
    if ! dir_readable "/dev"; then
        emit "system_visibility" "dev_access" "blocked" "" "medium"
        return
    fi

    # Count active terminal sessions (ttys00X owned by users, not root)
    # These are real login sessions, not the pre-allocated ttyp*/ttys0-f
    local active_ttys=0
    local our_tty=""
    our_tty=$(tty 2>/dev/null | sed 's|.*/||') || our_tty=""

    # shellcheck disable=SC2012 - ls needed for ownership check
    active_ttys=$(ls -la /dev/ttys0[0-9][0-9] 2>/dev/null | grep -v "^total" | grep -cv "root" 2>/dev/null) || active_ttys=0
    active_ttys=$(to_int "$active_ttys")

    if [[ $active_ttys -gt 0 ]]; then
        details="sessions:$active_ttys"
    fi

    # Check if we can write to OTHER PTYs (output injection risk)
    local can_write_others=0
    for pty in /dev/ttys0[0-9][0-9]; do
        [[ -e "$pty" ]] || continue
        local pty_name="${pty##*/}"
        # Skip our own terminal
        [[ "$pty_name" == "$our_tty" ]] && continue
        # Check if writable and not owned by root
        if [[ -w "$pty" ]]; then
            can_write_others=1
            break
        fi
    done

    if [[ $can_write_others -eq 1 ]]; then
        details="${details:+$details,}pty_write:yes"
        emit "system_visibility" "dev_access" "exposed" "$details" "medium"
    elif [[ $active_ttys -gt 0 ]]; then
        details="${details:+$details,}pty_write:no"
        emit "system_visibility" "dev_access" "partial" "$details" "medium"
    else
        emit "system_visibility" "dev_access" "blocked" "" "medium"
    fi
}

# =============================================================================
# lsof All Processes
# Severity: medium (reveals open files across system)
# =============================================================================
scan_lsof_all() {
    debug "scan_lsof_all: starting"

    if ! has_cmd lsof; then
        emit "system_visibility" "lsof_all" "error" "no_lsof" "medium"
        return
    fi

    # Check if we can see OTHER processes' open files (the security concern)
    # Use head to limit output and timeout to bound execution time
    local lsof_output
    lsof_output=$(with_timeout 10 lsof 2>/dev/null | head -100)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$lsof_output" ]]; then
        # Count unique PIDs to see how many processes we can observe
        local pid_count
        pid_count=$(echo "$lsof_output" | awk 'NR>1 {print $2}' | sort -u | wc -l) || pid_count=0
        pid_count=$(to_int "$pid_count")

        if [[ $pid_count -gt 1 ]]; then
            debug "scan_lsof_all: can see $pid_count processes"
            emit "system_visibility" "lsof_all" "exposed" "pids:$pid_count" "medium"
            return
        elif [[ $pid_count -eq 1 ]]; then
            debug "scan_lsof_all: can only see own process"
            emit "system_visibility" "lsof_all" "partial" "self_only" "medium"
            return
        fi
    fi

    emit "system_visibility" "lsof_all" "blocked" "" "medium"
}

# =============================================================================
# Run all process/memory tests
# =============================================================================
run_process_memory_tests() {
    debug "run_process_memory_tests: starting (darwin)"
    progress_start "process"
    scan_process_environment
    scan_process_tree
    scan_vmmap_access
    scan_memory_stats
    scan_dev_access
    scan_lsof_all
    progress_end "process"
    debug "run_process_memory_tests: complete"
}
