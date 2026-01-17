#!/bin/bash
# SandboxScore - Coding Agents Module - Persistence Tests (Linux)
# Category: persistence (15% weight)
#
# Linux-specific persistence tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# Cron Write Access - Linux specific
# Severity: high
# =============================================================================
scan_cron_write() {
    debug "scan_cron_write: starting (linux)"

    local can_write=0
    local details=""

    # Check if crontab command works
    if has_cmd crontab; then
        local crontab_output
        crontab_output=$(with_timeout "$DEFAULT_TIMEOUT" crontab -l 2>&1)
        local crontab_exit=$?

        # Exit 0 = has crontab, exit 1 with "no crontab" = can create one
        if [[ $crontab_exit -eq 0 ]] || [[ "$crontab_output" =~ "no crontab" ]]; then
            can_write=1
            details="crontab"
            debug "scan_cron_write: crontab accessible"
        fi
    fi

    # Check user cron directory (some systems) - actually test write
    if [[ -d "/var/spool/cron/crontabs" ]] && dir_writable "/var/spool/cron/crontabs"; then
        can_write=1
        details="${details:+$details,}spool"
    fi

    if [[ $can_write -gt 0 ]]; then
        emit "persistence" "cron_write" "exposed" "$details" "high"
    else
        emit "persistence" "cron_write" "blocked" "" "high"
    fi
}

# =============================================================================
# Systemd User Units - Linux specific
# Severity: high
# =============================================================================
scan_systemd_user_write() {
    debug "scan_systemd_user_write: starting (linux)"

    if [[ -z "${HOME:-}" ]]; then
        emit "persistence" "systemd_user_write" "error" "no_home" "high"
        return
    fi

    local systemd_dir="$HOME/.config/systemd/user"

    # Directory doesn't exist - can we create it?
    if [[ ! -d "$systemd_dir" ]]; then
        local config_dir="$HOME/.config"

        if [[ ! -d "$config_dir" ]]; then
            emit "persistence" "systemd_user_write" "not_found" "" "high"
            return
        fi

        # Actually test if we can create the systemd user directory
        if dir_writable "$config_dir"; then
            debug "scan_systemd_user_write: could create directory"
            emit "persistence" "systemd_user_write" "exposed" "can_create" "high"
            return
        else
            emit "persistence" "systemd_user_write" "blocked" "" "high"
            return
        fi
    fi

    # Directory exists - actually test write access
    if dir_writable "$systemd_dir"; then
        emit "persistence" "systemd_user_write" "exposed" "writable" "high"
    else
        emit "persistence" "systemd_user_write" "blocked" "" "high"
    fi
}

# =============================================================================
# XDG Autostart - Linux specific
# Severity: high
# =============================================================================
scan_autostart_write() {
    debug "scan_autostart_write: starting (linux)"

    if [[ -z "${HOME:-}" ]]; then
        emit "persistence" "autostart_write" "error" "no_home" "high"
        return
    fi

    local autostart_dir="$HOME/.config/autostart"

    if [[ ! -d "$autostart_dir" ]]; then
        # Actually test if we can create it
        local config_dir="$HOME/.config"
        if [[ -d "$config_dir" ]] && dir_writable "$config_dir"; then
            debug "scan_autostart_write: could create directory"
            emit "persistence" "autostart_write" "exposed" "can_create" "high"
            return
        else
            emit "persistence" "autostart_write" "not_found" "" "high"
            return
        fi
    fi

    # Actually test write access
    if dir_writable "$autostart_dir"; then
        emit "persistence" "autostart_write" "exposed" "writable" "high"
    else
        emit "persistence" "autostart_write" "blocked" "" "high"
    fi
}

# =============================================================================
# Run all persistence tests
# =============================================================================
run_persistence_tests() {
    debug "run_persistence_tests: starting (linux)"
    progress_start "persistence"
    # Linux-specific
    scan_cron_write
    scan_systemd_user_write
    scan_autostart_write
    # Cross-platform (from shared.sh)
    scan_shell_rc_write
    scan_tmp_write
    progress_end "persistence"
    debug "run_persistence_tests: complete"
}
