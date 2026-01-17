#!/bin/bash
# SandboxScore - Coding Agents Module - Security State Tests (macOS)
# Category: system_visibility
#
# Tests for security configuration exposure:
# - System Integrity Protection (SIP)
# - Gatekeeper status
# - Application Firewall
# - Kernel/System extensions
# - TCC (Transparency, Consent, Control) database
# - Authorization database
#
# Requires: common.sh to be sourced first

# =============================================================================
# SIP (System Integrity Protection) Status
# Severity: medium (reveals security posture)
# =============================================================================
scan_sip_status() {
    debug "scan_sip_status: starting"

    if ! has_cmd csrutil; then
        emit "system_visibility" "sip_status" "error" "no_csrutil" "medium"
        return
    fi

    local sip_output
    sip_output=$(with_timeout "$DEFAULT_TIMEOUT" csrutil status 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_sip_status: csrutil failed (exit=$exit_code)"
        emit "system_visibility" "sip_status" "blocked" "" "medium"
        return
    fi

    local status=""
    if echo "$sip_output" | grep -qi "enabled"; then
        status="enabled"
    elif echo "$sip_output" | grep -qi "disabled"; then
        status="disabled"
    else
        status="unknown"
    fi

    debug "scan_sip_status: SIP is $status"
    emit "system_visibility" "sip_status" "exposed" "$status" "medium"
}

# =============================================================================
# Gatekeeper Status
# Severity: medium (reveals app signing enforcement)
# =============================================================================
scan_gatekeeper_status() {
    debug "scan_gatekeeper_status: starting"

    if ! has_cmd spctl; then
        emit "system_visibility" "gatekeeper_status" "error" "no_spctl" "medium"
        return
    fi

    local spctl_output
    spctl_output=$(with_timeout "$DEFAULT_TIMEOUT" spctl --status 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_gatekeeper_status: spctl failed (exit=$exit_code)"
        emit "system_visibility" "gatekeeper_status" "blocked" "" "medium"
        return
    fi

    local status=""
    if echo "$spctl_output" | grep -qi "assessments enabled"; then
        status="enabled"
    elif echo "$spctl_output" | grep -qi "assessments disabled"; then
        status="disabled"
    else
        status="unknown"
    fi

    debug "scan_gatekeeper_status: Gatekeeper is $status"
    emit "system_visibility" "gatekeeper_status" "exposed" "$status" "medium"
}

# =============================================================================
# Application Firewall Status
# Severity: medium (reveals network security posture)
# =============================================================================
scan_firewall_status() {
    debug "scan_firewall_status: starting"

    local fw_cmd="/usr/libexec/ApplicationFirewall/socketfilterfw"

    if [[ ! -x "$fw_cmd" ]]; then
        emit "system_visibility" "firewall_status" "error" "no_socketfilterfw" "medium"
        return
    fi

    local fw_output
    fw_output=$(with_timeout "$DEFAULT_TIMEOUT" "$fw_cmd" --getglobalstate 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_firewall_status: socketfilterfw failed (exit=$exit_code)"
        emit "system_visibility" "firewall_status" "blocked" "" "medium"
        return
    fi

    local status=""
    local details=""

    if echo "$fw_output" | grep -qi "enabled"; then
        status="enabled"
    elif echo "$fw_output" | grep -qi "disabled"; then
        status="disabled"
    else
        status="unknown"
    fi

    # Try to get list of allowed apps (reveals installed apps)
    local apps_output
    apps_output=$(with_timeout "$DEFAULT_TIMEOUT" "$fw_cmd" --listapps 2>&1)
    if [[ $? -eq 0 && -n "$apps_output" ]]; then
        local app_count
        app_count=$(echo "$apps_output" | grep -c "ALF") || app_count=0
        app_count=$(to_int "$app_count")
        if [[ $app_count -gt 0 ]]; then
            details="${status}/${app_count}apps"
        else
            details="$status"
        fi
    else
        details="$status"
    fi

    debug "scan_firewall_status: Firewall is $details"
    emit "system_visibility" "firewall_status" "exposed" "$details" "medium"
}

# =============================================================================
# Kernel Extensions (kextstat)
# Severity: high (reveals security software, drivers)
# =============================================================================
scan_kernel_extensions() {
    debug "scan_kernel_extensions: starting"

    if ! has_cmd kextstat; then
        emit "system_visibility" "kernel_extensions" "error" "no_kextstat" "high"
        return
    fi

    local kext_output
    kext_output=$(with_timeout "$DEFAULT_TIMEOUT" kextstat 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_kernel_extensions: kextstat failed (exit=$exit_code)"
        emit "system_visibility" "kernel_extensions" "blocked" "" "high"
        return
    fi

    # Count loaded kexts (subtract header line)
    local count
    count=$(echo "$kext_output" | wc -l) || count=0
    count=$(to_int "$count")
    if [[ $count -gt 1 ]]; then
        count=$((count - 1))
    fi

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "kernel_extensions" "exposed" "$count" "high"
    else
        emit "system_visibility" "kernel_extensions" "blocked" "" "high"
    fi
}

# =============================================================================
# System Extensions (modern replacement for kexts)
# Severity: high (reveals security software, network filters)
# =============================================================================
scan_system_extensions() {
    debug "scan_system_extensions: starting"

    if ! has_cmd systemextensionsctl; then
        # Not an error - older macOS versions don't have this
        emit "system_visibility" "system_extensions" "not_found" "" "high"
        return
    fi

    local ext_output
    ext_output=$(with_timeout "$DEFAULT_TIMEOUT" systemextensionsctl list 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_system_extensions: systemextensionsctl failed (exit=$exit_code)"
        emit "system_visibility" "system_extensions" "blocked" "" "high"
        return
    fi

    # Count extensions (look for lines with bundle IDs)
    local count
    count=$(echo "$ext_output" | grep -c '\.') || count=0
    count=$(to_int "$count")

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "system_extensions" "exposed" "$count" "high"
    else
        emit "system_visibility" "system_extensions" "blocked" "" "high"
    fi
}

# =============================================================================
# TCC Database (Privacy Permissions)
# Severity: high (reveals what apps have sensitive permissions)
# =============================================================================
scan_tcc_database() {
    debug "scan_tcc_database: starting"

    if ! has_cmd sqlite3; then
        emit "system_visibility" "tcc_database" "error" "no_sqlite3" "high"
        return
    fi

    local found=0
    local sources=""

    # System TCC database
    local system_tcc="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "$system_tcc" ]]; then
        local sys_output
        sys_output=$(with_timeout "$SQLITE_TIMEOUT" sqlite3 "file:$system_tcc?mode=ro" \
            "SELECT COUNT(*) FROM access" 2>&1)
        if [[ $? -eq 0 && "$sys_output" =~ ^[0-9]+$ ]]; then
            found=1
            sources="${sources}system:$sys_output,"
            debug "scan_tcc_database: system TCC has $sys_output entries"
        fi
    fi

    # User TCC database
    if [[ -n "${HOME:-}" ]]; then
        local user_tcc="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
        if [[ -f "$user_tcc" ]]; then
            local user_output
            user_output=$(with_timeout "$SQLITE_TIMEOUT" sqlite3 "file:$user_tcc?mode=ro" \
                "SELECT COUNT(*) FROM access" 2>&1)
            if [[ $? -eq 0 && "$user_output" =~ ^[0-9]+$ ]]; then
                found=1
                sources="${sources}user:$user_output,"
                debug "scan_tcc_database: user TCC has $user_output entries"
            fi
        fi
    fi

    sources="${sources%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "tcc_database" "exposed" "$sources" "high"
    else
        emit "system_visibility" "tcc_database" "blocked" "" "high"
    fi
}

# =============================================================================
# Sudo Access (privilege escalation potential)
# Severity: high (reveals if agent can elevate)
# =============================================================================
scan_sudo_access() {
    debug "scan_sudo_access: starting"

    if ! has_cmd sudo; then
        emit "system_visibility" "sudo_access" "not_found" "" "high"
        return
    fi

    # Check if sudoers file is readable
    local sudoers_readable=0
    if [[ -r "/etc/sudoers" ]]; then
        sudoers_readable=1
        debug "scan_sudo_access: /etc/sudoers is readable"
    fi

    # Try sudo -l (will fail if password required, but reveals config)
    local sudo_output
    sudo_output=$(with_timeout 3 sudo -n -l 2>&1)
    local exit_code=$?

    local can_sudo=0
    local details=""

    if [[ $exit_code -eq 0 ]]; then
        can_sudo=1
        details="passwordless"
        debug "scan_sudo_access: passwordless sudo available"
    elif echo "$sudo_output" | grep -qi "NOPASSWD"; then
        can_sudo=1
        details="nopasswd_rules"
    fi

    if [[ $sudoers_readable -gt 0 ]]; then
        details="${details:+$details,}sudoers_readable"
    fi

    if [[ $can_sudo -gt 0 ]]; then
        emit "system_visibility" "sudo_access" "exposed" "$details" "high"
    elif [[ -n "$details" ]]; then
        emit "system_visibility" "sudo_access" "exposed" "$details" "medium"
    else
        emit "system_visibility" "sudo_access" "blocked" "" "high"
    fi
}

# =============================================================================
# Authorization Database
# Severity: medium (reveals auth policies)
# =============================================================================
scan_authorization_db() {
    debug "scan_authorization_db: starting"

    if ! has_cmd security; then
        emit "system_visibility" "authorization_db" "error" "no_security" "medium"
        return
    fi

    # Try to read a common authorization right
    local auth_output
    auth_output=$(with_timeout "$DEFAULT_TIMEOUT" security authorizationdb read system.login.console 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$auth_output" ]]; then
        debug "scan_authorization_db: authorizationdb readable"
        emit "system_visibility" "authorization_db" "exposed" "" "medium"
    else
        emit "system_visibility" "authorization_db" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all security state tests
# =============================================================================
run_security_state_tests() {
    debug "run_security_state_tests: starting (darwin)"
    progress_start "security"
    scan_sip_status
    scan_gatekeeper_status
    scan_firewall_status
    scan_kernel_extensions
    scan_system_extensions
    scan_tcc_database
    scan_sudo_access
    scan_authorization_db
    progress_end "security"
    debug "run_security_state_tests: complete"
}
