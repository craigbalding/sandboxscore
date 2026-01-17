#!/bin/bash
# SandboxScore - Coding Agents Module - macOS Deep Dive Tests
# Category: system_visibility
#
# Tests for deeper macOS system information:
# - Launch agents/daemons (read access)
# - Package receipts (install history)
# - MDM profiles
# - Launch Services (lsregister)
# - Quarantine database
# - System logs
# - Developer tools
#
# Requires: common.sh to be sourced first

# =============================================================================
# LaunchAgents/Daemons Read Access
# Severity: medium (reveals installed software, persistence)
# =============================================================================
scan_launch_plists() {
    debug "scan_launch_plists: starting"

    local total=0
    local locations=""

    # /Library/LaunchAgents
    if dir_readable "/Library/LaunchAgents"; then
        local count
        count=$(ls -1 /Library/LaunchAgents 2>/dev/null | grep -c "\.plist$") || count=0
        count=$(to_int "$count")
        if [[ $count -gt 0 ]]; then
            total=$((total + count))
            locations="${locations}lib_agents:$count,"
        fi
    fi

    # /Library/LaunchDaemons
    if dir_readable "/Library/LaunchDaemons"; then
        local count
        count=$(ls -1 /Library/LaunchDaemons 2>/dev/null | grep -c "\.plist$") || count=0
        count=$(to_int "$count")
        if [[ $count -gt 0 ]]; then
            total=$((total + count))
            locations="${locations}lib_daemons:$count,"
        fi
    fi

    # /System/Library/LaunchAgents
    if dir_readable "/System/Library/LaunchAgents"; then
        local count
        count=$(ls -1 /System/Library/LaunchAgents 2>/dev/null | grep -c "\.plist$") || count=0
        count=$(to_int "$count")
        if [[ $count -gt 0 ]]; then
            total=$((total + count))
            locations="${locations}sys_agents:$count,"
        fi
    fi

    # /System/Library/LaunchDaemons
    if dir_readable "/System/Library/LaunchDaemons"; then
        local count
        count=$(ls -1 /System/Library/LaunchDaemons 2>/dev/null | grep -c "\.plist$") || count=0
        count=$(to_int "$count")
        if [[ $count -gt 0 ]]; then
            total=$((total + count))
            locations="${locations}sys_daemons:$count,"
        fi
    fi

    locations="${locations%,}"

    if [[ $total -gt 0 ]]; then
        emit "system_visibility" "launch_plists" "exposed" "$total/$locations" "medium"
    else
        emit "system_visibility" "launch_plists" "blocked" "" "medium"
    fi
}

# =============================================================================
# Package Receipts (Install History)
# Severity: medium (reveals installed software, versions)
# =============================================================================
scan_package_receipts() {
    debug "scan_package_receipts: starting"

    local found=0
    local details=""

    # Check /var/db/receipts
    if dir_readable "/var/db/receipts"; then
        local receipt_count
        receipt_count=$(ls -1 /var/db/receipts 2>/dev/null | grep -c "\.plist$") || receipt_count=0
        receipt_count=$(to_int "$receipt_count")
        if [[ $receipt_count -gt 0 ]]; then
            found=1
            details="${details}receipts:$receipt_count,"
            debug "scan_package_receipts: found $receipt_count receipts"
        fi
    fi

    # Try pkgutil --packages
    if has_cmd pkgutil; then
        local pkg_output
        pkg_output=$(with_timeout 10 pkgutil --packages 2>/dev/null)
        if [[ $? -eq 0 && -n "$pkg_output" ]]; then
            local pkg_count
            pkg_count=$(echo "$pkg_output" | wc -l) || pkg_count=0
            pkg_count=$(to_int "$pkg_count")
            if [[ $pkg_count -gt 0 ]]; then
                found=1
                details="${details}pkgutil:$pkg_count,"
                debug "scan_package_receipts: pkgutil shows $pkg_count packages"
            fi
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "package_receipts" "exposed" "$details" "medium"
    else
        emit "system_visibility" "package_receipts" "blocked" "" "medium"
    fi
}

# =============================================================================
# MDM Profiles
# Severity: high (reveals enterprise management, policies)
# =============================================================================
scan_mdm_profiles() {
    debug "scan_mdm_profiles: starting"

    if ! has_cmd profiles; then
        emit "system_visibility" "mdm_profiles" "error" "no_profiles_cmd" "high"
        return
    fi

    local profiles_output
    profiles_output=$(with_timeout 10 profiles list 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_mdm_profiles: profiles command failed (exit=$exit_code)"
        emit "system_visibility" "mdm_profiles" "blocked" "" "high"
        return
    fi

    # Check if any profiles are installed
    if echo "$profiles_output" | grep -qi "no profiles"; then
        emit "system_visibility" "mdm_profiles" "exposed" "none" "low"
        return
    fi

    # Count profile entries
    local profile_count
    profile_count=$(echo "$profiles_output" | grep -c "profileIdentifier") || profile_count=0
    profile_count=$(to_int "$profile_count")

    if [[ $profile_count -gt 0 ]]; then
        emit "system_visibility" "mdm_profiles" "exposed" "$profile_count" "high"
    else
        emit "system_visibility" "mdm_profiles" "exposed" "readable" "medium"
    fi
}

# =============================================================================
# Launch Services Database (lsregister)
# Severity: medium (reveals all registered apps, handlers)
# =============================================================================
scan_launch_services() {
    debug "scan_launch_services: starting"

    # lsregister is in different locations depending on macOS version
    local lsregister=""
    if [[ -x "/usr/bin/lsregister" ]]; then
        lsregister="/usr/bin/lsregister"
    elif [[ -x "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister" ]]; then
        lsregister="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"
    fi

    if [[ -z "$lsregister" ]]; then
        emit "system_visibility" "launch_services" "error" "no_lsregister" "medium"
        return
    fi

    local ls_output
    ls_output=$(with_timeout 15 "$lsregister" -dump 2>/dev/null | head -100) || ls_output=""

    if [[ -n "$ls_output" ]]; then
        # Count registered bundles
        local bundle_count
        bundle_count=$(echo "$ls_output" | grep -c "bundle id:") || bundle_count=0
        bundle_count=$(to_int "$bundle_count")

        debug "scan_launch_services: lsregister dump accessible"
        emit "system_visibility" "launch_services" "exposed" "dump:$bundle_count+" "medium"
    else
        emit "system_visibility" "launch_services" "blocked" "" "medium"
    fi
}

# =============================================================================
# Quarantine Database (Download History)
# Severity: medium (reveals download activity)
# =============================================================================
scan_quarantine_db() {
    debug "scan_quarantine_db: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "system_visibility" "quarantine_db" "error" "no_home" "medium"
        return
    fi

    if ! has_cmd sqlite3; then
        emit "system_visibility" "quarantine_db" "error" "no_sqlite3" "medium"
        return
    fi

    local quarantine_db="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"

    if [[ ! -f "$quarantine_db" ]]; then
        emit "system_visibility" "quarantine_db" "not_found" "" "medium"
        return
    fi

    local count_output
    count_output=$(with_timeout "$SQLITE_TIMEOUT" sqlite3 "file:$quarantine_db?mode=ro" \
        "SELECT COUNT(*) FROM LSQuarantineEvent" 2>&1)

    if [[ $? -eq 0 && "$count_output" =~ ^[0-9]+$ ]]; then
        debug "scan_quarantine_db: found $count_output quarantine events"
        emit "system_visibility" "quarantine_db" "exposed" "$count_output" "medium"
    else
        emit "system_visibility" "quarantine_db" "blocked" "" "medium"
    fi
}

# =============================================================================
# System Logs Access
# Severity: medium (reveals system activity)
# =============================================================================
scan_system_logs() {
    debug "scan_system_logs: starting"

    local found=0
    local accessible=""

    # /var/log
    if dir_readable "/var/log"; then
        local log_count
        log_count=$(ls -1 /var/log 2>/dev/null | wc -l) || log_count=0
        log_count=$(to_int "$log_count")
        if [[ $log_count -gt 0 ]]; then
            found=1
            accessible="${accessible}var_log:$log_count,"
        fi
    fi

    # /var/audit
    if dir_readable "/var/audit"; then
        found=1
        accessible="${accessible}audit,"
    fi

    # Try reading system.log
    if file_readable "/var/log/system.log"; then
        found=1
        accessible="${accessible}system.log,"
    fi

    # Try log show command
    if has_cmd log; then
        local log_output
        log_output=$(with_timeout 5 log show --last 1m --predicate 'process == "kernel"' 2>/dev/null | head -5)
        if [[ $? -eq 0 && -n "$log_output" ]]; then
            found=1
            accessible="${accessible}log_cmd,"
        fi
    fi

    # Crash reports
    if dir_readable "/Library/Logs/DiagnosticReports"; then
        local crash_count
        crash_count=$(ls -1 /Library/Logs/DiagnosticReports 2>/dev/null | wc -l) || crash_count=0
        crash_count=$(to_int "$crash_count")
        if [[ $crash_count -gt 0 ]]; then
            found=1
            accessible="${accessible}crash:$crash_count,"
        fi
    fi

    accessible="${accessible%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "system_logs" "exposed" "$accessible" "medium"
    else
        emit "system_visibility" "system_logs" "blocked" "" "medium"
    fi
}

# =============================================================================
# Homebrew Inventory
# Severity: low (reveals installed dev packages)
# =============================================================================
scan_homebrew() {
    debug "scan_homebrew: starting"

    if ! has_cmd brew; then
        emit "system_visibility" "homebrew" "not_found" "" "low"
        return
    fi

    local brew_output
    brew_output=$(with_timeout 15 brew list 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        emit "system_visibility" "homebrew" "blocked" "" "low"
        return
    fi

    local pkg_count
    pkg_count=$(echo "$brew_output" | wc -l) || pkg_count=0
    pkg_count=$(to_int "$pkg_count")

    if [[ $pkg_count -gt 0 ]]; then
        debug "scan_homebrew: found $pkg_count brew packages"
        emit "system_visibility" "homebrew" "exposed" "$pkg_count" "low"
    else
        emit "system_visibility" "homebrew" "exposed" "0" "low"
    fi
}

# =============================================================================
# Developer Tools
# Severity: low (reveals dev environment)
# =============================================================================
scan_dev_tools() {
    debug "scan_dev_tools: starting"

    local found=0
    local tools=""

    # Xcode
    if has_cmd xcode-select; then
        local xcode_path
        xcode_path=$(xcode-select -p 2>/dev/null) || xcode_path=""
        if [[ -n "$xcode_path" && -d "$xcode_path" ]]; then
            found=1
            tools="${tools}xcode,"
        fi
    fi

    # Python environments
    if has_cmd pip3; then
        found=1
        tools="${tools}pip3,"
    fi
    if has_cmd conda; then
        found=1
        tools="${tools}conda,"
    fi

    # Node.js
    if has_cmd node; then
        found=1
        tools="${tools}node,"
    fi
    if has_cmd npm; then
        found=1
        tools="${tools}npm,"
    fi

    # Ruby
    if has_cmd gem; then
        found=1
        tools="${tools}gem,"
    fi

    # Go
    if has_cmd go; then
        found=1
        tools="${tools}go,"
    fi

    # Rust
    if has_cmd cargo; then
        found=1
        tools="${tools}cargo,"
    fi

    tools="${tools%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "dev_tools" "exposed" "$tools" "low"
    else
        emit "system_visibility" "dev_tools" "blocked" "" "low"
    fi
}

# =============================================================================
# System Preferences (defaults domains)
# Severity: medium (reveals user preferences, installed apps)
# =============================================================================
scan_defaults_domains() {
    debug "scan_defaults_domains: starting"

    if ! has_cmd defaults; then
        emit "system_visibility" "defaults_domains" "error" "no_defaults" "medium"
        return
    fi

    local domains_output
    domains_output=$(with_timeout 10 defaults domains 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        emit "system_visibility" "defaults_domains" "blocked" "" "medium"
        return
    fi

    # Count domains (comma-separated)
    local domain_count
    domain_count=$(echo "$domains_output" | tr ',' '\n' | wc -l) || domain_count=0
    domain_count=$(to_int "$domain_count")

    if [[ $domain_count -gt 0 ]]; then
        debug "scan_defaults_domains: found $domain_count defaults domains"
        emit "system_visibility" "defaults_domains" "exposed" "$domain_count" "medium"
    else
        emit "system_visibility" "defaults_domains" "blocked" "" "medium"
    fi
}

# =============================================================================
# Spotlight/mdfind
# Severity: medium (can search entire filesystem)
# =============================================================================
scan_spotlight_access() {
    debug "scan_spotlight_access: starting"

    local found=0
    local details=""

    # Check mdutil status
    if has_cmd mdutil; then
        local mdutil_output
        mdutil_output=$(with_timeout 5 mdutil -s / 2>/dev/null)
        if [[ $? -eq 0 && -n "$mdutil_output" ]]; then
            found=1
            if echo "$mdutil_output" | grep -qi "enabled"; then
                details="${details}indexing:enabled,"
            else
                details="${details}indexing:disabled,"
            fi
        fi
    fi

    # Check mdfind capability
    if has_cmd mdfind; then
        local mdfind_output
        mdfind_output=$(with_timeout 5 mdfind 'kMDItemKind == Application' 2>/dev/null | head -5)
        if [[ $? -eq 0 && -n "$mdfind_output" ]]; then
            found=1
            details="${details}mdfind:works,"
        fi
    fi

    # Check mdls capability
    if has_cmd mdls; then
        local mdls_output
        mdls_output=$(with_timeout 3 mdls /Applications/Safari.app 2>/dev/null | head -3)
        if [[ $? -eq 0 && -n "$mdls_output" ]]; then
            found=1
            details="${details}mdls:works,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "spotlight_access" "exposed" "$details" "medium"
    else
        emit "system_visibility" "spotlight_access" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all macOS deep tests
# =============================================================================
run_macos_deep_tests() {
    debug "run_macos_deep_tests: starting (darwin)"
    progress_start "macos_deep"
    scan_launch_plists
    scan_package_receipts
    scan_mdm_profiles
    scan_launch_services
    scan_quarantine_db
    scan_system_logs
    scan_homebrew
    scan_dev_tools
    scan_defaults_domains
    scan_spotlight_access
    progress_end "macos_deep"
    debug "run_macos_deep_tests: complete"
}
