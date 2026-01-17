#!/bin/bash
# SandboxScore - Coding Agents Module - Apple Services Tests (macOS)
# Category: system_visibility / personal_data
#
# Tests for Apple service exposure:
# - iCloud account info
# - iCloud Drive paths
# - Time Machine status
# - Spotlight status
# - Location Services
# - Continuity/Handoff
# - Siri preferences
#
# Requires: common.sh to be sourced first

# =============================================================================
# iCloud Account Info
# Severity: high (reveals Apple ID, account status)
# =============================================================================
scan_icloud_account() {
    debug "scan_icloud_account: starting"

    if ! has_cmd defaults; then
        emit "personal_data" "icloud_account" "error" "no_defaults" "high"
        return
    fi

    local found=0
    local details=""

    # Check MobileMeAccounts
    local mobileme_output
    mobileme_output=$(with_timeout 5 defaults read MobileMeAccounts 2>/dev/null)
    if [[ $? -eq 0 && -n "$mobileme_output" ]]; then
        found=1
        details="${details}mobileme,"
        debug "scan_icloud_account: MobileMeAccounts readable"
    fi

    # Check AppleID preferences
    local appleid_output
    appleid_output=$(with_timeout 5 defaults read com.apple.preferences.AppleID 2>/dev/null)
    if [[ $? -eq 0 && -n "$appleid_output" ]]; then
        found=1
        details="${details}appleid,"
        debug "scan_icloud_account: AppleID prefs readable"
    fi

    # Check iCloud preferences
    local icloud_output
    icloud_output=$(with_timeout 5 defaults read com.apple.icloud 2>/dev/null)
    if [[ $? -eq 0 && -n "$icloud_output" ]]; then
        found=1
        details="${details}icloud,"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "personal_data" "icloud_account" "exposed" "$details" "high"
    else
        emit "personal_data" "icloud_account" "blocked" "" "high"
    fi
}

# =============================================================================
# iCloud Drive Paths
# Severity: medium (reveals iCloud Drive structure, synced files)
# =============================================================================
scan_icloud_drive() {
    debug "scan_icloud_drive: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "icloud_drive" "error" "no_home" "medium"
        return
    fi

    local found=0
    local details=""

    # User's iCloud Drive
    local icloud_drive="$HOME/Library/Mobile Documents/com~apple~CloudDocs"
    if [[ -d "$icloud_drive" ]] && dir_readable "$icloud_drive"; then
        local item_count
        item_count=$(ls -1 "$icloud_drive" 2>/dev/null | wc -l) || item_count=0
        item_count=$(to_int "$item_count")
        if [[ $item_count -gt 0 ]]; then
            found=1
            details="${details}drive:$item_count,"
            debug "scan_icloud_drive: iCloud Drive has $item_count items"
        fi
    fi

    # Check Mobile Documents for app containers
    local mobile_docs="$HOME/Library/Mobile Documents"
    if [[ -d "$mobile_docs" ]] && dir_readable "$mobile_docs"; then
        local container_count
        container_count=$(ls -1 "$mobile_docs" 2>/dev/null | grep -c "com~") || container_count=0
        container_count=$(to_int "$container_count")
        if [[ $container_count -gt 0 ]]; then
            found=1
            details="${details}containers:$container_count,"
        fi
    fi

    # Check system iCloud support
    if [[ -d "/Library/Application Support/iCloud" ]] && dir_readable "/Library/Application Support/iCloud"; then
        found=1
        details="${details}system,"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "personal_data" "icloud_drive" "exposed" "$details" "medium"
    else
        emit "personal_data" "icloud_drive" "blocked" "" "medium"
    fi
}

# =============================================================================
# Time Machine Status
# Severity: medium (reveals backup info, destinations)
# =============================================================================
scan_time_machine() {
    debug "scan_time_machine: starting"

    if ! has_cmd tmutil; then
        emit "system_visibility" "time_machine" "error" "no_tmutil" "medium"
        return
    fi

    local found=0
    local details=""

    # Check tmutil status
    local status_output
    status_output=$(with_timeout 5 tmutil status 2>/dev/null)
    if [[ $? -eq 0 && -n "$status_output" ]]; then
        found=1
        if echo "$status_output" | grep -qi "Running = 1"; then
            details="${details}running,"
        else
            details="${details}idle,"
        fi
    fi

    # Check destination info
    local dest_output
    dest_output=$(with_timeout 5 tmutil destinationinfo 2>&1)
    if [[ $? -eq 0 && -n "$dest_output" ]]; then
        if ! echo "$dest_output" | grep -qi "no destinations"; then
            found=1
            details="${details}destinations,"
        fi
    fi

    # Check for backup list
    local backup_output
    backup_output=$(with_timeout 5 tmutil listbackups 2>&1 | head -3)
    if [[ $? -eq 0 && -n "$backup_output" ]] && ! echo "$backup_output" | grep -qi "error\|no backups"; then
        found=1
        details="${details}backups,"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "time_machine" "exposed" "$details" "medium"
    else
        emit "system_visibility" "time_machine" "blocked" "" "medium"
    fi
}

# =============================================================================
# Location Services Status
# Severity: medium (reveals location tracking state)
# =============================================================================
scan_location_services() {
    debug "scan_location_services: starting"

    local found=0
    local details=""

    # Check if locationd is running
    if pgrep -q "locationd" 2>/dev/null; then
        found=1
        details="${details}locationd,"
        debug "scan_location_services: locationd running"
    fi

    # Check CoreLocationAgent
    if pgrep -q "CoreLocationAgent" 2>/dev/null; then
        found=1
        details="${details}agent,"
    fi

    # Try to read location preferences
    if has_cmd defaults; then
        local loc_prefs
        loc_prefs=$(with_timeout 5 defaults read com.apple.locationd 2>/dev/null)
        if [[ $? -eq 0 && -n "$loc_prefs" ]]; then
            found=1
            details="${details}prefs,"
        fi
    fi

    # Check location clients database
    local clients_db="/var/db/locationd/clients.plist"
    if file_readable "$clients_db"; then
        found=1
        details="${details}clients_db,"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "location_services" "exposed" "$details" "medium"
    else
        emit "system_visibility" "location_services" "blocked" "" "medium"
    fi
}

# =============================================================================
# Continuity/Handoff Services
# Severity: low (reveals inter-device connectivity)
# =============================================================================
scan_continuity_services() {
    debug "scan_continuity_services: starting"

    local found=0
    local services=""

    # sharingd (handles Handoff, AirDrop)
    if pgrep -q "sharingd" 2>/dev/null; then
        found=1
        services="${services}sharingd,"
        debug "scan_continuity_services: sharingd running"
    fi

    # identityservicesd (iCloud identity)
    if pgrep -q "identityservicesd" 2>/dev/null; then
        found=1
        services="${services}identityservicesd,"
    fi

    # airportd (WiFi/AirDrop)
    if pgrep -q "airportd" 2>/dev/null; then
        found=1
        services="${services}airportd,"
    fi

    # bluetoothd
    if pgrep -q "bluetoothd" 2>/dev/null; then
        found=1
        services="${services}bluetoothd,"
    fi

    # rapportd (device communication)
    if pgrep -q "rapportd" 2>/dev/null; then
        found=1
        services="${services}rapportd,"
    fi

    services="${services%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "continuity_services" "exposed" "$services" "low"
    else
        emit "system_visibility" "continuity_services" "blocked" "" "low"
    fi
}

# =============================================================================
# Siri Preferences
# Severity: low (reveals assistant settings)
# =============================================================================
scan_siri_prefs() {
    debug "scan_siri_prefs: starting"

    if ! has_cmd defaults; then
        emit "system_visibility" "siri_prefs" "error" "no_defaults" "low"
        return
    fi

    local siri_output
    siri_output=$(with_timeout 5 defaults read com.apple.Siri 2>/dev/null)

    if [[ $? -eq 0 && -n "$siri_output" ]]; then
        local enabled=""
        if echo "$siri_output" | grep -qi "StatusMenuVisible = 1\|SiriEnabled = 1"; then
            enabled="enabled"
        else
            enabled="disabled"
        fi
        emit "system_visibility" "siri_prefs" "exposed" "$enabled" "low"
    else
        emit "system_visibility" "siri_prefs" "blocked" "" "low"
    fi
}

# =============================================================================
# Spotlight Metadata Database
# Severity: medium (reveals indexed file metadata)
# =============================================================================
scan_spotlight_metadata() {
    debug "scan_spotlight_metadata: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "spotlight_metadata" "error" "no_home" "medium"
        return
    fi

    local found=0
    local details=""

    # CoreSpotlight user database
    local spotlight_db="$HOME/Library/Metadata/CoreSpotlight"
    if [[ -d "$spotlight_db" ]] && dir_readable "$spotlight_db"; then
        found=1
        details="${details}corespotlight,"
        debug "scan_spotlight_metadata: CoreSpotlight accessible"
    fi

    # Spotlight-V100 on main drive
    if [[ -d "/.Spotlight-V100" ]]; then
        if dir_readable "/.Spotlight-V100"; then
            found=1
            details="${details}spotlight-v100,"
        fi
    fi

    # mds stores
    if [[ -d "/var/db/Spotlight" ]] && dir_readable "/var/db/Spotlight"; then
        found=1
        details="${details}mds,"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "personal_data" "spotlight_metadata" "exposed" "$details" "medium"
    else
        emit "personal_data" "spotlight_metadata" "blocked" "" "medium"
    fi
}

# =============================================================================
# Power Management (pmset)
# Severity: info (reveals power settings, battery)
# =============================================================================
scan_power_management() {
    debug "scan_power_management: starting"

    if ! has_cmd pmset; then
        emit "system_visibility" "power_management" "error" "no_pmset" "info"
        return
    fi

    local pmset_output
    pmset_output=$(with_timeout 5 pmset -g 2>/dev/null)

    if [[ $? -eq 0 && -n "$pmset_output" ]]; then
        debug "scan_power_management: pmset accessible"
        emit "system_visibility" "power_management" "exposed" "" "info"
    else
        emit "system_visibility" "power_management" "blocked" "" "info"
    fi
}

# =============================================================================
# NVRAM (Firmware Variables)
# Severity: medium (reveals boot configuration, sometimes secrets)
# =============================================================================
scan_nvram() {
    debug "scan_nvram: starting"

    if ! has_cmd nvram; then
        emit "system_visibility" "nvram" "error" "no_nvram" "medium"
        return
    fi

    local nvram_output
    nvram_output=$(with_timeout 5 nvram -p 2>/dev/null | head -10)

    if [[ $? -eq 0 && -n "$nvram_output" ]]; then
        local var_count
        var_count=$(echo "$nvram_output" | wc -l) || var_count=0
        var_count=$(to_int "$var_count")
        debug "scan_nvram: nvram has $var_count visible variables"
        emit "system_visibility" "nvram" "exposed" "$var_count+" "medium"
    else
        emit "system_visibility" "nvram" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all Apple services tests
# =============================================================================
run_apple_services_tests() {
    debug "run_apple_services_tests: starting (darwin)"
    progress_start "apple_services"
    scan_icloud_account
    scan_icloud_drive
    scan_time_machine
    scan_location_services
    scan_continuity_services
    scan_siri_prefs
    scan_spotlight_metadata
    scan_power_management
    scan_nvram
    progress_end "apple_services"
    debug "run_apple_services_tests: complete"
}
