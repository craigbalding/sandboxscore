#!/bin/bash
# SandboxScore - Coding Agents Module - Persistence Tests (macOS)
# Category: persistence (15% weight)
#
# macOS-specific persistence tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# LaunchAgents Write Access - macOS specific
# Severity: high
# =============================================================================
scan_launchagents_write() {
    debug "scan_launchagents_write: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_launchagents_write: HOME not set"
        emit "persistence" "launchagents_write" "error" "no_home" "high"
        return
    fi

    local launchagents_dir="$HOME/Library/LaunchAgents"

    # Check if directory exists
    if [[ ! -d "$launchagents_dir" ]]; then
        debug "scan_launchagents_write: directory does not exist, testing creation"

        local parent_dir="$HOME/Library"
        if [[ ! -d "$parent_dir" ]]; then
            debug "scan_launchagents_write: parent Library dir missing"
            emit "persistence" "launchagents_write" "not_found" "" "high"
            return
        fi

        # Actually test if we can create the directory
        if dir_writable "$parent_dir"; then
            debug "scan_launchagents_write: could create directory (parent writable)"
            emit "persistence" "launchagents_write" "exposed" "can_create_dir" "high"
            return
        else
            debug "scan_launchagents_write: cannot create directory"
            emit "persistence" "launchagents_write" "blocked" "" "high"
            return
        fi
    fi

    # Directory exists - actually test if we can write to it
    if dir_writable "$launchagents_dir"; then
        emit "persistence" "launchagents_write" "exposed" "writable" "high"
    else
        emit "persistence" "launchagents_write" "blocked" "" "high"
    fi
}

# =============================================================================
# Login Items - macOS specific
# Severity: medium
# Detects if we can enumerate background/login items via BTM database
# Note: Avoids osascript which triggers TCC Automation permission prompts
# =============================================================================
scan_login_items() {
    debug "scan_login_items: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "persistence" "login_items" "error" "no_home" "medium"
        return
    fi

    local found=0
    local details=""
    local item_count=0

    # Method 1: Read BTM database directly (macOS 13+)
    # This is the authoritative source for background/login items
    local btm_file="$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
    if [[ -f "$btm_file" ]] && [[ -r "$btm_file" ]]; then
        # Count items by looking for "internalItems" or container objects
        local btm_output
        btm_output=$(plutil -p "$btm_file" 2>/dev/null) || btm_output=""
        if [[ -n "$btm_output" ]]; then
            found=1
            # Count containers (each represents a login item)
            item_count=$(echo "$btm_output" | grep -c '"identifier"') || item_count=0
            item_count=$(to_int "$item_count")
            details="btm:$item_count"
            debug "scan_login_items: BTM readable, $item_count items"
        fi
    fi

    # Method 2: Check if BTM directory is at least listable
    if [[ $found -eq 0 ]]; then
        local btm_dir="$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent"
        if [[ -d "$btm_dir" ]] && dir_readable "$btm_dir"; then
            found=1
            details="btm_dir"
            debug "scan_login_items: BTM directory readable"
        fi
    fi

    # Method 3: Check SharedFileList directory (legacy)
    if [[ $found -eq 0 ]]; then
        local sfl_dir="$HOME/Library/Application Support/com.apple.sharedfilelist"
        if [[ -d "$sfl_dir" ]] && dir_readable "$sfl_dir"; then
            found=1
            details="sharedfilelist"
            debug "scan_login_items: SharedFileList directory readable"
        fi
    fi

    if [[ $found -gt 0 ]]; then
        emit "persistence" "login_items" "exposed" "$details" "medium"
    else
        emit "persistence" "login_items" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all persistence tests
# =============================================================================
run_persistence_tests() {
    debug "run_persistence_tests: starting (darwin)"
    progress_start "persistence"
    # macOS-specific
    scan_launchagents_write
    scan_login_items
    # Cross-platform (from shared.sh)
    scan_shell_rc_write
    scan_tmp_write
    progress_end "persistence"
    debug "run_persistence_tests: complete"
}
