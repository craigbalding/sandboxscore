#!/bin/bash
# SandboxScore - Coding Agents Module - Clipboard/Screen Tests (macOS)
# Category: personal_data / system_visibility
#
# Tests for clipboard and screen access:
# - Clipboard write (pbcopy)
# - Screen capture
# - Window/app listing
# - Display information
#
# Note: Clipboard read (pbpaste) is tested in personal_data.sh
#
# Requires: common.sh to be sourced first

# =============================================================================
# Clipboard Write Access (pbcopy)
# Severity: medium (can inject data into clipboard)
# =============================================================================
scan_clipboard_write() {
    debug "scan_clipboard_write: starting"

    if ! has_cmd pbcopy; then
        emit "system_visibility" "clipboard_write" "error" "no_pbcopy" "medium"
        return
    fi

    # Try to write to clipboard (use innocuous test string)
    local test_result
    test_result=$(echo "sandboxscore_test" | pbcopy 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        debug "scan_clipboard_write: pbcopy works"
        emit "system_visibility" "clipboard_write" "exposed" "" "medium"
    else
        debug "scan_clipboard_write: pbcopy failed"
        emit "system_visibility" "clipboard_write" "blocked" "" "medium"
    fi
}

# =============================================================================
# Screen Capture
# Severity: high (can capture sensitive information)
# =============================================================================
scan_screen_capture() {
    debug "scan_screen_capture: starting"

    if ! has_cmd screencapture; then
        emit "system_visibility" "screen_capture" "error" "no_screencapture" "high"
        return
    fi

    local tmp_dir="${TMPDIR:-/tmp}"
    local test_file="$tmp_dir/.sandboxscore_screen_$$"

    # Try to capture screen (use -x for silent mode)
    local capture_result
    capture_result=$(with_timeout 5 screencapture -x "$test_file" 2>&1)
    local exit_code=$?

    # Check if file was created
    if [[ -f "$test_file" ]]; then
        local file_size
        file_size=$(stat -f%z "$test_file" 2>/dev/null) || file_size=0
        rm -f "$test_file" 2>/dev/null

        if [[ "$file_size" -gt 0 ]]; then
            debug "scan_screen_capture: screencapture works (${file_size} bytes)"
            emit "system_visibility" "screen_capture" "exposed" "" "high"
            return
        fi
    fi

    # Clean up just in case
    rm -f "$test_file" 2>/dev/null

    # Check if it's a TCC denial
    if echo "$capture_result" | grep -qi "not permitted\|denied\|privacy"; then
        debug "scan_screen_capture: TCC denied"
        emit "system_visibility" "screen_capture" "blocked" "tcc_denied" "high"
    else
        debug "scan_screen_capture: screencapture failed"
        emit "system_visibility" "screen_capture" "blocked" "" "high"
    fi
}

# =============================================================================
# Window/App Listing via lsappinfo
# Severity: medium (reveals running applications)
# =============================================================================
scan_window_list_lsappinfo() {
    debug "scan_window_list_lsappinfo: starting"

    if ! has_cmd lsappinfo; then
        emit "system_visibility" "window_list_lsappinfo" "not_found" "" "medium"
        return
    fi

    local lsappinfo_output
    lsappinfo_output=$(with_timeout 5 lsappinfo list 2>/dev/null)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$lsappinfo_output" ]]; then
        # Count applications
        local app_count
        app_count=$(echo "$lsappinfo_output" | grep -c '"ASN:') || app_count=0
        app_count=$(to_int "$app_count")

        debug "scan_window_list_lsappinfo: found $app_count apps"
        emit "system_visibility" "window_list_lsappinfo" "exposed" "$app_count" "medium"
    else
        emit "system_visibility" "window_list_lsappinfo" "blocked" "" "medium"
    fi
}

# =============================================================================
# Login/Background Items Manager
# Severity: medium (reveals startup items)
# =============================================================================
scan_login_items_btm() {
    debug "scan_login_items_btm: starting"

    if ! has_cmd sfltool; then
        emit "system_visibility" "login_items_btm" "not_found" "" "medium"
        return
    fi

    # Try sfltool dumpbtm (Background Task Management)
    local btm_output
    btm_output=$(with_timeout 10 sfltool dumpbtm 2>&1)
    local exit_code=$?

    if [[ $exit_code -eq 0 && -n "$btm_output" ]]; then
        # Count items
        local item_count
        item_count=$(echo "$btm_output" | grep -c "identifier\|bundle") || item_count=0
        item_count=$(to_int "$item_count")

        debug "scan_login_items_btm: found $item_count background items"
        emit "system_visibility" "login_items_btm" "exposed" "$item_count" "medium"
    else
        emit "system_visibility" "login_items_btm" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all clipboard/screen tests
# =============================================================================
run_clipboard_screen_tests() {
    debug "run_clipboard_screen_tests: starting (darwin)"
    progress_start "clipboard"
    scan_clipboard_write
    scan_screen_capture
    scan_window_list_lsappinfo
    scan_login_items_btm
    progress_end "clipboard"
    debug "run_clipboard_screen_tests: complete"
}
