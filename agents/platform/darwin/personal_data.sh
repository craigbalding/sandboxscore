#!/bin/bash
# SandboxScore - Coding Agents Module - Personal Data Tests (macOS)
# Category: personal_data (25% weight)
#
# macOS-specific personal data tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# Helper: Run sqlite query safely (macOS-specific paths)
# =============================================================================
safe_sqlite_query() {
    local db="$1"
    local query="$2"
    local result=""

    if ! has_cmd sqlite3; then
        debug "safe_sqlite_query: sqlite3 not found"
        echo ""
        return 1
    fi

    if [[ ! -f "$db" || ! -r "$db" ]]; then
        debug "safe_sqlite_query: db not readable: $db"
        echo ""
        return 1
    fi

    result=$(with_timeout "$SQLITE_TIMEOUT" sqlite3 -bail -readonly "$db" "$query" 2>/dev/null) || result=""
    echo "$result"
}

safe_sqlite_count() {
    local db="$1"
    local query="$2"
    local result
    result=$(safe_sqlite_query "$db" "$query")
    to_int "$result"
}

# =============================================================================
# Contacts (AddressBook) - macOS specific
# Severity: high (but ignored for personal profile)
# =============================================================================
scan_contacts() {
    debug "scan_contacts: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_contacts: HOME not set"
        emit "personal_data" "contacts" "error" "no_home" "high"
        return
    fi

    if ! has_cmd sqlite3; then
        debug "scan_contacts: sqlite3 not found"
        emit "personal_data" "contacts" "error" "no_sqlite3" "high"
        return
    fi

    local db_base="$HOME/Library/Application Support/AddressBook/Sources"
    local db=""

    if [[ ! -d "$db_base" ]]; then
        debug "scan_contacts: AddressBook directory not found"
        emit "personal_data" "contacts" "not_found" "" "high"
        return
    fi

    # Find the database (may be in a UUID-named subdirectory)
    local source_dir
    for source_dir in "$db_base"/*/; do
        [[ ! -d "$source_dir" ]] && continue
        local candidate="${source_dir}AddressBook-v22.abcddb"
        if [[ -f "$candidate" ]]; then
            db="$candidate"
            debug "scan_contacts: found db at $db"
            break
        fi
    done

    if [[ -z "$db" ]]; then
        debug "scan_contacts: no AddressBook database found"
        emit "personal_data" "contacts" "not_found" "" "high"
        return
    fi

    if [[ ! -r "$db" ]]; then
        debug "scan_contacts: database not readable"
        emit "personal_data" "contacts" "blocked" "" "high"
        return
    fi

    local count
    count=$(safe_sqlite_count "$db" "SELECT COUNT(*) FROM ZABCDRECORD WHERE Z_ENT=9")

    debug "scan_contacts: found $count contacts"

    if [[ "$count" -gt 0 ]]; then
        emit "personal_data" "contacts" "exposed" "$count" "high"
    else
        emit "personal_data" "contacts" "blocked" "0" "high"
    fi
}

# =============================================================================
# Messages (iMessage) - macOS specific
# Severity: high (but ignored for personal profile)
# =============================================================================
scan_messages() {
    debug "scan_messages: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_messages: HOME not set"
        emit "personal_data" "messages" "error" "no_home" "high"
        return
    fi

    if ! has_cmd sqlite3; then
        debug "scan_messages: sqlite3 not found"
        emit "personal_data" "messages" "error" "no_sqlite3" "high"
        return
    fi

    local db="$HOME/Library/Messages/chat.db"

    if [[ ! -f "$db" ]]; then
        debug "scan_messages: database not found"
        emit "personal_data" "messages" "not_found" "" "high"
        return
    fi

    if [[ ! -r "$db" ]]; then
        debug "scan_messages: database not readable"
        emit "personal_data" "messages" "blocked" "" "high"
        return
    fi

    local count
    count=$(safe_sqlite_count "$db" "SELECT COUNT(*) FROM message")

    debug "scan_messages: found $count messages"

    if [[ "$count" -gt 0 ]]; then
        emit "personal_data" "messages" "exposed" "$count" "high"
    else
        emit "personal_data" "messages" "blocked" "0" "high"
    fi
}

# =============================================================================
# Browser History - uses shared helper with macOS paths
# Severity: medium
# =============================================================================
scan_browser_history() {
    debug "scan_browser_history: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_browser_history: HOME not set"
        emit "personal_data" "browser_history" "error" "no_home" "medium"
        return
    fi

    if ! has_cmd sqlite3; then
        debug "scan_browser_history: sqlite3 not found"
        emit "personal_data" "browser_history" "error" "no_sqlite3" "medium"
        return
    fi

    local safari_db="$HOME/Library/Safari/History.db"
    local chrome_db="$HOME/Library/Application Support/Google/Chrome/Default/History"
    local total_count=0
    local sources=""
    local any_db_exists=0

    # Check Safari
    if [[ -f "$safari_db" ]]; then
        any_db_exists=1
        if [[ -r "$safari_db" ]]; then
            local safari_count
            safari_count=$(safe_sqlite_count "$safari_db" "SELECT COUNT(*) FROM history_items")
            debug "scan_browser_history: Safari count=$safari_count"
            if [[ "$safari_count" -gt 0 ]]; then
                total_count=$((total_count + safari_count))
                sources="${sources}safari,"
            fi
        fi
    fi

    # Check Chrome
    if [[ -f "$chrome_db" ]]; then
        any_db_exists=1
        if [[ -r "$chrome_db" ]]; then
            local chrome_count
            chrome_count=$(safe_sqlite_count "$chrome_db" "SELECT COUNT(*) FROM urls")
            debug "scan_browser_history: Chrome count=$chrome_count"
            if [[ "$chrome_count" -gt 0 ]]; then
                total_count=$((total_count + chrome_count))
                sources="${sources}chrome,"
            fi
        fi
    fi

    # Check Firefox
    local firefox_profile_dir="$HOME/Library/Application Support/Firefox/Profiles"
    if [[ -d "$firefox_profile_dir" ]]; then
        local profile_dir
        for profile_dir in "$firefox_profile_dir"/*.default*; do
            [[ ! -d "$profile_dir" ]] && continue
            local firefox_db="$profile_dir/places.sqlite"
            if [[ -f "$firefox_db" ]]; then
                any_db_exists=1
                if [[ -r "$firefox_db" ]]; then
                    local firefox_count
                    firefox_count=$(safe_sqlite_count "$firefox_db" "SELECT COUNT(*) FROM moz_places")
                    debug "scan_browser_history: Firefox count=$firefox_count"
                    if [[ "$firefox_count" -gt 0 ]]; then
                        total_count=$((total_count + firefox_count))
                        sources="${sources}firefox,"
                    fi
                fi
                break
            fi
        done
    fi

    sources="${sources%,}"

    debug "scan_browser_history: total=$total_count sources=$sources"

    if [[ $total_count -gt 0 ]]; then
        emit "personal_data" "browser_history" "exposed" "${total_count}/${sources}" "medium"
    elif [[ $any_db_exists -gt 0 ]]; then
        emit "personal_data" "browser_history" "blocked" "" "medium"
    else
        emit "personal_data" "browser_history" "not_found" "" "medium"
    fi
}

# =============================================================================
# Calendar - macOS specific
# Severity: medium (varies by profile)
# =============================================================================
scan_calendar() {
    debug "scan_calendar: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "calendar" "error" "no_home" "medium"
        return
    fi

    local cal_dir="$HOME/Library/Calendars"

    if [[ ! -d "$cal_dir" ]]; then
        emit "personal_data" "calendar" "not_found" "" "medium"
        return
    fi

    if ! dir_readable "$cal_dir"; then
        emit "personal_data" "calendar" "blocked" "" "medium"
        return
    fi

    # Count calendar sources (each is a subdirectory with .calendar files)
    local count
    count=$(find "$cal_dir" -name "*.calendar" -type d 2>/dev/null | wc -l) || count=0
    count=$(to_int "$count")

    debug "scan_calendar: found $count calendars"

    if [[ $count -gt 0 ]]; then
        emit "personal_data" "calendar" "exposed" "$count" "medium"
    else
        emit "personal_data" "calendar" "blocked" "" "medium"
    fi
}

# =============================================================================
# Notes - macOS specific
# Severity: medium (varies by profile)
# =============================================================================
scan_notes() {
    debug "scan_notes: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "notes" "error" "no_home" "medium"
        return
    fi

    local notes_container="$HOME/Library/Group Containers/group.com.apple.notes"

    if [[ ! -d "$notes_container" ]]; then
        emit "personal_data" "notes" "not_found" "" "medium"
        return
    fi

    if ! dir_readable "$notes_container"; then
        emit "personal_data" "notes" "blocked" "" "medium"
        return
    fi

    # Check for the notes database
    local notes_db="$notes_container/NoteStore.sqlite"
    if file_readable "$notes_db"; then
        local count
        count=$(safe_sqlite_count "$notes_db" "SELECT COUNT(*) FROM ZICCLOUDSYNCINGOBJECT WHERE ZTITLE IS NOT NULL")
        debug "scan_notes: found $count notes"
        if [[ $count -gt 0 ]]; then
            emit "personal_data" "notes" "exposed" "$count" "medium"
            return
        fi
    fi

    emit "personal_data" "notes" "blocked" "" "medium"
}

# =============================================================================
# Mail - macOS specific
# Severity: high (varies by profile)
# =============================================================================
scan_mail() {
    debug "scan_mail: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "mail" "error" "no_home" "high"
        return
    fi

    local mail_dir="$HOME/Library/Mail"

    if [[ ! -d "$mail_dir" ]]; then
        emit "personal_data" "mail" "not_found" "" "high"
        return
    fi

    if ! dir_readable "$mail_dir"; then
        emit "personal_data" "mail" "blocked" "" "high"
        return
    fi

    # Count mail accounts (V* directories are mailbox versions)
    local count
    count=$(ls -1d "$mail_dir"/V*/*/INBOX.mbox 2>/dev/null | wc -l) || count=0
    count=$(to_int "$count")

    debug "scan_mail: found $count mailboxes"

    if [[ $count -gt 0 ]]; then
        emit "personal_data" "mail" "exposed" "$count accounts" "high"
    else
        emit "personal_data" "mail" "blocked" "" "high"
    fi
}

# =============================================================================
# Reminders - macOS specific
# Severity: low (varies by profile)
# =============================================================================
scan_reminders() {
    debug "scan_reminders: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "reminders" "error" "no_home" "low"
        return
    fi

    local reminders_dir="$HOME/Library/Reminders"

    if [[ ! -d "$reminders_dir" ]]; then
        emit "personal_data" "reminders" "not_found" "" "low"
        return
    fi

    if ! dir_readable "$reminders_dir"; then
        emit "personal_data" "reminders" "blocked" "" "low"
        return
    fi

    # Check for Container directories
    local count
    count=$(ls -1d "$reminders_dir"/Container_* 2>/dev/null | wc -l) || count=0
    count=$(to_int "$count")

    debug "scan_reminders: found $count reminder stores"

    if [[ $count -gt 0 ]]; then
        emit "personal_data" "reminders" "exposed" "$count" "low"
    else
        emit "personal_data" "reminders" "blocked" "" "low"
    fi
}

# =============================================================================
# Photos Metadata - macOS specific
# Severity: low (varies by profile)
# Note: Only checks metadata access, not photo content
# =============================================================================
scan_photos_metadata() {
    debug "scan_photos_metadata: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "photos_metadata" "error" "no_home" "low"
        return
    fi

    local photos_lib="$HOME/Pictures/Photos Library.photoslibrary"

    if [[ ! -d "$photos_lib" ]]; then
        emit "personal_data" "photos_metadata" "not_found" "" "low"
        return
    fi

    if ! dir_readable "$photos_lib"; then
        emit "personal_data" "photos_metadata" "blocked" "" "low"
        return
    fi

    # Check for database access
    local photos_db="$photos_lib/database/Photos.sqlite"
    if file_readable "$photos_db"; then
        local count
        count=$(safe_sqlite_count "$photos_db" "SELECT COUNT(*) FROM ZASSET" 2>/dev/null)
        debug "scan_photos_metadata: found $count photos"
        if [[ $count -gt 0 ]]; then
            emit "personal_data" "photos_metadata" "exposed" "$count" "low"
            return
        fi
    fi

    emit "personal_data" "photos_metadata" "blocked" "" "low"
}

# =============================================================================
# Recent Files - macOS specific
# Severity: medium
# =============================================================================
scan_recent_files() {
    debug "scan_recent_files: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "recent_files" "error" "no_home" "medium"
        return
    fi

    local sfl_dir="$HOME/Library/Application Support/com.apple.sharedfilelist"

    if [[ ! -d "$sfl_dir" ]]; then
        emit "personal_data" "recent_files" "not_found" "" "medium"
        return
    fi

    if ! dir_readable "$sfl_dir"; then
        emit "personal_data" "recent_files" "blocked" "" "medium"
        return
    fi

    # Count .sfl2 files (Shared File List format)
    local count
    count=$(ls -1 "$sfl_dir"/*.sfl2 2>/dev/null | wc -l) || count=0
    count=$(to_int "$count")

    debug "scan_recent_files: found $count SFL files"

    if [[ $count -gt 0 ]]; then
        emit "personal_data" "recent_files" "exposed" "$count lists" "medium"
    else
        emit "personal_data" "recent_files" "blocked" "" "medium"
    fi
}

# =============================================================================
# Clipboard - macOS specific
# Severity: medium
# =============================================================================
scan_clipboard() {
    debug "scan_clipboard: starting (darwin)"

    if ! has_cmd pbpaste; then
        emit "personal_data" "clipboard" "error" "no_pbpaste" "medium"
        return
    fi

    # Try to read clipboard content
    local clipboard_output
    clipboard_output=$(with_timeout 2 pbpaste 2>/dev/null) || clipboard_output=""

    # Note: Empty clipboard is valid, we just report if we CAN access it
    # pbpaste returns empty string for empty clipboard, so we check exit status
    if pbpaste >/dev/null 2>&1; then
        local has_content=0
        if [[ -n "$clipboard_output" ]]; then
            has_content=1
        fi
        debug "scan_clipboard: accessible (has_content=$has_content)"
        emit "personal_data" "clipboard" "exposed" "" "medium"
    else
        emit "personal_data" "clipboard" "blocked" "" "medium"
    fi
}

# =============================================================================
# Spotlight History - macOS specific
# Severity: low
# =============================================================================
scan_spotlight_history() {
    debug "scan_spotlight_history: starting (darwin)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "spotlight_history" "error" "no_home" "low"
        return
    fi

    local spotlight_dir="$HOME/Library/Metadata/CoreSpotlight"

    if [[ ! -d "$spotlight_dir" ]]; then
        # Also check alternative location
        spotlight_dir="$HOME/Library/Caches/com.apple.Spotlight"
        if [[ ! -d "$spotlight_dir" ]]; then
            emit "personal_data" "spotlight_history" "not_found" "" "low"
            return
        fi
    fi

    if ! dir_readable "$spotlight_dir"; then
        emit "personal_data" "spotlight_history" "blocked" "" "low"
        return
    fi

    debug "scan_spotlight_history: directory accessible"
    emit "personal_data" "spotlight_history" "exposed" "" "low"
}

# =============================================================================
# Run all personal data tests
# =============================================================================
run_personal_data_tests() {
    debug "run_personal_data_tests: starting (darwin)"
    progress_start "personal_data"
    # macOS-specific
    scan_contacts
    scan_messages
    scan_browser_history
    scan_calendar
    scan_notes
    scan_mail
    scan_reminders
    scan_photos_metadata
    # Activity history (macOS-specific)
    scan_recent_files
    scan_clipboard
    scan_spotlight_history
    # Cross-platform (from shared.sh)
    scan_shell_history
    progress_end "personal_data"
    debug "run_personal_data_tests: complete"
}
