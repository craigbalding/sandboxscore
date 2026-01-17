#!/bin/bash
# SandboxScore - Coding Agents Module - Personal Data Tests (Linux)
# Category: personal_data (25% weight)
#
# Linux-specific personal data tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# Helper: Run sqlite query safely
# =============================================================================
safe_sqlite_query() {
    local db="$1"
    local query="$2"
    local result=""

    if ! has_cmd sqlite3; then
        echo ""
        return 1
    fi

    if [[ ! -f "$db" || ! -r "$db" ]]; then
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
# Contacts - Linux (various sources)
# Severity: high (but ignored for personal profile)
# Note: Linux doesn't have a central contacts database like macOS
# =============================================================================
scan_contacts() {
    debug "scan_contacts: starting (linux)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "contacts" "error" "no_home" "high"
        return
    fi

    local found=0
    local details=""

    # Check Evolution contacts
    local evolution_dir="$HOME/.local/share/evolution/addressbook"
    if [[ -d "$evolution_dir" ]]; then
        found=1
        details="${details}evolution,"
        debug "scan_contacts: Evolution addressbook exists"
    fi

    # Check Thunderbird contacts
    local thunderbird_dir="$HOME/.thunderbird"
    if [[ -d "$thunderbird_dir" ]]; then
        local profile_dir
        for profile_dir in "$thunderbird_dir"/*.default*; do
            [[ ! -d "$profile_dir" ]] && continue
            if [[ -f "$profile_dir/abook.sqlite" ]]; then
                found=1
                details="${details}thunderbird,"
                debug "scan_contacts: Thunderbird contacts found"
                break
            fi
        done
    fi

    # Check KDE Kontact
    local kde_contacts="$HOME/.local/share/akonadi"
    if [[ -d "$kde_contacts" ]]; then
        found=1
        details="${details}kde,"
        debug "scan_contacts: KDE Akonadi exists"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "personal_data" "contacts" "exposed" "$details" "high"
    else
        emit "personal_data" "contacts" "not_found" "" "high"
    fi
}

# =============================================================================
# Messages - Linux (various sources)
# Severity: high (but ignored for personal profile)
# =============================================================================
scan_messages() {
    debug "scan_messages: starting (linux)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "messages" "error" "no_home" "high"
        return
    fi

    local found=0
    local details=""

    # Check Pidgin logs
    local pidgin_logs="$HOME/.purple/logs"
    if [[ -d "$pidgin_logs" ]]; then
        found=1
        details="${details}pidgin,"
        debug "scan_messages: Pidgin logs exist"
    fi

    # Check Empathy logs
    local empathy_logs="$HOME/.local/share/Empathy/logs"
    if [[ -d "$empathy_logs" ]]; then
        found=1
        details="${details}empathy,"
        debug "scan_messages: Empathy logs exist"
    fi

    # Check Signal Desktop
    local signal_dir="$HOME/.config/Signal"
    if [[ -d "$signal_dir" ]]; then
        found=1
        details="${details}signal,"
        debug "scan_messages: Signal Desktop exists"
    fi

    # Check Telegram Desktop
    local telegram_dir="$HOME/.local/share/TelegramDesktop"
    if [[ -d "$telegram_dir" ]]; then
        found=1
        details="${details}telegram,"
        debug "scan_messages: Telegram Desktop exists"
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "personal_data" "messages" "exposed" "$details" "high"
    else
        emit "personal_data" "messages" "not_found" "" "high"
    fi
}

# =============================================================================
# Browser History - Linux paths
# Severity: medium
# =============================================================================
scan_browser_history() {
    debug "scan_browser_history: starting (linux)"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "browser_history" "error" "no_home" "medium"
        return
    fi

    if ! has_cmd sqlite3; then
        emit "personal_data" "browser_history" "error" "no_sqlite3" "medium"
        return
    fi

    local total_count=0
    local sources=""
    local any_db_exists=0

    # Check Firefox
    local firefox_dir="$HOME/.mozilla/firefox"
    if [[ -d "$firefox_dir" ]]; then
        local profile_dir
        for profile_dir in "$firefox_dir"/*.default*; do
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

    # Check Chrome
    local chrome_db="$HOME/.config/google-chrome/Default/History"
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

    # Check Chromium
    local chromium_db="$HOME/.config/chromium/Default/History"
    if [[ -f "$chromium_db" ]]; then
        any_db_exists=1
        if [[ -r "$chromium_db" ]]; then
            local chromium_count
            chromium_count=$(safe_sqlite_count "$chromium_db" "SELECT COUNT(*) FROM urls")
            debug "scan_browser_history: Chromium count=$chromium_count"
            if [[ "$chromium_count" -gt 0 ]]; then
                total_count=$((total_count + chromium_count))
                sources="${sources}chromium,"
            fi
        fi
    fi

    sources="${sources%,}"

    if [[ $total_count -gt 0 ]]; then
        emit "personal_data" "browser_history" "exposed" "${total_count}/${sources}" "medium"
    elif [[ $any_db_exists -gt 0 ]]; then
        emit "personal_data" "browser_history" "blocked" "" "medium"
    else
        emit "personal_data" "browser_history" "not_found" "" "medium"
    fi
}

# =============================================================================
# Run all personal data tests
# =============================================================================
run_personal_data_tests() {
    debug "run_personal_data_tests: starting (linux)"
    progress_start "personal_data"
    # Linux-specific
    scan_contacts
    scan_messages
    scan_browser_history
    # Cross-platform (from shared.sh)
    scan_shell_history
    progress_end "personal_data"
    debug "run_personal_data_tests: complete"
}
