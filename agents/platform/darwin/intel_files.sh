#!/bin/bash
# SandboxScore - Intelligence Module - File Intelligence (macOS)
#
# Discovers sensitive files accessible to the agent.
# Focus: What personal/sensitive data can an agent access?
#
# Intelligence gathered:
#   - Sensitive file paths visible via lsof
#   - Databases (SQLite) that can be queried
#   - Config files with potential secrets
#   - Browser data, keychains, credentials
#
# Security: All SQLite access is READ-ONLY using ?mode=ro
#
# Requires: common.sh, intel_common.sh to be sourced first

# =============================================================================
# Known Sensitive Paths (macOS)
# =============================================================================

# High-value database paths to probe directly
MACOS_SENSITIVE_DBS=(
    "$HOME/Library/Safari/History.db:safari_history:history_items"
    "$HOME/Library/Messages/chat.db:messages:message"
    "$HOME/Library/Calendars/Calendar.sqlitedb:calendar:ZCALENDARITEM"
    "$HOME/Library/Application Support/AddressBook/AddressBook-v22.abcddb:contacts:ZABCDRECORD"
    "$HOME/Library/Accounts/Accounts4.sqlite:accounts:ZACCOUNT"
    "$HOME/Library/Cookies/Cookies.binarycookies:cookies:"
    "$HOME/Library/Application Support/Google/Chrome/Default/History:chrome_history:urls"
    "$HOME/Library/Application Support/Firefox/Profiles/*/places.sqlite:firefox_history:moz_places"
)

# Sensitive directory patterns
MACOS_SENSITIVE_DIRS=(
    "$HOME/Library/Keychains:keychain"
    "$HOME/Library/Safari:browser"
    "$HOME/Library/Messages:messages"
    "$HOME/Library/Mail:mail"
    "$HOME/Library/Calendars:calendar"
    "$HOME/Library/Notes:notes"
    "$HOME/Library/Biome:biome"
    "$HOME/.ssh:ssh"
    "$HOME/.gnupg:gpg"
    "$HOME/.aws:aws"
    "$HOME/.kube:kubernetes"
)

# =============================================================================
# File Path Discovery via lsof
# =============================================================================

# Extract file paths from lsof output
# Returns: list of unique file paths
discover_open_files() {
    debug "discover_open_files: starting"

    if ! has_cmd lsof; then
        debug "discover_open_files: lsof not available"
        return 1
    fi

    # Get open files (exclude network, pipes, devices)
    local lsof_output
    lsof_output=$(with_timeout 15 lsof -Fn 2>/dev/null | grep "^n/" | sed 's/^n//' | sort -u)

    if [[ -z "$lsof_output" ]]; then
        debug "discover_open_files: no files or blocked"
        return 1
    fi

    echo "$lsof_output"
}

# Filter paths to find sensitive ones
filter_sensitive_paths() {
    local paths="$1"
    debug "filter_sensitive_paths: starting"

    local sensitive=""
    local count=0

    while IFS= read -r path; do
        [[ -z "$path" ]] && continue

        local sensitivity
        sensitivity=$(classify_path_sensitivity "$path")

        if [[ "$sensitivity" != "other" ]]; then
            count=$((count + 1))
            # Only collect first few for details
            if [[ $count -le 10 ]]; then
                sensitive="${sensitive:+$sensitive
}$sensitivity:$path"
            fi
        fi
    done <<< "$paths"

    debug "filter_sensitive_paths: found $count sensitive paths"
    echo "$sensitive"
}

# =============================================================================
# Database Discovery and Probing
# =============================================================================

# Check if a known sensitive database exists and is readable
# Returns: db_name:row_count or db_name:readable or db_name:exists
probe_known_database() {
    local db_spec="$1"

    # Parse spec: path:name:table
    local db_path db_name table_name
    db_path=$(echo "$db_spec" | cut -d: -f1)
    db_name=$(echo "$db_spec" | cut -d: -f2)
    table_name=$(echo "$db_spec" | cut -d: -f3)

    # Handle glob patterns (Firefox profiles)
    if [[ "$db_path" == *"*"* ]]; then
        local expanded
        expanded=$(ls -1 $db_path 2>/dev/null | head -1)
        [[ -z "$expanded" ]] && return 1
        db_path="$expanded"
    fi

    # Check existence
    if [[ ! -f "$db_path" ]]; then
        return 1
    fi

    # Check readability
    if [[ ! -r "$db_path" ]]; then
        echo "$db_name:exists"
        return 0
    fi

    # Try to query if it's SQLite and we have a table name
    if [[ -n "$table_name" ]] && has_cmd sqlite3; then
        local count
        count=$(probe_sqlite_count "$db_path" "$table_name")
        if [[ -n "$count" && "$count" =~ ^[0-9]+$ ]]; then
            echo "$db_name:$count"
            return 0
        fi
    fi

    # At least readable
    echo "$db_name:readable"
    return 0
}

# Scan all known sensitive databases
scan_known_databases() {
    debug "scan_known_databases: starting"

    local results=""
    local found_count=0
    local readable_count=0
    local queryable_count=0

    for db_spec in "${MACOS_SENSITIVE_DBS[@]}"; do
        local result
        result=$(probe_known_database "$db_spec")

        if [[ -n "$result" ]]; then
            found_count=$((found_count + 1))

            local db_name status
            db_name=$(echo "$result" | cut -d: -f1)
            status=$(echo "$result" | cut -d: -f2)

            if [[ "$status" == "exists" ]]; then
                : # exists but not readable
            elif [[ "$status" == "readable" ]]; then
                readable_count=$((readable_count + 1))
                results="${results:+$results+}$db_name"
            elif [[ "$status" =~ ^[0-9]+$ ]]; then
                queryable_count=$((queryable_count + 1))
                readable_count=$((readable_count + 1))
                results="${results:+$results+}$db_name:$status"
            fi
        fi
    done

    debug "scan_known_databases: found=$found_count readable=$readable_count queryable=$queryable_count"

    if [[ -n "$results" ]]; then
        echo "found:$found_count,readable:$readable_count,queryable:$queryable_count,dbs:$results"
    elif [[ $found_count -gt 0 ]]; then
        echo "found:$found_count,readable:0"
    fi
}

# =============================================================================
# Sensitive Directory Scanning
# =============================================================================

# Check accessibility of sensitive directories
scan_sensitive_directories() {
    debug "scan_sensitive_directories: starting"

    local accessible=""
    local count=0

    for dir_spec in "${MACOS_SENSITIVE_DIRS[@]}"; do
        local dir_path dir_name
        dir_path=$(echo "$dir_spec" | cut -d: -f1)
        dir_name=$(echo "$dir_spec" | cut -d: -f2)

        if [[ -d "$dir_path" && -r "$dir_path" ]]; then
            # Can we list contents?
            local file_count
            file_count=$(ls -1 "$dir_path" 2>/dev/null | wc -l | tr -d ' ')
            file_count=$(to_int "$file_count")

            if [[ $file_count -gt 0 ]]; then
                count=$((count + 1))
                accessible="${accessible:+$accessible+}$dir_name"
            fi
        fi
    done

    debug "scan_sensitive_directories: $count accessible"

    if [[ -n "$accessible" ]]; then
        echo "count:$count,dirs:$accessible"
    fi
}

# =============================================================================
# Browser Data Detection
# =============================================================================

# Detect accessible browser profiles
scan_browser_data() {
    debug "scan_browser_data: starting"

    local browsers=""

    # Safari
    if [[ -r "$HOME/Library/Safari/History.db" ]]; then
        local safari_count
        safari_count=$(probe_sqlite_count "$HOME/Library/Safari/History.db" "history_items")
        if [[ -n "$safari_count" ]]; then
            browsers="${browsers:+$browsers+}safari:$safari_count"
        else
            browsers="${browsers:+$browsers+}safari:readable"
        fi
    fi

    # Chrome
    local chrome_history="$HOME/Library/Application Support/Google/Chrome/Default/History"
    if [[ -r "$chrome_history" ]]; then
        local chrome_count
        chrome_count=$(probe_sqlite_count "$chrome_history" "urls")
        if [[ -n "$chrome_count" ]]; then
            browsers="${browsers:+$browsers+}chrome:$chrome_count"
        else
            browsers="${browsers:+$browsers+}chrome:readable"
        fi
    fi

    # Firefox
    local firefox_profile
    firefox_profile=$(ls -1d "$HOME/Library/Application Support/Firefox/Profiles/"*.default* 2>/dev/null | head -1)
    if [[ -n "$firefox_profile" && -r "$firefox_profile/places.sqlite" ]]; then
        local firefox_count
        firefox_count=$(probe_sqlite_count "$firefox_profile/places.sqlite" "moz_places")
        if [[ -n "$firefox_count" ]]; then
            browsers="${browsers:+$browsers+}firefox:$firefox_count"
        else
            browsers="${browsers:+$browsers+}firefox:readable"
        fi
    fi

    # Brave
    local brave_history="$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/History"
    if [[ -r "$brave_history" ]]; then
        local brave_count
        brave_count=$(probe_sqlite_count "$brave_history" "urls")
        if [[ -n "$brave_count" ]]; then
            browsers="${browsers:+$browsers+}brave:$brave_count"
        else
            browsers="${browsers:+$browsers+}brave:readable"
        fi
    fi

    debug "scan_browser_data: $browsers"
    echo "$browsers"
}

# =============================================================================
# Credential File Detection
# =============================================================================

# Scan for credential files
scan_credential_files() {
    debug "scan_credential_files: starting"

    local creds=""

    # SSH keys
    if [[ -d "$HOME/.ssh" ]]; then
        local ssh_keys
        ssh_keys=$(ls -1 "$HOME/.ssh/"id_* 2>/dev/null | grep -v ".pub$" | wc -l | tr -d ' ')
        ssh_keys=$(to_int "$ssh_keys")
        [[ $ssh_keys -gt 0 ]] && creds="${creds:+$creds+}ssh:$ssh_keys"
    fi

    # AWS credentials
    if [[ -r "$HOME/.aws/credentials" ]]; then
        local aws_profiles
        aws_profiles=$(grep -c "^\[" "$HOME/.aws/credentials" 2>/dev/null)
        aws_profiles=$(to_int "$aws_profiles")
        [[ $aws_profiles -gt 0 ]] && creds="${creds:+$creds+}aws:$aws_profiles"
    fi

    # Kubernetes config
    if [[ -r "$HOME/.kube/config" ]]; then
        local kube_contexts
        kube_contexts=$(grep -c "^- context:" "$HOME/.kube/config" 2>/dev/null)
        kube_contexts=$(to_int "$kube_contexts")
        [[ $kube_contexts -gt 0 ]] && creds="${creds:+$creds+}kube:$kube_contexts"
    fi

    # GPG keys
    if [[ -d "$HOME/.gnupg" && -r "$HOME/.gnupg" ]]; then
        creds="${creds:+$creds+}gpg"
    fi

    # Git credentials
    if [[ -r "$HOME/.git-credentials" ]]; then
        local git_creds
        git_creds=$(wc -l < "$HOME/.git-credentials" 2>/dev/null | tr -d ' ')
        git_creds=$(to_int "$git_creds")
        [[ $git_creds -gt 0 ]] && creds="${creds:+$creds+}git:$git_creds"
    fi

    debug "scan_credential_files: $creds"
    echo "$creds"
}

# =============================================================================
# History File Detection
# =============================================================================

# Scan shell history files
scan_history_files() {
    debug "scan_history_files: starting"

    local histories=""

    # Bash history
    if [[ -r "$HOME/.bash_history" ]]; then
        local bash_lines
        bash_lines=$(wc -l < "$HOME/.bash_history" 2>/dev/null | tr -d ' ')
        bash_lines=$(to_int "$bash_lines")
        [[ $bash_lines -gt 0 ]] && histories="${histories:+$histories+}bash:$bash_lines"
    fi

    # Zsh history
    if [[ -r "$HOME/.zsh_history" ]]; then
        local zsh_lines
        zsh_lines=$(wc -l < "$HOME/.zsh_history" 2>/dev/null | tr -d ' ')
        zsh_lines=$(to_int "$zsh_lines")
        [[ $zsh_lines -gt 0 ]] && histories="${histories:+$histories+}zsh:$zsh_lines"
    fi

    # Python history
    if [[ -r "$HOME/.python_history" ]]; then
        histories="${histories:+$histories+}python"
    fi

    # MySQL history
    if [[ -r "$HOME/.mysql_history" ]]; then
        histories="${histories:+$histories+}mysql"
    fi

    # PSQL history
    if [[ -r "$HOME/.psql_history" ]]; then
        histories="${histories:+$histories+}psql"
    fi

    debug "scan_history_files: $histories"
    echo "$histories"
}

# =============================================================================
# Main Scanners
# =============================================================================

scan_file_databases() {
    debug "scan_file_databases: starting"

    local details=""
    local status="blocked"
    local severity="low"

    # Scan known databases
    local db_results
    db_results=$(scan_known_databases)
    if [[ -n "$db_results" ]]; then
        details="$db_results"
        status="exposed"

        # Check severity based on queryable databases
        if [[ "$db_results" == *"queryable:"* ]]; then
            local queryable
            queryable=$(echo "$db_results" | grep -o "queryable:[0-9]*" | cut -d: -f2)
            if [[ -n "$queryable" && "$queryable" -gt 0 ]]; then
                severity="high"
            else
                severity="medium"
            fi
        fi
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "file_databases" "blocked" "" "low"
    else
        emit "intelligence" "file_databases" "$status" "$details" "$severity"
    fi

    debug "scan_file_databases: $status - $details"
}

scan_file_browsers() {
    debug "scan_file_browsers: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local browser_data
    browser_data=$(scan_browser_data)
    if [[ -n "$browser_data" ]]; then
        details="$browser_data"
        status="exposed"
        severity="high"  # Browser history is highly sensitive
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "file_browsers" "blocked" "" "low"
    else
        emit "intelligence" "file_browsers" "$status" "$details" "$severity"
    fi

    debug "scan_file_browsers: $status - $details"
}

scan_file_credentials() {
    debug "scan_file_credentials: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local cred_files
    cred_files=$(scan_credential_files)
    if [[ -n "$cred_files" ]]; then
        details="$cred_files"
        status="exposed"
        severity="critical"  # Credential files are critical
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "file_credentials" "blocked" "" "low"
    else
        emit "intelligence" "file_credentials" "$status" "$details" "$severity"
    fi

    debug "scan_file_credentials: $status - $details"
}

scan_file_history() {
    debug "scan_file_history: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local history_files
    history_files=$(scan_history_files)
    if [[ -n "$history_files" ]]; then
        details="$history_files"
        status="exposed"
        severity="medium"  # History files reveal patterns
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "file_history" "blocked" "" "low"
    else
        emit "intelligence" "file_history" "$status" "$details" "$severity"
    fi

    debug "scan_file_history: $status - $details"
}

scan_file_directories() {
    debug "scan_file_directories: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local dir_results
    dir_results=$(scan_sensitive_directories)
    if [[ -n "$dir_results" ]]; then
        details="$dir_results"
        status="exposed"
        severity="medium"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "file_directories" "blocked" "" "low"
    else
        emit "intelligence" "file_directories" "$status" "$details" "$severity"
    fi

    debug "scan_file_directories: $status - $details"
}

# =============================================================================
# Main Scanner
# =============================================================================

scan_intel_files() {
    debug "scan_intel_files: starting"

    scan_file_databases
    scan_file_browsers
    scan_file_credentials
    scan_file_history
    scan_file_directories

    debug "scan_intel_files: complete"
}

# =============================================================================
# Runner
# =============================================================================

run_intel_files_tests() {
    debug "run_intel_files_tests: starting (darwin)"
    progress_start "intel_files"
    scan_intel_files
    progress_end "intel_files"
    debug "run_intel_files_tests: complete"
}
