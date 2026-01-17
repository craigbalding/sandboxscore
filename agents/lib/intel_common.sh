#!/bin/bash
# SandboxScore - Intelligence Module - Common Utilities
#
# Shared utilities for intelligence extraction across platforms.
# Requires: common.sh to be sourced first

# =============================================================================
# Process Classification
# =============================================================================

# System users that indicate a system process (macOS)
MACOS_SYSTEM_USERS="root:_:daemon:nobody:_www:_mysql:_postgres"

# System users that indicate a system process (Linux)
LINUX_SYSTEM_USERS="root:daemon:nobody:www-data:mysql:postgres:systemd"

# Categorize process by owner: own, other_user, system
classify_process_owner() {
    local proc_user="$1"
    local current_user="${USER:-$(whoami)}"

    # Own process
    if [[ "$proc_user" == "$current_user" ]]; then
        echo "own"
        return
    fi

    # System user check (platform-specific)
    local system_users
    if [[ "$(uname)" == "Darwin" ]]; then
        system_users="$MACOS_SYSTEM_USERS"
    else
        system_users="$LINUX_SYSTEM_USERS"
    fi

    # Check if it's a system user
    local IFS=':'
    for sys_user in $system_users; do
        # Handle prefix match for macOS underscore users
        if [[ "$proc_user" == "$sys_user" ]] || [[ "$proc_user" == _* && "$sys_user" == "_" ]]; then
            echo "system"
            return
        fi
    done

    # Another user's process
    echo "other_user"
}

# Check if a command line might contain secrets
cmdline_has_secrets() {
    local cmdline="$1"

    # Patterns that suggest secrets in command line
    if echo "$cmdline" | grep -qiE \
        'password|passwd|secret|token|api.?key|auth|credential|private.?key|bearer'; then
        return 0
    fi

    # AWS/cloud credential patterns
    if echo "$cmdline" | grep -qE 'AKIA|aws_|AWS_'; then
        return 0
    fi

    return 1
}

# =============================================================================
# Path Classification
# =============================================================================

# Classify file path by sensitivity
classify_path_sensitivity() {
    local path="$1"

    # Databases (high value)
    if [[ "$path" =~ \.(sqlite|sqlite3|sqlitedb|db|db-shm|db-wal)$ ]]; then
        echo "database"
        return
    fi

    # Credential files
    if echo "$path" | grep -qiE 'password|credential|token|secret|\.key$|\.pem$|id_rsa|id_ed25519'; then
        echo "credential"
        return
    fi

    # Config files
    if [[ "$path" =~ \.(conf|cfg|ini|yaml|yml|json)$ ]] || echo "$path" | grep -qi 'config'; then
        echo "config"
        return
    fi

    # Browser data
    if echo "$path" | grep -qiE 'history|cookie|cache|bookmark|login|password'; then
        echo "browser_data"
        return
    fi

    # Keychain/keyring
    if echo "$path" | grep -qiE 'keychain|keyring|wallet'; then
        echo "keychain"
        return
    fi

    echo "other"
}

# Known sensitive database paths (macOS)
# Returns: description if known, empty if not
identify_known_database() {
    local path="$1"

    case "$path" in
        */Safari/History.db*)
            echo "safari_history"
            ;;
        */Accounts/Accounts*.sqlite*)
            echo "accounts"
            ;;
        */Messages/chat.db*)
            echo "messages"
            ;;
        */AddressBook/*.abcddb*)
            echo "contacts"
            ;;
        */Calendar*.sqlitedb*)
            echo "calendar"
            ;;
        */Biome/*)
            echo "biome_activity"
            ;;
        */Notes/*)
            echo "notes"
            ;;
        */Mail/*Envelope*)
            echo "mail"
            ;;
        */Cookies/*)
            echo "cookies"
            ;;
        */Chrome/*/History|*/Chromium/*/History)
            echo "chrome_history"
            ;;
        */Firefox/*/places.sqlite*)
            echo "firefox_history"
            ;;
        *)
            echo ""
            ;;
    esac
}

# =============================================================================
# SQLite Probing (Read-Only)
# =============================================================================

# Probe a SQLite database for row count (ALWAYS read-only)
# Returns: row count or empty on failure
probe_sqlite_count() {
    local db_path="$1"
    local table="$2"

    # Must be readable
    [[ -r "$db_path" ]] || return 1

    # Must have sqlite3
    has_cmd sqlite3 || return 1

    # Query with read-only mode (prevents creating empty DBs)
    local count
    count=$(with_timeout 5 sqlite3 "file:${db_path}?mode=ro" \
        "SELECT COUNT(*) FROM \"$table\"" 2>/dev/null) || return 1

    # Validate it's a number
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
        return 0
    fi

    return 1
}

# List tables in a SQLite database (read-only)
probe_sqlite_tables() {
    local db_path="$1"

    [[ -r "$db_path" ]] || return 1
    has_cmd sqlite3 || return 1

    with_timeout 5 sqlite3 "file:${db_path}?mode=ro" ".tables" 2>/dev/null
}

# Check if we can query a SQLite database at all
probe_sqlite_accessible() {
    local db_path="$1"

    [[ -r "$db_path" ]] || return 1
    has_cmd sqlite3 || return 1

    # Try to get schema - if this works, DB is queryable
    with_timeout 3 sqlite3 "file:${db_path}?mode=ro" \
        "SELECT 1 FROM sqlite_master LIMIT 1" 2>/dev/null >/dev/null
}

# =============================================================================
# Output Helpers
# =============================================================================

# Build a details string from key:value pairs
# Usage: build_details "key1:val1" "key2:val2" ...
build_details() {
    local result=""
    for pair in "$@"; do
        [[ -z "$pair" ]] && continue
        if [[ -n "$result" ]]; then
            result="${result},"
        fi
        result="${result}${pair}"
    done
    echo "$result"
}

# Truncate a string with ellipsis if too long
truncate_string() {
    local str="$1"
    local max_len="${2:-30}"

    if [[ ${#str} -gt $max_len ]]; then
        echo "${str:0:$((max_len-3))}..."
    else
        echo "$str"
    fi
}

# Join array elements with delimiter
join_by() {
    local delim="$1"
    shift
    local first="$1"
    shift
    printf '%s' "$first" "${@/#/$delim}"
}
