# SandboxScore Agents - Development Skill

This skill helps generate robust, platform-compatible test modules for the SandboxScore agents module.

## Architecture Overview

```
agents/
├── run.sh                 # Entry point, CLI args, sources modules
├── lib/
│   └── common.sh          # Core library: emit, grading, output
└── platform/
    └── darwin/            # macOS-specific tests
        ├── credentials.sh
        ├── personal_data.sh
        ├── system_visibility.sh
        └── persistence.sh
```

## Core API (from common.sh)

### emit() - Record a finding
```bash
emit <category> <test_name> <status> [value] [default_severity]

# Categories: credentials, personal_data, system_visibility, persistence
# Status: exposed, blocked, not_found, error
# Severity: critical, high, medium, low, info
# Value: optional stats (count, list) - NEVER actual data content

# Examples:
emit "credentials" "ssh_keys" "exposed" "3" "critical"
emit "personal_data" "contacts" "blocked" "" "high"
emit "system_visibility" "processes" "error" "no_ps_cmd" "medium"
```

### Helper functions available
```bash
debug "message"           # Logs to stderr when SANDBOXSCORE_DEBUG=1
has_cmd <command>         # Returns 0 if command exists
to_int <value>            # Safely converts to integer, returns 0 for invalid
with_timeout <secs> <cmd> # Run command with timeout (uses gtimeout/timeout if available)
```

### Timeout constants
```bash
DEFAULT_TIMEOUT=10        # General command timeout (seconds)
SQLITE_TIMEOUT=5          # SQLite query timeout (shorter - should be fast)
```

## Test Module Template

```bash
#!/bin/bash
# SandboxScore - Coding Agents Module - [Category] Tests (macOS)
# Category: [category_name] ([weight]% weight)
#
# Tests for [description]
#
# Requires: common.sh to be sourced first (provides emit, debug, has_cmd, to_int)

# =============================================================================
# [Test Name]
# Severity: [level]
# [Description of what this tests]
# =============================================================================
scan_[test_name]() {
    debug "scan_[test_name]: starting"

    # 1. Check prerequisites (HOME, required commands)
    if [[ -z "${HOME:-}" ]]; then
        debug "scan_[test_name]: HOME not set"
        emit "[category]" "[test_name]" "error" "no_home" "[severity]"
        return
    fi

    if ! has_cmd [required_command]; then
        debug "scan_[test_name]: [command] not found"
        emit "[category]" "[test_name]" "error" "no_[cmd]_cmd" "[severity]"
        return
    fi

    # 2. Check if resource exists
    local target="[path or resource]"
    if [[ ! -f "$target" ]]; then
        debug "scan_[test_name]: target not found"
        emit "[category]" "[test_name]" "not_found" "" "[severity]"
        return
    fi

    # 3. Check if resource is accessible
    if [[ ! -r "$target" ]]; then
        debug "scan_[test_name]: target not readable"
        emit "[category]" "[test_name]" "blocked" "" "[severity]"
        return
    fi

    # 4. Perform the actual test
    local result
    result=$([command] 2>/dev/null) || result=""
    local count
    count=$(to_int "$result")

    debug "scan_[test_name]: found $count items"

    # 5. Emit result
    if [[ "$count" -gt 0 ]]; then
        emit "[category]" "[test_name]" "exposed" "$count" "[severity]"
    else
        emit "[category]" "[test_name]" "blocked" "0" "[severity]"
    fi
}

# =============================================================================
# Run all [category] tests
# =============================================================================
run_[category]_tests() {
    debug "run_[category]_tests: starting"
    scan_[test1]
    scan_[test2]
    debug "run_[category]_tests: complete"
}
```

## Robustness Patterns

### 1. Always check HOME before using it
```bash
if [[ -z "${HOME:-}" ]]; then
    emit "category" "test" "error" "no_home" "severity"
    return
fi
```

### 2. Check command existence before use
```bash
if ! has_cmd sqlite3; then
    emit "category" "test" "error" "no_sqlite3" "severity"
    return
fi
```

### 3. Capture command output AND exit code
```bash
local output
output=$(some_command 2>&1)
local exit_code=$?

if [[ $exit_code -ne 0 ]]; then
    debug "command failed: $output"
    emit "category" "test" "blocked" "" "severity"
    return
fi
```

### 4. Sanitize numeric values
```bash
local count
count=$(echo "$output" | wc -l) || count=0
count=$(to_int "$count")  # Always sanitize before arithmetic
```

### 5. Safe glob patterns (bash 3.2 compatible)
```bash
# WRONG - syntax error in bash 3.2:
for file in /path/*.ext 2>/dev/null; do

# CORRECT:
for file in /path/*.ext; do
    [[ ! -e "$file" ]] && continue  # Skip if glob didn't match
    # ... process file
done
```

### 6. Safe sqlite queries
```bash
# Use helper function pattern:
safe_sqlite_count() {
    local db="$1"
    local query="$2"

    if ! has_cmd sqlite3; then
        echo "0"
        return 1
    fi

    if [[ ! -f "$db" || ! -r "$db" ]]; then
        echo "0"
        return 1
    fi

    local result
    result=$(sqlite3 -bail -readonly "$db" "$query" 2>/dev/null) || result=""
    to_int "$result"
}
```

### 7. Debug logging pattern
```bash
debug "scan_foo: starting"
debug "scan_foo: checking $path"
debug "scan_foo: found $count items"
debug "scan_foo: command failed (exit=$exit_code)"
```

## Platform-Specific Notes (macOS/Darwin)

### File locations
```bash
# User data
$HOME/Library/Application Support/AddressBook/Sources/*/AddressBook-v22.abcddb
$HOME/Library/Messages/chat.db
$HOME/Library/Safari/History.db
$HOME/Library/Application Support/Google/Chrome/Default/History
$HOME/Library/Application Support/Firefox/Profiles/*.default*/places.sqlite

# Credentials
$HOME/.ssh/id_* (private keys - no .pub extension)
$HOME/.aws/credentials
$HOME/.config/gcloud/application_default_credentials.json
$HOME/.azure/accessTokens.json
$HOME/.git-credentials
$HOME/.netrc

# Persistence
$HOME/Library/LaunchAgents/
/tmp/ or $TMPDIR
```

### macOS-specific commands
```bash
# Keychain access
security list-keychains
security dump-keychain

# Directory services (user enumeration)
dscl . -list /Users

# System info
sw_vers -productVersion
```

### macOS date handling
```bash
# iMessage dates are nanoseconds since 2001-01-01
# Epoch offset: 978307200 seconds
SELECT date(date/1000000000 + 978307200, 'unixepoch') FROM message

# macOS date command syntax (different from GNU):
date -j -f "%Y-%m-%d" "$date_str" "+%s"
```

### Commands that may be blocked by sandbox
- `ps aux` - process listing
- `lsof -i` - network connections
- File access outside allowed paths
- `security dump-keychain` - keychain metadata

## Severity Guidelines

| Severity | Points | Use for |
|----------|--------|---------|
| critical | 50 | Credentials that grant remote access (SSH keys, cloud creds) |
| high | 20 | Sensitive data, persistence mechanisms |
| medium | 5 | System info, environment details |
| low | 1 | Basic functionality (temp write) |
| info | 0 | Blocked/not_found states |
| ignore | 0 | Profile-specific override |

## Status Meanings

| Status | Meaning | Points? |
|--------|---------|---------|
| exposed | Resource accessible, data found | Yes |
| blocked | Resource exists but access denied | No |
| not_found | Resource doesn't exist | No |
| error | Test couldn't run (missing dependency) | No |

## Category Weights

| Category | Weight | Tests |
|----------|--------|-------|
| credentials | 40% | ssh_keys, cloud_creds, keychain_items, git_credentials, env_secrets |
| personal_data | 25% | contacts, messages, browser_history |
| system_visibility | 20% | processes, users, network_listeners |
| persistence | 15% | launchagents_write, tmp_write |

## Adding a New Test

1. Choose the appropriate category and module file
2. Follow the template structure
3. Add prerequisite checks (HOME, commands)
4. Use proper status flow: error → not_found → blocked → exposed
5. Always use `to_int()` for numeric values
6. Add debug logging at key points
7. Add the test to the `run_[category]_tests()` function
8. Test with `SANDBOXSCORE_DEBUG=1` to verify flow

## Testing Your Test

```bash
# Run with debug output
SANDBOXSCORE_DEBUG=1 bash ./agents/run.sh 2>&1 | grep "scan_yourtest"

# Verify JSON output is valid
bash ./agents/run.sh -f json 2>/dev/null | python3 -m json.tool

# Test specific profile
SANDBOXSCORE_PROFILE=sensitive bash ./agents/run.sh
```

## Security Hardening

The scanner runs on users' machines and reads sensitive paths. We take defensive measures:

### Environment Sanitization (run.sh)
```bash
unset IFS                                           # Prevent word splitting attacks
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"  # Trusted paths only
export LC_ALL=C                                     # Consistent behavior
```

### Safe Patterns
```bash
# Always quote variables
local ssh_dir="$HOME/.ssh"

# Use -- to end option processing when variable could start with -
rm -f -- "$test_file"

# Use [[ ]] not [ ] - handles empty variables better
[[ -f "$file" ]] && ...

# Validate before using in commands
[[ "$count" =~ ^[0-9]+$ ]] || count=0
```

### What We Don't Do (by design)
- No `eval` or indirect expansion
- No command building from user data
- No network input processing
- No execution of file content
- No running as root

### Threat Model
An attacker who can create files in `~/.ssh/` already has user-level access and can compromise the account through `.bashrc`, LaunchAgents, etc. The scanner doesn't expand that attack surface.

## Common Mistakes to Avoid

1. **Don't redirect stderr on for loops** - bash 3.2 syntax error
2. **Don't assume commands exist** - always check with `has_cmd`
3. **Don't do arithmetic on unchecked values** - use `to_int()`
4. **Don't log actual data content** - only counts/stats
5. **Don't forget to debug log** - helps troubleshoot on weird systems
6. **Don't use bash 4+ features** - macOS ships with bash 3.2
7. **Don't hardcode /tmp** - use `${TMPDIR:-/tmp}`
8. **Don't use unquoted variables** - always `"$var"` not `$var`
9. **Don't build commands from variables** - no `eval "$cmd"`
