#!/bin/bash
# SandboxScore - Intelligence Module - Service Intelligence (macOS)
#
# Discovers services and daemons running on the system.
# Focus: What services can an agent see and potentially control?
#
# Intelligence gathered:
#   - Running launchd services (user and system)
#   - Services the agent can control (start/stop)
#   - Sensitive services (remote access, sharing)
#   - Login items and persistence mechanisms
#
# Requires: common.sh to be sourced first

# =============================================================================
# Sensitive Service Patterns
# =============================================================================

# Services that indicate potential attack surface or sensitive functionality
SENSITIVE_SERVICE_PATTERNS=(
    "ssh:com.openssh"
    "ard:com.apple.RemoteDesktop"
    "vnc:com.apple.screensharing"
    "smb:com.apple.smbd"
    "ftp:com.apple.ftpd"
    "http:com.apple.httpd"
    "postgres:com.postgresql"
    "mysql:com.mysql"
    "docker:com.docker"
    "ollama:com.ollama"
)

# =============================================================================
# LaunchD Service Enumeration
# =============================================================================

# Get user-level launchd services
enumerate_user_services() {
    debug "enumerate_user_services: starting"

    if ! has_cmd launchctl; then
        debug "enumerate_user_services: launchctl not available"
        return 1
    fi

    # List user services
    local services
    services=$(with_timeout 10 launchctl list 2>/dev/null)

    if [[ -z "$services" ]]; then
        debug "enumerate_user_services: no output or blocked"
        return 1
    fi

    # Count services (skip header)
    local count
    count=$(echo "$services" | tail -n +2 | wc -l | tr -d ' ')
    count=$(to_int "$count")

    # Count running (PID != -)
    local running
    running=$(echo "$services" | tail -n +2 | awk '$1 != "-" {print}' | wc -l | tr -d ' ')
    running=$(to_int "$running")

    debug "enumerate_user_services: total=$count running=$running"
    echo "total:$count,running:$running"
}

# Get system-level launchd services (requires privileges)
enumerate_system_services() {
    debug "enumerate_system_services: starting"

    if ! has_cmd launchctl; then
        return 1
    fi

    # Try to list system services (may fail without root)
    local services
    services=$(with_timeout 10 launchctl print system 2>/dev/null)

    if [[ -z "$services" || "$services" == *"Could not find"* ]]; then
        debug "enumerate_system_services: blocked or no access"
        return 1
    fi

    # Count services from output
    local count
    count=$(echo "$services" | grep -c "active count" 2>/dev/null)
    count=$(to_int "$count")

    debug "enumerate_system_services: accessible, count hints=$count"
    echo "accessible"
}

# Check if we can see service details
check_service_visibility() {
    debug "check_service_visibility: starting"

    local visibility=""

    # Can we list our own services?
    if launchctl list 2>/dev/null | head -1 | grep -q "PID"; then
        visibility="user"
    fi

    # Can we print user domain?
    if launchctl print "user/$(id -u)" 2>/dev/null | grep -q "domain"; then
        visibility="${visibility:+$visibility+}domain"
    fi

    # Can we see GUI domain?
    if launchctl print "gui/$(id -u)" 2>/dev/null | grep -q "domain"; then
        visibility="${visibility:+$visibility+}gui"
    fi

    debug "check_service_visibility: $visibility"
    echo "$visibility"
}

# =============================================================================
# Service Control Detection
# =============================================================================

# Check if we can control (start/stop) services
# We don't actually start/stop, just check if the commands would work
check_service_controllability() {
    debug "check_service_controllability: starting"

    local controllable=""

    # Check if we can kickstart a harmless service (dry-run style check)
    # We'll check if launchctl commands are available and what they report

    # Can we bootout/bootstrap user services?
    local test_result
    test_result=$(launchctl print "user/$(id -u)/com.apple.Finder" 2>&1)
    if [[ -n "$test_result" && ! "$test_result" == *"Could not find"* ]]; then
        controllable="user_services"
    fi

    # Check if we have any disabled services we could enable
    local disabled
    disabled=$(launchctl print-disabled "user/$(id -u)" 2>/dev/null | grep -c "true")
    disabled=$(to_int "$disabled")

    if [[ $disabled -gt 0 ]]; then
        controllable="${controllable:+$controllable+}disabled:$disabled"
    fi

    debug "check_service_controllability: $controllable"
    echo "$controllable"
}

# =============================================================================
# Sensitive Service Detection
# =============================================================================

# Check for sensitive services that are running
detect_sensitive_services() {
    debug "detect_sensitive_services: starting"

    local found=""

    # Check via launchctl list
    local services
    services=$(launchctl list 2>/dev/null)

    if [[ -z "$services" ]]; then
        return 1
    fi

    # Check each sensitive pattern
    for pattern in "${SENSITIVE_SERVICE_PATTERNS[@]}"; do
        local name search
        name=$(echo "$pattern" | cut -d: -f1)
        search=$(echo "$pattern" | cut -d: -f2)

        if echo "$services" | grep -qi "$search"; then
            found="${found:+$found+}$name"
        fi
    done

    # Also check for common services via process list or ports
    # SSH
    if lsof -i :22 2>/dev/null | grep -q LISTEN; then
        [[ ! "$found" == *"ssh"* ]] && found="${found:+$found+}ssh"
    fi

    # Screen sharing / VNC
    if lsof -i :5900 2>/dev/null | grep -q LISTEN; then
        [[ ! "$found" == *"vnc"* ]] && found="${found:+$found+}vnc"
    fi

    # ARD
    if lsof -i :3283 2>/dev/null | grep -q LISTEN; then
        [[ ! "$found" == *"ard"* ]] && found="${found:+$found+}ard"
    fi

    debug "detect_sensitive_services: $found"
    echo "$found"
}

# =============================================================================
# Login Items Detection
# =============================================================================

# Detect login items (persistence mechanism)
detect_login_items() {
    debug "detect_login_items: starting"

    local items=""

    # Method 1: osascript (may require permissions)
    if has_cmd osascript; then
        local login_items
        login_items=$(with_timeout 5 osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null)
        if [[ -n "$login_items" && "$login_items" != *"error"* ]]; then
            local count
            count=$(echo "$login_items" | tr ',' '\n' | wc -l | tr -d ' ')
            count=$(to_int "$count")
            [[ $count -gt 0 ]] && items="osascript:$count"
        fi
    fi

    # Method 2: Check BTM (Background Task Management) - macOS 13+
    if has_cmd sfltool; then
        local btm_items
        btm_items=$(sfltool dumpbtm 2>/dev/null | grep -c "itemType")
        btm_items=$(to_int "$btm_items")
        [[ $btm_items -gt 0 ]] && items="${items:+$items+}btm:$btm_items"
    fi

    # Method 3: Check LaunchAgents directories
    local launch_agents=0
    for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents"; do
        if [[ -d "$dir" && -r "$dir" ]]; then
            local count
            count=$(ls -1 "$dir"/*.plist 2>/dev/null | wc -l | tr -d ' ')
            count=$(to_int "$count")
            launch_agents=$((launch_agents + count))
        fi
    done
    [[ $launch_agents -gt 0 ]] && items="${items:+$items+}agents:$launch_agents"

    debug "detect_login_items: $items"
    echo "$items"
}

# =============================================================================
# XPC Service Detection
# =============================================================================

# Detect XPC services we can communicate with
detect_xpc_services() {
    debug "detect_xpc_services: starting"

    local accessible=""

    # Check if we can query some common XPC services
    # This is a lightweight check - not actually connecting

    # Check launchd print for XPC services
    local xpc_count
    xpc_count=$(launchctl print "user/$(id -u)" 2>/dev/null | grep -c "com.apple" | tr -d ' ')
    xpc_count=$(to_int "$xpc_count")

    if [[ $xpc_count -gt 0 ]]; then
        accessible="apple:$xpc_count"
    fi

    # Check for third-party XPC services
    local third_party
    third_party=$(launchctl print "user/$(id -u)" 2>/dev/null | grep -v "com.apple" | grep -c "com\." | tr -d ' ')
    third_party=$(to_int "$third_party")

    if [[ $third_party -gt 0 ]]; then
        accessible="${accessible:+$accessible+}third_party:$third_party"
    fi

    debug "detect_xpc_services: $accessible"
    echo "$accessible"
}

# =============================================================================
# Main Scanners
# =============================================================================

scan_services_launchd() {
    debug "scan_services_launchd: starting"

    local details=""
    local status="blocked"
    local severity="low"

    # User services
    local user_services
    user_services=$(enumerate_user_services)
    if [[ -n "$user_services" ]]; then
        details="user:$user_services"
        status="exposed"
    fi

    # System services visibility
    local system_services
    system_services=$(enumerate_system_services)
    if [[ -n "$system_services" ]]; then
        details="${details:+$details,}system:$system_services"
        status="exposed"
        severity="medium"
    fi

    # Service visibility level
    local visibility
    visibility=$(check_service_visibility)
    if [[ -n "$visibility" ]]; then
        details="${details:+$details,}visibility:$visibility"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "services_launchd" "blocked" "" "low"
    else
        emit "intelligence" "services_launchd" "$status" "$details" "$severity"
    fi

    debug "scan_services_launchd: $status - $details"
}

scan_services_sensitive() {
    debug "scan_services_sensitive: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local sensitive
    sensitive=$(detect_sensitive_services)
    if [[ -n "$sensitive" ]]; then
        details="running:$sensitive"
        status="exposed"
        severity="high"  # Sensitive services = high risk
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "services_sensitive" "blocked" "" "low"
    else
        emit "intelligence" "services_sensitive" "$status" "$details" "$severity"
    fi

    debug "scan_services_sensitive: $status - $details"
}

scan_services_control() {
    debug "scan_services_control: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local controllable
    controllable=$(check_service_controllability)
    if [[ -n "$controllable" ]]; then
        details="$controllable"
        status="exposed"
        severity="high"  # Can control services = high risk
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "services_control" "blocked" "" "low"
    else
        emit "intelligence" "services_control" "$status" "$details" "$severity"
    fi

    debug "scan_services_control: $status - $details"
}

scan_services_persistence() {
    debug "scan_services_persistence: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local login_items
    login_items=$(detect_login_items)
    if [[ -n "$login_items" ]]; then
        details="$login_items"
        status="exposed"
        severity="medium"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "services_persistence" "blocked" "" "low"
    else
        emit "intelligence" "services_persistence" "$status" "$details" "$severity"
    fi

    debug "scan_services_persistence: $status - $details"
}

# =============================================================================
# Main Scanner
# =============================================================================

scan_intel_services() {
    debug "scan_intel_services: starting"

    scan_services_launchd
    scan_services_sensitive
    scan_services_control
    scan_services_persistence

    debug "scan_intel_services: complete"
}

# =============================================================================
# Runner
# =============================================================================

run_intel_services_tests() {
    debug "run_intel_services_tests: starting (darwin)"
    progress_start "intel_services"
    scan_intel_services
    progress_end "intel_services"
    debug "run_intel_services_tests: complete"
}
