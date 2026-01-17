#!/bin/bash
# SandboxScore - Intelligence Module - Network Topology (macOS)
#
# Discovers network topology and active connections.
# Focus: What can an agent learn about the local network?
#
# Intelligence gathered:
#   - Local IP addresses (reveals network segments)
#   - Active connections (reveals services in use)
#   - Listening ports (reveals attack surface)
#   - LAN devices (via ARP, connections)
#   - VPN/tunnel presence
#
# Requires: common.sh to be sourced first

# =============================================================================
# Local IP Discovery
# =============================================================================

# Get local IP addresses
# Returns: comma-separated list of IPs
discover_local_ips() {
    debug "discover_local_ips: starting"

    local ips=""

    # Method 1: ifconfig (macOS native)
    if has_cmd ifconfig; then
        local ifconfig_ips
        ifconfig_ips=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print $2}')
        for ip in $ifconfig_ips; do
            ips="${ips:+$ips,}$ip"
        done
    fi

    # Method 2: Check via route (get primary IP)
    if [[ -z "$ips" ]] && has_cmd route; then
        local primary_ip
        primary_ip=$(route get default 2>/dev/null | grep "interface:" | awk '{print $2}')
        if [[ -n "$primary_ip" ]]; then
            local ip
            ip=$(ifconfig "$primary_ip" 2>/dev/null | grep "inet " | awk '{print $2}')
            [[ -n "$ip" ]] && ips="$ip"
        fi
    fi

    debug "discover_local_ips: found $ips"
    echo "$ips"
}

# Get IPv6 addresses
discover_local_ipv6() {
    debug "discover_local_ipv6: starting"

    local ips=""

    if has_cmd ifconfig; then
        local ifconfig_ips
        # Get global IPv6 addresses (not link-local fe80::)
        ifconfig_ips=$(ifconfig 2>/dev/null | grep "inet6" | grep -v "fe80:" | grep -v "::1" | awk '{print $2}')
        for ip in $ifconfig_ips; do
            # Truncate long IPv6 addresses for readability
            local short_ip="${ip:0:20}"
            [[ ${#ip} -gt 20 ]] && short_ip="${short_ip}..."
            ips="${ips:+$ips,}$short_ip"
        done
    fi

    debug "discover_local_ipv6: found $ips"
    echo "$ips"
}

# Classify IP address
classify_ip() {
    local ip="$1"

    case "$ip" in
        10.*) echo "private_10" ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) echo "private_172" ;;
        192.168.*) echo "private_192" ;;
        169.254.*) echo "link_local" ;;
        127.*) echo "loopback" ;;
        *) echo "public" ;;
    esac
}

# =============================================================================
# Active Connections Discovery
# =============================================================================

# Get active external connections
# Returns: service names or IPs we're connected to
discover_active_connections() {
    debug "discover_active_connections: starting"

    local connections=""

    if ! has_cmd lsof; then
        debug "discover_active_connections: lsof not available"
        return 1
    fi

    # Get established connections, extract remote addresses
    local lsof_output
    lsof_output=$(with_timeout 10 lsof -i -n -P 2>/dev/null | grep "ESTABLISHED")

    if [[ -z "$lsof_output" ]]; then
        debug "discover_active_connections: no established connections or blocked"
        return 1
    fi

    # Extract unique remote IPs/hostnames
    local remotes
    remotes=$(echo "$lsof_output" | awk '{print $9}' | grep -- "->" | sed 's/.*->//' | cut -d: -f1 | sort -u)

    # Identify known services by IP patterns or reverse DNS
    local services=""
    local ip_count=0
    local known_count=0

    while IFS= read -r remote; do
        [[ -z "$remote" ]] && continue
        ip_count=$((ip_count + 1))

        # Try to identify by known IP ranges or patterns
        local service=""
        case "$remote" in
            # Apple
            17.*) service="apple" ;;
            # Google
            142.250.*|172.217.*|216.58.*|74.125.*) service="google" ;;
            # Cloudflare
            104.16.*|104.17.*|104.18.*|104.19.*|104.20.*|104.21.*|104.22.*|104.23.*|104.24.*|104.25.*|104.26.*) service="cloudflare" ;;
            # Amazon
            52.*|54.*|34.*|35.*|3.*) service="aws" ;;
            # Microsoft
            40.*|52.*|13.*|20.*) service="microsoft" ;;
            # Tailscale
            100.64.*|100.65.*|100.66.*|100.67.*|100.68.*|100.69.*|100.7*|100.8*|100.9*|100.1[0-2]*) service="tailscale" ;;
        esac

        if [[ -n "$service" ]]; then
            if [[ ! "$services" == *"$service"* ]]; then
                services="${services:+$services+}$service"
                known_count=$((known_count + 1))
            fi
        fi
    done <<< "$remotes"

    # Build result
    local result=""
    [[ -n "$services" ]] && result="services:$services"
    result="${result:+$result,}ips:$ip_count"

    debug "discover_active_connections: $result"
    echo "$result"
}

# Identify active applications by their connections
discover_connected_apps() {
    debug "discover_connected_apps: starting"

    if ! has_cmd lsof; then
        return 1
    fi

    local lsof_output
    lsof_output=$(with_timeout 10 lsof -i -n -P 2>/dev/null | grep -E "ESTABLISHED|UDP")

    if [[ -z "$lsof_output" ]]; then
        return 1
    fi

    # Get unique process names with network connections
    local apps
    apps=$(echo "$lsof_output" | awk '{print $1}' | sort -u | head -20)

    local app_list=""
    local count=0

    while IFS= read -r app; do
        [[ -z "$app" ]] && continue
        count=$((count + 1))

        # Identify interesting apps
        case "$app" in
            Spotify|spotify) app_list="${app_list:+$app_list+}spotify" ;;
            Slack|slack) app_list="${app_list:+$app_list+}slack" ;;
            Discord|discord) app_list="${app_list:+$app_list+}discord" ;;
            Telegram|telegram) app_list="${app_list:+$app_list+}telegram" ;;
            zoom*|Zoom*) app_list="${app_list:+$app_list+}zoom" ;;
            Teams|teams) app_list="${app_list:+$app_list+}teams" ;;
            Chrome|chrome|Google*) app_list="${app_list:+$app_list+}chrome" ;;
            Safari|safari) app_list="${app_list:+$app_list+}safari" ;;
            Firefox|firefox) app_list="${app_list:+$app_list+}firefox" ;;
            Brave*|brave*) app_list="${app_list:+$app_list+}brave" ;;
            curl|wget|httpie) app_list="${app_list:+$app_list+}cli_http" ;;
            ssh|sshd) app_list="${app_list:+$app_list+}ssh" ;;
            docker|Docker|com.docke) app_list="${app_list:+$app_list+}docker" ;;
            kubectl) app_list="${app_list:+$app_list+}kubectl" ;;
            tailscal*|Tailscal*) app_list="${app_list:+$app_list+}tailscale" ;;
        esac
    done <<< "$apps"

    debug "discover_connected_apps: $count apps, known: $app_list"
    echo "total:$count${app_list:+,apps:$app_list}"
}

# =============================================================================
# Listening Ports Discovery
# =============================================================================

# Get listening ports and services
discover_listening_ports() {
    debug "discover_listening_ports: starting"

    if ! has_cmd lsof; then
        debug "discover_listening_ports: lsof not available"
        return 1
    fi

    local lsof_output
    lsof_output=$(with_timeout 10 lsof -i -n -P 2>/dev/null | grep "LISTEN")

    if [[ -z "$lsof_output" ]]; then
        debug "discover_listening_ports: no listeners or blocked"
        return 1
    fi

    # Count listeners and identify interesting ones
    local all_listeners=""
    local interesting=""
    local count=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        count=$((count + 1))

        local proc port
        proc=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | awk '{print $9}' | sed 's/.*://')

        # Track interesting listeners
        case "$proc:$port" in
            *:22) interesting="${interesting:+$interesting+}ssh:22" ;;
            *:80) interesting="${interesting:+$interesting+}http:80" ;;
            *:443) interesting="${interesting:+$interesting+}https:443" ;;
            *:3283) interesting="${interesting:+$interesting+}ard:3283" ;;
            *:5900) interesting="${interesting:+$interesting+}vnc:5900" ;;
            *:3306) interesting="${interesting:+$interesting+}mysql:3306" ;;
            *:5432) interesting="${interesting:+$interesting+}postgres:5432" ;;
            *:6379) interesting="${interesting:+$interesting+}redis:6379" ;;
            *:27017) interesting="${interesting:+$interesting+}mongo:27017" ;;
            *:9200) interesting="${interesting:+$interesting+}elastic:9200" ;;
            *:11434) interesting="${interesting:+$interesting+}ollama:11434" ;;
            *:8080) interesting="${interesting:+$interesting+}proxy:8080" ;;
            *:9090) interesting="${interesting:+$interesting+}metrics:9090" ;;
        esac
    done <<< "$lsof_output"

    local result="count:$count"
    [[ -n "$interesting" ]] && result="${result},services:$interesting"

    debug "discover_listening_ports: $result"
    echo "$result"
}

# =============================================================================
# LAN Topology Discovery
# =============================================================================

# Discover devices on LAN via ARP table
discover_lan_devices() {
    debug "discover_lan_devices: starting"

    local devices=""
    local count=0

    # Method 1: ARP table
    if has_cmd arp; then
        local arp_output
        arp_output=$(with_timeout 5 arp -a 2>/dev/null)

        if [[ -n "$arp_output" ]]; then
            # Count unique IPs (exclude incomplete entries)
            count=$(echo "$arp_output" | grep -v "incomplete" | grep -c "at")
            count=$(to_int "$count")
        fi
    fi

    # Method 2: Check connections to local IPs
    if has_cmd lsof && [[ $count -eq 0 ]]; then
        local local_conns
        local_conns=$(lsof -i -n -P 2>/dev/null | grep -E "192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\." | wc -l)
        count=$(to_int "$local_conns")
    fi

    if [[ $count -gt 0 ]]; then
        debug "discover_lan_devices: found $count devices"
        echo "$count"
        return 0
    fi

    debug "discover_lan_devices: no LAN devices found"
    return 1
}

# Get gateway information
discover_gateway() {
    debug "discover_gateway: starting"

    local gateway=""

    if has_cmd route; then
        gateway=$(route -n get default 2>/dev/null | grep "gateway:" | awk '{print $2}')
    fi

    if [[ -z "$gateway" ]] && has_cmd netstat; then
        gateway=$(netstat -rn 2>/dev/null | grep "^default" | awk '{print $2}' | head -1)
    fi

    debug "discover_gateway: $gateway"
    echo "$gateway"
}

# =============================================================================
# VPN/Tunnel Detection
# =============================================================================

# Detect VPN and tunnel interfaces
detect_vpn_tunnel() {
    debug "detect_vpn_tunnel: starting"

    local vpns=""
    local has_utun=0
    local has_tun=0
    local has_wg=0

    # Check interface names for VPN patterns
    if has_cmd ifconfig; then
        local interfaces
        interfaces=$(ifconfig -l 2>/dev/null)

        for iface in $interfaces; do
            case "$iface" in
                utun*)
                    has_utun=1
                    ;;
                tun*|tap*)
                    has_tun=1
                    ;;
                wg*)
                    has_wg=1
                    ;;
                ipsec*)
                    vpns="${vpns:+$vpns+}ipsec"
                    ;;
            esac
        done
    fi

    # Check for Tailscale specifically
    local is_tailscale=0
    if has_cmd tailscale; then
        local ts_status
        ts_status=$(tailscale status 2>/dev/null | head -1)
        if [[ -n "$ts_status" && ! "$ts_status" =~ "stopped" ]]; then
            is_tailscale=1
            vpns="${vpns:+$vpns+}tailscale"
        fi
    fi

    # Add generic utun if not identified as tailscale
    if [[ $has_utun -eq 1 && $is_tailscale -eq 0 ]]; then
        vpns="${vpns:+$vpns+}utun"
    fi

    # Add other VPN types
    [[ $has_tun -eq 1 ]] && vpns="${vpns:+$vpns+}openvpn"
    [[ $has_wg -eq 1 ]] && vpns="${vpns:+$vpns+}wireguard"

    # Check for active VPN connections via lsof
    if has_cmd lsof && [[ -z "$vpns" ]]; then
        local vpn_procs
        vpn_procs=$(lsof -i -n -P 2>/dev/null | grep -iE "wireguard|openvpn|tailscale|nordvpn|expressvpn|mullvad" | head -1)
        if [[ -n "$vpn_procs" ]]; then
            local vpn_name
            vpn_name=$(echo "$vpn_procs" | awk '{print tolower($1)}')
            vpns="${vpns:+$vpns+}$vpn_name"
        fi
    fi

    debug "detect_vpn_tunnel: $vpns"
    echo "$vpns"
}

# =============================================================================
# Network Interface Details
# =============================================================================

# Get network interface summary
discover_interfaces() {
    debug "discover_interfaces: starting"

    local iface_count=0
    local wifi=""
    local ethernet=""

    if has_cmd ifconfig; then
        # Count active interfaces (have inet address)
        iface_count=$(ifconfig 2>/dev/null | grep -c "inet " | tr -d ' ')

        # Check for WiFi (en0 is typically WiFi on Mac)
        if ifconfig en0 2>/dev/null | grep -q "status: active"; then
            wifi="active"
            # Try to get SSID (may fail if not WiFi or no permission)
            if has_cmd networksetup; then
                local ssid_output
                ssid_output=$(networksetup -getairportnetwork en0 2>/dev/null)
                if [[ "$ssid_output" == "Current Wi-Fi Network:"* ]]; then
                    local ssid="${ssid_output#Current Wi-Fi Network: }"
                    # Truncate long SSIDs
                    [[ ${#ssid} -gt 15 ]] && ssid="${ssid:0:12}..."
                    wifi="active:$ssid"
                fi
            fi
        fi

        # Check for Ethernet
        if ifconfig en1 2>/dev/null | grep -q "status: active" || \
           ifconfig en5 2>/dev/null | grep -q "status: active"; then
            ethernet="active"
        fi
    fi

    local result="count:$iface_count"
    [[ -n "$wifi" ]] && result="${result},wifi:$wifi"
    [[ -n "$ethernet" ]] && result="${result},ethernet:$ethernet"

    debug "discover_interfaces: $result"
    echo "$result"
}

# =============================================================================
# Main Scanners
# =============================================================================

scan_network_topology() {
    debug "scan_network_topology: starting"

    local details=""
    local status="blocked"
    local severity="low"

    # Local IPs
    local local_ips
    local_ips=$(discover_local_ips)
    if [[ -n "$local_ips" ]]; then
        # Count and classify
        local ip_count
        ip_count=$(echo "$local_ips" | tr ',' '\n' | wc -l | tr -d ' ')
        local first_ip
        first_ip=$(echo "$local_ips" | cut -d',' -f1)
        local ip_class
        ip_class=$(classify_ip "$first_ip")

        details="ips:$ip_count($ip_class)"
        status="exposed"
    fi

    # Gateway
    local gateway
    gateway=$(discover_gateway)
    if [[ -n "$gateway" ]]; then
        details="${details:+$details,}gw:$gateway"
        status="exposed"
    fi

    # Interfaces
    local interfaces
    interfaces=$(discover_interfaces)
    if [[ -n "$interfaces" ]]; then
        details="${details:+$details,}iface:$interfaces"
    fi

    # VPN detection
    local vpn
    vpn=$(detect_vpn_tunnel)
    if [[ -n "$vpn" ]]; then
        details="${details:+$details,}vpn:$vpn"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "network_topology" "blocked" "" "low"
    else
        emit "intelligence" "network_topology" "$status" "$details" "$severity"
    fi

    debug "scan_network_topology: $status - $details"
}

scan_network_connections() {
    debug "scan_network_connections: starting"

    local details=""
    local status="blocked"
    local severity="low"

    # Active connections
    local connections
    connections=$(discover_active_connections)
    if [[ -n "$connections" ]]; then
        details="$connections"
        status="exposed"
        severity="medium"
    fi

    # Connected apps
    local apps
    apps=$(discover_connected_apps)
    if [[ -n "$apps" ]]; then
        details="${details:+$details,}$apps"
        status="exposed"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "network_connections" "blocked" "" "low"
    else
        emit "intelligence" "network_connections" "$status" "$details" "$severity"
    fi

    debug "scan_network_connections: $status - $details"
}

scan_intel_listeners() {
    debug "scan_intel_listeners: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local listeners
    listeners=$(discover_listening_ports)
    if [[ -n "$listeners" ]]; then
        details="$listeners"
        status="exposed"
        severity="high"  # Listening ports = attack surface
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "network_listeners" "blocked" "" "low"
    else
        emit "intelligence" "network_listeners" "$status" "$details" "$severity"
    fi

    debug "scan_intel_listeners: $status - $details"
}

scan_network_lan() {
    debug "scan_network_lan: starting"

    local details=""
    local status="blocked"
    local severity="low"

    local lan_count
    lan_count=$(discover_lan_devices)
    if [[ -n "$lan_count" && "$lan_count" -gt 0 ]]; then
        details="devices:$lan_count"
        status="exposed"
        severity="medium"
    fi

    if [[ -z "$details" ]]; then
        emit "intelligence" "network_lan" "blocked" "" "low"
    else
        emit "intelligence" "network_lan" "$status" "$details" "$severity"
    fi

    debug "scan_network_lan: $status - $details"
}

# =============================================================================
# Main Scanner
# =============================================================================

scan_intel_network() {
    debug "scan_intel_network: starting"

    scan_network_topology
    scan_network_connections
    scan_intel_listeners
    scan_network_lan

    debug "scan_intel_network: complete"
}

# =============================================================================
# Runner
# =============================================================================

run_intel_network_tests() {
    debug "run_intel_network_tests: starting (darwin)"
    progress_start "intel_network"
    scan_intel_network
    progress_end "intel_network"
    debug "run_intel_network_tests: complete"
}
