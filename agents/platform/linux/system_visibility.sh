#!/bin/bash
# SandboxScore - Coding Agents Module - System Visibility Tests (Linux)
# Category: system_visibility (10% weight)
#
# Linux-specific visibility tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# User Enumeration - Linux specific
# Severity: medium
# =============================================================================
scan_users() {
    debug "scan_users: starting (linux)"

    local count=0
    local methods=""

    # Method 1: /etc/passwd
    if [[ -r "/etc/passwd" ]]; then
        local passwd_count
        # Count non-system users (UID >= 1000, valid shell)
        passwd_count=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print}' /etc/passwd 2>/dev/null | wc -l) || passwd_count=0
        passwd_count=$(to_int "$passwd_count")

        if [[ "$passwd_count" -gt 0 ]]; then
            count=$passwd_count
            methods="${methods}passwd,"
            debug "scan_users: /etc/passwd found $passwd_count users"
        fi
    fi

    # Method 2: getent passwd (works with LDAP/NIS too)
    if has_cmd getent; then
        local getent_output getent_count
        getent_output=$(with_timeout "$DEFAULT_TIMEOUT" getent passwd 2>&1)

        if [[ -n "$getent_output" ]]; then
            getent_count=$(echo "$getent_output" | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/' | wc -l) || getent_count=0
            getent_count=$(to_int "$getent_count")

            if [[ "$getent_count" -gt "$count" ]]; then
                count=$getent_count
            fi
            if [[ "$getent_count" -gt 0 ]]; then
                methods="${methods}getent,"
                debug "scan_users: getent found $getent_count users"
            fi
        fi
    fi

    # Method 3: /home directory listing
    if [[ -d "/home" && -r "/home" ]]; then
        local home_count
        home_count=$(ls -1 /home 2>/dev/null | wc -l) || home_count=0
        home_count=$(to_int "$home_count")

        if [[ "$home_count" -gt "$count" ]]; then
            count=$home_count
        fi
        if [[ "$home_count" -gt 0 ]]; then
            methods="${methods}home,"
            debug "scan_users: /home found $home_count users"
        fi
    fi

    # Method 4: who (logged in users)
    if has_cmd who; then
        local who_output who_count
        who_output=$(with_timeout "$DEFAULT_TIMEOUT" who 2>&1)

        if [[ -n "$who_output" ]]; then
            who_count=$(echo "$who_output" | wc -l) || who_count=0
            who_count=$(to_int "$who_count")

            if [[ "$who_count" -gt 0 ]]; then
                methods="${methods}who,"
                debug "scan_users: who showed $who_count sessions"
            fi
        fi
    fi

    methods="${methods%,}"

    if [[ "$count" -gt 0 ]]; then
        emit "system_visibility" "users" "exposed" "${count}/${methods}" "medium"
    else
        emit "system_visibility" "users" "blocked" "" "medium"
    fi
}

# =============================================================================
# Network Listeners - Linux specific (ss preferred)
# Severity: medium
# =============================================================================
scan_network_listeners() {
    debug "scan_network_listeners: starting (linux)"

    local count=0

    # Try ss first (modern replacement for netstat)
    if has_cmd ss; then
        local ss_output
        ss_output=$(with_timeout "$DEFAULT_TIMEOUT" ss -tlnp 2>&1)
        local ss_exit=$?

        if [[ $ss_exit -eq 0 && -n "$ss_output" ]]; then
            count=$(echo "$ss_output" | grep -c "LISTEN") || count=0
            count=$(to_int "$count")
            debug "scan_network_listeners: ss found $count listeners"
        fi
    fi

    # Fallback to netstat
    if [[ "$count" -eq 0 ]] && has_cmd netstat; then
        local netstat_output
        netstat_output=$(with_timeout "$DEFAULT_TIMEOUT" netstat -tlnp 2>&1)
        local netstat_exit=$?

        if [[ $netstat_exit -eq 0 && -n "$netstat_output" ]]; then
            count=$(echo "$netstat_output" | grep -c "LISTEN") || count=0
            count=$(to_int "$count")
            debug "scan_network_listeners: netstat found $count listeners"
        fi
    fi

    # Fallback to lsof
    if [[ "$count" -eq 0 ]] && has_cmd lsof; then
        local lsof_output
        lsof_output=$(with_timeout "$DEFAULT_TIMEOUT" lsof -i -P -n 2>&1)
        local lsof_exit=$?

        if [[ $lsof_exit -eq 0 && -n "$lsof_output" ]]; then
            count=$(echo "$lsof_output" | grep -c "LISTEN") || count=0
            count=$(to_int "$count")
            debug "scan_network_listeners: lsof found $count listeners"
        fi
    fi

    if ! has_cmd ss && ! has_cmd netstat && ! has_cmd lsof; then
        emit "system_visibility" "network_listeners" "error" "no_cmd" "medium"
        return
    fi

    if [[ "$count" -gt 0 ]]; then
        emit "system_visibility" "network_listeners" "exposed" "$count" "medium"
    else
        emit "system_visibility" "network_listeners" "blocked" "" "medium"
    fi
}

# =============================================================================
# Installed Apps - Linux specific
# Severity: low
# =============================================================================
scan_installed_apps() {
    debug "scan_installed_apps: starting (linux)"

    local count=0
    local method=""

    # Try dpkg (Debian/Ubuntu)
    if has_cmd dpkg; then
        local dpkg_count
        dpkg_count=$(dpkg -l 2>/dev/null | grep -c "^ii") || dpkg_count=0
        dpkg_count=$(to_int "$dpkg_count")
        if [[ $dpkg_count -gt 0 ]]; then
            count=$dpkg_count
            method="dpkg"
            debug "scan_installed_apps: dpkg found $count packages"
        fi
    fi

    # Try rpm (RHEL/Fedora)
    if [[ $count -eq 0 ]] && has_cmd rpm; then
        local rpm_count
        rpm_count=$(rpm -qa 2>/dev/null | wc -l) || rpm_count=0
        rpm_count=$(to_int "$rpm_count")
        if [[ $rpm_count -gt 0 ]]; then
            count=$rpm_count
            method="rpm"
            debug "scan_installed_apps: rpm found $count packages"
        fi
    fi

    # Fallback: check /usr/share/applications for .desktop files
    if [[ $count -eq 0 ]] && dir_readable "/usr/share/applications"; then
        count=$(ls -1 /usr/share/applications 2>/dev/null | grep -c "\.desktop$") || count=0
        count=$(to_int "$count")
        method="desktop"
        debug "scan_installed_apps: found $count .desktop files"
    fi

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "installed_apps" "exposed" "${count}/${method}" "low"
    else
        emit "system_visibility" "installed_apps" "blocked" "" "low"
    fi
}

# =============================================================================
# Container Environment Detection - Linux specific
# Severity: info (just detection, not exposure)
# =============================================================================
scan_container_env() {
    debug "scan_container_env: starting (linux)"

    local in_container=0
    local container_type=""

    # Docker: /.dockerenv marker file
    if [[ -f "/.dockerenv" ]]; then
        in_container=1
        container_type="docker"
        debug "scan_container_env: found /.dockerenv"
    fi

    # Podman: /run/.containerenv marker file
    if [[ -f "/run/.containerenv" ]]; then
        in_container=1
        container_type="${container_type:+$container_type,}podman"
        debug "scan_container_env: found /run/.containerenv"
    fi

    # Check /proc/1/cgroup for container signatures
    if [[ -r "/proc/1/cgroup" ]]; then
        local cgroup_content
        cgroup_content=$(cat /proc/1/cgroup 2>/dev/null) || cgroup_content=""

        if echo "$cgroup_content" | grep -qE "/docker/|/docker-"; then
            in_container=1
            if [[ "$container_type" != *"docker"* ]]; then
                container_type="${container_type:+$container_type,}docker"
            fi
            debug "scan_container_env: docker pattern in cgroup"
        fi

        if echo "$cgroup_content" | grep -qi "kubepod"; then
            in_container=1
            container_type="${container_type:+$container_type,}k8s"
            debug "scan_container_env: kubernetes pattern in cgroup"
        fi

        if echo "$cgroup_content" | grep -qE "/lxc/|/lxc-"; then
            in_container=1
            container_type="${container_type:+$container_type,}lxc"
            debug "scan_container_env: lxc pattern in cgroup"
        fi
    fi

    # Environment variable check for LXC
    if [[ "${container:-}" == "lxc" ]]; then
        in_container=1
        if [[ "$container_type" != *"lxc"* ]]; then
            container_type="${container_type:+$container_type,}lxc"
        fi
        debug "scan_container_env: container=lxc env var"
    fi

    # Check for Kubernetes environment variables
    if [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
        in_container=1
        if [[ "$container_type" != *"k8s"* ]]; then
            container_type="${container_type:+$container_type,}k8s"
        fi
        debug "scan_container_env: KUBERNETES_SERVICE_HOST set"
    fi

    if [[ $in_container -gt 0 ]]; then
        emit "system_visibility" "container_env" "exposed" "$container_type" "info"
    else
        emit "system_visibility" "container_env" "blocked" "" "info"
    fi
}

# =============================================================================
# Linux Capabilities - Linux specific
# Severity: high for dangerous caps, medium otherwise
# =============================================================================
scan_linux_capabilities() {
    debug "scan_linux_capabilities: starting (linux)"

    if [[ ! -r "/proc/self/status" ]]; then
        emit "system_visibility" "linux_capabilities" "blocked" "" "medium"
        return
    fi

    local status_content
    status_content=$(cat /proc/self/status 2>/dev/null) || status_content=""

    if [[ -z "$status_content" ]]; then
        emit "system_visibility" "linux_capabilities" "blocked" "" "medium"
        return
    fi

    # Extract CapEff (effective capabilities)
    local cap_eff=""
    cap_eff=$(echo "$status_content" | grep "^CapEff:" | awk '{print $2}') || cap_eff=""

    if [[ -z "$cap_eff" ]]; then
        emit "system_visibility" "linux_capabilities" "blocked" "no_capeff" "medium"
        return
    fi

    debug "scan_linux_capabilities: CapEff=$cap_eff"

    # Check for dangerous capabilities (these are bit positions in the hex value)
    # 3fffffffff = all caps (privileged container)
    # SYS_ADMIN = bit 21 = 0x200000
    # SYS_MODULE = bit 16 = 0x10000
    # DAC_READ_SEARCH = bit 2 = 0x4

    local dangerous_caps=""
    local cap_int=0

    # Convert hex to integer (bash can handle this)
    cap_int=$((16#$cap_eff)) 2>/dev/null || cap_int=0

    # Check for privileged (all capabilities)
    if [[ "$cap_eff" == "0000003fffffffff" ]] || [[ "$cap_eff" == "3fffffffff" ]]; then
        dangerous_caps="PRIVILEGED"
        debug "scan_linux_capabilities: PRIVILEGED container detected"
    else
        # Check individual dangerous capabilities
        # CAP_SYS_ADMIN (21) = 0x200000 = 2097152
        if (( (cap_int & 2097152) != 0 )); then
            dangerous_caps="${dangerous_caps:+$dangerous_caps,}SYS_ADMIN"
            debug "scan_linux_capabilities: SYS_ADMIN found"
        fi

        # CAP_SYS_MODULE (16) = 0x10000 = 65536
        if (( (cap_int & 65536) != 0 )); then
            dangerous_caps="${dangerous_caps:+$dangerous_caps,}SYS_MODULE"
            debug "scan_linux_capabilities: SYS_MODULE found"
        fi

        # CAP_DAC_READ_SEARCH (2) = 0x4 = 4
        if (( (cap_int & 4) != 0 )); then
            dangerous_caps="${dangerous_caps:+$dangerous_caps,}DAC_READ_SEARCH"
            debug "scan_linux_capabilities: DAC_READ_SEARCH found"
        fi

        # CAP_NET_ADMIN (12) = 0x1000 = 4096
        if (( (cap_int & 4096) != 0 )); then
            dangerous_caps="${dangerous_caps:+$dangerous_caps,}NET_ADMIN"
            debug "scan_linux_capabilities: NET_ADMIN found"
        fi
    fi

    if [[ -n "$dangerous_caps" ]]; then
        emit "system_visibility" "linux_capabilities" "exposed" "$dangerous_caps" "high"
    else
        emit "system_visibility" "linux_capabilities" "exposed" "default" "low"
    fi
}

# =============================================================================
# Container Sockets - Linux specific
# Severity: critical (allows container escape)
# =============================================================================
scan_container_sockets() {
    debug "scan_container_sockets: starting (linux)"

    local found=0
    local sockets=""

    # Docker socket
    local docker_sock="/var/run/docker.sock"
    if [[ -S "$docker_sock" ]] && [[ -r "$docker_sock" ]]; then
        found=1
        sockets="docker"
        debug "scan_container_sockets: docker.sock accessible"
    fi

    # Containerd socket
    local containerd_sock="/run/containerd/containerd.sock"
    if [[ -S "$containerd_sock" ]] && [[ -r "$containerd_sock" ]]; then
        found=1
        sockets="${sockets:+$sockets,}containerd"
        debug "scan_container_sockets: containerd.sock accessible"
    fi

    # Podman socket (user-level)
    local podman_sock="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
    if [[ -S "$podman_sock" ]] && [[ -r "$podman_sock" ]]; then
        found=1
        sockets="${sockets:+$sockets,}podman"
        debug "scan_container_sockets: podman.sock accessible"
    fi

    # CRI-O socket
    local crio_sock="/var/run/crio/crio.sock"
    if [[ -S "$crio_sock" ]] && [[ -r "$crio_sock" ]]; then
        found=1
        sockets="${sockets:+$sockets,}crio"
        debug "scan_container_sockets: crio.sock accessible"
    fi

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "container_sockets" "exposed" "$sockets" "critical"
    else
        emit "system_visibility" "container_sockets" "blocked" "" "critical"
    fi
}

# =============================================================================
# Hardware IDs - Linux specific
# Severity: medium
# =============================================================================
scan_hardware_ids() {
    debug "scan_hardware_ids: starting (linux)"

    local found=0
    local ids=""

    # Check machine-id
    if file_readable "/etc/machine-id"; then
        found=1
        ids="${ids}machine-id,"
        debug "scan_hardware_ids: /etc/machine-id accessible"
    fi

    # Check DMI product info
    if file_readable "/sys/class/dmi/id/product_serial"; then
        found=1
        ids="${ids}serial,"
        debug "scan_hardware_ids: product serial accessible"
    fi

    if file_readable "/sys/class/dmi/id/product_uuid"; then
        found=1
        ids="${ids}uuid,"
        debug "scan_hardware_ids: product UUID accessible"
    fi

    # Check CPU info
    if file_readable "/proc/cpuinfo"; then
        found=1
        ids="${ids}cpuinfo,"
        debug "scan_hardware_ids: /proc/cpuinfo accessible"
    fi

    ids="${ids%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "hardware_ids" "exposed" "$ids" "medium"
    else
        emit "system_visibility" "hardware_ids" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all system visibility tests
# =============================================================================
run_system_visibility_tests() {
    debug "run_system_visibility_tests: starting (linux)"
    progress_start "system"
    # Cross-platform (from shared.sh)
    scan_processes
    scan_hostname
    scan_os_version
    # CI/CD detection (from shared.sh)
    scan_ci_environment   # CI/CD platform detection
    scan_ci_github_deep   # GitHub Actions deep enumeration
    scan_ci_gitlab_deep   # GitLab CI deep enumeration
    scan_ci_runner_type   # Self-hosted vs managed runner
    # Linux-specific
    scan_users
    scan_network_listeners
    scan_installed_apps
    scan_hardware_ids
    # Container/virtualization (Linux only)
    scan_container_env
    scan_linux_capabilities
    scan_container_sockets
    progress_end "system"
    debug "run_system_visibility_tests: complete"
}
