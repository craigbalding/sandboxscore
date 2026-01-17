#!/bin/bash
# SandboxScore - Coding Agents Module - VM/Sandbox Detection Tests (macOS)
# Category: system_visibility
#
# Tests for virtualization and sandbox environment detection:
# - Hypervisor detection (kern.hv_support, VMX)
# - VM software indicators (VMware, VirtualBox, Parallels)
# - Container/virtualization (Docker Desktop, OrbStack)
# - Seatbelt sandbox profiles
# - Rosetta translation
#
# Requires: common.sh to be sourced first

# =============================================================================
# Hypervisor Support Detection
# Severity: medium (reveals if running in VM)
# =============================================================================
scan_hypervisor_support() {
    debug "scan_hypervisor_support: starting"

    if ! has_cmd sysctl; then
        emit "system_visibility" "hypervisor_support" "error" "no_sysctl" "medium"
        return
    fi

    local details=""
    local detected=0

    # Check kern.hv_support (Hypervisor.framework capability)
    local hv_output
    hv_output=$(with_timeout 3 sysctl -n kern.hv_support 2>/dev/null) || hv_output=""
    if [[ "$hv_output" == "1" ]]; then
        details="${details}hv_support,"
        detected=1
        debug "scan_hypervisor_support: kern.hv_support=1"
    fi

    # Check for VMX in CPU features (Intel virtualization)
    local cpu_features
    cpu_features=$(with_timeout 3 sysctl -n machdep.cpu.features 2>/dev/null) || cpu_features=""
    if echo "$cpu_features" | grep -qi "VMX"; then
        details="${details}vmx,"
        detected=1
        debug "scan_hypervisor_support: VMX detected"
    fi

    # Check if running inside a VM (kern.hv_vmm_present)
    local vmm_present
    vmm_present=$(with_timeout 3 sysctl -n kern.hv_vmm_present 2>/dev/null) || vmm_present=""
    if [[ "$vmm_present" == "1" ]]; then
        details="${details}in_vm,"
        detected=1
        debug "scan_hypervisor_support: running inside VM"
    fi

    details="${details%,}"

    if [[ $detected -gt 0 ]]; then
        emit "system_visibility" "hypervisor_support" "exposed" "$details" "medium"
    else
        emit "system_visibility" "hypervisor_support" "blocked" "" "medium"
    fi
}

# =============================================================================
# VM Software Detection (VMware, VirtualBox, Parallels, QEMU)
# Severity: medium (reveals virtualization platform)
# =============================================================================
scan_vm_indicators() {
    debug "scan_vm_indicators: starting"

    local detected=""
    local found=0

    # Check ioreg for VM indicators
    if has_cmd ioreg; then
        local ioreg_output
        ioreg_output=$(with_timeout 5 ioreg -l 2>/dev/null | head -500) || ioreg_output=""

        if echo "$ioreg_output" | grep -qi "vmware"; then
            detected="${detected}vmware,"
            found=1
            debug "scan_vm_indicators: VMware detected via ioreg"
        fi
        if echo "$ioreg_output" | grep -qi "virtualbox"; then
            detected="${detected}virtualbox,"
            found=1
            debug "scan_vm_indicators: VirtualBox detected via ioreg"
        fi
        if echo "$ioreg_output" | grep -qi "parallels"; then
            detected="${detected}parallels,"
            found=1
            debug "scan_vm_indicators: Parallels detected via ioreg"
        fi
        if echo "$ioreg_output" | grep -qi "qemu"; then
            detected="${detected}qemu,"
            found=1
            debug "scan_vm_indicators: QEMU detected via ioreg"
        fi
    fi

    # Check system_profiler for VM hardware model
    if has_cmd system_profiler; then
        local hw_output
        hw_output=$(with_timeout 10 system_profiler SPHardwareDataType 2>/dev/null) || hw_output=""

        local model_id
        model_id=$(echo "$hw_output" | grep "Model Identifier" | cut -d: -f2 | tr -d ' ') || model_id=""

        if [[ -n "$model_id" ]]; then
            # Virtual machines often have specific model identifiers
            if echo "$model_id" | grep -qiE "Virtual|VM"; then
                detected="${detected}hw_model:$model_id,"
                found=1
            fi
        fi
    fi

    # Check for VM-specific kexts
    if has_cmd kextstat; then
        local kext_output
        kext_output=$(with_timeout 5 kextstat 2>/dev/null) || kext_output=""

        if echo "$kext_output" | grep -qi "vmware"; then
            detected="${detected}vmware_kext,"
            found=1
        fi
        if echo "$kext_output" | grep -qi "vbox"; then
            detected="${detected}vbox_kext,"
            found=1
        fi
        if echo "$kext_output" | grep -qi "parallels"; then
            detected="${detected}parallels_kext,"
            found=1
        fi
    fi

    detected="${detected%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "vm_indicators" "exposed" "$detected" "medium"
    else
        emit "system_visibility" "vm_indicators" "blocked" "" "medium"
    fi
}

# =============================================================================
# Container Runtime Detection (Docker Desktop, OrbStack, Colima)
# Severity: low (reveals dev environment)
# =============================================================================
scan_container_runtimes() {
    debug "scan_container_runtimes: starting"

    local detected=""
    local found=0

    # Check for Docker Desktop
    if pgrep -q "Docker Desktop" 2>/dev/null || pgrep -q "com.docker" 2>/dev/null; then
        detected="${detected}docker_desktop,"
        found=1
        debug "scan_container_runtimes: Docker Desktop running"
    fi

    # Check for OrbStack
    if pgrep -q "OrbStack" 2>/dev/null; then
        detected="${detected}orbstack,"
        found=1
        debug "scan_container_runtimes: OrbStack running"
    fi

    # Check for Colima
    if pgrep -q "colima" 2>/dev/null; then
        detected="${detected}colima,"
        found=1
        debug "scan_container_runtimes: Colima running"
    fi

    # Check for Lima
    if pgrep -q "limactl" 2>/dev/null; then
        detected="${detected}lima,"
        found=1
        debug "scan_container_runtimes: Lima running"
    fi

    # Check for docker socket
    if [[ -S "/var/run/docker.sock" ]]; then
        detected="${detected}docker_sock,"
        found=1
        debug "scan_container_runtimes: docker.sock present"
    fi

    # Check ~/.docker/run/docker.sock (Docker Desktop location)
    if [[ -n "${HOME:-}" && -S "$HOME/.docker/run/docker.sock" ]]; then
        detected="${detected}docker_user_sock,"
        found=1
    fi

    detected="${detected%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "container_runtimes" "exposed" "$detected" "low"
    else
        emit "system_visibility" "container_runtimes" "blocked" "" "low"
    fi
}

# =============================================================================
# Seatbelt Sandbox Profiles
# Severity: medium (reveals what sandboxing is available)
# =============================================================================
scan_sandbox_profiles() {
    debug "scan_sandbox_profiles: starting"

    local profiles_dir="/System/Library/Sandbox/Profiles"

    if [[ ! -d "$profiles_dir" ]]; then
        emit "system_visibility" "sandbox_profiles" "not_found" "" "medium"
        return
    fi

    if ! dir_readable "$profiles_dir"; then
        emit "system_visibility" "sandbox_profiles" "blocked" "" "medium"
        return
    fi

    local count
    count=$(ls -1 "$profiles_dir" 2>/dev/null | grep -c "\.sb$") || count=0
    count=$(to_int "$count")

    if [[ $count -gt 0 ]]; then
        debug "scan_sandbox_profiles: found $count sandbox profiles"
        emit "system_visibility" "sandbox_profiles" "exposed" "$count" "medium"
    else
        emit "system_visibility" "sandbox_profiles" "blocked" "" "medium"
    fi
}

# =============================================================================
# Sandbox Self-Detection (are we sandboxed?)
# Severity: info
# =============================================================================
scan_sandbox_self() {
    debug "scan_sandbox_self: starting"

    local in_sandbox=0
    local details=""

    # Try to detect if we're in a seatbelt sandbox
    # sandbox-exec returns specific exit codes
    if has_cmd sandbox-exec; then
        # Try to run a simple sandboxed command
        local sb_output
        sb_output=$(sandbox-exec -n no-network true 2>&1)
        local exit_code=$?

        if [[ $exit_code -eq 0 ]]; then
            details="sandbox-exec:available"
            debug "scan_sandbox_self: sandbox-exec works"
        else
            # If we can't run sandbox-exec, we might be sandboxed ourselves
            if echo "$sb_output" | grep -qi "not permitted\|denied"; then
                in_sandbox=1
                details="in_sandbox"
                debug "scan_sandbox_self: appears to be sandboxed"
            fi
        fi
    fi

    # Check for App Sandbox indicators via csops (if available)
    # This is a heuristic - sandboxed apps have specific entitlements

    # Check asctl (App Sandbox control)
    if has_cmd asctl; then
        local asctl_output
        asctl_output=$(with_timeout 3 asctl status 2>&1)
        if [[ $? -eq 0 && -n "$asctl_output" ]]; then
            details="${details:+$details,}asctl:available"
        fi
    fi

    # Check for sandbox-related environment variables
    if [[ -n "${APP_SANDBOX_CONTAINER_ID:-}" ]]; then
        in_sandbox=1
        details="${details:+$details,}app_sandbox"
        debug "scan_sandbox_self: APP_SANDBOX_CONTAINER_ID set"
    fi

    if [[ $in_sandbox -gt 0 ]]; then
        emit "system_visibility" "sandbox_self" "exposed" "sandboxed:$details" "info"
    elif [[ -n "$details" ]]; then
        emit "system_visibility" "sandbox_self" "exposed" "$details" "info"
    else
        emit "system_visibility" "sandbox_self" "blocked" "" "info"
    fi
}

# =============================================================================
# Rosetta Translation Detection
# Severity: info (reveals architecture translation)
# =============================================================================
scan_rosetta_status() {
    debug "scan_rosetta_status: starting"

    local details=""
    local found=0

    # Check current architecture
    local arch
    arch=$(uname -m 2>/dev/null) || arch=""
    if [[ -n "$arch" ]]; then
        details="arch:$arch"
        found=1
    fi

    # Check if Rosetta daemon is running (oahd)
    if pgrep -q "oahd" 2>/dev/null; then
        details="${details:+$details,}oahd:running"
        found=1
        debug "scan_rosetta_status: Rosetta daemon running"
    fi

    # Check if we can run x86_64 binaries
    if has_cmd arch; then
        local x86_test
        x86_test=$(arch -x86_64 true 2>&1)
        if [[ $? -eq 0 ]]; then
            details="${details:+$details,}rosetta:available"
            found=1
            debug "scan_rosetta_status: Rosetta translation available"
        fi
    fi

    # Check CPU brand string
    if has_cmd sysctl; then
        local cpu_brand
        cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null) || cpu_brand=""
        if [[ -n "$cpu_brand" ]]; then
            if echo "$cpu_brand" | grep -qi "Apple"; then
                details="${details:+$details,}apple_silicon"
            elif echo "$cpu_brand" | grep -qi "Intel"; then
                details="${details:+$details,}intel"
            fi
            found=1
        fi
    fi

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "rosetta_status" "exposed" "$details" "info"
    else
        emit "system_visibility" "rosetta_status" "blocked" "" "info"
    fi
}

# =============================================================================
# Run all VM/sandbox detection tests
# =============================================================================
run_vm_sandbox_tests() {
    debug "run_vm_sandbox_tests: starting (darwin)"
    progress_start "vm_sandbox"
    scan_hypervisor_support
    scan_vm_indicators
    scan_container_runtimes
    scan_sandbox_profiles
    scan_sandbox_self
    scan_rosetta_status
    progress_end "vm_sandbox"
    debug "run_vm_sandbox_tests: complete"
}
