#!/bin/bash
# SandboxScore - Coding Agents Module - Hardware Devices Tests (macOS)
# Category: system_visibility
#
# Tests for hardware device enumeration:
# - USB devices
# - Bluetooth devices
# - Network interfaces / WiFi
# - Audio devices
# - Camera/video devices
# - Storage/disk information
#
# Requires: common.sh to be sourced first

# =============================================================================
# USB Devices
# Severity: medium (reveals connected peripherals, user activity)
# =============================================================================
scan_usb_devices() {
    debug "scan_usb_devices: starting"

    local found=0
    local details=""

    # Try system_profiler SPUSBDataType
    if has_cmd system_profiler; then
        local usb_output
        usb_output=$(with_timeout 15 system_profiler SPUSBDataType 2>/dev/null)
        if [[ $? -eq 0 && -n "$usb_output" ]]; then
            # Count USB devices (looking for product name entries)
            local device_count
            device_count=$(echo "$usb_output" | grep -c "Product ID:") || device_count=0
            device_count=$(to_int "$device_count")
            if [[ $device_count -gt 0 ]]; then
                found=1
                details="${details}profiler:$device_count,"
                debug "scan_usb_devices: system_profiler found $device_count USB devices"
            fi
        fi
    fi

    # Try ioreg for USB tree
    if has_cmd ioreg; then
        local ioreg_output
        ioreg_output=$(with_timeout 10 ioreg -p IOUSB -l 2>/dev/null | head -100)
        if [[ $? -eq 0 && -n "$ioreg_output" ]]; then
            found=1
            details="${details}ioreg,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "usb_devices" "exposed" "$details" "medium"
    else
        emit "system_visibility" "usb_devices" "blocked" "" "medium"
    fi
}

# =============================================================================
# Bluetooth Devices
# Severity: medium (reveals paired devices, nearby devices)
# =============================================================================
scan_bluetooth_devices() {
    debug "scan_bluetooth_devices: starting"

    local found=0
    local details=""

    # Try system_profiler SPBluetoothDataType
    if has_cmd system_profiler; then
        local bt_output
        bt_output=$(with_timeout 15 system_profiler SPBluetoothDataType 2>/dev/null)
        if [[ $? -eq 0 && -n "$bt_output" ]]; then
            found=1

            # Check for paired devices
            local paired_count
            paired_count=$(echo "$bt_output" | grep -c "Address:") || paired_count=0
            paired_count=$(to_int "$paired_count")
            details="${details}paired:$paired_count,"

            # Check if Bluetooth is on
            if echo "$bt_output" | grep -qi "State: On\|Bluetooth Power: On"; then
                details="${details}power:on,"
            fi

            debug "scan_bluetooth_devices: found $paired_count paired devices"
        fi
    fi

    # Check for blueutil if available
    if has_cmd blueutil; then
        local blueutil_output
        blueutil_output=$(with_timeout 5 blueutil --paired 2>/dev/null)
        if [[ $? -eq 0 && -n "$blueutil_output" ]]; then
            found=1
            details="${details}blueutil,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "bluetooth_devices" "exposed" "$details" "medium"
    else
        emit "system_visibility" "bluetooth_devices" "blocked" "" "medium"
    fi
}

# =============================================================================
# WiFi Networks
# Severity: medium (reveals network info, nearby networks)
# =============================================================================
scan_wifi_networks() {
    debug "scan_wifi_networks: starting"

    local found=0
    local details=""

    # airport command location (varies by macOS version)
    local airport=""
    if [[ -x "/usr/sbin/airport" ]]; then
        airport="/usr/sbin/airport"
    elif [[ -x "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport" ]]; then
        airport="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    fi

    if [[ -n "$airport" ]]; then
        # Get current connection info
        local airport_info
        airport_info=$(with_timeout 5 "$airport" -I 2>/dev/null)
        if [[ $? -eq 0 && -n "$airport_info" ]]; then
            found=1
            details="${details}current,"

            # Check if connected
            if echo "$airport_info" | grep -qi "SSID:"; then
                details="${details}connected,"
            fi
            debug "scan_wifi_networks: airport -I accessible"
        fi

        # Try to scan for networks (may require privileges)
        local scan_output
        scan_output=$(with_timeout 10 "$airport" -s 2>/dev/null | head -20)
        if [[ $? -eq 0 && -n "$scan_output" ]]; then
            local network_count
            network_count=$(echo "$scan_output" | wc -l) || network_count=0
            network_count=$(to_int "$network_count")
            if [[ $network_count -gt 1 ]]; then
                found=1
                details="${details}scan:$((network_count - 1)),"
                debug "scan_wifi_networks: scan found $((network_count - 1)) networks"
            fi
        fi
    fi

    # Fallback to system_profiler
    if [[ $found -eq 0 ]] && has_cmd system_profiler; then
        local net_output
        net_output=$(with_timeout 15 system_profiler SPNetworkDataType 2>/dev/null | head -50)
        if [[ $? -eq 0 && -n "$net_output" ]]; then
            found=1
            details="profiler"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "wifi_networks" "exposed" "$details" "medium"
    else
        emit "system_visibility" "wifi_networks" "blocked" "" "medium"
    fi
}

# =============================================================================
# Audio Devices
# Severity: low (reveals audio hardware)
# =============================================================================
scan_audio_devices() {
    debug "scan_audio_devices: starting"

    if ! has_cmd system_profiler; then
        emit "system_visibility" "audio_devices" "error" "no_system_profiler" "low"
        return
    fi

    local audio_output
    audio_output=$(with_timeout 15 system_profiler SPAudioDataType 2>/dev/null)

    if [[ $? -eq 0 && -n "$audio_output" ]]; then
        # Count audio devices
        local device_count
        device_count=$(echo "$audio_output" | grep -c "Device Name:\|Manufacturer:") || device_count=0
        device_count=$(to_int "$device_count")

        debug "scan_audio_devices: found $device_count audio device entries"
        emit "system_visibility" "audio_devices" "exposed" "$device_count" "low"
    else
        emit "system_visibility" "audio_devices" "blocked" "" "low"
    fi
}

# =============================================================================
# Camera Devices
# Severity: medium (reveals camera presence, models)
# =============================================================================
scan_camera_devices() {
    debug "scan_camera_devices: starting"

    if ! has_cmd system_profiler; then
        emit "system_visibility" "camera_devices" "error" "no_system_profiler" "medium"
        return
    fi

    local camera_output
    camera_output=$(with_timeout 15 system_profiler SPCameraDataType 2>/dev/null)

    if [[ $? -eq 0 && -n "$camera_output" ]]; then
        # Count cameras
        local camera_count
        camera_count=$(echo "$camera_output" | grep -c "Model ID:\|Unique ID:") || camera_count=0
        camera_count=$(to_int "$camera_count")

        debug "scan_camera_devices: found $camera_count camera entries"
        emit "system_visibility" "camera_devices" "exposed" "$camera_count" "medium"
    else
        emit "system_visibility" "camera_devices" "blocked" "" "medium"
    fi
}

# =============================================================================
# Display Information
# Severity: low (reveals display hardware)
# =============================================================================
scan_display_info() {
    debug "scan_display_info: starting"

    if ! has_cmd system_profiler; then
        emit "system_visibility" "display_info" "error" "no_system_profiler" "low"
        return
    fi

    local display_output
    display_output=$(with_timeout 15 system_profiler SPDisplaysDataType 2>/dev/null)

    if [[ $? -eq 0 && -n "$display_output" ]]; then
        # Count displays
        local display_count
        display_count=$(echo "$display_output" | grep -c "Resolution:\|Display Type:") || display_count=0
        display_count=$(to_int "$display_count")

        debug "scan_display_info: found $display_count display entries"
        emit "system_visibility" "display_info" "exposed" "$display_count" "low"
    else
        emit "system_visibility" "display_info" "blocked" "" "low"
    fi
}

# =============================================================================
# Storage/Disk Information
# Severity: medium (reveals storage layout, encryption)
# =============================================================================
scan_storage_info() {
    debug "scan_storage_info: starting"

    local found=0
    local details=""

    # diskutil list
    if has_cmd diskutil; then
        local diskutil_output
        diskutil_output=$(with_timeout 10 diskutil list 2>/dev/null)
        if [[ $? -eq 0 && -n "$diskutil_output" ]]; then
            found=1
            # Count disks
            local disk_count
            disk_count=$(echo "$diskutil_output" | grep -c "^/dev/disk") || disk_count=0
            disk_count=$(to_int "$disk_count")
            details="${details}disks:$disk_count,"
            debug "scan_storage_info: diskutil found $disk_count disks"
        fi

        # Check for encryption info
        local apfs_output
        apfs_output=$(with_timeout 10 diskutil apfs list 2>/dev/null)
        if [[ $? -eq 0 && -n "$apfs_output" ]]; then
            if echo "$apfs_output" | grep -qi "FileVault:\s*Yes"; then
                details="${details}filevault:on,"
            fi
        fi
    fi

    # system_profiler storage
    if has_cmd system_profiler; then
        local storage_output
        storage_output=$(with_timeout 15 system_profiler SPStorageDataType 2>/dev/null | head -50)
        if [[ $? -eq 0 && -n "$storage_output" ]]; then
            found=1
            details="${details}profiler,"
        fi

        # NVMe info
        local nvme_output
        nvme_output=$(with_timeout 10 system_profiler SPNVMeDataType 2>/dev/null | head -20)
        if [[ $? -eq 0 && -n "$nvme_output" ]]; then
            details="${details}nvme,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "storage_info" "exposed" "$details" "medium"
    else
        emit "system_visibility" "storage_info" "blocked" "" "medium"
    fi
}

# =============================================================================
# Network Interfaces
# Severity: low (reveals network configuration)
# =============================================================================
scan_network_interfaces() {
    debug "scan_network_interfaces: starting"

    local found=0
    local details=""

    # ifconfig
    if has_cmd ifconfig; then
        local ifconfig_output
        ifconfig_output=$(with_timeout 5 ifconfig 2>/dev/null)
        if [[ $? -eq 0 && -n "$ifconfig_output" ]]; then
            found=1
            local iface_count
            iface_count=$(echo "$ifconfig_output" | grep -c "^[a-z]") || iface_count=0
            iface_count=$(to_int "$iface_count")
            details="${details}interfaces:$iface_count,"
        fi
    fi

    # networksetup
    if has_cmd networksetup; then
        local ns_output
        ns_output=$(with_timeout 5 networksetup -listallnetworkservices 2>/dev/null)
        if [[ $? -eq 0 && -n "$ns_output" ]]; then
            found=1
            local service_count
            service_count=$(echo "$ns_output" | wc -l) || service_count=0
            service_count=$(to_int "$service_count")
            details="${details}services:$((service_count - 1)),"
        fi
    fi

    # scutil --dns
    if has_cmd scutil; then
        local dns_output
        dns_output=$(with_timeout 5 scutil --dns 2>/dev/null | head -20)
        if [[ $? -eq 0 && -n "$dns_output" ]]; then
            found=1
            details="${details}dns,"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "system_visibility" "network_interfaces" "exposed" "$details" "low"
    else
        emit "system_visibility" "network_interfaces" "blocked" "" "low"
    fi
}

# =============================================================================
# Run all hardware device tests
# =============================================================================
run_hardware_tests() {
    debug "run_hardware_tests: starting (darwin)"
    progress_start "hardware"
    scan_usb_devices
    scan_bluetooth_devices
    scan_wifi_networks
    scan_audio_devices
    scan_camera_devices
    scan_display_info
    scan_storage_info
    scan_network_interfaces
    progress_end "hardware"
    debug "run_hardware_tests: complete"
}
