#!/bin/bash
# SandboxScore - Coding Agents Module - Credentials Tests (Linux)
# Category: credentials (40% weight)
#
# Linux-specific credential tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# Keyring/Secret Storage - Linux specific
# Severity: high
# Checks for secret-tool (libsecret), gnome-keyring, kwallet, pass
# =============================================================================
scan_keychain_items() {
    debug "scan_keychain_items: starting (linux)"

    local found=0
    local details=""

    # Method 1: secret-tool (libsecret CLI - works with GNOME Keyring)
    if has_cmd secret-tool; then
        # Try to search for any items (this lists them, doesn't reveal secrets)
        local secret_output
        secret_output=$(with_timeout "$DEFAULT_TIMEOUT" secret-tool search --all 2>&1)
        local secret_exit=$?

        if [[ $secret_exit -eq 0 && -n "$secret_output" ]]; then
            local item_count
            item_count=$(echo "$secret_output" | grep -c "^\\[" 2>/dev/null) || item_count=0
            item_count=$(to_int "$item_count")
            if [[ "$item_count" -gt 0 ]]; then
                found=$((found + item_count))
                details="${details}libsecret:$item_count,"
                debug "scan_keychain_items: libsecret found $item_count items"
            fi
        fi
    fi

    # Method 2: Check for GNOME Keyring files
    if [[ -d "$HOME/.local/share/keyrings" ]]; then
        local keyring_count
        keyring_count=$(ls -1 "$HOME/.local/share/keyrings"/*.keyring 2>/dev/null | wc -l) || keyring_count=0
        keyring_count=$(to_int "$keyring_count")
        if [[ "$keyring_count" -gt 0 ]]; then
            found=$((found + 1))
            details="${details}gnome-keyring,"
            debug "scan_keychain_items: found $keyring_count keyring files"
        fi
    fi

    # Method 3: Check for KWallet
    if [[ -d "$HOME/.local/share/kwalletd" ]]; then
        found=$((found + 1))
        details="${details}kwallet,"
        debug "scan_keychain_items: kwallet directory exists"
    fi

    # Method 4: Check for pass (password-store)
    if [[ -d "$HOME/.password-store" ]]; then
        local pass_count
        pass_count=$(find "$HOME/.password-store" -name "*.gpg" 2>/dev/null | wc -l) || pass_count=0
        pass_count=$(to_int "$pass_count")
        if [[ "$pass_count" -gt 0 ]]; then
            found=$((found + pass_count))
            details="${details}pass:$pass_count,"
            debug "scan_keychain_items: pass has $pass_count entries"
        fi
    fi

    details="${details%,}"

    if [[ $found -gt 0 ]]; then
        emit "credentials" "keychain_items" "exposed" "$details" "high"
    else
        emit "credentials" "keychain_items" "blocked" "" "high"
    fi
}

# =============================================================================
# Run all credential tests
# =============================================================================
run_credentials_tests() {
    debug "run_credentials_tests: starting (linux)"
    progress_start "credentials"
    # Cross-platform tests (from shared.sh)
    scan_ssh_keys
    scan_cloud_creds
    # Linux-specific
    scan_keychain_items
    # Cross-platform tests (from shared.sh)
    scan_git_credentials
    scan_env_secrets
    scan_k8s_service_account  # K8s pod service account token
    scan_kube_config
    scan_docker_config
    scan_gpg_keys
    scan_npm_token
    scan_pypi_token
    # CI/CD specific (from shared.sh)
    scan_ci_secrets           # CI/CD platform tokens
    scan_ci_injection_vectors # GITHUB_ENV, GITHUB_PATH writability
    scan_ci_oidc              # OIDC token availability
    scan_ci_git_config        # .git/config token leakage
    progress_end "credentials"
    debug "run_credentials_tests: complete"
}
