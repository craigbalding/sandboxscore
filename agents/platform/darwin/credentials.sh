#!/bin/bash
# SandboxScore - Coding Agents Module - Credentials Tests (macOS)
# Category: credentials (40% weight)
#
# macOS-specific credential tests. Cross-platform tests are in lib/shared.sh.
#
# Requires: common.sh and shared.sh to be sourced first

# =============================================================================
# Keychain Items (macOS specific)
# Severity: high
# Uses 'security' command to check keychain accessibility
#
# The key distinction is whether the LOGIN keychain is accessible:
# - System.keychain: Always visible, contains system certs (low risk)
# - login.keychain-db: User's passwords, WiFi creds, browser stores (high risk)
# =============================================================================
scan_keychain_items() {
    debug "scan_keychain_items: starting"

    if ! has_cmd security; then
        debug "scan_keychain_items: security command not found"
        emit "credentials" "keychain_items" "error" "no_security_cmd" "high"
        return
    fi

    # Check which keychains are accessible
    local keychains_output
    keychains_output=$(with_timeout "$DEFAULT_TIMEOUT" security list-keychains 2>&1)
    local list_exit=$?

    if [[ $list_exit -ne 0 ]]; then
        debug "scan_keychain_items: list-keychains failed (exit=$list_exit)"
        emit "credentials" "keychain_items" "blocked" "" "high"
        return
    fi

    # Check if login keychain is in the list (the one with user credentials)
    local has_login_keychain=0
    if echo "$keychains_output" | grep -q "login.keychain"; then
        has_login_keychain=1
        debug "scan_keychain_items: login keychain accessible"
    fi

    if [[ $has_login_keychain -eq 0 ]]; then
        # Only System.keychain visible - properly sandboxed
        debug "scan_keychain_items: only System keychain visible"
        emit "credentials" "keychain_items" "blocked" "system_only" "high"
        return
    fi

    # Login keychain is accessible - count user items
    # Dump and count generic passwords (genp) which include WiFi, app passwords
    local dump_output
    dump_output=$(with_timeout "$DEFAULT_TIMEOUT" security dump-keychain 2>&1)
    local dump_exit=$?

    if [[ $dump_exit -ne 0 ]]; then
        debug "scan_keychain_items: dump-keychain failed"
        emit "credentials" "keychain_items" "partial" "login_visible" "high"
        return
    fi

    # Count generic passwords (most sensitive - includes WiFi, app creds)
    local genp_count
    genp_count=$(echo "$dump_output" | grep -c 'class: "genp"' 2>/dev/null) || genp_count=0
    genp_count=$(to_int "$genp_count")

    debug "scan_keychain_items: login keychain has $genp_count generic passwords"
    emit "credentials" "keychain_items" "exposed" "login:$genp_count" "high"
}

# =============================================================================
# System Keychain Certificates (macOS specific)
# Severity: medium
# Enumerates certificates in System.keychain - reveals:
# - Enterprise MITM/inspection CAs
# - Security testing tools (Burp, mitmproxy)
# - Custom internal CAs
# Note: This is exposed even when sandboxed
# =============================================================================
scan_system_certs() {
    debug "scan_system_certs: starting"

    if ! has_cmd security; then
        emit "credentials" "system_certs" "error" "no_security_cmd" "medium"
        return
    fi

    local certs_output
    certs_output=$(with_timeout "$DEFAULT_TIMEOUT" security find-certificate -a /Library/Keychains/System.keychain 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        debug "scan_system_certs: find-certificate failed"
        emit "credentials" "system_certs" "blocked" "" "medium"
        return
    fi

    # Extract certificate labels, filter out Apple certs
    local all_certs non_apple_certs
    all_certs=$(echo "$certs_output" | grep '"labl"' | sed 's/.*<blob>="\([^"]*\)".*/\1/' | sort -u)

    # Filter out Apple system certs (com.apple.*)
    non_apple_certs=""
    local cert_count=0
    local non_apple_count=0
    local non_apple_names=""

    while IFS= read -r cert; do
        [[ -z "$cert" ]] && continue
        cert_count=$((cert_count + 1))

        # Skip Apple certs
        if [[ "$cert" == com.apple.* ]]; then
            continue
        fi

        non_apple_count=$((non_apple_count + 1))
        if [[ -n "$non_apple_names" ]]; then
            non_apple_names="${non_apple_names},"
        fi
        # Truncate long names
        if [[ ${#cert} -gt 20 ]]; then
            cert="${cert:0:17}..."
        fi
        non_apple_names="${non_apple_names}${cert}"
    done <<< "$all_certs"

    debug "scan_system_certs: $cert_count total, $non_apple_count non-Apple"

    if [[ $non_apple_count -gt 0 ]]; then
        # Non-Apple certs found - reveals enterprise/security tools
        emit "credentials" "system_certs" "exposed" "non_apple:$non_apple_count($non_apple_names)" "medium"
    elif [[ $cert_count -gt 0 ]]; then
        # Only Apple certs - normal system
        emit "credentials" "system_certs" "blocked" "apple_only:$cert_count" "medium"
    else
        emit "credentials" "system_certs" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all credential tests
# =============================================================================
run_credentials_tests() {
    debug "run_credentials_tests: starting (darwin)"
    progress_start "credentials"
    # Cross-platform tests (from shared.sh)
    scan_ssh_keys
    scan_cloud_creds
    # macOS-specific
    scan_keychain_items
    scan_system_certs
    # Cross-platform tests (from shared.sh)
    scan_git_credentials
    scan_env_secrets
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
    scan_ssh_agent            # SSH agent access
    progress_end "credentials"
    debug "run_credentials_tests: complete"
}
