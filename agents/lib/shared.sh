#!/bin/bash
# SandboxScore - Coding Agents Module - Shared Test Functions
# Cross-platform tests that work identically on macOS and Linux
#
# Requires: common.sh to be sourced first (provides emit, debug, has_cmd, to_int, with_timeout)

# =============================================================================
# PURE HELPER FUNCTIONS (no side effects)
# =============================================================================

# Check if a directory is readable (actually tests read, not just permission bits)
dir_readable() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1

    # Actually test read capability by listing
    if ls "$dir" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Check if a file is readable (actually tests read, not just permission bits)
file_readable() {
    local file="$1"
    [[ -f "$file" ]] || return 1

    # Actually test read capability by reading one byte
    if head -c 1 "$file" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Check if a file is writable (actually tests write, not just permission bits)
file_writable() {
    local file="$1"
    [[ -f "$file" ]] || return 1

    # Actually test write capability by appending nothing
    # This tests the syscall without modifying content
    if ( echo -n >> "$file" ) 2>/dev/null; then
        return 0
    fi
    return 1
}

# Check if a directory is writable (actually tests write, not just permission bits)
# Uses unique probe filename for each call (sandboxes may allow create but block delete)
_dir_writable_counter=0
dir_writable() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1

    # Use unique probe name (counter + pid) for each call
    _dir_writable_counter=$((_dir_writable_counter + 1))
    local probe="$dir/.sandboxscore_probe_${$}_${_dir_writable_counter}"

    if touch "$probe" 2>/dev/null; then
        rm -f "$probe" 2>/dev/null  # Best effort cleanup
        return 0
    fi
    return 1
}

# Count lines in a file (returns 0 if file doesn't exist or isn't readable)
count_lines() {
    local file="$1"
    if [[ -r "$file" ]]; then
        wc -l < "$file" 2>/dev/null | tr -d ' '
    else
        echo "0"
    fi
}

# Count grep matches in a file (returns 0 on no match or error)
count_grep_matches() {
    local pattern="$1"
    local file="$2"
    if [[ -r "$file" ]]; then
        grep -c "$pattern" "$file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# =============================================================================
# CREDENTIALS: SSH Keys
# Severity: critical (caps grade at B)
# =============================================================================
scan_ssh_keys() {
    debug "scan_ssh_keys: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_ssh_keys: HOME not set"
        emit "credentials" "ssh_keys" "error" "no_home" "critical"
        return
    fi

    local ssh_dir="$HOME/.ssh"
    local count=0

    if [[ ! -d "$ssh_dir" ]]; then
        debug "scan_ssh_keys: $ssh_dir does not exist"
        emit "credentials" "ssh_keys" "not_found" "" "critical"
        return
    fi

    if [[ ! -r "$ssh_dir" ]]; then
        debug "scan_ssh_keys: $ssh_dir not readable"
        emit "credentials" "ssh_keys" "blocked" "" "critical"
        return
    fi

    # Count private keys (files without .pub extension that look like keys)
    local keyfile
    for keyfile in "$ssh_dir"/id_* "$ssh_dir"/*_key; do
        [[ ! -e "$keyfile" ]] && continue
        [[ -d "$keyfile" ]] && continue
        [[ "$keyfile" =~ \.pub$ ]] && continue
        if [[ -f "$keyfile" ]]; then
            count=$((count + 1))
            debug "scan_ssh_keys: found key $keyfile"
        fi
    done

    if [[ $count -gt 0 ]]; then
        emit "credentials" "ssh_keys" "exposed" "$count" "critical"
    else
        debug "scan_ssh_keys: no private keys found"
        emit "credentials" "ssh_keys" "blocked" "0" "critical"
    fi
}

# =============================================================================
# CREDENTIALS: Cloud Credentials (AWS, GCP, Azure)
# Severity: critical (caps grade at C)
# =============================================================================
scan_cloud_creds() {
    debug "scan_cloud_creds: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_cloud_creds: HOME not set"
        emit "credentials" "cloud_creds" "error" "no_home" "critical"
        return
    fi

    local found=0
    local providers=""
    local dirs_exist=0

    # AWS
    if [[ -d "$HOME/.aws" ]]; then
        dirs_exist=1
        if file_readable "$HOME/.aws/credentials"; then
            found=$((found + 1))
            providers="${providers}aws,"
            debug "scan_cloud_creds: found AWS credentials"
        fi
    fi

    # GCP
    if [[ -d "$HOME/.config/gcloud" ]]; then
        dirs_exist=1
        if file_readable "$HOME/.config/gcloud/application_default_credentials.json"; then
            found=$((found + 1))
            providers="${providers}gcp,"
            debug "scan_cloud_creds: found GCP credentials"
        fi
    fi

    # Azure
    if [[ -d "$HOME/.azure" ]]; then
        dirs_exist=1
        if file_readable "$HOME/.azure/accessTokens.json"; then
            found=$((found + 1))
            providers="${providers}azure,"
            debug "scan_cloud_creds: found Azure credentials"
        fi
    fi

    providers="${providers%,}"

    if [[ $found -gt 0 ]]; then
        emit "credentials" "cloud_creds" "exposed" "$providers" "critical"
    elif [[ $dirs_exist -gt 0 ]]; then
        emit "credentials" "cloud_creds" "blocked" "" "critical"
    else
        emit "credentials" "cloud_creds" "not_found" "" "critical"
    fi
}

# =============================================================================
# CREDENTIALS: Git Credentials
# Severity: high
# =============================================================================
scan_git_credentials() {
    debug "scan_git_credentials: starting"

    if [[ -z "${HOME:-}" ]]; then
        debug "scan_git_credentials: HOME not set"
        emit "credentials" "git_credentials" "error" "no_home" "high"
        return
    fi

    local exposed=0
    local details=""

    if has_cmd git; then
        local helper
        helper=$(git config --global credential.helper 2>/dev/null) || helper=""

        if [[ -n "$helper" ]]; then
            helper="${helper//[^a-zA-Z0-9_-]/}"
            details="helper:$helper"
            debug "scan_git_credentials: helper=$helper"

            # osxkeychain or libsecret helpers mean credentials may be accessible
            if [[ "$helper" == "osxkeychain" || "$helper" == "libsecret" || "$helper" == "cache" ]]; then
                exposed=1
            fi

            # store helper means plaintext file
            if [[ "$helper" == "store" ]]; then
                if file_readable "$HOME/.git-credentials"; then
                    exposed=1
                    details="${details},file"
                    debug "scan_git_credentials: found .git-credentials file"
                fi
            fi
        fi
    else
        debug "scan_git_credentials: git not installed"
    fi

    # Check for .netrc (often contains credentials)
    if file_readable "$HOME/.netrc"; then
        exposed=1
        details="${details:+$details,}netrc"
        debug "scan_git_credentials: found .netrc"
    fi

    if [[ $exposed -gt 0 ]]; then
        emit "credentials" "git_credentials" "exposed" "$details" "high"
    else
        emit "credentials" "git_credentials" "blocked" "" "high"
    fi
}

# =============================================================================
# CREDENTIALS: Environment Secrets
# Severity: medium
# =============================================================================
scan_env_secrets() {
    debug "scan_env_secrets: starting"

    local count=0

    if ! has_cmd env; then
        debug "scan_env_secrets: env command not found"
        emit "credentials" "env_secrets" "error" "no_env_cmd" "medium"
        return
    fi

    local patterns="API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH_|PRIVATE_KEY"
    local env_output
    env_output=$(env 2>/dev/null) || env_output=""

    if [[ -n "$env_output" ]]; then
        # shellcheck disable=SC2126  # grep -c returns 1 on zero matches, breaking || count=0
        count=$(echo "$env_output" | grep -iE "^[^=]*($patterns)[^=]*=" 2>/dev/null | wc -l) || count=0
        count=$(to_int "$count")
    fi

    debug "scan_env_secrets: found $count potential secrets"

    if [[ "$count" -gt 0 ]]; then
        emit "credentials" "env_secrets" "exposed" "$count" "medium"
    else
        emit "credentials" "env_secrets" "blocked" "0" "medium"
    fi
}

# =============================================================================
# CREDENTIALS: Kubernetes Service Account Token
# Severity: critical (allows cluster API access from within pods)
# =============================================================================
scan_k8s_service_account() {
    debug "scan_k8s_service_account: starting"

    # Standard K8s service account token location
    local token_path="/var/run/secrets/kubernetes.io/serviceaccount/token"
    local ca_path="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    local ns_path="/var/run/secrets/kubernetes.io/serviceaccount/namespace"

    # Check if we're in a K8s environment
    if [[ ! -d "/var/run/secrets/kubernetes.io/serviceaccount" ]]; then
        emit "credentials" "k8s_service_account" "not_found" "" "critical"
        return
    fi

    local found=0
    local details=""

    # Check token readability
    if file_readable "$token_path"; then
        found=1
        details="token"
        debug "scan_k8s_service_account: token readable"
    fi

    # Check CA cert
    if file_readable "$ca_path"; then
        details="${details:+$details,}ca"
        debug "scan_k8s_service_account: ca.crt readable"
    fi

    # Check namespace
    if file_readable "$ns_path"; then
        local ns
        ns=$(cat "$ns_path" 2>/dev/null) || ns=""
        if [[ -n "$ns" ]]; then
            details="${details:+$details,}ns:$ns"
            debug "scan_k8s_service_account: namespace=$ns"
        fi
    fi

    if [[ $found -gt 0 ]]; then
        emit "credentials" "k8s_service_account" "exposed" "$details" "critical"
    else
        emit "credentials" "k8s_service_account" "blocked" "" "critical"
    fi
}

# =============================================================================
# CREDENTIALS: Kubernetes Config
# Severity: critical
# =============================================================================
scan_kube_config() {
    debug "scan_kube_config: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "credentials" "kube_config" "error" "no_home" "critical"
        return
    fi

    local kube_config="${KUBECONFIG:-$HOME/.kube/config}"
    local found=0
    local contexts=0

    # Split on colon using parameter expansion (IFS-safe)
    local remaining="$kube_config"
    while [[ -n "$remaining" ]]; do
        local config_file="${remaining%%:*}"
        if [[ "$remaining" == *:* ]]; then
            remaining="${remaining#*:}"
        else
            remaining=""
        fi

        [[ -z "$config_file" ]] && continue

        if file_readable "$config_file"; then
            found=1
            local ctx_count
            ctx_count=$(count_grep_matches "^- context:" "$config_file")
            ctx_count=$(to_int "$ctx_count")
            contexts=$((contexts + ctx_count))
            debug "scan_kube_config: found $ctx_count contexts in $config_file"
        fi
    done

    if [[ $found -gt 0 && $contexts -gt 0 ]]; then
        emit "credentials" "kube_config" "exposed" "$contexts contexts" "critical"
    elif [[ $found -gt 0 ]]; then
        emit "credentials" "kube_config" "exposed" "config readable" "critical"
    else
        emit "credentials" "kube_config" "not_found" "" "critical"
    fi
}

# =============================================================================
# CREDENTIALS: Docker Config
# Severity: high
# =============================================================================
scan_docker_config() {
    debug "scan_docker_config: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "credentials" "docker_config" "error" "no_home" "high"
        return
    fi

    local docker_config="$HOME/.docker/config.json"

    if [[ ! -f "$docker_config" ]]; then
        emit "credentials" "docker_config" "not_found" "" "high"
        return
    fi

    if [[ ! -r "$docker_config" ]]; then
        emit "credentials" "docker_config" "blocked" "" "high"
        return
    fi

    local has_auths=0
    local auth_count=0

    if grep -q '"auths"' "$docker_config" 2>/dev/null; then
        # shellcheck disable=SC2126  # grep -c returns 1 on zero matches, breaking || auth_count=0
        auth_count=$(grep -E '"[a-zA-Z0-9.-]+\.(io|com|net|org|registry)":|"https?://' "$docker_config" 2>/dev/null | wc -l) || auth_count=0
        auth_count=$(to_int "$auth_count")
        if [[ $auth_count -gt 0 ]]; then
            has_auths=1
        fi
    fi

    local has_credstore=0
    if grep -q '"credsStore"' "$docker_config" 2>/dev/null; then
        has_credstore=1
    fi

    debug "scan_docker_config: auths=$auth_count, credstore=$has_credstore"

    if [[ $has_auths -gt 0 ]]; then
        emit "credentials" "docker_config" "exposed" "$auth_count registries" "high"
    elif [[ $has_credstore -gt 0 ]]; then
        emit "credentials" "docker_config" "exposed" "credstore" "high"
    else
        emit "credentials" "docker_config" "blocked" "no auths" "high"
    fi
}

# =============================================================================
# CREDENTIALS: GPG Private Keys
# Severity: high
# =============================================================================
scan_gpg_keys() {
    debug "scan_gpg_keys: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "credentials" "gpg_keys" "error" "no_home" "high"
        return
    fi

    local gnupg_dir="$HOME/.gnupg"
    local private_dir="$gnupg_dir/private-keys-v1.d"

    # Check if .gnupg exists
    if [[ ! -d "$gnupg_dir" ]]; then
        emit "credentials" "gpg_keys" "not_found" "" "high"
        return
    fi

    # Check for private keys directory (modern GPG 2.1+)
    local count=0
    if [[ -d "$private_dir" ]] && dir_readable "$private_dir"; then
        count=$(find "$private_dir" -maxdepth 1 -name "*.key" 2>/dev/null | wc -l) || count=0
        count=$(to_int "$count")
        debug "scan_gpg_keys: found $count keys in private-keys-v1.d"
    fi

    # Fallback: check for legacy secring.gpg
    if [[ $count -eq 0 ]] && file_readable "$gnupg_dir/secring.gpg"; then
        count=1
        debug "scan_gpg_keys: found legacy secring.gpg"
    fi

    if [[ $count -gt 0 ]]; then
        emit "credentials" "gpg_keys" "exposed" "$count" "high"
    elif [[ -d "$gnupg_dir" ]]; then
        emit "credentials" "gpg_keys" "blocked" "" "high"
    else
        emit "credentials" "gpg_keys" "not_found" "" "high"
    fi
}

# =============================================================================
# CREDENTIALS: NPM Token
# Severity: medium
# =============================================================================
scan_npm_token() {
    debug "scan_npm_token: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "credentials" "npm_token" "error" "no_home" "medium"
        return
    fi

    local npmrc="$HOME/.npmrc"

    if [[ ! -f "$npmrc" ]]; then
        emit "credentials" "npm_token" "not_found" "" "medium"
        return
    fi

    if ! file_readable "$npmrc"; then
        emit "credentials" "npm_token" "blocked" "" "medium"
        return
    fi

    # Look for auth tokens (//registry:_authToken= or _auth=)
    local has_token=0
    if grep -qE '(^|//).*:_authToken=|^_auth=' "$npmrc" 2>/dev/null; then
        has_token=1
        debug "scan_npm_token: found authToken"
    fi

    if [[ $has_token -gt 0 ]]; then
        emit "credentials" "npm_token" "exposed" "" "medium"
    else
        emit "credentials" "npm_token" "blocked" "no token" "medium"
    fi
}

# =============================================================================
# CREDENTIALS: PyPI Token
# Severity: medium
# =============================================================================
scan_pypi_token() {
    debug "scan_pypi_token: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "credentials" "pypi_token" "error" "no_home" "medium"
        return
    fi

    local pypirc="$HOME/.pypirc"

    if [[ ! -f "$pypirc" ]]; then
        emit "credentials" "pypi_token" "not_found" "" "medium"
        return
    fi

    if ! file_readable "$pypirc"; then
        emit "credentials" "pypi_token" "blocked" "" "medium"
        return
    fi

    # Look for password or token entries
    local has_creds=0
    if grep -qiE '^[[:space:]]*(password|token)[[:space:]]*=' "$pypirc" 2>/dev/null; then
        has_creds=1
        debug "scan_pypi_token: found credentials"
    fi

    if [[ $has_creds -gt 0 ]]; then
        emit "credentials" "pypi_token" "exposed" "" "medium"
    else
        emit "credentials" "pypi_token" "blocked" "no creds" "medium"
    fi
}

# =============================================================================
# CREDENTIALS: CI/CD Environment Detection
# Severity: info (detection) / high (tokens exposed)
# Detects which CI/CD platform we're running in
# =============================================================================
scan_ci_environment() {
    debug "scan_ci_environment: starting"

    local in_ci=0
    local platforms=""

    # GitHub Actions
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        in_ci=1
        platforms="${platforms}github,"
        debug "scan_ci_environment: GitHub Actions detected"
    fi

    # GitLab CI
    if [[ -n "${GITLAB_CI:-}" ]]; then
        in_ci=1
        platforms="${platforms}gitlab,"
        debug "scan_ci_environment: GitLab CI detected"
    fi

    # CircleCI
    if [[ -n "${CIRCLECI:-}" ]]; then
        in_ci=1
        platforms="${platforms}circleci,"
        debug "scan_ci_environment: CircleCI detected"
    fi

    # Jenkins
    if [[ -n "${JENKINS_URL:-}" ]] || [[ -n "${BUILD_TAG:-}" ]]; then
        in_ci=1
        platforms="${platforms}jenkins,"
        debug "scan_ci_environment: Jenkins detected"
    fi

    # Azure DevOps / Azure Pipelines
    if [[ -n "${TF_BUILD:-}" ]] || [[ -n "${AZURE_PIPELINES:-}" ]]; then
        in_ci=1
        platforms="${platforms}azure,"
        debug "scan_ci_environment: Azure DevOps detected"
    fi

    # AWS CodeBuild
    if [[ -n "${CODEBUILD_BUILD_ID:-}" ]]; then
        in_ci=1
        platforms="${platforms}codebuild,"
        debug "scan_ci_environment: AWS CodeBuild detected"
    fi

    # Travis CI
    if [[ -n "${TRAVIS:-}" ]]; then
        in_ci=1
        platforms="${platforms}travis,"
        debug "scan_ci_environment: Travis CI detected"
    fi

    # Buildkite
    if [[ -n "${BUILDKITE:-}" ]]; then
        in_ci=1
        platforms="${platforms}buildkite,"
        debug "scan_ci_environment: Buildkite detected"
    fi

    # Bitbucket Pipelines
    if [[ -n "${BITBUCKET_BUILD_NUMBER:-}" ]]; then
        in_ci=1
        platforms="${platforms}bitbucket,"
        debug "scan_ci_environment: Bitbucket Pipelines detected"
    fi

    # Generic CI detection (fallback)
    if [[ $in_ci -eq 0 ]] && [[ "${CI:-}" == "true" || -n "${CONTINUOUS_INTEGRATION:-}" ]]; then
        in_ci=1
        platforms="generic"
        debug "scan_ci_environment: Generic CI detected"
    fi

    platforms="${platforms%,}"

    if [[ $in_ci -gt 0 ]]; then
        emit "system_visibility" "ci_environment" "exposed" "$platforms" "info"
    else
        emit "system_visibility" "ci_environment" "blocked" "" "info"
    fi
}

# =============================================================================
# CREDENTIALS: CI/CD Secrets and Tokens
# Severity: critical (these tokens often have broad access)
# Checks for exposed CI/CD platform tokens
# =============================================================================
scan_ci_secrets() {
    debug "scan_ci_secrets: starting"

    local found=0
    local tokens=""

    # GitHub Actions tokens
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}GITHUB_TOKEN,"
        debug "scan_ci_secrets: GITHUB_TOKEN exposed"
    fi
    if [[ -n "${ACTIONS_RUNTIME_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}ACTIONS_RUNTIME_TOKEN,"
        debug "scan_ci_secrets: ACTIONS_RUNTIME_TOKEN exposed"
    fi
    if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}OIDC_TOKEN,"
        debug "scan_ci_secrets: ACTIONS_ID_TOKEN_REQUEST_TOKEN exposed"
    fi

    # GitLab CI tokens
    if [[ -n "${CI_JOB_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}CI_JOB_TOKEN,"
        debug "scan_ci_secrets: CI_JOB_TOKEN exposed"
    fi
    if [[ -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}CI_REGISTRY_PASSWORD,"
        debug "scan_ci_secrets: CI_REGISTRY_PASSWORD exposed"
    fi

    # Azure DevOps
    if [[ -n "${SYSTEM_ACCESSTOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}SYSTEM_ACCESSTOKEN,"
        debug "scan_ci_secrets: SYSTEM_ACCESSTOKEN exposed"
    fi

    # CircleCI
    if [[ -n "${CIRCLE_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}CIRCLE_TOKEN,"
        debug "scan_ci_secrets: CIRCLE_TOKEN exposed"
    fi

    # Buildkite
    if [[ -n "${BUILDKITE_AGENT_ACCESS_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}BUILDKITE_AGENT_ACCESS_TOKEN,"
        debug "scan_ci_secrets: BUILDKITE_AGENT_ACCESS_TOKEN exposed"
    fi

    # NPM automation tokens (commonly set in CI)
    if [[ -n "${NPM_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}NPM_TOKEN,"
        debug "scan_ci_secrets: NPM_TOKEN exposed"
    fi

    # PyPI tokens (commonly set in CI)
    if [[ -n "${TWINE_PASSWORD:-}" ]] || [[ -n "${PYPI_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}PYPI,"
        debug "scan_ci_secrets: PyPI token exposed"
    fi

    # Docker Hub (commonly set in CI)
    if [[ -n "${DOCKER_PASSWORD:-}" ]] || [[ -n "${DOCKERHUB_TOKEN:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}DOCKER,"
        debug "scan_ci_secrets: Docker credentials exposed"
    fi

    # AWS credentials (commonly set in CI)
    if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
        found=$((found + 1))
        tokens="${tokens}AWS,"
        debug "scan_ci_secrets: AWS credentials exposed"
    fi

    tokens="${tokens%,}"

    if [[ $found -gt 0 ]]; then
        emit "credentials" "ci_secrets" "exposed" "$found:$tokens" "critical"
    else
        # Only report not_found if we're in a CI environment
        if [[ "${CI:-}" == "true" || -n "${GITHUB_ACTIONS:-}" || -n "${GITLAB_CI:-}" ]]; then
            emit "credentials" "ci_secrets" "blocked" "" "critical"
        else
            emit "credentials" "ci_secrets" "not_found" "" "critical"
        fi
    fi
}

# =============================================================================
# CI/CD: GitHub Actions Deep Enumeration
# Severity: medium (metadata exposure enables targeted attacks)
# =============================================================================
scan_ci_github_deep() {
    debug "scan_ci_github_deep: starting"

    # Only run if we're in GitHub Actions
    if [[ -z "${GITHUB_ACTIONS:-}" ]]; then
        emit "system_visibility" "ci_github_deep" "not_found" "" "medium"
        return
    fi

    local exposed=""
    local count=0

    # Repository and workflow metadata
    if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
        exposed="${exposed}repo,"
        count=$((count + 1))
    fi
    if [[ -n "${GITHUB_WORKFLOW:-}" ]]; then
        exposed="${exposed}workflow,"
        count=$((count + 1))
    fi
    if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
        exposed="${exposed}run_id,"
        count=$((count + 1))
    fi
    if [[ -n "${GITHUB_SHA:-}" ]]; then
        exposed="${exposed}sha,"
        count=$((count + 1))
    fi

    # PR attack surface (can be manipulated by PR author)
    if [[ -n "${GITHUB_HEAD_REF:-}" ]]; then
        exposed="${exposed}head_ref,"
        count=$((count + 1))
    fi
    if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
        exposed="${exposed}base_ref,"
        count=$((count + 1))
    fi

    # Event payload file (contains PR body, issue body - injection vectors)
    if [[ -n "${GITHUB_EVENT_PATH:-}" ]] && [[ -r "${GITHUB_EVENT_PATH:-}" ]]; then
        exposed="${exposed}event_payload,"
        count=$((count + 1))
        debug "scan_ci_github_deep: event payload readable at $GITHUB_EVENT_PATH"
    fi

    # Runner information
    if [[ -n "${RUNNER_NAME:-}" ]]; then
        exposed="${exposed}runner_name,"
        count=$((count + 1))
    fi
    if [[ -n "${RUNNER_OS:-}" ]]; then
        exposed="${exposed}runner_os,"
        count=$((count + 1))
    fi
    if [[ -n "${RUNNER_TEMP:-}" ]]; then
        exposed="${exposed}runner_temp,"
        count=$((count + 1))
    fi
    if [[ -n "${RUNNER_TOOL_CACHE:-}" ]]; then
        exposed="${exposed}tool_cache,"
        count=$((count + 1))
    fi

    # Cache and artifact URLs (lateral movement potential)
    if [[ -n "${ACTIONS_CACHE_URL:-}" ]]; then
        exposed="${exposed}cache_url,"
        count=$((count + 1))
    fi
    if [[ -n "${ACTIONS_RUNTIME_URL:-}" ]]; then
        exposed="${exposed}runtime_url,"
        count=$((count + 1))
    fi

    # Workspace (code checkout location)
    if [[ -n "${GITHUB_WORKSPACE:-}" ]] && [[ -d "${GITHUB_WORKSPACE:-}" ]]; then
        exposed="${exposed}workspace,"
        count=$((count + 1))
    fi

    exposed="${exposed%,}"

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "ci_github_deep" "exposed" "$count:$exposed" "medium"
    else
        emit "system_visibility" "ci_github_deep" "blocked" "" "medium"
    fi
}

# =============================================================================
# CI/CD: GitLab CI Deep Enumeration
# Severity: medium (metadata exposure enables targeted attacks)
# =============================================================================
scan_ci_gitlab_deep() {
    debug "scan_ci_gitlab_deep: starting"

    # Only run if we're in GitLab CI
    if [[ -z "${GITLAB_CI:-}" ]]; then
        emit "system_visibility" "ci_gitlab_deep" "not_found" "" "medium"
        return
    fi

    local exposed=""
    local count=0

    # Project metadata
    if [[ -n "${CI_PROJECT_ID:-}" ]]; then
        exposed="${exposed}project_id,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_PROJECT_PATH:-}" ]]; then
        exposed="${exposed}project_path,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_COMMIT_SHA:-}" ]]; then
        exposed="${exposed}commit_sha,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_PIPELINE_ID:-}" ]]; then
        exposed="${exposed}pipeline_id,"
        count=$((count + 1))
    fi

    # API access (can enumerate projects, users, etc.)
    if [[ -n "${CI_API_V4_URL:-}" ]]; then
        exposed="${exposed}api_url,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_SERVER_URL:-}" ]]; then
        exposed="${exposed}server_url,"
        count=$((count + 1))
    fi

    # Registry credentials (push access to container registry)
    if [[ -n "${CI_REGISTRY:-}" ]]; then
        exposed="${exposed}registry,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_REGISTRY_USER:-}" ]]; then
        exposed="${exposed}registry_user,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_REGISTRY_PASSWORD:-}" ]]; then
        exposed="${exposed}registry_pass,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_REGISTRY_IMAGE:-}" ]]; then
        exposed="${exposed}registry_image,"
        count=$((count + 1))
    fi

    # Dependency proxy (package registry access)
    if [[ -n "${CI_DEPENDENCY_PROXY_USER:-}" ]]; then
        exposed="${exposed}dep_proxy_user,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_DEPENDENCY_PROXY_PASSWORD:-}" ]]; then
        exposed="${exposed}dep_proxy_pass,"
        count=$((count + 1))
    fi

    # User identity
    if [[ -n "${GITLAB_USER_LOGIN:-}" ]]; then
        exposed="${exposed}user_login,"
        count=$((count + 1))
    fi
    if [[ -n "${GITLAB_USER_EMAIL:-}" ]]; then
        exposed="${exposed}user_email,"
        count=$((count + 1))
    fi
    if [[ -n "${GITLAB_USER_ID:-}" ]]; then
        exposed="${exposed}user_id,"
        count=$((count + 1))
    fi

    # Runner info
    if [[ -n "${CI_RUNNER_ID:-}" ]]; then
        exposed="${exposed}runner_id,"
        count=$((count + 1))
    fi
    if [[ -n "${CI_RUNNER_TAGS:-}" ]]; then
        exposed="${exposed}runner_tags,"
        count=$((count + 1))
    fi

    exposed="${exposed%,}"

    if [[ $count -gt 0 ]]; then
        emit "system_visibility" "ci_gitlab_deep" "exposed" "$count:$exposed" "medium"
    else
        emit "system_visibility" "ci_gitlab_deep" "blocked" "" "medium"
    fi
}

# =============================================================================
# CI/CD: Runner Type Detection (Self-hosted vs Managed)
# Severity: high (self-hosted = persistence risk, network access)
# =============================================================================
scan_ci_runner_type() {
    debug "scan_ci_runner_type: starting"

    local runner_type=""
    local indicators=""

    # GitHub Actions runner detection
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        # Check for self-hosted indicators
        local is_self_hosted=0

        # RUNNER_ENVIRONMENT is set to "github-hosted" for managed runners
        if [[ "${RUNNER_ENVIRONMENT:-}" == "self-hosted" ]]; then
            is_self_hosted=1
            indicators="${indicators}RUNNER_ENVIRONMENT,"
        fi

        # Self-hosted runners often have RUNNER_TRACKING_ID persisted
        if [[ -n "${RUNNER_TRACKING_ID:-}" ]]; then
            indicators="${indicators}tracking_id,"
        fi

        # Check for runner work directory with prior artifacts (non-ephemeral)
        if [[ -n "${RUNNER_WORKSPACE:-}" ]] && [[ -d "${RUNNER_WORKSPACE:-}" ]]; then
            # Count directories that might be from previous runs
            local prev_runs
            prev_runs=$(find "${RUNNER_WORKSPACE}" -maxdepth 2 -type d -name "_work" 2>/dev/null | wc -l) || prev_runs=0
            if [[ "$prev_runs" -gt 1 ]]; then
                is_self_hosted=1
                indicators="${indicators}multi_work_dirs,"
            fi
        fi

        # Check for .runner config file (self-hosted registration)
        if [[ -f "${HOME:-}/.runner" ]] || [[ -f "/home/runner/.runner" ]]; then
            is_self_hosted=1
            indicators="${indicators}runner_config,"
        fi

        # Check for actions runner directory
        if [[ -d "/actions-runner" ]] || [[ -d "${HOME:-}/actions-runner" ]]; then
            is_self_hosted=1
            indicators="${indicators}runner_dir,"
        fi

        if [[ $is_self_hosted -gt 0 ]]; then
            runner_type="github:self-hosted"
        else
            runner_type="github:managed"
        fi
    fi

    # GitLab runner detection
    if [[ -n "${GITLAB_CI:-}" ]]; then
        local is_self_hosted=0

        # Check runner executor type
        if [[ -n "${CI_RUNNER_EXECUTABLE_ARCH:-}" ]]; then
            indicators="${indicators}runner_arch,"
        fi

        # Shared runners have specific tags
        if [[ "${CI_RUNNER_TAGS:-}" == *"shared"* ]] || [[ "${CI_RUNNER_TAGS:-}" == *"gitlab-org"* ]]; then
            runner_type="gitlab:shared"
        else
            # Check for persistent runner home
            if [[ -d "/home/gitlab-runner" ]]; then
                is_self_hosted=1
                indicators="${indicators}gitlab_runner_home,"
            fi

            # Check for builds directory with prior builds
            if [[ -d "/builds" ]]; then
                local build_count
                build_count=$(find /builds -maxdepth 1 -mindepth 1 2>/dev/null | wc -l) || build_count=0
                if [[ "$build_count" -gt 1 ]]; then
                    is_self_hosted=1
                    indicators="${indicators}multi_builds,"
                fi
            fi

            if [[ $is_self_hosted -gt 0 ]]; then
                runner_type="gitlab:self-hosted"
            else
                runner_type="gitlab:managed"
            fi
        fi
    fi

    # Jenkins detection (always self-hosted)
    if [[ -n "${JENKINS_URL:-}" ]]; then
        runner_type="jenkins:self-hosted"
        if [[ -n "${NODE_NAME:-}" ]]; then
            indicators="${indicators}node:${NODE_NAME},"
        fi
    fi

    # Azure DevOps
    if [[ -n "${TF_BUILD:-}" ]]; then
        if [[ "${AGENT_NAME:-}" == "Hosted"* ]] || [[ "${AGENT_NAME:-}" == "Azure Pipelines"* ]]; then
            runner_type="azure:managed"
        else
            runner_type="azure:self-hosted"
            indicators="${indicators}agent:${AGENT_NAME:-unknown},"
        fi
    fi

    indicators="${indicators%,}"

    if [[ -z "$runner_type" ]]; then
        emit "system_visibility" "ci_runner_type" "not_found" "" "high"
    elif [[ "$runner_type" == *"self-hosted"* ]]; then
        emit "system_visibility" "ci_runner_type" "exposed" "$runner_type:$indicators" "high"
    else
        emit "system_visibility" "ci_runner_type" "exposed" "$runner_type" "low"
    fi
}

# =============================================================================
# CI/CD: Injection Vector Detection
# Severity: critical (writable files = code execution)
# =============================================================================
scan_ci_injection_vectors() {
    debug "scan_ci_injection_vectors: starting"

    # Only relevant in CI environments
    if [[ -z "${CI:-}" && -z "${GITHUB_ACTIONS:-}" && -z "${GITLAB_CI:-}" ]]; then
        emit "credentials" "ci_injection_vectors" "not_found" "" "critical"
        return
    fi

    local vectors=""
    local count=0

    # GitHub Actions injection files
    # These files influence subsequent steps - if writable by attacker, game over
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        if [[ -w "${GITHUB_ENV}" ]]; then
            vectors="${vectors}GITHUB_ENV:write,"
            count=$((count + 1))
            debug "scan_ci_injection_vectors: GITHUB_ENV writable"
        elif [[ -r "${GITHUB_ENV}" ]]; then
            vectors="${vectors}GITHUB_ENV:read,"
            count=$((count + 1))
        fi
    fi

    if [[ -n "${GITHUB_PATH:-}" ]]; then
        if [[ -w "${GITHUB_PATH}" ]]; then
            vectors="${vectors}GITHUB_PATH:write,"
            count=$((count + 1))
            debug "scan_ci_injection_vectors: GITHUB_PATH writable (PATH injection)"
        elif [[ -r "${GITHUB_PATH}" ]]; then
            vectors="${vectors}GITHUB_PATH:read,"
            count=$((count + 1))
        fi
    fi

    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        if [[ -w "${GITHUB_OUTPUT}" ]]; then
            vectors="${vectors}GITHUB_OUTPUT:write,"
            count=$((count + 1))
            debug "scan_ci_injection_vectors: GITHUB_OUTPUT writable"
        elif [[ -r "${GITHUB_OUTPUT}" ]]; then
            vectors="${vectors}GITHUB_OUTPUT:read,"
            count=$((count + 1))
        fi
    fi

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        if [[ -w "${GITHUB_STEP_SUMMARY}" ]]; then
            vectors="${vectors}GITHUB_STEP_SUMMARY:write,"
            count=$((count + 1))
        fi
    fi

    # Check if event payload is readable (contains PR body, issue body - user input)
    if [[ -n "${GITHUB_EVENT_PATH:-}" ]] && [[ -r "${GITHUB_EVENT_PATH}" ]]; then
        vectors="${vectors}EVENT_PAYLOAD:read,"
        count=$((count + 1))
        debug "scan_ci_injection_vectors: event payload readable (user input source)"
    fi

    # GitLab CI injection vectors
    if [[ -n "${CI_PROJECT_DIR:-}" ]]; then
        # Check if dotenv artifacts could be injected
        if [[ -w "${CI_PROJECT_DIR}" ]]; then
            vectors="${vectors}CI_PROJECT_DIR:write,"
            count=$((count + 1))
        fi
    fi

    vectors="${vectors%,}"

    if [[ $count -gt 0 ]]; then
        # Check for critical write vectors
        if [[ "$vectors" == *":write"* ]]; then
            emit "credentials" "ci_injection_vectors" "exposed" "$count:$vectors" "critical"
        else
            emit "credentials" "ci_injection_vectors" "exposed" "$count:$vectors" "medium"
        fi
    else
        emit "credentials" "ci_injection_vectors" "blocked" "" "critical"
    fi
}

# =============================================================================
# CI/CD: OIDC Token Availability
# Severity: critical (OIDC tokens can be exchanged for cloud credentials)
# =============================================================================
scan_ci_oidc() {
    debug "scan_ci_oidc: starting"

    local oidc_available=""
    local count=0

    # GitHub Actions OIDC
    # If both URL and token are present, OIDC is configured and usable
    if [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]] && [[ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
        oidc_available="${oidc_available}github_oidc,"
        count=$((count + 1))
        debug "scan_ci_oidc: GitHub OIDC token available"
    fi

    # GitLab OIDC (JWT tokens)
    if [[ -n "${CI_JOB_JWT:-}" ]]; then
        oidc_available="${oidc_available}gitlab_jwt,"
        count=$((count + 1))
        debug "scan_ci_oidc: GitLab CI_JOB_JWT available"
    fi
    if [[ -n "${CI_JOB_JWT_V2:-}" ]]; then
        oidc_available="${oidc_available}gitlab_jwt_v2,"
        count=$((count + 1))
        debug "scan_ci_oidc: GitLab CI_JOB_JWT_V2 available"
    fi

    # Azure DevOps OIDC
    if [[ -n "${SYSTEM_OIDCREQUESTURI:-}" ]]; then
        oidc_available="${oidc_available}azure_oidc,"
        count=$((count + 1))
        debug "scan_ci_oidc: Azure DevOps OIDC available"
    fi

    # CircleCI OIDC
    if [[ -n "${CIRCLE_OIDC_TOKEN:-}" ]]; then
        oidc_available="${oidc_available}circleci_oidc,"
        count=$((count + 1))
        debug "scan_ci_oidc: CircleCI OIDC token available"
    fi

    oidc_available="${oidc_available%,}"

    if [[ $count -gt 0 ]]; then
        emit "credentials" "ci_oidc" "exposed" "$count:$oidc_available" "critical"
    else
        # Only report if we're in a CI environment
        if [[ "${CI:-}" == "true" || -n "${GITHUB_ACTIONS:-}" || -n "${GITLAB_CI:-}" ]]; then
            emit "credentials" "ci_oidc" "blocked" "" "critical"
        else
            emit "credentials" "ci_oidc" "not_found" "" "critical"
        fi
    fi
}

# =============================================================================
# CI/CD: Git Config Token Leakage
# Severity: critical (checkout often embeds tokens in .git/config)
# =============================================================================
scan_ci_git_config() {
    debug "scan_ci_git_config: starting"

    # Determine workspace directory
    local workspace=""
    if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
        workspace="${GITHUB_WORKSPACE}"
    elif [[ -n "${CI_PROJECT_DIR:-}" ]]; then
        workspace="${CI_PROJECT_DIR}"
    elif [[ -n "${WORKSPACE:-}" ]]; then
        workspace="${WORKSPACE}"
    else
        # Not in CI or no workspace found
        emit "credentials" "ci_git_config" "not_found" "" "critical"
        return
    fi

    local git_config="$workspace/.git/config"
    local findings=""
    local count=0

    if [[ ! -f "$git_config" ]]; then
        emit "credentials" "ci_git_config" "not_found" "" "critical"
        return
    fi

    if [[ ! -r "$git_config" ]]; then
        emit "credentials" "ci_git_config" "blocked" "" "critical"
        return
    fi

    # Check for embedded tokens in remote URLs
    # Pattern: https://x-access-token:TOKEN@github.com or https://oauth2:TOKEN@gitlab.com
    if grep -qE 'url\s*=.*://[^:]+:[^@]+@' "$git_config" 2>/dev/null; then
        findings="${findings}embedded_token,"
        count=$((count + 1))
        debug "scan_ci_git_config: found embedded token in remote URL"
    fi

    # Check for extraheader with Authorization (GitHub Actions uses this)
    if grep -qi 'extraheader.*authorization' "$git_config" 2>/dev/null; then
        findings="${findings}auth_header,"
        count=$((count + 1))
        debug "scan_ci_git_config: found authorization header"
    fi

    # Check for credential helper configuration
    if grep -qi 'credential.*helper' "$git_config" 2>/dev/null; then
        findings="${findings}cred_helper,"
        count=$((count + 1))
    fi

    # Check for insteadOf rules (URL rewriting with tokens)
    if grep -qE 'insteadOf\s*=' "$git_config" 2>/dev/null; then
        findings="${findings}url_rewrite,"
        count=$((count + 1))
    fi

    findings="${findings%,}"

    if [[ $count -gt 0 ]]; then
        emit "credentials" "ci_git_config" "exposed" "$count:$findings" "critical"
    else
        emit "credentials" "ci_git_config" "blocked" "no_tokens" "critical"
    fi
}

# =============================================================================
# PERSONAL DATA: Shell History
# Severity: high
# =============================================================================
scan_shell_history() {
    debug "scan_shell_history: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "personal_data" "shell_history" "error" "no_home" "high"
        return
    fi

    local total_lines=0
    local sources=""
    local any_file_exists=0

    # Bash history
    local bash_hist="$HOME/.bash_history"
    if [[ -f "$bash_hist" ]]; then
        any_file_exists=1
        if [[ -r "$bash_hist" ]]; then
            local count
            count=$(count_lines "$bash_hist")
            count=$(to_int "$count")
            if [[ "$count" -gt 0 ]]; then
                total_lines=$((total_lines + count))
                sources="${sources}bash,"
                debug "scan_shell_history: bash_history has $count lines"
            fi
        fi
    fi

    # Zsh history
    local zsh_hist="$HOME/.zsh_history"
    if [[ -f "$zsh_hist" ]]; then
        any_file_exists=1
        if [[ -r "$zsh_hist" ]]; then
            local count
            count=$(count_lines "$zsh_hist")
            count=$(to_int "$count")
            if [[ "$count" -gt 0 ]]; then
                total_lines=$((total_lines + count))
                sources="${sources}zsh,"
                debug "scan_shell_history: zsh_history has $count lines"
            fi
        fi
    fi

    # Fish history
    local fish_hist="$HOME/.local/share/fish/fish_history"
    if [[ -f "$fish_hist" ]]; then
        any_file_exists=1
        if [[ -r "$fish_hist" ]]; then
            local count
            count=$(count_grep_matches "^- cmd:" "$fish_hist")
            count=$(to_int "$count")
            if [[ "$count" -gt 0 ]]; then
                total_lines=$((total_lines + count))
                sources="${sources}fish,"
                debug "scan_shell_history: fish_history has $count commands"
            fi
        fi
    fi

    sources="${sources%,}"

    if [[ "$total_lines" -gt 0 ]]; then
        emit "personal_data" "shell_history" "exposed" "${total_lines}/${sources}" "high"
    elif [[ $any_file_exists -gt 0 ]]; then
        emit "personal_data" "shell_history" "blocked" "" "high"
    else
        emit "personal_data" "shell_history" "not_found" "" "high"
    fi
}

# =============================================================================
# PERSISTENCE: Shell RC Write Access
# Severity: high
# =============================================================================
scan_shell_rc_write() {
    debug "scan_shell_rc_write: starting"

    if [[ -z "${HOME:-}" ]]; then
        emit "persistence" "shell_rc_write" "error" "no_home" "high"
        return
    fi

    local can_write=0
    local details=""

    # Shell RC files to check (platform may extend this)
    local rc_files="${SHELL_RC_FILES:-.zshrc .bashrc .profile .bash_profile .zprofile}"

    for rc in $rc_files; do
        local rc_path="$HOME/$rc"
        if file_writable "$rc_path"; then
            can_write=1
            details="${details}${rc},"
            debug "scan_shell_rc_write: $rc writable"
        elif [[ ! -f "$rc_path" ]] && dir_writable "$HOME"; then
            can_write=1
            details="${details}${rc}:create,"
        fi
    done

    details="${details%,}"

    if [[ $can_write -gt 0 ]]; then
        emit "persistence" "shell_rc_write" "exposed" "$details" "high"
    else
        emit "persistence" "shell_rc_write" "blocked" "" "high"
    fi
}

# =============================================================================
# PERSISTENCE: Temp Directory Write Access
# Severity: low
# =============================================================================
scan_tmp_write() {
    debug "scan_tmp_write: starting"

    local tmp_dir="${TMPDIR:-/tmp}"
    tmp_dir="${tmp_dir%/}"

    if [[ ! -d "$tmp_dir" ]]; then
        emit "persistence" "tmp_write" "not_found" "" "low"
        return
    fi

    # Actually test write access (not just permission bits)
    if dir_writable "$tmp_dir"; then
        emit "persistence" "tmp_write" "exposed" "" "low"
    else
        emit "persistence" "tmp_write" "blocked" "" "low"
    fi
}

# =============================================================================
# NETWORK: Outbound HTTP Access
# Severity: medium
# =============================================================================
scan_outbound_http() {
    debug "scan_outbound_http: starting"

    local http_cmd=""
    if has_cmd curl; then
        http_cmd="curl"
    elif has_cmd wget; then
        http_cmd="wget"
    else
        debug "scan_outbound_http: no HTTP client found"
        emit "network" "outbound_http" "error" "no_http_cmd" "medium"
        return
    fi

    local test_url="https://httpbin.org/status/200"
    local success=0

    if [[ "$http_cmd" == "curl" ]]; then
        local http_code
        http_code=$(with_timeout "$DEFAULT_TIMEOUT" curl -s -o /dev/null -w "%{http_code}" \
            --connect-timeout 5 -m 8 "$test_url" 2>/dev/null) || http_code=""

        if [[ "$http_code" == "200" ]]; then
            success=1
            debug "scan_outbound_http: curl succeeded (HTTP $http_code)"
        else
            debug "scan_outbound_http: curl failed (HTTP $http_code)"
        fi
    else
        if with_timeout "$DEFAULT_TIMEOUT" wget -q --spider --timeout=5 "$test_url" 2>/dev/null; then
            success=1
            debug "scan_outbound_http: wget succeeded"
        else
            debug "scan_outbound_http: wget failed"
        fi
    fi

    if [[ $success -gt 0 ]]; then
        emit "network" "outbound_http" "exposed" "$http_cmd" "medium"
    else
        emit "network" "outbound_http" "blocked" "" "medium"
    fi
}

# =============================================================================
# NETWORK: Cloud Metadata Endpoint Access
# Severity: critical
# =============================================================================
scan_cloud_metadata() {
    debug "scan_cloud_metadata: starting"

    if ! has_cmd curl; then
        debug "scan_cloud_metadata: curl not found"
        emit "network" "cloud_metadata" "error" "no_curl" "critical"
        return
    fi

    local found=0
    local providers=""

    # AWS metadata endpoint
    local aws_response
    aws_response=$(with_timeout 3 curl -s --connect-timeout 1 -m 2 \
        "http://169.254.169.254/latest/meta-data/" 2>/dev/null) || aws_response=""

    if [[ -n "$aws_response" && ! "$aws_response" =~ "404" && ! "$aws_response" =~ "error" ]]; then
        found=1
        providers="${providers}aws,"
        debug "scan_cloud_metadata: AWS metadata accessible"
    fi

    # Azure metadata endpoint
    local azure_response
    azure_response=$(with_timeout 3 curl -s --connect-timeout 1 -m 2 \
        -H "Metadata:true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null) || azure_response=""

    if [[ -n "$azure_response" && ! "$azure_response" =~ "404" && ! "$azure_response" =~ "error" ]]; then
        found=1
        providers="${providers}azure,"
        debug "scan_cloud_metadata: Azure metadata accessible"
    fi

    # GCP metadata endpoint
    local gcp_response
    gcp_response=$(with_timeout 3 curl -s --connect-timeout 1 -m 2 \
        -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null) || gcp_response=""

    if [[ -n "$gcp_response" && ! "$gcp_response" =~ "404" && ! "$gcp_response" =~ "error" ]]; then
        found=1
        providers="${providers}gcp,"
        debug "scan_cloud_metadata: GCP metadata accessible"
    fi

    providers="${providers%,}"

    if [[ $found -gt 0 ]]; then
        emit "network" "cloud_metadata" "exposed" "$providers" "critical"
    else
        emit "network" "cloud_metadata" "blocked" "" "critical"
    fi
}

# =============================================================================
# NETWORK: DNS Resolution
# Severity: medium
# =============================================================================
scan_dns_resolution() {
    debug "scan_dns_resolution: starting"

    local dns_cmd=""
    if has_cmd host; then
        dns_cmd="host"
    elif has_cmd nslookup; then
        dns_cmd="nslookup"
    elif has_cmd dig; then
        dns_cmd="dig"
    else
        debug "scan_dns_resolution: no DNS command found"
        emit "network" "dns_resolution" "error" "no_dns_cmd" "medium"
        return
    fi

    local success=0
    local test_host="dns.google"

    case "$dns_cmd" in
        host)
            if with_timeout 5 host "$test_host" >/dev/null 2>&1; then
                success=1
            fi
            ;;
        nslookup)
            if with_timeout 5 nslookup "$test_host" >/dev/null 2>&1; then
                success=1
            fi
            ;;
        dig)
            if with_timeout 5 dig +short "$test_host" >/dev/null 2>&1; then
                success=1
            fi
            ;;
    esac

    debug "scan_dns_resolution: $dns_cmd result=$success"

    if [[ $success -gt 0 ]]; then
        emit "network" "dns_resolution" "exposed" "$dns_cmd" "medium"
    else
        emit "network" "dns_resolution" "blocked" "" "medium"
    fi
}

# =============================================================================
# NETWORK: Local Services
# Severity: medium
# Checks if common local dev ports are accessible
# =============================================================================
scan_local_services() {
    debug "scan_local_services: starting"

    # Need nc or curl to probe ports
    local probe_cmd=""
    if has_cmd nc; then
        probe_cmd="nc"
    elif has_cmd curl; then
        probe_cmd="curl"
    else
        debug "scan_local_services: no probe command found"
        emit "network" "local_services" "error" "no_probe_cmd" "medium"
        return
    fi

    # Common dev ports to check
    local ports="3000 4000 5000 5432 6379 8000 8080 8888 9000 27017"
    local found_ports=""
    local count=0

    for port in $ports; do
        local is_open=0

        if [[ "$probe_cmd" == "nc" ]]; then
            if with_timeout 1 nc -z 127.0.0.1 "$port" 2>/dev/null; then
                is_open=1
            fi
        else
            # curl fallback - just check if connection is refused vs timeout
            local curl_result
            curl_result=$(with_timeout 1 curl -s -o /dev/null -w "%{http_code}" \
                "http://127.0.0.1:$port/" 2>/dev/null) || curl_result=""
            # Any response (even error) means port is open
            if [[ -n "$curl_result" && "$curl_result" != "000" ]]; then
                is_open=1
            fi
        fi

        if [[ $is_open -gt 0 ]]; then
            found_ports="${found_ports}${port},"
            count=$((count + 1))
            debug "scan_local_services: port $port open"
        fi
    done

    found_ports="${found_ports%,}"

    if [[ $count -gt 0 ]]; then
        emit "network" "local_services" "exposed" "$count:$found_ports" "medium"
    else
        emit "network" "local_services" "blocked" "" "medium"
    fi
}

# =============================================================================
# Run all network tests (cross-platform)
# =============================================================================
run_network_tests() {
    debug "run_network_tests: starting"
    progress_start "network"
    scan_outbound_http
    scan_cloud_metadata
    scan_dns_resolution
    scan_local_services
    progress_end "network"
    debug "run_network_tests: complete"
}

# =============================================================================
# SYSTEM VISIBILITY: Process List
# Severity: medium
# =============================================================================
scan_processes() {
    debug "scan_processes: starting"

    if ! has_cmd ps; then
        emit "system_visibility" "processes" "error" "no_ps_cmd" "medium"
        return
    fi

    local ps_output
    ps_output=$(with_timeout "$DEFAULT_TIMEOUT" ps aux 2>&1)
    local ps_exit=$?

    if [[ $ps_exit -ne 0 ]]; then
        debug "scan_processes: ps aux failed (exit=$ps_exit)"
        emit "system_visibility" "processes" "blocked" "" "medium"
        return
    fi

    local count=0
    if [[ -n "$ps_output" ]]; then
        count=$(echo "$ps_output" | wc -l) || count=0
        count=$(to_int "$count")
        if [[ "$count" -gt 1 ]]; then
            count=$((count - 1))  # subtract header
        fi
    fi

    if [[ "$count" -gt 0 ]]; then
        emit "system_visibility" "processes" "exposed" "$count" "medium"
    else
        emit "system_visibility" "processes" "blocked" "" "medium"
    fi
}

# =============================================================================
# SYSTEM VISIBILITY: Hostname
# Severity: low
# =============================================================================
scan_hostname() {
    debug "scan_hostname: starting"

    local hostname_val=""

    # Try hostname command first
    if has_cmd hostname; then
        hostname_val=$(with_timeout 2 hostname 2>/dev/null) || hostname_val=""
    fi

    # Fallback to reading /etc/hostname (Linux)
    if [[ -z "$hostname_val" ]] && [[ -r "/etc/hostname" ]]; then
        hostname_val=$(head -1 /etc/hostname 2>/dev/null) || hostname_val=""
    fi

    # Fallback to scutil (macOS)
    if [[ -z "$hostname_val" ]] && has_cmd scutil; then
        hostname_val=$(scutil --get ComputerName 2>/dev/null) || hostname_val=""
    fi

    debug "scan_hostname: got '$hostname_val'"

    if [[ -n "$hostname_val" ]]; then
        # Don't expose actual hostname, just that we could get it
        emit "system_visibility" "hostname" "exposed" "" "low"
    else
        emit "system_visibility" "hostname" "blocked" "" "low"
    fi
}

# =============================================================================
# SYSTEM VISIBILITY: OS Version
# Severity: info
# =============================================================================
scan_os_version() {
    debug "scan_os_version: starting"

    local os_info=""

    # Try uname first (cross-platform)
    if has_cmd uname; then
        os_info=$(uname -sr 2>/dev/null) || os_info=""
    fi

    # macOS: sw_vers for more detail
    if [[ -z "$os_info" ]] && has_cmd sw_vers; then
        os_info=$(sw_vers -productVersion 2>/dev/null) || os_info=""
    fi

    # Linux: /etc/os-release
    if [[ -z "$os_info" ]] && [[ -r "/etc/os-release" ]]; then
        os_info=$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2) || os_info=""
    fi

    debug "scan_os_version: got '$os_info'"

    if [[ -n "$os_info" ]]; then
        # Report the version since it's not sensitive
        emit "system_visibility" "os_version" "exposed" "$os_info" "info"
    else
        emit "system_visibility" "os_version" "blocked" "" "info"
    fi
}

# =============================================================================
# CREDENTIALS: SSH Agent Access
# Severity: high (can use keys without reading them)
# =============================================================================
scan_ssh_agent() {
    debug "scan_ssh_agent: starting"

    local found=0
    local details=""

    # Check if SSH_AUTH_SOCK is set
    if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
        emit "credentials" "ssh_agent" "not_found" "no_socket_env" "high"
        return
    fi

    # Check if socket exists and is accessible
    if [[ ! -S "$SSH_AUTH_SOCK" ]]; then
        emit "credentials" "ssh_agent" "not_found" "socket_missing" "high"
        return
    fi

    # Check socket readability
    if [[ ! -r "$SSH_AUTH_SOCK" ]]; then
        emit "credentials" "ssh_agent" "blocked" "socket_unreadable" "high"
        return
    fi

    found=1
    details="socket_exists"

    # Try to list keys in agent
    if has_cmd ssh-add; then
        local ssh_add_output
        ssh_add_output=$(with_timeout 5 ssh-add -l 2>&1)
        local exit_code=$?

        if [[ $exit_code -eq 0 && -n "$ssh_add_output" ]]; then
            # Count keys (each line is a key)
            local key_count
            key_count=$(echo "$ssh_add_output" | grep -c "^[0-9]") || key_count=0
            key_count=$(to_int "$key_count")
            if [[ $key_count -gt 0 ]]; then
                details="keys:$key_count"
                debug "scan_ssh_agent: $key_count keys in agent"
            fi
        elif echo "$ssh_add_output" | grep -qi "no identities"; then
            details="socket_ok/no_keys"
            debug "scan_ssh_agent: agent accessible but no keys"
        elif echo "$ssh_add_output" | grep -qi "could not open\|refused"; then
            emit "credentials" "ssh_agent" "blocked" "agent_refused" "high"
            return
        fi
    fi

    emit "credentials" "ssh_agent" "exposed" "$details" "high"
}
