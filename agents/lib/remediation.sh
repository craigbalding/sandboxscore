#!/bin/bash
# SandboxScore - Remediation Hints Database
#
# Provides actionable guidance for exposed findings.
# Used by output functions to show recommendations.

# Get remediation hint for a test finding
# Returns: remediation hint string, or empty if none available
get_remediation() {
    local test_name="$1"

    case "$test_name" in
        # === CREDENTIALS ===
        ssh_keys)
            echo "Move SSH keys outside sandbox or use hardware key (YubiKey). Consider ssh-agent forwarding with confirmation."
            ;;
        cloud_creds)
            echo "Use IAM roles, instance profiles, or credential helpers instead of static credentials."
            ;;
        keychain_items)
            echo "Configure sandbox to block login keychain access. Use ephemeral credentials."
            ;;
        git_credentials)
            echo "Use credential helpers with short-lived tokens. Clear .git-credentials after sessions."
            ;;
        env_secrets)
            echo "Use secret manager or credential helper instead of env vars. Avoid secrets in process environment."
            ;;
        kube_config)
            echo "Use short-lived tokens via kubectl auth. Avoid persistent kubeconfig with long-lived certs."
            ;;
        docker_config)
            echo "Use credential helpers instead of storing auth tokens in config.json."
            ;;
        gpg_keys)
            echo "Move private keys outside sandbox. Consider hardware tokens for signing."
            ;;
        npm_token|pypi_token)
            echo "Use short-lived tokens or package registry proxies. Avoid global npmrc/pypirc."
            ;;
        ci_secrets)
            echo "Minimize token scopes. Use OIDC federation instead of long-lived tokens."
            ;;
        ci_oidc)
            echo "OIDC is powerful - ensure cloud role trust policies are scoped correctly."
            ;;
        ssh_agent)
            echo "Use ssh-agent with confirmation prompts. Consider per-session agent isolation."
            ;;
        k8s_service_account)
            echo "Bind to minimal RBAC role. Consider disabling automount in pod spec."
            ;;

        # === PERSONAL DATA ===
        shell_history)
            echo "Clear history or set HISTFILE to /dev/null in sandbox. Avoid storing secrets in commands."
            ;;
        browser_history|browser_data)
            echo "Use dedicated browser profile for sandboxed sessions. Clear data on exit."
            ;;
        clipboard)
            echo "Clear clipboard after sensitive operations. Use clipboard managers with timeout."
            ;;
        contacts|calendar|notes|messages|mail)
            echo "Run sandbox in separate user account or VM without access to personal data stores."
            ;;

        # === SYSTEM VISIBILITY ===
        processes)
            echo "Run in container with PID namespace isolation. Use hidepid mount option."
            ;;
        hostname)
            echo "Use container UTS namespace isolation. Set randomized hostname in sandbox."
            ;;
        network_topology|network_interfaces)
            echo "Use network namespace isolation. Consider network policy to limit visibility."
            ;;
        installed_apps)
            echo "Run in minimal container without host application list access."
            ;;

        # === PERSISTENCE ===
        shell_rc_write)
            echo "Make RC files read-only in sandbox. Use immutable containers."
            ;;
        launchagents_write)
            echo "Block write access to LaunchAgents directories. Use ephemeral sandboxes."
            ;;
        tmp_write)
            echo "Use tmpfs with noexec if persistence is a concern."
            ;;

        # === NETWORK / EGRESS ===
        outbound_http|egress_connectivity)
            echo "Configure network policy to block outbound except allowlist."
            ;;
        egress_destinations)
            echo "Block paste sites, webhooks, and file upload services at firewall/proxy."
            ;;
        egress_dns)
            echo "Force DNS through controlled resolver. Block DoH endpoints."
            ;;
        dns_resolution)
            echo "Use network namespace with controlled DNS. Consider DNS filtering."
            ;;
        cloud_metadata)
            echo "Block 169.254.169.254 at network level. Use IMDSv2 with hop limit."
            ;;
        local_services)
            echo "Isolate sandbox network. Use localhost proxy for required services only."
            ;;

        # === INTELLIGENCE ===
        file_databases)
            echo "Run in separate user account without access to application databases."
            ;;
        services_launchd)
            echo "Use container runtime isolation. Minimize visible services."
            ;;

        # === macOS SPECIFIC ===
        sip_status)
            echo "SIP visibility reveals system security state. Consider VM isolation."
            ;;
        tcc_database)
            echo "TCC database reveals granted permissions. Use sandboxed processes."
            ;;
        icloud_account)
            echo "Run sandbox in separate user account without iCloud access."
            ;;

        # Default: no remediation available
        *)
            echo ""
            ;;
    esac
}
