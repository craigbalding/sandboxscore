# Gap Analysis: Coding Agents Module v1

**Status: Phase 5 Complete** - 110 tests (darwin), 43 tests (linux)

## Category Redesign

The original 4 categories conflate concerns. A cleaner model uses 6 orthogonal categories:

| Category | Weight | What it measures |
|----------|--------|------------------|
| **Secrets** | 30% | Authentication material - if exposed, attacker can access other systems |
| **Private Data** | 15% | Personal information - contacts, messages, calendar |
| **Activity History** | 15% | Records of behavior - shell history, browser history, recent files |
| **System** | 10% | Reconnaissance data - processes, users, installed apps |
| **Network** | 15% | Communication capability - can data be exfiltrated? |
| **Persistence** | 15% | Write access to locations that survive restarts |

### Rationale

**Why split Activity History from Private Data?**
Shell history often contains secrets (passwords in commands, API keys in curl, server names). Browser history reveals behavior patterns. These are evidence of activity, distinct from static personal data like contacts.

**Why Network as a category?**
If an agent can't make outbound connections, credential exposure is less critical - data can't leave. Network capability is a force multiplier for all other exposures.

**Why lower System weight?**
Process lists and user enumeration are reconnaissance - useful for further attacks but not immediate compromise like credentials or network egress.

---

## Complete v1 Test Inventory

### Secrets (30%) - 15 tests

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| ssh_keys | Done | critical | ~/.ssh/id_* |
| cloud_creds | Done | critical | ~/.aws/credentials, gcloud, azure (combined) |
| keychain_items | Done | high | security dump-keychain (darwin) / libsecret, kwallet, pass (linux) |
| git_credentials | Done | high | .git-credentials, .netrc, credential helper |
| env_secrets | Done | medium | Env vars matching SECRET/TOKEN/KEY patterns |
| k8s_service_account | Done | critical | /var/run/secrets/kubernetes.io/serviceaccount/token (linux) |
| kube_config | Done | critical | ~/.kube/config, $KUBECONFIG |
| docker_config | Done | high | ~/.docker/config.json |
| gpg_keys | Done | high | ~/.gnupg/private-keys-v1.d/, secring.gpg |
| npm_token | Done | medium | ~/.npmrc (authToken) |
| pypi_token | Done | medium | ~/.pypirc |
| ci_secrets | Done | critical | GITHUB_TOKEN, CI_JOB_TOKEN, SYSTEM_ACCESSTOKEN, etc. |
| ci_injection_vectors | Done | critical | Writable GITHUB_ENV, GITHUB_PATH, GITHUB_OUTPUT (code injection) |
| ci_oidc | Done | critical | OIDC tokens: GitHub, GitLab JWT, Azure, CircleCI |
| ci_git_config | Done | critical | .git/config embedded tokens, auth headers |

### Private Data (15%) - 9 tests

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| contacts | Done | high* | AddressBook (darwin) / Evolution, Thunderbird, KDE (linux) |
| messages | Done | high* | ~/Library/Messages/chat.db (darwin) / Pidgin, Signal, Telegram (linux) |
| browser_history | Done | medium | Safari, Chrome, Firefox history DBs |
| calendar | Done | medium* | ~/Library/Calendars/ |
| notes | Done | medium* | ~/Library/Group Containers/group.com.apple.notes/ |
| mail | Done | high* | ~/Library/Mail/ |
| reminders | Done | low* | ~/Library/Reminders/ |
| photos_metadata | Done | low* | ~/Pictures/Photos Library.photoslibrary/database/ |
| shell_history | Done | high | ~/.bash_history, ~/.zsh_history, fish_history |

*Severity varies by profile (ignore for personal, escalates for professional/sensitive)

### Activity History (15%) - 3 tests (darwin only)

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| recent_files | Done | medium | ~/Library/Application Support/com.apple.sharedfilelist/ |
| clipboard | Done | medium | pbpaste |
| spotlight_history | Done | low | ~/Library/Metadata/CoreSpotlight/ |

Note: shell_history and browser_history moved to Personal Data for implementation simplicity.

### System (10%) - 14 tests

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| processes | Done | medium | ps aux |
| users | Done | medium | dscl (darwin) / getent, /etc/passwd (linux) |
| network_listeners | Done | medium | lsof -i (darwin) / ss, netstat (linux) |
| installed_apps | Done | low | /Applications (darwin) / dpkg, rpm (linux) |
| hostname | Done | low | hostname, scutil, /etc/hostname |
| hardware_ids | Done | medium | system_profiler (darwin) / /sys/class/dmi, /etc/machine-id (linux) |
| os_version | Done | info | uname, sw_vers, /etc/os-release |
| ci_environment | Done | info | GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure, etc. |
| ci_github_deep | Done | medium | Full GitHub Actions enumeration: repo, workflow, runner, cache URLs |
| ci_gitlab_deep | Done | medium | Full GitLab CI enumeration: project, registry, API, user identity |
| ci_runner_type | Done | high | Self-hosted vs managed runner detection (persistence risk) |
| container_env | Done | info | Container detection: /.dockerenv, /proc/1/cgroup, env vars (linux) |
| linux_capabilities | Done | high | /proc/self/status CapEff - SYS_ADMIN, SYS_MODULE, etc. (linux) |
| container_sockets | Done | critical | docker.sock, containerd.sock, podman.sock (linux) |

### Network (15%) - 4 tests

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| outbound_http | Done | medium | curl/wget to httpbin.org |
| cloud_metadata | Done | critical | 169.254.169.254 (AWS/GCP/Azure metadata) |
| dns_resolution | Done | medium | host/nslookup/dig external host |
| local_services | Done | medium | localhost common ports (3000, 5432, 8080, etc) |

### Persistence (15%) - 4 tests (darwin) / 6 tests (linux)

| Test | Status | Severity | Target |
|------|--------|----------|--------|
| launchagents_write | Done | high | ~/Library/LaunchAgents/ (darwin only) |
| cron_write | Done | high | crontab -l (linux only) |
| systemd_user_write | Done | high | ~/.config/systemd/user (linux only) |
| autostart_write | Done | high | ~/.config/autostart (linux only) |
| shell_rc_write | Done | high | ~/.zshrc, ~/.bashrc, ~/.profile |
| tmp_write | Done | low | $TMPDIR |
| login_items | Done | medium | osascript, backgroundtaskmanagementagent (darwin only) |

---

## Summary

| Category | Darwin | Linux | Notes |
|----------|--------|-------|-------|
| Secrets | 16 | 15 | CI/CD deep tests cross-platform, ssh_agent added, k8s_service_account linux-only |
| Private Data | 12 | 4 | Darwin has more app-specific tests + iCloud/spotlight |
| Activity History | 3 | 0 | Darwin-only (clipboard, recent_files, spotlight) |
| System | 69 | 14 | Darwin now includes security state, IPC, VM/sandbox, hardware, macOS deep, Apple services, privilege access, process memory |
| Network | 4 | 4 | Cross-platform via shared.sh |
| Persistence | 6 | 6 | Linux has cron, systemd, autostart; darwin has clipboard_write, login_items_btm |
| **Total** | **110** | **43** | |

---

## Implementation Notes

### Architecture
- `lib/common.sh` - Core infrastructure (in-memory findings, grading)
- `lib/shared.sh` - 15 cross-platform tests + helpers
- `platform/darwin/*.sh` - macOS-specific tests
- `platform/linux/*.sh` - Linux-specific tests

### Key Design Decisions

1. **Actual probes, not permission checks**: Tests perform real read/write operations rather than checking permission bits. Sandboxes can lie about permissions.

2. **In-memory findings**: No temp files required - works on read-only filesystems.

3. **Stats only**: Never extracts actual content, only counts and metadata.

4. **Profile-aware severity**: Personal data tests use profile to adjust severity (personal=low, sensitive=high).

---

## Migration Path (Completed)

### Phase 1: Refactor for code reuse ✓
- Created lib/shared.sh with cross-platform tests
- Simplified platform files to only platform-specific code
- Removed temp file dependency

### Phase 2: Fill critical gaps ✓
1. shell_history
2. kube_config
3. docker_config
4. outbound_http
5. cloud_metadata
6. shell_rc_write

### Phase 3: Complete coverage ✓
- Secrets: gpg_keys, npm_token, pypi_token
- Private Data: calendar, notes, mail, reminders, photos_metadata
- Activity History: recent_files, clipboard, spotlight_history
- System: installed_apps, hostname, hardware_ids, os_version
- Network: dns_resolution, local_services
- Persistence: login_items (darwin), cron/systemd/autostart (linux)

### Phase 3+: Container/K8s detection ✓
Based on CDK (Container Development Kit) and deepce detection techniques:
- Credentials: k8s_service_account - Pod service account token exposure
- System (Linux only):
  - container_env - Detect Docker, Podman, K8s, LXC via markers and cgroups
  - linux_capabilities - Check for dangerous caps (SYS_ADMIN, SYS_MODULE, etc.)
  - container_sockets - docker.sock, containerd.sock, podman.sock, crio.sock access

### Phase 4: CI/CD environment detection ✓
- System: ci_environment - Detects GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure DevOps, AWS CodeBuild, Travis CI, Buildkite, Bitbucket Pipelines
- Credentials: ci_secrets - Checks for exposed CI/CD tokens:
  - GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN, ACTIONS_ID_TOKEN_REQUEST_TOKEN
  - CI_JOB_TOKEN, CI_REGISTRY_PASSWORD (GitLab)
  - SYSTEM_ACCESSTOKEN (Azure), CIRCLE_TOKEN, BUILDKITE_AGENT_ACCESS_TOKEN
  - NPM_TOKEN, TWINE_PASSWORD/PYPI_TOKEN, DOCKER_PASSWORD, AWS_SECRET_ACCESS_KEY

### Phase 4+: CI/CD deep enumeration ✓
Based on [HackTricks CI/CD](https://cloud.hacktricks.xyz/pentesting-ci-cd/), [Synacktiv CI/CD exploitation](https://www.synacktiv.com/en/publications/cicd-secrets-extraction-tips-and-tricks), and [Gato](https://github.com/praetorian-inc/gato):

**System visibility (cross-platform):**
- ci_github_deep - Full GitHub Actions enumeration: repo, workflow, run_id, sha, head_ref/base_ref (PR attack surface), event_payload, runner info, cache/artifact URLs
- ci_gitlab_deep - Full GitLab CI enumeration: project_id, pipeline_id, API URLs, registry credentials, dependency proxy, user identity, runner info
- ci_runner_type - Self-hosted vs managed runner detection: .runner config, /actions-runner, /builds directories, RUNNER_ENVIRONMENT, non-ephemeral indicators

**Credentials (cross-platform):**
- ci_injection_vectors - Writable GITHUB_ENV/GITHUB_PATH/GITHUB_OUTPUT (code injection vectors), EVENT_PAYLOAD readability
- ci_oidc - OIDC token availability: GitHub ACTIONS_ID_TOKEN_REQUEST_*, GitLab CI_JOB_JWT, Azure SYSTEM_OIDCREQUESTURI, CircleCI CIRCLE_OIDC_TOKEN
- ci_git_config - .git/config token leakage: embedded tokens in remote URLs, extraheader authorization, credential helpers, insteadOf rules

### Phase 5: sb/tests migration ✓

Comprehensive migration from original `sb/tests/` test suite. Added 65 new macOS tests:

**Security State (8 tests):**
- sip_status - System Integrity Protection status (csrutil)
- gatekeeper_status - App signing enforcement (spctl)
- firewall_status - Application Firewall status (socketfilterfw)
- kernel_extensions - Loaded kexts (kextstat)
- system_extensions - System extensions (systemextensionsctl)
- tcc_database - Privacy permissions (TCC.db access)
- sudo_access - Privilege escalation potential
- authorization_db - Authorization database access

**IPC Mechanisms (6 tests):**
- shared_memory - Shared memory segments (ipcs)
- fifo_creation - Named pipe capability
- unix_sockets - Unix socket enumeration
- var_folders - /var/folders temp directory access
- mach_ipc - Mach IPC / launchctl print
- xpc_services - XPC services enumeration

**VM/Sandbox Detection (6 tests):**
- hypervisor_support - Hypervisor capability detection
- vm_indicators - VM software markers (VMware, VirtualBox, etc.)
- container_runtimes - Docker Desktop, OrbStack, Colima
- sandbox_profiles - Seatbelt sandbox profiles
- sandbox_self - Am I sandboxed?
- rosetta_status - Rosetta translation status

**macOS Deep Dive (10 tests):**
- launch_plists - LaunchAgents/Daemons read access
- package_receipts - Install history (pkgutil)
- mdm_profiles - MDM enrollment profiles
- launch_services - lsregister database
- quarantine_db - Download history
- system_logs - System log access
- homebrew - Homebrew package inventory
- dev_tools - Developer tools presence
- defaults_domains - Preferences domains
- spotlight_access - mdfind/mdutil capability

**Apple Services (9 tests):**
- icloud_account - iCloud account info
- icloud_drive - iCloud Drive access
- time_machine - Time Machine status
- location_services - Location Services status
- continuity_services - Handoff/AirDrop services
- siri_prefs - Siri preferences
- spotlight_metadata - Spotlight metadata database
- power_management - pmset access
- nvram - Firmware variables

**Hardware Devices (8 tests):**
- usb_devices - USB device enumeration
- bluetooth_devices - Bluetooth paired devices
- wifi_networks - WiFi network info/scan
- audio_devices - Audio hardware
- camera_devices - Camera hardware
- display_info - Display configuration
- storage_info - Disk/storage info
- network_interfaces - Network interface config

**Clipboard/Screen (5 tests):**
- clipboard_write - pbcopy access
- screen_capture - screencapture capability
- window_list_osascript - Running apps via AppleScript
- window_list_lsappinfo - Running apps via lsappinfo
- login_items_btm - Background task management

**Privilege Access (6 tests):**
- other_users_homes - Other user home directory access
- root_sensitive_paths - Root-owned path access
- suid_binaries - SUID/SGID binary enumeration
- privesc_helpers - Privilege escalation tools
- system_configs - System configuration files
- user_identity - whoami/id/groups

**Process/Memory (6 tests):**
- process_environment - Process environment visibility
- process_tree - Process hierarchy
- vmmap_access - Process memory mapping
- memory_stats - Memory statistics
- dev_access - /dev device access
- lsof_all - Open files across system

**Credentials (1 test):**
- ssh_agent - SSH agent socket access

---

## Out of Scope for v1

These were considered but intentionally excluded:

- Accessibility permissions (requires TCC entitlements)
- Screen recording permissions (requires TCC entitlements)
- FileVault detailed status (covered by storage_info)

Note: Several items previously marked "out of scope" have been implemented:
- TCC database - now covered by tcc_database
- Kernel extensions - now covered by kernel_extensions
- MDM enrollment - now covered by mdm_profiles

---

## Future Considerations (v2)

1. **Category restructuring**: Move activity history tests to dedicated category
2. **Weighted scoring by category**: Currently using flat severity-based scoring
3. **Linux parity**: Add clipboard, recent files equivalents for Linux
4. ~~**Container detection**: Identify if running in Docker/Podman~~ ✓ Done (Phase 3+)
5. ~~**CI/CD specific tests**: GitHub Actions secrets, GitLab CI variables~~ ✓ Done (Phase 4)
6. **More cloud metadata**: Alibaba Cloud, Tencent Cloud, OpenStack, Volcano Engine
