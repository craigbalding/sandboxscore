# Audit: sb/tests vs sandboxscore

**Status:** INCOMPLETE MIGRATION - Many tests missing

This audit compares the original tests in `sb/tests/` with what was implemented in `sandboxscore/agents/`.

## Legend
- [x] Implemented in sandboxscore
- [ ] **MISSING** - needs implementation
- [-] Partial / different approach

---

## tmp-ipc.sh - IPC and Temp Files

| Test | Status | Notes |
|------|--------|-------|
| /tmp, TMPDIR write | [x] | tmp_write in persistence |
| /var/folders access | [ ] | **MISSING** |
| ipcs (shared memory) | [ ] | **MISSING** |
| Named pipes/FIFOs | [ ] | **MISSING** |
| Unix socket enumeration | [ ] | **MISSING** |
| launchctl print system | [ ] | **MISSING** - Mach IPC |
| /System/Library/XPCServices | [ ] | **MISSING** - XPC enumeration |
| App bundle XPCServices | [ ] | **MISSING** |

## security-state.sh - Security Configuration

| Test | Status | Notes |
|------|--------|-------|
| csrutil status (SIP) | [ ] | **MISSING** |
| spctl status (Gatekeeper) | [ ] | **MISSING** |
| socketfilterfw (Firewall) | [ ] | **MISSING** |
| kextstat (Kernel extensions) | [ ] | **MISSING** |
| systemextensionsctl | [ ] | **MISSING** |
| TCC.db query | [ ] | **MISSING** |
| sudo -l | [ ] | **MISSING** |
| /etc/sudoers read | [ ] | **MISSING** |

## vm-sandbox.sh - VM/Sandbox Detection

| Test | Status | Notes |
|------|--------|-------|
| sysctl kern.hv_support | [ ] | **MISSING** - VM detection |
| ioreg VM indicators | [ ] | **MISSING** |
| Docker Desktop/OrbStack | [ ] | **MISSING** |
| Seatbelt profiles listing | [ ] | **MISSING** |
| Rosetta status | [ ] | **MISSING** |
| arch/uname | [x] | os_version covers this |

## macos-deep.sh - macOS Deep Dive

| Test | Status | Notes |
|------|--------|-------|
| /Applications listing | [x] | installed_apps |
| /Library/LaunchAgents read | [-] | Only check write, not read |
| /Library/LaunchDaemons read | [-] | Only check write, not read |
| /System/Library/LaunchAgents | [ ] | **MISSING** |
| pkgutil --packages | [ ] | **MISSING** - install history |
| profiles list | [ ] | **MISSING** - MDM profiles |
| lsregister dump | [ ] | **MISSING** - Launch Services |
| Quarantine database | [ ] | **MISSING** |
| /var/db/receipts | [ ] | **MISSING** |
| /var/audit, /var/log | [ ] | **MISSING** |
| Authorization database | [ ] | **MISSING** |
| Crash reports | [ ] | **MISSING** |
| Homebrew inventory | [ ] | **MISSING** |

## apple-services.sh - Apple Services

| Test | Status | Notes |
|------|--------|-------|
| iCloud account info | [ ] | **MISSING** |
| iCloud Drive paths | [ ] | **MISSING** |
| Continuity/Handoff | [ ] | **MISSING** |
| Siri prefs | [ ] | **MISSING** |
| Spotlight mdutil status | [ ] | **MISSING** |
| Time Machine status | [ ] | **MISSING** |
| Location Services | [ ] | **MISSING** |

## clipboard-screen.sh - Clipboard/Screen

| Test | Status | Notes |
|------|--------|-------|
| pbpaste | [x] | clipboard |
| pbcopy | [ ] | **MISSING** - write capability |
| screencapture | [ ] | **MISSING** |
| Window/app listing (lsappinfo) | [ ] | **MISSING** |
| osascript running apps | [ ] | **MISSING** |

## comms-privacy.sh - Communications

| Test | Status | Notes |
|------|--------|-------|
| Messages/chat.db | [x] | messages |
| Mail | [x] | mail |
| Contacts | [x] | contacts |
| Calendar | [x] | calendar |
| Safari/WebKit processes | [ ] | **MISSING** |
| Notifications (usernoted) | [ ] | **MISSING** |
| Screen Time | [ ] | **MISSING** |

## hardware-devices.sh - Hardware

| Test | Status | Notes |
|------|--------|-------|
| system_profiler Hardware | [x] | hardware_ids |
| Serial number | [x] | hardware_ids |
| USB devices | [ ] | **MISSING** |
| Bluetooth devices | [ ] | **MISSING** |
| WiFi networks (airport scan) | [ ] | **MISSING** |
| Audio devices | [ ] | **MISSING** |
| Camera devices | [ ] | **MISSING** |
| diskutil | [ ] | **MISSING** |

## info-leakage.sh - Information Leakage

| Test | Status | Notes |
|------|--------|-------|
| uname, sw_vers | [x] | os_version |
| hostname | [x] | hostname |
| whoami, id, groups | [ ] | **MISSING** |
| dscl list users | [x] | users |
| ps aux | [x] | processes |
| netstat/lsof | [x] | network_listeners |
| launchctl list | [ ] | **MISSING** |
| launchctl print | [ ] | **MISSING** |
| defaults domains | [ ] | **MISSING** |
| mdfind/mdls | [ ] | **MISSING** |
| csrutil/spctl | [ ] | **MISSING** |
| TCC.db | [ ] | **MISSING** |
| nvram | [ ] | **MISSING** |
| security dump-keychain | [x] | keychain_items |

## env-creds.sh - Environment/Credentials

| Test | Status | Notes |
|------|--------|-------|
| env dump | [x] | env_secrets |
| SSH_AUTH_SOCK | [ ] | **MISSING** - agent access |
| ssh-add -l | [ ] | **MISSING** |
| GPG agent | [x] | gpg_keys |
| git credential helper | [x] | git_credentials |
| aws/gcloud/az CLI | [x] | cloud_creds |
| kubectl | [x] | kube_config |
| docker config | [x] | docker_config |

## other-users.sh - Other Users

| Test | Status | Notes |
|------|--------|-------|
| /Users listing | [x] | users |
| /var/root access | [ ] | **MISSING** |
| /etc/master.passwd | [ ] | **MISSING** |
| SUID/SGID binaries | [ ] | **MISSING** |
| /etc/ssh access | [ ] | **MISSING** |
| /etc/pam.d | [ ] | **MISSING** |

## process-signals.sh - Process/Memory

| Test | Status | Notes |
|------|--------|-------|
| ps aux | [x] | processes |
| lsof | [x] | network_listeners |
| vmmap (process memory) | [ ] | **MISSING** |
| vm_stat | [ ] | **MISSING** |
| /dev enumeration | [ ] | **MISSING** |

## write-persist.sh - Write/Persistence

| Test | Status | Notes |
|------|--------|-------|
| /tmp write | [x] | tmp_write |
| /usr/local write | [ ] | **MISSING** |
| /Library write | [ ] | **MISSING** |
| LaunchAgents write | [x] | launchagents_write |
| crontab | [x] | cron_write (linux) |
| DYLD injection paths | [ ] | **MISSING** |

## secrets.sh - Already covered

Most of these are covered by existing credential tests.

## network.sh - Network

| Test | Status | Notes |
|------|--------|-------|
| curl/wget | [x] | outbound_http |
| DNS lookup | [x] | dns_resolution |
| Unix socket connect | [ ] | **MISSING** |

---

## Summary: Missing Test Categories

### High Priority (Security-Critical)
1. **Security state** - SIP, Gatekeeper, Firewall, TCC, kernel extensions
2. **XPC/Mach IPC** - launchctl print, XPCServices enumeration
3. **VM/Sandbox detection** - Are we being observed/contained?
4. **SUID/SGID binaries** - Privilege escalation vectors

### Medium Priority (Privacy/Recon)
5. **Apple services** - iCloud, Time Machine, Location Services
6. **Hardware enumeration** - USB, Bluetooth, WiFi, Audio/Video
7. **Install history** - pkgutil, receipts, MDM profiles
8. **Launch Services** - lsregister, defaults domains

### Lower Priority (Edge Cases)
9. **IPC mechanisms** - Shared memory, FIFOs, Unix sockets
10. **Process memory** - vmmap access
11. **System logs** - /var/log, audit logs

---

## Count

- **Original sb/tests:** ~180 distinct checks across 17 files
- **Implemented in sandboxscore:** ~45 tests
- **Missing:** ~60+ significant checks not migrated
