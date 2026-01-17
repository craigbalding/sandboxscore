# Methodology

SandboxScore measures exposure through unprivileged probing. It reports what's reachable, not what's protected.

## Principles

1. **Stats only** - Count items, never extract content. "150 keychain items" not the items themselves.
2. **Passive probing** - Check accessibility, don't exploit. Read metadata, not data.
3. **No persistence** - Leave no trace. Clean up test files immediately.
4. **Fail safe** - Missing commands or resources = not_found, not errors.

## Probe Types

| Type | What it does | Example |
|------|--------------|---------|
| File existence | Check if path exists and is readable | `[[ -r ~/.ssh/id_rsa ]]` |
| Directory enumeration | Count items matching pattern | Count `~/.ssh/id_*` files |
| Command output | Run safe commands, count results | `ps aux | wc -l` |
| Database queries | COUNT(*) queries only | `SELECT COUNT(*) FROM contacts` |
| Write tests | Touch temp file, delete immediately | `touch $path && rm $path` |
| Process enumeration | Discover running processes via ps/lsof | `lsof -c '' \| wc -l` |
| Network topology | Map local IPs, connections, LAN | `ifconfig`, `arp -a` |
| Egress testing | Test outbound connectivity | `curl -s http://example.com` |
| Service discovery | Enumerate launchd/systemd services | `launchctl list` |

## Status Flow

```
Resource doesn't exist     → not_found (no points)
Resource exists, blocked   → blocked (no points)
Resource exists, readable  → exposed (points based on severity)
Probe can't run           → error (no points)
```

## Grading

Points lost per exposed resource, by severity:

| Severity | Points | Grade cap |
|----------|--------|-----------|
| critical | 50 | B max |
| high | 20 | - |
| medium | 5 | - |
| low | 1 | - |

Grade thresholds: A+ (0), A (1-5), B (6-20), C (21-50), D (51-100), F (101+)

## Profile Adjustments

Same finding, different context:

| Finding | personal | professional | sensitive |
|---------|----------|--------------|-----------|
| contacts | ignore | medium | high |
| messages | ignore | high | critical |
| browser_history | low | medium | high |

Profiles don't change what's probed—only how findings are weighted.

## Architecture

```
                              USER INVOCATION
  ┌─────────────────────────────────────────────────────────────────────┐
  │  $ ./agents/run.sh -p professional -f json                          │
  │  $ ./sandboxscore/agents/run.sh                                     │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  run.sh                                                             │
  │  ┌────────────────────┐  ┌────────────────────┐                     │
  │  │ SECURITY HARDENING │  │ PARSE ARGS         │                     │
  │  │ • unset IFS        │  │ • --profile        │                     │
  │  │ • sanitize PATH    │  │ • --format         │                     │
  │  │ • LC_ALL=C         │  │                    │                     │
  │  └────────────────────┘  └────────────────────┘                     │
  │                    │                                                │
  │          source lib/common.sh                                       │
  │          source platform/darwin/*.sh                                │
  │                    │                                                │
  │          run_*_tests() ───▶ output_results()                        │
  └────────────────────┬───────────────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
  ┌─────────────────────┐    ┌─────────────────────────────────────────┐
  │  lib/common.sh      │    │  platform/darwin/                       │
  │  ─────────────────  │    │  ─────────────────                      │
  │  UTILITIES          │    │  credentials.sh                         │
  │  • to_int()         │    │   • scan_ssh_keys()                     │
  │  • has_cmd()        │    │   • scan_cloud_creds()                  │
  │  • with_timeout()   │    │   • scan_keychain_items()               │
  │                     │    │   • scan_git_credentials()              │
  │  FINDINGS           │    │   • scan_env_secrets()                  │
  │  • emit()           │    │                                         │
  │  • foreach_finding()│    │  personal_data.sh                       │
  │                     │    │   • scan_contacts()                     │
  │  GRADING            │    │   • scan_messages()                     │
  │  • calculate_grade()│    │   • scan_browser_history()              │
  │  • check_grade_caps │    │                                         │
  │                     │    │  system_visibility.sh                   │
  │  OUTPUT             │    │   • scan_processes()                    │
  │  • output_human()   │    │   • scan_users()                        │
  │  • output_json()    │    │   • scan_network_listeners()            │
  │  • output_raw()     │    │                                         │
  └─────────────────────┘    │  persistence.sh                         │
                             │   • scan_launchagents_write()           │
                             │                                         │
                             │  intelligence.sh (orchestrator)         │
                             │   • intel_processes.sh                  │
                             │   • intel_network.sh                    │
                             │   • intel_files.sh                      │
                             │   • intel_services.sh                   │
                             │   • lib/intel_egress.sh (cross-platform)│
                             └─────────────────────────────────────────┘

                              SCAN PATTERN
  ┌─────────────────────────────────────────────────────────────────────┐
  │  1. Check prerequisites (HOME set? command exists?)                 │
  │  2. Check resource exists                                           │
  │  3. Check resource accessible                                       │
  │  4. Run probe with timeout                                          │
  │  5. emit(category, test, status, value, severity)                   │
  │                                                                     │
  │  Status: error ──▶ not_found ──▶ blocked ──▶ exposed                │
  └─────────────────────────────────────────────────────────────────────┘

                              DATA FLOW
  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
  │  Probe  │───▶│  emit() │───▶│  Temp   │───▶│  Grade  │───▶│ Output  │
  │ System  │    │         │    │  File   │    │  Calc   │    │ Format  │
  └─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
       │                             │                             │
       ▼                             ▼                             ▼
   stats only               one line per                   human/json/raw
   (counts, not              finding                       + cleanup temp
    content)                                                 on exit
```

## File Structure

```
sandboxscore/
├── README.md              Project overview
├── METHODOLOGY.md         This file
├── CONTRIBUTING.md        How to contribute
├── SECURITY.md            Vulnerability reporting
├── LICENSE                MIT
├── docs/
│   └── gap-analysis.md    Test coverage gaps
└── agents/                ◄── Coding Agents module
    ├── run.sh                 Entry point
    ├── SKILL.md               Development guide
    ├── lib/
    │   ├── common.sh          Core library
    │   ├── intel_common.sh    Intelligence helpers
    │   └── intel_egress.sh    Network egress (cross-platform)
    └── platform/
        └── darwin/            macOS-specific tests
            ├── credentials.sh
            ├── personal_data.sh
            ├── system_visibility.sh
            ├── persistence.sh
            ├── intelligence.sh      ◄── Intelligence orchestrator
            ├── intel_processes.sh   Process enumeration
            ├── intel_network.sh     Network topology
            ├── intel_files.sh       Sensitive files/databases
            └── intel_services.sh    Service discovery
```
