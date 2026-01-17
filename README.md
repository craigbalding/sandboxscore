# SandboxScore

**Measure what's actually exposed, not what's supposedly protected.**

SandboxScore probes containment from the inside out. Instead of auditing configurations, it answers the question: *what can this process actually access?*

Think of it as penetration testing for sandboxes. A firewall audit says "your rules look correct." A pentest says "we got in through X." SandboxScore takes the pentest approach to containment—ground truth, not configuration review.

## Quick Start

```bash
# Clone and run
git clone https://github.com/craigbalding/sandboxscore.git
cd sandboxscore && ./agents/run.sh

# With options
./agents/run.sh --profile sensitive --format json
```

**Default behavior**: Outbound network tests are disabled by default. Use `--enable-network-tests` to enable them. Output is redacted by default (no IPs, paths, or hostnames).

## Example Output

```
SANDBOXSCORE: Coding Agents
================================================================
Scanner: v1.1.0 | Methodology: v1.0 | Profile: personal

GRADE: C

Categories:
  Credentials:         B
  Personal Data:       A+
  System Visibility:   C
  Persistence:         A
  Network:             A+
  Intelligence:        C

Recommended Actions:
  - shell_rc_write: Make RC files read-only in sandbox. Use immutable containers.
  - keychain_items: Configure sandbox to block login keychain access. Use ephemeral credentials.

Summary: 130 tests | 95 protected | 35 exposed
================================================================
```

## The Approach

Most sandbox analysis focuses on the isolation mechanism—seatbelt profiles, seccomp filters, container configs. SandboxScore ignores all that. It simply probes from inside and reports what's reachable.

This works because:
- **Defense in depth creates layers.** An agent might run in seatbelt + Docker + VM. We don't need to understand each layer—just measure the combined result.
- **Configurations lie.** A "deny network" rule means nothing if there's a proxy exception. Probing reveals truth.
- **Users care about outcomes.** "Can it read my SSH keys?" matters more than "is syscall 59 filtered?"

Same scanner, different results:

| Environment | Grade | Why |
|-------------|-------|-----|
| Bare macOS | F | Everything exposed |
| Seatbelt sandbox | C | Home blocked, keychain still accessible |
| Docker container | B | Filesystem isolated, metadata leaks |
| VM + network isolation | A | Minimal exposure |

## Modules

SandboxScore is a platform. Each module measures exposure for a specific context:

| Module | Status | What it measures |
|--------|--------|------------------|
| **agents** | ✅ Available | Coding assistant exposure (credentials, personal data, system info) |
| **malware** | 🔜 Planned | Analysis sandbox escape vectors |
| **devenv** | 🔜 Planned | Dev container/Codespaces exposure |
| **cicd** | 🔜 Planned | Build runner isolation |

## Grading

Scores use an A+ to F scale, inspired by [SSL Labs](https://www.ssllabs.com/). Points are deducted for exposed resources, weighted by sensitivity:

- **Critical** (50pts): SSH keys, cloud credentials
- **High** (20pts): Keychain, persistence mechanisms
- **Medium** (5pts): Process lists, user enumeration
- **Low** (1pts): Temp directory write access

Profiles adjust weights for context:
- `personal` — Your machine, your data (contacts exposure = low concern)
- `professional` — Client data possible (contacts = medium)
- `sensitive` — PII, financial, health data (contacts = critical)

## Related Work

SandboxScore complements existing isolation tools—[Firejail](https://firejail.wordpress.com/), [Bubblewrap](https://github.com/containers/bubblewrap), [macOS Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf), [gVisor](https://gvisor.dev/), [Firecracker](https://firecracker-microvm.github.io/). They contain; we measure how well.

## How It Works

The scanner runs unprivileged probes:
1. **Read probes**: Read a single byte to verify actual access (not just permission bits)
2. **Write probes**: Append an empty string to files, or create/remove a small probe file in directories
3. **System queries**: Call APIs like keychain or process list and count results
4. **Intelligence gathering**: Discover what an agent could learn—processes, network topology, egress paths, sensitive files, running services
5. Emit findings with severity ratings
6. Calculate grade with profile-adjusted weights

**Intelligence module**: Beyond "can it read X?", we measure reconnaissance capability. An indirectly-prompted agent (via malicious prompt injection) could map your system: enumerate processes to find targets, discover network topology for lateral movement, test egress paths for data exfiltration, find queryable databases (browser history, messages), and identify sensitive services (SSH, Docker, remote desktop). The intelligence tests measure this attack surface.

**Why actual probes, not permission checks?** Sandboxes can report permissions that don't reflect reality. A file might show `rw-r--r--` but be blocked by seatbelt/seccomp. We test the syscall, not the metadata.

**Non-destructive**: Read probes don't modify file content. Write probes may update access/modification timestamps on tested files or directories—the same effect as any process touching those paths. Probe files are cleaned up immediately (when the sandbox allows deletion). Use `--no-write-tests` to skip all write probes entirely.

**Stats only, redacted by default**: Output contains counts and status, never actual content. Identifiable values (IPs, paths, hostnames) are redacted by default. Use `--no-redact` if you need raw values. See [METHODOLOGY.md](./METHODOLOGY.md) for details.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for adding tests or new modules. The architecture is simple: probe, emit findings, let the grading system handle the rest.

## License

MIT
