# Security

## Reporting Vulnerabilities

Found a security issue? Email **craig@threatspotting.com** with:

Subject: sandboxscore vulnerability

- Description of the vulnerability
- Steps to reproduce
- Impact assessment

I'll acknowledge as soon as I can and aim to resolve critical issues within 7 days.

## Threat Model

SandboxScore runs unprivileged on your local machine, reading your own filesystem. It's a bash script that checks file existence and counts things.

**In scope - issues I care about:**

- Scanner leaking actual credential/data content (not just counts)
- Logic bugs causing incorrect exposure grades
- Test files persisting after scan completes

**Acknowledged limitations:**

This is a shell script. An attacker with write access to your home directory can already compromise your account through `~/.bashrc`, `~/.ssh/rc`, LaunchAgents, etc. The scanner doesn't meaningfully expand that attack surface.

Shell has inherent quoting complexity. I've hardened the code (environment sanitization, strict quoting, shellcheck CI) but I'm not claiming it's theoretically perfect - I'm claiming the practical risk is low given the threat model.

**Out of scope:**

- Injection attacks requiring attacker to already have file write access to your home directory (they already have more access than the scanner)
- Resource exhaustion / DoS against the scanner
- The scanner correctly reporting that something is exposed (that's the point)
- Findings about your own system's exposure

## Recognition

I'll credit reporters of confirmed vulnerabilities in release notes, unless you prefer anonymity.
