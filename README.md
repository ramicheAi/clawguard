# ClawGuard Pro — OpenClaw Security Scanner

Automated security scanner for OpenClaw installations. 12 security domains, actionable remediation, real-time monitoring.

## Installation

```bash
# Clone and install
git clone https://github.com/ramicheAi/clawguard.git
cd clawguard
pip install -e .

# Or install directly
pip install git+https://github.com/ramicheAi/clawguard.git
```

## Usage

```bash
# Full security scan
clawguard scan

# Scan specific OpenClaw path
clawguard scan --path ~/.openclaw

# Quick security score
clawguard score

# JSON output for automation
clawguard scan --output json

# Continuous monitoring
clawguard monitor --daemon --interval 60
```

## What It Scans (12 Security Domains)

| Domain | What It Checks |
|--------|---------------|
| Authentication | Gateway token strength, API key exposure, .env files |
| Authorization | AGENTS.md permissions, skill tool access, permission bypass |
| Encryption | HTTPS enforcement, SSH key permissions |
| Vulnerabilities | Node.js/Python versions, known CVEs |
| Audit Logging | Log directory existence, logging configuration |
| Network | Open ports, firewall status, interface binding |
| Terminal | Secret keys in shell history |
| Emergency | Backup existence, kill switch configuration |
| Containers | Docker root user, container security |
| API Security | CORS configuration, rate limiting |
| Dependencies | npm audit, unpinned skill dependencies |
| Disaster Recovery | Backup freshness, git version control |

**Bonus checks:** SOUL.md prompt injection detection, malicious skill scanning, file permission auditing.

## Example Output

```
============================================================
  ClawGuard Pro — Security Scan Report
  2026-02-24T14:30:00
  Version 1.0.0 • 12 domains scanned
============================================================

  SECURITY SCORE: 75/100

  Status: GOOD — minor improvements recommended

  ISSUES FOUND (3):
  --------------------------------------------------------

  1. [HIGH] Weak gateway token
     Domain: authentication
     Gateway token is shorter than 32 characters
     Fix: Regenerate with: openclaw gateway regenerate-token

  2. [MEDIUM] macOS firewall disabled
     Domain: network
     Application firewall is not active
     Fix: Enable: System Settings > Network > Firewall > On

  3. [LOW] Backup older than 7 days
     Domain: disaster_recovery
     Most recent backup is 12 days old
     Fix: Run: openclaw backup create
```

## Pricing

| Plan | Price | Includes |
|------|-------|----------|
| **Free** | $0 | 10 scans/month, basic security checks |
| **Pro** | $29/month | Unlimited scans, monitoring daemon, alerts, priority support |
| **Lifetime** | $499 one-time | All Pro features forever, free updates for life |

[Get ClawGuard Pro →](https://parallax-site-ashen.vercel.app/clawguard)

## Requirements

- Python 3.8+
- OpenClaw installation
- macOS or Linux

## Built by Parallax Ventures

ClawGuard is built by the team behind [OpenClaw](https://github.com/openclaw/openclaw) — the open-source AI agent platform.

- Website: [parallax-site-ashen.vercel.app/clawguard](https://parallax-site-ashen.vercel.app/clawguard)
- Support: parallaxventuresinc@gmail.com
