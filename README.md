# ClawGuard - OpenClaw Security Scanner

Automated security scanner for OpenClaw instances. Identifies vulnerabilities, detects malicious skills, validates configurations, and provides real-time monitoring.

## Problem
OpenClaw users are scared to give AI agents shell access due to:
- 341+ malicious skills on ClawHub
- SOUL.md prompt injection attacks
- CVE-2026-25253 WebSocket token hijacking
- No runtime defense tools available

## Solution
ClawGuard provides:
1. **Vulnerability Scanning** - Detect known CVEs and security flaws
2. **Skill Auditing** - Check ClawHub skills for malware
3. **Config Validation** - Validate OpenClaw configuration files
4. **Real-time Monitoring** - Watch for suspicious tool usage
5. **Whitelist Enforcement** - Safe execution policies

## Features (MVP)
- ✅ Scan for CVE-2026-25253 (WebSocket token hijacking)
- ✅ Detect malicious skills in ClawHub registry
- ✅ Validate SOUL.md/AGENTS.md for prompt injections
- ✅ Check file permissions and access controls
- ✅ Generate security score (0-100)
- ✅ Provide actionable remediation steps

## Installation
```bash
# Quick install
curl -fsSL https://get.clawguard.ai/install | bash

# Or manual
git clone https://github.com/ramiche/clawguard.git
cd clawguard
pip install -r requirements.txt
```

## Usage
```bash
# Basic scan
clawguard scan

# Scan specific OpenClaw instance
clawguard scan --path ~/.openclaw

# Continuous monitoring
clawguard monitor --daemon

# Skill audit
clawguard audit-skill https://clawhub.com/skill/suspicious-skill

# Generate security report
clawguard report --format html
```

## Pricing
**Beta Launch Pricing:**
- $49/month per instance
- $499 lifetime license (limited time)

## Roadmap
- Real-time threat intelligence updates
- Automated patching
- Team dashboard
- Compliance reporting (SOC2, GDPR)
- Slack/Discord alerts

## Why ClawGuard?
- Built by security experts who understand AI agent risks
- Focused exclusively on OpenClaw ecosystem
- Zero-configuration scanning
- Community-driven threat intelligence

## Getting Help
- Docs: https://docs.clawguard.ai
- Discord: https://discord.gg/clawguard
- Email: support@clawguard.ai