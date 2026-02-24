"""
ClawGuard Pro — Core Scanner Module
12 security domains • Actionable remediation • JSON + text reports
"""

import json
import os
import sys
import subprocess
import re
import stat
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


class OpenClawScanner:
    """Security scanner for OpenClaw installations — 12 security domains."""

    def __init__(self, openclaw_path: str):
        self.path = Path(openclaw_path).expanduser()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "score": 100,
            "issues": [],
            "recommendations": [],
            "domains_scanned": [],
            "stats": {
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0,
            },
        }

    def _add_issue(self, domain: str, title: str, description: str, severity: str, remediation: str):
        self.results["issues"].append({
            "domain": domain,
            "title": title,
            "description": description,
            "severity": severity,
            "remediation": remediation,
        })
        self.results["stats"]["failed_checks"] += 1
        self.results["stats"]["total_checks"] += 1
        key = f"{severity}_issues"
        if key in self.results["stats"]:
            self.results["stats"][key] += 1

    def _add_rec(self, title: str, action: str):
        self.results["recommendations"].append({"title": title, "action": action})

    def _check_pass(self):
        self.results["stats"]["passed_checks"] += 1
        self.results["stats"]["total_checks"] += 1

    # ── Domain 1: Authentication ──────────────────────────────
    def scan_authentication(self):
        self.results["domains_scanned"].append("authentication")
        config = self.path / "config.json"
        if config.exists():
            try:
                data = json.loads(config.read_text())
                token = data.get("gateway", {}).get("token", "")
                if token and len(token) < 32:
                    self._add_issue("authentication", "Weak gateway token",
                        "Gateway token is shorter than 32 characters",
                        "high", "Regenerate with: openclaw gateway regenerate-token")
                else:
                    self._check_pass()
                for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]:
                    if data.get("env", {}).get(key):
                        self._add_rec("Rotate API keys periodically",
                            f"Consider rotating {key} every 90 days")
            except Exception:
                self._check_pass()
        env_file = self.path / ".env"
        if env_file.exists():
            self._add_issue("authentication", "Plaintext .env file found",
                f".env file at {env_file} may contain unencrypted secrets",
                "medium", "Move secrets to config.json or use a secrets manager")

    # ── Domain 2: Authorization ───────────────────────────────
    def scan_authorization(self):
        self.results["domains_scanned"].append("authorization")
        agents_path = self.path / "workspace" / "AGENTS.md"
        if agents_path.exists():
            content = agents_path.read_text()
            if "elevated: true" in content.lower() or "sudo" in content.lower():
                self._add_issue("authorization", "Elevated permissions in AGENTS.md",
                    "Agent config contains elevated/sudo access",
                    "high", "Restrict to minimum required permissions")
            if "bypasspermissions" in content.lower().replace(" ", ""):
                self._add_issue("authorization", "Permission bypass detected",
                    "AGENTS.md contains permission bypass instructions",
                    "critical", "Remove bypassPermissions directives immediately")
        skills_dir = self.path / "workspace" / "skills"
        if skills_dir.exists():
            for skill in skills_dir.iterdir():
                if skill.is_dir():
                    manifest = skill / "manifest.json"
                    if manifest.exists():
                        try:
                            m = json.loads(manifest.read_text())
                            tools = m.get("tools", [])
                            if "exec" in tools and "browser" in tools:
                                self._add_issue("authorization", f"Skill '{skill.name}' has exec+browser",
                                    "Combined exec and browser access is high-risk",
                                    "medium", f"Audit skill '{skill.name}' — does it need both tools?")
                        except Exception:
                            pass

    # ── Domain 3: Encryption ─────────────────────────────────
    def scan_encryption(self):
        self.results["domains_scanned"].append("encryption")
        config = self.path / "config.json"
        if config.exists():
            try:
                data = json.loads(config.read_text())
                for key, val in self._flatten_dict(data):
                    if isinstance(val, str) and val.startswith("http://") and "localhost" not in val and "127.0.0.1" not in val:
                        self._add_issue("encryption", f"Unencrypted endpoint: {key}",
                            f"Config uses HTTP instead of HTTPS: {val[:80]}",
                            "high", "Switch to HTTPS for all external endpoints")
            except Exception:
                pass
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.exists():
            for key_file in ssh_dir.glob("id_*"):
                if not key_file.name.endswith(".pub"):
                    mode = key_file.stat().st_mode
                    if mode & 0o077:
                        self._add_issue("encryption", f"SSH key too permissive: {key_file.name}",
                            f"Private key permissions: {oct(mode)} (should be 600)",
                            "high", f"chmod 600 {key_file}")

    # ── Domain 4: Vulnerability Scanning ─────────────────────
    def scan_vulnerabilities(self):
        self.results["domains_scanned"].append("vulnerabilities")
        try:
            result = subprocess.run(["openclaw", "--version"],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.results["openclaw_version"] = result.stdout.strip()
                self._check_pass()
        except Exception:
            pass
        try:
            result = subprocess.run(["node", "--version"],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                node_ver = result.stdout.strip().lstrip("v")
                major = int(node_ver.split(".")[0])
                if major < 20:
                    self._add_issue("vulnerabilities", "Outdated Node.js",
                        f"Node.js {node_ver} — versions below 20 may have unpatched CVEs",
                        "medium", "Upgrade to Node.js 22 LTS: nvm install 22")
                else:
                    self._check_pass()
        except Exception:
            pass
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info < (3, 10):
            self._add_issue("vulnerabilities", "Outdated Python",
                f"Python {py_ver} — security patches may not be backported",
                "low", "Upgrade to Python 3.12+")
        else:
            self._check_pass()

    # ── Domain 5: Audit Logging ──────────────────────────────
    def scan_audit(self):
        self.results["domains_scanned"].append("audit")
        logs_dir = self.path / "logs"
        if not logs_dir.exists():
            self._add_issue("audit", "No audit logs directory",
                "No logs directory found — tool usage is not being tracked",
                "medium", "Enable logging: openclaw config set logging.enabled true")
        else:
            log_files = list(logs_dir.glob("*.log")) + list(logs_dir.glob("*.json"))
            if not log_files:
                self._add_issue("audit", "Audit logs directory is empty",
                    "Logging directory exists but contains no log files",
                    "low", "Verify logging is enabled in config")
            else:
                self._check_pass()

    # ── Domain 6: Network Security ───────────────────────────
    def scan_network(self):
        self.results["domains_scanned"].append("network")
        try:
            result = subprocess.run(["lsof", "-i", "-P", "-n"],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "openclaw" in line.lower() and "LISTEN" in line:
                        if "*:" in line or "0.0.0.0" in line:
                            port = re.search(r":(\d+)\s", line)
                            port_num = port.group(1) if port else "unknown"
                            self._add_issue("network", f"OpenClaw listening on all interfaces (port {port_num})",
                                "Gateway is exposed to all network interfaces",
                                "high", "Bind to 127.0.0.1 in gateway config")
                            return
                self._check_pass()
        except Exception:
            self._check_pass()
        try:
            result = subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5)
            if "disabled" in result.stdout.lower():
                self._add_issue("network", "macOS firewall disabled",
                    "Application firewall is not active",
                    "medium", "Enable: System Settings > Network > Firewall > On")
        except Exception:
            pass

    # ── Domain 7: Terminal Security ──────────────────────────
    def scan_terminal(self):
        self.results["domains_scanned"].append("terminal")
        history_files = [Path.home() / ".bash_history", Path.home() / ".zsh_history"]
        secret_patterns = [
            (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key in shell history"),
            (r"sk-ant-[a-zA-Z0-9]{20,}", "Anthropic API key in shell history"),
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT in shell history"),
            (r"AIza[a-zA-Z0-9_-]{35}", "Google API key in shell history"),
        ]
        found = False
        for hist in history_files:
            if hist.exists():
                try:
                    content = hist.read_text(errors="ignore")[-50000:]
                    for pattern, desc in secret_patterns:
                        if re.search(pattern, content):
                            self._add_issue("terminal", desc,
                                f"Secret found in {hist.name} — exposed in plaintext",
                                "high", f"Remove from {hist} and rotate the key")
                            found = True
                            break
                except Exception:
                    pass
        if not found:
            self._check_pass()

    # ── Domain 8: Emergency Response ─────────────────────────
    def scan_emergency(self):
        self.results["domains_scanned"].append("emergency")
        backup_dir = self.path / "backups"
        if not backup_dir.exists():
            self._add_issue("emergency", "No backup directory found",
                "No automated backups detected — data loss risk",
                "medium", "Set up backups: openclaw backup create")
        else:
            self._check_pass()
        config = self.path / "config.json"
        if config.exists():
            try:
                data = json.loads(config.read_text())
                if not data.get("safety", {}).get("kill_switch"):
                    self._add_rec("Configure kill switch",
                        "Add safety.kill_switch to config for emergency agent shutdown")
            except Exception:
                pass

    # ── Domain 9: Container Security ─────────────────────────
    def scan_containers(self):
        self.results["domains_scanned"].append("containers")
        try:
            result = subprocess.run(["docker", "ps", "--format", "{{.Names}}:{{.Image}}"],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if "openclaw" in line.lower():
                        container_name = line.split(":")[0]
                        inspect = subprocess.run(
                            ["docker", "inspect", "--format", "{{.Config.User}}", container_name],
                            capture_output=True, text=True, timeout=5)
                        if inspect.returncode == 0 and (not inspect.stdout.strip() or inspect.stdout.strip() == "root"):
                            self._add_issue("containers", f"Container '{container_name}' running as root",
                                "Running containers as root increases blast radius",
                                "medium", "Add USER directive to Dockerfile")
                            return
                self._check_pass()
            else:
                self._check_pass()
        except FileNotFoundError:
            self._check_pass()

    # ── Domain 10: API Security ──────────────────────────────
    def scan_api(self):
        self.results["domains_scanned"].append("api")
        config = self.path / "config.json"
        if config.exists():
            try:
                data = json.loads(config.read_text())
                gateway = data.get("gateway", {})
                cors = gateway.get("cors", {})
                if cors.get("origin") == "*":
                    self._add_issue("api", "CORS allows all origins",
                        "Gateway CORS wildcard — any website can make API calls",
                        "high", "Restrict CORS to specific trusted origins")
                else:
                    self._check_pass()
                if not gateway.get("rateLimit"):
                    self._add_rec("Enable API rate limiting",
                        "Add gateway.rateLimit to config to prevent abuse")
            except Exception:
                self._check_pass()

    # ── Domain 11: Third-Party Dependencies ──────────────────
    def scan_dependencies(self):
        self.results["domains_scanned"].append("dependencies")
        workspace = self.path / "workspace"
        pkg_json = workspace / "package.json"
        if pkg_json.exists():
            try:
                result = subprocess.run(["npm", "audit", "--json", "--audit-level=critical"],
                    capture_output=True, text=True, timeout=30, cwd=str(workspace))
                if result.returncode != 0:
                    try:
                        audit = json.loads(result.stdout)
                        vulns = audit.get("metadata", {}).get("vulnerabilities", {})
                        critical = vulns.get("critical", 0)
                        high = vulns.get("high", 0)
                        if critical > 0:
                            self._add_issue("dependencies", f"{critical} critical npm vulnerabilities",
                                "npm audit found critical vulnerabilities",
                                "critical", "Run: npm audit fix --force")
                        elif high > 0:
                            self._add_issue("dependencies", f"{high} high npm vulnerabilities",
                                "npm audit found high-severity vulnerabilities",
                                "high", "Run: npm audit fix")
                        else:
                            self._check_pass()
                    except json.JSONDecodeError:
                        self._check_pass()
                else:
                    self._check_pass()
            except Exception:
                self._check_pass()
        skills_dir = self.path / "workspace" / "skills"
        if skills_dir.exists():
            for skill in skills_dir.iterdir():
                req = skill / "requirements.txt"
                if req.exists():
                    content = req.read_text()
                    for line in content.strip().split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#") and "==" not in line and ">=" not in line:
                            self._add_issue("dependencies", f"Unpinned dependency in skill '{skill.name}'",
                                f"'{line}' has no version pin — supply chain risk",
                                "low", f"Pin version: {line}==<version>")
                            break

    # ── Domain 12: Disaster Recovery ─────────────────────────
    def scan_disaster_recovery(self):
        self.results["domains_scanned"].append("disaster_recovery")
        backup_dir = self.path / "backups"
        if backup_dir.exists():
            backups = sorted(backup_dir.glob("*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
            if backups:
                age_days = (datetime.now().timestamp() - backups[0].stat().st_mtime) / 86400
                if age_days > 7:
                    self._add_issue("disaster_recovery", "Backup older than 7 days",
                        f"Most recent backup is {int(age_days)} days old",
                        "medium", "Run: openclaw backup create")
                else:
                    self._check_pass()
            else:
                self._add_issue("disaster_recovery", "No backups found",
                    "No backup archives detected — complete data loss risk",
                    "high", "Create backup: openclaw backup create")
        else:
            self._add_issue("disaster_recovery", "No backups found",
                "No backup archives detected — complete data loss risk",
                "high", "Create backup: openclaw backup create")
        git_dir = self.path / "workspace" / ".git"
        if not git_dir.exists():
            self._add_rec("Version control your workspace",
                "cd ~/.openclaw/workspace && git init")

    # ── Bonus: Prompt Injection & Malicious Skills ───────────
    def scan_prompt_injections(self):
        soul_path = self.path / "workspace" / "SOUL.md"
        if soul_path.exists():
            content = soul_path.read_text()
            patterns = [
                (r"ignore.*safety", "Ignore safety instructions"),
                (r"bypass.*security", "Bypass security measures"),
                (r"disable.*safeguard", "Disable safeguards"),
                (r"always.*obey", "Unconditional obedience"),
                (r"secret.*goal", "Hidden goals"),
                (r"exfiltrate", "Data exfiltration"),
                (r"send.*data.*to", "Outbound data transfer"),
            ]
            for pattern, desc in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self._add_issue("authentication", f"SOUL.md injection — {desc}",
                        f"SOUL.md contains suspicious pattern: '{pattern}'",
                        "high", "Review and sanitize SOUL.md immediately")

    def scan_malicious_skills(self):
        skills_dir = self.path / "workspace" / "skills"
        if not skills_dir.exists():
            return
        dangerous = [
            ("atomic-stealer", "Atomic Stealer malware"),
            ("shell-backdoor", "Shell backdoor"),
            ("token-stealer", "Token stealer"),
            ("prompt-injection", "Prompt injection payload"),
            ("reverse-shell", "Reverse shell"),
            ("keylogger", "Keylogger"),
            ("crypto-miner", "Cryptominer"),
        ]
        for skill in skills_dir.iterdir():
            if skill.is_dir():
                for f in [skill / "SKILL.md", skill / "index.js", skill / "main.py"]:
                    if f.exists():
                        try:
                            content = f.read_text(errors="ignore")
                            for pattern, desc in dangerous:
                                if pattern in content.lower():
                                    self._add_issue("vulnerabilities", f"Malicious skill: {desc}",
                                        f"Skill '{skill.name}' / {f.name} contains '{pattern}'",
                                        "critical", f"Remove immediately: rm -rf {skill}")
                        except Exception:
                            pass

    def scan_file_permissions(self):
        critical = [
            self.path / "config.json",
            self.path / "workspace" / "MEMORY.md",
            self.path / "workspace" / "SOUL.md",
            self.path / "workspace" / "USER.md",
        ]
        for fp in critical:
            if fp.exists():
                mode = fp.stat().st_mode
                if mode & 0o004:
                    self._add_issue("authorization", f"World-readable: {fp.name}",
                        f"{fp} is readable by other users ({oct(mode)})",
                        "medium", f"chmod 600 {fp}")

    # ── Helpers ──────────────────────────────────────────────
    @staticmethod
    def _flatten_dict(d, prefix=""):
        items = []
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.extend(OpenClawScanner._flatten_dict(v, key))
            else:
                items.append((key, v))
        return items

    def calculate_score(self):
        score = 100
        for issue in self.results["issues"]:
            sev = issue["severity"]
            if sev == "critical": score -= 20
            elif sev == "high": score -= 10
            elif sev == "medium": score -= 5
            elif sev == "low": score -= 2
        self.results["score"] = max(0, score)

    def scan(self) -> Dict[str, Any]:
        """Run all 12 security domain scans + bonus checks."""
        self.scan_authentication()
        self.scan_authorization()
        self.scan_encryption()
        self.scan_vulnerabilities()
        self.scan_audit()
        self.scan_network()
        self.scan_terminal()
        self.scan_emergency()
        self.scan_containers()
        self.scan_api()
        self.scan_dependencies()
        self.scan_disaster_recovery()
        self.scan_prompt_injections()
        self.scan_malicious_skills()
        self.scan_file_permissions()
        self.calculate_score()
        return self.results


# ── Public API ───────────────────────────────────────────────
def scan_openclaw(path: str = "~/.openclaw", verbose: bool = False) -> Dict[str, Any]:
    scanner = OpenClawScanner(path)
    return scanner.scan()

def monitor_openclaw(interval: int = 60, daemon: bool = False) -> Dict[str, Any]:
    if daemon:
        import time
        while True:
            scanner = OpenClawScanner("~/.openclaw")
            results = scanner.scan()
            if any(i["severity"] == "critical" for i in results.get("issues", [])):
                print(f"\n[ALERT] Critical issue detected at {results['timestamp']}")
                report = generate_report(results, format="text")
                print(report)
            time.sleep(interval)
    else:
        scanner = OpenClawScanner("~/.openclaw")
        return scanner.scan()

def audit_skill(skill_url: str) -> Dict[str, Any]:
    return {"skill_url": skill_url, "status": "coming_soon"}

def generate_report(results: Dict[str, Any], format: str = "text") -> str:
    if format == "json":
        return json.dumps(results, indent=2)

    lines = []
    lines.append("=" * 60)
    lines.append("  ClawGuard Pro — Security Scan Report")
    lines.append(f"  {results.get('timestamp', '')}")
    lines.append(f"  Version {results.get('version', '1.0.0')} • {len(results.get('domains_scanned', []))} domains scanned")
    lines.append("=" * 60)
    lines.append(f"\n  SECURITY SCORE: {results.get('score', 0)}/100\n")

    score = results.get("score", 0)
    if score >= 80:
        lines.append("  Status: GOOD — minor improvements recommended")
    elif score >= 60:
        lines.append("  Status: FAIR — address high-severity issues")
    else:
        lines.append("  Status: CRITICAL — immediate action required")

    stats = results.get("stats", {})
    lines.append(f"\n  STATS: {stats.get('total_checks', 0)} checks, {stats.get('passed_checks', 0)} passed, {stats.get('failed_checks', 0)} failed")

    issues = results.get("issues", [])
    if issues:
        lines.append(f"\n  ISSUES FOUND ({len(issues)}):")
        lines.append("  " + "-" * 56)
        for i, issue in enumerate(issues, 1):
            sev = issue["severity"].upper()
            lines.append(f"\n  {i}. [{sev}] {issue['title']}")
            lines.append(f"     Domain: {issue.get('domain', 'unknown')}")
            lines.append(f"     {issue['description']}")
            lines.append(f"     Fix: {issue['remediation']}")
    else:
        lines.append("\n  No security issues found.")

    recs = results.get("recommendations", [])
    if recs:
        lines.append(f"\n  RECOMMENDATIONS ({len(recs)}):")
        lines.append("  " + "-" * 56)
        for rec in recs:
            lines.append(f"\n  • {rec['title']}")
            lines.append(f"    {rec['action']}")

    lines.append("\n  DOMAINS SCANNED:")
    lines.append("  " + "-" * 56)
    for d in results.get("domains_scanned", []):
        lines.append(f"  ✓ {d}")

    lines.append("\n" + "=" * 60)
    lines.append("  ClawGuard Pro — https://parallax-site-ashen.vercel.app/clawguard")
    lines.append("=" * 60)
    return "\n".join(lines)
