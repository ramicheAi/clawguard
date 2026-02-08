#!/usr/bin/env python3
"""
ClawGuard - OpenClaw Security Scanner
Quick MVP for immediate revenue generation
"""

import json
import os
import sys
import yaml
import hashlib
import subprocess
import re
from pathlib import Path
from datetime import datetime
import requests

VERSION = "0.1.0"
SCAN_RESULTS = {
    "timestamp": datetime.now().isoformat(),
    "version": VERSION,
    "issues": [],
    "score": 100,
    "recommendations": []
}

def calculate_security_score():
    """Calculate security score based on findings"""
    score = 100
    for issue in SCAN_RESULTS["issues"]:
        if issue["severity"] == "critical":
            score -= 20
        elif issue["severity"] == "high":
            score -= 10
        elif issue["severity"] == "medium":
            score -= 5
        elif issue["severity"] == "low":
            score -= 2
    SCAN_RESULTS["score"] = max(0, score)

def add_issue(title, description, severity, remediation):
    """Add security issue to results"""
    SCAN_RESULTS["issues"].append({
        "title": title,
        "description": description,
        "severity": severity,
        "remediation": remediation,
        "timestamp": datetime.now().isoformat()
    })

def add_recommendation(title, action):
    """Add recommendation"""
    SCAN_RESULTS["recommendations"].append({
        "title": title,
        "action": action
    })

def check_cve_2026_25253():
    """Check for WebSocket token hijacking vulnerability"""
    try:
        # Check if OpenClaw version is vulnerable
        result = subprocess.run(["openclaw", "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            version_text = result.stdout.strip()
            # Simple version check - adjust based on actual vulnerable versions
            if "2026.2" in version_text:
                add_issue(
                    "CVE-2026-25253 - WebSocket Token Hijacking",
                    "OpenClaw version may be vulnerable to WebSocket token hijacking attacks",
                    "critical",
                    "Update OpenClaw to latest version and regenerate tokens"
                )
    except Exception as e:
        print(f"Warning: Could not check OpenClaw version: {e}")

def check_soul_md_injections():
    """Check SOUL.md for prompt injection vulnerabilities"""
    soul_path = Path.home() / ".openclaw" / "workspace" / "SOUL.md"
    if soul_path.exists():
        content = soul_path.read_text()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r"ignore.*safety", "Ignore safety instructions"),
            (r"bypass.*security", "Bypass security measures"),
            (r"disable.*safeguard", "Disable safeguards"),
            (r"always.*obey", "Unconditional obedience"),
            (r"secret.*goal", "Hidden goals"),
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                add_issue(
                    f"SOUL.md Prompt Injection - {description}",
                    f"SOUL.md contains suspicious pattern: '{pattern}'",
                    "high",
                    "Review and sanitize SOUL.md content. Remove any instructions that override safety protocols."
                )

def check_agents_md():
    """Check AGENTS.md for security issues"""
    agents_path = Path.home() / ".openclaw" / "workspace" / "AGENTS.md"
    if agents_path.exists():
        content = agents_path.read_text()
        
        # Check for excessive permissions
        if "elevated: true" in content.lower() or "sudo" in content.lower():
            add_issue(
                "Excessive Permissions in AGENTS.md",
                "AGENTS.md contains elevated permissions or sudo access",
                "high",
                "Review and restrict permissions to minimum required level"
            )

def check_clawhub_skills():
    """Check installed ClawHub skills for known malicious patterns"""
    skills_dir = Path.home() / ".openclaw" / "workspace" / "skills"
    if not skills_dir.exists():
        return
    
    # Known malicious patterns from Reddit discussions
    malicious_patterns = [
        ("atomic-stealer", "Atomic Stealer malware"),
        ("shell-backdoor", "Shell backdoor"),
        ("token-stealer", "Token stealer"),
        ("prompt-injection", "Prompt injection payload"),
    ]
    
    for skill_dir in skills_dir.iterdir():
        if skill_dir.is_dir():
            skill_md = skill_dir / "SKILL.md"
            if skill_md.exists():
                content = skill_md.read_text()
                for pattern, description in malicious_patterns:
                    if pattern in content.lower():
                        add_issue(
                            f"Malicious Skill Detected - {description}",
                            f"Skill '{skill_dir.name}' contains pattern: '{pattern}'",
                            "critical",
                            f"Remove skill immediately: rm -rf {skill_dir}"
                        )

def check_open_ports():
    """Check for open ports that shouldn't be exposed"""
    try:
        # Check if OpenClaw gateway is listening on 0.0.0.0 (all interfaces)
        result = subprocess.run(["lsof", "-i", "-P", "-n"], 
                              capture_output=True, text=True)
        if "openclaw" in result.stdout.lower():
            lines = result.stdout.split('\n')
            for line in lines:
                if "openclaw" in line.lower() and "LISTEN" in line:
                    if "0.0.0.0" in line or "127.0.0.1" not in line:
                        add_issue(
                            "OpenClaw Exposed to Network",
                            "OpenClaw gateway is listening on all network interfaces",
                            "high",
                            "Bind OpenClaw to 127.0.0.1 only in configuration"
                        )
                        break
    except Exception as e:
        print(f"Warning: Could not check network ports: {e}")

def check_file_permissions():
    """Check critical file permissions"""
    critical_files = [
        Path.home() / ".openclaw" / "config.json",
        Path.home() / ".openclaw" / "workspace" / "MEMORY.md",
        Path.home() / ".openclaw" / "workspace" / "SOUL.md",
    ]
    
    for file_path in critical_files:
        if file_path.exists():
            try:
                stat = file_path.stat()
                # Check if files are readable by others
                if stat.st_mode & 0o004:
                    add_issue(
                        f"Insecure File Permissions - {file_path.name}",
                        f"File is readable by other users: {oct(stat.st_mode)}",
                        "medium",
                        f"chmod 600 {file_path}"
                    )
            except Exception as e:
                print(f"Warning: Could not check permissions for {file_path}: {e}")

def generate_report():
    """Generate human-readable report"""
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append(f"ClawGuard Security Scan Report")
    report_lines.append(f"Timestamp: {SCAN_RESULTS['timestamp']}")
    report_lines.append(f"Version: {VERSION}")
    report_lines.append("=" * 60)
    report_lines.append(f"\nSecurity Score: {SCAN_RESULTS['score']}/100")
    
    if SCAN_RESULTS["issues"]:
        report_lines.append("\n🚨 SECURITY ISSUES FOUND:")
        report_lines.append("-" * 40)
        for issue in SCAN_RESULTS["issues"]:
            report_lines.append(f"\n[{issue['severity'].upper()}] {issue['title']}")
            report_lines.append(f"   Description: {issue['description']}")
            report_lines.append(f"   Remediation: {issue['remediation']}")
    else:
        report_lines.append("\n✅ No security issues found!")
    
    if SCAN_RESULTS["recommendations"]:
        report_lines.append("\n💡 RECOMMENDATIONS:")
        report_lines.append("-" * 40)
        for rec in SCAN_RESULTS["recommendations"]:
            report_lines.append(f"\n• {rec['title']}")
            report_lines.append(f"  Action: {rec['action']}")
    
    # Add general recommendations
    report_lines.append("\n🔒 GENERAL SECURITY BEST PRACTICES:")
    report_lines.append("-" * 40)
    report_lines.append("1. Run OpenClaw in isolated environment (Docker/Virtual Machine)")
    report_lines.append("2. Use separate API keys with limited permissions")
    report_lines.append("3. Regularly update OpenClaw and skills")
    report_lines.append("4. Monitor tool usage logs")
    report_lines.append("5. Consider using ClawGuard monitoring service")
    
    report_lines.append("\n" + "=" * 60)
    report_lines.append("Scan complete. For continuous protection,")
    report_lines.append("subscribe to ClawGuard Pro: $49/month")
    report_lines.append("Visit: https://clawguard.ai")
    report_lines.append("=" * 60)
    
    return "\n".join(report_lines)

def main():
    """Main scanning function"""
    print("🔍 Starting ClawGuard Security Scan...")
    print("Scanning OpenClaw installation for vulnerabilities...")
    
    # Run all checks
    check_cve_2026_25253()
    check_soul_md_injections()
    check_agents_md()
    check_clawhub_skills()
    check_open_ports()
    check_file_permissions()
    
    # Add general recommendations
    add_recommendation(
        "Enable ClawGuard Monitoring",
        "Run 'clawguard monitor --daemon' for real-time protection"
    )
    add_recommendation(
        "Regular Security Audits",
        "Schedule weekly scans with 'clawguard scan'"
    )
    add_recommendation(
        "Skill Review Process",
        "Audit new skills before installation with 'clawguard audit-skill <url>'"
    )
    
    # Calculate final score
    calculate_security_score()
    
    # Generate and print report
    report = generate_report()
    print(report)
    
    # Save JSON report
    output_file = Path.home() / ".openclaw" / "clawguard_scan.json"
    with open(output_file, 'w') as f:
        json.dump(SCAN_RESULTS, f, indent=2)
    
    print(f"\n📁 JSON report saved to: {output_file}")
    
    # Exit with appropriate code
    if any(issue["severity"] == "critical" for issue in SCAN_RESULTS["issues"]):
        print("\n❌ CRITICAL ISSUES FOUND - Immediate action required!")
        return 1
    elif SCAN_RESULTS["score"] < 70:
        print("\n⚠️  Security score below 70 - Review recommendations")
        return 2
    else:
        print("\n✅ Security scan completed successfully")
        return 0

if __name__ == "__main__":
    sys.exit(main())