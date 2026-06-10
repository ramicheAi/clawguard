#!/usr/bin/env python3
"""
ClawGuard CLI - Command line interface
"""

import click
import sys
from pathlib import Path
from .scanner import scan_openclaw, monitor_openclaw, generate_report

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """ClawGuard - OpenClaw Security Scanner"""
    pass

@cli.command()
@click.option('--path', default='~/.openclaw', help='OpenClaw installation path')
@click.option('--output', type=click.Choice(['json', 'html', 'text']), default='text', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(path, output, verbose):
    """Scan OpenClaw installation for vulnerabilities"""
    path = Path(path).expanduser()
    if not path.exists():
        click.echo(f"Error: OpenClaw path not found: {path}", err=True)
        sys.exit(1)
    
    click.echo(f"🔍 Scanning OpenClaw installation at: {path}")
    results = scan_openclaw(str(path), verbose)
    
    if output == 'json':
        import json
        click.echo(json.dumps(results, indent=2))
    elif output == 'html':
        html_report = generate_report(results, format='html')
        click.echo(html_report)
    else:
        text_report = generate_report(results, format='text')
        click.echo(text_report)
    
    # Exit with appropriate code
    if any(issue.get('severity') == 'critical' for issue in results.get('issues', [])):
        sys.exit(1)
    elif results.get('score', 100) < 70:
        sys.exit(2)
    else:
        sys.exit(0)

@cli.command()
@click.option('--daemon', is_flag=True, help='Run as daemon')
@click.option('--interval', default=60, help='Check interval in seconds')
def monitor(daemon, interval):
    """Monitor OpenClaw for suspicious activity"""
    if daemon:
        click.echo(f"👁️  Starting ClawGuard monitor daemon (interval: {interval}s)")
        click.echo("Press Ctrl+C to stop")
        monitor_openclaw(interval, daemon=True)
    else:
        click.echo("🔍 Running one-time security check...")
        results = monitor_openclaw(interval, daemon=False)
        text_report = generate_report(results, format='text')
        click.echo(text_report)

@cli.command()
@click.argument('skill_url')
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
def audit_skill(skill_url, output):
    """Audit a ClawHub skill (URL or local path) for malicious patterns"""
    from . import scanner
    click.echo(f"🔍 Auditing skill: {skill_url}")
    result = scanner.audit_skill(skill_url)

    if output == 'json':
        import json
        click.echo(json.dumps(result, indent=2))
        sys.exit(0 if result.get('verdict') in ('CLEAN', 'REVIEW') else 2)

    if result.get('status') != 'ok':
        click.echo(f"Error: {result.get('error', 'unknown')}", err=True)
        sys.exit(1)

    verdict = result['verdict']
    color = {'CLEAN': 'green', 'REVIEW': 'yellow', 'SUSPICIOUS': 'red', 'DANGEROUS': 'red'}.get(verdict, 'white')
    click.echo(f"Checked against {result['patterns_checked']} patterns")
    click.echo(f"Verdict: {click.style(verdict, fg=color, bold=True)}")
    findings = result.get('findings', [])
    if findings:
        for f in findings:
            click.echo(f"  ✗ [{f['severity'].upper()}] {f['category']}: {f['description']}  ({f['match']})")
    else:
        click.echo("  ✓ No malicious patterns detected.")
    sys.exit(0 if verdict in ('CLEAN', 'REVIEW') else 2)

@cli.command()
@click.option('--path', default='~/.openclaw', help='OpenClaw installation path')
def score(path):
    """Get security score for OpenClaw installation"""
    path = Path(path).expanduser()
    if not path.exists():
        click.echo(f"Error: OpenClaw path not found: {path}", err=True)
        sys.exit(1)
    
    results = scan_openclaw(str(path), verbose=False)
    score = results.get('score', 0)
    
    if score >= 90:
        color = 'green'
        emoji = '✅'
        status = 'Excellent'
    elif score >= 70:
        color = 'yellow'
        emoji = '⚠️'
        status = 'Good'
    elif score >= 50:
        color = 'red'
        emoji = '❌'
        status = 'Needs Improvement'
    else:
        color = 'red'
        emoji = '🚨'
        status = 'Critical'
    
    click.echo(f"{emoji} Security Score: {click.style(str(score), fg=color, bold=True)}/100")
    click.echo(f"Status: {status}")
    
    if score < 70:
        click.echo("\n🔒 Recommendations:")
        for rec in results.get('recommendations', [])[:3]:
            click.echo(f"  • {rec.get('title', '')}")
    
    sys.exit(0 if score >= 70 else 1)

@cli.command()
@click.option('--path', default='~/.openclaw', help='OpenClaw installation path')
@click.option('--frameworks', default='soc2,hipaa,gdpr', help='Comma-separated frameworks to check')
@click.option('--output', type=click.Choice(['json', 'text']), default='text', help='Output format')
def compliance(path, frameworks, output):
    """Check compliance readiness (SOC 2, HIPAA, GDPR)"""
    from .scanner import OpenClawScanner
    path = Path(path).expanduser()
    if not path.exists():
        click.echo(f"Error: OpenClaw path not found: {path}", err=True)
        sys.exit(1)

    fw_list = [f.strip().lower() for f in frameworks.split(",")]
    click.echo(f"Checking compliance: {', '.join(f.upper() for f in fw_list)}")

    scanner = OpenClawScanner(str(path))
    scanner.scan_compliance(fw_list)

    if output == 'json':
        import json
        click.echo(json.dumps(scanner.results.get("compliance", {}), indent=2))
    else:
        comp = scanner.results.get("compliance", {})
        for fw_key, fw in comp.items():
            name = fw.get("framework", fw_key.upper())
            score_val = fw.get("score", 0)
            readiness = fw.get("readiness", "Unknown")
            color = 'green' if score_val >= 80 else 'yellow' if score_val >= 50 else 'red'
            click.echo(f"\n{name}: {click.style(f'{score_val}%', fg=color, bold=True)} — {readiness}")
            for ctrl in fw.get("controls", []):
                icon = "✓" if ctrl["status"] == "pass" else "✗"
                click.echo(f"  {icon} [{ctrl['id']}] {ctrl['name']}")
                click.echo(f"    {ctrl['detail']}")

    sys.exit(0)

@cli.command()
@click.option('--policy', type=click.Choice(['standard', 'strict']), default='standard', help='Sandbox strictness')
@click.option('--workdir', default='.', help='Directory the sandboxed process may write to')
@click.option('--allow-network', is_flag=True, help='Permit network access (default: blocked)')
@click.option('--no-exec', is_flag=True, help='(strict) deny spawning new programs')
@click.option('--show-profile', is_flag=True, help='Print the generated Seatbelt profile and exit')
@click.argument('command', nargs=-1)
def sandbox(policy, workdir, allow_network, no_exec, show_profile, command):
    """Run a command under a macOS Seatbelt sandbox (no command = self-test)."""
    from . import sandbox as sb
    if not sb.is_available():
        click.echo("Error: Seatbelt sandboxing requires macOS with /usr/bin/sandbox-exec.", err=True)
        sys.exit(1)

    wd = str(Path(workdir).expanduser())

    if show_profile:
        click.echo(sb.build_profile(policy, wd, allow_network, not no_exec))
        sys.exit(0)

    if not command:
        click.echo("🛡️  ClawGuard Seatbelt self-test")
        res = sb.check()
        for name, ok in res.get("checks", {}).items():
            click.echo(f"  {'✓' if ok else '✗'} {name.replace('_', ' ')}")
        passed = res.get("passed", False)
        click.echo("✅ Sandbox enforces isolation." if passed else "❌ Sandbox NOT enforcing — investigate.")
        sys.exit(0 if passed else 1)

    res = sb.run(list(command), policy=policy, workdir=wd,
                 allow_network=allow_network, allow_exec=not no_exec)
    if res.stdout:
        click.echo(res.stdout, nl=False)
    if res.stderr:
        click.echo(res.stderr, nl=False, err=True)
    sys.exit(res.returncode)


@cli.command()
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
def patterns(output):
    """Show the malicious-pattern corpus (count + categories)."""
    from . import patterns as P
    if output == 'json':
        import json
        click.echo(json.dumps({"count": P.count(), "categories": P.categories()}, indent=2))
        return
    click.echo(f"🛡️  ClawGuard malicious-pattern corpus: {click.style(str(P.count()), bold=True)} signatures")
    for cat, n in P.categories().items():
        click.echo(f"  {n:>4}  {cat}")


def main():
    cli()

if __name__ == '__main__':
    main()