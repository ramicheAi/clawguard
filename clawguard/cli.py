#!/usr/bin/env python3
"""
ClawGuard CLI - Command line interface
"""

import click
import sys
from pathlib import Path
from .scanner import scan_openclaw, monitor_openclaw, audit_skill, generate_report

@click.group()
@click.version_option(version="0.1.0")
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
def audit_skill(skill_url):
    """Audit a ClawHub skill for security issues"""
    click.echo(f"🔍 Auditing skill: {skill_url}")
    # TODO: Implement skill auditing
    click.echo("Skill auditing feature coming soon!")
    click.echo("Subscribe to ClawGuard Pro for early access.")
    sys.exit(0)

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

def main():
    cli()

if __name__ == '__main__':
    main()