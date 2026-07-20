#!/usr/bin/env python3
"""
Security Headers Scanner Pro - Complete Security Audit Tool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A comprehensive security audit tool that checks:
- Security Headers
- SSL/TLS Configuration
- Technology Fingerprinting
- Subdomain Discovery
- Directory Scanning
- CVSS Scoring
"""

import sys
import os
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box
import json

from src.scanner import SecurityHeaderScanner
from src.ssl_analyzer import SSLAnalyzer
from src.fingerprinter import TechnologyFingerprinter
from src.subdomain_scanner import SubdomainScanner
from src.directory_scanner import DirectoryScanner
from src.reporter import ReportGenerator
from src.storage import get_storage
from src.headers import HeaderStatus


console = Console()


def load_config():
    """Load configuration from config.yaml"""
    import yaml
    config_path = Path(__file__).parent / "config.yaml"
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}


@click.group()
@click.version_option(version="2.0.0", prog_name="Security Audit Pro")
def cli():
    """
    🛡️ Security Audit Pro - Complete Security Assessment Tool
    
    A comprehensive security audit tool for developers and security professionals.
    """
    pass


# ============================================================================
# SECURITY HEADERS SCAN
# ============================================================================

@cli.command()
@click.argument("url")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--format", "-f", type=click.Choice(["text", "json", "html", "csv", "markdown"]), 
              default="text", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def scan(url: str, verbose: bool, format: str, output: str):
    """
    Scan a URL for security headers.
    """
    config = load_config()
    
    scanner = SecurityHeaderScanner(
        timeout=config.get("scanner", {}).get("timeout", 30),
        max_retries=config.get("scanner", {}).get("max_retries", 3),
        rate_limit_delay=config.get("scanner", {}).get("rate_limit_delay", 1.0),
    )
    
    reporter = ReportGenerator()
    
    console.print(f"\n🔍 Scanning headers: [bold cyan]{url}[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching headers...", total=None)
        result = scanner.scan(url)
        progress.update(task, completed=True)
    
    if result.error:
        console.print(f"\n🚨 Error: {result.error}\n", style="bold red")
        sys.exit(1)
    
    # Generate and display report
    if format == "text":
        report = reporter.generate(result, "text")
        console.print(report)
    elif format == "json":
        report = reporter.generate(result, "json")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Report saved to: {output}")
        else:
            console.print(report)
    elif format == "html":
        report = reporter.generate(result, "html")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ HTML report saved to: {output}")
        else:
            console.print(report)


# ============================================================================
# SSL/TLS ANALYSIS
# ============================================================================

@cli.command()
@click.argument("host")
@click.option("--port", "-p", default=443, help="Port number")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def ssl(host: str, port: int, format: str, output: str):
    """
    Analyze SSL/TLS certificate and configuration.
    
    Example: python main.py ssl example.com
    """
    console.print(f"\n🔐 Analyzing SSL/TLS: [bold cyan]{host}:{port}[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing SSL...", total=None)
        
        analyzer = SSLAnalyzer(timeout=10)
        result = analyzer.analyze(host, port)
        
        progress.update(task, completed=True)
    
    if format == "json":
        report = json.dumps(result.to_dict(), indent=2)
        if output:
            Path(output).write_text(report)
            console.print(f"✅ Report saved to: {output}")
        else:
            console.print(report)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]SSL/TLS Analysis Results[/bold]\n\n"
        f"Host: {result.host}:{result.port}\n"
        f"Grade: [bold]{result.grade}[/bold] ({result.overall_score}/100)",
        border_style="blue"
    ))
    
    if result.certificate:
        cert = result.certificate
        console.print(f"\n📜 Certificate Information:")
        console.print(f"   Subject: {cert.subject}")
        console.print(f"   Issuer: {cert.issuer}")
        console.print(f"   Valid Until: {cert.valid_until}")
        
        if cert.is_expired:
            console.print(f"   ⚠️  [bold red]EXPIRED![/bold red] (Expired {abs(cert.days_remaining)} days ago)")
        elif cert.days_remaining < 30:
            console.print(f"   ⚠️  [bold yellow]Expires in {cert.days_remaining} days[/bold yellow]")
        else:
            console.print(f"   ✅ Valid (Expires in {cert.days_remaining} days)")
    
    if result.tls_analysis:
        tls = result.tls_analysis
        console.print(f"\n🔒 TLS Configuration:")
        console.print(f"   TLS Version: {tls.tls_version}")
        console.print(f"   Cipher Suite: {tls.cipher_suite}")
        
        if tls.is_secure:
            console.print(f"   ✅ Configuration is secure")
        else:
            console.print(f"   ❌ Configuration has issues")
    
    if result.issues:
        console.print(f"\n🚨 Issues Found:")
        for issue in result.issues:
            console.print(f"   • {issue}")
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}")


# ============================================================================
# TECHNOLOGY FINGERPRINTING
# ============================================================================

@cli.command()
@click.argument("url")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def fingerprint(url: str, format: str, output: str):
    """
    Detect technologies used by a website.
    
    Example: python main.py fingerprint https://example.com
    """
    console.print(f"\n🔎 Fingerprinting: [bold cyan]{url}[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing technologies...", total=None)
        
        fingerprinter = TechnologyFingerprinter()
        result = fingerprinter.fingerprint(url)
        
        progress.update(task, completed=True)
    
    if format == "json":
        report = json.dumps(result.to_dict(), indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"✅ Report saved to: {output}")
        else:
            console.print(report)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]Technology Fingerprint Results[/bold]\n\n"
        f"URL: {result.url}\n"
        f"Technologies Found: {len(result.technologies)}\n"
        f"Security Score: [bold]{result.overall_score}/100[/bold]",
        border_style="green"
    ))
    
    if result.server:
        console.print(f"\n🖥️  Server: {result.server}")
    if result.powered_by:
        console.print(f"⚡ Powered By: {result.powered_by}")
    
    # Categorize technologies
    if result.frontend_frameworks:
        console.print(f"\n🎨 Frontend Frameworks:")
        for fw in result.frontend_frameworks:
            console.print(f"   • {fw}")
    
    if result.backend_technologies:
        console.print(f"\n⚙️  Backend Technologies:")
        for bt in result.backend_technologies:
            console.print(f"   • {bt}")
    
    if result.cms_platform:
        console.print(f"\n📝 CMS Platform: [bold]{result.cms_platform}[/bold]")
    
    if result.javascript_libs:
        console.print(f"\n📚 JavaScript Libraries:")
        for lib in result.javascript_libs:
            console.print(f"   • {lib}")
    
    if result.issues:
        console.print(f"\n🚨 Security Issues:")
        for issue in result.issues:
            console.print(f"   • {issue}")
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}")


# ============================================================================
# SUBDOMAIN SCANNING
# ============================================================================

@cli.command()
@click.argument("domain")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--quick", is_flag=True, help="Quick scan (fewer subdomains)")
def subdomains(domain: str, format: str, output: str, quick: bool):
    """
    Discover subdomains for a domain.
    
    Example: python main.py subdomains example.com
    """
    console.print(f"\n🌐 Scanning subdomains: [bold cyan]{domain}[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Discovering subdomains...", total=None)
        
        scanner = SubdomainScanner(timeout=5, max_concurrent=50)
        result = scanner.scan(domain)
        
        progress.update(task, completed=True)
    
    if format == "json":
        report = json.dumps(result.to_dict(), indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"✅ Report saved to: {output}")
        else:
            console.print(report)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]Subdomain Discovery Results[/bold]\n\n"
        f"Domain: {result.domain}\n"
        f"Subdomains Found: {result.total_found}\n"
        f"Alive: {result.alive_count} | Dead: {result.dead_count}\n"
        f"Security Score: [bold]{result.overall_score}/100[/bold]",
        border_style="yellow"
    ))
    
    if result.alive_count > 0:
        console.print(f"\n✅ Live Subdomains Found:")
        
        table = Table(box=box.ROUNDED)
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP", style="white")
        table.add_column("Services", style="green")
        
        for sub in result.subdomains:
            if sub.is_alive:
                services = ", ".join(sub.services) if sub.services else "-"
                table.add_row(sub.subdomain, sub.ip_address or "-", services)
        
        console.print(table)
    
    if result.issues:
        console.print(f"\n🚨 Security Issues:")
        for issue in result.issues:
            console.print(f"   • {issue}")
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}")


# ============================================================================
# DIRECTORY SCANNING
# ============================================================================

@cli.command()
@click.argument("url")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--quick", is_flag=True, help="Quick scan (sensitive paths only)")
def dirs(url: str, format: str, output: str, quick: bool):
    """
    Scan for directories and sensitive files.
    
    Example: python main.py dirs https://example.com
    """
    console.print(f"\n📁 Scanning directories: [bold cyan]{url}[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning directories...", total=None)
        
        scanner = DirectoryScanner(timeout=5, max_workers=20)
        result = scanner.scan(
            url,
            check_sensitive=True,
            check_directories=not quick,
        )
        
        progress.update(task, completed=True)
    
    if format == "json":
        report = json.dumps(result.to_dict(), indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"✅ Report saved to: {output}")
        else:
            console.print(report)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]Directory Scan Results[/bold]\n\n"
        f"URL: {result.base_url}\n"
        f"Paths Scanned: {result.scanned_paths}\n"
        f"Paths Found: {result.found_paths}\n"
        f"Security Score: [bold]{result.overall_score}/100[/bold]",
        border_style="red"
    ))
    
    if result.sensitive_paths:
        console.print(f"\n🚨 Sensitive Paths Found:")
        
        table = Table(box=box.ROUNDED)
        table.add_column("Path", style="cyan")
        table.add_column("Status", style="yellow")
        table.add_column("Reason", style="red")
        
        for path in result.sensitive_paths[:20]:  # Limit to 20
            table.add_row(path.path, str(path.status_code), path.sensitivity_reason)
        
        console.print(table)
    
    if result.issues:
        console.print(f"\n🚨 Security Issues:")
        for issue in result.issues:
            console.print(f"   • {issue}")
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}")


# ============================================================================
# COMPLETE SECURITY AUDIT
# ============================================================================

@cli.command()
@click.argument("url")
@click.option("--format", "-f", type=click.Choice(["text", "json"]), default="text")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def audit(url: str, format: str, output: str):
    """
    Run complete security audit (all checks).
    
    Example: python main.py audit https://example.com
    """
    console.print(Panel.fit(
        "[bold cyan]🛡️  SECURITY AUDIT PRO[/bold cyan]\n\n"
        "Running comprehensive security assessment...",
        border_style="bold blue"
    ))
    
    # Parse domain
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc or url.replace("https://", "").replace("http://", "").split("/")[0]
    domain = host.replace("www.", "")
    
    results = {
        "url": url,
        "domain": domain,
        "timestamp": str(datetime.now()),
        "headers": None,
        "ssl": None,
        "fingerprint": None,
        "subdomains": None,
        "directories": None,
        "overall_score": 100,
        "critical_findings": [],
    }
    
    # 1. Security Headers Scan
    console.print(f"\n[cyan]1. Scanning security headers...[/cyan]")
    try:
        scanner = SecurityHeaderScanner()
        header_result = scanner.scan(url)
        results["headers"] = header_result.to_dict()
        
        if header_result.percentage_score < 50:
            results["critical_findings"].append({
                "type": "headers",
                "severity": "high",
                "message": f"Low security headers score: {header_result.percentage_score}%"
            })
    except Exception as e:
        results["headers"] = {"error": str(e)}
    
    # 2. SSL/TLS Analysis
    console.print(f"[cyan]2. Analyzing SSL/TLS...[/cyan]")
    try:
        ssl_analyzer = SSLAnalyzer()
        ssl_result = ssl_analyzer.analyze(domain)
        results["ssl"] = ssl_result.to_dict()
        
        if ssl_result.overall_score < 70:
            results["critical_findings"].append({
                "type": "ssl",
                "severity": "high",
                "message": f"SSL/TLS issues found: Grade {ssl_result.grade}"
            })
    except Exception as e:
        results["ssl"] = {"error": str(e)}
    
    # 3. Technology Fingerprinting
    console.print(f"[cyan]3. Fingerprinting technologies...[/cyan]")
    try:
        fingerprinter = TechnologyFingerprinter()
        fp_result = fingerprinter.fingerprint(url)
        results["fingerprint"] = fp_result.to_dict()
        
        for issue in fp_result.issues:
            results["critical_findings"].append({
                "type": "tech",
                "severity": "medium",
                "message": issue
            })
    except Exception as e:
        results["fingerprint"] = {"error": str(e)}
    
    # 4. Subdomain Discovery
    console.print(f"[cyan]4. Discovering subdomains...[/cyan]")
    try:
        subdomain_scanner = SubdomainScanner()
        sub_result = subdomain_scanner.scan(domain)
        results["subdomains"] = sub_result.to_dict()
        
        for issue in sub_result.issues:
            results["critical_findings"].append({
                "type": "subdomain",
                "severity": "medium",
                "message": issue
            })
    except Exception as e:
        results["subdomains"] = {"error": str(e)}
    
    # 5. Directory Scanning
    console.print(f"[cyan]5. Scanning directories...[/cyan]")
    try:
        dir_scanner = DirectoryScanner()
        dir_result = dir_scanner.scan(url, check_directories=False)
        results["directories"] = dir_result.to_dict()
        
        for issue in dir_result.issues:
            results["critical_findings"].append({
                "type": "directory",
                "severity": "high",
                "message": issue
            })
    except Exception as e:
        results["directories"] = {"error": str(e)}
    
    # Calculate overall score
    scores = []
    if results["headers"]:
        scores.append(results["headers"].get("percentage_score", 0))
    if results["ssl"]:
        scores.append(results["ssl"].get("overall_score", 0))
    if results["fingerprint"]:
        scores.append(results["fingerprint"].get("overall_score", 100))
    if results["subdomains"]:
        scores.append(results["subdomains"].get("overall_score", 100))
    if results["directories"]:
        scores.append(results["directories"].get("overall_score", 100))
    
    results["overall_score"] = sum(scores) / len(scores) if scores else 0
    
    # Output
    if format == "json":
        report = json.dumps(results, indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Full audit saved to: {output}")
        else:
            console.print(report)
        return
    
    # Text output
    console.print("\n" + "=" * 60)
    console.print("📊 AUDIT SUMMARY")
    console.print("=" * 60)
    
    console.print(f"\n🎯 Overall Security Score: [bold]{results['overall_score']:.1f}/100[/bold]")
    
    if results["headers"]:
        h = results["headers"]
        console.print(f"\n🔐 Security Headers: {h.get('percentage_score', 0):.1f}%")
    if results["ssl"]:
        s = results["ssl"]
        console.print(f"🔒 SSL/TLS: {s.get('grade', 'N/A')} ({s.get('overall_score', 0)}/100)")
    if results["fingerprint"]:
        f = results["fingerprint"]
        console.print(f"🔎 Technologies: {f.get('overall_score', 0)}/100 ({len(f.get('technologies', []))} found)")
    if results["subdomains"]:
        sub = results["subdomains"]
        console.print(f"🌐 Subdomains: {sub.get('alive_count', 0)} alive ({sub.get('overall_score', 0)}/100)")
    if results["directories"]:
        d = results["directories"]
        console.print(f"📁 Sensitive Paths: {len(d.get('sensitive_paths', []))} found ({d.get('overall_score', 0)}/100)")
    
    if results["critical_findings"]:
        console.print(f"\n🚨 CRITICAL FINDINGS:")
        for finding in results["critical_findings"]:
            console.print(f"   [{finding['severity'].upper()}] {finding['message']}")


# ============================================================================
# HELPER COMMANDS
# ============================================================================

@cli.command()
def headers():
    """List all security headers checked by the scanner."""
    config = load_config()
    scanner = SecurityHeaderScanner()
    
    table = Table(title="Security Headers Reference", box=box.ROUNDED)
    table.add_column("Header", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Weight", justify="center")
    
    for h in scanner.registry.get_all():
        table.add_row(
            h.display_name,
            h.description[:60] + "..." if len(h.description) > 60 else h.description,
            str(h.weight),
        )
    
    console.print(table)


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", type=int, default=5000, help="Port to bind to")
def serve(host: str, port: int):
    """Start the REST API server."""
    from src.api import create_app
    console.print(f"\n🚀 Starting API server on {host}:{port}\n")
    app = create_app()
    app.run(host=host, port=port, debug=False)


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n\n👋 Goodbye!\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n🚨 Error: {e}\n", style="bold red")
        sys.exit(1)


if __name__ == "__main__":
    main()
