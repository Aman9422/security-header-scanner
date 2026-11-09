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
from typing import Optional
from datetime import datetime
from urllib.parse import urlparse

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape as escape_rich_markup
from rich import box
import json

from src.scanner import SecurityHeaderScanner
from src.analyzer import HeaderAnalyzer
from src.ssl_analyzer import SSLAnalyzer
from src.fingerprinter import TechnologyFingerprinter
from src.subdomain_scanner import SubdomainScanner
from src.directory_scanner import DirectoryScanner
from src.reporter import ReportGenerator
from src.storage import get_storage
from src.headers import HeaderStatus
from src.config import load_config as _load_shared_config
from src.utils import normalize_http_url, redact_sensitive_url


console = Console()


def load_config():
    """Load and validate the repository configuration."""
    return _load_shared_config()


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
        rate_limit_delay=config["scanner"]["rate_limit_delay"],
        max_batch_size=config["scanner"]["max_batch_size"],
        user_agent=config["scanner"]["user_agent"],
        follow_redirects=config["scanner"]["follow_redirects"],
        analyzer=HeaderAnalyzer(config["thresholds"]),
    )
    
    reporter = ReportGenerator()
    
    console.print(f"\n🔍 Scanning headers: {redact_sensitive_url(url)}\n", markup=False)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching headers...", total=None)
        result = scanner.scan(url)
        progress.update(task, completed=True)
    
    if result.error:
        console.print(f"\n🚨 Error: {result.error}\n", style="bold red", markup=False)
        sys.exit(1)
    
    # All documented report formats share the same output and file handling.
    report = reporter.generate(result, format)
    if verbose and format == "text":
        details = [
            "", "VERBOSE DETAILS", f"Final URL: {redact_sensitive_url(result.final_url) or 'N/A'}",
            f"HTTP status: {result.http_status_code or 'N/A'}",
            f"Duration: {result.scan_duration_ms:.1f} ms", "Security response headers:",
        ]
        details.extend(f"  {name}: {value}" for name, value in sorted(result.headers_found.items()))
        report += "\n" + "\n".join(details)
    if output:
        Path(output).write_text(report, encoding="utf-8")
        console.print(f"\n✅ {format.upper()} report saved to: {output}", markup=False)
    else:
        console.print(report, markup=False)


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
    console.print(f"\n🔐 Analyzing SSL/TLS: {host}:{port}\n", markup=False)
    
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
            console.print(f"✅ Report saved to: {output}", markup=False)
        else:
            console.print(report, markup=False)
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
        console.print(f"   Subject: {cert.subject}", markup=False)
        console.print(f"   Issuer: {cert.issuer}", markup=False)
        console.print(f"   Valid Until: {cert.valid_until}", markup=False)
        
        if cert.is_expired:
            console.print(f"   ⚠️  [bold red]EXPIRED![/bold red] (Expired {abs(cert.days_remaining)} days ago)")
        elif cert.days_remaining < 30:
            console.print(f"   ⚠️  [bold yellow]Expires in {cert.days_remaining} days[/bold yellow]")
        else:
            console.print(f"   ✅ Valid (Expires in {cert.days_remaining} days)")
    
    if result.tls_analysis:
        tls = result.tls_analysis
        console.print(f"\n🔒 TLS Configuration:")
        console.print(f"   TLS Version: {tls.tls_version}", markup=False)
        console.print(f"   Cipher Suite: {tls.cipher_suite}", markup=False)
        
        if tls.is_secure:
            console.print(f"   ✅ Configuration is secure")
        else:
            console.print(f"   ❌ Configuration has issues")
    
    if result.issues:
        console.print(f"\n🚨 Issues Found:")
        for issue in result.issues:
            console.print(f"   • {issue}", markup=False)
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}", markup=False)


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
    console.print(f"\n🔎 Fingerprinting: {url}\n", markup=False)
    
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
            console.print(f"✅ Report saved to: {output}", markup=False)
        else:
            console.print(report, markup=False)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]Technology Fingerprint Results[/bold]\n\n"
        f"URL: {escape_rich_markup(result.url)}\n"
        f"Technologies Found: {len(result.technologies)}\n"
        f"Security Score: [bold]{result.overall_score}/100[/bold]",
        border_style="green"
    ))
    
    if result.server:
        console.print(f"\n🖥️  Server: {result.server}", markup=False)
    if result.powered_by:
        console.print(f"⚡ Powered By: {result.powered_by}", markup=False)
    
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
        console.print(f"\n📝 CMS Platform: {result.cms_platform}", markup=False)
    
    if result.javascript_libs:
        console.print(f"\n📚 JavaScript Libraries:")
        for lib in result.javascript_libs:
            console.print(f"   • {lib}")
    
    if result.issues:
        console.print(f"\n🚨 Security Issues:")
        for issue in result.issues:
            console.print(f"   • {issue}", markup=False)
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}", markup=False)


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
    console.print(f"\n🌐 Scanning subdomains: {domain}\n", markup=False)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Discovering subdomains...", total=None)
        
        scanner = SubdomainScanner(timeout=5, max_concurrent=50)
        wordlist = scanner.QUICK_SUBDOMAINS if quick else None
        result = scanner.scan(domain, wordlist=wordlist)
        
        progress.update(task, completed=True)
    
    if format == "json":
        report = json.dumps(result.to_dict(), indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"✅ Report saved to: {output}", markup=False)
        else:
            console.print(report, markup=False)
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
            console.print(f"   • {issue}", markup=False)
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}", markup=False)


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
    console.print(f"\n📁 Scanning directories: {url}\n", markup=False)
    
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
            console.print(f"✅ Report saved to: {output}", markup=False)
        else:
            console.print(report, markup=False)
        return
    
    # Text output
    console.print(Panel.fit(
        f"[bold]Directory Scan Results[/bold]\n\n"
        f"URL: {escape_rich_markup(result.base_url)}\n"
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
            console.print(f"   • {issue}", markup=False)
    
    if result.recommendations:
        console.print(f"\n💡 Recommendations:")
        for rec in result.recommendations:
            console.print(f"   • {rec}", markup=False)


def _compute_audit_scores(results):
    """Return visible component scores and a header/TLS-only composite."""
    score_components = {}
    headers_data = results.get("headers") or {}
    header_score = (headers_data.get("score") or {}).get("percentage")
    if not headers_data.get("error") and isinstance(header_score, (int, float)):
        score_components["headers"] = float(header_score)

    ssl_data = results.get("ssl") or {}
    if ssl_data.get("is_reachable") and isinstance(ssl_data.get("overall_score"), (int, float)):
        score_components["ssl"] = float(ssl_data["overall_score"])

    for key in ("fingerprint", "subdomains", "directories"):
        component = results.get(key) or {}
        if not component.get("error") and isinstance(component.get("overall_score"), (int, float)):
            score_components[key] = float(component["overall_score"])

    composite = [score_components[key] for key in ("headers", "ssl") if key in score_components]
    overall = round(sum(composite) / len(composite), 1) if composite else None
    return score_components, overall


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
    config = load_config()
    console.print(Panel.fit(
        "[bold cyan]🛡️  SECURITY AUDIT PRO[/bold cyan]\n\n"
        "Running comprehensive security assessment...",
        border_style="bold blue"
    ))
    
    # Parse and validate the URL once; use hostname and port separately.
    from urllib.parse import urlparse
    try:
        audit_url = normalize_http_url(url)
        parsed = urlparse(audit_url)
        host = parsed.hostname
        explicit_port = parsed.port
    except ValueError as exc:
        raise click.BadParameter(str(exc)) from exc
    if not host:
        raise click.BadParameter("Provide an HTTP(S) URL with a hostname")
    domain = host[4:] if host.lower().startswith("www.") else host
    tls_port = explicit_port if parsed.scheme.lower() == "https" and explicit_port else 443
    
    results = {
        "url": audit_url,
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
        scanner = SecurityHeaderScanner(
            timeout=config["scanner"]["timeout"],
            max_retries=config["scanner"]["max_retries"],
            rate_limit_delay=config["scanner"]["rate_limit_delay"],
            max_batch_size=config["scanner"]["max_batch_size"],
            user_agent=config["scanner"]["user_agent"],
            follow_redirects=config["scanner"]["follow_redirects"],
            analyzer=HeaderAnalyzer(config["thresholds"]),
        )
        header_result = scanner.scan(audit_url)
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
        ssl_result = ssl_analyzer.analyze(host, tls_port)
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
        fp_result = fingerprinter.fingerprint(audit_url)
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
        dir_result = dir_scanner.scan(audit_url, check_directories=False)
        results["directories"] = dir_result.to_dict()
        
        for issue in dir_result.issues:
            results["critical_findings"].append({
                "type": "directory",
                "severity": "high",
                "message": issue
            })
    except Exception as e:
        results["directories"] = {"error": str(e)}
    
    # Keep component scores visible. Only combine the independently normalized
    # header and TLS scores; the other scanners use different heuristics and
    # should not silently distort the composite.
    score_components, overall_score = _compute_audit_scores(results)
    results["score_components"] = score_components
    results["overall_score"] = overall_score
    results["overall_score_note"] = (
        "Average of successful header and TLS scores only; other component scores are heuristic and shown separately."
    )
    
    # Output
    if format == "json":
        report = json.dumps(results, indent=2, default=str)
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Full audit saved to: {output}", markup=False)
        else:
            console.print(report, markup=False)
        return
    
    # Text output
    console.print("\n" + "=" * 60)
    console.print("📊 AUDIT SUMMARY")
    console.print("=" * 60)
    
    if results["overall_score"] is None:
        console.print("\n🎯 Overall Security Score: [bold]N/A[/bold] (header and TLS checks did not complete)")
    else:
        console.print(f"\n🎯 Header/TLS Score: [bold]{results['overall_score']:.1f}/100[/bold]")
    
    if results["headers"]:
        h = results["headers"]
        header_score = (h.get("score") or {}).get("percentage")
        if isinstance(header_score, (int, float)):
            console.print(f"\n🔐 Security Headers: {header_score:.1f}%")
        else:
            console.print("\n🔐 Security Headers: N/A")
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
            console.print(f"   [{finding['severity'].upper()}] {finding['message']}", markup=False)


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
@click.option("--host", "-h", default=None, help="Override api.host from config.yaml")
@click.option("--port", "-p", type=click.IntRange(1, 65535), default=None, help="Override api.port from config.yaml")
def serve(host: Optional[str], port: Optional[int]):
    """Start the REST API with the production Waitress WSGI server."""
    from src.api import run_server
    config = load_config()
    api_config = config["api"]
    bind_host = host if host is not None else api_config["host"]
    bind_port = port if port is not None else api_config["port"]
    console.print(f"\n🚀 Starting API server on {bind_host}:{bind_port} (Waitress)\n")
    run_server(host=bind_host, port=bind_port)


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n\n👋 Goodbye!\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n🚨 Error: {e}\n", style="bold red", markup=False)
        sys.exit(1)


if __name__ == "__main__":
    main()
