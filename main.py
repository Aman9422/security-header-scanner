#!/usr/bin/env python3
"""
Security Headers Scanner Pro
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Command-line interface for the security header scanner.
"""

import sys
import os
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.syntax import Syntax

from src.scanner import SecurityHeaderScanner
from src.reporter import ReportGenerator, BatchReportGenerator
from src.storage import get_storage
from src.api import create_app
from src.headers import HeaderStatus
from src.utils import parse_urls_from_file, ProgressTracker


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
@click.version_option(version="2.0.0", prog_name="Security Headers Scanner")
def cli():
    """
    🛡️ Security Headers Scanner Pro
    
    A comprehensive security header analysis tool for developers.
    """
    pass


@cli.command()
@click.argument("url")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--format", "-f", type=click.Choice(["text", "json", "html", "csv", "markdown"]), 
                default="text", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--save/--no-save", default=True, help="Save to history")
def scan(url: str, verbose: bool, format: str, output: str, save: bool):
    """
    Scan a URL for security headers.
    """
    config = load_config()
    
    # Initialize scanner
    scanner = SecurityHeaderScanner(
        timeout=config.get("scanner", {}).get("timeout", 30),
        max_retries=config.get("scanner", {}).get("max_retries", 3),
        rate_limit_delay=config.get("scanner", {}).get("rate_limit_delay", 1.0),
    )
    
    reporter = ReportGenerator()
    storage = get_storage(
        config.get("storage", {}).get("type", "json"),
        config.get("storage", {}).get("path", "./data")
    )
    
    console.print(f"\n🔍 Scanning: [bold cyan]{url}[/bold cyan]\n")
    
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
    
    # Save to history
    if save:
        storage.save(result)
    
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
    elif format == "csv":
        report = reporter.generate(result, "csv")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ CSV report saved to: {output}")
        else:
            console.print(report)
    elif format == "markdown":
        report = reporter.generate(result, "markdown")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Markdown report saved to: {output}")
        else:
            console.print(report)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--format", "-f", type=click.Choice(["text", "json", "csv"]), 
                default="text", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--delay", "-d", type=float, default=1.0, help="Delay between requests (seconds)")
def batch(file: str, format: str, output: str, delay: float):
    """
    Scan multiple URLs from a file.
    
    FILE should contain one URL per line. Lines starting with # are comments.
    """
    urls = parse_urls_from_file(file)
    
    if not urls:
        console.print("🚨 No URLs found in file", style="bold red")
        sys.exit(1)
    
    console.print(f"\n📋 Batch scan: [bold cyan]{len(urls)}[/bold cyan] URLs\n")
    
    scanner = SecurityHeaderScanner(rate_limit_delay=delay)
    batch_reporter = BatchReportGenerator()
    storage = get_storage()
    
    results = []
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )
    
    with progress:
        task = progress.add_task("Scanning...", total=len(urls))
        
        for i, url in enumerate(urls):
            try:
                result = scanner.scan(url)
                results.append(result)
                storage.save(result)
            except Exception as e:
                console.print(f"\n🚨 Error scanning {url}: {e}", style="bold red")
            
            progress.update(task, advance=1, description=f"Scanning {url[:40]}...")
    
    # Generate report
    if format == "text":
        report = batch_reporter.generate(results, "text")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Report saved to: {output}")
        else:
            console.print("\n" + report)
    elif format == "json":
        import json
        report_data = [r.to_dict() for r in results]
        report = json.dumps(report_data, indent=2)
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Report saved to: {output}")
        else:
            console.print(report)
    elif format == "csv":
        report = batch_reporter.generate(results, "csv")
        if output:
            Path(output).write_text(report)
            console.print(f"\n✅ Report saved to: {output}")
        else:
            console.print(report)


@cli.command()
@click.option("--limit", "-n", type=int, default=10, help="Number of results to show")
def history(limit: int):
    """
    View scan history.
    """
    storage = get_storage()
    results = storage.get_all(limit)
    
    if not results:
        console.print("\n📭 No scan history found.\n")
        return
    
    table = Table(title=f"Scan History (Last {len(results)} scans)", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("URL", style="white")
    table.add_column("Score", justify="center")
    table.add_column("Grade", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Time", style="dim")
    
    for r in results:
        # Color code score
        score_style = "green" if r.percentage_score >= 75 else "yellow" if r.percentage_score >= 50 else "red"
        risk_style = "green" if r.risk_level == "excellent" or r.risk_level == "good" else "yellow" if r.risk_level == "medium" else "red"
        
        table.add_row(
            r.id,
            r.url[:40] + "..." if len(r.url) > 40 else r.url,
            f"[{score_style}]{r.percentage_score}%[/{score_style}]",
            f"[bold]{r.grade}[/bold]",
            f"[{risk_style}]{r.risk_level}[/{risk_style}]",
            r.timestamp.split()[1] if " " in r.timestamp else r.timestamp,
        )
    
    console.print(table)


@cli.command()
@click.argument("scan_id")
@click.option("--format", "-f", type=click.Choice(["text", "json", "html", "csv"]), 
                default="text", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def report(scan_id: str, format: str, output: str):
    """
    Generate a report from a previous scan.
    """
    storage = get_storage()
    result = storage.get(scan_id)
    
    if not result:
        console.print(f"\n🚨 Scan not found: {scan_id}\n", style="bold red")
        sys.exit(1)
    
    reporter = ReportGenerator()
    report_content = reporter.generate(result, format)
    
    if output:
        Path(output).write_text(report_content)
        console.print(f"\n✅ Report saved to: {output}")
    else:
        if format == "text":
            console.print("\n" + report_content)
        else:
            console.print(report_content)


@cli.command()
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", type=int, default=5000, help="Port to bind to")
@click.option("--debug", is_flag=True, help="Enable debug mode")
def serve(host: str, port: int, debug: bool):
    """
    Start the REST API server.
    """
    console.print(f"\n🚀 Starting API server on {host}:{port}\n")
    console.print("Available endpoints:")
    console.print("  GET  /api/v1/health           - Health check")
    console.print("  GET  /api/v1/scan?url=...      - Scan a URL")
    console.print("  GET  /api/v1/history          - Get scan history")
    console.print("  POST /api/v1/batch             - Batch scan")
    console.print("  GET  /api/v1/headers           - List all headers\n")
    
    app = create_app()
    app.run(host=host, port=port, debug=debug)


@cli.command()
def headers():
    """
    List all security headers checked by the scanner.
    """
    config = load_config()
    scanner = SecurityHeaderScanner()
    
    table = Table(title="Security Headers Reference", box=box.ROUNDED)
    table.add_column("Header", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Weight", justify="center")
    table.add_column("Category", style="magenta")
    
    for h in scanner.registry.get_all():
        table.add_row(
            h.display_name,
            h.description[:60] + "..." if len(h.description) > 60 else h.description,
            str(h.weight),
            h.category,
        )
    
    console.print(table)


@cli.command()
@click.option("--days", "-d", type=int, default=30, help="Delete scans older than N days")
@click.confirmation_option(prompt="Are you sure you want to delete old scans?")
def cleanup(days: int):
    """
    Clean up old scan history.
    """
    storage = get_storage()
    deleted = storage.cleanup(days)
    console.print(f"\n✅ Deleted {deleted} old scan(s).\n")


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
