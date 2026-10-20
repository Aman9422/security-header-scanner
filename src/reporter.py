"""
Report Generator
~~~~~~~~~~~~~~~~

Generate various report formats from scan results.
"""

import csv
import html
import io
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
from jinja2 import Template

from .scanner import ScanResult, HeaderResult
from .headers import HeaderStatus
from .utils import redact_sensitive_url


def _escape_markdown(value: Any) -> str:
    """Escape untrusted text for common Markdown and raw-HTML renderers."""
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\\", "\\\\")
    for character in "`*_{}[]()#+!|":
        text = text.replace(character, "\\" + character)
    return html.escape(text, quote=False)

class ReportGenerator:
    """
    Generate reports from scan results in various formats.
    """
    
    def __init__(self):
        self.html_template = self._get_html_template()
    
    def generate(
        self,
        result: ScanResult,
        format: str = "text",
        output_path: Optional[str] = None
    ) -> str:
        """
        Generate a report from scan results.
        
        Args:
            result: ScanResult object
            format: Output format (text, json, html, csv, markdown)
            output_path: Optional path to save the report
            
        Returns:
            Generated report as string
        """
        generators = {
            "text": self._generate_text,
            "json": self._generate_json,
            "html": self._generate_html,
            "csv": self._generate_csv,
            "markdown": self._generate_markdown,
        }
        
        if not isinstance(format, str) or format.lower() not in generators:
            raise ValueError(f"Unsupported report format: {format!r}")
        generator = generators[format.lower()]
        report = generator(result)
        
        if output_path:
            self._save_report(report, output_path)
        
        return report
    
    def _save_report(self, content: str, path: str):
        """Save report to file"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def _generate_text(self, result: ScanResult) -> str:
        """Generate plain text report"""
        lines = []
        
        # Header
        lines.append("=" * 70)
        lines.append("              🛡️  SECURITY HEADERS SCANNER PRO")
        lines.append("=" * 70)
        lines.append(f"  Target: {redact_sensitive_url(result.url)}")
        lines.append(f"  Scan ID: {result.id}")
        lines.append(f"  Time: {result.timestamp}")
        lines.append(f"  Duration: {result.scan_duration_ms:.0f}ms")
        lines.append(f"  HTTP Status: {result.http_status_code or 'N/A'}")
        lines.append("=" * 70)
        
        # Score summary
        lines.append("")
        lines.append(f"  📊 OVERALL SCORE: {result.percentage_score}% ({result.grade})")
        lines.append(f"  ⚠️  Risk Level: {result.risk_level.upper()}")
        lines.append("")
        
        # Progress bar
        bar_length = 40
        filled = int(bar_length * result.percentage_score / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        lines.append(f"  [{bar}]")
        lines.append("")
        
        # Summary
        lines.append("  📋 SUMMARY")
        lines.append(f"    ✅ Present: {result.summary.get('present', 0)}")
        lines.append(f"    ⚠️  Weak: {result.summary.get('weak', 0)}")
        lines.append(f"    ❌ Misconfigured: {result.summary.get('misconfigured', 0)}")
        lines.append(f"    ❌ Missing: {result.summary.get('missing', 0)}")
        lines.append("")
        
        # Header details
        lines.append("=" * 70)
        lines.append("  HEADER ANALYSIS")
        lines.append("=" * 70)
        
        for header in result.header_results:
            status_icon = {
                HeaderStatus.PRESENT: "✅",
                HeaderStatus.WEAK: "⚠️",
                HeaderStatus.MISCONFIGURED: "❌",
                HeaderStatus.MISSING: "❌",
            }.get(header.status, "❓")
            
            status_text = header.status.value.upper()
            score_text = f"+{header.score}" if header.score > 0 else str(header.score)
            
            lines.append(f"  {status_icon} {header.display_name:<35} {status_text:<15} ({score_text})")
            
            if header.value:
                display_value = header.value[:60] + "..." if len(header.value) > 60 else header.value
                lines.append(f"      Value: {display_value}")
            
            # Show remediation if not present
            if header.status != HeaderStatus.PRESENT and header.remediation:
                lines.append(f"      📌 {header.remediation.action}")

        if result.cookie_results:
            lines.extend(["", "=" * 70, "  COOKIE SECURITY ATTRIBUTES", "=" * 70])
            for cookie in result.cookie_results:
                same_site = cookie.same_site or "Missing"
                status = "OK" if not cookie.issues else "ISSUES"
                lines.append(
                    f"  {cookie.name}: Secure={'Yes' if cookie.secure else 'No'}, "
                    f"HttpOnly={'Yes' if cookie.http_only else 'No'}, SameSite={same_site} [{status}]"
                )
                for issue in cookie.issues:
                    lines.append(f"      ⚠ {issue}")
        
        lines.append("")
        
        # Remediation priority
        missing_headers = [h for h in result.header_results 
                         if h.status != HeaderStatus.PRESENT]
        if missing_headers:
            lines.append("=" * 70)
            lines.append("  🔧 REMEDIATION PRIORITY")
            lines.append("=" * 70)
            
            # Sort by weight
            for i, header in enumerate(missing_headers, 1):
                if header.remediation:
                    severity_emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🟢",
                    }.get(header.remediation.severity.value, "⚪")
                    lines.append(f"  {i}. {severity_emoji} [{header.remediation.severity.value.upper()}] {header.display_name}")
                    lines.append(f"     Action: {header.remediation.action}")
                    if header.remediation.example:
                        lines.append(f"     Example: {header.remediation.example}")
                    lines.append("")
        
        lines.append("=" * 70)
        lines.append(f"  Generated by Security Headers Scanner Pro")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _generate_json(self, result: ScanResult, pretty: bool = True) -> str:
        """Generate JSON report"""
        indent = 2 if pretty else None
        return json.dumps(result.to_dict(), indent=indent, default=str)
    
    def _generate_html(self, result: ScanResult) -> str:
        """Generate HTML report"""
        # Pass structured values into an autoescaped template; untrusted data is
        # never marked as safe HTML.
        template = Template(self.html_template, autoescape=True)

        header_rows = []
        for h in result.header_results:
            status_class = h.status.value
            status_icon = {
                HeaderStatus.PRESENT: "✓",
                HeaderStatus.WEAK: "⚠",
                HeaderStatus.MISCONFIGURED: "✗",
                HeaderStatus.MISSING: "✗",
            }.get(h.status, "?")
            remediation_action = ""
            remediation_example = ""
            if h.status != HeaderStatus.PRESENT and h.remediation:
                remediation_action = h.remediation.action
                remediation_example = h.remediation.example
            header_rows.append({
                "status_class": status_class,
                "status_icon": status_icon,
                "display_name": h.display_name,
                "status": h.status.value,
                "score": f"{h.score:+d}",
                "value": h.value if h.value is not None else "-",
                "remediation_action": remediation_action,
                "remediation_example": remediation_example,
            })

        cookie_rows = [{
            "status_class": "present" if not cookie.issues else "misconfigured",
            "name": cookie.name,
            "secure": "Yes" if cookie.secure else "No",
            "http_only": "Yes" if cookie.http_only else "No",
            "same_site": cookie.same_site or "Missing",
            "issues": "; ".join(cookie.issues) if cookie.issues else "No issues",
        } for cookie in result.cookie_results]
        
        # Get color based on grade
        grade_colors = {
            "A+": "#28a745", "A": "#28a745", "A-": "#5cb85c",
            "B+": "#5bc0de", "B": "#5bc0de", "B-": "#6c757d",
            "C+": "#ffc107", "C": "#ffc107", "C-": "#fd7e14",
            "D": "#dc3545", "F": "#dc3545",
        }
        score_color = grade_colors.get(result.grade, "#6c757d")
        
        return template.render(
            url=redact_sensitive_url(result.url),
            scan_id=result.id,
            timestamp=result.timestamp,
            duration_ms=round(result.scan_duration_ms, 0),
            http_status=result.http_status_code or "N/A",
            percentage_score=result.percentage_score,
            grade=result.grade,
            risk_level=result.risk_level,
            score_color=score_color,
            present_count=result.summary.get('present', 0),
            weak_count=result.summary.get('weak', 0),
            misconfigured_count=result.summary.get('misconfigured', 0),
            missing_count=result.summary.get('missing', 0),
            header_rows=header_rows,
            cookie_count=len(result.cookie_results),
            cookie_rows=cookie_rows,
            total_score=result.total_score,
            max_score=result.max_score,
        )
    
    def _generate_csv(self, result: ScanResult) -> str:
        """Generate spreadsheet-safe CSV report."""
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["Header", "Status", "Score", "Weight", "Value", "Description", "Remediation"])

        def safe_cell(value: Any) -> str:
            text = "" if value is None else str(value)
            # Spreadsheet applications may execute formulas even inside quoted
            # CSV fields. Prefix formula-like values with an apostrophe.
            if text.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
                return "'" + text
            return text

        for h in result.header_results:
            remediation = ""
            if h.status != HeaderStatus.PRESENT and h.remediation:
                remediation = h.remediation.action
            writer.writerow([
                safe_cell(h.display_name),
                h.status.value,
                h.score,
                h.weight,
                safe_cell(h.value),
                safe_cell(h.description),
                safe_cell(remediation),
            ])
        for cookie in result.cookie_results:
            attributes = (
                f"Secure={'Yes' if cookie.secure else 'No'}; "
                f"HttpOnly={'Yes' if cookie.http_only else 'No'}; "
                f"SameSite={cookie.same_site or 'Missing'}"
            )
            writer.writerow([
                safe_cell(f"Cookie: {cookie.name}"),
                "ISSUES" if cookie.issues else "OK",
                "",
                "",
                safe_cell(attributes),
                safe_cell("; ".join(cookie.issues)),
                safe_cell("Set the recommended cookie security attributes"),
            ])
        return output.getvalue()
    
    def _generate_markdown(self, result: ScanResult) -> str:
        """Generate Markdown report"""
        lines = []
        
        lines.append("# 🛡️ Security Headers Scan Report")
        lines.append("")
        lines.append("## Scan Details")
        lines.append(f"- **URL**: {_escape_markdown(redact_sensitive_url(result.url))}")
        lines.append(f"- **Scan ID**: {_escape_markdown(result.id)}")
        lines.append(f"- **Timestamp**: {_escape_markdown(result.timestamp)}")
        lines.append(f"- **Duration**: {result.scan_duration_ms:.0f}ms")
        lines.append(f"- **HTTP Status**: {result.http_status_code or 'N/A'}")
        lines.append("")
        
        lines.append("## Overall Score")
        lines.append(
            f"**{result.percentage_score}%** ({_escape_markdown(result.grade)}) - "
            f"{_escape_markdown(result.risk_level.upper())} Risk"
        )
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Score | {result.total_score}/{result.max_score} |")
        lines.append(f"| Present | {result.summary.get('present', 0)} |")
        lines.append(f"| Weak | {result.summary.get('weak', 0)} |")
        lines.append(f"| Misconfigured | {result.summary.get('misconfigured', 0)} |")
        lines.append(f"| Missing | {result.summary.get('missing', 0)} |")
        lines.append("")
        
        lines.append("## Header Analysis")
        lines.append("")
        lines.append("| Header | Status | Score |")
        lines.append("|--------|--------|-------|")
        
        for h in result.header_results:
            status_emoji = {
                HeaderStatus.PRESENT: "✅",
                HeaderStatus.WEAK: "⚠️",
                HeaderStatus.MISCONFIGURED: "❌",
                HeaderStatus.MISSING: "❌",
            }.get(h.status, "?")
            
            lines.append(
                f"| {_escape_markdown(h.display_name)} | {status_emoji} "
                f"{_escape_markdown(h.status.value)} | {h.score:+d} |"
            )
        
        lines.append("")
        
        if result.cookie_results:
            lines.append("## Cookie Security Attributes")
            lines.append("")
            lines.append("| Cookie | Secure | HttpOnly | SameSite | Findings |")
            lines.append("|--------|--------|----------|----------|----------|")
            for cookie in result.cookie_results:
                findings = "; ".join(cookie.issues) if cookie.issues else "No issues"
                lines.append(
                    f"| {_escape_markdown(cookie.name)} | {'Yes' if cookie.secure else 'No'} "
                    f"| {'Yes' if cookie.http_only else 'No'} "
                    f"| {_escape_markdown(cookie.same_site or 'Missing')} "
                    f"| {_escape_markdown(findings)} |"
                )
            lines.append("")

        # Issues section
        issues = [h for h in result.header_results if h.status != HeaderStatus.PRESENT]
        if issues:
            lines.append("## Issues & Remediation")
            lines.append("")
            
            for i, h in enumerate(issues, 1):
                if h.remediation:
                    lines.append(f"### {i}. {_escape_markdown(h.display_name)}")
                    lines.append(f"- **Status**: {_escape_markdown(h.status.value)}")
                    lines.append(f"- **Action**: {_escape_markdown(h.remediation.action)}")
                    lines.append(f"- **Example**: `{_escape_markdown(h.remediation.example)}`")
                    lines.append("")
        
        lines.append("---")
        lines.append("*Generated by Security Headers Scanner Pro*")
        
        return "\n".join(lines)
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Headers Report - {{ url }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin-bottom: 10px; }
        .meta { opacity: 0.9; font-size: 0.9em; }
        .score-card { background: white; border-radius: 10px; padding: 30px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .score-display { text-align: center; padding: 20px; }
        .score-value { font-size: 4em; font-weight: bold; color: {{ score_color }}; }
        .score-grade { font-size: 2em; margin-top: 10px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 20px; }
        .summary-item { text-align: center; padding: 15px; border-radius: 8px; }
        .summary-item.present { background: #d4edda; color: #155724; }
        .summary-item.weak { background: #fff3cd; color: #856404; }
        .summary-item.misconfigured { background: #f8d7da; color: #721c24; }
        .summary-item.missing { background: #f8d7da; color: #721c24; }
        .summary-value { font-size: 2em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th { background: #343a40; color: white; padding: 15px; text-align: left; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:last-child td { border-bottom: none; }
        tr.present td { background: #d4edda; }
        tr.weak td { background: #fff3cd; }
        tr.misconfigured td, tr.missing td { background: #f8d7da; }
        .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
        .badge.present { background: #28a745; color: white; }
        .badge.weak { background: #ffc107; color: black; }
        .badge.misconfigured, .badge.missing { background: #dc3545; color: white; }
        .value-cell { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.85em; }
        .remediation { margin-top: 10px; padding: 10px; background: #e9ecef; border-radius: 5px; font-size: 0.9em; }
        .remediation code { display: block; margin-top: 5px; padding: 5px; background: #dee2e6; border-radius: 3px; }
        .footer { text-align: center; margin-top: 30px; color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Headers Scan Report</h1>
            <div class="meta">
                <div><strong>URL:</strong> {{ url }}</div>
                <div><strong>Scan ID:</strong> {{ scan_id }}</div>
                <div><strong>Time:</strong> {{ timestamp }}</div>
                <div><strong>Duration:</strong> {{ duration_ms }}ms</div>
                <div><strong>HTTP Status:</strong> {{ http_status }}</div>
            </div>
        </div>
        
        <div class="score-card">
            <div class="score-display">
                <div class="score-value">{{ percentage_score }}%</div>
                <div class="score-grade">Grade: {{ grade }}</div>
                <div style="margin-top: 10px; color: {{ score_color }};">{{ risk_level|upper }} RISK</div>
            </div>
            <div class="summary-grid">
                <div class="summary-item present">
                    <div class="summary-value">{{ present_count }}</div>
                    <div>Present</div>
                </div>
                <div class="summary-item weak">
                    <div class="summary-value">{{ weak_count }}</div>
                    <div>Weak</div>
                </div>
                <div class="summary-item misconfigured">
                    <div class="summary-value">{{ misconfigured_count }}</div>
                    <div>Misconfigured</div>
                </div>
                <div class="summary-item missing">
                    <div class="summary-value">{{ missing_count }}</div>
                    <div>Missing</div>
                </div>
            </div>
        </div>
        
        <div class="score-card">
            <h2 style="margin-bottom: 20px;">Header Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Header</th>
                        <th>Result</th>
                        <th>Score</th>
                        <th>Value</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {% for row in header_rows %}
                    <tr class="{{ row.status_class }}">
                        <td>{{ row.status_icon }}</td>
                        <td>{{ row.display_name }}</td>
                        <td><span class="badge {{ row.status_class }}">{{ row.status }}</span></td>
                        <td>{{ row.score }}</td>
                        <td class="value-cell">{{ row.value }}</td>
                        <td>
                            {% if row.remediation_action %}
                            <div class="remediation">
                                <strong>Remediation:</strong> {{ row.remediation_action }}<br>
                                <code>{{ row.remediation_example }}</code>
                            </div>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        {% if cookie_count %}
        <div class="score-card">
            <h2 style="margin-bottom: 20px;">Cookie Security Attributes</h2>
            <table>
                <thead><tr><th>Cookie</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Findings</th></tr></thead>
                <tbody>
                    {% for row in cookie_rows %}
                    <tr class="{{ row.status_class }}">
                        <td>{{ row.name }}</td><td>{{ row.secure }}</td><td>{{ row.http_only }}</td>
                        <td>{{ row.same_site }}</td><td>{{ row.issues }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <div class="footer">
            Generated by Security Headers Scanner Pro
        </div>
    </div>
</body>
</html>
        """


class BatchReportGenerator:
    """Generate reports for batch scan results"""
    
    def __init__(self):
        self.reporter = ReportGenerator()
    
    def generate(self, results: List[ScanResult], format: str = "text") -> str:
        """Generate batch report"""
        if format == "json":
            return json.dumps([r.to_dict() for r in results], indent=2, default=str)
        
        lines = []
        lines.append("=" * 70)
        lines.append("           🛡️  BATCH SECURITY HEADERS SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"  Total URLs scanned: {len(results)}")
        lines.append(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 70)
        lines.append("")
        
        # Summary stats
        scores = [r.percentage_score for r in results]
        lines.append("  OVERVIEW")
        lines.append(f"    Average Score: {sum(scores)/len(scores):.1f}%")
        lines.append(f"    Highest Score: {max(scores):.1f}%")
        lines.append(f"    Lowest Score: {min(scores):.1f}%")
        lines.append("")
        
        # Per-URL results
        lines.append("  SCAN RESULTS")
        lines.append("-" * 70)
        lines.append(f"  {'URL':<45} {'Score':>8} {'Grade':>6} {'Risk':>12}")
        lines.append("-" * 70)
        
        for r in results:
            display_url = redact_sensitive_url(r.url)
            url_short = display_url[:42] + "..." if len(display_url) > 45 else display_url
            lines.append(f"  {url_short:<45} {r.percentage_score:>7.1f}% {r.grade:>6} {r.risk_level:>12}")
        
        lines.append("-" * 70)
        lines.append("")
        
        # Issues summary
        all_issues = {}
        for r in results:
            for h in r.header_results:
                if h.status != HeaderStatus.PRESENT:
                    if h.display_name not in all_issues:
                        all_issues[h.display_name] = 0
                    all_issues[h.display_name] += 1
        
        if all_issues:
            lines.append("  COMMON ISSUES")
            lines.append("-" * 70)
            for header, count in sorted(all_issues.items(), key=lambda x: x[1], reverse=True)[:10]:
                lines.append(f"    {header}: {count} occurrences")
            lines.append("")
        
        lines.append("=" * 70)
        lines.append("  Generated by Security Headers Scanner Pro")
        lines.append("=" * 70)
        
        return "\n".join(lines)
