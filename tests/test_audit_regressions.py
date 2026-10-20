"""Regression tests for security and correctness fixes from the final audit."""

import asyncio
import csv
import dataclasses
from concurrent.futures import ThreadPoolExecutor
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import os
import socket
import sqlite3
import stat
import ssl
import threading

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import main
import src.api as api_module

from src.api import create_app, validate_scan_target
from src.config import load_config
from src.cvss_scoring import CVSSCalculator
from src.directory_scanner import DirectoryScanner
from src.ssl_analyzer import SSLAnalyzer
from src.storage import JSONStorage, SQLiteStorage, get_storage
from src.utils import generate_id, normalize_http_url, redact_sensitive_url
from src.subdomain_scanner import SubdomainScanner
from src.fingerprinter import Technology, TechnologyFingerprinter
from src.headers import DEFAULT_HEADER_REGISTRY, HeaderStatus
from src.reporter import ReportGenerator
from src.pinned_http import PinnedAddressAdapter
from src.scanner import HeaderResult, ScanResult, SecurityHeaderScanner


def _scan_result(header_value, url="https://example.com/"):
    return ScanResult(
        id="test1234",
        url=url,
        timestamp="2026-01-01 00:00:00",
        scan_duration_ms=1.0,
        http_status_code=200,
        final_url=url,
        headers_found={},
        header_results=[HeaderResult(
            header_name="x-frame-options",
            display_name="X-Frame-Options",
            status=HeaderStatus.MISCONFIGURED,
            value=header_value,
            score=-7,
            weight=15,
            description="Test header",
            remediation=None,
        )],
        total_score=-7,
        max_score=15,
        percentage_score=27.0,
        grade="F",
        risk_level="critical",
        summary={"total": 1, "present": 0, "weak": 0, "misconfigured": 1, "missing": 0},
    )


def test_header_policies_do_not_mark_permissive_values_as_present():
    csp = DEFAULT_HEADER_REGISTRY.get("content-security-policy")
    status, _ = csp.validate("default-src 'none'; script-src *")
    assert status == HeaderStatus.MISCONFIGURED

    permissions = DEFAULT_HEADER_REGISTRY.get("permissions-policy")
    status, _ = permissions.validate("geolocation=*, camera=*, microphone=*")
    assert status == HeaderStatus.WEAK
    status, _ = permissions.validate("geolocation=(), camera=(), microphone=()")
    assert status == HeaderStatus.PRESENT


def test_obsolete_context_specific_headers_are_not_scored_by_default():
    names = {header.name for header in DEFAULT_HEADER_REGISTRY.get_all()}
    assert "x-xss-protection" not in names
    assert "expect-ct" not in names
    assert "x-permitted-cross-domain-policies" not in names
    assert "cache-control" not in names


def test_html_report_escapes_remote_header_and_url_values():
    payload = '<img src=x onerror="alert(1)">'
    report = ReportGenerator().generate(_scan_result(payload, "https://example.com/<script>alert(1)</script>"), "html")
    assert payload not in report
    assert "&lt;img" in report
    assert "&lt;script&gt;" in report


def test_markdown_report_escapes_remote_url_html_and_markdown_syntax():
    payload = '<script>alert(1)</script>[click](javascript:alert(1))'
    report = ReportGenerator().generate(_scan_result(None, "https://example.com/" + payload), "markdown")
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert r"\[click\]" in report


def test_sensitive_url_values_are_redacted_in_reports_and_serialization():
    secret_url = "https://example.com/scan?api_key=top-secret-value&view=full&accessToken=other-secret"
    safe_url = redact_sensitive_url(secret_url)
    result = _scan_result(None, secret_url)
    assert result.url == secret_url  # The actual target stays intact for scanning.
    assert result.to_dict()["url"] == safe_url

    reporter = ReportGenerator()
    for format_type in ("json", "text", "html", "markdown", "csv"):
        report = reporter.generate(result, format_type)
        assert "top-secret-value" not in report
        assert "other-secret" not in report
        if format_type == "json":
            assert json.loads(report)["url"] == safe_url


def test_csv_report_neutralizes_spreadsheet_formulas():
    report = ReportGenerator().generate(_scan_result('=HYPERLINK("https://attacker.test","click")'), "csv")
    value = next(csv.reader(io.StringIO(report)))[0]
    assert value == "Header"
    row = next(csv.reader(io.StringIO(report.splitlines()[1])))
    assert row[4].startswith("'=")


def test_ssl_analyzer_parses_certificate_and_checks_hostname(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_path), str(key_path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_once():
        connection, _ = listener.accept()
        try:
            with server_context.wrap_socket(connection, server_side=True) as tls_socket:
                tls_socket.recv(1)
        except ssl.SSLError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    analyzer = SSLAnalyzer(timeout=3)
    analyzer._verify_certificate_chain = lambda _host, _port: (False, "self-signed test certificate")
    info = analyzer._get_certificate("localhost", port)
    thread.join(timeout=3)

    assert info.public_key_algorithm == "RSA"
    assert info.key_size == 2048
    assert info.hostname_matches is True
    assert info.is_trusted is False
    assert info.is_valid is False
    assert info.is_expired is False
    assert info.is_not_yet_valid is False


def test_scan_result_does_not_persist_unrelated_response_headers(monkeypatch):
    scanner = SecurityHeaderScanner(rate_limit_delay=0)
    response_headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "set-cookie": "session=secret",
        "server": "ExampleServer/1.0",
    }
    monkeypatch.setattr(
        scanner,
        "_get_response_headers",
        lambda url: (200, response_headers, url, None),
    )

    result = scanner.scan("https://example.com")

    assert result.headers_found == {
        "content_security_policy": "default-src 'self'",
        "x_frame_options": "DENY",
    }
    assert "set-cookie" not in result.headers_found
    assert "server" not in result.headers_found
    assert result.cookie_results[0].name == "session"
    assert "secret" not in json.dumps(result.to_dict())


def test_cookie_security_analysis_checks_secure_httponly_and_samesite_without_values():
    scanner = SecurityHeaderScanner(rate_limit_delay=0)
    cookies = scanner._analyze_cookies(
        [
            "sid=highly-sensitive-cookie; Secure; HttpOnly; SameSite=Lax; Path=/",
            "legacy=private-cookie; SameSite=None",
        ]
    )
    assert len(cookies) == 2
    assert cookies[0].name == "sid"
    assert cookies[0].secure is True
    assert cookies[0].http_only is True
    assert cookies[0].same_site == "Lax"
    assert cookies[0].issues == []
    assert cookies[1].issues == [
        "Missing Secure attribute", "Missing HttpOnly attribute", "SameSite=None requires Secure"
    ]
    serialized = json.dumps([cookie.to_dict() for cookie in cookies])
    assert "highly-sensitive-cookie" not in serialized
    assert "private-cookie" not in serialized

    http_cookie = scanner._analyze_cookies(["anon=x"])[0]
    assert "Missing Secure attribute" in http_cookie.issues
    assert "Missing HttpOnly attribute" in http_cookie.issues
    assert "Missing SameSite attribute" in http_cookie.issues


def test_cookie_findings_appear_in_all_report_formats_without_values():
    from src.scanner import CookieResult

    result = dataclasses.replace(
        _scan_result(None),
        cookie_results=[CookieResult(
            name="session-id",
            secure=False,
            http_only=False,
            same_site=None,
            issues=["Missing Secure attribute", "Missing HttpOnly attribute", "Missing SameSite attribute"],
        )],
    )
    for format_type in ("json", "text", "html", "markdown", "csv"):
        report = ReportGenerator().generate(result, format_type)
        assert "session-id" in report
        assert "Missing HttpOnly attribute" in report
        assert "never-persist-this" not in report


def test_api_scanner_pins_socket_destination_and_preserves_host_header():
    observed_hosts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed_hosts.append(self.headers.get("Host"))
            self.send_response(200)
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Set-Cookie", "session=must-not-be-stored")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    resolved = []

    def resolve(host, target_port):
        resolved.append((host, target_port))
        return ("127.0.0.1",)

    scanner = SecurityHeaderScanner(
        timeout=2,
        max_retries=1,
        rate_limit_delay=0,
        follow_redirects=False,
        trust_env=False,
        address_resolver=resolve,
    )
    try:
        result = scanner.scan(f"http://dns-rebinding.invalid:{port}/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert result.error is None
    assert result.http_status_code == 200
    assert resolved == [("dns-rebinding.invalid", port)]
    assert observed_hosts == [f"dns-rebinding.invalid:{port}"]
    assert result.headers_found == {"x_frame_options": "DENY"}
    assert len(result.cookie_results) == 1
    cookie = result.cookie_results[0]
    assert cookie.name == "session"
    assert cookie.issues == [
        "Missing Secure attribute", "Missing HttpOnly attribute", "Missing SameSite attribute"
    ]
    assert "must-not-be-stored" not in json.dumps(result.to_dict())


def test_pinned_https_adapter_verifies_the_original_hostname(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dns-rebinding.test")])
    now = datetime.datetime.utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("dns-rebinding.test")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "pinned-ca.pem"
    key_path = tmp_path / "pinned-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    observed_hosts = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            observed_hosts.append(self.headers.get("Host"))
            body = b"pinned"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_path), str(key_path))
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    session = requests.Session()
    session.trust_env = False
    adapter = PinnedAddressAdapter("dns-rebinding.test", port, ["127.0.0.1"])
    session.mount("https://", adapter)
    try:
        response = session.get(
            f"https://dns-rebinding.test:{port}/",
            verify=str(cert_path),
            timeout=3,
        )
        assert response.status_code == 200
        assert response.text == "pinned"
        response.close()
    finally:
        session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert observed_hosts == [f"dns-rebinding.test:{port}"]


def test_connection_time_dns_rebinding_to_private_ip_is_rejected(monkeypatch):
    responses = iter(("93.184.216.34", "127.0.0.1"))

    def fake_getaddrinfo(host, port, type):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (next(responses), port))]

    monkeypatch.setattr(api_module.socket, "getaddrinfo", fake_getaddrinfo)
    validated_url = validate_scan_target("http://example.com/")
    scanner = SecurityHeaderScanner(
        timeout=1,
        max_retries=1,
        rate_limit_delay=0,
        follow_redirects=False,
        trust_env=False,
        address_resolver=lambda host, port: api_module._resolve_target_addresses(host, port),
    )

    result = scanner.scan(validated_url)

    assert result.error is not None
    assert "Private, loopback, link-local, and reserved targets are disabled" in result.error
    assert result.http_status_code is None


def test_scan_comparison_reports_header_changes_and_rejects_failed_scans():
    old = _scan_result(None)
    old = dataclasses.replace(old, headers_found={}, percentage_score=20.0, grade="F")
    new_header = HeaderResult(
        header_name="x-frame-options",
        display_name="X-Frame-Options",
        status=HeaderStatus.PRESENT,
        value="DENY",
        score=15,
        weight=15,
        description="Test header",
        remediation=None,
    )
    new = dataclasses.replace(
        old,
        headers_found={"x_frame_options": "DENY"},
        header_results=[new_header],
        percentage_score=90.0,
        grade="A",
    )
    scanner = SecurityHeaderScanner()
    comparison = scanner.compare_scans(old, new)
    assert comparison["score_change"] == 70.0
    assert comparison["grade_change"] is True
    assert comparison["grade_from"] == "F"
    assert comparison["grade_to"] == "A"
    assert comparison["headers_improved"] == ["x-frame-options"]
    assert comparison["headers_added"] == ["x-frame-options"]
    assert comparison["headers_removed"] == []

    with pytest.raises(ValueError, match="Failed scans"):
        scanner.compare_scans(dataclasses.replace(old, error="network failure"), new)


def test_configured_risk_thresholds_are_used_by_cli_and_api(tmp_path):
    from src.analyzer import HeaderAnalyzer

    thresholds = {"critical": 0, "high": 20, "medium": 60, "low": 90}
    analyzer = HeaderAnalyzer(thresholds)
    assert analyzer.get_risk_level(85) == "medium"

    config = tmp_path / "config.yaml"
    config.write_text(
        "thresholds:\n  critical: 0\n  high: 20\n  medium: 60\n  low: 90\n"
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    assert app.scanner.analyzer.get_risk_level(85) == "medium"
    assert app.scanner.trust_env is False


def test_audit_score_uses_nested_header_score_and_skips_heuristics():
    results = {
        "headers": {"score": {"percentage": 100.0}},
        "ssl": {"is_reachable": True, "overall_score": 80},
        "fingerprint": {"overall_score": 0},
        "subdomains": {"overall_score": 10},
        "directories": {"overall_score": 20},
    }
    components, overall = main._compute_audit_scores(results)
    assert components == {
        "headers": 100.0,
        "ssl": 80.0,
        "fingerprint": 0.0,
        "subdomains": 10.0,
        "directories": 20.0,
    }
    assert overall == 90.0


def test_audit_score_is_unavailable_when_primary_checks_fail():
    components, overall = main._compute_audit_scores({"headers": {"error": "failed"}, "ssl": {"is_reachable": False}})
    assert components == {}
    assert overall is None


def test_fingerprinter_matches_normalized_header_names_and_values():
    fingerprinter = TechnologyFingerprinter()
    technologies = fingerprinter._analyze_content(
        "",
        {"server": "Apache/2.4.58", "x-powered-by": "PHP/7.4.0"},
        {},
    )
    by_name = {technology.name: technology for technology in technologies}
    assert by_name["Apache"].version is None
    assert by_name["PHP"].version == "7.4.0"
    issues, _ = fingerprinter._analyze_security_findings(technologies, {"x-powered-by": "PHP/7.4.0"})
    assert any("PHP 7.4.0" in issue for issue in issues)


def test_fingerprinter_uses_only_technology_specific_version_evidence():
    fingerprinter = TechnologyFingerprinter()
    unrelated_version = fingerprinter._analyze_content(
        "<script src='/assets/react-dom.js'></script> Version 99.4.3",
        {},
        {},
    )
    react = next(technology for technology in unrelated_version if technology.name == "React")
    assert react.version is None

    versioned_react = fingerprinter._analyze_content("react-dom@17.0.2", {}, {})
    react = next(technology for technology in versioned_react if technology.name == "React")
    assert react.version == "17.0.2"
    issues, _ = fingerprinter._analyze_security_findings(versioned_react, {})
    assert any("React 17.0.2" in issue for issue in issues)


def test_subdomain_scanner_normalizes_domain_and_limits_candidates(monkeypatch):
    scanner = SubdomainScanner()
    captured = {}

    async def fake_scan(base_domain, wordlist):
        captured["base_domain"] = base_domain
        captured["wordlist"] = wordlist
        return []

    monkeypatch.setattr(scanner, "_scan_all_async", fake_scan)
    result = scanner.scan("https://WWW.Example.COM:8443/path", ["Admin", "admin", "www"])
    assert result.domain == "example.com"
    assert captured == {"base_domain": "example.com", "wordlist": ["admin", "www"]}

    invalid = scanner.scan("127.0.0.1")
    assert invalid.total_found == 0
    assert any("IP address" in issue for issue in invalid.issues)
    invalid_word = scanner.scan("example.com", ["admin.attacker.test"])
    assert invalid_word.total_found == 0
    assert any("Invalid subdomain label" in issue for issue in invalid_word.issues)
    oversized = scanner.scan("example.com", ["x"] * (scanner.MAX_WORDLIST_SIZE + 1))
    assert any("limit" in issue for issue in oversized.issues)


def test_subdomain_probes_use_real_http_status_and_all_supported_ports(monkeypatch):
    scanner = SubdomainScanner()

    async def fake_getaddrinfo(self, host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", 0))]

    class FakeResponse:
        status = 404

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return False

    class FakeSession:
        def __init__(self):
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append((url, kwargs))
            return FakeResponse()

    fake_session = FakeSession()
    scanner.session = fake_session
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)
    result = asyncio.run(scanner._check_subdomain_async("www", "example.com"))

    assert result.is_alive
    assert result.ip_address == "203.0.113.9"
    assert result.http_status == 404
    assert result.has_https
    assert result.services == ["HTTP", "HTTPS", "HTTP:8080", "HTTPS:8443"]
    assert len(fake_session.urls) == len(scanner.COMMON_PORTS)


def test_directory_scanner_normalizes_urls_and_rejects_unsafe_schemes():
    with pytest.raises(ValueError, match="printable string"):
        DirectoryScanner(user_agent="scanner\r\nInjected: yes")
    assert DirectoryScanner._normalize_base_url(
        "example.com/app/?token=ignored#fragment"
    ) == "https://example.com/app"
    with pytest.raises(ValueError):
        DirectoryScanner._normalize_base_url("ftp://example.com")
    with pytest.raises(ValueError):
        DirectoryScanner._normalize_base_url("https://user:pass@example.com")

    result = DirectoryScanner().scan("javascript:alert(1)")
    assert result.scanned_paths == 0
    assert result.issues


def test_directory_scanner_does_not_flag_forbidden_paths_and_bounds_body(monkeypatch):
    scanner = DirectoryScanner(max_workers=1)
    scanner.SENSITIVE_PATHS = {"/.env": "Environment variables"}
    scanner.COMMON_DIRECTORIES = []
    scanner.max_response_bytes = 8
    status = {"value": 403}
    progress = []

    class FakeResponse:
        headers = {"Content-Type": "application/octet-stream"}
        encoding = "utf-8"

        def __init__(self, status_code):
            self.status_code = status_code

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def iter_content(self, chunk_size):
            yield b"0123456789abcdef"

    class FakeSession:
        headers = {}

        def get(self, url, **kwargs):
            assert kwargs["stream"] is True
            status_code = 404 if "__scanner_missing_" in url else status["value"]
            return FakeResponse(status_code)

    scanner.session = FakeSession()
    forbidden = scanner.scan("https://example.com", check_directories=False, progress_callback=lambda done, total: progress.append((done, total)))
    assert forbidden.scanned_paths == 1
    assert forbidden.found_paths == 1
    assert forbidden.sensitive_paths == []
    assert forbidden.to_dict()["sensitive_paths"] == []
    assert progress == [(1, 1)]

    status["value"] = 200
    exposed = scanner.scan("https://example.com", check_directories=False)
    assert exposed.sensitive_paths[0].is_sensitive
    assert exposed.sensitive_paths[0].content_length == 8


def test_directory_scanner_suppresses_single_page_catch_all_responses():
    scanner = DirectoryScanner(max_workers=1)
    scanner.SENSITIVE_PATHS = {}
    scanner.COMMON_DIRECTORIES = ["index"]

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        encoding = "utf-8"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def iter_content(self, chunk_size):
            yield b"<html>app shell</html>"

    class FakeSession:
        headers = {}

        def get(self, *args, **kwargs):
            return FakeResponse()

    scanner.session = FakeSession()
    result = scanner.scan("example.com", check_sensitive=False, check_directories=True)
    assert result.scanned_paths == 1
    assert result.found_paths == 0


def test_scan_ids_use_full_uuid_entropy():
    generated = {generate_id() for _ in range(1000)}
    assert len(generated) == 1000
    assert all(len(scan_id) == 36 for scan_id in generated)


def test_json_storage_serializes_concurrent_index_updates(tmp_path):
    storage_path = tmp_path / "json-store"
    first = JSONStorage(storage_path, max_history=100, auto_cleanup_days=None)
    second = JSONStorage(storage_path, max_history=100, auto_cleanup_days=None)
    base_time = datetime.datetime.now().replace(microsecond=0)

    def save_one(index):
        result = dataclasses.replace(
            _scan_result(None),
            id=f"id{index:06d}",
            timestamp=(base_time + datetime.timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S"),
        )
        return (first if index % 2 else second).save(result)

    with ThreadPoolExecutor(max_workers=8) as executor:
        assert all(executor.map(save_one, range(40)))
    loaded = JSONStorage(storage_path, max_history=100, auto_cleanup_days=None).get_all(100)
    assert len(loaded) == 40
    assert len({result.id for result in loaded}) == 40


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode assertions")
def test_storage_files_are_private_on_posix(tmp_path):
    json_path = tmp_path / "private-json"
    json_store = JSONStorage(json_path, auto_cleanup_days=None)
    result = _scan_result(None)
    assert json_store.save(result)
    json_modes = {
        "directory": stat.S_IMODE(json_path.stat().st_mode),
        "index": stat.S_IMODE((json_path / "index.json").stat().st_mode),
        "lock": stat.S_IMODE((json_path / ".storage.lock").stat().st_mode),
        "scan": stat.S_IMODE((json_path / f"{result.id}.json").stat().st_mode),
    }
    assert json_modes == {"directory": 0o700, "index": 0o600, "lock": 0o600, "scan": 0o600}

    sqlite_path = tmp_path / "private-sqlite.db"
    sqlite_store = SQLiteStorage(sqlite_path, auto_cleanup_days=None)
    assert sqlite_store.save(result)
    assert stat.S_IMODE(sqlite_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("storage_kind", ["json", "sqlite"])
def test_storage_redacts_urls_and_preserves_history_lookup(tmp_path, storage_kind):
    secret_url = "https://example.com/path?token=very-secret-value&mode=full"
    result = dataclasses.replace(
        _scan_result(None, secret_url),
        id="secret-scan-01",
        error=f"request failed for {secret_url}",
    )
    if storage_kind == "json":
        store = JSONStorage(tmp_path / "redacted-json", max_history=None, auto_cleanup_days=None)
    else:
        store = SQLiteStorage(tmp_path / "redacted-sqlite.db", max_history=None, auto_cleanup_days=None)

    assert store.save(result)
    assert len(store.get_by_url(secret_url.upper())) == 1
    loaded = store.get(result.id)
    assert loaded is not None
    assert loaded.url == redact_sensitive_url(secret_url)
    assert "very-secret-value" not in json.dumps(loaded.to_dict())

    persisted = b"".join(path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    assert b"very-secret-value" not in persisted
    assert b"token=very-secret-value" not in persisted


def test_storage_migrates_legacy_persisted_secret_urls(tmp_path):
    secret_url = "https://example.com/path?token=legacy-secret-value"
    result = dataclasses.replace(
        _scan_result(None, secret_url),
        id="legacy-secret-01",
        error=f"legacy failure: {secret_url}",
    )
    legacy_data = result.to_dict()
    legacy_data["url"] = secret_url
    legacy_data["final_url"] = secret_url
    legacy_data["error"] = result.error

    json_path = tmp_path / "legacy-json"
    json_path.mkdir()
    (json_path / f"{result.id}.json").write_text(json.dumps(legacy_data), encoding="utf-8")
    (json_path / "index.json").write_text(json.dumps({result.id: {
        "url": secret_url,
        "timestamp": result.timestamp,
        "percentage_score": result.percentage_score,
        "grade": result.grade,
        "file": f"{result.id}.json",
        "saved_at_ns": 1,
    }}), encoding="utf-8")
    json_store = JSONStorage(json_path, max_history=None, auto_cleanup_days=None)
    assert "legacy-secret-value" not in (json_path / "index.json").read_text(encoding="utf-8")
    assert len(json_store.get_by_url(secret_url)) == 1
    assert "legacy-secret-value" not in (json_path / f"{result.id}.json").read_text(encoding="utf-8")

    sqlite_path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(str(sqlite_path))
    connection.execute("""
        CREATE TABLE scans (
            id TEXT PRIMARY KEY, url TEXT NOT NULL, timestamp TEXT NOT NULL,
            scan_duration_ms REAL, http_status_code INTEGER, final_url TEXT,
            headers_found TEXT, total_score INTEGER, max_score INTEGER,
            percentage_score REAL, grade TEXT, risk_level TEXT, summary TEXT,
            error TEXT, scan_data TEXT
        )
    """)
    connection.execute("""
        INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result.id, secret_url, result.timestamp, result.scan_duration_ms,
        result.http_status_code, secret_url, json.dumps(result.headers_found),
        result.total_score, result.max_score, result.percentage_score, result.grade,
        result.risk_level, json.dumps(result.summary), result.error, json.dumps(legacy_data),
    ))
    connection.commit()
    connection.close()

    sqlite_store = SQLiteStorage(sqlite_path, max_history=None, auto_cleanup_days=None)
    assert len(sqlite_store.get_by_url(secret_url)) == 1
    assert b"legacy-secret-value" not in sqlite_path.read_bytes()
    row = sqlite3.connect(str(sqlite_path)).execute(
        "SELECT url, final_url, error, scan_data, url_lookup_key FROM scans WHERE id = ?",
        (result.id,),
    ).fetchone()
    assert row[0] == redact_sensitive_url(secret_url)
    assert row[1] == redact_sensitive_url(secret_url)
    assert "legacy-secret-value" not in (row[2] or "") + row[3]
    assert row[4]


def test_storage_retention_tie_breaks_choose_latest_insertions(tmp_path):
    timestamp = "2026-01-01 00:00:00"
    for storage_class, path in (
        (JSONStorage, tmp_path / "json-ties"),
        (SQLiteStorage, tmp_path / "sqlite-ties.db"),
    ):
        store = storage_class(path, max_history=2, auto_cleanup_days=None)
        for index in range(4):
            result = dataclasses.replace(
                _scan_result(None),
                id=f"tie{index:04d}",
                timestamp=timestamp,
            )
            assert store.save(result)
        assert [result.id for result in store.get_all(10)] == ["tie0003", "tie0002"]


def test_storage_retention_limits_json_and_sqlite_and_honors_directory_path(tmp_path):
    now = datetime.datetime.now().replace(microsecond=0)
    json_store = JSONStorage(tmp_path / "json-retention", max_history=2, auto_cleanup_days=None)
    for index in range(3):
        result = dataclasses.replace(
            _scan_result(None),
            id=f"keep{index:04d}",
            timestamp=(now + datetime.timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S"),
        )
        assert json_store.save(result)
    assert [result.id for result in json_store.get_all(10)] == ["keep0002", "keep0001"]
    assert json_store.get("../index") is None

    sqlite_store = get_storage(
        "sqlite", str(tmp_path / "sqlite-directory"), max_history=2, auto_cleanup_days=None
    )
    assert isinstance(sqlite_store, SQLiteStorage)
    assert sqlite_store.storage_path == tmp_path / "sqlite-directory" / "scans.db"
    for index in range(3):
        result = dataclasses.replace(
            _scan_result(None),
            id=f"sql{index:05d}",
            timestamp=(now + datetime.timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S"),
        )
        assert sqlite_store.save(result)
    assert [result.id for result in sqlite_store.get_all(10)] == ["sql00002", "sql00001"]
    assert sqlite_store.get("../index") is None


@pytest.mark.parametrize(
    "url",
    [None, "", "ftp://example.com", "https://user:pass@example.com", "http://example.com:0", "https://example.com\ninvalid", "https://example.com/\x7f"],
)
def test_http_url_normalizer_rejects_invalid_inputs(url):
    with pytest.raises(ValueError):
        normalize_http_url(url)


def test_http_url_normalizer_canonicalizes_scheme_host_and_fragment():
    assert normalize_http_url(" BÜCHER.Example/path#section ") == "https://xn--bcher-kva.example/path"
    assert normalize_http_url("//example.com") == "https://example.com"


@pytest.mark.parametrize(
    "yaml_content",
    [
        "scanner:\n  max_retries: 0\n",
        "api:\n  port: 70000\n",
        "api:\n  cors_origins: ['*']\n",
        "storage:\n  type: unknown\n",
        "api:\n  max_request_bytes: false\n",
        "api:\n  allowed_hosts: ['https://example.com']\n",
        "api:\n  allowed_cidrs: ['192.0.2.1/99']\n",
        "api:\n  allowed_ports: [0]\n",
        "api:\n  trusted_proxy_hops: -1\n",
        "api:\n  rate_limit_backend: external\n",
        "api:\n  debug: true\n",
    ],
)
def test_config_loader_rejects_invalid_boundaries(tmp_path, yaml_content):
    config = tmp_path / "invalid.yaml"
    config.write_text(yaml_content, encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(config))


def test_config_loader_reports_malformed_yaml_instead_of_silently_defaulting(tmp_path):
    config = tmp_path / "malformed.yaml"
    config.write_text("scanner: [", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(str(config))


def test_scanner_components_reject_unsafe_configuration_values():
    with pytest.raises(ValueError):
        SecurityHeaderScanner(max_retries=0)
    with pytest.raises(ValueError):
        SecurityHeaderScanner(timeout=float("inf"))
    with pytest.raises(ValueError):
        TechnologyFingerprinter(max_response_bytes=0)
    with pytest.raises(ValueError):
        SubdomainScanner(max_concurrent=0)
    with pytest.raises(ValueError):
        DirectoryScanner(max_workers=0)
    with pytest.raises(ValueError):
        SSLAnalyzer(timeout=0)


def test_api_app_passes_storage_retention_configuration(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n"
        "  type: sqlite\n"
        "  path: " + str(tmp_path / "configured-db") + "\n"
        "  max_history: 7\n"
        "  auto_cleanup_days: null\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    assert isinstance(app.storage, SQLiteStorage)
    assert app.storage.max_history == 7
    assert app.storage.auto_cleanup_days is None
    assert app.storage.storage_path == tmp_path / "configured-db" / "scans.db"


def test_storage_applies_configured_age_retention(tmp_path):
    storage = JSONStorage(tmp_path / "age-retention", max_history=None, auto_cleanup_days=30)
    old = dataclasses.replace(_scan_result(None), id="oldscan1", timestamp="2020-01-01 00:00:00")
    assert storage.save(old)
    assert storage.get(old.id) is None


def test_cvss_v31_known_vector_and_unset_metrics():
    calculator = CVSSCalculator()
    score = calculator.calculate_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert score.base_score == 9.8
    assert score.temporal_score is None
    assert score.environmental_score is None
    assert score.to_dict()["temporal_score"] is None

    changed_scope = calculator.calculate_from_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    )
    assert changed_scope.base_score == 10.0


def test_cvss_rejects_incomplete_wrong_version_and_unsupported_vectors():
    calculator = CVSSCalculator()
    with pytest.raises(ValueError):
        calculator.calculate_from_vector("CVSS:3.1/AV:N")
    with pytest.raises(ValueError):
        calculator.calculate_from_vector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    with pytest.raises(ValueError):
        calculator.calculate_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F"
        )
    with pytest.raises(ValueError, match="256 characters"):
        calculator.calculate_from_vector("CVSS:3.1/" + "A" * 257)


def test_api_target_validation_blocks_private_and_unsafe_urls():
    with pytest.raises(ValueError):
        validate_scan_target("http://127.0.0.1/admin")
    with pytest.raises(ValueError):
        validate_scan_target("file:///etc/passwd")
    with pytest.raises(ValueError):
        validate_scan_target("https://user:pass@example.com/")
    with pytest.raises(ValueError):
        validate_scan_target("https://example.com/" + "x" * 2049)


def test_api_target_validation_resolves_and_allows_public_targets(monkeypatch):
    monkeypatch.setattr(
        "src.api.socket.getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ],
    )
    assert validate_scan_target("https://example.com/") == "https://example.com/"


def test_api_target_policy_enforces_host_cidr_and_port_allowlists(monkeypatch):
    monkeypatch.setattr(
        "src.api.socket.getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ],
    )
    assert validate_scan_target(
        "https://api.example.com/",
        allowed_hosts=["*.example.com"],
        allowed_cidrs=["93.184.216.0/24"],
    ) == "https://api.example.com/"
    assert validate_scan_target(
        "https://example.com/",
        allowed_cidrs=["93.184.216.0/24"],
    ) == "https://example.com/"

    with pytest.raises(ValueError, match="allowed_hosts"):
        validate_scan_target("https://example.com/", allowed_hosts=["*.example.com"])
    with pytest.raises(ValueError, match="allowed_hosts"):
        validate_scan_target("https://badexample.com/", allowed_hosts=["*.example.com"])
    with pytest.raises(ValueError, match="allowed_cidrs"):
        validate_scan_target("https://example.com/", allowed_cidrs=["93.184.217.0/24"])
    with pytest.raises(ValueError, match="allowed_ports"):
        validate_scan_target("https://example.com:8443/")
    assert validate_scan_target(
        "https://example.com:8443/", allowed_ports=[443, 8443]
    ) == "https://example.com:8443/"


def test_api_scan_routes_enforce_destination_scope_configuration(tmp_path, monkeypatch):
    config = tmp_path / "scoped-api.yaml"
    config.write_text(
        f"""api:
  allowed_hosts: ['*.scope.example']
  allowed_cidrs: ['93.184.216.0/24']
  allowed_ports: [8443]
storage:
  type: json
  path: {tmp_path / 'data'}
""",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"scanner": "scan-secret"}
    monkeypatch.setattr(
        api_module.socket,
        "getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ],
    )
    scanned = []

    def fake_scan(url):
        scanned.append(url)
        return dataclasses.replace(_scan_result(None, url), id="scoped-target-01")

    monkeypatch.setattr(app.scanner, "scan", fake_scan)
    monkeypatch.setattr(app.storage, "save", lambda result: True)
    client = app.test_client()
    headers = {"Authorization": "Bearer scan-secret"}

    allowed = client.post(
        "/api/v1/scan",
        json={"url": "https://api.scope.example:8443/"},
        headers=headers,
    )
    assert allowed.status_code == 200
    assert scanned == ["https://api.scope.example:8443/"]

    for url in ("https://scope.example:8443/", "https://api.scope.example:443/"):
        denied = client.post("/api/v1/scan", json={"url": url}, headers=headers)
        assert denied.status_code == 400
    assert scanned == ["https://api.scope.example:8443/"]


def test_config_normalizes_api_destination_allowlists(tmp_path):
    config = tmp_path / "targets.yaml"
    config.write_text(
        "api:\n"
        "  allowed_hosts: ['*.BÜCHER.example', 'example.com']\n"
        "  allowed_cidrs: ['93.184.216.7/24', '2001:db8::1/64']\n"
        "  allowed_ports: [443, 8443, 443]\n",
        encoding="utf-8",
    )
    loaded = load_config(str(config))
    assert loaded["api"]["allowed_hosts"] == ["*.xn--bcher-kva.example", "example.com"]
    assert loaded["api"]["allowed_cidrs"] == ["2001:db8::/64", "93.184.216.0/24"]
    assert loaded["api"]["allowed_ports"] == [443, 8443]


@pytest.mark.parametrize("days", [-1, 0, 3651, True, "30", 1.5])
def test_cleanup_rejects_invalid_retention_periods(tmp_path, days):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"admin": "admin-secret"}
    response = app.test_client().post(
        "/api/v1/cleanup", json={"days": days},
        headers={"Authorization": "Bearer admin-secret"},
    )
    assert response.status_code == 400


def test_report_api_rejects_server_file_paths(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"reader": "read-secret"}
    output_path = tmp_path / "outside" / "report.html"
    response = app.test_client().post(
        "/api/v1/report",
        json={"scan_id": "arbitrary", "format": "html", "output_path": str(output_path)},
        headers={"Authorization": "Bearer read-secret"},
    )
    assert response.status_code == 400
    assert not output_path.exists()


def test_api_allows_only_configured_cors_preflight_origins(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "api:\n  cors_origins:\n    - https://ui.example\n"
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    headers = {
        "Origin": "https://ui.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    response = app.test_client().options("/api/v1/scan", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "https://ui.example"


def test_api_enforces_configured_scan_rate_limit(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "api:\n  max_urls_per_minute: 1\n"
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"scanner": "scan-secret"}
    result = _scan_result("DENY")
    monkeypatch.setattr(api_module, "validate_scan_target", lambda url, **kwargs: url)
    monkeypatch.setattr(app.scanner, "scan", lambda url: result)
    monkeypatch.setattr(app.storage, "save", lambda scan: None)
    headers = {"Authorization": "Bearer scan-secret"}
    client = app.test_client()

    assert client.post("/api/v1/scan", json={"url": "https://one.example"}, headers=headers).status_code == 200
    limited = client.post("/api/v1/scan", json={"url": "https://two.example"}, headers=headers)
    assert limited.status_code == 429
    assert limited.headers["Retry-After"]


def test_api_uses_waitress_instead_of_flask_development_server(monkeypatch):
    from types import SimpleNamespace
    import waitress

    fake_app = SimpleNamespace(config={"api": {"host": "127.0.0.1", "port": 5500, "threads": 6}})
    calls = []
    monkeypatch.setattr(api_module, "create_app", lambda: fake_app)
    monkeypatch.setattr(waitress, "serve", lambda app, **kwargs: calls.append((app, kwargs)))

    api_module.run_server()
    assert calls == [(fake_app, {"host": "127.0.0.1", "port": 5500, "threads": 6})]
    with pytest.raises(ValueError, match="does not support debug"):
        api_module.run_server(debug=True)


def test_api_trusts_forwarded_client_ip_only_for_configured_proxy_hops(tmp_path):
    def make_app(path, hops):
        config = tmp_path / path
        config.write_text(
            f"""api:
  trusted_proxy_hops: {hops}
storage:
  type: json
  path: {tmp_path / (path + '-data')}
""",
            encoding="utf-8",
        )
        return create_app(str(config))

    trusted_app = make_app("trusted-proxy.yaml", 1)
    trusted_addresses = []
    trusted_app.before_request(lambda: trusted_addresses.append(api_module.request.remote_addr)
                               if api_module.request.endpoint == "health_check" else None)
    assert trusted_app.test_client().get(
        "/api/v1/health", headers={"X-Forwarded-For": "198.51.100.24"}
    ).status_code == 200
    assert trusted_addresses == ["198.51.100.24"]

    direct_app = make_app("direct.yaml", 0)
    direct_addresses = []
    direct_app.before_request(lambda: direct_addresses.append(api_module.request.remote_addr)
                              if api_module.request.endpoint == "health_check" else None)
    direct_app.test_client().get(
        "/api/v1/health", headers={"X-Forwarded-For": "198.51.100.24"}
    )
    assert direct_addresses == ["127.0.0.1"]

def test_api_redis_rate_limit_backend_requires_and_checks_shared_store(tmp_path, monkeypatch):
    import redis
    from src.rate_limit import RedisRateLimiter

    config = tmp_path / "redis.yaml"
    config.write_text(
        f"""api:
  rate_limit_backend: redis
storage:
  type: json
  path: {tmp_path / 'data'}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SECURITY_SCANNER_REDIS_URL", "redis://:not-logged@cache.example:6379/0")

    class RedisStub:
        def __init__(self):
            self.pinged = False

        def ping(self):
            self.pinged = True

    client = RedisStub()
    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kwargs: client))
    app = create_app(str(config))
    assert isinstance(app.extensions["scanner_rate_limiter"], RedisRateLimiter)
    assert app.extensions["scanner_rate_limiter"].redis is client
    assert client.pinged

    class UnavailableRedis:
        def ping(self):
            raise OSError("offline")

    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url, **kwargs: UnavailableRedis()))
    with pytest.raises(ValueError, match="failed closed"):
        create_app(str(config))

def test_api_enforces_request_size_and_history_limit_bounds(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "api:\n  max_request_bytes: 128\n"
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"scanner": "scan-secret", "reader": "read-secret"}
    headers = {"Authorization": "Bearer scan-secret", "Content-Type": "application/json"}
    large_payload = '{"url":"https://' + ("a" * 256) + '.example"}'
    too_large = app.test_client().post("/api/v1/scan", data=large_payload, headers=headers)
    assert too_large.status_code == 413
    assert too_large.is_json

    invalid_limit = app.test_client().get(
        "/api/v1/history?limit=-1", headers={"Authorization": "Bearer read-secret"}
    )
    assert invalid_limit.status_code == 400


def test_api_report_formats_and_scan_role_are_consistent(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"reader": "read-secret", "scanner": "scan-secret"}
    result = _scan_result("DENY")
    monkeypatch.setattr(api_module, "validate_scan_target", lambda url, **kwargs: url)
    monkeypatch.setattr(app.scanner, "scan", lambda url: result)
    monkeypatch.setattr(app.storage, "save", lambda scan: None)
    monkeypatch.setattr(app.storage, "get", lambda scan_id: result)
    client = app.test_client()

    reader_headers = {"Authorization": "Bearer read-secret"}
    scanner_headers = {"Authorization": "Bearer scan-secret"}
    assert client.get(
        "/api/v1/scan?url=https://example.com", headers=reader_headers
    ).status_code == 403

    html_response = client.post(
        "/api/v1/scan?format=html", json={"url": "https://example.com"}, headers=scanner_headers
    )
    assert html_response.status_code == 200
    assert html_response.mimetype == "text/html"

    csv_response = client.post(
        "/api/v1/report", json={"scan_id": result.id, "format": "csv"}, headers=reader_headers
    )
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"

    assert client.post(
        "/api/v1/scan?format=xml", json={"url": "https://example.com"}, headers=scanner_headers
    ).status_code == 400
    assert client.post(
        "/api/v1/scan", data="not-json", content_type="text/plain", headers=scanner_headers
    ).status_code == 400


def test_api_scan_responses_and_errors_redact_query_secrets_without_altering_target(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"scanner": "scan-secret"}
    monkeypatch.setattr(api_module, "validate_scan_target", lambda url, **kwargs: url)
    targets = []
    success_url = "https://example.com/check?api_key=response-secret"
    error_url = "https://example.com/fail?access_token=error-secret"

    def fake_scan(url):
        targets.append(url)
        result = dataclasses.replace(_scan_result(None, url), id="scan-" + str(len(targets)))
        if "/fail" in url:
            result.error = f"request failed for {url}"
        return result

    monkeypatch.setattr(app.scanner, "scan", fake_scan)
    headers = {"Authorization": "Bearer scan-secret"}
    client = app.test_client()
    success = client.post("/api/v1/scan", json={"url": success_url}, headers=headers)
    assert success.status_code == 200
    assert success.json["url"] == redact_sensitive_url(success_url)
    assert "response-secret" not in success.get_data(as_text=True)

    failed = client.post("/api/v1/scan", json={"url": error_url}, headers=headers)
    assert failed.status_code == 500
    assert failed.json["url"] == redact_sensitive_url(error_url)
    assert "error-secret" not in failed.get_data(as_text=True)
    assert "response-secret" not in failed.get_data(as_text=True)
    assert targets == [success_url, error_url]


def test_batch_api_validates_all_targets_before_scanning(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    app.config["API_TOKENS"] = {"scanner": "scan-secret"}
    calls = []

    def fake_validate(url, **kwargs):
        if "127.0.0.1" in url:
            raise ValueError("private target rejected")
        return url

    monkeypatch.setattr(api_module, "validate_scan_target", fake_validate)
    monkeypatch.setattr(app.scanner, "batch_scan", lambda urls: calls.append(urls) or [])
    response = app.test_client().post(
        "/api/v1/batch",
        json={"urls": ["https://public.example", "http://127.0.0.1"]},
        headers={"Authorization": "Bearer scan-secret"},
    )
    assert response.status_code == 400
    assert calls == []


def test_api_rejects_weak_or_reused_environment_tokens(monkeypatch):
    monkeypatch.setenv("SECURITY_SCANNER_API_TOKEN", "short")
    monkeypatch.delenv("SECURITY_SCANNER_READ_TOKEN", raising=False)
    monkeypatch.delenv("SECURITY_SCANNER_ADMIN_TOKEN", raising=False)
    with pytest.raises(ValueError, match="32-512 printable ASCII"):
        api_module._load_api_tokens()

    monkeypatch.setenv("SECURITY_SCANNER_API_TOKEN", "x" * 31 + "é")
    with pytest.raises(ValueError, match="printable ASCII"):
        api_module._load_api_tokens()

    shared = "x" * 40
    monkeypatch.setenv("SECURITY_SCANNER_API_TOKEN", shared)
    monkeypatch.setenv("SECURITY_SCANNER_READ_TOKEN", shared)
    with pytest.raises(ValueError, match="distinct"):
        api_module._load_api_tokens()


def test_api_requires_role_token_and_protects_scan_route(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "storage:\n  type: json\n  path: " + str(tmp_path / "data") + "\n",
        encoding="utf-8",
    )
    app = create_app(str(config))
    app.testing = True
    client = app.test_client()

    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/history").status_code == 503

    app.config["API_TOKENS"] = {"reader": "read-secret", "scanner": "scan-secret", "admin": "admin-secret"}
    assert client.get("/api/v1/history").status_code == 401
    assert client.get(
        "/api/v1/scan?url=https://example.com",
        headers={"Authorization": "Bearer read-secret"},
    ).status_code == 403
    assert client.post(
        "/api/v1/scan", json={"url": "https://example.com"},
        headers={"Authorization": "Bearer read-secret"},
    ).status_code == 403
