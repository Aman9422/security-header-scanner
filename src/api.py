"""
REST API Module
~~~~~~~~~~~~~~~

Flask-based REST API for the security header scanner.
"""

import hmac
import ipaddress
import os
import socket
import threading
import time
from typing import Dict, Any, Optional
from urllib.parse import urlsplit

from flask import Flask, request, jsonify, Response, g
from flask_cors import CORS
from .config import load_config
from .scanner import SecurityHeaderScanner
from .analyzer import HeaderAnalyzer
from .reporter import ReportGenerator
from .storage import get_storage
from .utils import normalize_http_url


def create_app(config_path: Optional[str] = None) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)

    # Load configuration before enabling any browser access. CORS is denied by
    # default and should only be enabled for explicitly trusted frontends.
    config = _load_config(config_path)
    api_config = config.get("api", {})
    app.config.update(config)
    app.config["MAX_CONTENT_LENGTH"] = api_config.get("max_request_bytes", 1_048_576)
    app.config["API_TOKENS"] = _load_api_tokens()
    app.extensions["scanner_rate_buckets"] = {}
    app.extensions["scanner_rate_lock"] = threading.Lock()
    origins = api_config.get("cors_origins", [])
    if origins:
        CORS(app, origins=origins, supports_credentials=False)
    
    # Initialize components
    storage_config = config.get("storage", {})
    storage = get_storage(
        storage_config.get("type", "json"),
        storage_config.get("path", "./data"),
        max_history=storage_config.get("max_history", 1000),
        auto_cleanup_days=storage_config.get("auto_cleanup_days", 30),
    )
    scanner = SecurityHeaderScanner(
        timeout=config.get("scanner", {}).get("timeout", 30),
        max_retries=config.get("scanner", {}).get("max_retries", 3),
        rate_limit_delay=config["scanner"]["rate_limit_delay"],
        max_batch_size=config["scanner"]["max_batch_size"],
        user_agent=config["scanner"]["user_agent"],
        analyzer=HeaderAnalyzer(config["thresholds"]),
        # Re-resolve and validate at request time, then pin the actual socket
        # connection to those addresses. Redirects and ambient proxies are off.
        follow_redirects=False,
        trust_env=False,
        address_resolver=lambda host, port: _resolve_target_addresses(
            host, port, api_config["allow_private_networks"]
        ),
    )
    reporter = ReportGenerator()
    
    # Store in app context
    app.scanner = scanner
    app.storage = storage
    app.reporter = reporter
    app.config.update(config)
    
    # Register routes
    _register_routes(app)
    
    return app


def _load_config(config_path: Optional[str]) -> Dict[str, Any]:
    """Load and validate shared configuration; malformed files fail closed."""
    return load_config(config_path)


API_ROLE_RANK = {"reader": 1, "scanner": 2, "admin": 3}
REPORT_FORMAT_MIMETYPES = {
    "text": "text/plain",
    "json": "application/json",
    "html": "text/html",
    "markdown": "text/markdown",
    "csv": "text/csv",
}


def _parse_history_limit(default: int):
    raw_limit = request.args.get("limit")
    if raw_limit is None:
        return default
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        return None
    return limit if 1 <= limit <= 500 else None


def _report_response(app: Flask, result: Any, format_type: str):
    if format_type == "json":
        return jsonify(result.to_dict())
    report = app.reporter.generate(result, format_type)
    return Response(report, mimetype=REPORT_FORMAT_MIMETYPES[format_type])


def _load_api_tokens() -> Dict[str, str]:
    """Load role-specific bearer tokens from the process environment."""
    tokens = {
        "reader": os.environ.get("SECURITY_SCANNER_READ_TOKEN", "").strip(),
        "scanner": os.environ.get("SECURITY_SCANNER_API_TOKEN", "").strip(),
        "admin": os.environ.get("SECURITY_SCANNER_ADMIN_TOKEN", "").strip(),
    }
    active_tokens = [token for token in tokens.values() if token]
    if any(
        len(token) < 32
        or len(token) > 512
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
        for token in active_tokens
    ):
        raise ValueError("Configured API bearer tokens must be 32-512 printable ASCII characters")
    if len(set(active_tokens)) != len(active_tokens):
        raise ValueError("Reader, scanner, and admin API tokens must be distinct")
    return {role: token for role, token in tokens.items() if token}


def _resolve_target_addresses(host: str, port: int, allow_private_networks: bool = False):
    """Resolve a host once and return only addresses allowed by SSRF policy."""
    if not isinstance(allow_private_networks, bool):
        raise ValueError("allow_private_networks must be a boolean")
    if not isinstance(host, str) or not host or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Target hostname and port are invalid")
    try:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise ValueError("Target hostname could not be resolved") from exc

    addresses = list(dict.fromkeys(addresses))
    if not addresses:
        raise ValueError("Target hostname has no usable address")

    def is_global(address):
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return address.is_global

    if not allow_private_networks and any(not is_global(address) for address in addresses):
        raise ValueError("Private, loopback, link-local, and reserved targets are disabled")
    return tuple(str(address) for address in addresses)


def validate_scan_target(url: Any, allow_private_networks: bool = False) -> str:
    """Canonicalize an API target and reject local/private destinations by default.

    DNS answers are checked here and again immediately before a request; the HTTP
    transport pins its socket destination to that validated answer. Redirects and
    ambient proxies are disabled as additional SSRF defenses.
    """
    if not isinstance(allow_private_networks, bool):
        raise ValueError("allow_private_networks must be a boolean")
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ValueError("URL must be a non-empty string of at most 2048 characters")
    if any(ord(ch) < 32 for ch in url):
        raise ValueError("URL contains control characters")
    try:
        parsed_input = urlsplit(url.strip())
    except ValueError as exc:
        raise ValueError("URL is invalid") from exc
    if parsed_input.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are allowed")

    try:
        normalized_url = normalize_http_url(url)
        parsed = urlsplit(normalized_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    host = parsed.hostname
    if not host:
        raise ValueError("URL must include a hostname")
    _resolve_target_addresses(host, port, allow_private_networks)
    return normalized_url


def _deep_merge(base: Dict, update: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = base.copy()
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _register_routes(app: Flask):
    """Register API routes and enforce bearer-token role checks."""
    
    @app.before_request
    def authorize_request():
        endpoint = request.endpoint
        # CORS preflight is side-effect-free; the actual request still passes
        # through bearer-token and role checks.
        if request.method == "OPTIONS" or endpoint in {None, "health_check"}:
            return None

        tokens = app.config.get("API_TOKENS", {})
        if not tokens:
            return jsonify({"error": "API authentication is not configured"}), 503

        authorization = request.headers.get("Authorization", "")
        scheme, _, supplied_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not supplied_token:
            return jsonify({"error": "Bearer token required"}), 401
        if not supplied_token.isascii():
            return jsonify({"error": "Invalid bearer token"}), 401

        role = None
        for token_role, configured_token in tokens.items():
            if configured_token and hmac.compare_digest(supplied_token, configured_token):
                role = token_role
                break
        if role not in API_ROLE_RANK:
            return jsonify({"error": "Invalid bearer token"}), 401

        required_role = "reader"
        if endpoint == "cleanup_storage":
            required_role = "admin"
        elif endpoint == "scan_url" or (endpoint == "batch_scan" and request.method == "POST"):
            required_role = "scanner"
        if API_ROLE_RANK[role] < API_ROLE_RANK[required_role]:
            return jsonify({"error": "Insufficient role"}), 403

        g.api_role = role
        scanning_request = endpoint == "scan_url" or (endpoint == "batch_scan" and request.method == "POST")
        if scanning_request:
            api_config = app.config.get("api", {})
            limit = api_config["max_urls_per_minute"]
            cost = 1
            if endpoint == "batch_scan":
                payload = request.get_json(silent=True)
                urls = payload.get("urls") if isinstance(payload, dict) else None
                if isinstance(urls, list):
                    cost = max(1, len(urls))
            if cost > limit:
                return jsonify({"error": "Rate limit exceeded", "limit": limit}), 429, {"Retry-After": "60"}

            now = time.monotonic()
            cutoff = now - 60
            key = request.remote_addr or "unknown"
            buckets = app.extensions["scanner_rate_buckets"]
            with app.extensions["scanner_rate_lock"]:
                for bucket_key, entries in list(buckets.items()):
                    active = [(stamp, amount) for stamp, amount in entries if stamp > cutoff]
                    if active:
                        buckets[bucket_key] = active
                    else:
                        buckets.pop(bucket_key, None)
                entries = buckets.setdefault(key, [])
                used = sum(amount for _, amount in entries)
                if used + cost > limit:
                    retry_after = max(1, int(entries[0][0] + 60 - now)) if entries else 60
                    return jsonify({
                        "error": "Rate limit exceeded",
                        "limit": limit,
                        "retry_after_seconds": retry_after,
                    }), 429, {"Retry-After": str(retry_after)}
                entries.append((now, cost))
        return None

    @app.route("/api/v1/health", methods=["GET"])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            "status": "healthy",
            "service": "security-header-scanner",
            "version": "2.0.0",
        })
    
    @app.route("/api/v1/scan", methods=["GET", "POST"])
    def scan_url():
        """Scan a URL for security headers and return a supported report format."""
        payload = request.get_json(silent=True)
        url = request.args.get("url")
        if not url and isinstance(payload, dict):
            url = payload.get("url")
        if not url:
            return jsonify({
                "error": "URL parameter is required",
                "example": "/api/v1/scan?url=https://example.com",
            }), 400

        format_type = request.args.get("format", "json").lower()
        if format_type not in REPORT_FORMAT_MIMETYPES:
            return jsonify({"error": "Unsupported format", "supported": sorted(REPORT_FORMAT_MIMETYPES)}), 400
        try:
            url = validate_scan_target(
                url,
                allow_private_networks=app.config.get("api", {}).get("allow_private_networks", False),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        result = app.scanner.scan(url)
        if result.error:
            return jsonify({"error": result.error, "url": url}), 500

        app.storage.save(result)
        return _report_response(app, result, format_type)
    
    @app.route("/api/v1/scan/<scan_id>", methods=["GET"])
    def get_scan(scan_id: str):
        """Get a previous scan by ID"""
        result = app.storage.get(scan_id)
        
        if result:
            return jsonify(result.to_dict())
        else:
            return jsonify({"error": "Scan not found"}), 404
    
    @app.route("/api/v1/history", methods=["GET"])
    def get_history():
        """Get scan history"""
        limit = _parse_history_limit(100)
        if limit is None:
            return jsonify({"error": "limit must be an integer between 1 and 500"}), 400
        results = app.storage.get_all(limit)
        
        return jsonify({
            "count": len(results),
            "scans": [r.to_dict() for r in results],
        })
    
    @app.route("/api/v1/history/<path:url>", methods=["GET"])
    def get_url_history(url: str):
        """Get scan history for a specific URL"""
        if len(url) > 2048:
            return jsonify({"error": "URL must be at most 2048 characters"}), 400
        limit = _parse_history_limit(10)
        if limit is None:
            return jsonify({"error": "limit must be an integer between 1 and 500"}), 400
        results = app.storage.get_by_url(url, limit)
        
        return jsonify({
            "url": url,
            "count": len(results),
            "scans": [r.to_dict() for r in results],
        })
    
    @app.route("/api/v1/batch", methods=["GET", "POST"])
    def batch_scan():
        """Return batch status or scan a bounded list of URLs."""
        if request.method == "GET":
            all_scans = app.storage.get_all(50)
            return jsonify({
                "recent_scans": len(all_scans),
                "message": "Send POST request with URLs to perform batch scan",
                "example": {"urls": ["https://example.com", "https://test.com"]},
            })

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400
        urls = data.get("urls")
        if not isinstance(urls, list) or not urls:
            return jsonify({
                "error": "URLs must be a non-empty array",
                "example": {"urls": ["https://example.com"]},
            }), 400

        max_batch = app.config.get("scanner", {}).get("max_batch_size", 100)
        if len(urls) > max_batch:
            return jsonify({
                "error": f"Batch size exceeds maximum of {max_batch}",
                "urls_provided": len(urls),
            }), 400

        # Pre-validate every target before any outbound request to prevent a
        # mixed public/private batch from partially executing.
        validated_urls = []
        allow_private = app.config.get("api", {}).get("allow_private_networks", False)
        for index, url in enumerate(urls):
            try:
                validated_urls.append(validate_scan_target(url, allow_private_networks=allow_private))
            except ValueError as exc:
                return jsonify({"error": f"Invalid URL at index {index}: {exc}", "index": index}), 400

        results = app.scanner.batch_scan(validated_urls)
        for result in results:
            app.storage.save(result)

        scores = [result.percentage_score for result in results if not result.error]
        return jsonify({
            "total_urls": len(validated_urls),
            "successful_scans": len(scores),
            "failed_scans": len(validated_urls) - len(scores),
            "average_score": round(sum(scores) / len(scores), 1) if scores else None,
            "results": [result.to_dict() for result in results],
        })
    
    @app.route("/api/v1/compare", methods=["POST"])
    def compare_scans():
        """Compare two stored scans, including changed header scores."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400
        scan_id1 = data.get("scan_id_1")
        scan_id2 = data.get("scan_id_2")
        if not isinstance(scan_id1, str) or not scan_id1 or not isinstance(scan_id2, str) or not scan_id2:
            return jsonify({"error": "Both scan_id_1 and scan_id_2 are required"}), 400

        result1 = app.storage.get(scan_id1)
        result2 = app.storage.get(scan_id2)
        if not result1 or not result2:
            return jsonify({"error": "One or both scans not found"}), 404
        try:
            comparison = app.scanner.compare_scans(result1, result2)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify({
            "scan_1": result1.to_dict(),
            "scan_2": result2.to_dict(),
            "comparison": comparison,
        })
    
    @app.route("/api/v1/report", methods=["POST"])
    def generate_report():
        """Generate a supported report format for a stored scan."""
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400
        scan_id = data.get("scan_id")
        format_type = data.get("format", "json")
        if "output_path" in data:
            return jsonify({"error": "Server-side output_path is not supported"}), 400
        if not isinstance(scan_id, str) or not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        if not isinstance(format_type, str) or format_type.lower() not in REPORT_FORMAT_MIMETYPES:
            return jsonify({"error": "Unsupported format", "supported": sorted(REPORT_FORMAT_MIMETYPES)}), 400
        format_type = format_type.lower()
        result = app.storage.get(scan_id)
        if not result:
            return jsonify({"error": "Scan not found"}), 404
        return _report_response(app, result, format_type)
    
    @app.route("/api/v1/headers", methods=["GET"])
    def list_headers():
        """Get list of all security headers checked"""
        headers = app.scanner.registry.get_all()
        
        return jsonify({
            "count": len(headers),
            "headers": [
                {
                    "name": h.name,
                    "display_name": h.display_name,
                    "description": h.description,
                    "weight": h.weight,
                    "category": h.category,
                }
                for h in headers
            ],
        })
    
    @app.route("/api/v1/cleanup", methods=["POST"])
    def cleanup_storage():
        """Clean up old scan results"""
        data = request.get_json(silent=True)
        if data is None and not request.data.strip():
            data = {}
        if not isinstance(data, dict):
            return jsonify({"error": "Request body must be a JSON object"}), 400
        days = data.get("days", 30)
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
            return jsonify({"error": "days must be an integer between 1 and 3650"}), 400
        
        deleted = app.storage.cleanup(days)
        
        return jsonify({
            "deleted_count": deleted,
            "message": f"Cleaned up scans older than {days} days",
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Endpoint not found"}), 404
    
    @app.errorhandler(413)
    def request_too_large(error):
        return jsonify({"error": "Request body exceeds the configured size limit"}), 413

    @app.errorhandler(500)
    def server_error(error):
        return jsonify({"error": "Internal server error"}), 500


def run_server(host: Optional[str] = None, port: Optional[int] = None, debug: Optional[bool] = None):
    """Run the API server using validated configuration unless overridden."""
    app = create_app()
    api_config = app.config["api"]
    app.run(
        host=host or api_config["host"],
        port=port or api_config["port"],
        debug=api_config["debug"] if debug is None else debug,
        threaded=api_config["threaded"],
    )
