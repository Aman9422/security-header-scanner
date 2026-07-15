"""
REST API Module
~~~~~~~~~~~~~~~

Flask-based REST API for the security header scanner.
"""

import os
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from typing import Dict, Any, Optional
import yaml
from pathlib import Path

from .scanner import SecurityHeaderScanner
from .reporter import ReportGenerator
from .storage import get_storage


def create_app(config_path: Optional[str] = None) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        config_path: Optional path to config file
        
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    config = _load_config(config_path)
    
    # Initialize components
    storage = get_storage(
        config.get("storage", {}).get("type", "json"),
        config.get("storage", {}).get("path", "./data")
    )
    scanner = SecurityHeaderScanner(
        timeout=config.get("scanner", {}).get("timeout", 30),
        max_retries=config.get("scanner", {}).get("max_retries", 3),
        rate_limit_delay=config.get("scanner", {}).get("rate_limit_delay", 1.0),
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
    """Load configuration from file"""
    default_config = {
        "scanner": {
            "timeout": 30,
            "max_retries": 3,
            "rate_limit_delay": 1.0,
        },
        "storage": {
            "type": "json",
            "path": "./data",
        },
        "api": {
            "host": "0.0.0.0",
            "port": 5000,
        },
    }
    
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                if user_config:
                    return _deep_merge(default_config, user_config)
        except Exception:
            pass
    
    return default_config


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
    """Register API routes"""
    
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
        """
        Scan a URL for security headers.
        
        GET: /api/v1/scan?url=https://example.com
        POST: /api/v1/scan with JSON body {"url": "https://example.com"}
        """
        # Get URL from query param or body
        url = request.args.get("url") or (request.json or {}).get("url")
        
        if not url:
            return jsonify({
                "error": "URL parameter is required",
                "example": "/api/v1/scan?url=https://example.com",
            }), 400
        
        # Optional format parameter
        format_type = request.args.get("format", "json")
        
        # Perform scan
        result = app.scanner.scan(url)
        
        # Check for error
        if result.error:
            return jsonify({
                "error": result.error,
                "url": url,
            }), 500
        
        # Save to storage
        app.storage.save(result)
        
        # Return based on format
        if format_type == "json":
            return jsonify(result.to_dict())
        else:
            report = app.reporter.generate(result, format_type)
            return Response(report, mimetype="text/plain")
    
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
        limit = request.args.get("limit", 100, type=int)
        results = app.storage.get_all(limit)
        
        return jsonify({
            "count": len(results),
            "scans": [r.to_dict() for r in results],
        })
    
    @app.route("/api/v1/history/<path:url>", methods=["GET"])
    def get_url_history(url: str):
        """Get scan history for a specific URL"""
        limit = request.args.get("limit", 10, type=int)
        results = app.storage.get_by_url(url, limit)
        
        return jsonify({
            "url": url,
            "count": len(results),
            "scans": [r.to_dict() for r in results],
        })
    
    @app.route("/api/v1/batch", methods=["GET", "POST"])
    def batch_scan():
        """
        Batch scan endpoints.
        
        GET: Get batch status/summary
        POST: Submit batch scan with URL list
        """
        if request.method == "GET":
            # Return batch scan summary
            all_scans = app.storage.get_all(50)
            return jsonify({
                "recent_scans": len(all_scans),
                "message": "Send POST request with URLs to perform batch scan",
                "example": {
                    "urls": ["https://example.com", "https://test.com"],
                },
            })
        
        # POST: Perform batch scan
        data = request.json or {}
        urls = data.get("urls", [])
        
        if not urls:
            return jsonify({
                "error": "URLs array is required",
                "example": {"urls": ["https://example.com"]},
            }), 400
        
        # Limit batch size
        max_batch = app.config.get("scanner", {}).get("max_batch_size", 100)
        if len(urls) > max_batch:
            return jsonify({
                "error": f"Batch size exceeds maximum of {max_batch}",
                "urls_provided": len(urls),
            }), 400
        
        # Perform batch scan
        results = app.scanner.batch_scan(urls)
        
        # Save all results
        for result in results:
            app.storage.save(result)
        
        # Calculate summary
        scores = [r.percentage_score for r in results if not r.error]
        
        return jsonify({
            "total_urls": len(urls),
            "successful_scans": len(scores),
            "failed_scans": len(urls) - len(scores),
            "average_score": sum(scores) / len(scores) if scores else 0,
            "results": [r.to_dict() for r in results],
        })
    
    @app.route("/api/v1/compare", methods=["POST"])
    def compare_scans():
        """Compare two scan results"""
        data = request.json or {}
        scan_id1 = data.get("scan_id_1")
        scan_id2 = data.get("scan_id_2")
        
        if not scan_id1 or not scan_id2:
            return jsonify({
                "error": "Both scan_id_1 and scan_id_2 are required",
            }), 400
        
        result1 = app.storage.get(scan_id1)
        result2 = app.storage.get(scan_id2)
        
        if not result1 or not result2:
            return jsonify({"error": "One or both scans not found"}), 404
        
        comparison = app.scanner.compare_scans(result1, result2)
        
        return jsonify({
            "scan_1": result1.to_dict(),
            "scan_2": result2.to_dict(),
            "comparison": comparison,
        })
    
    @app.route("/api/v1/report", methods=["POST"])
    def generate_report():
        """Generate a report from scan results"""
        data = request.json or {}
        scan_id = data.get("scan_id")
        format_type = data.get("format", "json")
        output_path = data.get("output_path")
        
        if not scan_id:
            return jsonify({"error": "scan_id is required"}), 400
        
        result = app.storage.get(scan_id)
        
        if not result:
            return jsonify({"error": "Scan not found"}), 404
        
        report = app.reporter.generate(result, format_type, output_path)
        
        if format_type == "html":
            return Response(report, mimetype="text/html")
        elif format_type == "markdown":
            return Response(report, mimetype="text/markdown")
        elif format_type == "csv":
            return Response(report, mimetype="text/csv")
        else:
            return jsonify(result.to_dict())
    
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
        data = request.json or {}
        days = data.get("days", 30)
        
        deleted = app.storage.cleanup(days)
        
        return jsonify({
            "deleted_count": deleted,
            "message": f"Cleaned up scans older than {days} days",
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Endpoint not found"}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({"error": "Internal server error"}), 500


def run_server(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Run the API server"""
    app = create_app()
    app.run(host=host, port=port, debug=debug)
