"""
Security Headers Scanner Pro
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A comprehensive security headers analysis tool for developers and security professionals.
"""

__version__ = "2.0.0"
__author__ = "Security Headers Team"
__license__ = "MIT"

from .scanner import SecurityHeaderScanner
from .analyzer import HeaderAnalyzer
from .reporter import ReportGenerator
from .headers import SecurityHeader, HeaderRegistry

__all__ = [
    "SecurityHeaderScanner",
    "HeaderAnalyzer",
    "ReportGenerator",
    "SecurityHeader",
    "HeaderRegistry",
]
