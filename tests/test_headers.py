import pytest
from redrecon.modules.headers.analyzer import HeaderAnalyzer


def test_header_analyzer_present():
    analyzer = HeaderAnalyzer()
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    observations = analyzer.analyze_headers(headers)
    present_headers = [o.header for o in observations if o.status == "PRESENT"]
    assert "Strict-Transport-Security" in present_headers
    assert "X-Frame-Options" in present_headers
    assert "X-Content-Type-Options" in present_headers


def test_header_analyzer_missing():
    analyzer = HeaderAnalyzer()
    observations = analyzer.analyze_headers({})
    missing_headers = [o.header for o in observations if o.status == "MISSING"]
    assert "Strict-Transport-Security" in missing_headers
    assert "Content-Security-Policy" in missing_headers
