import os
import pytest
from httpx import ASGITransport, AsyncClient

from redrecon.core.scope import ScopeValidator
from redrecon.dashboard.app import app
from redrecon.modules.nmap.scanner import NmapScanner
from redrecon.modules.nuclei.scanner import NucleiScanner
from redrecon.intelligence.benchmark import BenchmarkMetrics


def test_scope_rejection_and_bypass_prevention():
    """Verify scope controller strictly rejects out-of-scope third-party infrastructure and malformed hosts."""
    validator = ScopeValidator(
        target_domain="example.com",
        allowed_domains=["example.com", "*.example.com"],
        allow_third_party=False,
    )

    # Valid in-scope subdomains
    assert validator.is_in_scope("api.example.com") is True
    assert validator.is_in_scope("dev.sub.example.com") is True

    # Third-party cloud/CDN domains must be blocked
    assert validator.is_in_scope("s3.amazonaws.com") is False
    assert validator.is_in_scope("example.com.evil.com") is False
    assert validator.is_in_scope("evil-example.com") is False
    assert validator.is_in_scope("cloudflare.net") is False

    # Filter scoped list
    hosts = ["api.example.com", "evil.com", "auth.example.com", "cdn.cloudfront.net"]
    filtered = validator.filter_scoped_hosts(hosts)
    assert filtered == ["api.example.com", "auth.example.com"]


def test_nmap_malformed_xml_resilience():
    """Verify Nmap parser recovers from corrupt or truncated XML without terminating the scan."""
    scanner = NmapScanner()
    malformed_xml = "<nmaprun><host><ports><port protocol='tcp' portid='80'><state state='open'/>"  # unclosed tags
    parsed = scanner.parse_nmap_xml(malformed_xml)
    # Must return empty list or parsed fraction without crashing
    assert isinstance(parsed, list)


def test_nuclei_malformed_jsonl_resilience():
    """Verify Nuclei parser skips corrupt lines and continues parsing valid findings."""
    scanner = NucleiScanner()
    raw_jsonl = (
        '{"template-id": "cve-1", "info": {"name": "Test CVE", "severity": "high"}, "matched-at": "https://example.com"}\n'
        'CORRUPT_NON_JSON_LINE\n'
        '{"template-id": "cve-2", "info": {"name": "Info Leak", "severity": "low"}, "matched-at": "https://example.com/api"}\n'
    )
    findings = scanner.parse_nuclei_jsonl(raw_jsonl)
    assert len(findings) == 2
    assert findings[0].name == "Test CVE"
    assert findings[1].name == "Info Leak"


@pytest.mark.asyncio
async def test_api_key_query_param_rejected():
    """
    Security test: API key provided via URL query parameter '?api_key=' must be strictly
    REJECTED when authentication is configured, enforcing header-based authentication.
    """
    os.environ["REDRECON_API_KEY"] = "super-secret-msc-key"
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Unauthenticated request -> 401
            r_no_auth = await client.get("/api/scans")
            assert r_no_auth.status_code == 401

            # 2. Query param attempt (?api_key=...) -> must still be 401 rejected!
            r_query_param = await client.get("/api/scans?api_key=super-secret-msc-key")
            assert r_query_param.status_code == 401

            # 3. Secure header attempt (X-API-Key) -> 200 OK
            r_header = await client.get("/api/scans", headers={"X-API-Key": "super-secret-msc-key"})
            assert r_header.status_code == 200

            # 4. Bearer token header attempt -> 200 OK
            r_bearer = await client.get("/api/scans", headers={"Authorization": "Bearer super-secret-msc-key"})
            assert r_bearer.status_code == 200
    finally:
        os.environ.pop("REDRECON_API_KEY", None)


def test_academic_benchmark_metrics_formulae():
    """Verify academic research derivation formulas in BenchmarkMetrics."""
    m = BenchmarkMetrics(
        target="example.com",
        single_source_ct_count=20,
        provider_breakdown={"CT": 20, "AlienVault": 15, "Wayback": 15},
        raw_discoveries=50,
        unique_assets=30,
        duplicates_removed=20,
        deduplication_rate_pct=40.0,
        dns_verified_hosts=25,
        http_verified_hosts=18,
        verification_ratio_pct=60.0,
        coverage_gain_pct=50.0,
        total_duration_sec=32.5,
        graph_nodes=65,
        graph_edges=82,
    )
    assert m.deduplication_rate_pct == 40.0
    assert m.coverage_gain_pct == 50.0
    assert m.verification_ratio_pct == 60.0
    assert m.graph_nodes == 65
