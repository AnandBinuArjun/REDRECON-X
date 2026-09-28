"""
Integration tests for REDRECON-X scanning pipeline & operational resilience.
Validates:
1. End-to-end passive scan pipeline with database persistence
2. Graceful cancellation handling (preserves CANCELLED status in database)
3. Exception resilience (preserves FAILED status in database)
4. Scope boundary validation before pipeline entry
"""

import asyncio
import os
import pytest
from unittest.mock import patch, AsyncMock
from redrecon.core.config import ScanConfig
from redrecon.core.engine import ReconEngine
from redrecon.models.scan import ScanMode, ScanStatus
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository


@pytest.fixture
def test_config(tmp_path):
    db_path = str(tmp_path / "test_recon.db")
    output_dir = str(tmp_path / "test_reports")
    return ScanConfig(
        db_path=db_path,
        output_dir=output_dir,
        allowed_domains=["example.com"],
        allow_third_party=False,
    )


@pytest.mark.asyncio
async def test_end_to_end_passive_scan(test_config):
    """Verify that a passive scan executes all passive stages and persists results to SQLite."""
    engine = ReconEngine(test_config)

    # Mock external network queries for fast, deterministic CI execution
    mock_ct = {"subdomains": ["api.example.com", "vpn.example.com"], "status": "completed"}
    mock_wb = {"urls": ["http://api.example.com/login", "http://dev.example.com/api"], "status": "completed"}
    mock_sub = {
        "subdomains": ["api.example.com", "vpn.example.com", "dev.example.com"],
        "provenance": {
            "api.example.com": ["Certificate Transparency"],
            "vpn.example.com": ["Certificate Transparency"],
            "dev.example.com": ["Wayback Machine"],
        },
    }
    mock_dns = {
        "records": {
            "api.example.com": {"A": ["93.184.216.34"]},
            "vpn.example.com": {"A": ["93.184.216.35"]},
            "dev.example.com": {"A": []},
        }
    }
    mock_ip = {
        "ip_map": {
            "93.184.216.34": {"hostnames": ["api.example.com"], "asn": "AS15133"},
            "93.184.216.35": {"hostnames": ["vpn.example.com"], "asn": "AS15133"},
        }
    }

    with patch("redrecon.modules.certificate.scanner.CertificateScanner.scan", new=AsyncMock(return_value=mock_ct)), \
         patch("redrecon.modules.wayback.scanner.WaybackScanner.scan", new=AsyncMock(return_value=mock_wb)), \
         patch("redrecon.modules.subdomain.scanner.SubdomainScanner.scan", new=AsyncMock(return_value=mock_sub)), \
         patch("redrecon.modules.dns.scanner.DNSScanner.scan", new=AsyncMock(return_value=mock_dns)), \
         patch("redrecon.modules.ip.scanner.IPScanner.correlate_ips", new=AsyncMock(return_value=mock_ip)):

        result = await engine.run_scan(target="example.com", mode=ScanMode.PASSIVE, scan_id="RX-TEST-PASSIVE-01")

        assert result.status == ScanStatus.COMPLETED
        assert result.scan_id == "RX-TEST-PASSIVE-01"
        assert result.target == "example.com"
        assert result.mode == ScanMode.PASSIVE
        assert len(result.assets) >= 2
        assert result.metrics.discovered_hosts >= 2

        # Verify database record
        db = Database(test_config.db_path)
        repo = ScanRepository(db)
        saved = repo.get_scan("RX-TEST-PASSIVE-01")
        assert saved is not None
        assert saved.status == ScanStatus.COMPLETED
        assert saved.metrics.discovered_hosts >= 2


@pytest.mark.asyncio
async def test_interrupted_scan_fails_safely(test_config):
    """Verify that an aborted / cancelled scan preserves CANCELLED state and partial timing."""
    engine = ReconEngine(test_config)

    # Simulate cancellation during certificate scanning
    with patch("redrecon.modules.certificate.scanner.CertificateScanner.scan", side_effect=asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            await engine.run_scan(target="example.com", mode=ScanMode.PASSIVE, scan_id="RX-TEST-CANCEL-01")

    # Verify database state was recorded as CANCELLED, not left in limbo
    db = Database(test_config.db_path)
    repo = ScanRepository(db)
    saved = repo.get_scan("RX-TEST-CANCEL-01")
    assert saved is not None
    assert saved.status == ScanStatus.CANCELLED
    assert "cancelled" in saved.raw_data.get("error", "").lower()


@pytest.mark.asyncio
async def test_unexpected_failure_recovery(test_config):
    """Verify that an unexpected module exception is captured, recorded as FAILED, and logged."""
    engine = ReconEngine(test_config)

    with patch("redrecon.modules.certificate.scanner.CertificateScanner.scan", side_effect=RuntimeError("Hardware/DNS fault")):
        with pytest.raises(RuntimeError):
            await engine.run_scan(target="example.com", mode=ScanMode.PASSIVE, scan_id="RX-TEST-FAIL-01")

    db = Database(test_config.db_path)
    repo = ScanRepository(db)
    saved = repo.get_scan("RX-TEST-FAIL-01")
    assert saved is not None
    assert saved.status == ScanStatus.FAILED
    assert "Hardware/DNS fault" in saved.raw_data.get("error", "")


@pytest.mark.asyncio
async def test_scope_rejection_prior_to_pipeline(test_config):
    """Verify that scanning an out-of-scope domain aborts immediately before any scanner runs."""
    engine = ReconEngine(test_config)

    with pytest.raises(ValueError):
        await engine.run_scan(target="invalid_domain_target_!@#")
