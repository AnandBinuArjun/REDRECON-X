import os
import pytest
from fastapi import HTTPException
from redrecon.core.logger import init_error_tracking
from redrecon.core.scope import normalize_domain
from redrecon.dashboard.app import verify_api_key
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus
from redrecon.reporting.generator import ReportGenerator
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository


def test_normalize_domain_canonical():
    assert normalize_domain("https://API.Example.com:8443/v1/test", strip_wildcard=True) == "api.example.com"
    assert normalize_domain("*.sub.example.com", strip_wildcard=True) == "sub.example.com"
    assert normalize_domain("*.sub.example.com", strip_wildcard=False) == "*.sub.example.com"
    assert normalize_domain("http://example.com.") == "example.com"


def test_error_tracking_initialization(monkeypatch):
    # With no DSN configured, should return False gracefully without raising exception
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert init_error_tracking() is False

    # With invalid dummy DSN, should handle gracefully
    monkeypatch.setenv("SENTRY_DSN", "https://public@sentry.example.com/1")
    assert init_error_tracking() is True


def test_verify_api_key_dependency(monkeypatch):
    # Case 1: No key configured -> allows open localhost development
    monkeypatch.delenv("REDRECON_API_KEY", raising=False)
    assert verify_api_key(api_key=None, authorization=None) is True

    # Case 2: Key configured -> verifies matching key in X-API-Key or Bearer header
    monkeypatch.setenv("REDRECON_API_KEY", "super-secret-key-123")
    assert verify_api_key(api_key="super-secret-key-123", authorization=None) is True
    assert verify_api_key(api_key=None, authorization="Bearer super-secret-key-123") is True

    # Case 3: Wrong or missing key -> raises 401
    with pytest.raises(HTTPException) as exc:
        verify_api_key(api_key="wrong-key", authorization=None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_module_12_report_generator(tmp_path):
    db_path = str(tmp_path / "test_gen.db")
    out_dir = str(tmp_path / "out")
    db = Database(db_path=db_path)
    repo = ScanRepository(db)

    # Save dummy scan
    scan = ScanResult(
        scan_id="RX-GEN-001",
        target="target.local",
        mode=ScanMode.PASSIVE,
        status=ScanStatus.COMPLETED,
        metrics=ScanMetrics(discovered_hosts=1, live_hosts=1),
    )
    repo.save_scan(scan)

    gen = ReportGenerator()
    gen.config.db_path = db_path
    gen.config.output_dir = out_dir

    res = await gen.scan("target.local")
    assert res.get("status") == "success"
    assert res.get("scan_id") == "RX-GEN-001"
    assert os.path.exists(res.get("html_report"))
