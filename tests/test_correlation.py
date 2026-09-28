import os
import tempfile
import pytest
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.models.asset import Asset, AssetConfidence, DNSRecords, PortService
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository


def test_asset_correlation():
    domain = "example.com"
    hosts = ["example.com", "api.example.com"]
    prov = {"example.com": ["Scope"], "api.example.com": ["CT", "DNS"]}
    dns = {
        "example.com": {"records": {"A": ["93.184.216.34"]}},
        "api.example.com": {"records": {"A": ["93.184.216.35"]}},
    }
    http = {
        "example.com": {"url": "https://example.com", "status_code": 200, "title": "Example Domain"},
    }
    ports = {
        "example.com": [PortService(port=443, service_name="https")],
    }

    assets = AssetCorrelator.correlate_target_assets(
        root_domain=domain,
        discovered_hosts=hosts,
        provenance_map=prov,
        dns_results=dns,
        http_results=http,
        headers_results={},
        ports_results=ports,
        wayback_urls=["https://example.com/api/v1"],
        findings=[],
    )

    assert len(assets) == 2
    ex_asset = next(a for a in assets if a.hostname == "example.com")
    assert ex_asset.confidence == AssetConfidence.HIGH
    assert len(ex_asset.ports) == 1
    assert ex_asset.http_service.status_code == 200

    graph = AssetCorrelator.generate_attack_surface_graph(domain, assets)
    assert graph["total_nodes"] >= 3
    assert graph["total_edges"] >= 2


def test_database_and_repository(tmp_path):
    db_path = str(tmp_path / "test.db")
    db = Database(db_path=db_path)
    repo = ScanRepository(db)

    scan = ScanResult(
        scan_id="RX-TEST-001",
        target="example.com",
        mode=ScanMode.PASSIVE,
        status=ScanStatus.COMPLETED,
        metrics=ScanMetrics(discovered_hosts=5, live_hosts=3),
    )

    repo.save_scan(scan)
    retrieved = repo.get_scan("RX-TEST-001")
    assert retrieved is not None
    assert retrieved.target == "example.com"
    assert retrieved.metrics.discovered_hosts == 5

    scans_list = repo.list_scans()
    assert len(scans_list) == 1
