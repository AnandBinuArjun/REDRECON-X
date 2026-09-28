from datetime import datetime, timezone
import pytest
from redrecon.intelligence.difference import AttackSurfaceDifferenceEngine
from redrecon.intelligence.prioritization import AssetPrioritizer
from redrecon.models.asset import Asset, AssetConfidence, DNSRecords, HeaderObservation, HTTPService, PortService
from redrecon.models.finding import Finding, FindingSeverity
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus


def test_section_38_priority_formula():
    """Verify Section 38 formula: 3 (internet) + 1 (service) + 2 (admin) + 1 (headers) + 2 (findings) = 9"""
    asset = Asset(
        hostname="admin.example.com",
        root_domain="example.com",
        ip_addresses=["203.0.113.10"],
        dns_records=DNSRecords(A=["203.0.113.10"]),
        http_service=HTTPService(
            url="https://admin.example.com",
            status_code=200,
            title="Internal Admin Portal",
        ),
        ports=[PortService(port=443, service_name="https")],
        security_headers=[
            HeaderObservation(header="Content-Security-Policy", status="MISSING", severity="MEDIUM")
        ],
        confidence=AssetConfidence.HIGH,
    )

    score, breakdown = AssetPrioritizer.calculate_priority_score(asset, findings_count=1)
    assert score == 9
    assert breakdown["internet_exposure"] == 3
    assert breakdown["service_exposure"] == 1
    assert breakdown["administrative_context"] == 2
    assert breakdown["configuration_observations"] == 1
    assert breakdown["scanner_findings"] == 2


def test_attack_surface_difference_engine():
    """Verify Section 27 & 48 change detection: new/removed assets, ports, headers, and findings."""
    time_base = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    time_curr = datetime(2026, 9, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Base scan
    asset_base_1 = Asset(
        hostname="api.example.com",
        root_domain="example.com",
        ip_addresses=["203.0.113.10"],
        ports=[PortService(port=443, service_name="https")],
        security_headers=[
            HeaderObservation(header="Strict-Transport-Security", status="PRESENT")
        ],
        confidence=AssetConfidence.HIGH,
    )
    asset_base_2 = Asset(
        hostname="legacy.example.com",
        root_domain="example.com",
        ip_addresses=["203.0.113.20"],
        confidence=AssetConfidence.MEDIUM,
    )

    base_finding = Finding(
        id="f-base-1",
        target="https://api.example.com",
        source="nuclei",
        name="Old CVE",
        severity=FindingSeverity.MEDIUM,
    )

    scan_base = ScanResult(
        scan_id="RX-20260920-001",
        target="example.com",
        mode=ScanMode.FULL,
        status=ScanStatus.COMPLETED,
        started_at=time_base,
        assets=[asset_base_1, asset_base_2],
        findings=[base_finding],
    )

    # Current scan
    # - legacy.example.com removed
    # - admin.example.com added
    # - api.example.com gained port 8080 and lost HSTS
    # - new finding discovered
    asset_curr_1 = Asset(
        hostname="api.example.com",
        root_domain="example.com",
        ip_addresses=["203.0.113.10"],
        ports=[
            PortService(port=443, service_name="https"),
            PortService(port=8080, service_name="http-alt"),
        ],
        security_headers=[
            HeaderObservation(header="Strict-Transport-Security", status="MISSING")
        ],
        confidence=AssetConfidence.HIGH,
    )
    asset_curr_new = Asset(
        hostname="admin.example.com",
        root_domain="example.com",
        ip_addresses=["203.0.113.30"],
        confidence=AssetConfidence.HIGH,
    )

    new_finding = Finding(
        id="f-curr-1",
        target="https://admin.example.com",
        source="nuclei",
        name="Admin Exposure",
        severity=FindingSeverity.HIGH,
    )

    scan_curr = ScanResult(
        scan_id="RX-20260928-002",
        target="example.com",
        mode=ScanMode.FULL,
        status=ScanStatus.COMPLETED,
        started_at=time_curr,
        assets=[asset_curr_1, asset_curr_new],
        findings=[new_finding],
    )

    diff = AttackSurfaceDifferenceEngine.compare_scans(scan_base, scan_curr)

    assert diff.summary["new_assets"] == 1
    assert diff.new_assets[0].hostname == "admin.example.com"

    assert diff.summary["removed_assets"] == 1
    assert diff.removed_assets[0].hostname == "legacy.example.com"

    assert diff.summary["persisted_assets"] == 1

    assert diff.summary["new_open_ports"] == 1
    assert diff.new_open_ports[0].port == 8080

    assert diff.summary["new_findings"] == 1
    assert diff.new_findings[0].name == "Admin Exposure"

    assert diff.summary["resolved_findings"] == 1
    assert diff.resolved_findings[0].name == "Old CVE"

    assert diff.summary["changed_headers"] == 1
    assert diff.changed_headers[0].header == "Strict-Transport-Security"
    assert diff.changed_headers[0].old_status == "PRESENT"
    assert diff.changed_headers[0].new_status == "MISSING"

    # Verify Rich rendering works without error
    table = AttackSurfaceDifferenceEngine.render_rich_diff(diff)
    assert table is not None
