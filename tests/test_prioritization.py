import pytest
from redrecon.intelligence.prioritization import AssetPrioritizer
from redrecon.models.asset import AssetConfidence, DNSRecords, HTTPService, PortService


def test_confidence_live_http():
    http_svc = HTTPService(url="https://api.example.com", status_code=200, title="API Gateway")
    conf = AssetPrioritizer.calculate_confidence(
        sources=["CT", "DNS"],
        dns_records=DNSRecords(A=["1.2.3.4"]),
        http_service=http_svc,
    )
    assert conf == AssetConfidence.HIGH


def test_confidence_dns_only():
    conf = AssetPrioritizer.calculate_confidence(
        sources=["CT"],
        dns_records=DNSRecords(A=["1.2.3.4"]),
        http_service=None,
    )
    assert conf == AssetConfidence.MEDIUM


def test_confidence_historical_unresolved():
    conf = AssetPrioritizer.calculate_confidence(
        sources=["Wayback"],
        dns_records=DNSRecords(),
        http_service=None,
    )
    assert conf == AssetConfidence.LOW
