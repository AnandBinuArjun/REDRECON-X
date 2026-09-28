import pytest
from redrecon.intelligence.deduplication import AssetDeduplicator


def test_normalize_host():
    assert AssetDeduplicator.normalize_host("*.api.example.com.") == "api.example.com"
    assert AssetDeduplicator.normalize_host("https://admin.example.com:8443/login") == "admin.example.com"


def test_deduplicate_hosts():
    raw_data = [
        ("api.example.com", "Certificate Transparency"),
        ("api.example.com", "DNS"),
        ("*.api.example.com", "Wayback"),
        ("dev.example.com", "AlienVault"),
        ("DEV.example.com.", "HackerTarget"),
    ]

    unique, sources, dupes = AssetDeduplicator.deduplicate_hosts(raw_data)
    assert sorted(unique) == ["api.example.com", "dev.example.com"]
    assert "Certificate Transparency" in sources["api.example.com"]
    assert "DNS" in sources["api.example.com"]
    assert "Wayback" in sources["api.example.com"]
    assert dupes == 3


def test_deduplicate_urls():
    urls = [
        "https://example.com:443/api/v1?test=1",
        "https://example.com/api/v1?test=1",
        "http://example.com:80/login",
        "http://example.com/login",
    ]
    unique, dupes = AssetDeduplicator.deduplicate_urls(urls)
    assert len(unique) == 2
    assert dupes == 2
