import pytest
from redrecon.core.config import load_config


def test_bugbounty_profile():
    """Verify bugbounty profile settings."""
    cfg = load_config(profile="bugbounty")
    assert cfg.enable_bruteforce is True
    assert cfg.max_nmap_targets == 30
    assert cfg.max_nuclei_targets == 40
    assert "brute" in cfg.subdomain_providers


def test_pentest_profile():
    """Verify pentest profile settings."""
    cfg = load_config(profile="pentest")
    assert cfg.max_nmap_targets == 100
    assert cfg.max_nuclei_targets == 100
    assert cfg.concurrency == 40
    assert cfg.nuclei_rate_limit == 75


def test_fast_profile():
    """Verify fast triage profile settings."""
    cfg = load_config(profile="fast")
    assert cfg.enable_bruteforce is False
    assert cfg.nmap_top_ports == 20
    assert cfg.timeout == 3.5


def test_monitoring_profile():
    """Verify monitoring drift profile settings."""
    cfg = load_config(profile="monitoring")
    assert cfg.nuclei_enabled is False
    assert cfg.max_nuclei_targets == 0
    assert cfg.enable_bruteforce is False
