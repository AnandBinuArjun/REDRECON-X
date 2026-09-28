import pytest
from redrecon.core.scope import ScopeValidator


def test_normalize_host():
    assert ScopeValidator.normalize_host("https://api.example.com:443/test") == "api.example.com"
    assert ScopeValidator.normalize_host("HTTP://WWW.EXAMPLE.COM/") == "www.example.com"
    assert ScopeValidator.normalize_host("*.sub.example.com.") == "*.sub.example.com"


def test_is_valid_domain():
    assert ScopeValidator.is_valid_domain("example.com") is True
    assert ScopeValidator.is_valid_domain("sub.domain.co.uk") is True
    assert ScopeValidator.is_valid_domain("192.168.1.1") is True
    assert ScopeValidator.is_valid_domain("invalid domain with spaces") is False


def test_is_in_scope():
    validator = ScopeValidator(
        target_domain="example.com",
        allowed_domains=["example.com", "*.example.com"],
        excluded_domains=["secret.example.com"],
        allow_third_party=False,
    )

    assert validator.is_in_scope("example.com") is True
    assert validator.is_in_scope("api.example.com") is True
    assert validator.is_in_scope("dev.sub.example.com") is True
    assert validator.is_in_scope("secret.example.com") is False
    assert validator.is_in_scope("google.com") is False


def test_third_party_blocking():
    validator = ScopeValidator(
        target_domain="example.com",
        allow_third_party=False,
    )
    assert validator.is_third_party("bucket.s3.amazonaws.com") is True
    assert validator.is_third_party("test.cloudfront.net") is True
    assert validator.is_third_party("api.example.com") is False
