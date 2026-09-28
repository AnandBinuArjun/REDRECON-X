import fnmatch
import ipaddress
import re
from typing import List, Optional, Set
from redrecon.core.logger import get_logger

logger = get_logger()

# Known third-party hosting / CDN domains where active intrusive scanning should be carefully guarded
THIRD_PARTY_DOMAINS = [
    "*.amazonaws.com",
    "*.cloudfront.net",
    "*.s3.amazonaws.com",
    "*.azureedge.net",
    "*.trafficmanager.net",
    "*.cloudapp.net",
    "*.cloudflare.com",
    "*.cloudflare.net",
    "*.fastly.net",
    "*.akamaized.net",
    "*.akamai.net",
    "*.github.io",
    "*.herokuapp.com",
    "*.wpengine.com",
    "*.googlehosted.com",
    "*.pantheonsite.io",
    "*.shopify.com",
]

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_domain(host: str, strip_wildcard: bool = False) -> str:
    """Canonical domain and host normalizer across all REDRECON-X modules."""
    if not host:
        return ""
    host = host.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0]
    host = host.split(":")[0]
    if strip_wildcard and host.startswith("*."):
        host = host[2:]
    host = host.rstrip(".")
    return host


class ScopeValidator:
    """
    Enforces authorization and boundary constraints for active and passive recon.
    Prevents unintentional scanning of out-of-scope or third-party cloud assets.
    """

    def __init__(
        self,
        target_domain: str,
        allowed_domains: Optional[List[str]] = None,
        excluded_domains: Optional[List[str]] = None,
        allow_third_party: bool = False,
    ):
        self.target_domain = self.normalize_host(target_domain, strip_wildcard=True)
        self.allowed_domains = [self.normalize_host(d, strip_wildcard=False) for d in (allowed_domains or [])]
        if not self.allowed_domains:
            self.allowed_domains = [self.target_domain, f"*.{self.target_domain}"]

        self.excluded_domains = [self.normalize_host(d, strip_wildcard=False) for d in (excluded_domains or [])]
        self.allow_third_party = allow_third_party
        self._third_party_patterns = THIRD_PARTY_DOMAINS

    @staticmethod
    def normalize_host(host: str, strip_wildcard: bool = False) -> str:
        """Strip protocol, port, path, and whitespace."""
        return normalize_domain(host, strip_wildcard=strip_wildcard)

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        norm = ScopeValidator.normalize_host(domain)
        if not norm:
            return False
        # If it's an IP address, validate IP format
        try:
            ipaddress.ip_address(norm)
            return True
        except ValueError:
            pass
        return bool(DOMAIN_REGEX.match(norm))

    def is_in_scope(self, host: str) -> bool:
        """
        Check if host belongs to target domain scope.
        """
        normalized = self.normalize_host(host)
        if not normalized:
            return False

        # 1. Check exclusions first
        for exc in self.excluded_domains:
            if fnmatch.fnmatch(normalized, exc):
                logger.debug(f"[SCOPE] Excluded host blocked: {normalized} (matches {exc})")
                return False

        # 2. Check if it matches allowed patterns or target domain
        matches_allowed = False
        for pattern in self.allowed_domains:
            if fnmatch.fnmatch(normalized, pattern):
                matches_allowed = True
                break

        if not matches_allowed:
            # Check if it's a subdomain of target_domain
            if normalized == self.target_domain or normalized.endswith(f".{self.target_domain}"):
                matches_allowed = True

        if not matches_allowed:
            logger.debug(f"[SCOPE] Out of scope: {normalized}")
            return False

        # 3. Check for third-party cloud infrastructure if not explicitly allowed
        if not self.allow_third_party:
            if self.is_third_party(normalized):
                logger.warning(f"[SCOPE] Third-party cloud asset flagged/restricted: {normalized}")
                return False

        return True

    def is_third_party(self, host: str) -> bool:
        """Determine if hostname belongs to public CDN/Cloud provider."""
        normalized = self.normalize_host(host)
        for pattern in self._third_party_patterns:
            if fnmatch.fnmatch(normalized, pattern):
                return True
        return False

    def filter_scoped_hosts(self, hosts: List[str]) -> List[str]:
        """Convenience filter returning only hosts that strictly satisfy scope constraints."""
        return [h for h in hosts if self.is_in_scope(h)]
