import asyncio
import json
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Set
import dns.asyncresolver
import httpx
from redrecon.core.logger import get_logger
from redrecon.core.scope import normalize_domain

logger = get_logger()

# Curated list of high-value subdomains for discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "test", "staging", "stage", "admin", "vpn",
    "portal", "app", "corp", "internal", "remote", "gateway", "auth", "sso",
    "login", "beta", "demo", "cloud", "git", "gitlab", "github", "jenkins",
    "jira", "confluence", "monitor", "grafana", "prometheus", "k8s", "kube",
    "status", "docs", "cdn", "static", "assets", "media", "images", "files",
    "secure", "pay", "billing", "shop", "store", "chat", "slack", "support",
    "help", "helpdesk", "mx", "smtp", "ns1", "ns2", "dns", "server", "db",
    "database", "mysql", "postgres", "redis", "elastic", "kibana", "backup",
    "old", "new", "v1", "v2", "ws", "connect", "proxy", "edge", "hub",
    "direct", "router", "switch", "firewall", "idp", "iam", "access", "member",
    "user", "account", "profile", "m", "mobile", "preview", "sandbox", "lab"
]


class DiscoveryProvider(ABC):
    """Abstract base class for subdomain discovery sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def discover(self, domain: str) -> Set[str]:
        pass

    def _clean_host(self, host: str, domain: str) -> str:
        host = normalize_domain(host, strip_wildcard=True)
        if host and (host == domain or host.endswith(f".{domain}")) and re.match(r"^[a-z0-9.-]+$", host):
            return host
        return ""


class CertificateProvider(DiscoveryProvider):
    @property
    def name(self) -> str:
        return "Certificate Transparency"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    for item in resp.json():
                        for name in item.get("name_value", "").split("\n"):
                            clean = self._clean_host(name, domain)
                            if clean:
                                found.add(clean)
        except Exception as e:
            logger.debug(f"[SubdomainProvider] crt.sh failed: {e}")
        return found


class WaybackSubdomainProvider(DiscoveryProvider):
    @property
    def name(self) -> str:
        return "Wayback Machine"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit=500"
        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rows = resp.json()
                    # Skip header row if present
                    if rows and rows[0] == ["original"]:
                        rows = rows[1:]
                    for row in rows:
                        if not row:
                            continue
                        orig_url = row[0] if isinstance(row, list) else str(row)
                        # Extract host from URL
                        match = re.search(r"https?://([^/:]+)", orig_url, re.IGNORECASE)
                        if match:
                            clean = self._clean_host(match.group(1), domain)
                            if clean:
                                found.add(clean)
        except Exception as e:
            logger.debug(f"[SubdomainProvider] Wayback failed: {e}")
        return found


class AlienVaultProvider(DiscoveryProvider):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False, headers=headers) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        clean = self._clean_host(hostname, domain)
                        if clean:
                            found.add(clean)
        except Exception as e:
            logger.debug(f"[SubdomainProvider] AlienVault failed: {e}")
        return found


class HackerTargetProvider(DiscoveryProvider):
    @property
    def name(self) -> str:
        return "HackerTarget"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        parts = line.split(",")
                        if parts:
                            clean = self._clean_host(parts[0], domain)
                            if clean:
                                found.add(clean)
        except Exception as e:
            logger.debug(f"[SubdomainProvider] HackerTarget failed: {e}")
        return found


class AnubisProvider(DiscoveryProvider):
    @property
    def name(self) -> str:
        return "Anubis DB"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    for item in resp.json():
                        clean = self._clean_host(item, domain)
                        if clean:
                            found.add(clean)
        except Exception as e:
            logger.debug(f"[SubdomainProvider] Anubis failed: {e}")
        return found


class DNSBruteProvider(DiscoveryProvider):
    """Active DNS probe using curated high-probability prefixes."""

    def __init__(self, wordlist: List[str] = None, concurrency: int = 30):
        self.wordlist = wordlist or COMMON_SUBDOMAINS
        self.concurrency = concurrency

    @property
    def name(self) -> str:
        return "DNS Brute Force"

    async def discover(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        resolver.timeout = 2.0
        resolver.lifetime = 3.0

        sem = asyncio.Semaphore(self.concurrency)

        async def _probe(prefix: str):
            candidate = f"{prefix}.{domain}"
            async with sem:
                try:
                    ans = await resolver.resolve(candidate, "A")
                    if ans:
                        found.add(candidate.lower())
                except Exception:
                    pass

        tasks = [_probe(w) for w in self.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)
        return found
