import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse


class AssetDeduplicator:
    """
    Normalizes and deduplicates hostnames, IPs, and URLs across multiple discovery sources.
    Keeps track of origin sources and deduplication reduction statistics.
    """

    @staticmethod
    def normalize_host(host: str) -> str:
        """Sanitize and normalize hostname."""
        if not host:
            return ""
        host = host.lower().strip()
        # Remove schemes if present
        if "://" in host:
            host = host.split("://", 1)[1]
        # Remove paths and query strings
        host = host.split("/")[0]
        # Remove port numbers
        host = host.split(":")[0]
        # Strip wildcard prefixes (*.)
        if host.startswith("*."):
            host = host[2:]
        # Strip trailing dots
        host = host.rstrip(".")
        return host

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL by stripping default ports and fragment."""
        if not url:
            return ""
        url = url.strip()
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() or "https"
            netloc = parsed.netloc.lower()
            # Remove standard ports
            if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
                netloc = netloc.rsplit(":", 1)[0]
            path = parsed.path or "/"
            query = f"?{parsed.query}" if parsed.query else ""
            return f"{scheme}://{netloc}{path}{query}"
        except Exception:
            return url

    @classmethod
    def deduplicate_hosts(
        cls, raw_hosts_with_sources: List[Tuple[str, str]]
    ) -> Tuple[List[str], Dict[str, Set[str]], int]:
        """
        Takes list of (hostname, source_name) tuples.
        Returns:
            - list of unique normalized hostnames
            - mapping of hostname -> set of sources that reported it
            - count of duplicates removed
        """
        host_sources: Dict[str, Set[str]] = {}
        total_raw = len(raw_hosts_with_sources)

        for raw_host, source in raw_hosts_with_sources:
            norm = cls.normalize_host(raw_host)
            if not norm or not re.match(r"^[a-z0-9.-]+$", norm):
                continue
            if norm not in host_sources:
                host_sources[norm] = set()
            host_sources[norm].add(source)

        unique_hosts = sorted(list(host_sources.keys()))
        duplicates_removed = max(0, total_raw - len(unique_hosts))
        return unique_hosts, host_sources, duplicates_removed

    @classmethod
    def deduplicate_urls(cls, raw_urls: List[str]) -> Tuple[List[str], int]:
        """Deduplicate list of URLs."""
        seen: Set[str] = set()
        for u in raw_urls:
            norm = cls.normalize_url(u)
            if norm:
                seen.add(norm)
        unique_urls = sorted(list(seen))
        duplicates = max(0, len(raw_urls) - len(unique_urls))
        return unique_urls, duplicates
