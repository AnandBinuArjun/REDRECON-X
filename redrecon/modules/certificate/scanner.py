import json
import re
from typing import Any, Dict, List, Set
import httpx
from redrecon.core.logger import get_logger
from redrecon.modules.base import BaseModule

logger = get_logger()


class CertificateScanner(BaseModule):
    """
    Certificate Transparency Scanner.
    Queries public CT logs (crt.sh and CertSpotter) for certificates associated with target.
    Extracts Subject Alternative Names (SANs), cleans wildcards, and removes duplicates.
    """

    @property
    def name(self) -> str:
        return "Certificate Transparency"

    @property
    def description(self) -> str:
        return "Discovers certificates and subdomains via Certificate Transparency logs"

    async def scan(self, domain: str) -> Dict[str, Any]:
        logger.info(f"Querying Certificate Transparency logs for: [bold cyan]{domain}[/bold cyan]")
        discovered_hosts: Set[str] = set()
        certificates: List[Dict[str, Any]] = []

        # 1. Query crt.sh
        crt_hosts, crt_certs = await self._query_crtsh(domain)
        discovered_hosts.update(crt_hosts)
        certificates.extend(crt_certs)

        # 2. Query CertSpotter fallback if results are sparse
        if len(discovered_hosts) < 5:
            spotter_hosts, spotter_certs = await self._query_certspotter(domain)
            discovered_hosts.update(spotter_hosts)
            certificates.extend(spotter_certs)

        # Normalize hostnames
        normalized_hosts = self._normalize_hosts(discovered_hosts, domain)

        return {
            "target": domain,
            "total_certificates": len(certificates),
            "discovered_count": len(normalized_hosts),
            "certificates": certificates[:50],  # Keep sample of raw certs
            "subdomains": sorted(list(normalized_hosts)),
        }

    async def _query_crtsh(self, domain: str) -> tuple[Set[str], List[Dict[str, Any]]]:
        hosts: Set[str] = set()
        certs: List[Dict[str, Any]] = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with self.get_http_client(timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        for item in data:
                            name_value = item.get("name_value", "")
                            # name_value can contain multiple domains separated by newlines
                            for raw_name in name_value.split("\n"):
                                raw_name = raw_name.strip()
                                if raw_name:
                                    hosts.add(raw_name)

                            certs.append({
                                "id": item.get("id"),
                                "issuer_name": item.get("issuer_name"),
                                "common_name": item.get("common_name"),
                                "name_value": name_value,
                                "entry_timestamp": item.get("entry_timestamp"),
                                "not_before": item.get("not_before"),
                                "not_after": item.get("not_after"),
                            })
                    except json.JSONDecodeError:
                        logger.warning(f"crt.sh returned non-JSON response for {domain}")
        except Exception as e:
            logger.debug(f"crt.sh query encountered issue: {e}")

        return hosts, certs

    async def _query_certspotter(self, domain: str) -> tuple[Set[str], List[Dict[str, Any]]]:
        hosts: Set[str] = set()
        certs: List[Dict[str, Any]] = []
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"

        try:
            async with self.get_http_client(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data:
                        dns_names = item.get("dns_names", [])
                        for name in dns_names:
                            hosts.add(name.strip())
                        certs.append({
                            "id": item.get("id"),
                            "dns_names": dns_names,
                            "not_before": item.get("not_before"),
                            "not_after": item.get("not_after"),
                        })
        except Exception as e:
            logger.debug(f"Certspotter query encountered issue: {e}")

        return hosts, certs

    def _normalize_hosts(self, raw_hosts: Set[str], domain: str) -> Set[str]:
        cleaned = set()
        for host in raw_hosts:
            host = host.lower().strip()
            # Strip wildcard prefixes like *.
            if host.startswith("*."):
                host = host[2:]
            # Remove any trailing periods
            host = host.rstrip(".")
            # Ensure it is a subdomain or the target domain itself
            if host == domain or host.endswith(f".{domain}"):
                # Basic check for valid hostname chars
                if re.match(r"^[a-z0-9.-]+$", host):
                    cleaned.add(host)
        return cleaned
