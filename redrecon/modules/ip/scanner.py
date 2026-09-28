import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Set
import dns.asyncresolver
import dns.reversename
from redrecon.core.logger import get_logger
from redrecon.modules.base import BaseModule

logger = get_logger()

# Known CDN/Cloud IP ranges or identifiers
CLOUD_PROVIDERS = {
    "cloudflare": ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"],
    "fastly": ["151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16"],
}


class IPScanner(BaseModule):
    """
    IP Discovery and Correlation Module.
    Extracts unique IPs, resolves reverse PTR records, and tags cloud infrastructure.
    """

    @property
    def name(self) -> str:
        return "IP Discovery"

    @property
    def description(self) -> str:
        return "Host-to-IP correlation, reverse DNS (PTR), and network classification"

    async def get_ptr(self, ip_str: str) -> Optional[str]:
        """Perform reverse DNS lookup asynchronously."""
        try:
            rev_name = dns.reversename.from_address(ip_str)
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout
            answer = await resolver.resolve(rev_name, "PTR")
            for rdata in answer:
                return str(rdata).rstrip(".")
        except Exception:
            pass
        return None

    def detect_cloud_provider(self, ip_str: str) -> Optional[str]:
        """Identify known CDN/Cloud IP ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for provider, cidrs in CLOUD_PROVIDERS.items():
                for cidr in cidrs:
                    if ip_obj in ipaddress.ip_network(cidr):
                        return provider
        except Exception:
            pass
        return None

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except Exception:
            return False

    async def correlate_ips(self, host_dns_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Takes DNS results map {host: {records: {A: [...], AAAA: [...]}}}
        and produces correlated IP inventory.
        """
        logger.info("Correlating IP addresses and resolving PTR records...")
        ip_to_hosts: Dict[str, Set[str]] = {}
        host_to_ips: Dict[str, List[str]] = {}

        for host, data in host_dns_map.items():
            records = data.get("records", {})
            ips = records.get("A", []) + records.get("AAAA", [])
            host_to_ips[host] = ips
            for ip in ips:
                if ip not in ip_to_hosts:
                    ip_to_hosts[ip] = set()
                ip_to_hosts[ip].add(host)

        unique_ips = sorted(list(ip_to_hosts.keys()))
        logger.info(f"Identified [bold green]{len(unique_ips)}[/bold green] unique IP addresses")

        # Resolve PTRs concurrently
        ip_details: Dict[str, Dict[str, Any]] = {}
        sem = asyncio.Semaphore(self.config.concurrency)

        async def _inspect_ip(ip: str):
            async with sem:
                ptr = await self.get_ptr(ip)
                cloud = self.detect_cloud_provider(ip)
                is_priv = self.is_private_ip(ip)
                ip_details[ip] = {
                    "ip": ip,
                    "associated_hosts": sorted(list(ip_to_hosts.get(ip, []))),
                    "ptr": ptr,
                    "cloud_provider": cloud,
                    "is_private": is_priv,
                }

        await asyncio.gather(*[_inspect_ip(ip) for ip in unique_ips], return_exceptions=True)

        return {
            "unique_ip_count": len(unique_ips),
            "unique_ips": unique_ips,
            "ip_inventory": ip_details,
            "host_to_ips": host_to_ips,
        }
