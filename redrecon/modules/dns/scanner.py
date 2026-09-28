import asyncio
from typing import Any, Dict, List, Optional
import dns.asyncresolver
import dns.resolver
from redrecon.core.logger import get_logger
from redrecon.models.asset import DNSRecords
from redrecon.modules.base import BaseModule

logger = get_logger()


class DNSScanner(BaseModule):
    """
    DNS Resolution Module.
    Resolves A, AAAA, CNAME, MX, TXT, and NS records for discovered hostnames.
    Handles resolution failures, timeouts, and multi-record responses.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.record_types = self.config.dns_record_types

    @property
    def name(self) -> str:
        return "DNS Resolution"

    @property
    def description(self) -> str:
        return "Resolves A, AAAA, CNAME, MX, TXT, and NS records with dnspython"

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver()
        if self.config.dns_resolvers:
            resolver.nameservers = self.config.dns_resolvers
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout * 1.5
        return resolver

    async def resolve_host(self, host: str) -> Dict[str, Any]:
        """Resolve all configured DNS records for a single host."""
        resolver = self._get_resolver()
        records: Dict[str, List[str]] = {rtype: [] for rtype in self.record_types}
        is_live = False

        for rtype in self.record_types:
            try:
                answer = await resolver.resolve(host, rtype)
                for rdata in answer:
                    val = str(rdata).rstrip(".")
                    records[rtype].append(val)
                    if rtype in ("A", "AAAA"):
                        is_live = True
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.resolver.LifetimeTimeout,
            ):
                continue
            except Exception as e:
                logger.debug(f"DNS error resolving {rtype} for {host}: {e}")
                continue

        # If CNAME exists, consider host resolved
        if records.get("CNAME"):
            is_live = True

        return {
            "hostname": host,
            "is_resolved": is_live,
            "records": records,
        }

    async def scan_hosts(self, hosts: List[str]) -> Dict[str, Dict[str, Any]]:
        """Resolve DNS for a list of hosts concurrently with a semaphore."""
        logger.info(f"Resolving DNS records for [bold cyan]{len(hosts)}[/bold cyan] hosts...")
        sem = asyncio.Semaphore(self.config.concurrency)
        results: Dict[str, Dict[str, Any]] = {}

        async def _worker(host: str):
            async with sem:
                res = await self.resolve_host(host)
                results[host] = res

        await asyncio.gather(*[_worker(h) for h in hosts], return_exceptions=True)

        resolved_count = sum(1 for r in results.values() if r.get("is_resolved"))
        logger.info(
            f"DNS resolution finished: [bold green]{resolved_count}/{len(hosts)}[/bold green] hosts resolved"
        )
        return results

    async def scan(self, domain: str) -> Dict[str, Any]:
        """Single domain scan convenience method."""
        res = await self.resolve_host(domain)
        return {
            "target": domain,
            "results": {domain: res},
            "records": res["records"],
            "is_resolved": res["is_resolved"],
        }
