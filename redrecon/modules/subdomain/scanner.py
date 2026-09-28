import asyncio
from typing import Any, Dict, List, Set
from redrecon.core.logger import get_logger
from redrecon.modules.base import BaseModule
from redrecon.modules.subdomain.providers import (
    AlienVaultProvider,
    AnubisProvider,
    CertificateProvider,
    DiscoveryProvider,
    DNSBruteProvider,
    HackerTargetProvider,
    WaybackSubdomainProvider,
)

logger = get_logger()


class SubdomainScanner(BaseModule):
    """
    Multi-source subdomain discovery engine.
    Orchestrates multiple independent passive and active providers,
    normalizes output, tracks provenance, and deduplicates assets.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.providers: List[DiscoveryProvider] = [
            CertificateProvider(),
            WaybackSubdomainProvider(),
            AlienVaultProvider(),
            HackerTargetProvider(),
            AnubisProvider(),
        ]
        if self.config.enable_bruteforce:
            self.providers.append(
                DNSBruteProvider(concurrency=self.config.concurrency)
            )

    @property
    def name(self) -> str:
        return "Subdomain Discovery"

    @property
    def description(self) -> str:
        return "Multi-source enumeration combining CT logs, archives, threat feeds, and DNS probing"

    async def scan(self, domain: str) -> Dict[str, Any]:
        logger.info(f"Starting multi-source subdomain discovery for: [bold cyan]{domain}[/bold cyan]")
        results_by_provider: Dict[str, List[str]] = {}
        subdomain_sources: Dict[str, Set[str]] = {}
        all_discovered: Set[str] = set()
        total_raw_findings = 0

        async def _run_provider(provider: DiscoveryProvider):
            nonlocal total_raw_findings
            try:
                hosts = await provider.discover(domain)
                logger.debug(f"Provider {provider.name} found {len(hosts)} subdomains")
                results_by_provider[provider.name] = sorted(list(hosts))
                total_raw_findings += len(hosts)
                for h in hosts:
                    if h not in subdomain_sources:
                        subdomain_sources[h] = set()
                    subdomain_sources[h].add(provider.name)
                    all_discovered.add(h)
            except Exception as e:
                logger.debug(f"Provider {provider.name} error: {e}")
                results_by_provider[provider.name] = []

        await asyncio.gather(*[_run_provider(p) for p in self.providers])

        # Always include the root domain itself
        all_discovered.add(domain)
        if domain not in subdomain_sources:
            subdomain_sources[domain] = {"Target Scope"}
        else:
            subdomain_sources[domain].add("Target Scope")

        unique_subdomains = sorted(list(all_discovered))
        duplicates_removed = max(0, total_raw_findings - len(unique_subdomains))

        logger.info(
            f"Subdomain discovery complete: [bold green]{len(unique_subdomains)}[/bold green] unique "
            f"(deduplicated {duplicates_removed} cross-source overlaps)"
        )

        return {
            "target": domain,
            "total_unique": len(unique_subdomains),
            "duplicates_removed": duplicates_removed,
            "subdomains": unique_subdomains,
            "sources_breakdown": {p: len(hosts) for p, hosts in results_by_provider.items()},
            "provenance": {h: sorted(list(srcs)) for h, srcs in subdomain_sources.items()},
        }
