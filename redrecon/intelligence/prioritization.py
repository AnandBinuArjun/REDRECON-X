from typing import List, Optional
from redrecon.models.asset import Asset, AssetConfidence, DNSRecords, HTTPService, PortService


class AssetPrioritizer:
    """
    Computes confidence ratings and priority scores for discovered assets.
    Distinguishes live assets from historical/unresolved artifacts.
    """

    @staticmethod
    def calculate_confidence(
        sources: List[str],
        dns_records: Optional[DNSRecords] = None,
        http_service: Optional[HTTPService] = None,
        ports: Optional[List[PortService]] = None,
    ) -> AssetConfidence:
        """
        Calculates confidence score based on multi-source evidence:
        - HIGH: Confirmed live (Active HTTP response or open ports or multiple corroborating sources + DNS)
        - MEDIUM: Confirmed in DNS (has A/AAAA or CNAME) but no active HTTP or open ports detected yet
        - LOW: Historical discovery (e.g. crt.sh or Wayback only) that failed DNS resolution
        """
        has_ips = bool(dns_records and (dns_records.A or dns_records.AAAA))
        has_cname = bool(dns_records and dns_records.CNAME)
        is_dns_live = has_ips or has_cname

        has_http = http_service is not None and http_service.status_code is not None
        has_ports = bool(ports and len(ports) > 0)

        # High confidence if verified live through active service or port
        if has_http or has_ports:
            return AssetConfidence.HIGH

        # Medium confidence if resolved in DNS
        if is_dns_live:
            # If confirmed by 3+ independent sources, elevate
            if len(sources) >= 3:
                return AssetConfidence.HIGH
            return AssetConfidence.MEDIUM

        # Otherwise Low (e.g. historical unresolving subdomain)
        return AssetConfidence.LOW

    @staticmethod
    def prioritize_assets(assets: List[Asset]) -> List[Asset]:
        """
        Sort assets by confidence (HIGH -> MEDIUM -> LOW) and presence of findings/ports.
        """
        def _sort_key(a: Asset):
            conf_score = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(a.confidence.value, 0)
            ports_count = len(a.ports)
            urls_count = len(a.historical_urls)
            return (conf_score, ports_count, urls_count)

        return sorted(assets, key=_sort_key, reverse=True)
