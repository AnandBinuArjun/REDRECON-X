from typing import Dict, List, Optional, Tuple
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

    ADMIN_KEYWORDS = {
        "admin", "administrator", "internal", "dev", "develop", "development",
        "stage", "staging", "api", "portal", "vpn", "test", "auth", "sso",
        "login", "corp", "jenkins", "gitlab", "jira", "gateway", "backend",
        "manage", "dashboard", "intranet", "db", "database", "kibana", "grafana"
    }

    @classmethod
    def calculate_priority_score(
        cls,
        asset: Asset,
        findings_count: int = 0,
    ) -> tuple[int, Dict[str, int]]:
        """
        Calculates transparent Attack Surface Priority based on Section 38 formula:
        Priority = internet exposure (+3)
                 + service exposure (+1)
                 + administrative context (+2)
                 + configuration observations (+1)
                 + validated scanner findings (+2)
        """
        breakdown: Dict[str, int] = {}

        # 1. Internet exposure (+3): Valid public IP or DNS A/AAAA records
        has_ips = bool(asset.ip_addresses or (asset.dns_records and (asset.dns_records.A or asset.dns_records.AAAA)))
        breakdown["internet_exposure"] = 3 if has_ips else 0

        # 2. Service exposure (+1): Active HTTP/HTTPS service or open TCP ports
        has_http = bool(asset.http_service and asset.http_service.status_code)
        has_ports = len(asset.ports) > 0
        breakdown["service_exposure"] = 1 if (has_http or has_ports) else 0

        # 3. Administrative context (+2): Sensitive keywords in hostname or HTML title
        host_parts = set(asset.hostname.lower().replace("-", ".").replace("_", ".").split("."))
        title_lower = (asset.http_service.title.lower() if asset.http_service and asset.http_service.title else "")
        title_words = set(title_lower.split())
        is_admin_ctx = bool(host_parts & cls.ADMIN_KEYWORDS or title_words & cls.ADMIN_KEYWORDS)
        breakdown["administrative_context"] = 2 if is_admin_ctx else 0

        # 4. Configuration observations (+1): Missing or misconfigured security headers
        has_config_gap = any(obs.status in ("MISSING", "MISCONFIGURED") for obs in asset.security_headers)
        breakdown["configuration_observations"] = 1 if has_config_gap else 0

        # 5. Scanner findings (+2): Validated candidate vulnerabilities
        breakdown["scanner_findings"] = 2 if findings_count > 0 else 0

        total_priority = sum(breakdown.values())
        return total_priority, breakdown

    @classmethod
    def prioritize_assets(
        cls,
        assets: List[Asset],
        findings_map: Optional[Dict[str, int]] = None,
    ) -> List[Asset]:
        """
        Calculate priority score for each asset and sort by priority score descending.
        """
        findings_map = findings_map or {}
        for a in assets:
            f_count = findings_map.get(a.hostname, 0)
            score, breakdown = cls.calculate_priority_score(a, findings_count=f_count)
            a.priority_score = score
            a.priority_breakdown = breakdown

        def _sort_key(a: Asset):
            conf_val = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(a.confidence.value, 0)
            return (a.priority_score, conf_val, len(a.ports), len(a.historical_urls))

        return sorted(assets, key=_sort_key, reverse=True)
