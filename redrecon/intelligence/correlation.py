from typing import Any, Dict, List, Optional, Set
from redrecon.intelligence.prioritization import AssetPrioritizer
from redrecon.models.asset import (
    Asset,
    AssetConfidence,
    DNSRecords,
    HeaderObservation,
    HTTPService,
    PortService,
)
from redrecon.models.finding import Finding


class AssetCorrelator:
    """
    Asset Intelligence & Correlation Engine.
    Correlates disparate recon observations (subdomains, DNS records, IP addresses,
    open ports, HTTP services, security headers, historical URLs, and findings)
    into a unified attack-surface model and relationship graph.
    """

    @classmethod
    def correlate_target_assets(
        cls,
        root_domain: str,
        discovered_hosts: List[str],
        provenance_map: Dict[str, List[str]],
        dns_results: Dict[str, Dict[str, Any]],
        http_results: Dict[str, Dict[str, Any]],
        headers_results: Dict[str, List[Dict[str, Any]]],
        ports_results: Dict[str, List[PortService]],
        wayback_urls: List[str],
        findings: List[Finding],
    ) -> List[Asset]:
        """
        Merge all scanner outputs into unified Asset models.
        """
        # Map historical URLs by hostname
        urls_by_host: Dict[str, List[str]] = {}
        for url in wayback_urls:
            try:
                from urllib.parse import urlparse
                host = urlparse(url).netloc.split(":")[0].lower()
                if host not in urls_by_host:
                    urls_by_host[host] = []
                urls_by_host[host].append(url)
            except Exception:
                pass

        # Map findings by target
        findings_by_host: Dict[str, List[Finding]] = {}
        for f in findings:
            target_norm = f.target.lower()
            # Match target to host
            matched_host = None
            for h in discovered_hosts:
                if h in target_norm:
                    matched_host = h
                    break
            if not matched_host:
                matched_host = root_domain

            if matched_host not in findings_by_host:
                findings_by_host[matched_host] = []
            findings_by_host[matched_host].append(f)

        assets: List[Asset] = []

        for host in discovered_hosts:
            sources = provenance_map.get(host, ["Discovery"])

            # 1. DNS records
            dns_data = dns_results.get(host, {}).get("records", {})
            dns_model = DNSRecords(
                A=dns_data.get("A", []),
                AAAA=dns_data.get("AAAA", []),
                CNAME=dns_data.get("CNAME", []),
                MX=dns_data.get("MX", []),
                TXT=dns_data.get("TXT", []),
                NS=dns_data.get("NS", []),
            )

            # IP addresses
            ip_addresses = dns_model.A + dns_model.AAAA

            # 2. HTTP service
            http_data = http_results.get(host)
            http_model: Optional[HTTPService] = None
            if http_data:
                http_model = HTTPService(
                    url=http_data.get("url", f"https://{host}"),
                    is_https=http_data.get("is_https", True),
                    status_code=http_data.get("status_code"),
                    title=http_data.get("title"),
                    server=http_data.get("server"),
                    content_type=http_data.get("content_type"),
                    response_time_ms=http_data.get("response_time_ms"),
                    redirect_url=http_data.get("redirect_url"),
                    redirect_chain=http_data.get("redirect_chain", []),
                    headers=http_data.get("headers", {}),
                )

            # 3. Open Ports
            ports_list = ports_results.get(host, [])

            # 4. Security Headers
            header_obs_raw = headers_results.get(host, [])
            header_obs = [HeaderObservation(**h) for h in header_obs_raw]

            # 5. Historical URLs
            historical = urls_by_host.get(host, [])

            # 6. Calculate Confidence
            confidence = AssetPrioritizer.calculate_confidence(
                sources=sources,
                dns_records=dns_model,
                http_service=http_model,
                ports=ports_list,
            )

            is_live = confidence in (AssetConfidence.HIGH, AssetConfidence.MEDIUM)

            tags = []
            if http_model and http_model.title:
                tags.append("web")
            if ports_list:
                tags.append("active-ports")
            if any(f.severity.value in ("HIGH", "CRITICAL") for f in findings_by_host.get(host, [])):
                tags.append("vulnerable")

            asset = Asset(
                hostname=host,
                root_domain=root_domain,
                ip_addresses=ip_addresses,
                sources=sources,
                dns_records=dns_model,
                http_service=http_model,
                ports=ports_list,
                historical_urls=historical[:100],  # Keep reasonable sample
                security_headers=header_obs,
                confidence=confidence,
                is_live=is_live,
                tags=tags,
            )
            assets.append(asset)

        return AssetPrioritizer.prioritize_assets(assets)

    @classmethod
    def generate_attack_surface_graph(cls, root_domain: str, assets: List[Asset]) -> Dict[str, Any]:
        """
        Builds a node-edge graph representation suitable for D3, React Flow, or Vis.js.
        """
        nodes = []
        edges = []
        seen_nodes: Set[str] = set()

        def _add_node(node_id: str, label: str, node_type: str, details: Dict[str, Any] = None):
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "details": details or {},
                })

        # 1. Root domain node
        root_id = f"root_{root_domain}"
        _add_node(root_id, root_domain, "root", {"domain": root_domain})

        for asset in assets:
            host_id = f"host_{asset.hostname}"
            _add_node(host_id, asset.hostname, "subdomain", {
                "confidence": asset.confidence.value,
                "is_live": asset.is_live,
                "sources": asset.sources,
            })
            if asset.hostname != root_domain:
                edges.append({"source": root_id, "target": host_id, "label": "subdomain"})

            # IPs
            for ip in asset.ip_addresses:
                ip_id = f"ip_{ip}"
                _add_node(ip_id, ip, "ip", {"ip": ip})
                edges.append({"source": host_id, "target": ip_id, "label": "resolves_to"})

                # Ports under IP
                for p in asset.ports:
                    port_id = f"port_{ip}_{p.port}"
                    _add_node(port_id, f"{p.port}/{p.service_name}", "port", {
                        "port": p.port,
                        "service": p.service_name,
                    })
                    edges.append({"source": ip_id, "target": port_id, "label": "exposes"})

            # HTTP Service under Host
            if asset.http_service:
                svc_id = f"http_{asset.hostname}"
                label = f"{asset.http_service.server or 'HTTP'} ({asset.http_service.status_code})"
                _add_node(svc_id, label, "http_service", {
                    "title": asset.http_service.title,
                    "server": asset.http_service.server,
                    "status": asset.http_service.status_code,
                })
                edges.append({"source": host_id, "target": svc_id, "label": "serves"})

        return {
            "root_domain": root_domain,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
