import json
import os
from pathlib import Path
from typing import Any, Dict
from redrecon.core.logger import get_logger
from redrecon.models.scan import ScanResult

logger = get_logger()


class JSONReporter:
    """
    Generates structured, machine-readable JSON outputs conforming to the exact
    directory structure outlined in Section 18.
    """

    @classmethod
    def export(cls, scan: ScanResult, base_dir: str = "reports") -> str:
        """
        Exports reports/{target}/ organized directory structure:
        - scan.json
        - summary.json
        - passive/certificates.json, subdomains.json, wayback.json, dns.json
        - active/http.json, headers.json, nmap.json
        - nuclei/findings.json
        """
        target_dir = Path(base_dir) / scan.target
        passive_dir = target_dir / "passive"
        active_dir = target_dir / "active"
        nuclei_dir = target_dir / "nuclei"

        for d in [passive_dir, active_dir, nuclei_dir]:
            d.mkdir(parents=True, exist_ok=True)

        raw = scan.raw_data

        # 1. scan.json (Complete unified scan)
        with open(target_dir / "scan.json", "w", encoding="utf-8") as f:
            f.write(scan.model_dump_json(indent=2))

        # 2. summary.json
        summary_data = {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "mode": scan.mode.value,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_sec": scan.metrics.scan_duration_sec,
            "attack_surface": {
                "discovered_hosts": scan.metrics.discovered_hosts,
                "live_hosts": scan.metrics.live_hosts,
                "unique_ips": scan.metrics.unique_ips,
                "http_services": scan.metrics.http_services,
                "open_ports": scan.metrics.open_ports,
                "historical_urls": scan.metrics.historical_urls,
            },
            "security_observations": {
                "header_observations": scan.metrics.header_observations,
                "nuclei_findings": scan.metrics.nuclei_findings,
            },
            "discovery_sources": scan.metrics.sources_summary,
        }
        with open(target_dir / "summary.json", "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        # 3. Passive reports
        with open(passive_dir / "certificates.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("certificates", {}), f, indent=2)

        with open(passive_dir / "subdomains.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("subdomains", {}), f, indent=2)

        with open(passive_dir / "wayback.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("wayback", {}), f, indent=2)

        with open(passive_dir / "dns.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("dns", {}), f, indent=2)

        # 4. Active reports
        with open(active_dir / "http.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("http", {}), f, indent=2)

        with open(active_dir / "headers.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("headers", {}), f, indent=2)

        with open(active_dir / "nmap.json", "w", encoding="utf-8") as f:
            json.dump(raw.get("nmap", {}), f, indent=2)

        # 5. Nuclei reports
        with open(nuclei_dir / "findings.json", "w", encoding="utf-8") as f:
            findings_data = [f.model_dump() for f in scan.findings]
            json.dump(findings_data, f, indent=2)

        logger.info(f"Organized JSON evidence saved to: [bold green]{target_dir}[/bold green]")
        return str(target_dir)
