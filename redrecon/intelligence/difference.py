from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from redrecon.models.asset import Asset
from redrecon.models.finding import Finding
from redrecon.models.scan import ScanResult


class AssetChange(BaseModel):
    hostname: str
    sources: List[str] = Field(default_factory=list)
    confidence: str = "LOW"
    priority_score: int = 0
    ip_addresses: List[str] = Field(default_factory=list)
    title: Optional[str] = None


class PortChange(BaseModel):
    hostname: str
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None


class HeaderDiff(BaseModel):
    hostname: str
    header: str
    old_status: str
    new_status: str


class AttackSurfaceDiff(BaseModel):
    target: str
    base_scan_id: str
    current_scan_id: str
    base_scan_time: datetime
    current_scan_time: datetime
    new_assets: List[AssetChange] = Field(default_factory=list)
    removed_assets: List[AssetChange] = Field(default_factory=list)
    persisted_assets_count: int = 0
    new_open_ports: List[PortChange] = Field(default_factory=list)
    closed_ports: List[PortChange] = Field(default_factory=list)
    new_findings: List[Finding] = Field(default_factory=list)
    resolved_findings: List[Finding] = Field(default_factory=list)
    changed_headers: List[HeaderDiff] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)


class AttackSurfaceDifferenceEngine:
    """
    Compares two scans to detect attack surface drift:
    - New vs removed subdomains/assets
    - Newly open vs closed service ports
    - Configuration changes in HTTP security headers
    - Newly discovered vs remediated security findings
    """

    @classmethod
    def compare_scans(cls, base_scan: ScanResult, current_scan: ScanResult) -> AttackSurfaceDiff:
        target = current_scan.target

        base_assets_by_host: Dict[str, Asset] = {a.hostname: a for a in base_scan.assets}
        curr_assets_by_host: Dict[str, Asset] = {a.hostname: a for a in current_scan.assets}

        base_hosts: Set[str] = set(base_assets_by_host.keys())
        curr_hosts: Set[str] = set(curr_assets_by_host.keys())

        # 1. New & Removed Assets
        new_hostnames = sorted(list(curr_hosts - base_hosts))
        removed_hostnames = sorted(list(base_hosts - curr_hosts))
        persisted_hosts = base_hosts & curr_hosts

        new_assets = [
            AssetChange(
                hostname=h,
                sources=curr_assets_by_host[h].sources,
                confidence=curr_assets_by_host[h].confidence.value,
                priority_score=curr_assets_by_host[h].priority_score,
                ip_addresses=curr_assets_by_host[h].ip_addresses,
                title=curr_assets_by_host[h].http_service.title if curr_assets_by_host[h].http_service else None,
            )
            for h in new_hostnames
        ]

        removed_assets = [
            AssetChange(
                hostname=h,
                sources=base_assets_by_host[h].sources,
                confidence=base_assets_by_host[h].confidence.value,
                priority_score=base_assets_by_host[h].priority_score,
                ip_addresses=base_assets_by_host[h].ip_addresses,
                title=base_assets_by_host[h].http_service.title if base_assets_by_host[h].http_service else None,
            )
            for h in removed_hostnames
        ]

        # 2. Port Changes
        new_open_ports: List[PortChange] = []
        closed_ports: List[PortChange] = []

        for host in persisted_hosts:
            base_ports = {p.port: p for p in base_assets_by_host[host].ports}
            curr_ports = {p.port: p for p in curr_assets_by_host[host].ports}

            for p_num in sorted(curr_ports.keys() - base_ports.keys()):
                p = curr_ports[p_num]
                new_open_ports.append(
                    PortChange(hostname=host, port=p.port, protocol=p.protocol, service_name=p.service_name)
                )

            for p_num in sorted(base_ports.keys() - curr_ports.keys()):
                p = base_ports[p_num]
                closed_ports.append(
                    PortChange(hostname=host, port=p.port, protocol=p.protocol, service_name=p.service_name)
                )

        # 3. Security Header Diffs
        changed_headers: List[HeaderDiff] = []
        for host in persisted_hosts:
            base_hdrs = {h.header: h.status for h in base_assets_by_host[host].security_headers}
            curr_hdrs = {h.header: h.status for h in curr_assets_by_host[host].security_headers}

            for hdr_name, curr_status in curr_hdrs.items():
                base_status = base_hdrs.get(hdr_name, "UNKNOWN")
                if base_status != curr_status and base_status != "UNKNOWN":
                    changed_headers.append(
                        HeaderDiff(
                            hostname=host,
                            header=hdr_name,
                            old_status=base_status,
                            new_status=curr_status,
                        )
                    )

        # 4. Finding Changes
        base_finding_keys = {f"{f.name}:{f.target}": f for f in base_scan.findings}
        curr_finding_keys = {f"{f.name}:{f.target}": f for f in current_scan.findings}

        new_findings = [curr_finding_keys[k] for k in sorted(curr_finding_keys.keys() - base_finding_keys.keys())]
        resolved_findings = [base_finding_keys[k] for k in sorted(base_finding_keys.keys() - curr_finding_keys.keys())]

        summary = {
            "new_assets": len(new_assets),
            "removed_assets": len(removed_assets),
            "persisted_assets": len(persisted_hosts),
            "new_open_ports": len(new_open_ports),
            "closed_ports": len(closed_ports),
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "changed_headers": len(changed_headers),
        }

        return AttackSurfaceDiff(
            target=target,
            base_scan_id=base_scan.scan_id,
            current_scan_id=current_scan.scan_id,
            base_scan_time=base_scan.started_at,
            current_scan_time=current_scan.started_at,
            new_assets=new_assets,
            removed_assets=removed_assets,
            persisted_assets_count=len(persisted_hosts),
            new_open_ports=new_open_ports,
            closed_ports=closed_ports,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            changed_headers=changed_headers,
            summary=summary,
        )

    @classmethod
    def render_rich_diff(cls, diff: AttackSurfaceDiff) -> Table:
        """Render a formatted comparison table for the Rich CLI."""
        table = Table(
            title=f"Attack Surface Drift: {diff.base_scan_id} -> {diff.current_scan_id}",
            header_style="bold red",
            border_style="red",
        )
        table.add_column("Category", style="cyan", width=22)
        table.add_column("Status / Delta", style="bold")
        table.add_column("Details", style="white")

        # Assets
        if diff.new_assets:
            names = ", ".join(a.hostname for a in diff.new_assets[:5])
            if len(diff.new_assets) > 5:
                names += f" (+{len(diff.new_assets) - 5} more)"
            table.add_row("[green]+ New Assets[/green]", f"[green]+{len(diff.new_assets)}[/green]", names)
        else:
            table.add_row("New Assets", "0", "No new assets discovered")

        if diff.removed_assets:
            names = ", ".join(a.hostname for a in diff.removed_assets[:5])
            if len(diff.removed_assets) > 5:
                names += f" (+{len(diff.removed_assets) - 5} more)"
            table.add_row("[red]- Removed Assets[/red]", f"[red]-{len(diff.removed_assets)}[/red]", names)
        else:
            table.add_row("Removed Assets", "0", "No assets removed")

        table.add_row("Persisted Assets", str(diff.persisted_assets_count), "Continuously verified assets")

        # Ports
        if diff.new_open_ports:
            ports_desc = ", ".join(f"{p.hostname}:{p.port}" for p in diff.new_open_ports[:5])
            table.add_row("[bold yellow]! New Open Ports[/bold yellow]", f"[yellow]+{len(diff.new_open_ports)}[/yellow]", ports_desc)
        if diff.closed_ports:
            ports_desc = ", ".join(f"{p.hostname}:{p.port}" for p in diff.closed_ports[:5])
            table.add_row("Closed Ports", f"-{len(diff.closed_ports)}", ports_desc)

        # Findings
        if diff.new_findings:
            f_desc = ", ".join(f.name for f in diff.new_findings[:3])
            table.add_row("[bold red]! New Findings[/bold red]", f"[red]+{len(diff.new_findings)}[/red]", f_desc)
        if diff.resolved_findings:
            f_desc = ", ".join(f.name for f in diff.resolved_findings[:3])
            table.add_row("[bold green]✓ Resolved Findings[/bold green]", f"[green]+{len(diff.resolved_findings)}[/green]", f_desc)

        # Headers
        if diff.changed_headers:
            h_desc = ", ".join(f"{h.hostname} ({h.header}: {h.old_status}->{h.new_status})" for h in diff.changed_headers[:2])
            table.add_row("Header Changes", str(len(diff.changed_headers)), h_desc)

        return table
