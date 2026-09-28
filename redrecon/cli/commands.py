import asyncio
import os
import sys
from pathlib import Path
from typing import Optional
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
import typer

from redrecon.cli.banner import print_banner
from redrecon.core.config import ScanConfig, load_config
from redrecon.core.engine import ReconEngine
from redrecon.core.logger import console, error_console, setup_logger
from redrecon.models.scan import ScanMode, ScanResult
from redrecon.modules.certificate.scanner import CertificateScanner
from redrecon.modules.dns.scanner import DNSScanner
from redrecon.modules.headers.analyzer import HeaderAnalyzer
from redrecon.modules.http.scanner import HTTPScanner
from redrecon.modules.ip.scanner import IPScanner
from redrecon.modules.nmap.scanner import NmapScanner
from redrecon.modules.nuclei.scanner import NucleiScanner
from redrecon.modules.subdomain.scanner import SubdomainScanner
from redrecon.modules.wayback.scanner import WaybackScanner
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository

MODULE_LIST = [
    ("[01]", "Certificate Transparency", "Passive CT log enumeration (crt.sh, CertSpotter)"),
    ("[02]", "Subdomain Discovery", "Multi-source subdomain engine with 5+ providers"),
    ("[03]", "DNS Resolution", "A, AAAA, CNAME, MX, TXT, NS record resolution"),
    ("[04]", "IP Discovery", "Host -> IP correlation, PTR, and cloud network identification"),
    ("[05]", "HTTP/HTTPS Probe", "Async endpoint discovery with latency profiling"),
    ("[06]", "HTTP Title Detection", "HTML title tag extraction and sanitation"),
    ("[07]", "HTTP Status Detection", "HTTP response status & redirect chain tracking"),
    ("[08]", "Security Header Analysis", "Evaluation of HSTS, CSP, XFO, XCTO, and Permissions"),
    ("[09]", "Wayback URL Discovery", "Historical endpoint classification (API, Auth, Admin, etc.)"),
    ("[10]", "Nmap Port Scanner", "Nmap XML integration with native socket fallback"),
    ("[11]", "Nuclei Scanner", "Nuclei JSONL runner with heuristic exposure auditor"),
    ("[12]", "Report Generator", "Automated JSON tree and interactive HTML dashboard"),
]


def print_final_report_panel(scan: ScanResult, target_dir: str):
    """Prints the exact terminal summary card from Section 19."""
    started_str = scan.started_at.strftime("%H:%M:%S")
    completed_str = scan.completed_at.strftime("%H:%M:%S") if scan.completed_at else "-"

    summary_text = f"""
[bold red]Target[/bold red]              [white]{scan.target}[/white]
[bold red]Scan ID[/bold red]             [cyan]{scan.scan_id}[/cyan]
[bold red]Mode[/bold red]                [bold yellow]{scan.mode.value.upper()}[/bold yellow]
[bold red]Started[/bold red]             [white]{started_str}[/white]
[bold red]Completed[/bold red]           [white]{completed_str}[/white]

[bold underline bright_white]ATTACK SURFACE[/bold underline bright_white]

Subdomains                  [bold green]{scan.metrics.discovered_hosts}[/bold green]
Unique IPs                   [bold green]{scan.metrics.unique_ips}[/bold green]
HTTP services               [bold green]{scan.metrics.http_services}[/bold green]
Open TCP ports              [bold green]{scan.metrics.open_ports}[/bold green]
Historical URLs            [bold green]{scan.metrics.historical_urls}[/bold green]

[bold underline bright_white]SECURITY OBSERVATIONS[/bold underline bright_white]

Header observations          [bold yellow]{scan.metrics.header_observations}[/bold yellow]
Nuclei findings              [bold red]{scan.metrics.nuclei_findings}[/bold red]

[bold underline bright_white]DISCOVERY SOURCES[/bold underline bright_white]

Certificate Transparency    [cyan]{scan.metrics.sources_summary.get('Certificate Transparency', 0)}[/cyan]
DNS                         [cyan]{scan.metrics.sources_summary.get('DNS', 0)}[/cyan]
Wayback                     [cyan]{scan.metrics.sources_summary.get('Wayback', 0)}[/cyan]
HTTP                        [cyan]{scan.metrics.sources_summary.get('HTTP', 0)}[/cyan]
Nmap                         [cyan]{scan.metrics.sources_summary.get('Nmap', 0)}[/cyan]

[dim]Reports generated at:[/dim] [bold underline]{target_dir}[/bold underline]
"""
    panel = Panel(
        summary_text.strip(),
        title="[bold red]╔══ REDRECON REPORT ══╗[/bold red]",
        border_style="red",
        box=box.DOUBLE,
    )
    console.print()
    console.print(panel)
    console.print()


async def run_scan_command(
    domain: str,
    mode: str = "full",
    config_path: Optional[str] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[float] = None,
):
    print_banner()
    cfg = load_config(config_path)
    if concurrency:
        cfg.concurrency = concurrency
    if timeout:
        cfg.timeout = timeout

    scan_mode = ScanMode.PASSIVE if mode.lower() == "passive" else ScanMode.FULL

    engine = ReconEngine(cfg)
    try:
        scan_result = await engine.run_scan(domain, mode=scan_mode)
        target_dir = os.path.join(cfg.output_dir, domain)

        if scan_mode == ScanMode.PASSIVE:
            console.print("\n[bold red]PASSIVE RECON[/bold red]\n")
            console.print(f"[bold green][✓][/bold green] Certificate enumeration     [cyan]{scan_result.metrics.sources_summary.get('Certificate Transparency', 0)}[/cyan]")
            console.print(f"[bold green][✓][/bold green] Subdomain discovery         [cyan]{scan_result.metrics.discovered_hosts}[/cyan]")
            console.print(f"[bold green][✓][/bold green] Wayback URLs               [cyan]{scan_result.metrics.historical_urls}[/cyan]")
            console.print(f"[bold green][✓][/bold green] DNS records                 [cyan]{scan_result.metrics.sources_summary.get('DNS', 0)}[/cyan]")
            console.print(f"\nAssets discovered: [bold green]{scan_result.metrics.discovered_hosts}[/bold green]\n")
            console.print(f"Report generated:\n[bold cyan]{target_dir}/[/bold cyan]\n")
        else:
            print_final_report_panel(scan_result, target_dir)

    except Exception as e:
        error_console.print(f"[bold red]Scan failed:[/bold red] {e}")
        sys.exit(1)


def list_modules_command():
    print_banner()
    console.print("[bold red]AVAILABLE MODULES[/bold red]\n")
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Code", style="bold red")
    table.add_column("Module Name", style="bold white")
    table.add_column("Description", style="dim cyan")

    for code, name, desc in MODULE_LIST:
        table.add_row(code, name, desc)

    console.print(table)
    console.print()


async def run_cert_command(domain: str):
    print_banner()
    scanner = CertificateScanner()
    res = await scanner.scan(domain)
    subdomains = res.get("subdomains", [])

    console.print(f"\n[bold red]CERTIFICATE TRANSPARENCY[/bold red]\n")
    console.print(f"[bold white]{domain}[/bold white]")
    for s in subdomains[:15]:
        console.print(f"├── {s}")
    if len(subdomains) > 15:
        console.print(f"└── ... ({len(subdomains) - 15} more)")

    console.print(f"\nDiscovered: [bold green]{len(subdomains)}[/bold green]")
    console.print(f"Total certificates analyzed: [bold cyan]{res.get('total_certificates', 0)}[/bold cyan]\n")


async def run_subdomains_command(domain: str):
    print_banner()
    scanner = SubdomainScanner()
    res = await scanner.scan(domain)

    console.print(f"\n[bold red]SUBDOMAIN DISCOVERY[/bold red] - [bold cyan]{domain}[/bold cyan]\n")
    table = Table(title="Discovered Subdomains", box=box.ROUNDED)
    table.add_column("Hostname", style="bold white")
    table.add_column("Discovered By", style="cyan")

    provenance = res.get("provenance", {})
    for host in res.get("subdomains", []):
        srcs = ", ".join(provenance.get(host, ["Unknown"]))
        table.add_row(host, srcs)

    console.print(table)
    console.print(f"\nTotal unique: [bold green]{res.get('total_unique')}[/bold green] (Cross-source duplicates removed: {res.get('duplicates_removed')})\n")


async def run_dns_command(domain: str):
    print_banner()
    scanner = DNSScanner()
    res = await scanner.scan(domain)

    console.print(f"\n[bold red]DNS RECORDS[/bold red] - [bold cyan]{domain}[/bold cyan]\n")
    records = res.get("records", {})
    tree = Tree(f"[bold white]{domain}[/bold white]")
    for rtype, vals in records.items():
        if vals:
            r_branch = tree.add(f"[bold cyan]{rtype}[/bold cyan]")
            for v in vals:
                r_branch.add(f"[green]{v}[/green]")
        else:
            tree.add(f"[dim]{rtype}: (none)[/dim]")
    console.print(tree)
    console.print()


async def run_http_command(target: str):
    print_banner()
    scanner = HTTPScanner()
    res = await scanner.scan(target)
    svc = res.get("service")

    if not svc:
        console.print(f"[yellow]No active HTTP/HTTPS service detected on {target}[/yellow]")
        return

    console.print(f"\n[bold red]HTTP RECONNAISSANCE[/bold red]\n")
    console.print(f"[bold cyan]{svc.get('url')}[/bold cyan]\n")
    console.print(f"Status       : [bold green]{svc.get('status_code')}[/bold green]")
    console.print(f"Title        : [white]{svc.get('title') or '-'}[/white]")
    console.print(f"Server       : [cyan]{svc.get('server') or '-'}[/cyan]")
    console.print(f"Content-Type : [dim]{svc.get('content_type') or '-'}[/dim]")
    console.print(f"Response     : [yellow]{svc.get('response_time_ms')} ms[/yellow]")
    if svc.get("redirect_chain"):
        console.print(f"Redirects    : {' -> '.join(svc.get('redirect_chain'))}")
    console.print()


async def run_headers_command(target: str):
    print_banner()
    analyzer = HeaderAnalyzer()
    res = await analyzer.scan(target)

    console.print(f"\n[bold red]SECURITY HEADERS[/bold red] - [bold cyan]{target}[/bold cyan]\n")
    for obs in res.get("observations", []):
        header = obs.get("header")
        status = obs.get("status")
        if status == "PRESENT":
            console.print(f"[bold green]✓[/bold green] [white]{header}[/white]")
        elif status == "MISCONFIGURED":
            console.print(f"[bold yellow]⚠[/bold yellow] [yellow]{header}[/yellow] (Misconfigured: {obs.get('recommendation')})")
        else:
            console.print(f"[bold red]✗[/bold red] [dim]{header}[/dim] (Missing)")
    console.print("\n[dim]Note: Classified as defensive configuration observations.[/dim]\n")


async def run_wayback_command(domain: str):
    print_banner()
    scanner = WaybackScanner()
    res = await scanner.scan(domain)

    console.print(f"\n[bold red]WAYBACK DISCOVERY[/bold red] - [bold cyan]{domain}[/bold cyan]\n")
    summary = res.get("summary_by_category", {})
    for cat, count in summary.items():
        console.print(f"{cat:<18}: [bold green]{count}[/bold green]")

    console.print(f"\nTotal Records: [cyan]{res.get('total_records')}[/cyan] | Unique URLs: [bold green]{res.get('unique_count')}[/bold green]\n")


async def run_ports_command(target: str):
    print_banner()
    scanner = NmapScanner()
    res = await scanner.scan(target)

    console.print(f"\n[bold red]HOST: {target}[/bold red] (Engine: {res.get('engine')})\n")
    table = Table(box=box.ROUNDED)
    table.add_column("PORT", style="bold cyan")
    table.add_column("STATE", style="bold green")
    table.add_column("SERVICE", style="white")

    for p in res.get("ports", []):
        table.add_row(f"{p.get('port')}/{p.get('protocol')}", p.get("state"), p.get("service_name") or "-")

    console.print(table)
    console.print(f"\nTotal open ports: [bold green]{res.get('total_open_ports')}[/bold green]\n")


async def run_nuclei_command(target: str):
    print_banner()
    scanner = NucleiScanner()
    res = await scanner.scan(target)

    console.print(f"\n[bold red]SECURITY FINDINGS[/bold red] - [bold cyan]{target}[/bold cyan]\n")
    findings = res.get("findings", [])
    if not findings:
        console.print("[green]No candidate exposures or findings detected.[/green]\n")
        return

    table = Table(box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Finding Name", style="white")
    table.add_column("Target", style="dim")
    table.add_column("Evidence", style="cyan")

    for f in findings:
        sev = f.get("severity")
        style = "red" if sev in ("CRITICAL", "HIGH") else ("yellow" if sev == "MEDIUM" else "cyan")
        table.add_row(f"[{style}]{sev}[/{style}]", f.get("name"), f.get("target"), f.get("evidence") or "-")

    console.print(table)
    console.print()


async def run_diff_command(target_or_scan1: str, scan2: Optional[str] = None):
    print_banner()
    repo = ScanRepository(Database())

    if scan2:
        s1 = repo.get_scan(target_or_scan1)
        s2 = repo.get_scan(scan2)
        if not s1:
            console.print(f"[bold red]Scan not found:[/bold red] {target_or_scan1}")
            return
        if not s2:
            console.print(f"[bold red]Scan not found:[/bold red] {scan2}")
            return
    else:
        # Check if target_or_scan1 is a scan_id
        s2 = repo.get_scan(target_or_scan1)
        if s2:
            s1 = repo.get_previous_scan_for_target(s2.target, exclude_scan_id=s2.scan_id)
            if not s1:
                console.print(f"[yellow]Only one scan exists for target {s2.target}. Need at least two scans to compute drift.[/yellow]")
                return
        else:
            # Assume it's a domain/target
            target = target_or_scan1
            scans = [s for s in repo.list_scans(limit=10) if s["target"] == target]
            if len(scans) < 2:
                console.print(f"[yellow]Need at least two completed scans for '{target}' to compute attack-surface drift. Found: {len(scans)}[/yellow]")
                return
            s2 = repo.get_scan(scans[0]["scan_id"])  # most recent
            s1 = repo.get_scan(scans[1]["scan_id"])  # earlier scan

    from redrecon.intelligence.difference import AttackSurfaceDifferenceEngine
    diff = AttackSurfaceDifferenceEngine.compare_scans(s1, s2)
    diff_table = AttackSurfaceDifferenceEngine.render_rich_diff(diff)
    console.print()
    console.print(diff_table)
    console.print()
