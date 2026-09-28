import asyncio
import os
import webbrowser
from typing import Optional
import typer

from redrecon.cli.banner import print_banner
from redrecon.cli.commands import (
    list_modules_command,
    run_cert_command,
    run_diff_command,
    run_dns_command,
    run_headers_command,
    run_http_command,
    run_nuclei_command,
    run_ports_command,
    run_scan_command,
    run_subdomains_command,
    run_wayback_command,
)
from redrecon.core.logger import console, init_error_tracking

# Initialize error tracking if SENTRY_DSN is configured
init_error_tracking()

app = typer.Typer(
    name="redrecon",
    help="REDRECON-X — Automated Web Reconnaissance & Attack-Surface Intelligence Framework",
    add_completion=False,
    no_args_is_help=True,
)


@app.command("scan", help="Run comprehensive attack-surface reconnaissance against an authorized target.")
def scan(
    target: str = typer.Argument(..., help="Authorized target domain or IP (e.g. example.com)"),
    mode: str = typer.Option("full", "--mode", "-m", help="Reconnaissance mode: 'full' or 'passive'"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to custom configuration YAML"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-t", help="Max concurrent workers"),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Network timeout in seconds"),
):
    asyncio.run(run_scan_command(target, mode=mode, config_path=config, concurrency=concurrency, timeout=timeout))


@app.command("full", help="Run full reconnaissance pipeline (Active + Passive + Nmap + Nuclei).")
def full_cmd(
    target: str = typer.Argument(..., help="Authorized target domain or IP (e.g. example.com)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to custom configuration YAML"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-t", help="Max concurrent workers"),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Network timeout in seconds"),
):
    asyncio.run(run_scan_command(target, mode="full", config_path=config, concurrency=concurrency, timeout=timeout))


@app.command("passive", help="Run passive-only reconnaissance pipeline (CT + Subdomains + Wayback + DNS).")
def passive_cmd(
    target: str = typer.Argument(..., help="Authorized target domain or IP (e.g. example.com)"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to custom configuration YAML"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-t", help="Max concurrent workers"),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Network timeout in seconds"),
):
    asyncio.run(run_scan_command(target, mode="passive", config_path=config, concurrency=concurrency, timeout=timeout))


@app.command("modules", help="List all 12 discovery, scanning, and correlation modules.")
def modules():
    list_modules_command()


@app.command("cert", help="Query Certificate Transparency logs for domain certificates & SANs.")
def cert(target: str = typer.Argument(..., help="Target domain")):
    asyncio.run(run_cert_command(target))


@app.command("subdomains", help="Multi-source subdomain discovery with cross-source deduplication.")
def subdomains(target: str = typer.Argument(..., help="Target domain")):
    asyncio.run(run_subdomains_command(target))


@app.command("dns", help="Resolve DNS records (A, AAAA, CNAME, MX, TXT, NS).")
def dns_cmd(target: str = typer.Argument(..., help="Target domain")):
    asyncio.run(run_dns_command(target))


@app.command("http", help="Probe HTTP/HTTPS endpoints, detect titles, server banners, and latency.")
def http_cmd(target: str = typer.Argument(..., help="Target domain or host")):
    asyncio.run(run_http_command(target))


@app.command("headers", help="Analyze defensive security headers (HSTS, CSP, XFO, Referrer, Permissions).")
def headers_cmd(target: str = typer.Argument(..., help="Target domain or URL")):
    asyncio.run(run_headers_command(target))


@app.command("wayback", help="Query Internet Archive Wayback Machine CDX API for historical URLs.")
def wayback_cmd(target: str = typer.Argument(..., help="Target domain")):
    asyncio.run(run_wayback_command(target))


@app.command("ports", help="Scan top ports and fingerprint services (Nmap XML / Native Socket).")
def ports_cmd(target: str = typer.Argument(..., help="Target domain or IP")):
    asyncio.run(run_ports_command(target))


@app.command("nuclei", help="Run security audit and candidate vulnerability checks.")
def nuclei_cmd(target: str = typer.Argument(..., help="Target URL or host")):
    asyncio.run(run_nuclei_command(target))


@app.command("dashboard", help="Start the interactive Web Dashboard and REST API.")
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Port number"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open browser on start"),
):
    print_banner()
    from redrecon.dashboard.app import start_dashboard
    if open_browser:
        webbrowser.open(f"http://{host}:{port}")
    start_dashboard(host=host, port=port)


@app.command("diff", help="Compute attack-surface drift between two scans or the latest two scans of a target.")
def diff_cmd(
    target_or_scan1: str = typer.Argument(..., help="Target domain (e.g. example.com) or base scan ID"),
    scan2: Optional[str] = typer.Argument(None, help="Optional comparison scan ID (e.g. RX-20260928-123456)"),
):
    asyncio.run(run_diff_command(target_or_scan1, scan2))


@app.command("report", help="Locate and open generated HTML reports for a target.")
def report_cmd(
    target: str = typer.Argument(..., help="Target domain"),
    report_type: str = typer.Option("all", "--type", "-t", help="Report view: 'all', 'executive', or 'technical'"),
):
    filename = "report.html"
    if report_type == "executive":
        filename = "executive_report.html"
    elif report_type == "technical":
        filename = "technical_report.html"

    path = os.path.join("reports", target, filename)
    if os.path.exists(path):
        console.print(f"[bold green]Opening {report_type.upper()} HTML report:[/bold green] {path}")
        webbrowser.open(f"file://{os.path.abspath(path)}")
    else:
        console.print(f"[bold red]Report not found:[/bold red] {path}. Run 'redrecon scan {target}' first.")


def main():
    app()


if __name__ == "__main__":
    main()
