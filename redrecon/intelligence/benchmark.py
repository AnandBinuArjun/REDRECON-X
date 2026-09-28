import asyncio
import csv
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from rich import box
from rich.panel import Panel
from rich.table import Table

from redrecon.core.config import ScanConfig, load_config
from redrecon.core.logger import console, get_logger
from redrecon.core.scope import ScopeValidator
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.intelligence.deduplication import AssetDeduplicator
from redrecon.modules.certificate.scanner import CertificateScanner
from redrecon.modules.dns.scanner import DNSScanner
from redrecon.modules.http.scanner import HTTPScanner
from redrecon.modules.subdomain.scanner import SubdomainScanner
from redrecon.modules.wayback.scanner import WaybackScanner

logger = get_logger()


class BenchmarkMetrics(BaseModel):
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    single_source_ct_count: int = 0
    provider_breakdown: Dict[str, int] = Field(default_factory=dict)
    raw_discoveries: int = 0
    unique_assets: int = 0
    duplicates_removed: int = 0
    deduplication_rate_pct: float = 0.0
    dns_verified_hosts: int = 0
    http_verified_hosts: int = 0
    verification_ratio_pct: float = 0.0
    coverage_gain_pct: float = 0.0
    total_duration_sec: float = 0.0
    graph_nodes: int = 0
    graph_edges: int = 0


class BenchmarkEngine:
    """
    Academic Evaluation & Benchmark Engine.
    Executes comparative experiments to measure:
    1. Multi-source coverage gain vs single-source CT
    2. Exact cross-feed duplicate removal rate
    3. Verification ratio (Discovered vs Live HTTP services)
    4. Execution performance and graph complexity metrics
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or load_config()

    async def run_benchmark(self, target: str) -> BenchmarkMetrics:
        start_time = time.perf_counter()
        norm_target = ScopeValidator.normalize_host(target)

        logger.info(f"Initiating academic benchmark evaluation for [bold cyan]{norm_target}[/bold cyan]...")

        cert_scanner = CertificateScanner(self.config)
        sub_scanner = SubdomainScanner(self.config)
        wb_scanner = WaybackScanner(self.config)
        dns_scanner = DNSScanner(self.config)
        http_scanner = HTTPScanner(self.config)

        # 1. Measure Single-Source Baseline (CT alone)
        ct_task = cert_scanner.scan(norm_target)
        wb_task = wb_scanner.scan(norm_target)
        sub_task = sub_scanner.scan(norm_target)

        ct_res, wb_res, sub_res = await asyncio.gather(ct_task, wb_task, sub_task)

        ct_subs = ct_res.get("subdomains", [])
        ct_count = len(set(s.lower() for s in ct_subs))

        # Provider Breakdown
        breakdown: Dict[str, int] = {
            "Certificate Transparency": len(ct_subs),
            "Wayback Archive": len(wb_res.get("subdomains", [])),
        }

        # Merge provider counts from subdomain module
        for prov_name, prov_hosts in sub_res.get("providers", {}).items():
            breakdown[prov_name.capitalize()] = len(prov_hosts)

        raw_total = sum(breakdown.values())

        # Collect all raw hostnames
        all_raw = list(ct_subs) + list(wb_res.get("subdomains", [])) + list(sub_res.get("subdomains", []))
        dedup_hosts, prov_map, dup_count = AssetDeduplicator.deduplicate_with_provenance(all_raw, "Discovery")

        scope_validator = ScopeValidator(
            target_domain=norm_target,
            allowed_domains=self.config.allowed_domains,
            excluded_domains=self.config.excluded_domains,
            allow_third_party=self.config.allow_third_party,
        )
        scoped_hosts = scope_validator.filter_scoped_hosts(dedup_hosts)
        unique_count = len(scoped_hosts)

        # 2. DNS Verification
        dns_res = await dns_scanner.scan_hosts(scoped_hosts)
        dns_verified = sum(
            1 for h, r in dns_res.items()
            if r.get("records", {}).get("A") or r.get("records", {}).get("AAAA") or r.get("records", {}).get("CNAME")
        )

        live_dns_hosts = [
            h for h, r in dns_res.items()
            if r.get("records", {}).get("A") or r.get("records", {}).get("AAAA") or r.get("records", {}).get("CNAME")
        ]

        # 3. HTTP Live Verification
        candidate_http = live_dns_hosts[:self.config.max_http_targets]
        http_res = await http_scanner.scan_hosts(candidate_http)
        http_verified = sum(1 for h, s in http_res.items() if s.get("status_code") is not None)

        total_duration = round(time.perf_counter() - start_time, 2)

        # Rates & Metrics
        dedup_rate = round((dup_count / raw_total * 100), 2) if raw_total > 0 else 0.0
        verif_ratio = round((http_verified / unique_count * 100), 2) if unique_count > 0 else 0.0
        gain_pct = round(((unique_count - ct_count) / max(ct_count, 1) * 100), 2)

        # Correlation topology metrics
        prov_dict = {h: list(srcs) for h, srcs in prov_map.items()}
        assets = AssetCorrelator.correlate_target_assets(
            root_domain=norm_target,
            discovered_hosts=scoped_hosts,
            provenance_map=prov_dict,
            dns_results=dns_res,
            http_results=http_res,
            headers_results={},
            ports_results={},
            wayback_urls=wb_res.get("urls", []),
            findings=[],
        )
        graph = AssetCorrelator.generate_attack_surface_graph(norm_target, assets)

        metrics = BenchmarkMetrics(
            target=norm_target,
            single_source_ct_count=ct_count,
            provider_breakdown=breakdown,
            raw_discoveries=raw_total,
            unique_assets=unique_count,
            duplicates_removed=dup_count,
            deduplication_rate_pct=dedup_rate,
            dns_verified_hosts=dns_verified,
            http_verified_hosts=http_verified,
            verification_ratio_pct=verif_ratio,
            coverage_gain_pct=gain_pct,
            total_duration_sec=total_duration,
            graph_nodes=graph.get("total_nodes", 0),
            graph_edges=graph.get("total_edges", 0),
        )

        self._export_benchmark_artifacts(metrics)
        return metrics

    def _export_benchmark_artifacts(self, m: BenchmarkMetrics) -> None:
        """Exports benchmark.json, benchmark.csv, and benchmark.html."""
        bench_dir = Path(self.config.output_dir) / m.target / "benchmark"
        bench_dir.mkdir(parents=True, exist_ok=True)

        # 1. JSON
        json_path = bench_dir / "benchmark.json"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(m.model_dump_json(indent=2))

        # 2. CSV
        csv_path = bench_dir / "benchmark.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value", "Description"])
            writer.writerow(["Target", m.target, "Domain evaluated"])
            writer.writerow(["Raw Discoveries", m.raw_discoveries, "Total asset records before deduplication"])
            writer.writerow(["Unique Assets", m.unique_assets, "Distinct hostnames normalized"])
            writer.writerow(["Duplicates Removed", m.duplicates_removed, "Redundant records eliminated"])
            writer.writerow(["Deduplication Rate (%)", f"{m.deduplication_rate_pct}%", "Percentage of duplicate noise removed"])
            writer.writerow(["DNS Verified", m.dns_verified_hosts, "Hosts with live A/AAAA/CNAME records"])
            writer.writerow(["HTTP Verified", m.http_verified_hosts, "Confirmed responsive web endpoints"])
            writer.writerow(["Verification Ratio (%)", f"{m.verification_ratio_pct}%", "Live endpoints vs discovered assets"])
            writer.writerow(["Multi-Source Gain (%)", f"{m.coverage_gain_pct}%", "Asset coverage increase over CT alone"])
            writer.writerow(["Total Duration (s)", f"{m.total_duration_sec}s", "Complete experiment runtime"])
            writer.writerow(["Graph Nodes", m.graph_nodes, "Correlated entities in topology"])
            writer.writerow(["Graph Relationships", m.graph_edges, "Cross-entity graph connections"])

        # 3. HTML Academic Report with Charts
        html_path = bench_dir / "benchmark.html"
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>REDRECON-X Empirical Benchmark — {m.target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{ font-family: -apple-system, sans-serif; background: #090d16; color: #f3f4f6; padding: 32px; max-width: 1100px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #ef4444; padding-bottom: 16px; margin-bottom: 24px; }}
    h1 {{ color: #fff; margin-bottom: 4px; }}
    h1 span {{ color: #ef4444; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; text-align: center; }}
    .val {{ font-size: 32px; font-weight: 800; color: #ef4444; }}
    .lbl {{ font-size: 12px; color: #9ca3af; text-transform: uppercase; margin-top: 4px; }}
    .chart-container {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #1f2937; text-align: left; }}
    th {{ color: #9ca3af; font-size: 12px; text-transform: uppercase; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>REDRECON-<span>X</span> Empirical Research Evaluation</h1>
    <p style="color:#9ca3af;">Target: <strong>{m.target}</strong> | Timestamp: {m.timestamp.isoformat()} | Evaluation Engine v1.0.0</p>
  </div>

  <div class="grid">
    <div class="card"><div class="val">{m.raw_discoveries}</div><div class="lbl">Raw Observations</div></div>
    <div class="card"><div class="val" style="color:#10b981;">{m.unique_assets}</div><div class="lbl">Normalized Assets</div></div>
    <div class="card"><div class="val" style="color:#06b6d4;">{m.deduplication_rate_pct}%</div><div class="lbl">Deduplication Rate</div></div>
    <div class="card"><div class="val" style="color:#f59e0b;">+{m.coverage_gain_pct}%</div><div class="lbl">Multi-Source Gain</div></div>
  </div>

  <div class="chart-container">
    <h3 style="color:#fff; margin-bottom: 16px;">Provider Distribution vs Verification Yield</h3>
    <canvas id="yieldChart" style="max-height: 320px;"></canvas>
  </div>

  <div class="chart-container">
    <h3 style="color:#fff; margin-bottom: 16px;">Experimental Metrics Table</h3>
    <table>
      <thead><tr><th>Metric</th><th>Observation</th><th>Formula / Derivation</th></tr></thead>
      <tbody>
        <tr><td><strong>Coverage Gain</strong></td><td><strong style="color:#10b981;">+{m.coverage_gain_pct}%</strong></td><td><code>(Unique - CT_Baseline) / CT_Baseline</code></td></tr>
        <tr><td><strong>Deduplication Rate</strong></td><td><strong>{m.deduplication_rate_pct}%</strong></td><td><code>Duplicates_Removed / Raw_Discoveries</code></td></tr>
        <tr><td><strong>Verification Ratio</strong></td><td><strong>{m.verification_ratio_pct}%</strong></td><td><code>HTTP_Live / Discovered_Assets</code></td></tr>
        <tr><td><strong>Pipeline Throughput</strong></td><td><strong>{m.total_duration_sec}s</strong></td><td>Total concurrent execution latency</td></tr>
        <tr><td><strong>Graph Complexity</strong></td><td><strong>{m.graph_nodes} nodes, {m.graph_edges} edges</strong></td><td>Correlated multi-tier topological graph density</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    const ctx = document.getElementById('yieldChart').getContext('2d');
    new Chart(ctx, {{
      type: 'bar',
      data: {{
        labels: {json.dumps(list(m.provider_breakdown.keys()))},
        datasets: [{{
          label: 'Raw Discovered Assets',
          data: {json.dumps(list(m.provider_breakdown.values()))},
          backgroundColor: 'rgba(239, 68, 68, 0.7)',
          borderColor: '#ef4444',
          borderWidth: 1
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ labels: {{ color: '#9ca3af' }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#9ca3af' }} }},
          y: {{ ticks: {{ color: '#9ca3af' }} }}
        }}
      }}
    }});
  </script>
</body>
</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Academic benchmark datasets saved to: [bold green]{bench_dir}[/bold green]")

    @classmethod
    def render_rich_benchmark(cls, m: BenchmarkMetrics) -> None:
        """Renders the exact academic evaluation terminal panel from Section 17."""
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Feed", style="cyan", width=28)
        table.add_column("Count", style="bold white", justify="right")

        for prov, count in m.provider_breakdown.items():
            table.add_row(prov, str(count))

        console.print()
        console.print(Panel(table, title="[bold red]╔══ REDRECON-X BENCHMARK ══╗[/bold red]", subtitle=f"[dim]Target: {m.target}[/dim]", border_style="red", box=box.DOUBLE))

        summary_table = Table(box=box.ROUNDED, border_style="red")
        summary_table.add_column("Academic Metric", style="bold white")
        summary_table.add_column("Experimental Value", style="bold yellow", justify="right")
        summary_table.add_column("Evaluation Note", style="dim cyan")

        summary_table.add_row("Raw discoveries", str(m.raw_discoveries), "Aggregated cross-provider observations")
        summary_table.add_row("Unique assets", str(m.unique_assets), "Distinct root-scoped hosts")
        summary_table.add_row("Duplicates removed", str(m.duplicates_removed), "Filtered cross-source redundancy")
        summary_table.add_row("Deduplication rate", f"{m.deduplication_rate_pct}%", "Reduction in asset noise")
        summary_table.add_row("DNS verified", str(m.dns_verified_hosts), "Confirmed in global DNS")
        summary_table.add_row("HTTP verified", str(m.http_verified_hosts), "Confirmed active web services")
        summary_table.add_row("Verification ratio", f"{m.verification_ratio_pct}%", "Live endpoints vs discovered assets")
        summary_table.add_row("Multi-source gain", f"+{m.coverage_gain_pct}%", "Gain over CT baseline alone")
        summary_table.add_row("Total duration", f"{m.total_duration_sec}s", "Concurrent execution time")
        summary_table.add_row("Graph Nodes", str(m.graph_nodes), "Entity complexity in attack-surface")
        summary_table.add_row("Relationships", str(m.graph_edges), "Graph edges between hosts, IPs & ports")

        console.print(summary_table)
        console.print(f"\n[bold green]Benchmark datasets exported to:[/bold green] [bold underline]reports/{m.target}/benchmark/[/bold underline]\n")
