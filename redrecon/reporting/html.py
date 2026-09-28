import json
from pathlib import Path
from typing import Any, Dict
from redrecon.core.logger import get_logger
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.models.scan import ScanResult

logger = get_logger()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>REDRECON-X Intelligence Report — __TARGET__</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --card-border: #1f2937;
      --primary: #ef4444;
      --primary-glow: rgba(239, 68, 68, 0.25);
      --accent: #06b6d4;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --crit: #b91c1c;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.8) 100%);
      border: 1px solid var(--primary-glow);
      border-radius: 12px;
      padding: 24px 32px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }
    .brand h1 {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: 1px;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand h1 span { color: var(--primary); }
    .tagline { color: var(--text-muted); font-size: 14px; margin-top: 4px; }
    .scan-meta { text-align: right; font-size: 13px; color: var(--text-muted); }
    .scan-meta strong { color: var(--text); }
    .badge-mode {
      background: var(--primary);
      color: #fff;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      margin-left: 8px;
    }

    /* Stat Cards Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px 20px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    }
    .stat-card .val {
      font-size: 30px;
      font-weight: 800;
      color: #fff;
      line-height: 1.2;
    }
    .stat-card .lbl {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    /* Tabs Navigation */
    .tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 20px;
      overflow-x: auto;
    }
    .tab-btn {
      background: none;
      border: none;
      padding: 12px 20px;
      font-size: 14px;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      border-bottom: 3px solid transparent;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active {
      color: var(--primary);
      border-bottom-color: var(--primary);
      background: rgba(239, 68, 68, 0.05);
      border-radius: 6px 6px 0 0;
    }

    /* Tab Content */
    .tab-pane { display: none; }
    .tab-pane.active { display: block; }

    /* Tables & Cards */
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .panel-title {
      font-size: 18px;
      font-weight: 700;
      color: #fff;
    }

    .search-box {
      background: #111827;
      border: 1px solid var(--card-border);
      padding: 8px 14px;
      border-radius: 6px;
      color: #fff;
      font-size: 13px;
      width: 260px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }
    th {
      background: #111827;
      color: var(--text-muted);
      padding: 10px 14px;
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
    }
    td {
      padding: 12px 14px;
      border-bottom: 1px solid rgba(31, 41, 55, 0.5);
      vertical-align: top;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge-high { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .badge-low { background: rgba(107, 114, 128, 0.2); color: #9ca3af; border: 1px solid #6b7280; }
    .badge-crit { background: rgba(220, 38, 38, 0.25); color: #f87171; border: 1px solid #dc2626; }

    .tag {
      background: rgba(6, 182, 212, 0.15);
      color: #22d3ee;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      margin-right: 4px;
    }

    /* Attack Surface Visual Map */
    .graph-container {
      background: #060911;
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 24px;
      overflow-x: auto;
      min-height: 480px;
    }
    .tree-node {
      margin-left: 24px;
      position: relative;
      padding: 6px 0;
    }
    .tree-node::before {
      content: "";
      position: absolute;
      left: -14px;
      top: 16px;
      width: 12px;
      height: 1px;
      background: #374151;
    }
    .node-box {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 13px;
      font-family: monospace;
    }
    .node-box.root { border-color: var(--primary); background: rgba(239, 68, 68, 0.1); font-weight: bold; }
    .node-box.host { border-color: #3b82f6; }
    .node-box.ip { border-color: #10b981; }
    .node-box.port { border-color: #f59e0b; font-size: 11px; }

    /* URL categories */
    .category-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
    .cat-pill {
      background: #1f2937;
      color: #9ca3af;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 12px;
      cursor: pointer;
      border: 1px solid transparent;
    }
    .cat-pill.active { background: var(--primary); color: #fff; font-weight: 600; }
  </style>
</head>
<body>

  <header class="header">
    <div class="brand">
      <h1>REDRECON<span>-X</span> <span class="badge-mode">__MODE__</span></h1>
      <div class="tagline">Automated Web Reconnaissance & Attack-Surface Intelligence</div>
    </div>
    <div class="scan-meta">
      <div>Target: <strong>__TARGET__</strong></div>
      <div>Scan ID: <strong>__SCAN_ID__</strong></div>
      <div>Duration: <strong>__DURATION__s</strong></div>
      <div>Completed: <strong>__COMPLETED__</strong></div>
    </div>
  </header>

  <!-- Metric Stat Cards -->
  <section class="stats-grid">
    <div class="stat-card">
      <div class="val">__STAT_HOSTS__</div>
      <div class="lbl">Subdomains</div>
    </div>
    <div class="stat-card">
      <div class="val">__STAT_LIVE__</div>
      <div class="lbl">Live Assets</div>
    </div>
    <div class="stat-card">
      <div class="val">__STAT_IPS__</div>
      <div class="lbl">Unique IPs</div>
    </div>
    <div class="stat-card">
      <div class="val">__STAT_SERVICES__</div>
      <div class="lbl">HTTP Services</div>
    </div>
    <div class="stat-card">
      <div class="val">__STAT_PORTS__</div>
      <div class="lbl">Open Ports</div>
    </div>
    <div class="stat-card">
      <div class="val">__STAT_URLS__</div>
      <div class="lbl">Wayback URLs</div>
    </div>
    <div class="stat-card">
      <div class="val" style="color: var(--primary);">__STAT_FINDINGS__</div>
      <div class="lbl">Security Findings</div>
    </div>
  </section>

  <!-- Navigation Tabs -->
  <nav class="tabs">
    <button class="tab-btn active" onclick="showTab('tab-graph')">Attack Surface Map</button>
    <button class="tab-btn" onclick="showTab('tab-assets')">Asset Inventory</button>
    <button class="tab-btn" onclick="showTab('tab-dns')">DNS Records</button>
    <button class="tab-btn" onclick="showTab('tab-http')">HTTP & Headers</button>
    <button class="tab-btn" onclick="showTab('tab-wayback')">Historical URLs</button>
    <button class="tab-btn" onclick="showTab('tab-findings')">Findings & Vulns</button>
    <button class="tab-btn" onclick="showTab('tab-research')">Research Metrics</button>
  </nav>

  <!-- Tab 1: Attack Surface Topology Graph -->
  <div id="tab-graph" class="tab-pane active">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Asset Relationship Topology (Root &rarr; Hosts &rarr; IPs &rarr; Ports)</div>
      </div>
      <div class="graph-container">
        __GRAPH_HTML__
      </div>
    </div>
  </div>

  <!-- Tab 2: Assets Inventory Table -->
  <div id="tab-assets" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Discovered Assets (__STAT_HOSTS__)</div>
        <input type="text" id="assetSearch" class="search-box" placeholder="Filter assets or IPs..." onkeyup="filterAssets()">
      </div>
      <table id="assetTable">
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Confidence</th>
            <th>IP Addresses</th>
            <th>HTTP Title / Server</th>
            <th>Open Ports</th>
            <th>Sources</th>
          </tr>
        </thead>
        <tbody>
          __ASSET_ROWS__
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab 3: DNS Records -->
  <div id="tab-dns" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">DNS Record Matrix</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          __DNS_ROWS__
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab 4: HTTP & Headers -->
  <div id="tab-http" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">HTTP Services & Security Header Evaluation</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Endpoint</th>
            <th>Status</th>
            <th>Title</th>
            <th>Server</th>
            <th>Latency</th>
            <th>Security Headers Observations</th>
          </tr>
        </thead>
        <tbody>
          __HTTP_ROWS__
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab 5: Wayback Historical URLs -->
  <div id="tab-wayback" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Historical URLs & Categorized Endpoints</div>
        <input type="text" id="urlSearch" class="search-box" placeholder="Search URLs..." onkeyup="filterUrls()">
      </div>
      <div class="category-pills">
        <button class="cat-pill active" onclick="filterUrlCat('ALL')">All</button>
        __CAT_PILLS__
      </div>
      <table id="urlTable">
        <thead>
          <tr>
            <th>Category</th>
            <th>URL</th>
          </tr>
        </thead>
        <tbody>
          __URL_ROWS__
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab 6: Security Findings -->
  <div id="tab-findings" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Security Observations & Exposure Candidates</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding Name</th>
            <th>Target</th>
            <th>Source</th>
            <th>Evidence / Details</th>
          </tr>
        </thead>
        <tbody>
          __FINDING_ROWS__
        </tbody>
      </table>
    </div>
  </div>

  <!-- Tab 7: Academic Research & Benchmark Metrics -->
  <div id="tab-research" class="tab-pane">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">MSc Cybersecurity Research & Evaluation Metrics</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Evaluation Dimension</th>
            <th>Metric Value</th>
            <th>Research Significance</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Coverage & Discovery</strong></td>
            <td>__STAT_HOSTS__ subdomains from __NUM_SOURCES__ independent providers</td>
            <td>Measures external attack-surface perimeter visibility</td>
          </tr>
          <tr>
            <td><strong>Deduplication Efficiency</strong></td>
            <td>__DUPLICATES_REMOVED__ redundant data artifacts filtered</td>
            <td>Demonstrates multi-source correlation without telemetry fragmentation</td>
          </tr>
          <tr>
            <td><strong>Live Asset Verification Ratio</strong></td>
            <td>__STAT_LIVE__ live confirmed / __STAT_HOSTS__ total discovered</td>
            <td>Distinguishes confirmed infrastructure from stale DNS/CT artifacts</td>
          </tr>
          <tr>
            <td><strong>Scan Pipeline Duration</strong></td>
            <td>__DURATION__ seconds</td>
            <td>Async execution efficiency and operational scalability</td>
          </tr>
          <tr>
            <td><strong>Correlated Entities</strong></td>
            <td>__GRAPH_NODES__ Graph Nodes &amp; __GRAPH_EDGES__ Relationships</td>
            <td>Knowledge graph integration of attack surface components</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    function showTab(tabId) {
      document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      event.target.classList.add('active');
    }

    function filterAssets() {
      const q = document.getElementById('assetSearch').value.toLowerCase();
      const rows = document.querySelectorAll('#assetTable tbody tr');
      rows.forEach(r => {
        r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    }

    function filterUrls() {
      const q = document.getElementById('urlSearch').value.toLowerCase();
      const rows = document.querySelectorAll('#urlTable tbody tr');
      rows.forEach(r => {
        r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    }

    let activeCat = 'ALL';
    function filterUrlCat(cat) {
      activeCat = cat;
      document.querySelectorAll('.cat-pill').forEach(p => p.classList.remove('active'));
      event.target.classList.add('active');
      const rows = document.querySelectorAll('#urlTable tbody tr');
      rows.forEach(r => {
        const rowCat = r.getAttribute('data-cat');
        if (cat === 'ALL' || rowCat === cat) {
          r.style.display = '';
        } else {
          r.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>
"""


class HTMLReporter:
    """
    Generates rich, self-contained HTML dashboards for interactive attack-surface visualization.
    """

    @classmethod
    def generate(cls, scan: ScanResult, base_dir: str = "reports") -> str:
        target_dir = Path(base_dir) / scan.target
        target_dir.mkdir(parents=True, exist_ok=True)
        html_file = target_dir / "report.html"

        # Generate attack surface graph data
        graph_data = AssetCorrelator.generate_attack_surface_graph(scan.target, scan.assets)

        # Build Graph HTML (tree view)
        graph_html_lines = [f'<div class="node-box root">Target: {scan.target}</div>']
        for asset in scan.assets:
            graph_html_lines.append('<div class="tree-node">')
            conf_badge = f'<span class="badge badge-{asset.confidence.value.lower()}">{asset.confidence.value}</span>'
            graph_html_lines.append(f'<div class="node-box host">&#127760; {asset.hostname} {conf_badge}</div>')

            if asset.http_service:
                s = asset.http_service
                graph_html_lines.append(
                    f'<div class="tree-node"><div class="node-box" style="border-color:#06b6d4">&#128279; HTTP {s.status_code} - {s.title or s.server or "Web"}</div></div>'
                )

            for ip in asset.ip_addresses:
                graph_html_lines.append(
                    f'<div class="tree-node"><div class="node-box ip">&#128225; {ip}</div>'
                )
                for p in asset.ports:
                    graph_html_lines.append(
                        f'<div class="tree-node"><div class="node-box port">&#128274; {p.port}/{p.service_name}</div></div>'
                    )
                graph_html_lines.append('</div>')
            graph_html_lines.append('</div>')

        graph_html = "\n".join(graph_html_lines)

        # Build Asset Rows
        asset_rows = []
        for a in scan.assets:
            ips = "<br>".join(a.ip_addresses) if a.ip_addresses else '<span style="color:#6b7280">Unresolved</span>'
            ports = ", ".join([f"{p.port}/{p.service_name}" for p in a.ports]) or "-"
            title_server = ""
            if a.http_service:
                title_server = f"<strong>{a.http_service.title or '-'}</strong><br><span style='color:#9ca3af'>{a.http_service.server or ''} ({a.http_service.status_code})</span>"
            sources = " ".join([f'<span class="tag">{s}</span>' for s in a.sources])
            badge_class = f"badge-{a.confidence.value.lower()}"

            pri_color = "#ef4444" if a.priority_score >= 6 else "#f59e0b" if a.priority_score >= 4 else "#3b82f6"
            pri_badge = f'<span class="badge" style="background:rgba(239,68,68,0.15); color:{pri_color}; border:1px solid {pri_color}; margin-top:4px;" title="{json.dumps(a.priority_breakdown)}">Priority: {a.priority_score}</span>'

            asset_rows.append(f"""
            <tr>
              <td><strong>{a.hostname}</strong><br>{pri_badge}</td>
              <td><span class="badge {badge_class}">{a.confidence.value}</span></td>
              <td>{ips}</td>
              <td>{title_server}</td>
              <td>{ports}</td>
              <td>{sources}</td>
            </tr>
            """)

        # Build DNS Rows
        dns_rows = []
        for a in scan.assets:
            for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]:
                vals = getattr(a.dns_records, rtype, [])
                for v in vals:
                    dns_rows.append(f"<tr><td>{a.hostname}</td><td><span class='tag'>{rtype}</span></td><td><code>{v}</code></td></tr>")

        # Build HTTP Rows
        http_rows = []
        for a in scan.assets:
            if a.http_service:
                s = a.http_service
                obs_badges = []
                for obs in a.security_headers:
                    status_color = "#10b981" if obs.status == "PRESENT" else "#f59e0b"
                    obs_badges.append(f"<span style='color:{status_color}; font-size:11px;'>&#9679; {obs.header}: {obs.status}</span><br>")

                http_rows.append(f"""
                <tr>
                  <td><a href="{s.url}" target="_blank" style="color:#38bdf8;">{s.url}</a></td>
                  <td><span class="badge" style="background:#1e293b; color:#fff;">{s.status_code}</span></td>
                  <td>{s.title or '-'}</td>
                  <td>{s.server or '-'}</td>
                  <td>{s.response_time_ms} ms</td>
                  <td>{''.join(obs_badges) or 'None'}</td>
                </tr>
                """)

        # Build URL Rows & Category Pills
        url_rows = []
        cat_pills = []
        raw_wayback = scan.raw_data.get("wayback", {})
        classified = raw_wayback.get("classified", {})

        for cat, urls in classified.items():
            cat_pills.append(f'<button class="cat-pill" onclick="filterUrlCat(\'{cat}\')">{cat} ({len(urls)})</button>')
            for u in urls[:50]:  # limit view for performance
                url_rows.append(f"""
                <tr data-cat="{cat}">
                  <td><span class="tag">{cat}</span></td>
                  <td><a href="{u}" target="_blank" style="color:#94a3b8; text-decoration:none;">{u}</a></td>
                </tr>
                """)

        # Build Finding Rows
        finding_rows = []
        for f in scan.findings:
            sev_class = {
                "CRITICAL": "badge-crit",
                "HIGH": "badge-crit",
                "MEDIUM": "badge-medium",
                "LOW": "badge-low",
                "INFO": "badge-low",
            }.get(f.severity.value, "badge-low")

            finding_rows.append(f"""
            <tr>
              <td><span class="badge {sev_class}">{f.severity.value}</span></td>
              <td><strong>{f.name}</strong><br><small style="color:#9ca3af;">{f.description}</small></td>
              <td><code>{f.target}</code></td>
              <td><span class="tag">{f.source}</span></td>
              <td><small style="color:#cbd5e1;">{f.evidence or '-'}</small></td>
            </tr>
            """)

        # Fill Template
        rendered = (
            HTML_TEMPLATE
            .replace("__TARGET__", scan.target)
            .replace("__MODE__", scan.mode.value.upper())
            .replace("__SCAN_ID__", scan.scan_id)
            .replace("__DURATION__", str(scan.metrics.scan_duration_sec))
            .replace("__COMPLETED__", scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else "In Progress")
            .replace("__STAT_HOSTS__", str(scan.metrics.discovered_hosts))
            .replace("__STAT_LIVE__", str(scan.metrics.live_hosts))
            .replace("__STAT_IPS__", str(scan.metrics.unique_ips))
            .replace("__STAT_SERVICES__", str(scan.metrics.http_services))
            .replace("__STAT_PORTS__", str(scan.metrics.open_ports))
            .replace("__STAT_URLS__", str(scan.metrics.historical_urls))
            .replace("__STAT_FINDINGS__", str(scan.metrics.nuclei_findings + scan.metrics.header_observations))
            .replace("__GRAPH_HTML__", graph_html)
            .replace("__ASSET_ROWS__", "\n".join(asset_rows) if asset_rows else "<tr><td colspan='6'>No assets discovered</td></tr>")
            .replace("__DNS_ROWS__", "\n".join(dns_rows) if dns_rows else "<tr><td colspan='3'>No DNS records recorded</td></tr>")
            .replace("__HTTP_ROWS__", "\n".join(http_rows) if http_rows else "<tr><td colspan='6'>No active HTTP services found</td></tr>")
            .replace("__CAT_PILLS__", "\n".join(cat_pills))
            .replace("__URL_ROWS__", "\n".join(url_rows) if url_rows else "<tr><td colspan='2'>No historical URLs found</td></tr>")
            .replace("__FINDING_ROWS__", "\n".join(finding_rows) if finding_rows else "<tr><td colspan='5'>No candidate findings identified</td></tr>")
            .replace("__NUM_SOURCES__", str(len(scan.metrics.sources_summary)))
            .replace("__DUPLICATES_REMOVED__", str(scan.metrics.duplicate_assets))
            .replace("__GRAPH_NODES__", str(graph_data["total_nodes"]))
            .replace("__GRAPH_EDGES__", str(graph_data["total_edges"]))
        )

        with open(html_file, "w", encoding="utf-8") as f:
            f.write(rendered)

        # Also generate dedicated Executive and Technical reports (Section 37)
        cls._generate_executive_report(scan, target_dir)
        cls._generate_technical_report(scan, target_dir)

        logger.info(f"Interactive HTML Report generated: [bold green]{html_file}[/bold green]")
        return str(html_file)

    @classmethod
    def _generate_executive_report(cls, scan: ScanResult, target_dir: Path) -> Path:
        """Section 37: Executive Report tailored for leadership and CISOs."""
        exec_file = target_dir / "executive_report.html"

        # High priority assets (Priority >= 4)
        pri_assets = [a for a in scan.assets if a.priority_score >= 4]
        pri_rows = []
        for a in pri_assets[:10]:
            pri_rows.append(f"""
            <tr>
              <td><strong>{a.hostname}</strong></td>
              <td><span class="badge badge-crit">Priority {a.priority_score}</span></td>
              <td><code>{', '.join(a.ip_addresses) or 'Unresolved'}</code></td>
              <td>{a.http_service.title if a.http_service else 'No HTTP'}</td>
              <td>{len(a.ports)} active ports</td>
            </tr>
            """)

        exec_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>REDRECON-X Executive Report — {scan.target}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; background: #0b0f19; color: #f3f4f6; padding: 32px; max-width: 1000px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #ef4444; padding-bottom: 16px; margin-bottom: 24px; }}
    h1 {{ color: #fff; margin-bottom: 4px; }}
    h1 span {{ color: #ef4444; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }}
    .kpi {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; text-align: center; }}
    .kpi .num {{ font-size: 32px; font-weight: 800; color: #ef4444; }}
    .kpi .lbl {{ font-size: 12px; color: #9ca3af; text-transform: uppercase; margin-top: 4px; }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #1f2937; text-align: left; }}
    th {{ color: #9ca3af; font-size: 13px; text-transform: uppercase; }}
    .badge-crit {{ background: rgba(239,68,68,0.2); color: #f87171; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>REDRECON-<span>X</span> Executive Attack-Surface Summary</h1>
    <p style="color:#9ca3af;">Target: <strong>{scan.target}</strong> | Scan ID: <code>{scan.scan_id}</code> | Date: {scan.completed_at.strftime("%Y-%m-%d %H:%M") if scan.completed_at else "Recent"}</p>
  </div>

  <div class="kpi-grid">
    <div class="kpi"><div class="num">{scan.metrics.discovered_hosts}</div><div class="lbl">Total Assets</div></div>
    <div class="kpi"><div class="num">{scan.metrics.live_hosts}</div><div class="lbl">Live Web Endpoints</div></div>
    <div class="kpi"><div class="num">{scan.metrics.open_ports}</div><div class="lbl">Exposed Ports</div></div>
    <div class="kpi"><div class="num">{scan.metrics.nuclei_findings}</div><div class="lbl">Candidate Findings</div></div>
  </div>

  <div class="card">
    <h3 style="color:#fff; margin-bottom: 8px;">Executive Risk Overview</h3>
    <p style="color:#9ca3af; line-height: 1.6;">
      Reconnaissance analysis for <strong>{scan.target}</strong> identified <strong>{scan.metrics.discovered_hosts}</strong> unique hostnames across {len(scan.metrics.sources_summary)} independent intelligence sources.
      A total of <strong>{scan.metrics.duplicate_assets} duplicate asset records</strong> were successfully normalized and deduplicated.
      There are <strong>{len(pri_assets)}</strong> high-priority exposure points requiring security attention.
    </p>
  </div>

  <div class="card">
    <h3 style="color:#fff;">High Priority Assets</h3>
    <table>
      <thead>
        <tr><th>Hostname</th><th>Priority</th><th>IP Addresses</th><th>Web Title</th><th>Ports</th></tr>
      </thead>
      <tbody>
        {"".join(pri_rows) if pri_rows else "<tr><td colspan='5'>No critical exposure assets identified</td></tr>"}
      </tbody>
    </table>
  </div>
</body>
</html>"""
        with open(exec_file, "w", encoding="utf-8") as f:
            f.write(exec_html)
        return exec_file

    @classmethod
    def _generate_technical_report(cls, scan: ScanResult, target_dir: Path) -> Path:
        """Section 37: Technical Report for engineers and pen-testers."""
        tech_file = target_dir / "technical_report.html"
        with open(target_dir / "report.html", "r", encoding="utf-8") as f:
            content = f.read()
        # Create technical copy with specific technical branding
        content = content.replace("REDRECON-X Intelligence Report", "REDRECON-X Technical Dossier")
        with open(tech_file, "w", encoding="utf-8") as f:
            f.write(content)
        return tech_file
