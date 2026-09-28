import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

from redrecon.core.config import ScanConfig, load_config
from redrecon.core.engine import ReconEngine
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.models.scan import ScanMode
from redrecon.modules import MODULE_REGISTRY
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository

app = FastAPI(title="REDRECON-X Intelligence Dashboard", version="1.0.0")

db = Database()
repo = ScanRepository(db)


class NewScanRequest(BaseModel):
    target: str
    mode: str = "full"


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>REDRECON-X — Attack Surface Intelligence Dashboard</title>
  <style>
    :root {
      --bg: #0b0f19;
      --sidebar: #070a12;
      --card-bg: rgba(17, 24, 39, 0.9);
      --border: #1f2937;
      --primary: #ef4444;
      --text: #f9fafb;
      --text-muted: #9ca3af;
      --accent: #06b6d4;
      --success: #10b981;
      --warning: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    /* Sidebar */
    .sidebar {
      width: 250px;
      background: var(--sidebar);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      padding: 20px;
    }
    .brand {
      font-size: 20px;
      font-weight: 900;
      letter-spacing: 1px;
      margin-bottom: 30px;
      color: #fff;
    }
    .brand span { color: var(--primary); }
    .nav-link {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 14px;
      color: var(--text-muted);
      text-decoration: none;
      border-radius: 8px;
      margin-bottom: 6px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }
    .nav-link:hover, .nav-link.active {
      color: #fff;
      background: rgba(239, 68, 68, 0.15);
      border-left: 3px solid var(--primary);
    }
    /* Main Area */
    .main {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
    }
    .topbar {
      padding: 18px 28px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(11, 15, 25, 0.8);
      backdrop-filter: blur(8px);
    }
    .topbar h2 { font-size: 18px; font-weight: 700; }
    .btn-new {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 8px 18px;
      border-radius: 6px;
      font-weight: 700;
      cursor: pointer;
      font-size: 13px;
      transition: opacity 0.2s;
    }
    .btn-new:hover { opacity: 0.9; }

    .content { padding: 24px 28px; flex: 1; }
    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
    }
    .stat-card .val { font-size: 26px; font-weight: 800; color: #fff; }
    .stat-card .lbl { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-top: 4px; }

    .panel {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .panel h3 { font-size: 16px; margin-bottom: 16px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
    th { color: var(--text-muted); padding: 10px 14px; border-bottom: 1px solid var(--border); }
    td { padding: 12px 14px; border-bottom: 1px solid rgba(31, 41, 55, 0.5); }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .badge-full { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-passive { background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid #06b6d4; }
    .badge-completed { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }

    /* Modal */
    .modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.7);
      backdrop-filter: blur(4px);
      align-items: center;
      justify-content: center;
      z-index: 100;
    }
    .modal-box {
      background: #111827;
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 420px;
      padding: 24px;
    }
    .input-grp { margin-bottom: 16px; }
    .input-grp label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
    .input-grp input, .input-grp select {
      width: 100%;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 12px;
      color: #fff;
    }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
    .btn-cancel { background: transparent; border: 1px solid var(--border); color: #fff; padding: 8px 14px; border-radius: 6px; cursor: pointer; }
  </style>
</head>
<body>

  <div class="sidebar">
    <div class="brand">REDRECON<span>-X</span></div>
    <div class="nav-link active" onclick="navigate('scans')">&#128269; Scans</div>
    <div class="nav-link" onclick="navigate('modules')">&#129513; Modules</div>
    <div class="nav-link" onclick="navigate('api')">&#9881; API Docs</div>
  </div>

  <div class="main">
    <div class="topbar">
      <h2 id="viewTitle">Reconnaissance Operations</h2>
      <button class="btn-new" onclick="openNewScan()">+ NEW SCAN</button>
    </div>

    <div class="content">
      <div class="stats-row">
        <div class="stat-card">
          <div class="val" id="totalScans">0</div>
          <div class="lbl">Total Scans</div>
        </div>
        <div class="stat-card">
          <div class="val" id="totalAssets">0</div>
          <div class="lbl">Assets Mapped</div>
        </div>
        <div class="stat-card">
          <div class="val" id="totalFindings">0</div>
          <div class="lbl">Security Findings</div>
        </div>
        <div class="stat-card">
          <div class="val" id="activeTargets">0</div>
          <div class="lbl">Unique Targets</div>
        </div>
      </div>

      <div class="panel" id="scansPanel">
        <h3>Recent Recon Scans</h3>
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Target</th>
              <th>Mode</th>
              <th>Status</th>
              <th>Started</th>
              <th>Duration</th>
              <th>Assets</th>
              <th>Findings</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="scansTableBody">
            <tr><td colspan="9" style="text-align:center;">Loading scans...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- New Scan Modal -->
  <div class="modal" id="scanModal">
    <div class="modal-box">
      <h3 style="margin-bottom: 16px;">Launch Target Reconnaissance</h3>
      <div class="input-grp">
        <label>Authorized Domain</label>
        <input type="text" id="targetInput" placeholder="example.com">
      </div>
      <div class="input-grp">
        <label>Reconnaissance Mode</label>
        <select id="modeInput">
          <option value="full">Full Mode (Passive + Active + Ports + Vulns)</option>
          <option value="passive">Passive Mode (Zero Active Probing)</option>
        </select>
      </div>
      <div class="modal-actions">
        <button class="btn-cancel" onclick="closeNewScan()">Cancel</button>
        <button class="btn-new" onclick="submitScan()">Start Scan</button>
      </div>
    </div>
  </div>

  <script>
    function openNewScan() { document.getElementById('scanModal').style.display = 'flex'; }
    function closeNewScan() { document.getElementById('scanModal').style.display = 'none'; }

    async function loadScans() {
      try {
        const res = await fetch('/api/scans');
        const scans = await res.json();
        document.getElementById('totalScans').innerText = scans.length;

        let totalAssets = 0;
        let totalFindings = 0;
        let targets = new Set();

        const tbody = document.getElementById('scansTableBody');
        if (scans.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;">No scans recorded yet. Click "+ NEW SCAN" to begin!</td></tr>';
          return;
        }

        tbody.innerHTML = scans.map(s => {
          const m = s.metrics || {};
          totalAssets += (m.discovered_hosts || 0);
          totalFindings += (m.nuclei_findings || 0);
          targets.add(s.target);

          return `
            <tr>
              <td><code>${s.scan_id}</code></td>
              <td><strong>${s.target}</strong></td>
              <td><span class="badge badge-${s.mode}">${s.mode.toUpperCase()}</span></td>
              <td><span class="badge badge-completed">${s.status.toUpperCase()}</span></td>
              <td>${s.started_at.split('T')[0]}</td>
              <td>${s.duration_sec}s</td>
              <td>${m.discovered_hosts || 0}</td>
              <td style="color:#ef4444; font-weight:bold;">${m.nuclei_findings || 0}</td>
              <td><a href="/reports/${s.target}/report.html" target="_blank" style="color:#06b6d4; text-decoration:none;">View Report &rarr;</a></td>
            </tr>
          `;
        }).join('');

        document.getElementById('totalAssets').innerText = totalAssets;
        document.getElementById('totalFindings').innerText = totalFindings;
        document.getElementById('activeTargets').innerText = targets.size;
      } catch (e) {
        console.error(e);
      }
    }

    async function submitScan() {
      const target = document.getElementById('targetInput').value.trim();
      const mode = document.getElementById('modeInput').value;
      if (!target) return alert('Target domain required');

      closeNewScan();
      alert(`Recon initiated for ${target} [${mode}]. Scan running in background.`);
      await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode })
      });
      setTimeout(loadScans, 2000);
    }

    loadScans();
    setInterval(loadScans, 8000);
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD_HTML


@app.get("/api/scans")
def list_scans():
    return repo.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/graph")
def get_scan_graph(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return AssetCorrelator.generate_attack_surface_graph(scan.target, scan.assets)


@app.get("/api/modules")
def list_modules():
    return [
        {"code": code, "name": name, "class": cls.__name__ if cls else "Reporter"}
        for code, (name, cls) in MODULE_REGISTRY.items()
    ]


async def _background_scan(target: str, mode: str):
    engine = ReconEngine()
    scan_mode = ScanMode.PASSIVE if mode == "passive" else ScanMode.FULL
    await engine.run_scan(target, mode=scan_mode)


@app.post("/api/scan")
def trigger_scan(req: NewScanRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(_background_scan, req.target, req.mode)
    return {"message": "Scan queued", "target": req.target, "mode": req.mode}


def start_dashboard(host: str = "127.0.0.1", port: int = 8000):
    print(f"[*] Launching REDRECON-X Intelligence Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
