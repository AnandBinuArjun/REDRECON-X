import asyncio
import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Security, Depends, Header
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from redrecon.core.config import ScanConfig, load_config
from redrecon.core.engine import ReconEngine
from redrecon.core.logger import get_logger, init_error_tracking
from redrecon.core.scope import ScopeValidator
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.models.scan import ScanMode
from redrecon.modules import MODULE_REGISTRY
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository

logger = get_logger()
init_error_tracking()

app = FastAPI(title="REDRECON-X Intelligence Dashboard", version="1.0.0")

db = Database()
repo = ScanRepository(db)
cfg = load_config()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(None),
):
    """
    Validates API key against REDRECON_API_KEY if configured.
    If no key is configured in environment or YAML, allows localhost access.
    """
    expected_key = os.getenv("REDRECON_API_KEY") or cfg.api_secret_key
    if not expected_key:
        return True

    if api_key and api_key == expected_key:
        return True

    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if token == expected_key:
            return True

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: Missing or invalid API key in 'X-API-Key' or 'Authorization' header",
    )


class NewScanRequest(BaseModel):
    target: str
    mode: str = "full"


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>REDRECON-X // Linux Cyber Intelligence Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {
      --bg-dark: #030712;
      --bg-surface: #0a0f1d;
      --bg-card: rgba(14, 20, 36, 0.85);
      --bg-card-hover: rgba(22, 31, 54, 0.95);
      --border-subtle: #1e293b;
      --border-focus: #10b981;
      --term-green: #10b981;
      --term-green-glow: rgba(16, 185, 129, 0.25);
      --term-red: #ef4444;
      --term-red-glow: rgba(239, 68, 68, 0.25);
      --term-cyan: #06b6d4;
      --term-amber: #f59e0b;
      --term-purple: #a855f7;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --font-mono: "JetBrains Mono", monospace;
      --font-sans: "Inter", sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font-sans);
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(rgba(16, 185, 129, 0.05) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(3, 7, 18, 0.9) 0%, rgba(10, 15, 29, 0.98) 100%);
      background-size: 24px 24px, 100% 100%;
      color: var(--text-main);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
      -webkit-font-smoothing: antialiased;
    }

    /* Linux Desktop Top Chrome */
    .linux-topbar {
      height: 40px;
      background: #02040a;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      user-select: none;
      z-index: 50;
    }

    .window-controls {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .win-btn {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      display: inline-block;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .win-close { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5); }
    .win-min { background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,0.5); }
    .win-max { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,0.5); }
    .win-btn:hover { opacity: 0.8; }

    .linux-host-tag {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--text-muted);
    }
    .linux-host-tag .prompt {
      color: var(--term-green);
      font-weight: 700;
    }

    .status-pill {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      padding: 3px 10px;
      border-radius: 9999px;
      color: var(--term-green);
      font-size: 11px;
      font-weight: 600;
    }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--term-green);
      box-shadow: 0 0 8px var(--term-green);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    /* Main Container */
    .app-body {
      display: flex;
      flex: 1;
      height: calc(100vh - 40px);
      overflow: hidden;
    }

    /* Sidebar */
    .sidebar {
      width: 260px;
      background: var(--bg-surface);
      border-right: 1px solid var(--border-subtle);
      display: flex;
      flex-direction: column;
      padding: 16px 12px;
      gap: 6px;
    }

    .brand-section {
      padding: 8px 12px 16px;
      border-bottom: 1px solid var(--border-subtle);
      margin-bottom: 8px;
    }
    .brand-title {
      font-family: var(--font-mono);
      font-size: 16px;
      font-weight: 800;
      letter-spacing: 0.5px;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .brand-title span { color: var(--term-red); text-shadow: 0 0 10px var(--term-red-glow); }
    .brand-sub {
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-dim);
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .nav-btn {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease-in-out;
      user-select: none;
    }
    .nav-btn svg { width: 16px; height: 16px; flex-shrink: 0; fill: currentColor; }
    .nav-btn:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-main);
      border-color: var(--border-subtle);
    }
    .nav-btn.active {
      background: rgba(16, 185, 129, 0.12);
      color: #fff;
      border-color: rgba(16, 185, 129, 0.4);
      box-shadow: 0 0 12px rgba(16, 185, 129, 0.15);
    }
    .nav-btn.active svg { color: var(--term-green); }

    .nav-divider {
      height: 1px;
      background: var(--border-subtle);
      margin: 8px 4px;
    }

    .launch-scan-btn {
      margin-top: 8px;
      background: linear-gradient(135deg, #ef4444 0%, #b91c1c 100%);
      color: #fff;
      border: 1px solid #f87171;
      padding: 10px 14px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 14px rgba(239, 68, 68, 0.35);
      transition: all 0.2s ease;
    }
    .launch-scan-btn:hover {
      box-shadow: 0 6px 20px rgba(239, 68, 68, 0.55);
      transform: translateY(-1px);
    }

    .sidebar-footer {
      margin-top: auto;
      padding: 12px;
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-dim);
    }
    .sidebar-footer strong { color: var(--term-green); }

    /* Content Area */
    .main-viewport {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      background: transparent;
    }

    .linux-header-bar {
      padding: 16px 24px;
      background: rgba(10, 15, 29, 0.75);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 40;
    }
    .view-title {
      font-family: var(--font-mono);
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .view-title::before {
      content: "#";
      color: var(--term-green);
    }

    .terminal-quick-input {
      display: flex;
      align-items: center;
      background: #020617;
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 4px 12px;
      width: 420px;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .terminal-quick-input span {
      color: var(--term-green);
      margin-right: 8px;
      font-weight: 700;
    }
    .terminal-quick-input input {
      background: transparent;
      border: none;
      color: #fff;
      font-family: inherit;
      font-size: inherit;
      width: 100%;
      outline: none;
    }

    .content-area {
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 20px;
      flex: 1;
    }

    /* Metric Cards Grid */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 16px 18px;
      position: relative;
      overflow: hidden;
      transition: all 0.2s ease;
    }
    .metric-card:hover {
      border-color: rgba(16, 185, 129, 0.4);
      background: var(--bg-card-hover);
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.4);
    }
    .metric-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      width: 3px;
      height: 100%;
      background: var(--term-green);
    }
    .metric-card.alert::before { background: var(--term-red); }
    .metric-card.cyan::before { background: var(--term-cyan); }
    .metric-card.amber::before { background: var(--term-amber); }

    .metric-val {
      font-family: var(--font-mono);
      font-size: 28px;
      font-weight: 800;
      color: #fff;
      line-height: 1.1;
    }
    .metric-label {
      font-family: var(--font-mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      margin-top: 6px;
    }

    /* Linux Terminal Panel */
    .terminal-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .terminal-panel-header {
      background: #020617;
      padding: 12px 18px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .terminal-panel-header h3 {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Linux Styled Table */
    .table-container {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
      font-family: var(--font-mono);
    }
    th {
      background: rgba(2, 6, 23, 0.7);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-size: 11px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-subtle);
    }
    td {
      padding: 12px 16px;
      border-bottom: 1px solid rgba(30, 41, 59, 0.4);
      color: var(--text-main);
    }
    tr:hover td {
      background: rgba(16, 185, 129, 0.04);
    }

    /* Badges */
    .tag {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .tag-full { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .tag-passive { background: rgba(6, 182, 212, 0.15); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.4); }
    .tag-completed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .tag-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .tag-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .tag-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .tag-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    .tag-info { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid #64748b; }

    /* Action Buttons */
    .btn-action {
      background: rgba(6, 182, 212, 0.1);
      color: #38bdf8;
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 4px 10px;
      border-radius: 4px;
      text-decoration: none;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: all 0.15s;
    }
    .btn-action:hover {
      background: rgba(6, 182, 212, 0.25);
      border-color: #38bdf8;
      color: #fff;
    }

    /* Embedded Terminal Console View */
    .term-stdout {
      background: #020617;
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #34d399;
      height: 480px;
      overflow-y: auto;
      line-height: 1.6;
    }
    .term-stdout .cmd-prompt { color: #f87171; font-weight: 700; }
    .term-stdout .cmd-target { color: #38bdf8; }
    .term-stdout .cmd-dim { color: #64748b; }

    /* Modal dialog */
    .modal {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
      z-index: 100;
    }
    .modal-box {
      background: #090d18;
      border: 1px solid var(--term-green);
      box-shadow: 0 0 30px rgba(16, 185, 129, 0.2);
      border-radius: 8px;
      width: 500px;
      max-width: 95vw;
      overflow: hidden;
      font-family: var(--font-mono);
    }
    .modal-header {
      background: #020617;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .modal-header h3 { font-size: 13px; color: var(--term-green); }
    .modal-body { padding: 20px; display: flex; flex-direction: column; gap: 14px; }
    .modal-body label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); }
    .modal-body input, .modal-body select {
      background: #020617;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      padding: 8px 12px;
      color: #fff;
      font-family: var(--font-mono);
      font-size: 12px;
      outline: none;
    }
    .modal-body input:focus, .modal-body select:focus {
      border-color: var(--term-green);
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.3);
    }
    .modal-footer {
      background: #020617;
      padding: 12px 16px;
      border-top: 1px solid var(--border-subtle);
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .btn-cancel {
      background: transparent;
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      padding: 6px 14px;
      border-radius: 4px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
    }
    .btn-submit {
      background: var(--term-green);
      border: 1px solid var(--term-green);
      color: #020617;
      font-weight: 700;
      padding: 6px 16px;
      border-radius: 4px;
      cursor: pointer;
      font-family: var(--font-mono);
      font-size: 12px;
      box-shadow: 0 0 10px var(--term-green-glow);
    }

    /* Embedded Graph Canvas */
    #graphContainer {
      width: 100%;
      height: 520px;
      background: #020617;
      border-radius: 6px;
    }

    /* Modules Grid */
    .modules-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }
    .module-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 6px;
      padding: 16px;
      font-family: var(--font-mono);
    }
    .module-card:hover {
      border-color: var(--term-cyan);
    }
    .module-code { color: var(--term-green); font-size: 11px; font-weight: 700; }
    .module-name { font-size: 14px; font-weight: 700; color: #fff; margin: 4px 0 8px; }
    .module-class { font-size: 11px; color: var(--text-dim); }

    @media (max-width: 900px) {
      .metric-grid { grid-template-columns: repeat(2, 1fr); }
      .modules-grid { grid-template-columns: 1fr; }
      .sidebar { width: 70px; }
      .brand-title, .brand-sub, .nav-btn span, .sidebar-footer { display: none; }
      .terminal-quick-input { display: none; }
    }
  </style>
</head>
<body>

  <!-- Top Chrome -->
  <div class="linux-topbar">
    <div class="window-controls">
      <span class="win-btn win-close" title="Close"></span>
      <span class="win-btn win-min" title="Minimize"></span>
      <span class="win-btn win-max" title="Maximize"></span>
    </div>
    <div class="linux-host-tag">
      <span class="prompt">root@redrecon-x:~#</span>
      <span>systemctl status redrecon-engine</span>
    </div>
    <div class="status-pill">
      <span class="pulse-dot"></span>
      <span>ACTIVE // 127.0.0.1:8000</span>
    </div>
  </div>

  <div class="app-body">
    <!-- Sidebar Navigation -->
    <div class="sidebar">
      <div class="brand-section">
        <div class="brand-title">REDRECON<span>-X</span></div>
        <div class="brand-sub">Attack Surface Intelligence</div>
      </div>

      <div class="nav-btn active" id="nav-scans" onclick="showTab('scans')">
        <svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
        <span>Operations Console</span>
      </div>

      <div class="nav-btn" id="nav-assets" onclick="showTab('assets')">
        <svg viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        <span>Asset Inventory</span>
      </div>

      <div class="nav-btn" id="nav-findings" onclick="showTab('findings')">
        <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Security Findings</span>
      </div>

      <div class="nav-btn" id="nav-graph" onclick="showTab('graph')">
        <svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        <span>Topology Graph</span>
      </div>

      <div class="nav-btn" id="nav-modules" onclick="showTab('modules')">
        <svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
        <span>Modules Matrix</span>
      </div>

      <div class="nav-btn" id="nav-shell" onclick="showTab('shell')">
        <svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        <span>Terminal Shell</span>
      </div>

      <div class="nav-divider"></div>

      <button class="launch-scan-btn" onclick="openNewScan()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        <span>+ RUN RECON</span>
      </button>

      <div class="sidebar-footer">
        System: <strong>v1.0.0</strong><br>
        Arch: <strong>Linux / x86_64</strong><br>
        Developer: <strong>AnandBinuArjun</strong>
      </div>
    </div>

    <!-- Main Viewport -->
    <div class="main-viewport">
      <div class="linux-header-bar">
        <div class="view-title" id="tabTitle">Operations Console</div>
        <div class="terminal-quick-input">
          <span>#</span>
          <input type="text" id="quickCommand" placeholder="Enter target to quick scan (e.g. scanme.nmap.org) [ENTER]" onkeydown="if(event.key==='Enter') quickLaunch()">
        </div>
      </div>

      <div class="content-area">

        <!-- TAB 1: OPERATIONS CONSOLE -->
        <div id="tab-scans" class="tab-pane">
          <div class="metric-grid">
            <div class="metric-card">
              <div class="metric-val" id="totalScans">0</div>
              <div class="metric-label">Completed Scans</div>
            </div>
            <div class="metric-card cyan">
              <div class="metric-val" id="totalAssets">0</div>
              <div class="metric-label">Mapped Assets</div>
            </div>
            <div class="metric-card alert">
              <div class="metric-val" id="totalFindings">0</div>
              <div class="metric-label">Candidate Findings</div>
            </div>
            <div class="metric-card amber">
              <div class="metric-val" id="activeTargets">0</div>
              <div class="metric-label">Active Scopes</div>
            </div>
          </div>

          <div class="terminal-panel" style="margin-top: 20px;">
            <div class="terminal-panel-header">
              <h3>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
                Active & Recorded Scans
              </h3>
              <span id="scanRefreshTime" style="color: var(--text-dim);">Live Polling: 8s</span>
            </div>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Scan Identifier</th>
                    <th>Target Scope</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Duration</th>
                    <th>Discovered</th>
                    <th>Findings</th>
                    <th>Interactive Dossier</th>
                  </tr>
                </thead>
                <tbody id="scansTableBody">
                  <tr><td colspan="9" style="text-align: center; color: var(--text-dim);">Loading reconnaissance database...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- TAB 2: ASSET INVENTORY -->
        <div id="tab-assets" class="tab-pane" style="display: none;">
          <div class="terminal-panel">
            <div class="terminal-panel-header">
              <h3>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5z"/></svg>
                Correlated Asset Intelligence Inventory
              </h3>
              <input type="text" id="assetSearchInput" placeholder="Filter hostname / IP..." onkeyup="filterAssetsTable()" style="background:#020617; border:1px solid var(--border-subtle); color:#fff; padding:4px 8px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">
            </div>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Asset Hostname</th>
                    <th>Resolved IP(s)</th>
                    <th>HTTP Status</th>
                    <th>Open Ports</th>
                    <th>Priority Score</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody id="assetsTableBody">
                  <tr><td colspan="6" style="text-align: center; color: var(--text-dim);">Loading asset entities...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- TAB 3: CANDIDATE FINDINGS -->
        <div id="tab-findings" class="tab-pane" style="display: none;">
          <div class="terminal-panel">
            <div class="terminal-panel-header">
              <h3>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Candidate Security Findings Ledger
              </h3>
              <span style="color: var(--text-dim);">Automated Exposure Heuristics & Nuclei Signatures</span>
            </div>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Finding Name</th>
                    <th>Severity</th>
                    <th>Target Host / URL</th>
                    <th>Detection Engine</th>
                    <th>Template ID</th>
                  </tr>
                </thead>
                <tbody id="findingsTableBody">
                  <tr><td colspan="5" style="text-align: center; color: var(--text-dim);">Loading candidate security findings...</td></tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- TAB 4: TOPOLOGY GRAPH -->
        <div id="tab-graph" class="tab-pane" style="display: none;">
          <div class="terminal-panel">
            <div class="terminal-panel-header">
              <h3>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/></svg>
                Attack Surface Graph Topology
              </h3>
              <div style="display:flex; gap:10px; align-items:center;">
                <label style="color:var(--text-muted); font-size:11px;">Scan Scope:</label>
                <select id="graphScanSelect" onchange="loadGraphData(this.value)" style="background:#020617; border:1px solid var(--border-subtle); color:#fff; padding:4px 8px; border-radius:4px; font-family:var(--font-mono); font-size:11px;">
                </select>
                <button class="btn-action" onclick="networkInstance && networkInstance.fit()">Fit View</button>
              </div>
            </div>
            <div id="graphContainer"></div>
          </div>
        </div>

        <!-- TAB 5: MODULES MATRIX -->
        <div id="tab-modules" class="tab-pane" style="display: none;">
          <div class="modules-grid" id="modulesGrid">
            <!-- Populated via API -->
          </div>
        </div>

        <!-- TAB 6: TERMINAL SHELL -->
        <div id="tab-shell" class="tab-pane" style="display: none;">
          <div class="terminal-panel">
            <div class="terminal-panel-header">
              <h3>Interactive Linux Recon Shell (v1.0.0)</h3>
              <span style="color: var(--term-green);">TTY: /dev/pts/1</span>
            </div>
            <div class="term-stdout" id="termConsole">
              <div><span class="cmd-prompt">root@redrecon-x:~#</span> REDRECON-X Linux Shell Environment Initialized.</div>
              <div><span class="cmd-dim">Type </span><span style="color:#fff;">help</span><span class="cmd-dim"> to view available commands or </span><span style="color:#fff;">scan &lt;domain&gt;</span><span class="cmd-dim"> to trigger live reconnaissance.</span></div>
              <br>
            </div>
            <div style="background:#020617; border-top:1px solid var(--border-subtle); padding:10px 16px; display:flex; align-items:center; gap:8px;">
              <span style="color:var(--term-green); font-family:var(--font-mono); font-weight:700;">root@redrecon-x:~#</span>
              <input type="text" id="termInput" onkeydown="if(event.key==='Enter') executeShellCommand()" style="flex:1; background:transparent; border:none; color:#fff; font-family:var(--font-mono); font-size:12px; outline:none;" placeholder="help, scans, modules, scan <target>...">
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <!-- Launch Scan Modal -->
  <div class="modal" id="scanModal">
    <div class="modal-box">
      <div class="modal-header">
        <h3>[EXECUTE] Launch Target Reconnaissance</h3>
        <span onclick="closeNewScan()" style="cursor:pointer; color:var(--text-dim);">&times;</span>
      </div>
      <div class="modal-body">
        <div>
          <label>Authorized Domain or IP Target</label>
          <input type="text" id="targetInput" placeholder="example.com">
        </div>
        <div>
          <label>Reconnaissance Mode</label>
          <select id="modeInput">
            <option value="full">Full Mode (CT + Subdomains + DNS + IP + HTTP + Nmap + Nuclei)</option>
            <option value="passive">Passive Mode (Zero Active Probing)</option>
          </select>
        </div>
        <div>
          <label>Max Nmap Port Scan Targets</label>
          <input type="number" id="maxNmapInput" value="10" min="1" max="100">
        </div>
        <div>
          <label>Max Nuclei Scan Targets</label>
          <input type="number" id="maxNucleiInput" value="15" min="1" max="100">
        </div>
        <div style="background:#020617; border:1px solid var(--border-subtle); padding:10px; border-radius:4px; font-size:11px; color:var(--term-green);">
          CLI Command Equivalent:<br>
          <code id="cmdPreview" style="color:#fff;">redrecon scan example.com --mode full</code>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn-cancel" onclick="closeNewScan()">Cancel</button>
        <button class="btn-submit" onclick="submitScan()">EXECUTE SCAN</button>
      </div>
    </div>
  </div>

  <script>
    let networkInstance = null;
    let cachedAssets = [];

    function getAuthHeaders() {
      const key = sessionStorage.getItem('redrecon_api_key') || '';
      return key ? { 'X-API-Key': key } : {};
    }

    function showTab(tabName) {
      document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

      const targetPane = document.getElementById('tab-' + tabName);
      const targetNav = document.getElementById('nav-' + tabName);
      if (targetPane) targetPane.style.display = 'block';
      if (targetNav) targetNav.classList.add('active');

      const titles = {
        'scans': 'Operations Console',
        'assets': 'Asset Inventory Explorer',
        'findings': 'Candidate Security Findings Ledger',
        'graph': 'Attack Surface Graph Topology',
        'modules': 'Reconnaissance Modules Matrix',
        'shell': 'Interactive Linux Shell Terminal'
      };
      document.getElementById('tabTitle').innerText = titles[tabName] || 'Operations';

      if (tabName === 'assets') loadAssets();
      if (tabName === 'findings') loadFindings();
      if (tabName === 'modules') loadModules();
      if (tabName === 'graph') initGraphView();
    }

    function openNewScan() {
      document.getElementById('scanModal').style.display = 'flex';
      updateCmdPreview();
    }
    function closeNewScan() {
      document.getElementById('scanModal').style.display = 'none';
    }

    document.getElementById('targetInput').addEventListener('input', updateCmdPreview);
    document.getElementById('modeInput').addEventListener('change', updateCmdPreview);
    document.getElementById('maxNmapInput').addEventListener('input', updateCmdPreview);
    document.getElementById('maxNucleiInput').addEventListener('input', updateCmdPreview);

    function updateCmdPreview() {
      const target = document.getElementById('targetInput').value.trim() || 'example.com';
      const mode = document.getElementById('modeInput').value;
      const nmap = document.getElementById('maxNmapInput').value;
      const nuclei = document.getElementById('maxNucleiInput').value;
      document.getElementById('cmdPreview').innerText = `redrecon scan ${target} --mode ${mode} --max-nmap-targets ${nmap} --max-nuclei-targets ${nuclei}`;
    }

    async function loadScans() {
      try {
        const res = await fetch('/api/scans', { headers: getAuthHeaders() });
        if (res.status === 401) {
          const key = prompt('Authentication required. Enter REDRECON API key (sent securely via X-API-Key header):');
          if (key) {
            sessionStorage.setItem('redrecon_api_key', key.trim());
            return loadScans();
          }
        }
        const scans = await res.json();
        document.getElementById('totalScans').innerText = scans.length;

        let totalAssets = 0;
        let totalFindings = 0;
        let targets = new Set();
        const select = document.getElementById('graphScanSelect');
        select.innerHTML = '';

        const tbody = document.getElementById('scansTableBody');
        if (scans.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--text-dim);">No scans recorded yet. Click "+ RUN RECON" to initiate discovery.</td></tr>';
          return;
        }

        tbody.innerHTML = scans.map(s => {
          const m = s.metrics || {};
          totalAssets += (m.discovered_hosts || 0);
          totalFindings += (m.nuclei_findings || 0);
          targets.add(s.target);

          const opt = document.createElement('option');
          opt.value = s.scan_id;
          opt.innerText = `${s.target} [${s.scan_id}]`;
          select.appendChild(opt);

          return `
            <tr>
              <td><code>${s.scan_id}</code></td>
              <td><strong style="color:#fff;">${s.target}</strong></td>
              <td><span class="tag tag-${s.mode}">${s.mode.toUpperCase()}</span></td>
              <td><span class="tag tag-completed">${s.status.toUpperCase()}</span></td>
              <td>${s.started_at ? s.started_at.split('T')[0] : 'N/A'}</td>
              <td>${s.duration_sec ? s.duration_sec.toFixed(1) : 0}s</td>
              <td style="color:var(--term-cyan); font-weight:700;">${m.discovered_hosts || 0}</td>
              <td style="color:var(--term-red); font-weight:700;">${m.nuclei_findings || 0}</td>
              <td>
                <a href="/reports/${s.target}/report.html" target="_blank" class="btn-action">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  Dossier &rarr;
                </a>
              </td>
            </tr>
          `;
        }).join('');

        document.getElementById('totalAssets').innerText = totalAssets;
        document.getElementById('totalFindings').innerText = totalFindings;
        document.getElementById('activeTargets').innerText = targets.size;
        document.getElementById('scanRefreshTime').innerText = 'Synced: ' + new Date().toLocaleTimeString();
      } catch (e) {
        console.error("Failed to load scans", e);
      }
    }

    async function loadAssets() {
      const tbody = document.getElementById('assetsTableBody');
      try {
        const res = await fetch('/api/assets', { headers: getAuthHeaders() });
        const assets = await res.json();
        cachedAssets = assets;
        renderAssetsTable(assets);
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--term-red);">Failed to load assets.</td></tr>';
      }
    }

    function renderAssetsTable(assets) {
      const tbody = document.getElementById('assetsTableBody');
      if (!assets || assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-dim);">No assets registered.</td></tr>';
        return;
      }
      tbody.innerHTML = assets.slice(0, 100).map(a => `
        <tr>
          <td><strong style="color:var(--term-green);">${a.hostname}</strong></td>
          <td>${(a.ip_addresses || []).join(', ') || 'N/A'}</td>
          <td>${a.http_status ? `<span class="tag tag-completed">${a.http_status}</span>` : '<span style="color:var(--text-dim);">-</span>'}</td>
          <td>${(a.ports || []).map(p => `<span class="tag tag-passive">${p.port}/${p.service_name}</span>`).join(' ') || '<span style="color:var(--text-dim);">-</span>'}</td>
          <td><span style="color:${a.priority_score > 4 ? 'var(--term-red)' : 'var(--term-green)'}; font-weight:bold;">${a.priority_score || 0}</span></td>
          <td><span class="tag tag-${(a.confidence || 'LOW').toLowerCase()}">${a.confidence || 'LOW'}</span></td>
        </tr>
      `).join('');
    }

    function filterAssetsTable() {
      const query = document.getElementById('assetSearchInput').value.toLowerCase();
      const filtered = cachedAssets.filter(a => 
        (a.hostname && a.hostname.toLowerCase().includes(query)) ||
        (a.ip_addresses && a.ip_addresses.some(ip => ip.includes(query)))
      );
      renderAssetsTable(filtered);
    }

    async function loadFindings() {
      const tbody = document.getElementById('findingsTableBody');
      try {
        const res = await fetch('/api/findings', { headers: getAuthHeaders() });
        const findings = await res.json();
        if (!findings || findings.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim);">No candidate vulnerabilities detected.</td></tr>';
          return;
        }
        tbody.innerHTML = findings.map(f => `
          <tr>
            <td><strong style="color:#fff;">${f.name}</strong></td>
            <td><span class="tag tag-${(f.severity || 'INFO').toLowerCase()}">${f.severity}</span></td>
            <td><code>${f.target}</code></td>
            <td><span class="tag tag-passive">${f.source}</span></td>
            <td style="color:var(--text-dim);">${f.template_id || 'N/A'}</td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:var(--term-red);">Failed to load findings.</td></tr>';
      }
    }

    async function loadModules() {
      const grid = document.getElementById('modulesGrid');
      try {
        const res = await fetch('/api/modules', { headers: getAuthHeaders() });
        const modules = await res.json();
        grid.innerHTML = modules.map(m => `
          <div class="module-card">
            <div class="module-code">[${m.code}] ACTIVE</div>
            <div class="module-name">${m.name}</div>
            <div class="module-class">Class: <code>${m.class}</code></div>
          </div>
        `).join('');
      } catch (e) {
        grid.innerHTML = '<div style="color:var(--term-red);">Failed to load modules registry.</div>';
      }
    }

    async function initGraphView() {
      const select = document.getElementById('graphScanSelect');
      if (select && select.value) {
        loadGraphData(select.value);
      }
    }

    async function loadGraphData(scanId) {
      if (!scanId) return;
      try {
        const res = await fetch(`/api/scans/${scanId}/graph`, { headers: getAuthHeaders() });
        const graphData = await res.json();
        const container = document.getElementById('graphContainer');

        const nodes = new vis.DataSet(graphData.nodes || []);
        const edges = new vis.DataSet(graphData.edges || []);

        const options = {
          physics: {
            stabilization: false,
            barnesHut: { gravitationalConstant: -3000, springLength: 95 }
          },
          nodes: {
            shape: 'dot',
            size: 16,
            font: { color: '#f8fafc', face: 'JetBrains Mono', size: 11 },
            borderWidth: 2
          },
          edges: {
            color: { color: '#334155', highlight: '#10b981' },
            arrows: { to: { enabled: true, scaleFactor: 0.5 } }
          }
        };

        if (networkInstance) networkInstance.destroy();
        networkInstance = new vis.Network(container, { nodes, edges }, options);
      } catch (e) {
        console.error("Failed to load attack graph", e);
      }
    }

    async function quickLaunch() {
      const input = document.getElementById('quickCommand');
      const target = input.value.trim();
      if (!target) return;
      input.value = '';
      logTerminal(`Initiating quick scan for ${target} [mode=full]...`);
      await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ target, mode: 'full' })
      });
      setTimeout(loadScans, 2000);
    }

    async function submitScan() {
      const target = document.getElementById('targetInput').value.trim();
      const mode = document.getElementById('modeInput').value;
      if (!target) return alert('Target domain required');
      closeNewScan();
      logTerminal(`Dispatched scan job for ${target} in ${mode.toUpperCase()} mode.`);
      await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ target, mode })
      });
      setTimeout(loadScans, 2000);
    }

    function logTerminal(text, isCmd = false) {
      const term = document.getElementById('termConsole');
      const div = document.createElement('div');
      if (isCmd) {
        div.innerHTML = `<span class="cmd-prompt">root@redrecon-x:~#</span> ${text}`;
      } else {
        div.innerHTML = `<span class="cmd-dim">[SYS]</span> ${text}`;
      }
      term.appendChild(div);
      term.scrollTop = term.scrollHeight;
    }

    function executeShellCommand() {
      const input = document.getElementById('termInput');
      const cmd = input.value.trim();
      if (!cmd) return;
      input.value = '';
      logTerminal(cmd, true);

      const parts = cmd.split(' ');
      const action = parts[0].toLowerCase();

      if (action === 'help') {
        logTerminal("Available commands:");
        logTerminal("  help              - Display this guide");
        logTerminal("  clear             - Clear terminal display");
        logTerminal("  scans             - Refresh and display recorded scans count");
        logTerminal("  modules           - List all 12 registered modules");
        logTerminal("  scan <domain>     - Execute reconnaissance against target");
      } else if (action === 'clear') {
        document.getElementById('termConsole').innerHTML = '';
      } else if (action === 'scans') {
        loadScans();
        logTerminal("Synchronized latest scan inventory with database.");
      } else if (action === 'modules') {
        logTerminal("Active engines: CT, Subdomains, DNS, IP, HTTP, Headers, Wayback, Nmap, Nuclei, AssetCorrelator, DifferenceEngine, Reporter");
      } else if (action === 'scan' && parts[1]) {
        fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify({ target: parts[1], mode: 'full' })
        });
        logTerminal(`[+] Reconnaissance task dispatched for: ${parts[1]}`);
        setTimeout(loadScans, 2000);
      } else {
        logTerminal(`Command not recognized: '${cmd}'. Type 'help' for command list.`);
      }
    }

    // Initial Load & Heartbeat
    loadScans();
    setInterval(loadScans, 8000);
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return DASHBOARD_HTML


@app.get("/api/scans", dependencies=[Depends(verify_api_key)])
def list_scans():
    return repo.list_scans()


@app.get("/api/scans/{scan_id}", dependencies=[Depends(verify_api_key)])
def get_scan(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/graph", dependencies=[Depends(verify_api_key)])
def get_scan_graph(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return AssetCorrelator.generate_attack_surface_graph(scan.target, scan.assets)


@app.get("/api/scans/{scan_id}/diff", dependencies=[Depends(verify_api_key)])
def get_scan_diff(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    prev_scan = repo.get_previous_scan_for_target(scan.target, exclude_scan_id=scan_id)
    if not prev_scan:
        return {"message": "No baseline scan found for target comparison", "target": scan.target}
    from redrecon.intelligence.difference import AttackSurfaceDifferenceEngine
    diff = AttackSurfaceDifferenceEngine.compare_scans(prev_scan, scan)
    return diff.model_dump(mode="json")


@app.get("/api/assets", dependencies=[Depends(verify_api_key)])
def list_assets(
    target: Optional[str] = None,
    scan_id: Optional[str] = None,
    confidence: Optional[str] = None,
    min_priority: Optional[int] = None,
    limit: int = 100,
):
    return repo.list_assets(
        target=target,
        scan_id=scan_id,
        confidence=confidence,
        min_priority=min_priority,
        limit=limit,
    )


@app.get("/api/assets/{asset_id}", dependencies=[Depends(verify_api_key)])
def get_asset(asset_id: int):
    asset = repo.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@app.get("/api/findings", dependencies=[Depends(verify_api_key)])
def list_findings(
    target: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
):
    return repo.list_findings(
        target=target,
        scan_id=scan_id,
        severity=severity,
        limit=limit,
    )


@app.get("/api/reports/{scan_id}", dependencies=[Depends(verify_api_key)])
def get_report(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "mode": scan.mode.value,
        "status": scan.status.value,
        "metrics": scan.metrics.model_dump(),
        "report_paths": {
            "json_summary": f"reports/{scan.target}/summary.json",
            "json_full": f"reports/{scan.target}/scan.json",
            "html_unified": f"reports/{scan.target}/report.html",
            "html_executive": f"reports/{scan.target}/executive_report.html",
            "html_technical": f"reports/{scan.target}/technical_report.html",
        }
    }


@app.get("/reports/{target}/{filename}")
def serve_report_file(target: str, filename: str):
    """Serve generated HTML and JSON report files for browser viewing."""
    reports_base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "reports"))
    if not os.path.exists(reports_base):
        reports_base = os.path.abspath("reports")

    target_clean = os.path.basename(target)
    filename_clean = os.path.basename(filename)
    file_path = os.path.join(reports_base, target_clean, filename_clean)

    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail=f"Report file '{filename_clean}' for target '{target_clean}' not found.",
        )

    media_type = "text/html" if file_path.endswith(".html") else "application/json" if file_path.endswith(".json") else None
    return FileResponse(file_path, media_type=media_type)


@app.get("/api/modules", dependencies=[Depends(verify_api_key)])
def list_modules():
    return [
        {"code": code, "name": name, "class": cls.__name__ if cls else "Reporter"}
        for code, (name, cls) in MODULE_REGISTRY.items()
    ]


async def _background_scan(target: str, mode: str):
    try:
        engine = ReconEngine()
        scan_mode = ScanMode.PASSIVE if mode == "passive" else ScanMode.FULL
        await engine.run_scan(target, mode=scan_mode)
    except Exception as e:
        logger.error(f"Background scan error for {target}: {e}", exc_info=True)


@app.post("/api/scan", dependencies=[Depends(verify_api_key)])
@app.post("/api/scans", dependencies=[Depends(verify_api_key)])
def trigger_scan(req: NewScanRequest, background_tasks: BackgroundTasks):
    norm_target = ScopeValidator.normalize_host(req.target, strip_wildcard=True)
    if not ScopeValidator.is_valid_domain(norm_target):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target domain: {req.target}. Must be a valid FQDN or IP.",
        )
    background_tasks.add_task(_background_scan, norm_target, req.mode)
    return {"message": "Scan queued", "target": norm_target, "mode": req.mode}


def start_dashboard(host: str = "127.0.0.1", port: int = 8000):
    print(f"[*] Launching REDRECON-X Intelligence Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
