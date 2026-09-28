# REDRECON-X

### Modular Automated Web Reconnaissance & Attack-Surface Intelligence Framework

> **Discover. Correlate. Understand.**

```text
██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║  ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║
██║  ██║███████╗██████╔╝██████╔╝███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-red.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Windows%20%7C%20macOS-blue.svg)](README.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)

---

## 1. Overview

**REDRECON-X** is an enterprise-grade, modular attack-surface intelligence and automated reconnaissance framework written in Python. Rather than acting as a disjointed script wrapper, REDRECON-X functions as an **asset intelligence engine**: it orchestrates passive enumeration, active resolution, HTTP probing, defensive header analysis, port fingerprinting, and security audits into a **unified graph-based attack surface model**.

```text
                     REDRECON-X
                         │
             ┌───────────┴───────────┐
             │                       │
       PASSIVE RECON             ACTIVE RECON
             │                       │
      ┌──────┼──────┐        ┌───────┼────────┐
      ▼      ▼      ▼        ▼       ▼        ▼
     CT   Wayback  Subdomain DNS     HTTP     Nmap
      │      │      │        │       │        │
      └──────┴──────┴────────┴───────┴────────┘
                         │
                         ▼
                  ASSET CORRELATION
                         │
                         ▼
                  SECURITY ANALYSIS
                         │
                         ▼
                    NUCLEI SCAN
                         │
                         ▼
                  REPORT GENERATOR
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
          JSON Report           HTML Report
```

---

## 2. Key Differentiator: Asset Intelligence Engine

Traditional recon tools output fragmented files from each tool:

```text
Python
 ├── Nmap      -> raw terminal output / nmap.xml
 ├── Nuclei    -> raw JSON lines
 ├── Subfinder -> hosts.txt
 └── Wayback   -> urls.txt
```

REDRECON-X eliminates telemetry fragmentation by compiling all signals into a **correlated asset graph**:

```text
                     example.com
                          │
             ┌────────────┼────────────┐
             │            │            │
      api.example.com    www          dev
             │            │            │
             ▼            ▼            ▼
       203.0.113.10     IP-02        IP-03
             │            │            │
             ▼            ▼            ▼
         HTTPS: 443      443           80
             │            │            │
           nginx         nginx       Apache
             │
      ┌──────┴────────────────────────┐
      ▼                               ▼
"API Gateway" (200 OK)       Security Headers:
184 ms response latency      HSTS ✓ | CSP ⚠ | XFO ✓
```

### Multi-Source Asset Confidence Scoring

Every asset receives a defensible confidence score:

| Signal | Source / Observation | Confidence Weight |
|---|---|---|
| **CT Logs** | Discovered in crt.sh / CertSpotter | Baseline historical discovery |
| **Wayback Machine** | Historical archive URL | Historical asset existence |
| **DNS Resolution** | A/AAAA or CNAME records resolved | Live name resolution confirmation |
| **HTTP Probe** | Active 200/301/403 web endpoint | **Confirmed Live Service** |
| **Port Scanner** | Live TCP socket / open port | **Confirmed Live Host** |

- **HIGH CONFIDENCE**: Verified live service (HTTP endpoint responding or active TCP ports confirmed) or validated across multiple corroborating independent feeds.
- **MEDIUM CONFIDENCE**: Resolved in DNS (A/AAAA/CNAME present), awaiting port/HTTP verification.
- **LOW CONFIDENCE**: Historical-only artifact (discovered on Wayback or expired CT certificate, but currently fails DNS resolution).

---

## 3. Architecture & Modules

```text
REDRECON-X/
│
├── redrecon/
│   ├── cli/
│   │   ├── main.py              # Typer CLI application entry point
│   │   ├── banner.py            # Rich red ASCII banner
│   │   └── commands.py          # Command handlers and terminal formatters
│   │
│   ├── core/
│   │   ├── engine.py            # Recon orchestration pipeline
│   │   ├── scope.py             # Boundary validation & cloud asset protection
│   │   ├── config.py            # YAML configuration loader
│   │   └── logger.py            # Rich console logger
│   │
│   ├── modules/
│   │   ├── certificate/         # [01] Certificate Transparency (crt.sh, CertSpotter)
│   │   ├── subdomain/           # [02] Multi-source Subdomain Engine (5+ providers)
│   │   ├── dns/                 # [03] DNS Resolver (A, AAAA, CNAME, MX, TXT, NS)
│   │   ├── ip/                  # [04] IP Discovery & reverse PTR correlation
│   │   ├── http/                # [05-07] HTTP/HTTPS Prober, Title & Status detection
│   │   ├── headers/             # [08] Defensive Security Header Analyzer
│   │   ├── wayback/             # [09] Wayback CDX URL Discovery & Classifier
│   │   ├── nmap/                # [10] Nmap XML Adapter + Native async socket fallback
│   │   └── nuclei/              # [11] Nuclei JSONL Adapter + Heuristic auditor
│   │
│   ├── intelligence/
│   │   ├── correlation.py       # Graph correlation & relationship mapping
│   │   ├── deduplication.py     # Cross-feed asset and URL deduplication
│   │   ├── prioritization.py    # Asset confidence scoring
│   │   └── timeline.py          # Benchmark duration & metrics tracker
│   │
│   ├── storage/
│   │   ├── database.py          # SQLite database schema
│   │   └── repository.py        # Scan history and asset repository
│   │
│   ├── reporting/
│   │   ├── json.py              # Organized JSON evidence exporter
│   │   └── html.py              # Interactive standalone HTML dashboard
│   │
│   └── dashboard/
│       └── app.py               # FastAPI web server and REST API
│
├── configs/default.yaml         # Default runtime configurations
├── tests/                       # Complete pytest test suite
├── Dockerfile                   # Kali / Debian container image
└── setup.py                     # Package installation definition
```

---

## 4. Installation

### Option 1: Native Python (Linux, Kali, macOS, Windows)

```bash
git clone https://github.com/your-org/redrecon-x.git
cd redrecon-x
pip install -r requirements.txt
pip install -e .
```

### Option 2: Docker Container (With Nmap & Nuclei pre-installed)

```bash
docker build -t redrecon-x .
docker run --rm -v $(pwd)/reports:/app/reports redrecon-x scan example.com --mode full
```

---

## 5. Usage & CLI Commands

### 1. Full Reconnaissance Mode (Default)
Executes the complete pipeline: Scope Check &rarr; CT &rarr; Subdomains &rarr; DNS &rarr; IP &rarr; HTTP/HTTPS &rarr; Headers &rarr; Wayback &rarr; Nmap/Ports &rarr; Nuclei/Security &rarr; Asset Correlation &rarr; Reporting.

```bash
redrecon scan example.com --mode full
```

### 2. Passive Reconnaissance Mode
Discovers certificates, subdomains, archive URLs, and DNS records without launching active port probes or intrusive vulnerability scans.

```bash
redrecon scan example.com --mode passive
```

### 3. Individual Modular Execution
Every scanner is independently executable:

```bash
redrecon cert example.com          # Certificate Transparency enumeration
redrecon subdomains example.com    # Multi-source subdomain discovery
redrecon dns example.com           # DNS record tree resolution
redrecon http example.com          # HTTP probing, title & latency
redrecon headers example.com       # Defensive security header evaluation
redrecon wayback example.com       # Historical URL discovery & categorization
redrecon ports example.com         # Nmap / native socket port scan
redrecon nuclei example.com        # Candidate security exposure checks
```

### 4. List All Available Modules

```bash
redrecon modules
```

```text
AVAILABLE MODULES

[01] Certificate Transparency
[02] Subdomain Discovery
[03] DNS Resolution
[04] IP Discovery
[05] HTTP/HTTPS Probe
[06] HTTP Title Detection
[07] HTTP Status Detection
[08] Security Header Analysis
[09] Wayback URL Discovery
[10] Nmap Port Scanner
[11] Nuclei Scanner
[12] Report Generator
```

### 5. Attack Surface Drift & Difference Engine (§27 & §48)

Track changes over time across scans:

```bash
redrecon diff example.com                      # Compare the two most recent scans of example.com
redrecon diff RX-20260920-001 RX-20260928-002  # Compare two specific scan IDs
```

The difference engine detects:
- `+ New Assets` (first observed in the recent scan)
- `- Removed Assets` (disappeared or unresolvable since last scan)
- `! New Open Ports / Services`
- `! New Candidate Findings` & `✓ Remediated Findings`
- Configuration changes in defensive security headers

### 6. Transparent Attack Surface Priority Scoring (§38)

Unlike arbitrary risk scores, REDRECON-X calculates a transparent additive priority based strictly on observable exposure characteristics:

$$\text{Priority} = \text{Internet Exposed (+3)} + \text{Service Exposure (+1)} + \text{Admin Context (+2)} + \text{Config Observation (+1)} + \text{Candidate Finding (+2)}$$

### 7. Executive & Technical Reports (§37)

Generate and open dedicated report formats:

```bash
redrecon report example.com --type all         # Comprehensive interactive cyber report
redrecon report example.com --type executive   # CISO & leadership risk posture summary
redrecon report example.com --type technical   # Detailed technical dossier
```

### 8. Web Intelligence Dashboard & REST API (§35)

Launch the interactive web dashboard and REST API:

```bash
redrecon dashboard --port 8000
```

Available REST Endpoints:
- `GET  /api/scans` — List scan history & metrics
- `POST /api/scans` — Trigger a new scan (`{"target": "example.com", "mode": "full"}`)
- `GET  /api/scans/{id}` — Full scan details & correlated assets
- `GET  /api/scans/{id}/diff` — Attack surface drift against previous baseline scan
- `GET  /api/scans/{id}/graph` — Cytoscape / React Flow attack-surface graph
- `GET  /api/assets` — Query assets with filters (`?confidence=HIGH&min_priority=4`)
- `GET  /api/assets/{id}` — Detailed asset entity by database ID
- `GET  /api/findings` — Query findings with filters (`?severity=HIGH`)
- `GET  /api/reports/{id}` — Report paths and artifact links

---

## 6. Organized Output Structure

Outputs follow an organized, per-target directory structure:

```text
reports/
└── example.com/
    │
    ├── scan.json              # Unified scan object with all correlated assets
    ├── summary.json           # High-level metrics, counts, and scan timestamps
    │
    ├── passive/
    │   ├── certificates.json  # Raw certificate transparency entries
    │   ├── subdomains.json    # Discovered subdomains and provenance breakdown
    │   ├── wayback.json       # Categorized archive URLs (API, Auth, Admin, etc.)
    │   └── dns.json           # A, AAAA, CNAME, MX, TXT, NS records
    │
    ├── active/
    │   ├── http.json          # Status, titles, headers, response latency
    │   ├── headers.json       # Security header observations and remediation
    │   └── nmap.json          # Open ports, states, and service fingerprints
    │
    ├── nuclei/
    │   └── findings.json      # Normalized candidate security findings
    │
    └── report.html            # Standalone interactive cyber-themed HTML report
```

---

## 7. Scope Control & Boundary Protection

Before active modules execute, the target is validated against the scope controller:

```text
TARGET
  ↓
SCOPE VALIDATOR
  ↓
Is asset authorized?
  │
 ┌┴─────────┐
YES         NO
 │           │
 ▼           ▼
SCAN       BLOCK
```

- Wildcard matching (`*.example.com`)
- Strict exclusion lists (e.g. `secret.example.com`, `mail.example.com`)
- Third-party cloud protection: prevents unauthorized scanning of CDN and public cloud edges (e.g. S3 buckets, Cloudflare, Akamai, Azure Edge) unless explicitly allowed in `configs/default.yaml`.

---

## 8. Academic Research & MSc Evaluation Framework

For academic thesis work, cybersecurity dissertations, or comparative benchmarks, REDRECON-X is designed around the following research framing:

### Research Title
> **"Design and Evaluation of an Automated Multi-Source Attack Surface Discovery Framework"**

### Core Research Question
> *How effectively can multiple passive and active reconnaissance sources be integrated into a unified framework to improve external attack-surface visibility while reducing duplicate and fragmented reconnaissance results?*

### Benchmark Metrics Tracked

| Evaluation Metric | Description | Benchmark Formula |
|---|---|---|
| **Coverage Gain** | Improvement in unique assets identified compared to individual tools | $\frac{\text{Unique Hosts (Multi-Source)}}{\text{Unique Hosts (Single Tool)}} - 1$ |
| **Deduplication Rate** | Redundant data artifacts filtered out across providers | $\text{Raw Hosts} - \text{Unique Hosts}$ |
| **Verification Ratio** | Percentage of discovered hostnames confirmed live | $\frac{\text{Live Hosts}}{\text{Total Discovered Hosts}}$ |
| **Pipeline Throughput** | Speed and latency of async concurrent scanning | $\text{Scan Duration (s)}$ tracked per module in `ScanTimeline` |
| **Correlation Completeness** | Number of multi-layered entity connections created | Total graph nodes & edges generated |

---

## 9. Running Tests

```bash
python -m pytest tests/ -v
```

All 14 unit and integration tests validate scope enforcement, deduplication efficiency, prioritization algorithms, header rules, correlation mapping, and SQLite storage.

---

## 10. Legal & Ethical Disclaimer

> **IMPORTANT**: REDRECON-X is designed strictly for authorized penetration testing, security research, and vulnerability assessments on systems you own or have explicit written authorization to evaluate. Performing reconnaissance against third-party systems without prior authorization is illegal.
