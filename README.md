# REDRECON-X

### Modular Automated Web Reconnaissance & Attack-Surface Intelligence Framework

> **Discover. Correlate. Understand.**  
> **Developer:** [AnandBinuArjun](https://github.com/AnandBinuArjun)

```text
██████╗ ███████╗██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║  ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║
██║  ██║███████╗██████╔╝██████╔╝███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
```

[![CI Pipeline](https://github.com/AnandBinuArjun/REDRECON-X/actions/workflows/ci.yml/badge.svg)](https://github.com/AnandBinuArjun/REDRECON-X/actions)
[![Security SAST](https://github.com/AnandBinuArjun/REDRECON-X/actions/workflows/security.yml/badge.svg)](https://github.com/AnandBinuArjun/REDRECON-X/actions)
[![Docker Build](https://github.com/AnandBinuArjun/REDRECON-X/actions/workflows/docker.yml/badge.svg)](https://github.com/AnandBinuArjun/REDRECON-X/actions)
[![Release](https://img.shields.io/github/v/release/AnandBinuArjun/REDRECON-X?color=green)](https://github.com/AnandBinuArjun/REDRECON-X/releases)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-red.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)

---

## 1. Overview

**REDRECON-X** is an academic-grade, modular attack-surface intelligence and automated reconnaissance framework written in Python. Rather than acting as a disjointed script wrapper, REDRECON-X functions as an **asset intelligence engine**: it orchestrates passive enumeration, active resolution, HTTP probing, defensive header analysis, port fingerprinting, and security audits into a **unified graph-based attack surface model**.

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
git clone https://github.com/AnandBinuArjun/REDRECON-X.git
cd REDRECON-X
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

### 1. Full Reconnaissance Mode
Executes the complete pipeline: Scope Check &rarr; CT &rarr; Subdomains &rarr; DNS &rarr; IP &rarr; HTTP/HTTPS &rarr; Headers &rarr; Wayback &rarr; Nmap/Ports &rarr; Nuclei/Security &rarr; Asset Correlation &rarr; Reporting.

```bash
redrecon full example.com                      # Direct command
# or with configurable active scan limits:
redrecon scan example.com --mode full --max-nmap-targets 25 --max-nuclei-targets 30 --max-http-targets 150
```

> **Target Limit Configuration**: For responsible operations, active intrusive probes (Nmap & Nuclei) have safety defaults (`max_nmap_targets: 10`, `max_nuclei_targets: 15`). In authorized environments, expand these limits up to your authorized scope using CLI flags or `configs/default.yaml`.

### 2. Passive Reconnaissance Mode
Discovers certificates, subdomains, archive URLs, and DNS records without launching active port probes or intrusive vulnerability scans.

```bash
redrecon passive example.com                   # Direct command
# or:
redrecon scan example.com --mode passive       # Standard command
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

### 8. Modern Linux Cyber Terminal Dashboard & REST API (§35)

REDRECON-X features a high-density, modern Linux cyber terminal console powered by FastAPI:
- **Design System**: OLED background (`#030712`), Linux terminal window chrome with status telemetry, and `JetBrains Mono` monospace typography.
- **Topology Graph**: Interactive Vis.js attack-surface graph visualizing entity relationships (`Domain` → `Subdomain` → `IP` → `Port` → `Finding`).
- **Interactive Shell**: Embedded `/dev/pts/1` terminal shell for immediate command execution and modular probing.
- **API Key Security**: Endpoints strictly require header authentication (`X-API-Key: <key>`); URL query parameter key leaks are rejected.

```bash
redrecon dashboard --port 8000
```

Available REST Endpoints:
- `GET  /api/scans` — List scan history & metrics
- `POST /api/scans` — Trigger a new scan (`{"target": "example.com", "mode": "full"}`)
- `GET  /api/scans/{id}` — Full scan details & correlated assets
- `GET  /api/scans/{id}/diff` — Attack surface drift against previous baseline scan
- `GET  /api/scans/{id}/graph` — Vis.js attack-surface graph topology
- `GET  /api/assets` — Query assets with filters (`?confidence=HIGH&min_priority=4`)
- `GET  /api/assets/{id}` — Detailed asset entity by database ID
- `GET  /api/findings` — Query findings with filters (`?severity=HIGH`)
- `GET  /api/reports/{id}` — Report paths and artifact links
- `GET  /reports/{target}/{filename}` — Stream interactive HTML & JSON reports

### 9. Pre-configured Scan Profiles

Select an operational profile tailored to your assessment engagement:

```bash
redrecon scan example.com --profile bugbounty    # Deep OSINT, full DNS, extensive HTTP probing
redrecon scan example.com --profile pentest      # Full active scan with top-100 Nmap & Nuclei
redrecon scan example.com --profile fast         # High-concurrency rapid asset discovery
redrecon scan example.com --profile monitoring   # Lightweight recurring baseline drift check
```

Profiles are defined in `configs/profiles/*.yaml` and override default concurrency, timeouts, and module toggles cleanly.

### 10. Scan Resource Controls & Bounds

To ensure stability across massive external domains, REDRECON-X enforces strict bounding limits:
```yaml
# configs/default.yaml
scan_limits:
  max_subdomains: 500       # Capped to avoid unbounded DNS lookups
  max_http_targets: 150     # Limit for active HTTP/HTTPS probing
  max_nmap_targets: 25      # Active port scan IP threshold
  max_nuclei_targets: 50    # Vulnerability scan target threshold
  max_wayback_urls: 10000   # Archive URL extraction boundary
concurrency: 25             # Async worker pipeline concurrency
timeout: 8.0                # Socket and HTTP timeout limit (seconds)
```

### 11. Automated Notifications & Webhook Dispatcher

Configure webhooks in your profile or environment (`REDRECON_WEBHOOK_URL`) to receive real-time JSON alerts for:
- `SCAN_COMPLETED`: Scan summary with asset and finding metrics.
- `ATTACK_SURFACE_DRIFT`: Alerts on newly exposed assets, new open ports, or altered HTTP response headers.
- `SECURITY_FINDING_ALERT`: Critical and High severity candidate findings.

### 12. Controlled Cyber Range Test Lab

Evaluate the complete framework in an offline, reproducible environment:
```bash
docker-compose -f docker-compose.lab.yml up -d
redrecon scan lab.redrecon.local --mode full
```
The lab simulates an enterprise multi-tier environment (Web, API, DNS server, vulnerable apps) for controlled benchmark evaluation.

### 13. Empirical Research Benchmark Engine

For academic evaluation and dissertation defense, REDRECON-X provides a dedicated benchmark command that measures multi-source yield, deduplication performance, and live verification ratios against single-source Certificate Transparency:

```bash
redrecon benchmark example.com
```

This exports three reproducible evaluation artifacts in `reports/benchmark_<target>_<timestamp>/`:
- `benchmark.json` — Machine-readable evaluation dataset including config hash and platform metrics
- `benchmark.csv` — Delimited metrics suitable for importing directly into LaTeX, R, or Python dataframes
- `benchmark.html` — Interactive visualization with provider distribution and metric cards

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

### Empirical Evaluation Results

Controlled experimental trials across authoritative testbeds demonstrated empirical validation of the research questions:

| Experiment | Configuration | Raw Discoveries | Unique Assets | Deduplication Rate | Live Hosts | Duration | Coverage Gain |
|---|---|---|---|---|---|---|---|
| **Exp 1: Baseline** | Single-Source CT (`crt.sh`) | 24 | 24 | 0.0% | 14 | 18.2s | Baseline |
| **Exp 1: Multi-Source** | **REDRECON-X Multi-Source** | **86** | **49** | **43.0%** (37 removed) | **31** | 41.5s | **+104.2%** |
| **Exp 2: Chaining** | Disjoint Manual Tools | 86 | 49 | N/A (manual) | 31 | 124.8s | Baseline |
| **Exp 2: Async Pipeline**| **REDRECON-X Pipeline** | **86** | **49** | **43.0%** | **31** | **41.5s** | **66.8% faster** |
| **Exp 3: Drift Engine** | Temporal Drift Precision | 4 mutated entities | 4 detected | 0 false positives | 4 | 8.4s | **100% F1-Score** |

> Complete experimental protocols, raw datasets, and statistical derivations are documented in [docs/experiments/METHODOLOGY.md](docs/experiments/METHODOLOGY.md) and [benchmarks/experiment_results.csv](benchmarks/experiment_results.csv).

---

## 9. Running Tests & Continuous Integration

```bash
python -m pytest tests/ -v --cov=redrecon
```

All **41 automated tests** validate the core framework:
- **Unit & Logic Tests**: Scope boundaries, normalization, multi-source deduplication, transparent priority scoring, defensive header analysis, correlation models, and SQLite persistence.
- **End-to-End Pipeline & Resilience**: End-to-end passive scan verification, graceful cancellation state preservation (`ScanStatus.CANCELLED`), unhandled exception recovery (`ScanStatus.FAILED`), and pre-pipeline boundary aborts.
- **Drift & Difference Engine**: Validation of asset/port/finding delta detection between baseline and active scans.
- **Failure Resilience**: Graceful handling of corrupt/truncated Nmap XML, malformed/non-JSON Nuclei output, DNS timeouts, and third-party cloud infrastructure bypass attempts.
- **Security Hardening**: Enforces rejection of API keys provided via URL query strings (`?api_key=`), ensuring authentication strictly relies on `X-API-Key` or `Authorization: Bearer` request headers.
- **CLI & Module Suite**: Verification of Typer CLI entrypoints, modular arguments, and benchmark generation.
- **Multi-Platform CI/CD**:
  - `REDRECON-X CI` (`.github/workflows/ci.yml`): Matrix testing on Python 3.10, 3.11, and 3.12 across both Ubuntu and Windows runners.
  - `Security Audit & SAST` (`.github/workflows/security.yml`): Bandit security linter and pip-audit dependency scanner.
  - `Docker Build & Verification` (`.github/workflows/docker.yml`): Container compilation and CLI verification.

---

## 10. Developer & Author

- **Author**: AnandBinuArjun
- **GitHub**: [@AnandBinuArjun](https://github.com/AnandBinuArjun)
- **Repository**: [REDRECON-X](https://github.com/AnandBinuArjun/REDRECON-X)

---

## 11. Legal & Ethical Disclaimer

> **IMPORTANT**: REDRECON-X is designed strictly for authorized penetration testing, security research, and vulnerability assessments on systems you own or have explicit written authorization to evaluate. Performing reconnaissance against third-party systems without prior authorization is illegal.
