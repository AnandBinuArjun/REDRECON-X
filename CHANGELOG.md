# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-09-28

### Added
- **Asynchronous Reconnaissance Engine**: Fully non-blocking multi-stage pipeline orchestrating Certificate Transparency, multi-source subdomain discovery, DNS tree resolution, IP correlation, HTTP/HTTPS probing, defensive header analysis, Wayback URL collection, Nmap port scanning, and Nuclei exposure auditing.
- **Modern Linux Cyber Terminal Web UI**: Real-time operations console built with UI-UX Pro Max intelligence featuring Linux window chrome, live polling, Vis.js attack-surface graph topology, filterable asset inventory, candidate findings ledger, and embedded interactive shell terminal (`/dev/pts/1`).
- **Empirical Research Benchmark Engine**: Built-in CLI command (`redrecon benchmark <target>`) and empirical dataset measuring coverage gain (+104.2%), deduplication efficiency (43.0%), and live verification ratio (63.3%).
- **Interactive Network Graph Topology**: Dynamic Vis.js network visualization in HTML reports and dashboard with physics simulation, zoom/pan controls, and entity inspector.
- **Configurable Active Scan Targets**: `--max-nmap-targets`, `--max-nuclei-targets`, and `--max-http-targets` flags to control active assessment boundaries.
- **Security & Authorization Controls**: Strict header-based API authentication (`X-API-Key` and `Authorization: Bearer`), rejection of query-parameter key exposure (`?api_key=`), and third-party cloud/CDN scope filtering.
- **Reproducibility & Provenance Tracking**: Automated SHA-256 configuration hashing, OS platform metadata, and tool version capture in all scan results.
- **Comprehensive Automated Test Suite**: 31 unit, integration, failure resilience, and security tests.
- **Continuous Integration (CI)**: GitHub Actions workflow testing Python 3.10, 3.11, and 3.12 across Ubuntu and Windows runners.

### Changed
- Standardized terminology to **Candidate Security Findings** across all prioritized vulnerability feeds.
- Corrected installation and cloning references in documentation.
- Elevated dashboard report file serving with native `FileResponse` and `aiofiles`.

### Security
- Hardened dashboard endpoints against unauthorized query string token leaks.
- Enforced strict scope containment preventing unintentional scanning of out-of-scope cloud infrastructure (AWS S3, Cloudflare, Akamai, Azure Edge).

---

[1.0.0]: https://github.com/AnandBinuArjun/REDRECON-X/releases/tag/v1.0.0
