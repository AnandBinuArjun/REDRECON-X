import asyncio
from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from redrecon.core.config import ScanConfig, load_config
from redrecon.core.logger import console, get_logger
from redrecon.core.scope import ScopeValidator
from redrecon.intelligence.correlation import AssetCorrelator
from redrecon.intelligence.deduplication import AssetDeduplicator
from redrecon.intelligence.timeline import ScanTimeline
from redrecon.models.finding import Finding
from redrecon.models.scan import ScanMetrics, ScanMode, ScanResult, ScanStatus
from redrecon.modules.certificate.scanner import CertificateScanner
from redrecon.modules.dns.scanner import DNSScanner
from redrecon.modules.headers.analyzer import HeaderAnalyzer
from redrecon.modules.http.scanner import HTTPScanner
from redrecon.modules.ip.scanner import IPScanner
from redrecon.modules.nmap.scanner import NmapScanner
from redrecon.modules.nuclei.scanner import NucleiScanner
from redrecon.modules.subdomain.scanner import SubdomainScanner
from redrecon.modules.wayback.scanner import WaybackScanner
from redrecon.reporting.html import HTMLReporter
from redrecon.reporting.json import JSONReporter
from redrecon.storage.database import Database
from redrecon.storage.repository import ScanRepository

logger = get_logger()


class ReconEngine:
    """
    REDRECON-X Core Orchestration Engine.
    Executes passive or full reconnaissance workflows, coordinates modules,
    performs scope validation, tracks timeline metrics, and generates correlated reports.
    """

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or load_config()
        self.db = Database(db_path=self.config.db_path)
        self.repo = ScanRepository(self.db)

    async def run_scan(
        self,
        target: str,
        mode: ScanMode = ScanMode.FULL,
        scan_id: Optional[str] = None,
    ) -> ScanResult:
        """
        Execute full or passive recon pipeline for target domain.
        """
        norm_target = ScopeValidator.normalize_host(target)
        if not ScopeValidator.is_valid_domain(norm_target):
            raise ValueError(f"Invalid domain or target: {target}")

        scan_id = scan_id or f"RX-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:6]}"
        timeline = ScanTimeline()

        logger.info(f"Initialized scan [bold yellow]{scan_id}[/bold yellow] for [bold cyan]{norm_target}[/bold cyan] [mode: {mode.value.upper()}]")

        # 1. Scope validation
        scope_validator = ScopeValidator(
            target_domain=norm_target,
            allowed_domains=self.config.allowed_domains,
            excluded_domains=self.config.excluded_domains,
            allow_third_party=self.config.allow_third_party,
        )

        raw_data: Dict[str, Any] = {
            "certificates": {},
            "subdomains": {},
            "wayback": {},
            "dns": {},
            "http": {},
            "headers": {},
            "nmap": {},
            "nuclei": {},
        }
        # Save initial RUNNING scan state
        initial_scan = ScanResult(
            scan_id=scan_id,
            target=norm_target,
            mode=mode,
            status=ScanStatus.RUNNING,
            started_at=datetime.fromtimestamp(timeline.start_time, tz=timezone.utc),
            completed_at=None,
            assets=[],
            findings=[],
            metrics=ScanMetrics(scan_duration_sec=0.0),
            raw_data=raw_data,
        )
        self.repo.save_scan(initial_scan)

        try:
            return await self._execute_pipeline(
                norm_target=norm_target,
                mode=mode,
                scan_id=scan_id,
                timeline=timeline,
                scope_validator=scope_validator,
                raw_data=raw_data,
            )
        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.warning(f"Scan {scan_id} interrupted or cancelled. Safely persisting aborted state.")
            cancelled_scan = ScanResult(
                scan_id=scan_id,
                target=norm_target,
                mode=mode,
                status=ScanStatus.CANCELLED,
                started_at=datetime.fromtimestamp(timeline.start_time, tz=timezone.utc),
                completed_at=datetime.now(timezone.utc),
                assets=[],
                findings=[],
                metrics=ScanMetrics(scan_duration_sec=round(datetime.now().timestamp() - timeline.start_time, 2)),
                raw_data={"error": "Scan execution interrupted / cancelled", **raw_data},
            )
            self.repo.save_scan(cancelled_scan)
            raise
        except Exception as exc:
            logger.error(f"Scan {scan_id} failed: {exc}")
            failed_scan = ScanResult(
                scan_id=scan_id,
                target=norm_target,
                mode=mode,
                status=ScanStatus.FAILED,
                started_at=datetime.fromtimestamp(timeline.start_time, tz=timezone.utc),
                completed_at=datetime.now(timezone.utc),
                assets=[],
                findings=[],
                metrics=ScanMetrics(scan_duration_sec=round(datetime.now().timestamp() - timeline.start_time, 2)),
                raw_data={"error": str(exc), **raw_data},
            )
            self.repo.save_scan(failed_scan)
            raise

    async def _execute_pipeline(
        self,
        norm_target: str,
        mode: ScanMode,
        scan_id: str,
        timeline: ScanTimeline,
        scope_validator: ScopeValidator,
        raw_data: Dict[str, Any],
    ) -> ScanResult:
        """Internal execution pipeline for scan stages."""
        # Initialize Scanners
        cert_scanner = CertificateScanner(self.config)
        sub_scanner = SubdomainScanner(self.config)
        wayback_scanner = WaybackScanner(self.config)
        dns_scanner = DNSScanner(self.config)
        ip_scanner = IPScanner(self.config)
        http_scanner = HTTPScanner(self.config)
        headers_analyzer = HeaderAnalyzer(self.config)
        nmap_scanner = NmapScanner(self.config)
        nuclei_scanner = NucleiScanner(self.config)

        # -------------------------------------------------------------
        # STAGE 1: Passive Discovery (CT, Subdomains, Wayback)
        # -------------------------------------------------------------
        timeline.start_stage("passive_discovery")

        # 1. Query Certificate Transparency and Wayback Archive once
        ct_task = cert_scanner.scan(norm_target)
        wb_task = wayback_scanner.scan(norm_target)
        ct_res, wb_res = await asyncio.gather(ct_task, wb_task)

        # 2. Extract hostnames from Wayback URLs
        from urllib.parse import urlparse
        wb_hosts = set()
        for u in wb_res.get("urls", []):
            try:
                h = urlparse(u).netloc.split(":")[0].lower()
                if h == norm_target or h.endswith(f".{norm_target}"):
                    wb_hosts.add(h)
            except Exception:
                pass

        preloaded = {
            "Certificate Transparency": ct_res.get("subdomains", []),
            "Wayback Machine": sorted(list(wb_hosts)),
        }

        # 3. Run remaining discovery providers without redundant duplicate requests
        sub_res = await sub_scanner.scan(
            norm_target,
            skip_providers=["Certificate Transparency", "Wayback Machine"],
            preloaded_results=preloaded,
        )
        raw_data["subdomains"] = sub_res
        raw_data["wayback"] = wb_res
        raw_data["certificates"] = ct_res

        # Merge discovered hosts
        all_hosts_with_sources = []
        for h in sub_res.get("subdomains", []):
            for src in sub_res.get("provenance", {}).get(h, ["Subdomain Engine"]):
                all_hosts_with_sources.append((h, src))

        for h in ct_res.get("subdomains", []):
            all_hosts_with_sources.append((h, "Certificate Transparency"))

        unique_hosts, provenance_map, duplicates_count = AssetDeduplicator.deduplicate_hosts(
            all_hosts_with_sources
        )

        # Filter strictly by scope
        scoped_hosts = [h for h in unique_hosts if scope_validator.is_in_scope(h)]
        timeline.end_stage("passive_discovery", items_processed=len(scoped_hosts))

        # -------------------------------------------------------------
        # STAGE 2: DNS & IP Resolution
        # -------------------------------------------------------------
        timeline.start_stage("dns_ip_resolution")
        dns_results = await dns_scanner.scan_hosts(scoped_hosts)
        raw_data["dns"] = dns_results

        ip_res = await ip_scanner.correlate_ips(dns_results)
        raw_data["ip"] = ip_res
        timeline.end_stage("dns_ip_resolution", items_processed=len(ip_res.get("unique_ips", [])))

        # Identify live hosts (hosts with A, AAAA or CNAME records)
        live_dns_hosts = [
            h for h, d in dns_results.items() if d.get("is_resolved")
        ]
        # Always probe the root domain even if external DNS failed
        if norm_target not in live_dns_hosts:
            live_dns_hosts.append(norm_target)

        http_results: Dict[str, Dict[str, Any]] = {}
        headers_results: Dict[str, List[Dict[str, Any]]] = {}
        ports_results: Dict[str, List[Any]] = {}
        all_findings: List[Finding] = []

        # -------------------------------------------------------------
        # STAGE 3: Active Reconnaissance (HTTP, Headers, Nmap, Nuclei)
        # -------------------------------------------------------------
        if mode == ScanMode.FULL:
            logger.info(f"Initiating active probing for [bold cyan]{len(live_dns_hosts)}[/bold cyan] live targets...")

            # 3a. HTTP Probing
            timeline.start_stage("http_probing")
            candidate_http_hosts = live_dns_hosts[:self.config.max_http_targets]
            if len(live_dns_hosts) > self.config.max_http_targets:
                logger.info(f"Target limit active: Probing {self.config.max_http_targets} of {len(live_dns_hosts)} hosts (configurable via max_http_targets)")
            http_results = await http_scanner.scan_hosts(candidate_http_hosts)
            raw_data["http"] = http_results
            timeline.end_stage("http_probing", items_processed=len(http_results))

            # 3b. Security Header Analysis
            timeline.start_stage("security_headers")
            for host, h_data in http_results.items():
                headers_dict = h_data.get("headers", {})
                obs = headers_analyzer.analyze_headers(headers_dict, target_url=h_data.get("url", ""))
                headers_results[host] = [o.model_dump() for o in obs]
            raw_data["headers"] = headers_results
            timeline.end_stage("security_headers", items_processed=len(headers_results))

            # 3c. Port Scanning (Nmap / Native socket)
            timeline.start_stage("port_scanning")
            all_ips = list(ip_res.get("unique_ips", []))
            candidate_ips = all_ips[:self.config.max_nmap_targets]
            if len(all_ips) > self.config.max_nmap_targets:
                logger.info(f"Target limit active: Scanning {self.config.max_nmap_targets} of {len(all_ips)} IPs (configurable via max_nmap_targets)")
            ports_targets = list(set([norm_target] + candidate_ips))
            ports_results = await nmap_scanner.scan_multiple(ports_targets)
            raw_data["nmap"] = {t: [p.model_dump() for p in ps] for t, ps in ports_results.items()}
            total_open_ports = sum(len(ps) for ps in ports_results.values())
            timeline.end_stage("port_scanning", items_processed=total_open_ports)

            # 3d. Nuclei / Heuristic Security Checks
            timeline.start_stage("security_scanning")
            web_targets = [h_data.get("url") for h_data in http_results.values() if h_data.get("url")]
            if not web_targets:
                web_targets = [f"https://{norm_target}"]
            candidate_nuclei = web_targets[:self.config.max_nuclei_targets]
            if len(web_targets) > self.config.max_nuclei_targets:
                logger.info(f"Target limit active: Auditing {self.config.max_nuclei_targets} of {len(web_targets)} targets (configurable via max_nuclei_targets)")
            all_findings = await nuclei_scanner.scan_targets(candidate_nuclei)
            raw_data["nuclei"] = [f.model_dump() for f in all_findings]
            timeline.end_stage("security_scanning", items_processed=len(all_findings))

        # -------------------------------------------------------------
        # STAGE 4: Asset Intelligence & Correlation
        # -------------------------------------------------------------
        timeline.start_stage("asset_correlation")
        prov_dict = {h: list(srcs) for h, srcs in provenance_map.items()}
        wayback_urls = wb_res.get("urls", [])

        assets = AssetCorrelator.correlate_target_assets(
            root_domain=norm_target,
            discovered_hosts=scoped_hosts,
            provenance_map=prov_dict,
            dns_results=dns_results,
            http_results=http_results,
            headers_results=headers_results,
            ports_results=ports_results,
            wayback_urls=wayback_urls,
            findings=all_findings,
        )
        timeline.end_stage("asset_correlation", items_processed=len(assets))

        # Calculate metrics
        live_count = sum(1 for a in assets if a.is_live)
        unique_ips = sorted(list(set(ip for a in assets for ip in a.ip_addresses)))
        total_open_ports = sum(len(a.ports) for a in assets)
        total_header_obs = sum(
            1 for a in assets for obs in a.security_headers if obs.status in ("MISSING", "MISCONFIGURED")
        )

        sources_summary = {
            "Certificate Transparency": len(ct_res.get("subdomains", [])),
            "DNS": len(live_dns_hosts),
            "Wayback": len(wayback_urls),
            "HTTP": len(http_results),
            "Nmap": sum(1 for ps in ports_results.values() if ps),
        }

        metrics = ScanMetrics(
            discovered_hosts=len(assets),
            live_hosts=live_count,
            unique_ips=len(unique_ips),
            http_services=len(http_results),
            open_ports=total_open_ports,
            historical_urls=len(wayback_urls),
            nuclei_findings=len(all_findings),
            header_observations=total_header_obs,
            duplicate_assets=duplicates_count,
            scan_duration_sec=timeline.total_duration(),
            sources_summary=sources_summary,
        )

        import platform
        raw_data["reproducibility"] = {
            "framework_version": "1.0.0",
            "developer": "AnandBinuArjun",
            "python_version": platform.python_version(),
            "os_platform": platform.platform(),
            "config_hash": self.config.compute_hash(),
            "nmap_engine": nmap_scanner.engine if hasattr(nmap_scanner, "engine") else "auto",
            "nuclei_engine": nuclei_scanner.engine if hasattr(nuclei_scanner, "engine") else "auto",
            "limits": {
                "max_nmap_targets": self.config.max_nmap_targets,
                "max_nuclei_targets": self.config.max_nuclei_targets,
                "max_http_targets": self.config.max_http_targets,
                "max_wayback_urls": self.config.max_wayback_urls,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        scan_result = ScanResult(
            scan_id=scan_id,
            target=norm_target,
            mode=mode,
            status=ScanStatus.COMPLETED,
            started_at=datetime.fromtimestamp(timeline.start_time, tz=timezone.utc),
            completed_at=datetime.now(timezone.utc),
            assets=assets,
            findings=all_findings,
            metrics=metrics,
            raw_data=raw_data,
        )

        # Check for previous scan to compute attack-surface drift
        try:
            prev_scan = self.repo.get_previous_scan_for_target(norm_target, exclude_scan_id=scan_id)
            if prev_scan:
                from redrecon.intelligence.difference import AttackSurfaceDifferenceEngine
                diff = AttackSurfaceDifferenceEngine.compare_scans(prev_scan, scan_result)
                raw_data["attack_surface_diff"] = diff.model_dump(mode="json")
                logger.info(
                    f"[bold magenta]Attack Surface Drift[/bold magenta]: "
                    f"+{len(diff.new_assets)} new assets, -{len(diff.removed_assets)} removed, "
                    f"+{len(diff.new_findings)} new findings vs {prev_scan.scan_id}"
                )
        except Exception as e:
            logger.warning(f"Could not compute attack surface diff: {e}")

        # -------------------------------------------------------------
        # STAGE 5: Storage & Reporting
        # -------------------------------------------------------------
        # 1. Save to SQLite database
        self.repo.save_scan(scan_result)

        # 2. Export organized JSON directories
        JSONReporter.export(scan_result, base_dir=self.config.output_dir)

        # 3. Generate Rich HTML Report
        HTMLReporter.generate(scan_result, base_dir=self.config.output_dir)

        logger.info(
            f"Scan [bold green]{scan_id}[/bold green] complete in {metrics.scan_duration_sec}s! "
            f"Assets: {metrics.discovered_hosts} | Live: {metrics.live_hosts} | IPs: {metrics.unique_ips} | Findings: {metrics.nuclei_findings}"
        )

        return scan_result
