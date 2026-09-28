import asyncio
import json
import shutil
import uuid
from typing import Any, Dict, List, Optional
import httpx
from redrecon.core.logger import get_logger
from redrecon.models.finding import Finding, FindingSeverity
from redrecon.modules.base import BaseModule

logger = get_logger()

# Common sensitive path checks for built-in heuristic scanner
SENSITIVE_PATHS = [
    ("/.git/HEAD", "ref: refs/heads", "Exposed Git Repository", FindingSeverity.HIGH),
    ("/.env", "DB_", "Exposed Environment File (.env)", FindingSeverity.HIGH),
    ("/.DS_Store", "\x00\x00\x00\x01Bud1", "Exposed macOS .DS_Store file", FindingSeverity.LOW),
    ("/robots.txt", "User-agent:", "Robots.txt Information Disclosure", FindingSeverity.INFO),
    ("/sitemap.xml", "<?xml", "XML Sitemap Detected", FindingSeverity.INFO),
    ("/.well-known/security.txt", "Contact:", "Security.txt Contact File Found", FindingSeverity.INFO),
    ("/server-status", "Apache Server Status", "Apache server-status exposed", FindingSeverity.MEDIUM),
    ("/phpinfo.php", "PHP Version", "PHP Info Disclosure", FindingSeverity.MEDIUM),
]


class NucleiScanner(BaseModule):
    """
    Nuclei Vulnerability & Security Scanner Adapter.
    Executes Nuclei JSONL scanner when available; falls back to native heuristic
    exposure checks if Nuclei CLI is absent. Normalizes all results into Finding objects.
    """

    @property
    def name(self) -> str:
        return "Nuclei & Security Scanner"

    @property
    def description(self) -> str:
        return "Nuclei JSONL scanner with built-in exposure heuristic auditor"

    def is_nuclei_available(self) -> bool:
        return shutil.which("nuclei") is not None

    async def scan_host_nuclei(self, target_url: str) -> List[Finding]:
        """Run Nuclei CLI and parse JSONL stream."""
        findings: List[Finding] = []
        sev_arg = ",".join(self.config.nuclei_severity)

        cmd = [
            "nuclei",
            "-target", target_url,
            "-severity", sev_arg,
            "-jsonl",
            "-silent",
            "-rate-limit", str(self.config.nuclei_rate_limit),
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    raw_sev = str(info.get("severity", "info")).upper()

                    # Map severity
                    try:
                        severity = FindingSeverity(raw_sev)
                    except ValueError:
                        severity = FindingSeverity.INFO

                    findings.append(
                        Finding(
                            id=str(uuid.uuid4())[:8],
                            target=data.get("matched-at", target_url),
                            source="nuclei",
                            template_id=data.get("template-id"),
                            name=info.get("name", data.get("template-id", "Unknown Nuclei Finding")),
                            severity=severity,
                            description=info.get("description", ""),
                            evidence=data.get("extracted-results", [None])[0] if isinstance(data.get("extracted-results"), list) else None,
                            reference=info.get("reference", [None])[0] if isinstance(info.get("reference"), list) else None,
                        )
                    )
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.warning(f"Nuclei execution failed: {e}. Falling back to native auditor.")
            return await self.scan_host_native(target_url)

        return findings

    async def scan_host_native(self, target_url: str) -> List[Finding]:
        """
        Built-in heuristic check for exposed paths, headers, and misconfigurations.
        """
        findings: List[Finding] = []
        base_url = target_url.rstrip("/")

        async with self.get_http_client(timeout=5.0) as client:
            # 1. Check sensitive exposure paths
            for path, signature, check_name, sev in SENSITIVE_PATHS:
                test_url = f"{base_url}{path}"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and signature in resp.text:
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4())[:8],
                                target=test_url,
                                source="heuristic_auditor",
                                template_id=f"exposure{path.replace('/', '-')}",
                                name=check_name,
                                severity=sev,
                                description=f"Identified accessible sensitive resource at {test_url}",
                                evidence=resp.text[:120].strip(),
                            )
                        )
                except Exception:
                    pass

            # 2. Check CORS misconfiguration
            try:
                cors_resp = await client.options(
                    base_url,
                    headers={"Origin": "https://evil-attacker.example"}
                )
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "")
                if acao == "https://evil-attacker.example" or (acao == "*" and acac.lower() == "true"):
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4())[:8],
                            target=base_url,
                            source="heuristic_auditor",
                            template_id="cors-misconfiguration",
                            name="Permissive CORS Origin Reflection",
                            severity=FindingSeverity.MEDIUM,
                            description=f"Server reflects arbitrary Origin in Access-Control-Allow-Origin: {acao}",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                        )
                    )
            except Exception:
                pass

        return findings

    async def scan(self, target: str) -> Dict[str, Any]:
        """Scan a URL or host."""
        url = target if target.startswith("http://") or target.startswith("https://") else f"https://{target}"
        engine = "nuclei" if self.is_nuclei_available() else "native_heuristic"
        logger.info(f"Running security scan on [bold cyan]{url}[/bold cyan] using: [bold yellow]{engine}[/bold yellow]")

        if self.is_nuclei_available():
            findings = await self.scan_host_nuclei(url)
        else:
            findings = await self.scan_host_native(url)

        logger.info(f"Identified [bold green]{len(findings)}[/bold green] candidate security findings on {url}")
        return {
            "target": url,
            "engine": engine,
            "findings_count": len(findings),
            "findings": [f.model_dump() for f in findings],
        }

    async def scan_targets(self, targets: List[str]) -> List[Finding]:
        """Scan multiple targets concurrently."""
        all_findings: List[Finding] = []
        sem = asyncio.Semaphore(4)

        async def _scan(target: str):
            async with sem:
                res = await self.scan(target)
                for f_data in res.get("findings", []):
                    all_findings.append(Finding(**f_data))

        await asyncio.gather(*[_scan(t) for t in targets], return_exceptions=True)
        return all_findings
