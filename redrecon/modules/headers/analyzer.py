from typing import Any, Dict, List, Optional
import httpx
from redrecon.core.logger import get_logger
from redrecon.models.asset import HeaderObservation
from redrecon.modules.base import BaseModule

logger = get_logger()

# Security Header rules and best-practice recommendations
HEADER_RULES = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections and protects against protocol downgrade attacks",
        "check": lambda val: "max-age=" in val.lower(),
        "recommendation": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        "severity": "LOW",
    },
    "Content-Security-Policy": {
        "description": "Restricts sources of executable scripts, stylesheets, and resources",
        "check": lambda val: len(val.strip()) > 0 and "default-src" in val.lower() or "script-src" in val.lower(),
        "recommendation": "Define a robust CSP without 'unsafe-inline' or 'unsafe-eval'",
        "severity": "LOW",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks",
        "check": lambda val: val.strip().lower() == "nosniff",
        "recommendation": "Set 'X-Content-Type-Options: nosniff'",
        "severity": "INFO",
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking by controlling if site can be framed",
        "check": lambda val: val.strip().upper() in ("DENY", "SAMEORIGIN"),
        "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP frame-ancestors",
        "severity": "INFO",
    },
    "Referrer-Policy": {
        "description": "Governs how much referrer information is included with requests",
        "check": lambda val: val.strip().lower() in (
            "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin"
        ),
        "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'",
        "severity": "INFO",
    },
    "Permissions-Policy": {
        "description": "Allows site to restrict browser features and APIs (e.g., camera, microphone, geolocation)",
        "check": lambda val: len(val.strip()) > 0,
        "recommendation": "Set 'Permissions-Policy' to restrict sensitive web APIs (geolocation=(), microphone=(), camera=())",
        "severity": "INFO",
    },
}


class HeaderAnalyzer(BaseModule):
    """
    Security Header Analyzer.
    Evaluates HTTP response headers against modern security hardening baselines.
    Treats findings as configuration observations and provides remediation guidance.
    """

    @property
    def name(self) -> str:
        return "Security Header Analyzer"

    @property
    def description(self) -> str:
        return "Analyzes HSTS, CSP, XFO, XCTO, Referrer, and Permissions policies"

    def analyze_headers(self, headers_dict: Dict[str, str], target_url: str = "") -> List[HeaderObservation]:
        """
        Analyze a raw dictionary of headers and return HeaderObservation objects.
        """
        observations: List[HeaderObservation] = []
        # Lowercase headers for case-insensitive lookup
        lower_headers = {k.lower(): v for k, v in headers_dict.items()}

        for header_name, rule in HEADER_RULES.items():
            header_key = header_name.lower()
            val = lower_headers.get(header_key)

            if val is None:
                observations.append(
                    HeaderObservation(
                        header=header_name,
                        status="MISSING",
                        severity=rule["severity"],
                        value=None,
                        recommendation=rule["recommendation"],
                    )
                )
            else:
                passed = rule["check"](val)
                if passed:
                    observations.append(
                        HeaderObservation(
                            header=header_name,
                            status="PRESENT",
                            severity="INFO",
                            value=val,
                            recommendation=None,
                        )
                    )
                else:
                    observations.append(
                        HeaderObservation(
                            header=header_name,
                            status="MISCONFIGURED",
                            severity=rule["severity"],
                            value=val,
                            recommendation=rule["recommendation"],
                        )
                    )

        return observations

    async def scan(self, target: str) -> Dict[str, Any]:
        """Fetch headers from target and analyze them."""
        url = target if target.startswith("http://") or target.startswith("https://") else f"https://{target}"
        logger.info(f"Analyzing security headers for: [bold cyan]{url}[/bold cyan]")

        headers_dict: Dict[str, str] = {}
        try:
            async with self.get_http_client() as client:
                resp = await client.get(url)
                headers_dict = dict(resp.headers)
        except Exception as e:
            logger.debug(f"Failed to fetch headers from {url}: {e}")

        observations = self.analyze_headers(headers_dict, target_url=url)
        return {
            "target": target,
            "url": url,
            "observations_count": len(observations),
            "observations": [obs.model_dump() for obs in observations],
        }
