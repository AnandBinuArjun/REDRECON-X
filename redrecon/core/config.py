import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field

DEFAULT_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    853, 993, 995, 1080, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2181, 2375,
    2376, 3000, 3128, 3306, 3389, 4000, 4200, 4443, 5000, 5432, 5601, 5672,
    5900, 5984, 6379, 7000, 7001, 8000, 8001, 8008, 8080, 8081, 8082, 8088,
    8090, 8181, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9443,
    9999, 10000, 11211, 27017, 27018, 50000
]

DEFAULT_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


class ScanConfig(BaseModel):
    # Concurrency & Network
    concurrency: int = 25
    timeout: float = 8.0
    retries: int = 2
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) REDRECON-X/1.0 (Security Assessment)"
    verify_ssl: bool = False
    rate_limit: Optional[float] = None  # requests per second, None for unlimited

    # Output & Storage
    output_dir: str = "reports"
    db_path: str = "reports/redrecon.db"

    # DNS Module
    dns_resolvers: List[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"])
    dns_record_types: List[str] = Field(default_factory=lambda: ["A", "AAAA", "CNAME", "MX", "TXT", "NS"])

    # Subdomain Module
    subdomain_providers: List[str] = Field(
        default_factory=lambda: ["crtsh", "wayback", "alienvault", "hackertarget", "anubis", "brute"]
    )
    enable_bruteforce: bool = True
    bruteforce_limit: int = 100

    # HTTP Module
    probe_http: bool = True
    probe_https: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5

    # Headers Module
    security_headers: List[str] = Field(default_factory=lambda: list(DEFAULT_SECURITY_HEADERS))

    # Port Scanning Module
    nmap_enabled: bool = True
    nmap_top_ports: int = 100
    custom_ports: List[int] = Field(default_factory=lambda: list(DEFAULT_TOP_PORTS))

    # Nuclei Module
    nuclei_enabled: bool = True
    nuclei_severity: List[str] = Field(default_factory=lambda: ["info", "low", "medium", "high", "critical"])
    nuclei_rate_limit: int = 50

    # API Keys & External Providers (loaded from env by default)
    otx_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OTX_API_KEY"))
    shodan_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("SHODAN_API_KEY"))
    virustotal_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY"))

    # Observability & Security
    sentry_dsn: Optional[str] = Field(default_factory=lambda: os.getenv("SENTRY_DSN"))
    api_secret_key: Optional[str] = Field(default_factory=lambda: os.getenv("REDRECON_API_KEY"))

    # Target Limits (Configurable Boundaries)
    max_nmap_targets: int = 50
    max_nuclei_targets: int = 50
    max_http_targets: int = 150
    max_wayback_urls: int = 10000

    # Scope
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_domains: List[str] = Field(default_factory=list)
    allow_third_party: bool = False

    def compute_hash(self) -> str:
        """Computes deterministic SHA256 hash for research reproducibility."""
        import hashlib
        dump = self.model_dump_json()
        return hashlib.sha256(dump.encode("utf-8")).hexdigest()[:16]


def load_config(config_path: Optional[str] = None) -> ScanConfig:
    if config_path and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return ScanConfig(**data)
    # Check default path
    default_cfg = Path("configs/default.yaml")
    if default_cfg.exists():
        with open(default_cfg, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return ScanConfig(**data)
    return ScanConfig()
