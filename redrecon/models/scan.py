from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from redrecon.models.asset import Asset
from redrecon.models.finding import Finding


class ScanMode(str, Enum):
    PASSIVE = "passive"
    FULL = "full"
    MODULE = "module"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanMetrics(BaseModel):
    discovered_hosts: int = 0
    live_hosts: int = 0
    unique_ips: int = 0
    http_services: int = 0
    open_ports: int = 0
    historical_urls: int = 0
    nuclei_findings: int = 0
    header_observations: int = 0
    duplicate_assets: int = 0
    scan_duration_sec: float = 0.0
    sources_summary: Dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: str
    target: str
    mode: ScanMode
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    assets: List[Asset] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    metrics: ScanMetrics = Field(default_factory=ScanMetrics)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
