from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class AssetConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DNSRecords(BaseModel):
    A: List[str] = Field(default_factory=list)
    AAAA: List[str] = Field(default_factory=list)
    CNAME: List[str] = Field(default_factory=list)
    MX: List[str] = Field(default_factory=list)
    TXT: List[str] = Field(default_factory=list)
    NS: List[str] = Field(default_factory=list)


class HTTPService(BaseModel):
    url: str
    is_https: bool = True
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    response_time_ms: Optional[float] = None
    redirect_url: Optional[str] = None
    redirect_chain: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)


class PortService(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class HeaderObservation(BaseModel):
    header: str
    status: str  # PRESENT, MISSING, MISCONFIGURED
    severity: str = "INFO"  # INFO, LOW, MEDIUM
    value: Optional[str] = None
    recommendation: Optional[str] = None


class Asset(BaseModel):
    hostname: str
    root_domain: str
    ip_addresses: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    dns_records: DNSRecords = Field(default_factory=DNSRecords)
    http_service: Optional[HTTPService] = None
    ports: List[PortService] = Field(default_factory=list)
    historical_urls: List[str] = Field(default_factory=list)
    security_headers: List[HeaderObservation] = Field(default_factory=list)
    confidence: AssetConfidence = AssetConfidence.LOW
    priority_score: int = 0
    priority_breakdown: Dict[str, int] = Field(default_factory=dict)
    is_live: bool = False
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
