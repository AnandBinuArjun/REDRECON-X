from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ServiceFingerprint(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: float = 1.0


class ServiceDetails(BaseModel):
    host: str
    ip: str
    port: int
    protocol: str = "tcp"
    transport: str = "ip"
    banner: Optional[str] = None
    fingerprint: Optional[ServiceFingerprint] = None
    tls_enabled: bool = False
    tls_subject: Optional[str] = None
    tls_issuer: Optional[str] = None
