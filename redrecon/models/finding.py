from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    id: str = Field(description="Unique finding identifier")
    target: str = Field(description="Host or URL where finding was observed")
    source: str = Field(default="nuclei", description="Scanner/module that produced finding")
    template_id: Optional[str] = Field(default=None, description="Nuclei or check template identifier")
    name: str = Field(description="Title or check name")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO)
    description: str = Field(default="")
    evidence: Optional[str] = Field(default=None, description="Extracted proof or response snippet")
    reference: Optional[str] = Field(default=None, description="External reference URL or CVE")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
