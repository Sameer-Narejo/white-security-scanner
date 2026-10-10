# app/core/models.py

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Finding(BaseModel):
    """
    Standardized finding model representing a security observation,
    aligned with SecuLens Project Plan Appendix A.
    """
    finding_id: str
    title: str
    category: str  # e.g., TLS, Headers, Cookies, Configuration
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # High, Medium, Low
    target: str
    evidence: str
    technical_explanation: str
    plain_explanation: str
    business_impact: str
    remediation: str
    references: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    """
    Summary container for a completed security scan.
    """
    target: str
    profile: str
    total_findings: int
    findings: List[Finding] = Field(default_factory=list)