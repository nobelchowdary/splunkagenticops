"""Investigation data models."""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
import uuid
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    DETECTING_ANOMALIES = "detecting_anomalies"
    RESPONDING = "responding"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationRequest(BaseModel):
    """Request to start a new investigation."""
    alert_id: Optional[str] = None
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    timerange: str = "-24h"
    auto_respond: bool = False


class Finding(BaseModel):
    """A single finding from an investigation."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    type: str  # "ioc", "correlation", "anomaly", "recommendation"
    title: str
    description: str
    severity: Severity = Severity.MEDIUM
    evidence: Optional[str] = None  # SPL query or raw data
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    confidence: float = 0.5


class TimelineEvent(BaseModel):
    """An event in the investigation timeline."""
    timestamp: datetime
    agent: str
    action: str
    detail: str
    spl_query: Optional[str] = None
    result_count: Optional[int] = None


class InvestigationState(BaseModel):
    """Full state of an investigation."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: InvestigationStatus = InvestigationStatus.PENDING
    request: InvestigationRequest
    severity: Severity = Severity.MEDIUM
    findings: List[Finding] = []
    timeline: List[TimelineEvent] = []
    mitre_techniques: List[str] = []
    iocs: List[str] = []
    affected_assets: List[str] = []
    affected_users: List[str] = []
    summary: Optional[str] = None
    recommendations: List[str] = []

    @classmethod
    def from_request(cls, request: InvestigationRequest) -> "InvestigationState":
        return cls(request=request)
