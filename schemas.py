from datetime import datetime, timezone
from typing import Annotated, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

DEFENSE_CATALOG = ("block_ip_iptables", "install_fail2ban")
DefenseId = Literal["block_ip_iptables", "install_fail2ban"]

def utc_z(dt: datetime) -> str:
    """ISO 8601 UTC with Z. Naive datetimes are treated as UTC."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

Ts = Annotated[datetime, PlainSerializer(utc_z, return_type=str)]

class Event(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    event_id: str
    timestamp: Ts
    host_id: str
    source: str
    event_type: Literal["ssh_login_failed", "ssh_login_success", "process_start", "net_connection"]
    src_ip: str
    username: str
    raw: str

class AIAnalysis(BaseModel):
    summary: str
    impact: str
    recommended_defense_id: DefenseId

class Alert(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    alert_id: str
    rule_id: Literal["R001_ssh_bruteforce", "R002_success_after_failures"]
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    risk_score: int = Field(..., ge=0, le=100)
    host_id: str
    src_ip: str
    mitre_technique: str
    first_seen: Ts
    last_seen: Ts
    event_ids: List[str]
    status: Literal["open", "defended", "verified", "failed_verification"]
    ai_analysis: Optional[AIAnalysis] = None

class EventIngestRequest(BaseModel):
    events: List[Event]

class EventIngestResponse(BaseModel):
    accepted: int

class AlertDetailResponse(Alert):
    events: List[Event]

class DefenseApplyRequest(BaseModel):
    alert_id: str
    defense_id: DefenseId

class DefenseApplyResponse(BaseModel):
    run_id: str
    status: str

class VerificationRequest(BaseModel):
    alert_id: str

class VerificationResponse(BaseModel):
    verification_id: str
    status: str

class VerificationBaselineRetest(BaseModel):
    attack_succeeded: bool
    detected: bool

class VerificationDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    verification_id: str
    alert_id: str
    baseline: Optional[VerificationBaselineRetest] = None
    retest: Optional[VerificationBaselineRetest] = None
    result: Literal["verified", "not_verified", "running"]
    evidence: Optional[str] = None

class ErrorResponse(BaseModel):
    error: str
