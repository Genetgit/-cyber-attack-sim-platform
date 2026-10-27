"""Detection rules: each rule is its own function and returns the new AlertModel (or None)."""
import uuid
from datetime import timedelta
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import AlertModel, EventModel

SEVERITY_WEIGHTS = {"low": 20, "medium": 50, "high": 75, "critical": 100}

def calculate_risk_score(severity: str, confidence: float) -> int:
    """risk = severity weight x confidence, clamped to 0-100."""
    return max(0, min(100, round(SEVERITY_WEIGHTS.get(severity, 50) * confidence)))

async def is_duplicate(db: AsyncSession, rule_id: str, src_ip: str, now) -> bool:
    stmt = select(AlertModel.alert_id).where(
        AlertModel.rule_id == rule_id, AlertModel.src_ip == src_ip,
        AlertModel.first_seen >= now - timedelta(minutes=5))
    return (await db.execute(stmt)).first() is not None

async def _failures(db: AsyncSession, ip: str, start, end) -> List[EventModel]:
    stmt = select(EventModel).where(
        EventModel.src_ip == ip, EventModel.event_type == "ssh_login_failed",
        EventModel.timestamp >= start, EventModel.timestamp <= end).order_by(EventModel.timestamp)
    return list((await db.execute(stmt)).scalars().all())

def _build(rule_id, title, severity, confidence, event, related) -> AlertModel:
    alert = AlertModel(
        alert_id=str(uuid.uuid4()), rule_id=rule_id, title=title, severity=severity,
        risk_score=calculate_risk_score(severity, confidence), host_id=event.host_id,
        src_ip=event.src_ip, mitre_technique="T1110",
        first_seen=min(e.timestamp for e in related), last_seen=max(e.timestamp for e in related), status="open")
    alert.events.extend(related)
    return alert

async def rule_r001(db: AsyncSession, event: EventModel) -> Optional[AlertModel]:
    """R001: >=5 ssh_login_failed from the same src_ip within 60s."""
    if event.event_type != "ssh_login_failed":
        return None
    failures = await _failures(db, event.src_ip, event.timestamp - timedelta(seconds=60), event.timestamp)
    if len(failures) < 5 or await is_duplicate(db, "R001_ssh_bruteforce", event.src_ip, event.timestamp):
        return None
    confidence = min(1.0, 0.6 + 0.04 * len(failures))   # 5 failures -> 0.8, 10+ -> 1.0
    alert = _build("R001_ssh_bruteforce", "SSH brute force attempt detected", "high", confidence, event, failures)
    db.add(alert)
    return alert

async def rule_r002(db: AsyncSession, event: EventModel) -> Optional[AlertModel]:
    """R002: ssh_login_success from an IP with >=5 failures in the previous 10 minutes."""
    if event.event_type != "ssh_login_success":
        return None
    failures = await _failures(db, event.src_ip, event.timestamp - timedelta(minutes=10), event.timestamp)
    if len(failures) < 5 or await is_duplicate(db, "R002_success_after_failures", event.src_ip, event.timestamp):
        return None
    alert = _build("R002_success_after_failures", "SSH login success after multiple failures",
                   "critical", 0.95, event, failures + [event])
    db.add(alert)
    return alert

RULES = (rule_r001, rule_r002)

async def run_detection_engine(db: AsyncSession, new_events: List[EventModel]) -> List[AlertModel]:
    created = []
    for event in sorted(new_events, key=lambda e: e.timestamp):
        for rule in RULES:
            alert = await rule(db, event)
            if alert:
                created.append(alert)
    await db.commit()
    return created
