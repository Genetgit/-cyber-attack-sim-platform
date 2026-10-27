import uuid
from datetime import datetime, timedelta
from sqlalchemy import select
from app.detection import calculate_risk_score, run_detection_engine
from app.models import AlertModel, EventModel

T0 = datetime(2026, 10, 1, 12, 0, 0)

def ev(kind, sec, ip="10.0.0.5"):
    return EventModel(event_id=str(uuid.uuid4()), timestamp=T0 + timedelta(seconds=sec), host_id="target-01",
                      source="auth_log", event_type=kind, src_ip=ip, username="root", raw="x")

async def feed(db, events):
    db.add_all(events)
    await db.commit()
    await run_detection_engine(db, events)
    return list((await db.execute(select(AlertModel))).scalars().all())

async def test_r001_fires_on_five_failures_in_60s(db):
    alerts = await feed(db, [ev("ssh_login_failed", i) for i in range(5)])
    assert [a.rule_id for a in alerts] == ["R001_ssh_bruteforce"]
    assert alerts[0].severity == "high" and alerts[0].risk_score == 60 and len(alerts[0].events) == 5

async def test_r001_silent_below_threshold(db):
    assert await feed(db, [ev("ssh_login_failed", i) for i in range(4)]) == []

async def test_r001_silent_when_spread_over_60s(db):
    assert await feed(db, [ev("ssh_login_failed", i * 20) for i in range(5)]) == []

async def test_r001_ignores_different_ips(db):
    events = [ev("ssh_login_failed", i, ip=f"10.0.0.{i + 1}") for i in range(5)]
    assert await feed(db, events) == []

async def test_alert_deduplicated_within_5_minutes(db):
    alerts = await feed(db, [ev("ssh_login_failed", i) for i in range(12)])
    assert len(alerts) == 1

async def test_r002_critical_after_failures(db):
    alerts = await feed(db, [ev("ssh_login_failed", i) for i in range(5)] + [ev("ssh_login_success", 10)])
    r2 = [a for a in alerts if a.rule_id == "R002_success_after_failures"]
    assert len(r2) == 1 and r2[0].severity == "critical" and r2[0].risk_score == 95
    assert any(e.event_type == "ssh_login_success" for e in r2[0].events)

async def test_r002_needs_five_failures(db):
    alerts = await feed(db, [ev("ssh_login_failed", i) for i in range(3)] + [ev("ssh_login_success", 10)])
    assert alerts == []

def test_risk_score_is_weight_times_confidence_and_clamped():
    assert calculate_risk_score("high", 0.8) == 60
    assert calculate_risk_score("critical", 5) == 100
    assert calculate_risk_score("low", 0) == 0
