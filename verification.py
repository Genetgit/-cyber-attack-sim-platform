"""Verification: reset -> baseline attack -> apply defense -> re-test -> compare."""
import asyncio
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from sqlalchemy import func, select
from app.client import RunnerClient
from app.config import settings
from app.models import AlertModel, EventModel, VerificationModel

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def evaluate(baseline: Dict[str, Any], retest: Dict[str, Any]) -> Tuple[str, str]:
    """Pure comparison. 'verified' only when the baseline attack worked AND the re-test cleanly failed."""
    if baseline.get("status") != "success" or baseline.get("attack_succeeded") is None:
        return "not_verified", f"Baseline attack did not complete: {baseline.get('output')}"
    if not baseline["attack_succeeded"]:
        return "not_verified", "Baseline attack did not succeed, so the defense effect cannot be proven."
    if retest.get("status") != "success" or retest.get("attack_succeeded") is None:
        return "not_verified", f"Re-test did not complete: {retest.get('output')}"
    if retest["attack_succeeded"]:
        return "not_verified", "Re-test attack still succeeded after the defense was applied."
    return "verified", "Baseline attack succeeded; after the defense the re-test attack was blocked."

async def _update(db_factory, vid: str, **fields):
    async with db_factory() as db:
        v = await db.get(VerificationModel, vid)
        if v:
            for k, val in fields.items():
                setattr(v, k, val)
            await db.commit()

async def _finish(db_factory, vid: str, alert_id: str, result: str, evidence: str):
    await _update(db_factory, vid, result=result, evidence=evidence)
    async with db_factory() as db:
        alert = await db.get(AlertModel, alert_id)
        if alert:
            alert.status = "verified" if result == "verified" else "failed_verification"
            await db.commit()

async def _detected(db_factory, runner, run, alert, since) -> bool:
    """Detected = the telemetry saw >=5 failed logins from the attacker since the run started."""
    async with db_factory() as db:
        if runner.mock and run.get("attack_succeeded"):   # simulate the agent shipping auth-log events
            for _ in range(6):
                db.add(EventModel(event_id=str(uuid.uuid4()), timestamp=_utcnow(), host_id=alert["host_id"],
                    source="auth_log", event_type="ssh_login_failed", src_ip=alert["src_ip"], username="root",
                    raw=f"sshd: Failed password for root from {alert['src_ip']} port {random.randint(30000, 60000)} ssh2"))
            await db.commit()
    if not runner.mock:
        await asyncio.sleep(3)   # give the real agent time to ship events
    async with db_factory() as db:
        n = (await db.execute(select(func.count()).select_from(EventModel).where(
            EventModel.src_ip == alert["src_ip"], EventModel.event_type == "ssh_login_failed",
            EventModel.timestamp >= since))).scalar_one()
    return n >= 5

async def _pipeline(vid: str, alert_id: str, db_factory, runner):
    async with db_factory() as db:
        a = await db.get(AlertModel, alert_id)
        if not a:
            raise ValueError("Alert not found")
        alert = {"src_ip": a.src_ip, "host_id": a.host_id}
        defense = a.applied_defense or (a.ai_analysis or {}).get("recommended_defense_id") or "block_ip_iptables"
    await runner.run_reset()                         # clean target: removes any earlier defense
    t0 = _utcnow()
    base = await runner.run_attack("ssh_bruteforce", settings.TARGET_IP)
    await _update(db_factory, vid, baseline={"attack_succeeded": bool(base.get("attack_succeeded")),
                                             "detected": await _detected(db_factory, runner, base, alert, t0)})
    d = await runner.run_defense(defense, alert["src_ip"])
    if d.get("status") != "success":
        return await _finish(db_factory, vid, alert_id, "not_verified", f"Defense failed to apply: {d.get('output')}")
    t1 = _utcnow()
    retest = await runner.run_attack("ssh_bruteforce", settings.TARGET_IP)
    await _update(db_factory, vid, retest={"attack_succeeded": bool(retest.get("attack_succeeded")),
                                           "detected": await _detected(db_factory, runner, retest, alert, t1)})
    result, evidence = evaluate(base, retest)
    await _finish(db_factory, vid, alert_id, result, evidence)

async def run_verification_pipeline(verification_id: str, alert_id: str, db_factory, runner=None):
    runner = runner or RunnerClient()
    try:
        await asyncio.wait_for(_pipeline(verification_id, alert_id, db_factory, runner), settings.VERIFY_TIMEOUT_S)
    except asyncio.TimeoutError:
        await _finish(db_factory, verification_id, alert_id, "not_verified", "Verification timed out.")
    except Exception as e:
        await _finish(db_factory, verification_id, alert_id, "not_verified", f"Verification error: {e}")
