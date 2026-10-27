import uuid
from datetime import datetime
from sqlalchemy import select
from app.client import RunnerClient
from app.models import AlertModel, VerificationModel
from app.verification import evaluate, run_verification_pipeline

def run(ok, status="success", out=""):
    return {"status": status, "attack_succeeded": ok, "output": out}

def test_verified_when_attack_blocked_after_defense():
    assert evaluate(run(True), run(False))[0] == "verified"

def test_not_verified_when_retest_still_succeeds():
    assert evaluate(run(True), run(True))[0] == "not_verified"

def test_not_verified_when_baseline_attack_never_worked():
    assert evaluate(run(False), run(False))[0] == "not_verified"

def test_runner_failure_is_never_verified():
    assert evaluate(run(True), run(None, "failed", "timeout"))[0] == "not_verified"
    assert evaluate(run(None, "failed"), run(False))[0] == "not_verified"

async def test_mock_runner_defense_blocks_attack():
    r = RunnerClient(mock=True)
    await r.run_reset()
    assert (await r.run_attack("ssh_bruteforce", "10.0.0.5"))["attack_succeeded"] is True
    await r.run_defense("block_ip_iptables", "10.0.0.5")
    assert (await r.run_attack("ssh_bruteforce", "10.0.0.5"))["attack_succeeded"] is False

async def seed(db_factory):
    async with db_factory() as db:
        db.add(AlertModel(alert_id="a1", rule_id="R001_ssh_bruteforce", title="t", severity="high", risk_score=60,
                          host_id="target-01", src_ip="10.0.0.5", mitre_technique="T1110",
                          first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), status="defended"))
        db.add(VerificationModel(verification_id="v1", alert_id="a1", result="running"))
        await db.commit()

async def outcome(db_factory):
    async with db_factory() as db:
        v = (await db.execute(select(VerificationModel))).scalar_one()
        a = (await db.execute(select(AlertModel))).scalar_one()
        return v, a

async def test_pipeline_verifies_with_mock_runner(db_factory):
    await seed(db_factory)
    await run_verification_pipeline("v1", "a1", db_factory, runner=RunnerClient(mock=True))
    v, a = await outcome(db_factory)
    assert v.result == "verified" and a.status == "verified"
    assert v.baseline == {"attack_succeeded": True, "detected": True}
    assert v.retest == {"attack_succeeded": False, "detected": False}

class BrokenRunner(RunnerClient):
    mock = False
    async def _post(self, endpoint, payload):
        return {"run_id": "x", "status": "failed", "attack_succeeded": None, "output": "runner down"}

async def test_pipeline_handles_runner_failure(db_factory):
    await seed(db_factory)
    await run_verification_pipeline("v1", "a1", db_factory, runner=BrokenRunner())
    v, a = await outcome(db_factory)
    assert v.result == "not_verified" and a.status == "failed_verification" and "runner down" in v.evidence
