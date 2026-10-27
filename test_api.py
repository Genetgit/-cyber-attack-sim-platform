import uuid
from datetime import datetime, timedelta, timezone
import pytest
from httpx import ASGITransport, AsyncClient
from app.config import settings
from app.database import get_db
from app.main import app

H = {"X-API-Key": settings.API_KEY}

@pytest.fixture
async def client(db):
    async def override():
        yield db
    app.dependency_overrides[get_db] = override
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()

def make_events(n, kind="ssh_login_failed"):
    base = datetime.now(timezone.utc) - timedelta(seconds=30)
    return [{"event_id": str(uuid.uuid4()), "timestamp": (base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "host_id": "target-01", "source": "auth_log", "event_type": kind, "src_ip": "10.0.0.5",
             "username": "root", "raw": "Failed password"} for i in range(n)]

async def test_auth_errors_use_error_key(client):
    for headers in ({}, {"X-API-Key": "wrong"}):
        r = await client.get("/api/alerts", headers=headers)
        assert r.status_code == 401 and "error" in r.json()

async def test_unknown_alert_is_404_with_error_key(client):
    r = await client.get("/api/alerts/nope", headers=H)
    assert r.status_code == 404 and r.json() == {"error": "Alert not found"}

async def test_ingest_list_and_dedupe_events(client):
    events = make_events(3)
    assert (await client.post("/api/events", json={"events": events}, headers=H)).json() == {"accepted": 3}
    assert (await client.post("/api/events", json={"events": events}, headers=H)).json() == {"accepted": 0}
    listed = (await client.get("/api/events?limit=2", headers=H)).json()
    assert len(listed) == 2 and listed[0]["timestamp"].endswith("Z")

async def test_full_flow_detect_analyze(client):
    await client.post("/api/events", json={"events": make_events(6)}, headers=H)
    alerts = (await client.get("/api/alerts", headers=H)).json()
    assert len(alerts) == 1 and alerts[0]["rule_id"] == "R001_ssh_bruteforce" and alerts[0]["status"] == "open"
    aid = alerts[0]["alert_id"]
    detail = (await client.get(f"/api/alerts/{aid}", headers=H)).json()
    assert len(detail["events"]) >= 5
    analyzed = (await client.post(f"/api/alerts/{aid}/analyze", headers=H)).json()
    assert analyzed["ai_analysis"]["recommended_defense_id"] in ("block_ip_iptables", "install_fail2ban")
    d = (await client.post("/api/defenses/apply", json={"alert_id": aid, "defense_id": "block_ip_iptables"}, headers=H)).json()
    assert d["status"] == "success"
    assert (await client.get(f"/api/alerts/{aid}", headers=H)).json()["status"] == "defended"
