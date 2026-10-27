"""RunnerClient: talks to the lab runner. mock=True simulates a lab with one stateful defense."""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import httpx
from app.config import settings

_MOCK_STATE = {"defended": False}   # shared so /defenses/apply and the verification see the same lab

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _result(status: str, attack_succeeded: Optional[bool], output: str, started: str) -> Dict[str, Any]:
    return {"run_id": str(uuid.uuid4()), "status": status, "attack_succeeded": attack_succeeded,
            "output": output, "started_at": started, "finished_at": _now()}

class RunnerClient:
    def __init__(self, mock: Optional[bool] = None, base_url: Optional[str] = None, timeout: float = 30.0):
        self.mock = settings.MOCK_RUNNER if mock is None else mock
        self.base_url = base_url or settings.RUNNER_API_BASE
        self.timeout = timeout

    def _mock(self, endpoint: str) -> Dict[str, Any]:
        t = _now()
        if endpoint == "/run/attack":
            ok = not _MOCK_STATE["defended"]
            return _result("success", ok, "SSH brute force succeeded." if ok else "SSH brute force blocked.", t)
        if endpoint == "/run/defense":
            _MOCK_STATE["defended"] = True
            return _result("success", None, "Simulated defense applied.", t)
        _MOCK_STATE["defended"] = False
        return _result("success", None, "Target reset to clean state.", t)

    async def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.mock:
            return self._mock(endpoint)
        started = _now()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}{endpoint}", json=payload,
                                      headers={"X-API-Key": settings.API_KEY})
            if r.status_code != 200:
                return _result("failed", None, f"Runner HTTP {r.status_code}: {r.text[:200]}", started)
            return r.json()
        except httpx.TimeoutException:
            return _result("failed", None, "Runner request timed out.", started)
        except Exception as e:
            return _result("failed", None, f"Runner unreachable: {e}", started)

    async def run_attack(self, scenario_id: str, target_ip: str):
        return await self._post("/run/attack", {"scenario_id": scenario_id, "target_ip": target_ip})

    async def run_defense(self, defense_id: str, ip: str):
        return await self._post("/run/defense", {"defense_id": defense_id, "params": {"ip": ip}})

    async def run_reset(self):
        return await self._post("/run/reset", {})
