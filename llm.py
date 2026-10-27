import json
import httpx
from typing import Any, Dict, List
from app.config import settings
from app.schemas import DEFENSE_CATALOG

def fallback_analysis(alert: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, str]:
    ip, n = alert["src_ip"], len(events)
    if alert["rule_id"] == "R002_success_after_failures":
        summary = f"A login from {ip} succeeded after repeated failures ({n} related events). The account may be compromised."
        impact = "The attacker likely guessed valid credentials and may already have shell access to the host."
    else:
        summary = f"{n} failed SSH logins from {ip} in a short time match a brute force pattern (MITRE T1110)."
        impact = "If a guess succeeds the attacker gains access to the host."
    return {"summary": summary, "impact": impact, "recommended_defense_id": "block_ip_iptables"}

def validate_analysis(data: Any) -> Dict[str, str]:
    if not isinstance(data, dict):
        raise ValueError("LLM output is not a JSON object")
    out = {k: data.get(k) for k in ("summary", "impact", "recommended_defense_id")}
    if not all(isinstance(v, str) and v.strip() for v in out.values()):
        raise ValueError("LLM output is missing fields")
    if out["recommended_defense_id"] not in DEFENSE_CATALOG:
        raise ValueError("defense not in catalog")
    return out

async def call_llm_analysis(alert: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, str]:
    """Ask the LLM for ai_analysis JSON; on any failure use the fallback template."""
    if not settings.OPENAI_API_KEY:
        return fallback_analysis(alert, events)
    system = ("You are a SOC analyst. Reply with JSON only: "
              '{"summary": str, "impact": str, "recommended_defense_id": "block_ip_iptables" | "install_fail2ban"}')
    user = json.dumps({"alert": alert, "events": events[:30]})
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(f"{settings.OPENAI_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                json={"model": settings.OPENAI_MODEL, "temperature": 0.2, "response_format": {"type": "json_object"},
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            r.raise_for_status()
            return validate_analysis(json.loads(r.json()["choices"][0]["message"]["content"]))
    except Exception:
        return fallback_analysis(alert, events)
