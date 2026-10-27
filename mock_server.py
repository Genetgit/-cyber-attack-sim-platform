"""Mock backend for the dashboard (Python stdlib only).
Run:  python mock_server.py   then open http://localhost:8000
Serves this folder as static files and the contract API under /api.
Demo: alerts with rule R001 verify successfully; R002 shows NOT VERIFIED.
Env: API_KEY (default secure_shared_lab_key_2026), PORT (default 8000)."""
import json, os, random, threading, time, uuid
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

KEY = os.environ.get("API_KEY", "secure_shared_lab_key_2026")
PORT = int(os.environ.get("PORT", 8000))
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
EVENTS, ALERTS, VERS = [], {}, {}
LOCK = threading.Lock()
ts = lambda ago=0: (datetime.now(timezone.utc) - timedelta(seconds=ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

def make_event(ip="10.0.0.5", typ="ssh_login_failed", ago=0):
    user = random.choice(["root", "admin", "ubuntu", "test"]); port = random.randint(30000, 60000)
    raw = (f"sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port} ssh2" if typ == "ssh_login_failed"
           else f"sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {port} ssh2")
    e = {"event_id": str(uuid.uuid4()), "timestamp": ts(ago), "host_id": "target-01", "source": "auth_log",
         "event_type": typ, "src_ip": ip, "username": user, "raw": raw}
    EVENTS.append(e); return e

def make_alert(rule, title, sev, risk, ip, success=False):
    evs = [make_event(ip, ago=60 - i * 5) for i in range(5)]
    if success: evs.append(make_event(ip, "ssh_login_success", ago=2))
    a = {"alert_id": str(uuid.uuid4()), "rule_id": rule, "title": title, "severity": sev, "risk_score": risk, "host_id": "target-01",
         "src_ip": ip, "mitre_technique": "T1110", "first_seen": evs[0]["timestamp"], "last_seen": evs[-1]["timestamp"],
         "event_ids": [e["event_id"] for e in evs], "status": "open", "ai_analysis": None}
    ALERTS[a["alert_id"]] = a

make_alert("R001_ssh_bruteforce", "SSH brute force attempt detected", "high", 60, "10.0.0.5")
make_alert("R002_success_after_failures", "SSH login success after multiple failures", "critical", 95, "10.0.0.9", True)
make_alert("R001_ssh_bruteforce", "SSH brute force attempt detected", "medium", 40, "10.0.0.7")

def ticker():  # a new failed login every 2s so the live table moves
    while True:
        time.sleep(2)
        with LOCK:
            make_event(random.choice(["10.0.0.5", "10.0.0.7", "10.0.0.9"])); del EVENTS[:-500]
threading.Thread(target=ticker, daemon=True).start()

def run_verification(v):
    time.sleep(2); v["baseline"] = {"attack_succeeded": True, "detected": True}
    time.sleep(3)
    a = ALERTS[v["alert_id"]]; ok = a["rule_id"] != "R002_success_after_failures"
    v["retest"] = {"attack_succeeded": not ok, "detected": True}
    v["evidence"] = ("Baseline attack succeeded; after the defense the re-test attack was blocked and still detected." if ok
                     else "Re-test attack still succeeded after the defense, so the defense did not work.")
    v["result"] = "verified" if ok else "not_verified"
    a["status"] = "verified" if ok else "failed_verification"

class H(SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code); self.cors()
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(204); self.cors(); self.end_headers()
    def do_GET(self):
        if self.path.startswith("/api"): self.api("GET")
        else: super().do_GET()
    def do_POST(self):
        if self.path.startswith("/api"): self.api("POST")
        else: self.send_json(404, {"error": "Not found"})
    def api(self, method):
        if self.headers.get("X-API-Key") != KEY: return self.send_json(401, {"error": "Invalid or missing API key."})
        u = urlparse(self.path); parts = u.path.strip("/").split("/")[1:]
        try: n = int(self.headers.get("Content-Length") or 0); body = json.loads(self.rfile.read(n) or "{}")
        except ValueError: return self.send_json(400, {"error": "Invalid JSON body."})
        with LOCK:
            if method == "GET" and parts == ["events"]:
                limit = int(parse_qs(u.query).get("limit", ["50"])[0]); return self.send_json(200, EVENTS[::-1][:limit])
            if method == "POST" and parts == ["events"]:
                EVENTS.extend(body.get("events", [])); return self.send_json(200, {"accepted": len(body.get("events", []))})
            if method == "GET" and parts == ["alerts"]:
                return self.send_json(200, sorted(ALERTS.values(), key=lambda a: a["last_seen"], reverse=True))
            if parts[:1] == ["alerts"] and len(parts) >= 2:
                a = ALERTS.get(parts[1])
                if not a: return self.send_json(404, {"error": "Alert not found"})
                if method == "GET" and len(parts) == 2:
                    return self.send_json(200, {**a, "events": [e for e in EVENTS if e["event_id"] in a["event_ids"]]})
                if method == "POST" and parts[2:] == ["analyze"]:
                    time.sleep(1)  # pretend the LLM is thinking
                    a["ai_analysis"] = {"summary": f"Repeated SSH login attempts from {a['src_ip']} against {a['host_id']} match a brute force pattern (T1110).",
                        "impact": "The attacker may guess valid credentials and gain shell access to the host.",
                        "recommended_defense_id": "block_ip_iptables"}
                    return self.send_json(200, a)
            if method == "POST" and parts == ["defenses", "apply"]:
                a = ALERTS.get(body.get("alert_id"))
                if not a: return self.send_json(404, {"error": "Alert not found"})
                if body.get("defense_id") not in ("block_ip_iptables", "install_fail2ban"):
                    return self.send_json(400, {"error": "Unknown defense_id"})
                time.sleep(1); a["status"] = "defended"; return self.send_json(200, {"run_id": str(uuid.uuid4()), "status": "success"})
            if method == "POST" and parts == ["verifications"]:
                if body.get("alert_id") not in ALERTS: return self.send_json(404, {"error": "Alert not found"})
                v = {"verification_id": str(uuid.uuid4()), "alert_id": body["alert_id"], "baseline": None, "retest": None, "result": "running", "evidence": ""}
                VERS[v["verification_id"]] = v; threading.Thread(target=run_verification, args=(v,), daemon=True).start()
                return self.send_json(200, {"verification_id": v["verification_id"], "status": "running"})
            if method == "GET" and parts[:1] == ["verifications"] and len(parts) == 2:
                v = VERS.get(parts[1])
                return self.send_json(200, v) if v else self.send_json(404, {"error": "Verification not found"})
        self.send_json(404, {"error": "Not found"})

if __name__ == "__main__":
    print(f"Mock server: http://localhost:{PORT}  (API key: {KEY})")
    ThreadingHTTPServer(("0.0.0.0", PORT), partial(H, directory=HERE)).serve_forever()
