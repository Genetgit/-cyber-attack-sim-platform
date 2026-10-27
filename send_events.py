#!/usr/bin/env python3
"""Send events to the backend like the lab agent would (stdlib only).

  python scripts/send_events.py                 # load sample_events.jsonl (timestamps shifted to now)
  python scripts/send_events.py --live          # live attack: 1 failed login/sec, then a success
Env: API_URL (default http://localhost:8000/api), API_KEY
"""
import argparse, json, os, random, time, urllib.request, uuid
from datetime import datetime, timedelta, timezone

URL = os.environ.get("API_URL", "http://localhost:8000/api")
KEY = os.environ.get("API_KEY", "secure_shared_lab_key_2026")
Z = "%Y-%m-%dT%H:%M:%SZ"

def post(events):
    req = urllib.request.Request(f"{URL}/events", json.dumps({"events": events}).encode(),
                                 {"X-API-Key": KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)

def event(kind, ip, user="root"):
    verb = "Failed" if kind == "ssh_login_failed" else "Accepted"
    return {"event_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).strftime(Z), "host_id": "target-01",
            "source": "auth_log", "event_type": kind, "src_ip": ip, "username": user,
            "raw": f"sshd[2201]: {verb} password for {user} from {ip} port {random.randint(30000, 60000)} ssh2"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--file", default=os.path.join(os.path.dirname(__file__), "..", "sample_events.jsonl"))
    p.add_argument("--live", action="store_true")
    p.add_argument("--ip", default="10.0.0.5")
    p.add_argument("--failures", type=int, default=8)
    a = p.parse_args()
    if a.live:
        for i in range(a.failures):
            print("failed login", i + 1, post([event("ssh_login_failed", a.ip, random.choice(["root", "admin", "ubuntu"]))]))
            time.sleep(1)
        print("successful login", post([event("ssh_login_success", a.ip)]))
        return
    events = [json.loads(l) for l in open(a.file) if l.strip()]
    last = max(datetime.strptime(e["timestamp"], Z) for e in events)
    shift = datetime.utcnow() - last
    for e in events:   # rebase to now and use fresh ids so the file can be loaded repeatedly
        e["timestamp"] = (datetime.strptime(e["timestamp"], Z) + shift).strftime(Z)
        e["event_id"] = str(uuid.uuid4())
    print(post(events))

if __name__ == "__main__":
    main()
