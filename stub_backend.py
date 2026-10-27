#!/usr/bin/env python3
"""Minimal stand-in for POST /api/events so Member A can test the agent
without running the real backend. Prints every event it receives and
returns {"accepted": n}, exactly like the real contract.

  python3 stub_backend.py          # listens on :8000
Env: PORT (default 8000), API_KEY (default secure_shared_lab_key_2026)
"""
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", 8000))
API_KEY = os.environ.get("API_KEY", "secure_shared_lab_key_2026")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/events":
            return self._send(404, {"error": "not found"})
        if self.headers.get("X-API-Key") != API_KEY:
            return self._send(401, {"error": "Invalid or missing API key."})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or "{}")
        except ValueError:
            return self._send(400, {"error": "Invalid JSON body."})
        events = body.get("events", [])
        ts = datetime.now().strftime("%H:%M:%S")
        for e in events:
            print(f"[{ts}] {e.get('event_type'):<20} {e.get('src_ip'):<15} "
                  f"user={e.get('username'):<10} {e.get('raw', '')[:80]}")
        self._send(200, {"accepted": len(events)})

if __name__ == "__main__":
    print(f"stub backend listening on :{PORT} (expects X-API-Key: {API_KEY})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
