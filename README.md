# Member A — Lab, Event Collector Agent, Runner service

Three pieces, matching the contract exactly:
- **`agent/`** — runs on the target VM. Tails `/var/log/auth.log`, parses login
  attempts, batch-sends them as `EVENT`s to `POST /api/events` every 2s.
- **`runner/`** — FastAPI service, runs on the attacker VM. Implements the
  Runner API (`/run/attack` via Hydra, `/run/defense`, `/run/reset`).
- **`stub_backend/`** — a throwaway `POST /api/events` that just prints what
  it receives, so you can test the agent without the real backend running.

Also included: `Vagrantfile` for a Kali attacker + Ubuntu target on an
isolated host-only network, `sample_events.jsonl` (30 events for teammates to
use as mock data), and unit tests for the log parser.

## Quick test — no VMs needed
```
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pytest -q                                   # parser + sender unit tests

# in one terminal: a fake backend that just prints what it receives
python3 stub_backend/stub_backend.py

# in another: feed it a fake auth.log line by line
mkdir -p /tmp/fakelog && touch /tmp/fakelog/auth.log
LOG_FILE=/tmp/fakelog/auth.log API_URL=http://localhost:8000/api \
  python3 agent/collector.py &
echo 'sshd[1]: Failed password for root from 10.0.0.5 port 41000 ssh2' >> /tmp/fakelog/auth.log
```
You should see the line printed by the stub backend within ~2 seconds.

## Full lab (needs VirtualBox + Vagrant)
```
vagrant up                      # boots target (192.168.56.10) + attacker (192.168.56.20)
vagrant ssh target
  cd /opt/agent && sudo API_URL=http://<backend-host>:8000/api API_KEY=<key> \
    venv/bin/python3 collector.py
vagrant ssh attacker
  cd /opt/runner && venv/bin/uvicorn main:app --host 0.0.0.0 --port 8001
```
Point the real backend at the runner with `MOCK_RUNNER=false` and
`RUNNER_API_BASE=http://192.168.56.20:8001`.

## Config (all via env vars)
**Agent:** `API_URL`, `API_KEY`, `HOST_ID`, `LOG_FILE`, `BATCH_INTERVAL_S`, `MAX_RETRIES`.
**Runner:** `TARGET_SSH_HOST`, `TARGET_SSH_USER`, `SSH_KEY_PATH`, `WORDLIST`, `GUESS_USER`, `HYDRA_TIMEOUT_S`.

## Notes
- The agent never crashes on a bad log line or a network failure — both are
  caught, logged, and it keeps running.
- `sample_events.jsonl` includes a 9-failure brute force burst from one IP
  (triggers R001 and, after the following success, R002), a smaller 3-failure
  probe that stays under threshold, and quiet baseline traffic.
- Lab only: the throwaway accounts, weak passwords, and real Hydra attack are
  for an isolated host-only network. Never point this at anything else.
