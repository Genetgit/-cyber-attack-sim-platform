# Adaptive Cyber Attack Simulation & Defense Verification Platform

##  Video Presentation
Watch the 5-minute demonstration video here: [https://drive.google.com/file/d/1z6QZWVsy4oEGxapR8sO23QOYS2VSHbIY/view?usp=sharing]

---

##  Team Information

| Team Member | CTC ID |
| :--- | :--- |
| Yosef Addisu | CTC-318-26 |
| Genet Wegayehu | CT-2298-26 |
| Fikremariam Worku | CTC-7267-26 |
| Natnael Gebrehiwet | CTC-4763-26 |
| Amanuel Dawit | CTC-7132-26 |

---

##  Project Information

### Purpose
Most security tools only alert you when an attack happens. The **Adaptive Cyber Attack Simulation & Defense Verification Platform** goes one step further by automating a complete, closed-loop cyber defense cycle in an isolated lab environment. It simulates a real attack, detects it, applies a defense, re-runs the exact same attack, and verifies whether the defense actually blocked it.

**Full Lifecycle:**
`Attack → Collect → Detect → Analyze → Defend → Re-test → Verify`

### Main Features
* **Isolated Attack & Target Lab:** Uses two virtual machines—**Kali Linux** (attacker running Hydra) and **Ubuntu** (target)—connected over an isolated host-only network.
* **Real-Time Log Collection Agent:** Tails `/var/log/auth.log` on the Ubuntu target and streams SSH authentication events to the backend every 2 seconds.
* **Automated Detection Engine:** Uses FastAPI and SQLite to evaluate incoming events against two detection rules (`R001` for SSH brute-force attempts and `R002` for successful logins following multiple failures) and calculates a 0–100 risk score.
* **AI-Powered Alert Analysis:** Explains alerts in plain language (with an automatic fallback response if the AI service is offline).
* **Active Defense & Automated Re-Test Verification:** Applies real defenses (`block_ip_iptables` or `install_fail2ban`) via the Runner service, re-launches the Hydra brute-force attack, and displays a clear **VERIFIED** or **NOT VERIFIED** status badge on the dashboard.

---

##  System Architecture

1. **Lab, Agent & Runner:**
   * **Agent:** Runs on the Ubuntu target VM, parses `/var/log/auth.log`, and sends batches of events to `POST /api/events` every 2 seconds.
   * **Runner:** FastAPI service on the Kali attacker VM exposing `/run/attack` (via Hydra), `/run/defense`, and `/run/reset`.
2. **Backend (FastAPI + SQLite):**
   * Stores events, triggers alerts based on `R001` and `R002`, generates AI explanations, and orchestrates the baseline → defend → re-test verification loop.
3. **Dashboard (HTML/JS/CSS):**
   * Live web UI served on port `8000` allowing operators to view real-time alerts, trigger **Analyze with AI**, **Apply Defense**, and **Run Verification**.

---

##  Detection Rules

| Rule ID | Condition | Severity |
| :--- | :--- | :--- |
| **R001** | 5 or more failed SSH logins from the same IP within 60 seconds | High |
| **R002** | A successful login from an IP that had 5 or more failures in the last 10 minutes | Critical |

---

##  How to Run in the Lab

### 1. Ubuntu (Backend + Dashboard)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export API_KEY=secure_shared_lab_key_2026
export MOCK_RUNNER=false
export RUNNER_API_BASE=http://<KALI_IP>:8001
export TARGET_IP=127.0.0.1

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Access the dashboard at `http://<UBUNTU_IP>:8000`.

### 2. Ubuntu (Log Collector Agent)
```bash
source venv/bin/activate
sudo API_URL=http://127.0.0 \
  API_KEY=secure_shared_lab_key_2026 \
  HOST_ID=target-01 \
  LOG_FILE=/var/log/auth.log \
  venv/bin/python3 collector.py
```

### 3. Kali Linux (Attacker Runner Service)
```bash
venv/bin/uvicorn main:app --host 0.0.0.0 --port 8001
```

> **Disclaimer:** Designed strictly for educational testing in an isolated host-only virtual lab network.
