# Adaptive Cyber Attack Simulation & Defense Verification Platform

A small, safe-lab platform that runs a complete cyber defense loop: **attack a machine, detect the attack, stop it, and then prove the defense really worked.**
---
🎥 Demo video :https://drive.google.com/file/d/1z6QZWVsy4oEGxapR8sO23QOYS2VSHbIY/view?usp=sharing
## Table of Contents
1. [Purpose](#purpose)
2. [Key Features](#key-features)
3. [How It Works](#how-it-works)
4. [Architecture](#architecture)
5. [Detection Rules](#detection-rules)
6. [How a Defense Is Proven](#how-a-defense-is-proven)
7. [Lab Setup](#lab-setup)
8. [Running the Project](#running-the-project)
9. [Demo Results](#demo-results)
10. [Troubleshooting](#troubleshooting)
11. [Team](#team)

---

## Purpose

Most security tools only tell you that an attack happened. This project goes one step further: after a defense is applied, it **runs the same attack again** and checks whether the attack now fails. If it does, the defense is marked **VERIFIED**, with evidence saved. If not, it is marked **NOT VERIFIED**.

The project is intentionally small and focused:

- 1 attack: **SSH brute force**
- 2 defenses: **block IP with iptables**, **install fail2ban**
- 2 detection rules: **R001** and **R002**
- 1 database: **SQLite**
- 1 dashboard: plain **HTML + JavaScript**

## Key Features

- **Real attack simulation**: Hydra on Kali Linux brute-forces SSH on an Ubuntu target.
- **Live log collection**: an agent reads the SSH auth log on the target and sends events to the backend every 2 seconds.
- **Rule-based detection**: two rules generate alerts with a 0–100 risk score.
- **AI-assisted analysis**: an AI service explains each alert. If it is unavailable, a built-in fallback answer keeps the demo running.
- **One-click defense**: apply `block_ip_iptables` or `install_fail2ban` from the dashboard.
- **Automated verification**: re-run the attack and compare before/after results, shown as a clear VERIFIED / NOT VERIFIED badge.
- **Single-process deployment**: FastAPI serves both the API and the dashboard on port 8000.

## How It Works

```
Attack → Collect → Detect → Analyze → Defend → Re-test → Verify
```

| Step | What happens |
|------|--------------|
| **Attack** | The Runner on Kali starts a Hydra SSH brute-force attack against the Ubuntu target. |
| **Collect** | The Agent on the target tails `/var/log/auth.log` and posts events to the backend every 2 seconds. |
| **Detect** | The backend applies rules R001 and R002 and creates alerts with risk scores. |
| **Analyze** | The user clicks **Analyze with AI** to get an explanation of the alert. |
| **Defend** | The user applies a defense (`block_ip_iptables` or `install_fail2ban`). |
| **Re-test** | The Runner repeats the same attack. |
| **Verify** | The backend compares baseline vs. re-test and stores the verdict with evidence. |

## Architecture

The project has three parts. All three follow one shared API contract so they fit together.

| Part | Technology | Role |
|------|-----------|------|
| **Lab, Agent & Runner** | Kali Linux (attacker), Ubuntu (target), Python, Hydra | The agent reads the SSH log and sends events. The runner starts the attack, applies defenses, and resets the target. |
| **Backend** | FastAPI + SQLite | Stores events, detects attacks, asks AI to explain alerts, runs verification. |
| **Dashboard** | HTML + JavaScript | Shows live events and alerts; buttons for Analyze, Apply Defense, Run Verification. |

```
 ┌──────────────┐   SSH brute force    ┌─────────────────────────┐
 │  Kali Linux  │ ───────────────────▶ │      Ubuntu target      │
 │  (attacker)  │                      │  ┌───────────────────┐  │
 │  Runner API  │ ◀── apply defense ── │  │ Agent (collector) │  │
 └──────────────┘                      │  └─────────┬─────────┘  │
                                       │            │ events/2s  │
                                       │  ┌─────────▼─────────┐  │
                                       │  │ FastAPI + SQLite  │  │
                                       │  │  + Dashboard :8000│  │
                                       │  └───────────────────┘  │
                                       └─────────────────────────┘
```

## Detection Rules

| Rule | What it looks for | Alert level |
|------|-------------------|-------------|
| **R001** `ssh_bruteforce` | 5 or more failed SSH logins from the same IP within 60 seconds | High |
| **R002** `success_after_failures` | A successful login from an IP that had 5 or more failures in the last 10 minutes | Critical |

- The same rule + same IP will not create a new alert within **5 minutes**.
- **Risk score (0–100)** = severity weight × confidence.

## How a Defense Is Proven

1. **Baseline**: the Runner attacks the target. We confirm the attack works and that it is detected.
2. **Defend**: the backend applies the chosen defense (block the attacker IP with iptables, or install fail2ban).
3. **Re-test**: the Runner attacks again in exactly the same way.
4. **Compare**: if the attack worked before and fails now → **VERIFIED**. Otherwise → **NOT VERIFIED**. The result and evidence are saved to the database.

## Lab Setup

**Requirements**

- Two machines or VMs on the same isolated network:
  - **Kali Linux**: attacker (Hydra, Runner service)
  - **Ubuntu**: target (SSH server, Agent, Backend, Dashboard)
- Python 3.10+ on both machines
- SSH key access from Kali to Ubuntu (needed so the Runner can apply defenses without a password prompt)

**One-time SSH key setup (on Kali)**

```bash
ssh-keygen -t ed25519 -f ~/.ssh/lab_key
ssh-copy-id -i ~/.ssh/lab_key.pub ubuntu@<UBUNTU_IP>
```

> Note: Hydra *guesses* the login (the attack). `ssh-copy-id` installs a *trusted key* so the Runner can apply defenses. These are two different things, and mixing them up was our most common setup bug.

## Running the Project

Replace `<UBUNTU_IP>` and `<KALI_IP>` with the real addresses from `ip a` on each machine. Do **not** type the placeholders literally.

### 1. Ubuntu: Backend + Dashboard

```bash
unzip ~/<project-file>.zip && cd <project-folder>
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export API_KEY=<your_shared_lab_key>
export MOCK_RUNNER=false
export RUNNER_API_BASE=http://<KALI_IP>:8001
export TARGET_IP=127.0.0.1

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

- FastAPI serves the `frontend/` folder as static files, so **one process on port 8000 serves both the API and the UI**.
- `MOCK_RUNNER=false` makes the backend call the real Runner on Kali instead of simulating results.
- `RUNNER_API_BASE` must point to Kali's real IP on the lab network.
- Open the dashboard at `http://<UBUNTU_IP>:8000` from any machine on the lab network.

### 2. Ubuntu: Event Collector Agent

In a second terminal:

```bash
source venv/bin/activate

sudo API_URL=http://127.0.0.1:8000/api \
     API_KEY=<your_shared_lab_key> \
     HOST_ID=target-01 \
     LOG_FILE=/var/log/auth.log \
     venv/bin/python3 agent/collector.py
```

### 3. Kali: Runner

Start the Runner service on port `8001` (see the `runner/` folder), using the same `API_KEY`.
Manual Hydra Brute-Force Test (Optional Direct Attack)
```bash
hydra -l ubuntu -P lab_wordlist.txt -t 4 192.168.56.107 ssh
```
### 4. Use the dashboard

1. Start an attack from the Runner (Hydra against the Ubuntu target).
2. Watch live events and **R001 / R002** alerts appear.
3. Click **Analyze with AI** on an alert.
4. Choose a defense: `block_ip_iptables` or `install_fail2ban`, then click **Apply defense**.
5. Click **Run verification** and read the **VERIFIED / NOT VERIFIED** badge.

>  Never commit a real `API_KEY`. Keep it in an environment variable or a local `.env` file that is listed in `.gitignore`.

## Demo Results

In our lab test, Kali ran Hydra against the Ubuntu target and the collector sent events to the backend:

- Several **R001** alerts (High) from the same attacker IP, with risk scores of about **60–66**.
- One **R002** alert (Critical) with a risk score of **95**, because Hydra found a valid login.
- The attacker IP in the alerts was the Kali machine, so the data is **real, not mock**.
- Alerts appeared about **2 seconds** after the agent sent the events, matching the collector's poll interval.

This confirms the **Attack → Collect → Detect** steps work end to end. A field-by-field check of all parts against the shared contract found no mismatches.

## Troubleshooting

Problems we hit while building the lab, and the fixes:

| Problem | Fix |
|---------|-----|
| Port 8000 already in use by an old process | Stop the old process, then start the backend again. |
| Attack pointed at the wrong IP (Kali's own IP) | Use the Ubuntu IP from `ip a` on the target. |
| SSH key login from Kali failed | Create a key and copy it with `ssh-copy-id` to the Ubuntu machine. |
| Commands failed with `<KALI_IP>` or `<UBUNTU_IP>` | Replace the placeholders with real IP addresses. |

## Team

| Full name | CTC ID |
|-----------|--------|
| Yosef Addisu | CTC-318-26 |
| Genet Wegayehu | CT-2298-26 |
| Fikremariam Worku | CTC-7267-26 |
| Natnael Gebrehiwet | CTC-4763-26 |
| Amanuel Dawit | CTC-7132-26 |

---

**
