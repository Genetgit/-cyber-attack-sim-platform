#!/bin/bash
# Attacker VM: hydra plus the Runner service that the backend calls.
set -e
apt-get update -y
apt-get install -y hydra python3 python3-venv openssh-client

python3 -m venv /opt/runner/venv
/opt/runner/venv/bin/pip install -q -r /opt/runner/requirements.txt

echo "attacker-01 ready. Start the runner with:"
echo "  cd /opt/runner && venv/bin/uvicorn main:app --host 0.0.0.0 --port 8001"
