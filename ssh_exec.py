"""Runs a command on the target over SSH. Kept separate so it's easy to stub in tests."""
import subprocess
from config import settings

def ssh_run(remote_cmd: str, timeout: int) -> subprocess.CompletedProcess:
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
    if settings.SSH_KEY_PATH:
        cmd += ["-i", settings.SSH_KEY_PATH]
    cmd += [f"{settings.TARGET_SSH_USER}@{settings.TARGET_SSH_HOST}", remote_cmd]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
