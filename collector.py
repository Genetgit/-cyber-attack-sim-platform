#!/usr/bin/env python3
"""Event Collector Agent. Tails the SSH log, parses login attempts, and
batch-sends them to the backend every BATCH_INTERVAL_S seconds. Designed to
run forever on the target VM: any error is caught and logged, never crashes.

  sudo python3 collector.py
Config: see config.py (env vars API_URL, API_KEY, HOST_ID, LOG_FILE, ...)
"""
import os
import time

from config import settings
from parser import parse_line
from sender import send_batch

def follow(path: str):
    """Tail -f: open the file, seek to the end, then yield new lines as written."""
    while not os.path.exists(path):
        print(f"[collector] waiting for {path} to exist...")
        time.sleep(2)
    f = open(path, "r")
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def main():
    print(f"[collector] watching {settings.log_file} -> {settings.api_url} "
          f"(host_id={settings.host_id}, batch every {settings.batch_interval_s}s)")
    buffer: list[dict] = []
    last_flush = time.monotonic()
    for line in follow(settings.log_file):
        try:
            event = parse_line(line, settings.host_id)
            if event:
                buffer.append(event)
        except Exception as e:  # a bad line must never kill the agent
            print(f"[collector] could not parse line: {e}")
        if buffer and time.monotonic() - last_flush >= settings.batch_interval_s:
            try:
                send_batch(settings.api_url, settings.api_key, buffer, settings.max_retries)
            except Exception as e:  # a send failure must never kill the agent
                print(f"[collector] send error: {e}")
            buffer = []
            last_flush = time.monotonic()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[collector] stopped")
