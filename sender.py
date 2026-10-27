"""POSTs a batch of EVENTs to the backend with retry + backoff. Never raises:
a send failure is logged and the batch is dropped so the agent keeps running."""
import json
import time
import urllib.error
import urllib.request

def send_batch(api_url: str, api_key: str, events: list[dict], max_retries: int = 5) -> bool:
    if not events:
        return True
    body = json.dumps({"events": events}).encode()
    delay = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                f"{api_url}/events", body,
                {"X-API-Key": api_key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                r.read()
            print(f"[sender] sent {len(events)} event(s)")
            return True
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            print(f"[sender] attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(delay)
                delay = min(delay * 2, 30)
    print(f"[sender] giving up on this batch ({len(events)} event(s) dropped)")
    return False
