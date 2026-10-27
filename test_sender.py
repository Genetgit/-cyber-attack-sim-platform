import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from sender import send_batch

def test_empty_batch_is_a_noop():
    assert send_batch("http://localhost:1", "key", [], max_retries=1) is True

def test_unreachable_backend_does_not_raise(capsys):
    # port 1 is never listening; this must return False, never throw
    ok = send_batch("http://127.0.0.1:1", "key", [{"event_id": "x"}], max_retries=1)
    assert ok is False
