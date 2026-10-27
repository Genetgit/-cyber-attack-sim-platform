import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from parser import parse_line

def test_parses_failed_password():
    e = parse_line("Oct 1 12:00:05 target-01 sshd[2201]: Failed password for root from 10.0.0.5 port 41000 ssh2", "target-01")
    assert e["event_type"] == "ssh_login_failed"
    assert e["src_ip"] == "10.0.0.5" and e["username"] == "root" and e["host_id"] == "target-01"
    assert e["event_id"] and e["timestamp"].endswith("Z")

def test_parses_failed_password_invalid_user():
    e = parse_line("sshd[2201]: Failed password for invalid user oracle from 10.0.0.5 port 41005 ssh2", "target-01")
    assert e["event_type"] == "ssh_login_failed" and e["username"] == "oracle"

def test_parses_accepted_password():
    e = parse_line("sshd[2201]: Accepted password for root from 10.0.0.5 port 41020 ssh2", "target-01")
    assert e["event_type"] == "ssh_login_success" and e["username"] == "root" and e["src_ip"] == "10.0.0.5"

def test_ignores_publickey_lines():
    assert parse_line("sshd[1991]: Accepted publickey for deploy from 192.168.1.50 port 51211 ssh2", "target-01") is None

def test_ignores_unrelated_lines():
    assert parse_line("systemd[1]: Started OpenBSD Secure Shell server.", "target-01") is None
    assert parse_line("", "target-01") is None

def test_each_event_has_a_unique_id():
    a = parse_line("sshd[1]: Failed password for root from 10.0.0.5 port 1 ssh2", "target-01")
    b = parse_line("sshd[1]: Failed password for root from 10.0.0.5 port 1 ssh2", "target-01")
    assert a["event_id"] != b["event_id"]
