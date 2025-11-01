import json, time, pathlib, threading, os

# Adjustable via env; default to the path we planned for systemd/logrotate
AGENT_LOG = os.getenv("AGENT_LOG_PATH", "/var/log/aether/agents.jsonl")

_lock = threading.Lock()

def emit_agent_decision(*, trace_id: str | None, endpoint: str, agent: str, rule: str, status: str = "VULNERABLE", extra: dict | None = None):
    """
    Write a single JSONL record that the harness can assert against.
    - trace_id: optional (propagate X-Trace-Id if your orchestrator sets one)
    - endpoint: e.g. "/search"
    - agent: "InputAgent", "AuthAgent", etc.
    - rule: the specific detection (e.g., "SQLi-detect", "Missing-Auth", "NoRateLimit")
    - status: VULNERABLE | SECURE | MISCONFIGURATION | ERROR (whatever you use)
    """
    entry = {
        "ts": time.time(),
        "trace_id": trace_id,
        "endpoint": endpoint,
        "agent": agent,
        "rule": rule,
        "status": status,
    }
    if extra:
        entry["extra"] = extra
    p = pathlib.Path(AGENT_LOG)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False)
    with _lock:
        with p.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
