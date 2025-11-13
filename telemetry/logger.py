import json
import time
import pathlib
import threading
import os
import uuid  # ✅ for generating trace_id

# Adjustable via env; default to the path we planned for systemd/logrotate
AGENT_LOG = os.getenv(
    "AGENT_LOG_PATH",
    str(pathlib.Path(__file__).resolve().parent.parent / "log" / "agents.jsonl")
)

_lock = threading.Lock()


def emit_agent_decision(
    *,
    trace_id: str | None,
    endpoint: str,
    agent: str,
    rule: str | None = None,
    status: str = "VULNERABLE",
    extra: dict | None = None
):
    """
    Write a single JSONL record that the harness can assert against.
    - trace_id: optional (auto-generated if not provided)
    - endpoint: e.g. "/search"
    - agent: "InputAgent", "AuthAgent", etc.
    - rule: the specific detection (e.g., "SQLi-detect", "Missing-Auth", "NoRateLimit")
    - status: VULNERABLE | SECURE | INFO | ERROR
    """
    # ✅ generate a new trace_id if not passed
    if not trace_id:
        trace_id = str(uuid.uuid4())

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

    return trace_id  # ✅ return trace_id so it can be reused later
