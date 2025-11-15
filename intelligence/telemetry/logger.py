import json
import time
import pathlib
import threading
import os
import uuid

_lock = threading.Lock()


def get_next_log_filename(prefix: str, folder: str, ext: str):
    """Return the next available incremented filename."""
    os.makedirs(folder, exist_ok=True)

    existing = [
        f for f in os.listdir(folder)
        if f.startswith(prefix) and f.endswith("." + ext)
    ]

    if not existing:
        next_num = 1
    else:
        nums = []
        for f in existing:
            num = f.replace(prefix, "").replace("." + ext, "").strip("_")
            if num.isdigit():
                nums.append(int(num))
        next_num = max(nums) + 1 if nums else 1

    return os.path.join(folder, f"{prefix}_{next_num:03d}.{ext}")


# ----------------------------------------
# 🔥 Auto-increment log file
# ----------------------------------------
LOG_FOLDER = str(pathlib.Path(__file__).resolve().parent.parent / "log")
AGENT_LOG = get_next_log_filename("agents", LOG_FOLDER, "jsonl")


def emit_agent_decision(
    *,
    trace_id: str | None,
    endpoint: str,
    agent: str,
    rule: str | None = None,
    status: str = "VULNERABLE",
    extra: dict | None = None
):
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

    with _lock:
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return trace_id
