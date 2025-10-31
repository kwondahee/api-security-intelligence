#!/usr/bin/env python3
import time, requests, json, pathlib

API_BASE = "http://127.0.0.1:8080"
AGENT_LOG = "/var/log/api-security-intel/agents.jsonl"

tests = [
    {"name": "sqli_search", "method": "GET", "path": "/search", "params": {"q": "' OR 1=1 --"}, "expect": "InputAgent"},
    {"name": "admin_noauth", "method": "GET", "path": "/admin/users", "params": {}, "expect": "AuthAgent"},
    {"name": "tenant_cross", "method": "GET", "path": "/v2/tenant/T001/resources/R101", "params": {}, "expect": "AccessAgent"},
]

def send(t):
    url = API_BASE + t["path"]
    headers = {"X-Trace-Id": f"demo-{t['name']}-{int(time.time()%10000)}"}
    try:
        if t["method"] == "GET":
            r = requests.get(url, params=t.get("params", {}), headers=headers, timeout=5)
        else:
            r = requests.post(url, json=t.get("json"), headers=headers, timeout=5)
    except Exception as e:
        print("Request error", e)
        return None, headers["X-Trace-Id"]
    return r, headers["X-Trace-Id"]

def check_log_for_expect(trace_id, expect):
    p = pathlib.Path(AGENT_LOG)
    if not p.exists():
        print("Agent log not found:", AGENT_LOG); return False, None
    lines = p.read_text().strip().splitlines()[-500:]
    for l in lines[::-1]:
        try:
            o = json.loads(l)
        except Exception:
            continue
        if o.get("trace_id") == trace_id:
            return True, o
        if o.get("agent") == expect and trace_id in (o.get("trace_id") or ""):
            return True, o
        if o.get("agent") == expect and o.get("endpoint","").endswith("/" + trace_id.split("-")[1]):
            return True, o
    return False, None

if __name__ == "__main__":
    outcomes = []
    for t in tests:
        print("Running", t["name"])
        r, tid = send(t)
        time.sleep(1.5)
        ok, entry = check_log_for_expect(tid, t["expect"])
        outcomes.append((t["name"], ok, entry))
    print("-- RESULTS --")
    for name, ok, entry in outcomes:
        print(name, "PASS" if ok else "FAIL")
        if entry:
            print("  example log:", entry)
