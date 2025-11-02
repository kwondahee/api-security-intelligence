#!/usr/bin/env python3
import time, json, pathlib, argparse, requests

# Defaults (can be overridden by CLI)
API_BASE   = "http://127.0.0.1:8080"
AGENT_LOG  = "/var/log/aether/agents.jsonl"   # <-- your real path
MAX_AGE_S  = 90                                # only match logs from last N seconds
SLEEP_S    = 1.5                                # wait after request before reading logs

# The tests your API actually implements
TESTS = [
    # InputAgent — SQLi on /search
    dict(name="sqli_search",   method="GET",  path="/search",
         params={"q": "' OR 1=1 --"},
        expect_agent="InputAgent", expect_rule="SQLi-detect",  expect_ep="/search"),

    # AuthAgent — Missing-Auth on /admin/users
    dict(name="admin_noauth",  method="GET",  path="/admin/users",
         params=None,
        expect_agent="AuthAgent",  expect_rule="Missing-Auth", expect_ep="/admin/users"),

    # InputAgent — XSS on /echo
    dict(name="xss_echo",      method="POST", path="/echo",
         json={"body": "<script>alert(1)</script>"},
        expect_agent="InputAgent", expect_rule="XSS-detect",   expect_ep="/echo"),

    # InputAgent — Path traversal on /files
    dict(name="traversal_path",method="GET",  path="/files",
         params={"path": "../../etc/passwd"},
        expect_agent="InputAgent", expect_rule="Traversal-detect", expect_ep="/files"),

    # AccessAgent — BOLA on /rest/users
    dict(name="bola_access",   method="GET",  path="/rest/users",
         params=None,
        expect_agent="AccessAgent", expect_rule="BOLA",        expect_ep="/rest/users"),

    # DocAccuracyAgent — Undocumented endpoint (optional)
    dict(name="docs_undocumented", method="GET", path="/users/v1/_debug",
        params=None,
        expect_agent="DocAccuracyAgent", expect_rule="Undocumented-Endpoint", expect_ep="/users/v1/_debug"),
]

def send(session, base, t):
    url = base + t["path"]
    try:
        if t["method"] == "GET":
            r = session.get(url, params=t.get("params") or {}, timeout=5)
        else:
            r = session.post(url, json=t.get("json") or {}, timeout=5)
        return r
    except Exception as e:
        return e  # bubble up for printing

def parse_log_line(line):
    try:
        obj = json.loads(line)
        ts  = float(obj.get("ts", 0))  # your log has "ts" epoch float
        return ts, obj
    except Exception:
        return None, None

def find_match(agent_log_path, since_ts, expect_agent, expect_rule, expect_ep):
    p = pathlib.Path(agent_log_path)
    if not p.exists():
        return False, "agent log not found"

    # read only the tail to be cheap
    lines = p.read_text().splitlines()[-1000:]
    for line in reversed(lines):
        ts, obj = parse_log_line(line)
        if not obj or ts is None:
            continue
        if ts < since_ts:
            continue
        if obj.get("agent") != expect_agent:
            continue
        if expect_rule and obj.get("rule") != expect_rule:
            continue
        if expect_ep and not str(obj.get("endpoint","")).startswith(expect_ep):
            continue
        return True, obj
    return False, None

def run_one(session, base, agent_log_path, t):
    print(f"Running {t['name']} ...", end="", flush=True)
    start = time.time()
    r = send(session, base, t)

    # basic network/HTTP feedback
    if isinstance(r, Exception):
        print(" FAIL")
        return t['name'], False, f"request-error: {r}"
    else:
        # ok if 200; some demos purposely return 200 while logging VULNERABLE
        # if your route returns something else, relax this as needed
        if getattr(r, "status_code", None) not in (200, 201, 204):
            print(" FAIL")
            return t['name'], False, f"http {r.status_code}"

    time.sleep(SLEEP_S)
    ok, obj = find_match(agent_log_path, since_ts=start - 1,  # tiny backoff
                         expect_agent=t["expect_agent"],
                         expect_rule=t["expect_rule"],
                         expect_ep=t["expect_ep"])
    print(" PASS" if ok else " FAIL")
    return t['name'], ok, obj if ok else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=API_BASE, help="API base URL (default http://127.0.0.1:8080)")
    ap.add_argument("--agent-log", default=AGENT_LOG, help="Path to agents.jsonl")
    ap.add_argument("--since-seconds", type=int, default=MAX_AGE_S, help="Only match logs within the last N seconds")
    args = ap.parse_args()

    sess = requests.Session()
    results = []
    for t in TESTS:
        name, ok, obj = run_one(sess, args.api, args.agent_log, t)
        results.append((name, ok, obj))

    print("\n-- RESULTS --")
    failed = 0
    for name, ok, obj in results:
        print(f"{name:18} {'PASS' if ok else 'FAIL'}")
        if obj:
            print("  log:", json.dumps(obj, ensure_ascii=False))
        if not ok:
            failed += 1
    print(f"\nSummary: {len(results)-failed}/{len(results)} PASS")

if __name__ == "__main__":
    main()
