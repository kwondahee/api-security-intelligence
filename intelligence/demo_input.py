#!/usr/bin/env python3
"""
run_input_agent_scan.py

Iterates a list of endpoints and parameters, runs agents.input_agent.InputAgent
against each target, aggregates findings (including SECURE if enabled), and
writes findings.json.
"""

import json
import logging
import time
from pathlib import Path

from rag.agents.input_agent import InputAgent

# Basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("run_input_agent_scan")

# --- CONFIGURATION ---
TARGET_BASE = "http://localhost:5001"   # Juice Shop local instance
OUTPUT_FILE = Path("findings.json")

# If True, save SECURE checks as findings too (full audit). If False, only VULNERABLE/ERROR are saved.
RECORD_SECURE = True

# List of endpoints to test.
ENDPOINTS_TO_TEST = [
    {"path": "/rest/products/search", "param": "q", "method": "GET"},
    {"path": "/rest/user/login", "param": "email", "method": "POST"},
    {"path": "/api/Feedback", "param": "comment", "method": "POST"},
    {"path": "/files", "param": "name", "method": "GET"},
    {"path": "/rest/product/{id}", "param": "id", "method": "GET"},
]

PAUSE_BETWEEN = 0.5

def run():
    logger.info("Initializing InputAgent runner")
    agent = InputAgent(target_base_url=TARGET_BASE)

    all_findings = []

    # If agent._report_secure appends secure findings (as suggested), we may simply collect them.
    # If not, and RECORD_SECURE == True, we will synthesize secure records from logged info (not implemented here).
    for entry in ENDPOINTS_TO_TEST:
        path = entry["path"]
        param = entry["param"]
        method = entry.get("method", "GET").upper()

        logger.info(f"Running scan for {method} {path}  (param: {param})")

        # Clear agent.findings for per-endpoint isolation if desired:
        agent.findings = []

        try:
            findings = agent.run_scan(endpoint_path=path, parameter=param, method=method) or []
        except Exception as e:
            logger.exception(f"Unhandled exception while scanning {path}: {e}")
            findings = [{
                "agent": agent.name,
                "category": "Input Validation",
                "vuln": "ScanError",
                "status": "ERROR",
                "severity": "Unknown",
                "endpoint": f"{method} {path}",
                "method": method,
                "actor": "runner",
                "evidence": {"error": str(e)},
                "recommendation": "Investigate runner exception"
            }]

        # If RECORD_SECURE is False, filter out SECURE findings
        if not RECORD_SECURE:
            findings = [f for f in findings if f.get("status") != "SECURE"]

        # Annotate and add metadata
        for f in findings:
            if not f.get("endpoint"):
                f["endpoint"] = f"{method} {path}"
            f.setdefault("scan_target", TARGET_BASE)
            f.setdefault("scanned_at", time.strftime("%Y-%m-%dT%H:%M:%S%z"))

        all_findings.extend(findings)

        time.sleep(PAUSE_BETWEEN)

    # Save results
    try:
        OUTPUT_FILE.write_text(json.dumps(all_findings, indent=2))
        logger.info(f"Wrote {len(all_findings)} findings to {OUTPUT_FILE.resolve()}")
    except Exception as e:
        logger.exception(f"Failed to write output file: {e}")

    # Console summary
    if not all_findings:
        logger.info("No findings recorded.")
    else:
        by_status = {}
        for f in all_findings:
            st = f.get("status", "UNKNOWN")
            by_status[st] = by_status.get(st, 0) + 1
        logger.info("Summary by status:")
        for st, cnt in by_status.items():
            logger.info(f"  {st}: {cnt}")

    return all_findings

if __name__ == "__main__":
    run()
