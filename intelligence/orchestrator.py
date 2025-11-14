#!/usr/bin/env python3
"""
Orchestrator: RAG + LLM + Agents Controller
Coordinates the full API Security Intelligence pipeline.
Now Qdrant-based (no Milvus).
"""

import logging
import time
import os
import json
import glob
import requests

from llm.rag import RAGSystem             # Qdrant RAG
from llm.llm import FoundationSecLLM
from telemetry.logger import emit_agent_decision

# === Agents ===
from agents.input_agent import InputAgent
from agents.auth_agent import AuthAgent
from agents.access_agent import AccessAgent
from agents.rate_agent import RateAgent
from agents.docaccuracy_agent import DocAccuracyAgent


logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s: %(message)s")
logger = logging.getLogger("orchestrator")


# ============================================================
# QDRANT HEALTH CHECK
# ============================================================

def wait_for_qdrant(url="http://localhost:6333/healthz", retries=30, delay=2):
    print(f"➡️  Checking Qdrant using URL: {url}")

    for i in range(retries):
        try:
            res = requests.get(url, timeout=2)
            print("Status:", res.status_code, "Body:", res.text)

            # Qdrant returns status 200 with "healthz check passed"
            if res.status_code == 200:
                logger.info("Qdrant is healthy ✔")
                return True

        except Exception as e:
            print("EXCEPTION:", e)

        logger.warning(f"Qdrant not ready yet ({i+1}/{retries})... waiting {delay}s")
        time.sleep(delay)

    raise RuntimeError("❌ Qdrant did not become healthy. Cannot start orchestrator.")


# ============================================================
# STATIC TEST API PAYLOADS (LOCAL DEVELOPMENT)
# Matches mock_api.py endpoints
# ============================================================

STATIC_APIS = [
    # --- Existing ones ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/openapi.json",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/books/v1/search?book_title=Python",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/books/v1/search?book_title=' OR 1=1 --",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/users/v1/profile/1",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/users/v1/profile/2",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/admin/users",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/api/users/v1",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/api/internal/debug",
        "payload": {},
        "headers": {}
    },

    # --- NEW: Auth / login tests ---
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/api/v1/login",
        "payload": {"username": "admin", "password": "password123"},
        "headers": {"Content-Type": "application/json"}
    },
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/api/v1/login",
        "payload": {"username": "nonexistent", "password": "anything"},
        "headers": {"Content-Type": "application/json"}
    },

    # --- NEW: Payment endpoint (sensitive data handling, missing auth) ---
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/payments/v1/charge",
        "payload": {
            "card_number": "4111111111111111",
            "cvv": "123",
            "amount": 99.99
        },
        "headers": {"Content-Type": "application/json"}
    },

    # --- NEW: File download with path traversal ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/files/v1/download?path=../../etc/passwd",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/files/v1/download?path=logs/app.log",
        "payload": {},
        "headers": {}
    },

    # --- NEW: Inventory IDOR/BOLA ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/inventory/v1/item/1",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/inventory/v1/item/2",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/inventory/v1/item/999",
        "payload": {},
        "headers": {}
    },

    # --- NEW: SSRF-like endpoint ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/search/v1/ssrf?url=http://localhost:5001/",
        "payload": {},
        "headers": {}
    },

    # --- NEW: Sensitive config + env leaks ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/admin/config",
        "payload": {},
        "headers": {}
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/debug/env",
        "payload": {},
        "headers": {}
    },

    # --- NEW: Rate limit test endpoint ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/rate/v1/test",
        "payload": {},
        "headers": {}
    }
]


# ============================================================
# Load dissector output JSON
# ============================================================

def load_latest_dissector_file(folder="/home/ubuntu/llmjson"):
    """Find and load the latest API traffic JSON file from the dissector."""
    pattern = os.path.join(folder, "api_traffic.pcap*.json")
    files = glob.glob(pattern)

    if not files:
        raise FileNotFoundError(f"No dissector JSON files found in: {folder}")

    latest_file = max(files, key=os.path.getmtime)
    logger.info(f"Loading dissector output from: {latest_file}")

    with open(latest_file, "r") as f:
        return json.load(f)


# ============================================================
# Main orchestrator
# ============================================================

def main():
    print("\n======================================================================")
    print("[ORCHESTRATOR] Starting API Security Intelligence Framework")
    print("======================================================================")

    # 1️⃣ Ensure Qdrant is alive
    logger.info("Checking Qdrant health...")
    wait_for_qdrant()

    # 2️⃣ Initialize RAG + LLM
    logger.info("Initializing Qdrant-based RAG System...")
    rag = RAGSystem()
    logger.info("RAG System is ready ✔")

    logger.info("Initializing Foundation-Sec-8B LLM...")
    llm = FoundationSecLLM()
    logger.info("LLM initialized ✔")

    # 3️⃣ Try to load dissector output — fallback to static APIs
    logger.info("Attempting to load dissector output...")
    try:
        apis = load_latest_dissector_file("/home/ubuntu/llmjson")
        logger.info(f"Loaded {len(apis)} API records from dissector.")
    except Exception:
        logger.warning("No dissector files found — using STATIC test APIs instead.")
        apis = STATIC_APIS

    # 4️⃣ Analyze each API
    for api in apis:
        print("\n--------------------------------------------------------------")
        print(f"[ANALYZING] {api.get('method')} {api.get('endpoint')}")

        # 4.1 LLM routing
        agent_name, trace_id = run_llm_routing(llm, api)

        # 4.2 RAG contextual reasoning
        rag.retrieve(
            agent_name=agent_name,
            finding={"endpoint": api.get("endpoint"), "trace_id": trace_id},
            top_k=5
        )

        # 4.3 Run agent
        run_agent(agent_name, api, trace_id)

    print("\n======================================================================")
    print("[SUCCESS] Security intelligence pipeline complete.")
    print("Check intelligence/log/agents.jsonl for full reasoning traces.")
    print("======================================================================")


# ============================================================
# Helper functions
# ============================================================

def run_llm_routing(llm, api_payload):
    """Run LLM routing and log reasoning with a trace_id."""
    try:
        prompt_info = {
            "method": api_payload.get("method"),
            "endpoint": api_payload.get("endpoint"),
            "payload": api_payload.get("payload", {})
        }

        logger.info(f"Routing API {prompt_info['endpoint']} via LLM...")
        agent_name = llm.route_to_agent(api_payload)

        # Emit LLM routing reasoning
        trace_id = emit_agent_decision(
            trace_id=None,
            endpoint=prompt_info["endpoint"],
            agent=agent_name,
            rule=None,
            status="INFO",
            extra={"llm_reasoning": {"routed_agent": agent_name, "api": prompt_info}}
        )

        logger.info(f"LLM routed to {agent_name} (trace_id={trace_id})")
        return agent_name, trace_id

    except Exception as e:
        logger.error(f"LLM routing failed: {e}")
        fallback_agent = "InputAgent"
        trace_id = emit_agent_decision(
            trace_id=None,
            endpoint=api_payload.get("endpoint", "unknown"),
            agent=fallback_agent,
            rule="LLM-RoutingError",
            status="ERROR",
            extra={"exception": str(e)}
        )
        return fallback_agent, trace_id


def get_base_url(endpoint: str) -> str:
    """Extract the base URL from an endpoint."""
    from urllib.parse import urlparse
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "http://localhost:5001"


def run_agent(agent_name, api_payload, trace_id):
    """Run the actual security agent and link logs via trace_id."""
    endpoint = api_payload.get("endpoint", "unknown")
    base_url = get_base_url(endpoint)

    agents = {
        "InputAgent": lambda: InputAgent(base_url).analyze(api_payload, trace_id),
        "AuthAgent": lambda: AuthAgent(base_url).analyze(api_payload, trace_id),
        "AccessAgent": lambda: AccessAgent(base_url).analyze(api_payload, trace_id),
        "RateAgent": lambda: RateAgent(base_url).analyze(api_payload, trace_id),
        "DocAccuracyAgent": lambda: DocAccuracyAgent(base_url).analyze(api_payload, trace_id),
    }

    try:
        if agent_name in agents:
            agents[agent_name]()
        else:
            logger.warning(f"Unknown agent '{agent_name}', skipping.")

        logger.info(f"[{agent_name}] Analysis complete (trace_id={trace_id})")

    except Exception as e:
        logger.error(f"[{agent_name}] failed: {e}")
        emit_agent_decision(
            trace_id=trace_id,
            endpoint=endpoint,
            agent=agent_name,
            rule="AgentError",
            status="ERROR",
            extra={"exception": str(e)}
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()
