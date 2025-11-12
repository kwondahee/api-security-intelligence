#!/usr/bin/env python3
"""
Orchestrator: RAG + LLM + Agents Controller
Coordinates the full security intelligence pipeline.
"""

import logging
import time
from urllib.parse import urlparse

from llm.rag import RAGSystem
from llm.llm import FoundationSecLLM
from telemetry.logger import emit_agent_decision  # adjust import path if needed

# === Agent imports ===
from agents.input_agent import InputAgent
from agents.auth_agent import AuthAgent
from agents.access_agent import AccessAgent
from agents.rate_agent import RateAgent
from agents.docaccuracy_agent import DocAccuracyAgent


logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# ============================================================
# Main orchestrator
# ============================================================

def main():
    print("\n======================================================================")
    print("[ORCHESTRATOR] Starting API Security Intelligence Framework")
    print("======================================================================")

    # 1️⃣ Initialize components
    logger.info("Initializing LangChain RAG System with Milvus...")
    rag = RAGSystem()
    logger.info("RAG System initialized successfully")

    logger.info("Initializing Foundation-Sec-8B LLM...")
    llm = FoundationSecLLM()
    logger.info("LLM initialized successfully")

    # 2️⃣ Define the test API endpoints
    apis = [
        {"method": "GET", "endpoint": "http://localhost:5001/books/v1/search", "payload": {"book_title": "test"}},     # normal search
        {"method": "GET", "endpoint": "http://localhost:5001/books/v1/search", "payload": {"book_title": "' OR 1=1 --"}},  # SQLi test
        {"method": "GET", "endpoint": "/users/v1/profile/1", "payload": {}},     # BOLA
        {"method": "GET", "endpoint": "/admin/users", "payload": {}},            # Missing auth
        {"method": "GET", "endpoint": "/api/internal/debug", "payload": {}},     # Undocumented endpoint
        {"method": "GET", "endpoint": "/rate_limit_test", "payload": {}},        # Rate limiting test
    ]

    # 3️⃣ Iterate through APIs and run full analysis
    for api in apis:
        print("\n--------------------------------------------------------------")
        print(f"[ANALYZING] {api['method']} {api['endpoint']}")

        # 3.1 Run LLM routing
        agent_name, trace_id = run_llm_routing(llm, api)

        # 3.2 Run RAG contextual reasoning
        rag.retrieve(
            agent_name=agent_name,
            finding={"endpoint": api["endpoint"], "trace_id": trace_id}
        )

        # 3.3 Run the specific agent analysis
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

        # ✅ Log LLM reasoning with automatic trace_id
        trace_id = emit_agent_decision(
            trace_id=None,
            endpoint=prompt_info["endpoint"],
            agent=agent_name,
            rule=None,
            status="INFO",
            extra={
                "llm_reasoning": {
                    "routed_agent": agent_name,
                    "api": prompt_info
                }
            }
        )

        logger.info(f"[LLM] Routed to {agent_name} (trace_id={trace_id})")
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
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "http://localhost:5001"  # fallback default


def run_agent(agent_name, api_payload, trace_id):
    """Run the actual security agent and link logs via trace_id."""
    endpoint = api_payload.get("endpoint", "unknown")
    base_url = get_base_url(endpoint)

    try:
        if agent_name == "InputAgent":
            InputAgent().analyze(api_payload, trace_id)
        elif agent_name == "AuthAgent":
            AuthAgent(base_url).analyze(api_payload, trace_id)
        elif agent_name == "AccessAgent":
            AccessAgent(base_url).analyze(api_payload, trace_id)
        elif agent_name == "RateAgent":
            RateAgent(base_url).analyze(api_payload, trace_id)
        elif agent_name == "DocAccuracyAgent":
            DocAccuracyAgent(base_url).analyze(api_payload, trace_id)
        else:
            logger.warning(f"Unknown agent '{agent_name}', skipping analysis.")

        logger.info(f"[{agent_name}] Analysis complete for {endpoint} (trace_id={trace_id})")

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
