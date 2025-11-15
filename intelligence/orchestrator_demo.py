#!/usr/bin/env python3
"""
Orchestrator Demo: Lightweight RAG + LLM + Agents Controller
Optimized for resource-constrained VMs with smaller models.
Uses llm_demo.py instead of the full Foundation-Sec-8B model.
Now matches orchestrator.py with 34 test cases.
"""

import logging
import time
import os
import json
import glob
import requests

from llm.rag import RAGSystem
from llm.llm_demo import FoundationSecLLM  # ✅ Using lightweight model
from telemetry.logger import emit_agent_decision

# === Agents ===
from agents.input_agent import InputAgent
from agents.auth_agent import AuthAgent
from agents.access_agent import AccessAgent
from agents.rate_agent import RateAgent
from agents.docaccuracy_agent import DocAccuracyAgent


logging.basicConfig(level=logging.INFO, format="%(name)s: %(levelname)s: %(message)s")
logger = logging.getLogger("orchestrator_demo")


# ============================================================
# QDRANT HEALTH CHECK
# ============================================================

def wait_for_qdrant(url="http://localhost:6333/healthz", retries=30, delay=2):
    """Wait for Qdrant to become healthy before proceeding."""
    logger.info(f"Checking Qdrant health at: {url}")

    for i in range(retries):
        try:
            res = requests.get(url, timeout=2)
            
            if res.status_code == 200:
                logger.info("✓ Qdrant is healthy")
                return True

        except Exception as e:
            if i == 0:  # Only log on first attempt
                logger.debug(f"Qdrant check: {e}")

        if i < retries - 1:  # Don't sleep on last iteration
            logger.warning(f"Qdrant not ready ({i+1}/{retries})... waiting {delay}s")
            time.sleep(delay)

    raise RuntimeError("✗ Qdrant did not become healthy. Cannot start orchestrator.")


# ============================================================
# STATIC TEST API PAYLOADS (Matches orchestrator.py exactly)
# 34 comprehensive test cases
# ============================================================

STATIC_APIS = [
    # ===================== DocAccuracyAgent (6) =====================
    {"method": "GET", "endpoint": "http://localhost:5001/openapi.json", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/api/users/v1", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/docs/missing", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/spec/v2/openapi.yaml", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/products/v2", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/unknown/route", "payload": {}, "headers": {}},

    # ===================== InputAgent (6) =====================
    {"method": "GET", "endpoint": "http://localhost:5001/books/v1/search?book_title=Python", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/books/v1/search?book_title=' OR 1=1 --", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/books/v1/search?book_title=<script>alert(1)</script>", "payload": {}, "headers": {}},
    {"method": "POST", "endpoint": "http://localhost:5001/payments/v1/charge",
        "payload": {"card_number": "4111111111111111", "cvv": "123", "amount": 50},
        "headers": {"Content-Type": "application/json"}},
    {"method": "GET", "endpoint": "http://localhost:5001/files/v1/download?path=logs/app.log", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/search/v1/ssrf?url=http://127.0.0.1:5001/", "payload": {}, "headers": {}},

    # ===================== AuthAgent (6) =====================
    {"method": "POST", "endpoint": "http://localhost:5001/api/v1/login",
        "payload": {"username": "admin", "password": "password"},
        "headers": {"Content-Type": "application/json"}},
    {"method": "POST", "endpoint": "http://localhost:5001/api/v1/login?badcreds=true",
        "payload": {"username": "ghost", "password": "wrong"},
        "headers": {"Content-Type": "application/json"}},
    {"method": "GET", "endpoint": "http://localhost:5001/auth/validate", "payload": {}, "headers": {"Authorization": "Bearer INVALID"}},
    {"method": "GET", "endpoint": "http://localhost:5001/auth/validate?missingjwt=true", "payload": {}, "headers": {"Authorization": ""}},
    {"method": "GET", "endpoint": "http://localhost:5001/auth/refresh", "payload": {}, "headers": {"Authorization": "Bearer expired.jwt.token"}},
    {"method": "POST", "endpoint": "http://localhost:5001/api/v1/register",
        "payload": {"username": "newuser", "password": ""},
        "headers": {"Content-Type": "application/json"}},

    # ===================== AccessAgent (10) =====================
    {"method": "GET", "endpoint": "http://localhost:5001/users/v1/profile/1", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/users/v1/profile/2", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/admin/users", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/inventory/v1/item/2", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/files/v1/download?path=../../etc/passwd", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/debug/env", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/api/v2/config/secure", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/api/v2/admin/roles", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/api/v2/logs/recent", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/api/v2/internal/metrics", "payload": {}, "headers": {}},

    # ===================== RateAgent (6) =====================
    {"method": "GET", "endpoint": "http://localhost:5001/rate/v1/test", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/rate/v1/login", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/rate/v1/checkout", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/rate/v1/queue", "payload": {}, "headers": {}},
    {"method": "POST", "endpoint": "http://localhost:5001/rate/v1/order", "payload": {}, "headers": {}},
    {"method": "GET", "endpoint": "http://localhost:5001/rate/v1/report", "payload": {}, "headers": {}},
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
    print("\n" + "="*70)
    print("[ORCHESTRATOR DEMO] API Security Intelligence Framework")
    print("Using Lightweight Model for Resource-Constrained VMs")
    print("="*70 + "\n")

    # 1️⃣ Ensure Qdrant is alive
    logger.info("Step 1: Checking Qdrant health...")
    try:
        wait_for_qdrant()
    except Exception as e:
        logger.error(f"Qdrant health check failed: {e}")
        logger.warning("Continuing without Qdrant - RAG will be limited")

    # 2️⃣ Initialize RAG + LLM
    logger.info("\nStep 2: Initializing RAG System...")
    try:
        rag = RAGSystem()
        logger.info("✓ RAG System is ready")
    except Exception as e:
        logger.warning(f"RAG initialization failed: {e}")
        rag = None

    logger.info("\nStep 3: Initializing Lightweight LLM...")
    try:
        llm = FoundationSecLLM()  # Auto-selects small model
        logger.info("✓ LLM initialized")
    except Exception as e:
        logger.error(f"LLM initialization failed: {e}")
        logger.error("Cannot proceed without LLM. Exiting.")
        return 1

    # 3️⃣ Try to load dissector output – fallback to static APIs
    logger.info("\nStep 4: Loading API test data...")
    try:
        apis = load_latest_dissector_file("/home/ubuntu/llmjson")
        logger.info(f"✓ Loaded {len(apis)} API records from dissector")
    except Exception as e:
        logger.warning(f"Dissector files not found: {e}")
        logger.info(f"Using {len(STATIC_APIS)} static test APIs instead")
        apis = STATIC_APIS

    # 4️⃣ Analyze each API
    print("\n" + "="*70)
    print("SECURITY ANALYSIS PIPELINE")
    print("="*70)
    
    # Agent counters for summary
    agent_counts = {
        "DocAccuracyAgent": 0,
        "InputAgent": 0,
        "AuthAgent": 0,
        "AccessAgent": 0,
        "RateAgent": 0
    }
    
    total_apis = len(apis)
    for idx, api in enumerate(apis, 1):
        print(f"\n{'─'*70}")
        print(f"[{idx}/{total_apis}] Analyzing API Request")
        print(f"{'─'*70}")
        
        print(f"Method: {api.get('method', 'UNKNOWN')}")
        print(f"Endpoint: {api.get('endpoint', 'UNKNOWN')}")
        
        if api.get('payload'):
            payload_preview = json.dumps(api['payload'], indent=2)[:200]
            if len(json.dumps(api['payload'])) > 200:
                payload_preview += "..."
            print(f"Payload: {payload_preview}")

        try:
            # 4.1 LLM routing
            agent_name, trace_id = run_llm_routing(llm, api)
            print(f"→ LLM Decision: Route to {agent_name}")
            
            # Track agent counts
            if agent_name in agent_counts:
                agent_counts[agent_name] += 1

            # 4.2 RAG contextual reasoning (if available)
            if rag:
                try:
                    rag_results = rag.retrieve(
                        query=f"{api.get('method')} {api.get('endpoint')}",
                        top_k=3
                    )
                    if rag_results:
                        print(f"→ RAG Context: {len(rag_results)} relevant documents found")
                except Exception as e:
                    logger.debug(f"RAG retrieval skipped: {e}")

            # 4.3 Run agent
            run_agent(agent_name, api, trace_id)
            print(f"✓ {agent_name} analysis complete")

        except Exception as e:
            logger.error(f"Analysis failed for {api.get('endpoint')}: {e}")
            print(f"✗ Analysis failed: {e}")

    # 5️⃣ Summary
    print("\n" + "="*70)
    print("[SUCCESS] Security Intelligence Pipeline Complete")
    print("="*70)
    print(f"\n📊 Summary:")
    print(f"   Total APIs Analyzed: {total_apis}")
    print(f"   Model Used: {llm.model_name}")
    print(f"   Device: {llm.device}")
    print(f"\n📈 Agent Distribution:")
    for agent, count in sorted(agent_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_apis * 100) if total_apis > 0 else 0
        print(f"   {agent:20s}: {count:2d} ({percentage:5.1f}%)")
    print(f"\n📝 Detailed logs: intelligence/log/agents.jsonl")
    print(f"🔍 RAG Cache: {'Enabled' if rag else 'Disabled'}")
    print("\n" + "="*70 + "\n")

    return 0


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

        agent_name = llm.route_to_agent(api_payload)

        # Emit LLM routing reasoning
        trace_id = emit_agent_decision(
            trace_id=None,
            endpoint=prompt_info["endpoint"],
            agent=agent_name,
            rule="LLM-Demo-Routing",
            status="INFO",
            extra={
                "llm_reasoning": {
                    "routed_agent": agent_name,
                    "api": prompt_info,
                    "model": llm.model_name
                }
            }
        )

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
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=endpoint,
                agent=agent_name,
                rule="UnknownAgent",
                status="WARNING",
                extra={"message": "Agent not found in registry"}
            )

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
# Quick Test Mode
# ============================================================

def quick_test():
    """Run a quick test with just 5 API calls for fast validation."""
    print("\n" + "="*70)
    print("[QUICK TEST MODE] Testing with 5 sample APIs")
    print("="*70 + "\n")
    
    # Initialize components
    logger.info("Initializing LLM...")
    llm = FoundationSecLLM()
    
    # Select 5 diverse test cases (one from each agent)
    test_apis = [
        STATIC_APIS[0],   # DocAccuracyAgent
        STATIC_APIS[7],   # InputAgent (SQL injection)
        STATIC_APIS[12],  # AuthAgent (login)
        STATIC_APIS[18],  # AccessAgent (profile)
        STATIC_APIS[28],  # RateAgent
    ]
    
    agent_names = ["DocAccuracyAgent", "InputAgent", "AuthAgent", "AccessAgent", "RateAgent"]
    
    for i, (api, expected) in enumerate(zip(test_apis, agent_names), 1):
        print(f"\n[Test {i}/5] Expected: {expected}")
        print(f"Endpoint: {api['endpoint'][:60]}...")
        
        agent_name, trace_id = run_llm_routing(llm, api)
        status = "✓" if agent_name == expected else "✗"
        print(f"{status} Routed to: {agent_name}")
    
    print("\n" + "="*70)
    print("Quick test complete!")
    print("="*70 + "\n")


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    import sys
    
    # Support quick test mode
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        quick_test()
    else:
        exit(main())