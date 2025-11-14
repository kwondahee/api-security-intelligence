#!/usr/bin/env python3
"""
Orchestrator Demo: Lightweight RAG + LLM + Agents Controller
Optimized for resource-constrained VMs with smaller models.
Uses llm_demo.py instead of the full Foundation-Sec-8B model.
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
# STATIC TEST API PAYLOADS
# Enhanced test suite for comprehensive security testing
# ============================================================

STATIC_APIS = [
    # --- OpenAPI Documentation ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/openapi.json",
        "payload": {},
        "headers": {},
        "description": "OpenAPI specification retrieval"
    },
    
    # --- Input Validation Tests ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/books/v1/search?book_title=Python",
        "payload": {},
        "headers": {},
        "description": "Normal book search"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/books/v1/search?book_title=' OR 1=1 --",
        "payload": {},
        "headers": {},
        "description": "SQL injection attempt"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/files/v1/download?path=../../etc/passwd",
        "payload": {},
        "headers": {},
        "description": "Path traversal attempt"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/files/v1/download?path=logs/app.log",
        "payload": {},
        "headers": {},
        "description": "Normal file download"
    },
    
    # --- Authentication Tests ---
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/api/v1/login",
        "payload": {"username": "admin", "password": "password123"},
        "headers": {"Content-Type": "application/json"},
        "description": "Login with credentials"
    },
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/api/v1/login",
        "payload": {"username": "nonexistent", "password": "anything"},
        "headers": {"Content-Type": "application/json"},
        "description": "Login with invalid credentials"
    },
    {
        "method": "POST",
        "endpoint": "http://localhost:5001/payments/v1/charge",
        "payload": {
            "card_number": "4111111111111111",
            "cvv": "123",
            "amount": 99.99
        },
        "headers": {"Content-Type": "application/json"},
        "description": "Payment without authentication"
    },
    
    # --- Authorization/Access Control Tests ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/users/v1/profile/1",
        "payload": {},
        "headers": {},
        "description": "User profile access (user 1)"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/users/v1/profile/2",
        "payload": {},
        "headers": {},
        "description": "User profile access (user 2) - potential BOLA"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/admin/users",
        "payload": {},
        "headers": {},
        "description": "Admin endpoint access without privileges"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/inventory/v1/item/1",
        "payload": {},
        "headers": {},
        "description": "Inventory access (item 1)"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/inventory/v1/item/999",
        "payload": {},
        "headers": {},
        "description": "Inventory access (item 999) - potential IDOR"
    },
    
    # --- Rate Limiting Tests ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/rate/v1/test",
        "payload": {},
        "headers": {},
        "description": "Rate limit test endpoint"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/api/users/v1",
        "payload": {},
        "headers": {},
        "description": "User listing endpoint"
    },
    
    # --- Information Disclosure Tests ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/api/internal/debug",
        "payload": {},
        "headers": {},
        "description": "Internal debug endpoint"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/admin/config",
        "payload": {},
        "headers": {},
        "description": "Configuration disclosure"
    },
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/debug/env",
        "payload": {},
        "headers": {},
        "description": "Environment variables disclosure"
    },
    
    # --- SSRF Tests ---
    {
        "method": "GET",
        "endpoint": "http://localhost:5001/search/v1/ssrf?url=http://localhost:5001/",
        "payload": {},
        "headers": {},
        "description": "SSRF attempt"
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
    
    total_apis = len(apis)
    for idx, api in enumerate(apis, 1):
        print(f"\n{'─'*70}")
        print(f"[{idx}/{total_apis}] Analyzing API Request")
        print(f"{'─'*70}")
        
        # Show description if available
        if "description" in api:
            print(f"Test: {api['description']}")
        
        print(f"Method: {api.get('method', 'UNKNOWN')}")
        print(f"Endpoint: {api.get('endpoint', 'UNKNOWN')}")
        
        if api.get('payload'):
            print(f"Payload: {json.dumps(api['payload'], indent=2)[:200]}")

        try:
            # 4.1 LLM routing
            agent_name, trace_id = run_llm_routing(llm, api)
            print(f"→ LLM Decision: Route to {agent_name}")

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
    print(f"   - APIs Analyzed: {total_apis}")
    print(f"   - Model Used: {llm.model_name}")
    print(f"   - Device: {llm.device}")
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
    """Run a quick test with just 3 API calls for fast validation."""
    print("\n" + "="*70)
    print("[QUICK TEST MODE] Testing with 3 sample APIs")
    print("="*70 + "\n")
    
    # Initialize components
    logger.info("Initializing LLM...")
    llm = FoundationSecLLM()
    
    # Select 3 diverse test cases
    test_apis = [
        STATIC_APIS[2],   # SQL injection
        STATIC_APIS[5],   # Login
        STATIC_APIS[10],  # Admin access
    ]
    
    for i, api in enumerate(test_apis, 1):
        print(f"\n[Test {i}/3] {api.get('description', 'Testing API')}")
        print(f"Endpoint: {api['endpoint']}")
        
        agent_name, trace_id = run_llm_routing(llm, api)
        print(f"✓ Routed to: {agent_name}")
    
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