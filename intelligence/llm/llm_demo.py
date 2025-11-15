"""
Lightweight LLM Demo for Resource-Constrained Environments
Uses smaller models (DistilGPT-2 or TinyLlama) with RAG integration
Drop-in replacement for llm.py with reduced memory footprint
"""

import logging
import torch
import time
from typing import Dict, Any
import sys
import os

from transformers import AutoTokenizer, AutoModelForCausalLM
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from llm.rag import RAGSystem
from telemetry.logger import emit_agent_decision

logger = logging.getLogger(__name__)


class FoundationSecLLM:
    """
    Lightweight LLM for API security routing using smaller models.
    Compatible with existing orchestrator.py interface.
    """

    def __init__(self, model_name: str = None):
        """
        Initialize with a small model suitable for limited resources.
        
        Args:
            model_name: Model to use. Options:
                - "TinyLlama/TinyLlama-1.1B-Chat-v1.0" (1.1B params, recommended)
                - "distilgpt2" (82M params, fastest but less capable)
                - None (auto-select based on available memory)
        """
        # Auto-select model if not specified
        if model_name is None:
            model_name = self._auto_select_model()
        
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # Initialize RAG system
        logger.info("Initializing Lightweight LLM with RAG integration...")
        try:
            self.rag = RAGSystem()
        except Exception as e:
            logger.warning(f"RAG initialization failed: {e}. Continuing without RAG.")
            self.rag = None

        logger.info(f"Initializing {model_name} on {self.device}...")
        self._load_model()

    def _auto_select_model(self) -> str:
        """Auto-select appropriate model based on available resources."""
        try:
            import psutil
            available_ram_gb = psutil.virtual_memory().available / (1024**3)
            
            if available_ram_gb > 8:
                logger.info(f"Detected {available_ram_gb:.1f}GB RAM - using TinyLlama-1.1B")
                return "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
            else:
                logger.info(f"Detected {available_ram_gb:.1f}GB RAM - using DistilGPT2")
                return "distilgpt2"
        except:
            logger.warning("Could not detect RAM - defaulting to DistilGPT2")
            return "distilgpt2"

    def _load_model(self):
        """Load model with memory-efficient settings."""
        try:
            logger.info(f"Loading tokenizer for {self.model_name}...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Set pad token if not present
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            if self.device == "cuda":
                logger.info("Loading model on CUDA with float16...")
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float16,
                    low_cpu_mem_usage=True,
                    trust_remote_code=True
                )
                self.model = self.model.to(self.device)
            else:
                logger.info("Loading model on CPU with float32...")
                self.model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    torch_dtype=torch.float32,
                    low_cpu_mem_usage=True,
                    trust_remote_code=True
                )

            logger.info(f"✓ {self.model_name} loaded successfully on {self.device}")

        except Exception as e:
            logger.error(f"Failed to load {self.model_name}: {e}")
            raise

    def route_to_agent(self, api_payload: Dict[str, Any]) -> str:
        """
        Route API payload to appropriate agent using LLM + RAG context.
        Compatible with orchestrator.py interface.
        """
        try:
            # Step 1: Retrieve relevant context from RAG
            rag_docs = []
            context_text = "No RAG context available."
            
            if self.rag:
                try:
                    rag_query = f"{api_payload.get('method', 'GET')} {api_payload.get('endpoint', '/')}"
                    rag_docs = self.rag.retrieve(query=rag_query, top_k=3)
                    context_text = "\n\n".join([
                        f"- {doc['text'][:300]}..." 
                        for doc in rag_docs
                    ]) if rag_docs else "No relevant documents found."
                except Exception as e:
                    logger.warning(f"RAG retrieval failed: {e}")

            # Step 2: Build routing prompt
            prompt = self._build_routing_prompt(api_payload, context_text)

            # Step 3: Run inference
            start_time = time.time()
            inputs = self.tokenizer(
                prompt, 
                return_tensors="pt",
                truncation=True,
                max_length=1024
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=100,
                    temperature=0.1,
                    do_sample=False,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            latency = (time.time() - start_time)
            agent_name = self._extract_agent_name(response)

            logger.info(f"LLM routed request to: {agent_name} (latency: {latency:.2f}s)")

            # Step 4: Log reasoning
            rag_sources = [doc.get("source", "Unknown") for doc in rag_docs]
            emit_agent_decision(
                trace_id=None,
                endpoint=api_payload.get("endpoint", "Unknown"),
                agent="LLM-Router-Demo",
                rule="RAG-informed-routing",
                status="REASONED",
                extra={
                    "chosen_agent": agent_name,
                    "model": self.model_name,
                    "reasoning": response.strip()[-500:],  # Last 500 chars
                    "rag_sources": rag_sources,
                    "latency_sec": round(latency, 2)
                }
            )

            return agent_name

        except Exception as e:
            logger.error(f"LLM routing failed: {e}")
            emit_agent_decision(
                trace_id=None,
                endpoint=api_payload.get("endpoint", "Unknown"),
                agent="LLM-Router-Demo",
                rule="RAG-informed-routing",
                status="ERROR",
                extra={"error": str(e)}
            )
            return self._fallback_routing(api_payload)

    def _build_routing_prompt(self, api_payload: Dict[str, Any], context_text: str) -> str:
        """
        Build the RAG-informed prompt for agent routing with priority rules.
        Simplified version for smaller models.
        """
        method = api_payload.get('method', 'GET')
        endpoint = api_payload.get('endpoint', '/')
        payload = str(api_payload.get('payload', {}))[:150]  # Truncate for small models
        
        # Condensed prompt optimized for small models
        prompt = f"""API Security Classification:

Request: {method} {endpoint}
Data: {payload}

Context: {context_text[:300]}

PRIORITY RULES (apply in order):
1. DocAccuracyAgent: openapi, swagger, docs, spec, missing routes
2. AuthAgent: login, auth, token, register, validation
3. InputAgent: SQLi (' OR, --), XSS (<script>), SSRF (url=http), injection
4. RateAgent: rate, throttle, dos, limit
5. AccessAgent: resource IDs, admin, config, debug, file paths (../)

EXAMPLES:
- GET /openapi.json → DocAccuracyAgent
- GET /search?q=' OR 1=1 -- → InputAgent
- POST /api/v1/login → AuthAgent
- GET /users/profile/2 → AccessAgent
- GET /rate/test → RateAgent

Answer with ONE agent name:"""
        
        return prompt

    def _extract_agent_name(self, response: str) -> str:
        """Extract agent name from LLM response."""
        valid_agents = [
            "InputAgent", "AuthAgent", "AccessAgent",
            "RateAgent", "DocAccuracyAgent"
        ]

        # Check last line first
        lines = response.strip().split('\n')
        last_line = lines[-1].strip()
        
        for agent in valid_agents:
            if agent in last_line:
                return agent

        # Check entire response
        for agent in valid_agents:
            if agent in response:
                return agent

        # Rule-based fallback
        logger.warning(f"Could not extract agent, using fallback routing")
        return self._fallback_routing({"endpoint": response})

    def _fallback_routing(self, api_payload: Dict[str, Any]) -> str:
        """
        Priority-based rule fallback matching the LLM prompt structure.
        """
        endpoint = api_payload.get("endpoint", "").lower()
        method = api_payload.get("method", "").upper()
        payload = str(api_payload.get("payload", {})).lower()
        
        # Priority 1: DocAccuracyAgent
        if any(kw in endpoint for kw in ["openapi", "swagger", "docs", "spec", ".json", ".yaml"]):
            return "DocAccuracyAgent"
        
        # Priority 2: AuthAgent
        if any(kw in endpoint for kw in ["auth", "login", "token", "register", "validate"]):
            return "AuthAgent"
        
        # Priority 3: InputAgent (dangerous input)
        dangerous_patterns = ["' or", "--", "1=1", "<script>", "url=http", "../"]
        if any(pattern in endpoint or pattern in payload for pattern in dangerous_patterns):
            return "InputAgent"
        
        # Priority 4: RateAgent
        if any(kw in endpoint for kw in ["rate", "throttle", "limit", "dos"]):
            return "RateAgent"
        
        # Priority 5: AccessAgent (default for resources)
        if any(kw in endpoint for kw in ["admin", "config", "debug", "env", "internal", "profile", "inventory"]):
            return "AccessAgent"
        
        # Final fallback
        return "InputAgent"


# ============================================================
# Standalone Demo
# ============================================================

def demo():
    """Standalone demo of the lightweight LLM."""
    print("\n" + "="*70)
    print("Lightweight LLM Demo - API Security Routing")
    print("="*70 + "\n")
    
    # Initialize LLM
    llm = FoundationSecLLM()
    
    # Test cases
    test_cases = [
        {
            "method": "GET",
            "endpoint": "http://localhost:5001/openapi.json",
            "payload": {},
            "description": "OpenAPI spec"
        },
        {
            "method": "GET",
            "endpoint": "http://localhost:5001/books/v1/search?book_title=' OR 1=1 --",
            "payload": {},
            "description": "SQL injection"
        },
        {
            "method": "POST",
            "endpoint": "http://localhost:5001/api/v1/login",
            "payload": {"username": "admin", "password": "password123"},
            "description": "Login"
        },
        {
            "method": "GET",
            "endpoint": "http://localhost:5001/admin/users",
            "payload": {},
            "description": "Admin access"
        },
        {
            "method": "GET",
            "endpoint": "http://localhost:5001/rate/v1/test",
            "payload": {},
            "description": "Rate limiting"
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n--- Test Case {i}: {test['description']} ---")
        print(f"Method: {test['method']}")
        print(f"Endpoint: {test['endpoint']}")
        
        agent = llm.route_to_agent(test)
        print(f"✓ Routed to: {agent}\n")
    
    print("="*70)
    print("Demo complete! Check intelligence/log/agents.jsonl for logs.")
    print("="*70 + "\n")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s: %(levelname)s: %(message)s"
    )
    demo()