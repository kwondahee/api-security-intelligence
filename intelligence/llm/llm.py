"""
Foundation-Sec-8B LLM Integration (RAG-Enhanced Routing + JSONL Logging)
"""

import logging
import torch
import time
from typing import Dict, Any
import sys
import os

from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


from llm.rag import RAGSystem
from telemetry.logger import emit_agent_decision  # ✅ use your existing JSONL logger

logger = logging.getLogger(__name__)


class FoundationSecLLM:
    """
    Foundation-Sec-8B model for routing API requests to appropriate agents,
    enhanced with RAG knowledge and logged reasoning.
    """

    def __init__(self, model_name: str = "fdtn-ai/Foundation-Sec-8B-Instruct"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # Initialize RAG system
        logger.info("Initializing Foundation-Sec-8B LLM with RAG integration...")
        self.rag = RAGSystem()

        logger.info(f"Initializing Foundation-Sec-8B on {self.device}...")
        self._load_model()

    def _load_model(self):
        """Load model with optional quantization and CPU fallback."""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)

            if self.device == "cuda":
                try:
                    bnb_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_use_double_quant=True,
                        bnb_4bit_quant_type="nf4",
                        bnb_4bit_compute_dtype=torch.float16
                    )
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.model_name,
                        quantization_config=bnb_config,
                        device_map="auto",
                        trust_remote_code=True
                    )
                    logger.info("Foundation-Sec-8B loaded successfully in 4-bit CUDA mode.")
                    return
                except Exception as quant_e:
                    logger.warning(f"Quantized load failed: {quant_e}")
                    logger.info("Falling back to full-precision CUDA model...")
                    self.model = AutoModelForCausalLM.from_pretrained(
                        self.model_name,
                        device_map="auto",
                        torch_dtype=torch.float16,
                        trust_remote_code=True
                    )
                    logger.info("Foundation-Sec-8B loaded successfully (CUDA full precision).")
                    return

            # CPU fallback
            logger.warning("No CUDA detected or GPU load failed — using CPU mode.")
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map="cpu",
                torch_dtype=torch.float32,
                trust_remote_code=True
            )
            logger.info("Foundation-Sec-8B loaded successfully on CPU.")

        except Exception as e:
            logger.error(f"Failed to load Foundation-Sec-8B: {e}")
            raise

    def route_to_agent(self, api_payload: Dict[str, Any]) -> str:
        """
        Route API payload to appropriate agent using LLM + RAG context,
        and log reasoning into agents.jsonl.
        """
        try:
            # Step 1: Retrieve relevant context from RAG
            rag_query = f"{api_payload.get('method', 'GET')} {api_payload.get('endpoint', '/')}"
            rag_docs = self.rag.retrieve(query=rag_query, top_k=3)

            # Combine retrieved docs into readable context
            context_text = "\n\n".join([doc["text"][:400] for doc in rag_docs]) if rag_docs else "No relevant documents found."

            # Step 2: Build RAG-informed routing prompt
            prompt = self._build_routing_prompt(api_payload, context_text)

            # Step 3: Run inference
            start_time = time.time()
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=120,
                    temperature=0.1,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id
                )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            latency = (time.time() - start_time)
            agent_name = self._extract_agent_name(response)

            logger.info(f"LLM (RAG-informed) routed request to: {agent_name}")

            # Step 4: Log reasoning into agents.jsonl
            rag_sources = [doc.get("source", "Unknown") for doc in rag_docs]
            emit_agent_decision(
                trace_id=None,
                endpoint=api_payload.get("endpoint", "Unknown"),
                agent="LLM-Router",
                rule="RAG-informed-routing",
                status="REASONED",
                extra={
                    "chosen_agent": agent_name,
                    "reasoning": response.strip()[:2000],
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
                agent="LLM-Router",
                rule="RAG-informed-routing",
                status="ERROR",
                extra={"error": str(e)}
            )
            return "InputAgent"  # Fallback

def _build_routing_prompt(self, api_payload: Dict[str, Any], context_text: str) -> str:
    """
    Build the RAG-informed prompt for agent routing.
    Rules are priority-based but expressed as PATTERN categories,
    not hard-coded paths — so the model generalizes to any API shape.
    """

    method = api_payload.get('method', 'GET')
    endpoint = api_payload.get('endpoint', '/')
    payload = api_payload.get('payload', {})
    headers = api_payload.get('headers', {})

    agent_descriptions = """
Available Agents:
- InputAgent: Detects unsafe or malicious user input (SQLi, XSS, SSRF, injection payloads, suspicious parameters).
- AuthAgent: Handles authentication flows (login, auth, token, register, refresh, validation).
- AccessAgent: Handles authorization issues (BOLA, IDOR, privilege escalation, accessing protected resources).
- RateAgent: Handles rate limiting, throttling, DoS-abuse or burst requests.
- DocAccuracyAgent: Ensures documentation consistency (OpenAPI, Swagger, documentation/schema endpoints, missing routes).
"""

    strict_rules = """
=== PRIORITY DECISION RULES (Generalized Pattern-Based) ===

1) DocAccuracyAgent  (HIGHEST PRIORITY)
Choose DocAccuracyAgent when:
- The route suggests documentation: keywords like "openapi", "swagger", "schema", "docs", "spec".
- The route appears undefined, unfamiliar, or resembles a missing/incorrect API.
- The request appears meant to check API accuracy.

2) AuthAgent
Choose AuthAgent when the request involves:
- Authentication, identity, sessions, tokens, login, registration.
- Keywords: "auth", "login", "token", "register", "refresh", "validate".

3) InputAgent
Choose InputAgent when:
- The input itself is dangerous:
    • SQLi patterns:  ' OR, --, 1=1
    • XSS patterns:   <script>
    • SSRF patterns:  url=http:// or url=https://
    • Suspicious or malformed query/body parameters

4) RateAgent
Choose RateAgent when:
- The route involves rate limiting or request-abuse testing:
    • keywords: "rate", "throttle", "ratelimit", "dos", "stress".

5) AccessAgent (LOWEST PRIORITY)
Choose AccessAgent when none of the above match, and:
- The route references a resource by ID (users/{id}, item/{id}, etc.)
- The route refers to privileged/sensitive areas:
    • admin, config, debug, env, internal, metrics, logs
- The request attempts file access or traversal:
    • ../  ../../  system file paths
"""

    few_shot_examples = """
=== CLASSIFICATION EXAMPLES ===

Example 1
Request: GET /openapi.json
Reasoning: Documentation reference → DocAccuracyAgent
Answer: DocAccuracyAgent

Example 2
Request: GET /search?title=' OR 1=1 --
Reasoning: SQL injection → InputAgent
Answer: InputAgent

Example 3
Request: GET /search?query=<script>alert(1)</script>
Reasoning: XSS payload → InputAgent
Answer: InputAgent

Example 4
Request: POST /api/v1/login
Reasoning: Authentication flow → AuthAgent
Answer: AuthAgent

Example 5
Request: GET /users/v1/profile/2
Reasoning: Accessing another user’s record → AccessAgent
Answer: AccessAgent

Example 6
Request: GET /rate/v1/test
Reasoning: Rate limit test → RateAgent
Answer: RateAgent
"""

    prompt = f"""
You are a cybersecurity LLM router. Classify the API request into exactly ONE agent.

=== Retrieved Security Knowledge (RAG Context) ===
{context_text}

=== API Request ===
Method: {method}
Endpoint: {endpoint}
Payload: {payload}
Headers: {headers}

=== Agent Definitions ===
{agent_descriptions}

{strict_rules}

{few_shot_examples}

=== INSTRUCTIONS ===
1. Apply rules IN PRIORITY ORDER (Doc → Auth → Input → Rate → Access).
2. Use pattern-based reasoning, not exact string matching.
3. Provide a short reasoning paragraph.
4. On the LAST LINE print ONLY one of:
   InputAgent, AuthAgent, AccessAgent, RateAgent, DocAccuracyAgent

Agent:
"""

    return prompt


    def _extract_agent_name(self, response: str) -> str:
        """Extract agent name from LLM response."""
        lines = response.strip().split('\n')
        last_line = lines[-1].strip()

        valid_agents = [
            "InputAgent", "AuthAgent", "AccessAgent",
            "RateAgent", "DocAccuracyAgent"
        ]

        for agent in valid_agents:
            if agent in last_line:
                return agent

        for agent in valid_agents:
            if agent in response:
                return agent

        logger.warning(f"Could not extract agent from LLM response: {last_line}")
        return "InputAgent"
