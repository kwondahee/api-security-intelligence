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
        api_payload["payload"] = api_payload.get("payload") or {}

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
                    max_new_tokens=50,
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
        Build simple prompt for agent routing without complex prompt engineering.
        Just provides the API request and asks for the agent name.
        """
        method = api_payload.get('method', 'GET')
        endpoint = api_payload.get('endpoint', '/')
        payload = api_payload.get('payload', {})
        headers = api_payload.get('headers', {})

        prompt = f"""Classify this API request into one agent:
- InputAgent
- AuthAgent
- AccessAgent
- RateAgent
- DocAccuracyAgent

Request: {method} {endpoint}
Payload: {payload}
Headers: {headers}

Agent:"""

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
