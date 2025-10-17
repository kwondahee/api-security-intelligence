# rag/llm.py
"""
Foundation-Sec-8B LLM Integration
"""

import logging
import torch
from typing import Dict, Any, Optional
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

logger = logging.getLogger(__name__)

class FoundationSecLLM:
    """
    Foundation-Sec-8B model for routing API requests to appropriate agents.
    Uses 4-bit quantization for efficient inference.
    """
    
    def __init__(self, model_name: str = "fdtn-ai/Foundation-Sec-8B-Instruct"):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        logger.info(f"Initializing Foundation-Sec-8B on {self.device}...")
        self._load_model()
    
    def _load_model(self):
        """Load model with 4-bit quantization (from midterm report)."""
        try:
            # Configure 4-bit quantization
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16
            )
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Load model with quantization
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                quantization_config=bnb_config,
                device_map="auto",
                trust_remote_code=True
            )
            
            logger.info("Foundation-Sec-8B loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load Foundation-Sec-8B: {e}")
            raise
    
    def route_to_agent(self, api_payload: Dict[str, Any]) -> str:
        """
        Route API payload to appropriate agent using LLM.
        
        Args:
            api_payload: Parsed API request (from dissector)
            
        Returns:
            Agent name (InputAgent, AuthAgent, AccessAgent, RateAgent, DocAccuracyAgent)
        """
        prompt = self._build_routing_prompt(api_payload)
        
        try:
            # Tokenize
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            
            # Generate
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=50,
                    temperature=0.1,  # Low temperature for deterministic routing
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Extract agent name from response
            agent_name = self._extract_agent_name(response)
            
            logger.info(f"LLM routed request to: {agent_name}")
            return agent_name
            
        except Exception as e:
            logger.error(f"LLM routing failed: {e}")
            return "InputAgent"  # Default fallback
    
    def _build_routing_prompt(self, api_payload: Dict[str, Any]) -> str:
        """Build prompt for agent routing."""
        method = api_payload.get('method', 'GET')
        endpoint = api_payload.get('endpoint', '/')
        payload = api_payload.get('payload', {})
        headers = api_payload.get('headers', {})
        
        prompt = f"""You are a cybersecurity expert analyzing API requests. Based on the API request details below, determine which security agent should analyze it.

API Request Details:
- Method: {method}
- Endpoint: {endpoint}
- Payload: {payload}
- Headers: {headers}

Available Agents:
- InputAgent: Handles input validation (SQL injection, XSS, path traversal)
- AuthAgent: Handles authentication issues (missing auth, JWT vulnerabilities, weak credentials)
- AccessAgent: Handles authorization issues (BOLA, BFLA, privilege escalation)
- RateAgent: Handles rate limiting and DoS vulnerabilities
- DocAccuracyAgent: Handles API documentation accuracy

Analyze the request and determine which agent is most appropriate. Consider:
- Suspicious input patterns in payload or parameters
- Authentication/authorization headers
- Request frequency patterns
- Endpoint documentation status

Important: The last line of your response must contain ONLY the agent name with no additional text.

Agent:"""
        
        return prompt
    
    def _extract_agent_name(self, response: str) -> str:
        """Extract agent name from LLM response."""
        # Get last line
        lines = response.strip().split('\n')
        last_line = lines[-1].strip()
        
        # Valid agent names
        valid_agents = [
            "InputAgent", "AuthAgent", "AccessAgent", 
            "RateAgent", "DocAccuracyAgent"
        ]
        
        # Check if last line contains a valid agent name
        for agent in valid_agents:
            if agent in last_line:
                return agent
        
        # Fallback: search entire response
        for agent in valid_agents:
            if agent in response:
                return agent
        
        logger.warning(f"Could not extract agent from LLM response: {last_line}")
        return "InputAgent"  # Default
