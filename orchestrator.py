# ==============================================================================
# 1. CORE EXECUTION AGENT (input_agent.py content)
#    (The code for this agent would typically be imported from input_agent.py)
# ==============================================================================
import json
import requests
from typing import Dict, Any, Optional, List
import time
from agents.input_agent import InputAgent
from agents.auth_agent import AuthAgent
from agents.access_agent import AccessAgent
from agents.rate_agent import RateAgent
from agents.docaccuracy_agent import DocAccuracyAgent



class InputAgent:
    """Agent for testing injection vulnerabilities (SQLi, XSS, etc.)."""
    def __init__(self, base_url: str):
        self.findings = []
        self.base_url = base_url
        self.sqli_payloads: List[str] = ["1' OR 1=1 --", "admin' --", "' OR '1'='1"]

    def _make_request(self, url: str, method: str, params: Dict[str, str]) -> Optional[requests.Response]:
        """Handles sending the actual HTTP request (simplified)."""
        print(f"    [EXECUTION] -> Sending {method} request to: {url}")
        try:
            # Simulated request to prevent errors if VAmPI is not running
            response = requests.request(method, url, params=params, timeout=1)
            return response
        except requests.exceptions.RequestException:
            # Simulate a successful response for a finding demonstration
            if "1=1" in url:
                 # Simulate a successful finding
                class MockResponse:
                    def __init__(self, text):
                        self.text = text
                        self.status_code = 200
                    def json(self): return {}
                return MockResponse(text="SQLITE_ERROR: syntax error")
            return None

    def test_sqli(self, endpoint: str, parameter: str, method: str) -> Optional[Dict[str, str]]:
        """Executes a test run for SQL Injection."""
        # Simplified: We just check the first payload for a finding demonstration
        full_url = f"{self.base_url}{endpoint.split('{')[0]}{self.sqli_payloads[0]}"
        response = self._make_request(full_url, method, params={})

        if response and 'syntax error' in response.text.lower():
            finding = {
                "agent": "InputAgent",
                "endpoint": endpoint,
                "status": "VULNERABLE",
                "vuln_type": "SQL Injection",
                "severity": "HIGH",
            }
            self.findings.append(finding)
            return finding
        return {"status": "SECURE", "vuln_type": "None Found"}

# ==============================================================================
# 2. NEW MOCK AGENTS (These would be in their own files: access_agent.py, etc.)
# ==============================================================================
class DocAccuracyAgent:
    """Agent for checking if the documentation matches the actual API implementation."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings = []
    
    def run_check(self, spec_path: str) -> None:
        print(f"[DOCS AGENT] Analyzing OpenAPI spec at '{spec_path}'...")
        time.sleep(0.5)
        # Simulate a finding: an undocumented endpoint
        finding = {
            "agent": "DocAccuracyAgent",
            "endpoint": "/v1/internal/admin_data",
            "status": "MISCONFIGURATION",
            "vuln_type": "Improper Inventory Management (Undocumented Endpoint)",
            "severity": "MEDIUM",
        }
        self.findings.append(finding)

class AuthAgent:
    """Agent for testing authentication mechanisms (API keys, JWT, OAuth flows)."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings = []

    def test_auth_bypass(self, endpoint: str, method: str) -> None:
        print(f"[AUTH AGENT] Attempting unauthenticated access to '{endpoint}'...")
        time.sleep(0.5)
        # Simulate a successful bypass attempt
        finding = {
            "agent": "AuthAgent",
            "endpoint": endpoint,
            "status": "VULNERABLE",
            "vuln_type": "Broken Authentication (Unauthenticated Access)",
            "severity": "CRITICAL",
        }
        self.findings.append(finding)

class AccessAgent:
    """Agent for testing authorization and access control (BOLA, BFLA)."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings = []

    def test_bola(self, target_resource: str) -> None:
        print(f"[ACCESS AGENT] Testing Broken Object Level Authorization (BOLA) on '{target_resource}'...")
        time.sleep(0.5)
        # Simulate a secure finding
        print("    [RESULT] Access control check passed for BOLA.")

class RateAgent:
    """Agent for testing rate limiting, throttling, and resource consumption."""
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.findings = []

    def test_rate_limit(self, endpoint: str) -> None:
        print(f"[RATE AGENT] Stress-testing rate limits on '{endpoint}'...")
        time.sleep(0.5)
        # Simulate a finding: no rate limit
        finding = {
            "agent": "RateAgent",
            "endpoint": endpoint,
            "status": "VULNERABLE",
            "vuln_type": "Unrestricted Resource Consumption (No Rate Limit)",
            "severity": "HIGH",
        }
        self.findings.append(finding)

# ==============================================================================
# 3. THE ORCHESTRATOR LOGIC
# ==============================================================================
def run_full_scan():
    """Defines the full, sequential, and orchestrated security assessment workflow."""
    
    API_BASE_URL = "http://localhost:5001"
    
    # Target defined for the scan
    TARGET_ENDPOINT_SQLI = "/books/v1/{book_title}"
    TARGET_ENDPOINT_AUTH = "/users/v1/profile"
    TARGET_ENDPOINT_RATE = "/login"
    
    ALL_AGENTS = []
    ALL_FINDINGS = []

    print("==================================================================")
    print("🛡️ Multi-Agent Security Orchestrator: Full Scan 🛡️")
    print(f"Target: {API_BASE_URL}")
    print("==================================================================")

    # 1. INITIALIZE AGENTS
    docs_agent = DocAccuracyAgent(API_BASE_URL)
    auth_agent = AuthAgent(API_BASE_URL)
    access_agent = AccessAgent(API_BASE_URL)
    rate_agent = RateAgent(API_BASE_URL)
    input_agent = InputAgent(API_BASE_URL)

    ALL_AGENTS.extend([docs_agent, auth_agent, access_agent, rate_agent, input_agent])

    # 2. WORKFLOW EXECUTION (Logical Security Assessment Flow)
    
    # --- PHASE 1: Discovery & Documentation ---
    print("\n--- PHASE 1: DocAccuracy & Inventory Management ---")
    docs_agent.run_check(spec_path="/docs/openapi.json")

    # --- PHASE 2: Core Access Controls ---
    print("\n--- PHASE 2: Authentication (AuthAgent) ---")
    auth_agent.test_auth_bypass(TARGET_ENDPOINT_AUTH, "GET")

    print("\n--- PHASE 3: Authorization (AccessAgent) ---")
    access_agent.test_bola(target_resource="/accounts/123/details")

    # --- PHASE 4: Abuse & Resource Consumption ---
    print("\n--- PHASE 4: Rate Limiting (RateAgent) ---")
    rate_agent.test_rate_limit(TARGET_ENDPOINT_RATE)

    # --- PHASE 5: Input & Fuzzing ---
    print("\n--- PHASE 5: Input Fuzzing (InputAgent) ---")
    input_agent.test_sqli(
        endpoint=TARGET_ENDPOINT_SQLI,
        parameter="book_title",
        method="GET"
    )

    # 3. CONSOLIDATE REPORTING
    print("\n==================================================================")
    print("                FINAL CONSOLIDATED REPORT")
    print("==================================================================")

    for agent in ALL_AGENTS:
        if agent.findings:
            ALL_FINDINGS.extend(agent.findings)

    if ALL_FINDINGS:
        print(f"🚨 Total Findings: {len(ALL_FINDINGS)}")
        print(json.dumps(ALL_FINDINGS, indent=2))
    else:
        print("✅ No vulnerabilities found in this scan.")
    
    print("\n==================================================================")


if __name__ == '__main__':
    run_full_scan()