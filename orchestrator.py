#!/usr/bin/env python3
"""
API Security Intelligence Orchestrator
***with RAG integration***
This script coordinates multiple security agents to perform a comprehensive
vulnerability assessment on a target API.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import asdict

# Import Agent Modules (Ensure all necessary libraries are installed via pip)
from agents.docaccuracy_agent import DocAccuracyAgent
from agents.input_agent import InputAgent
from agents.rate_agent import RateAgent
# Assuming the user has these agents based on the previous conversation
from agents.auth_agent import AuthAgent 
from agents.access_agent import AccessAgent 

# Import RAG System
from rag.rag import RAGSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
TARGET_BASE_URL = "http://localhost:5001" # Target VAmPI or similar API endpoint
SPEC_FILE_PATH = "openapi.json"           # Path to the OpenAPI spec (if local)

# Endpoints for specific agent testing (based on common API paths)
#TARGET_ENDPOINT_DOCS = "http://localhost:5001/docs/openapi.json"
TARGET_ENDPOINT_DOCS = "/openapi.json"
TARGET_ENDPOINT_SQLI = "/books/v1/search" # Example endpoint for input testing
TARGET_PARAM_SQLI = "book_title"          # Example parameter for input testing
TARGET_ENDPOINT_RATE = "/users/v1/profile/1" # Example endpoint for rate testing
TARGET_ENDPOINT_AUTH = "/admin/users"       # Example endpoint for auth testing

# --- MAIN ORCHESTRATOR CLASS ---
class APISecurityOrchestrator:
    def __init__(self, base_url: str, enable_rag: bool = True):
        self.base_url = base_url
        self.all_findings: List[Dict[str, Any]] = []
        self.enable_rag = enable_rag
        #Initialize RAG
        if self.enable_rag:
            try:
                logger.info("Initializing RAG System...")
                self.rag = RAGSystem()
                logger.info("RAG System successfully initialized")
            except Exception as e:
                logger.error(f"Failed to initialize RAG: {e}"
                logger.warning("Continuing without RAG")
                self.enable_rag = False
                self.rag = None
        # Initialize Agents
        self.docs_agent = DocAccuracyAgent(base_url=self.base_url)
        self.input_agent = InputAgent(target_base_url=self.base_url)
        self.rate_agent = RateAgent(target_base_url=self.base_url)
        self.auth_agent = AuthAgent(target_base_url=self.base_url)
        self.access_agent = AccessAgent(target_base_url=self.base_url)

        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - INFO - AuthAgent initialized for target: {self.base_url}")
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - INFO - AccessAgent initialized for target: {self.base_url}")
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - INFO - RateAgent initialized for target: {self.base_url}")


    def run_full_scan(self):
        print("==================================================================")
        print(f"🛡️ Multi-Agent Security Orchestrator: Full Scan 🛡️")
        print(f"Target: {self.base_url}")
        print("==================================================================")

        # --- PHASE 1: DocAccuracy & Inventory Management ---
        print("\n--- PHASE 1: DocAccuracy & Inventory Management (DocAccuracyAgent) ---")
        
        # FIX APPLIED HERE: Changed 'spec_path' to 'doc_source'
        docs_findings = self.docs_agent.run_check(doc_source=TARGET_ENDPOINT_DOCS)
        self.all_findings.extend(docs_findings)

        # --- PHASE 2: Input Validation & Fuzzing ---
        print("\n--- PHASE 2: Input Validation & Fuzzing (InputAgent) ---")
        
        # Target an endpoint likely to be vulnerable (e.g., search or lookup)
        input_findings = self.input_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_SQLI, 
            parameter=TARGET_PARAM_SQLI, 
            method="GET"
        )
        self.all_findings.extend(input_findings)

        # --- PHASE 3: Rate Limiting & Denial of Service ---
        print("\n--- PHASE 3: Rate Limiting & DoS (RateAgent) ---")
        
        # Target an exposed endpoint with moderate complexity
        rate_findings = self.rate_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_RATE,
            method="GET"
        )
        self.all_findings.extend(rate_findings)

        # --- PHASE 4: Authentication & Authorization ---
        print("\n--- PHASE 4: Authentication & Authorization (AuthAgent & AccessAgent) ---")
        
        # Test a privileged endpoint
        auth_findings = self.auth_agent.run_scan(
            endpoint_url=TARGET_ENDPOINT_AUTH,
            endpoint_method="GET"
        )
        self.all_findings.extend(auth_findings)
        
        # Test BOLA/BFLA on the same privileged endpoint (assuming user 1 and user 2 exist)
        
        access_findings = self.access_agent.run_scan(
            target_resource=TARGET_ENDPOINT_RATE.replace('1', '2'), 
        )
        self.all_findings.extend(access_findings)


    def generate_report(self):
        """Generates a final summary report of all findings."""
        
        if not self.all_findings:
            print("\n--- SCAN COMPLETE ---")
            print("No security findings were reported by the agents.")
            return

        print("\n==================================================================")
        print("                   FINAL SECURITY REPORT                          ")
        print("==================================================================")
        print(f"Total Findings: {len(self.all_findings)}")
        print(f"Scan Time: {datetime.now().isoformat()}")
        print("-" * 50)
        
        # Group and summarize findings
        severity_counts = {}
        for finding in self.all_findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("Severity Breakdown:")
        for severity, count in sorted(severity_counts.items(), key=lambda item: item[0], reverse=True):
            print(f"  - {severity:<10}: {count}")
            
        print("-" * 50)
        print("Detailed Findings:")

        for i, finding in enumerate(self.all_findings):
            print(f"\n[{i+1}/{len(self.all_findings)}] {finding.get('vuln', 'Unknown Vulnerability')}")
            print(f"  Agent   : {finding.get('agent', 'N/A')}")
            print(f"  Endpoint: {finding.get('method', 'N/A')} {finding.get('endpoint', 'N/A')}")
            print(f"  Severity: {finding.get('severity', 'N/A')}")
            print(f"  Status  : {finding.get('status', 'N/A')}")
            print(f"  Recommend: {finding.get('recommendation', 'N/A')[:100]}...")


# --- EXECUTION ---
if __name__ == "__main__":
    orchestrator = APISecurityOrchestrator(TARGET_BASE_URL)
    
    try:
        orchestrator.run_full_scan()
        orchestrator.generate_report()
    except Exception as e:
        print(f"\n!!! ORCHESTRATOR CRITICAL ERROR !!!")
        print(f"An unhandled error occurred during the scan: {e}")
        print("This often indicates a configuration issue, an unreachable target API, or an error within one of the agents.")
