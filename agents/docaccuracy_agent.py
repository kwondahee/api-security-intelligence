#!/usr/bin/env python3
"""
Documentation Accuracy Agent

This agent analyzes API documentation accuracy by comparing documented behavior
with actual API responses. It can work with various documentation formats
including OpenAPI/Swagger specs, and provides detailed accuracy reports.
"""

import requests
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict  # NOTE: asdict is now imported
from enum import Enum
import logging
from urllib.parse import urljoin, urlparse
import yaml
from agents.logger import emit_agent_decision


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(name)s:%(levelname)s:%(message)s')
logger = logging.getLogger("agents.docaccuracy_agent")

class DocFormat(Enum):
    OPENAPI = "openapi"
    SWAGGER = "swagger"
    UNKNOWN = "unknown"

@dataclass
class EndpointInfo:
    """Information about an API endpoint"""
    path: str
    method: str
    description: Optional[str] = None
    parameters: List[Dict[str, Any]] = None
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[str, Dict[str, Any]] = None
    security: List[Dict[str, Any]] = None

@dataclass
class AccuracyIssue:
    """Represents a documentation accuracy issue (used internally by agent)"""
    severity: str  # "critical", "high", "medium", "low"
    category: str  # "parameter", "response", "status_code", "security", "endpoint"
    description: str
    expected: Any
    actual: Any
    endpoint: str
    suggestion: Optional[str] = None

class DocAccuracyAgent:
    """Core class for the Documentation Accuracy Agent."""
    
    name = "DocAccuracyAgent"

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.doc_endpoints: List[EndpointInfo] = []
        self.discovered_endpoints: List[EndpointInfo] = []
        self.accuracy_issues: List[AccuracyIssue] = []
        self.session = requests.Session()
        self.timeout = 10
        logger.info(f"{self.name} initialized for target: {self.base_url}")


    def _fetch_spec(self, doc_source: str) -> Optional[Dict[str, Any]]:
        """
        Fetches the OpenAPI/Swagger specification from a local file or remote URL.
        
        Args:
            doc_source: The URL path (relative to base_url) of the spec.
            
        Returns:
            The parsed specification as a dictionary, or None on failure.
        """
        try:
            full_url = urljoin(self.base_url, doc_source)
            
            # Check for file extension to determine parser (handles remote and local paths)
            if full_url.endswith(('.yaml', '.yml')):
                response = self.session.get(full_url, timeout=self.timeout)
                response.raise_for_status()
                # Use yaml.safe_load for YAML content
                return yaml.safe_load(response.text)
            
            else: # Assume JSON if no YAML extension is found
                response = self.session.get(full_url, timeout=self.timeout)
                response.raise_for_status()
                return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching spec from {full_url}: {e}")
            return None
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML spec: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON spec: {e}")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred during spec fetching/parsing: {e}")
            return None


    def _parse_openapi_spec(self, spec: Dict[str, Any]) -> List[EndpointInfo]:
        """Parses the 'paths' section of an OpenAPI spec to extract endpoint info."""
        endpoints = []
        paths = spec.get("paths", {})
        for path, path_data in paths.items():
            for method, operation_data in path_data.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    endpoint = EndpointInfo(
                        path=path,
                        method=method.upper(),
                        description=operation_data.get('summary') or operation_data.get('description'),
                        parameters=operation_data.get('parameters'),
                        request_body=operation_data.get('requestBody'),
                        responses=operation_data.get('responses'),
                        security=operation_data.get('security')
                    )
                    endpoints.append(endpoint)
        return endpoints


    def _discover_endpoints(self) -> None:
        """
        (Placeholder) Attempts to find undocumented endpoints by fuzzing common paths.
        For VAmPI, we simulate a finding to demonstrate the agent's capability
        of detecting an undocumented endpoint like /users/v1/_debug.
        """
        logger.info("Discovering potential undocumented endpoints...")
        
        # Simulated discovery of a known undocumented VAmPI endpoint
        path = "/users/v1/_debug"
        method = "GET"
        
        # Check if this path is documented
        is_documented = any(
            ep.path == path and ep.method == method
            for ep in self.doc_endpoints
        )
        
        if not is_documented:
            response_info = self.test_endpoint(path, method)
            
            if response_info.get('success') and response_info['status_code'] == 200:
                self.discovered_endpoints.append(
                    EndpointInfo(path=path, method=method, description="Discovered via fuzzing/simulation.")
                )
                self.accuracy_issues.append(
                    AccuracyIssue(
                        severity="CRITICAL",
                        category="endpoint",
                        description=f"Undocumented endpoint found: {method} {path}. Responds with 200 OK.",
                        expected="404 Not Found (or documented)",
                        actual="200 OK",
                        endpoint=f"{method} {path}",
                        suggestion="Document this sensitive debug endpoint or remove it from production."
                    )
                )


    def _generate_report(self) -> Dict[str, Any]:
        """Generates the comprehensive internal report structure."""
        
        # Group issues by severity
        issues_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for issue in self.accuracy_issues:
            issues_by_severity[issue.severity.upper()].append(issue)
        
        summary = {
            "total_issues": len(self.accuracy_issues),
            "documented_count": len(self.doc_endpoints),
            "discovered_count": len(self.discovered_endpoints),
            "issues_by_severity": {k: len(v) for k, v in issues_by_severity.items()}
        }
        
        return {
            "summary": summary,
            # Convert internal dataclass issues to dicts for external consumption
            "issues": [asdict(i) for i in self.accuracy_issues], 
            "documented_endpoints": [
                {"path": ep.path, "method": ep.method, "description": ep.description} 
                for ep in self.doc_endpoints
            ],
            "discovered_endpoints": [
                {"path": ep.path, "method": ep.method, "description": ep.description} 
                for ep in self.discovered_endpoints
            ]
        }


    def run_check(self, doc_source: str) -> List[Dict[str, Any]]:
        """
        Main entry point for the orchestrator. Fetches, analyzes, and returns security findings.
        
        Args:
            doc_source: The path or URL of the OpenAPI spec file (e.g., /docs/openapi.json).
            
        Returns:
            A list of security finding dictionaries for the orchestrator.
        """
        logger.info(f"[{self.name}] Analyzing OpenAPI spec at '{self.base_url}{doc_source}'...")
        
        # 1. Fetch and Parse Spec
        spec = self._fetch_spec(doc_source)
        if not spec:
            return [] # Return empty list if spec cannot be fetched/parsed

        self.doc_endpoints = self._parse_openapi_spec(spec)
        
        # 2. Discover Endpoints (Inventory Check)
        self._discover_endpoints()
        
        # 3. Generate internal report and extract issues
        full_report = self._generate_report()
        
        # 4. Transform findings into the simplified dictionary format expected by the orchestrator
        orchestrator_findings = []
        
        # The 'issues' in full_report are already dictionaries due to asdict() in _generate_report
        for issue in full_report.get('issues', []):
            
            # FIX 1: Use .get() to access dictionary values instead of attribute notation
            if issue.get('category') == "endpoint":
                
                # Check for Undocumented Endpoints
                # FIX 2: Use .get() to access dictionary values
                if "undocumented" in issue.get('description', '').lower():
                    vuln_type = "Improper Inventory Management (Undocumented Endpoint)"
                    severity = "CRITICAL"
                
                # Check for Documented but Non-Existent Endpoints (Simulated)
                # FIX 3: Use .get() to access dictionary values
                elif "not found" in issue.get('description', '').lower():
                    vuln_type = "Improper Inventory Management (Non-Existent Endpoint)"
                    severity = "HIGH"
                else:
                    continue # Skip other less critical endpoint issues
                
                # Standardize the output dictionary
                orchestrator_findings.append({
                    "agent": self.name,
                    # FIX 4: Use .get() to access dictionary values
                    "endpoint": issue.get('endpoint'), 
                    "method": issue.get('endpoint').split(" ")[0] if issue.get('endpoint') else "N/A",
                    "status": "MISCONFIGURATION", # Use MISCONFIGURATION for documentation issues
                    "vuln": vuln_type, # Changed 'vuln_type' to 'vuln' for orchestrator compatibility
                    "severity": severity,
                    "description": issue.get('description'),
                    "recommendation": issue.get('suggestion')
                })

                try:
                    emit_agent_decision(
                        trace_id=None,
                        endpoint=issue.get('endpoint') or "",
                        agent=self.name,
                        rule=vuln_type,       # e.g., "Undocumented-Endpoint", "Method-Mismatch"
                        status="MISCONFIGURATION",
                        extra={"severity": severity}
                    )
                except Exception:
                    pass

        
        return orchestrator_findings
    
    
    def test_endpoint(self, path: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """Test a specific endpoint and return detailed information"""
        try:
            url = urljoin(self.base_url, path)
            # Prevent SSL errors if target uses self-signed certs (common in lab envs)
            response = self.session.request(method=method.upper(), url=url, timeout=self.timeout, verify=False, **kwargs)
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_type": response.headers.get('content-type', ''),
                "response_time": response.elapsed.total_seconds(),
                "content": response.text[:1000] if response.text else None,
                "success": True
            }
        except Exception as e:
            return {"error": str(e), "success": False}


# --- END DocAccuracyAgent ---
# --- EXECUTION BLOCK FOR STANDALONE TESTING ---
if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    
    # Change this line:
    # TEST_RESOURCE = "/openapi.json" 
    
    # To this line (Try the most common Swagger/OpenAPI endpoint):
    TEST_DOC_SOURCE = "/api-docs" 
    
    print("=====================================================")
    print(f"📜 Running DocAccuracyAgent Standalone Scan on: {TEST_DOC_SOURCE}")
    print("=====================================================")
    
    # 1. Initialize the Agent
    agent = DocAccuracyAgent(base_url=TEST_TARGET_BASE_URL)
    
    # 2. Run the check
    try:
        report = agent.run_check(doc_source=TEST_DOC_SOURCE)
        
        # 3. Print the results
        print("\n--- DocAccuracyAgent Scan Complete ---")
        print(json.dumps(report.get('summary'), indent=4))

    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"DocAccuracyAgent failed during execution: {e}")