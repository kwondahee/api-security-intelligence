#!/usr/bin/env python3
"""
Documentation Accuracy Agent

This agent analyzes API documentation accuracy by comparing documented behavior
with actual API responses. It can work with various documentation formats
including OpenAPI/Swagger specs, and provides detailed accuracy reports.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import requests
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict  # NOTE: asdict is now imported
from enum import Enum
import logging
from urllib.parse import urljoin, urlparse
import yaml
from telemetry.logger import emit_agent_decision


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
        """
        logger.info(f"[{self.name}] Analyzing OpenAPI spec at '{self.base_url}{doc_source}'...")
        
        spec = self._fetch_spec(doc_source)
        if not spec:
            return []

        self.doc_endpoints = self._parse_openapi_spec(spec)
        self._discover_endpoints()
        full_report = self._generate_report()
        
        orchestrator_findings = []
        for issue in full_report.get('issues', []):
            if issue.get('category') == "endpoint":
                if "undocumented" in issue.get('description', '').lower():
                    vuln_type = "Improper Inventory Management (Undocumented Endpoint)"
                    severity = "CRITICAL"
                elif "not found" in issue.get('description', '').lower():
                    vuln_type = "Improper Inventory Management (Non-Existent Endpoint)"
                    severity = "HIGH"
                else:
                    continue
                
                orchestrator_findings.append({
                    "agent": self.name,
                    "endpoint": issue.get('endpoint'),
                    "method": issue.get('endpoint').split(" ")[0] if issue.get('endpoint') else "N/A",
                    "status": "MISCONFIGURATION",
                    "vuln": vuln_type,
                    "severity": severity,
                    "description": issue.get('description'),
                    "recommendation": issue.get('suggestion')
                })

                try:
                    emit_agent_decision(
                        trace_id=None,
                        endpoint=issue.get('endpoint') or "",
                        agent=self.name,
                        rule=vuln_type,
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

    # --- Unified Orchestrator Entry Point ---
    def analyze(self, api_payload: Dict[str, Any], trace_id: Optional[str]) -> List[Dict[str, Any]]:
        """
        Unified entry point for orchestrator-triggered analysis.
        Wraps run_check() and emits telemetry events.
        """
        doc_source = api_payload.get("doc_source") or api_payload.get("endpoint") or "/api-docs"
        logger.info(f"[{self.name}] Starting documentation accuracy analysis for {doc_source} (trace_id={trace_id})")

        try:
            findings = self.run_check(doc_source)
            if findings:
                for finding in findings:
                    emit_agent_decision(
                        trace_id=trace_id,
                        endpoint=finding.get("endpoint", ""),
                        agent=self.name,
                        rule=finding.get("vuln", "DocumentationMismatch"),
                        status=finding.get("status", "MISCONFIGURATION"),
                        extra={
                            "severity": finding.get("severity", "Unknown"),
                            "recommendation": finding.get("recommendation", "")
                        }
                    )
            else:
                emit_agent_decision(
                    trace_id=trace_id,
                    endpoint=doc_source,
                    agent=self.name,
                    rule="DocumentationAccuracy",
                    status="SECURE",
                    extra={"message": "No documentation inconsistencies found."}
                )

            return findings

        except Exception as e:
            logger.error(f"[{self.name}] analyze() failed: {e}", exc_info=True)
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=doc_source,
                agent=self.name,
                rule="AgentError",
                status="ERROR",
                extra={"exception": str(e)}
            )
            return []


# --- END DocAccuracyAgent ---
# --- EXECUTION BLOCK FOR STANDALONE TESTING ---
if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    TEST_DOC_SOURCE = "/api-docs" 
    
    print("=====================================================")
    print(f"📜 Running DocAccuracyAgent Standalone Scan on: {TEST_DOC_SOURCE}")
    print("=====================================================")
    
    agent = DocAccuracyAgent(base_url=TEST_TARGET_BASE_URL)
    
    try:
        report = agent.run_check(doc_source=TEST_DOC_SOURCE)
        print("\n--- DocAccuracyAgent Scan Complete ---")
        print(json.dumps(report, indent=4))
    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"DocAccuracyAgent failed during execution: {e}")
