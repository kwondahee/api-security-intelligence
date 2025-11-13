#!/usr/bin/env python3
"""
AuthAgent - API Authentication Security Agent
Part of the API Security Intelligence Framework for Continuous API Vulnerability Assessment
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import requests
import json
import jwt
import base64
import hashlib
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from urllib.parse import urljoin
from telemetry.logger import emit_agent_decision

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Severity(Enum):
    """Security finding severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SecurityFinding:
    """Represents a security vulnerability finding"""
    vulnerability_type: str
    severity: Severity
    endpoint: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class APIEndpoint:
    """Represents an API endpoint to be tested"""
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None

class AuthAgent:
    """
    Authentication Security Agent for API vulnerability assessment
    """
    
    def __init__(self, target_base_url: str, name: str = "AuthAgent", timeout: int = 30):
        self.name = name
        self.base_url = target_base_url.rstrip('/')
        self.timeout = timeout
        self.findings: List[SecurityFinding] = []
        self.session = requests.Session()
        
        self.common_auth_headers = [
            'Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Access-Token',
            'Bearer', 'Cookie', 'X-Requested-With', 'X-CSRF-Token'
        ]
        self.weak_passwords = [
            'password', '123456', 'admin', 'password123', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'password1'
        ]
        self.weak_jwt_secrets = [
            'secret', 'password', 'key', 'admin', '123456', 'test'
        ]
        
        logger.info(f"AuthAgent initialized for target: {self.base_url}")

    # --- ORCHESTRATOR INTEGRATION ---
    def run_scan(self, endpoint_url: str, endpoint_method: str):
        """
        Wrapper method called by the orchestrator.
        """
        logger.info(f"AuthAgent running scan on: {endpoint_method} {endpoint_url}")
        
        endpoint = APIEndpoint(
            url=f"{self.base_url}{endpoint_url}", 
            method=endpoint_method,
            headers={"Authorization": "Bearer MOCK_TOKEN_FOR_TESTS", "Content-Type": "application/json"},
            body={} 
        )
        
        initial_findings = self.analyze_endpoint(endpoint)

        self.findings = [
            {
                "agent": self.name,
                "endpoint": endpoint_url, 
                "method": endpoint_method, 
                "status": "VULNERABLE",    
                "vuln": finding.vulnerability_type, 
                "severity": finding.severity.name,
                "description": finding.description,
                "recommendation": finding.remediation 
            }
            for finding in initial_findings
        ]
        
        print(f"[AUTH AGENT] Finished scan on {endpoint_url}. Found {len(self.findings)} potential issues.")
        return self.findings
    
    # --- NEW ORCHESTRATOR ENTRY POINT ---
    def analyze(self, api_payload: Dict[str, Any], trace_id: Optional[str]) -> List[Dict[str, Any]]:
        """
        Unified entry point for orchestrator-triggered analysis.
        Wraps run_scan() and emits telemetry events.
        """
        endpoint_url = api_payload.get("endpoint_url") or api_payload.get("endpoint") or "/"
        endpoint_method = api_payload.get("method", "GET").upper()
        logger.info(f"[{self.name}] Starting authentication analysis for {endpoint_url} (trace_id={trace_id})")

        try:
            findings = self.run_scan(endpoint_url, endpoint_method)
            if findings:
                for finding in findings:
                    emit_agent_decision(
                        trace_id=trace_id,
                        endpoint=finding.get("endpoint"),
                        agent=self.name,
                        rule=finding.get("vuln"),
                        status=finding.get("status"),
                        extra={
                            "severity": finding.get("severity"),
                            "recommendation": finding.get("recommendation")
                        }
                    )
            else:
                emit_agent_decision(
                    trace_id=trace_id,
                    endpoint=endpoint_url,
                    agent=self.name,
                    rule="AuthenticationChecks",
                    status="SECURE",
                    extra={"message": "No authentication vulnerabilities found."}
                )

            return findings

        except Exception as e:
            logger.error(f"[{self.name}] analyze() failed: {e}", exc_info=True)
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=endpoint_url,
                agent=self.name,
                rule="AgentError",
                status="ERROR",
                extra={"exception": str(e)}
            )
            return []

    # --- MAIN ANALYSIS METHOD ---
    def analyze_endpoint(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        findings = []
        try:
            findings.extend(self._test_missing_authentication(endpoint))
            findings.extend(self._test_auth_bypass(endpoint)) 
            findings.extend(self._test_weak_auth_mechanisms(endpoint)) 
            findings.extend(self._test_jwt_vulnerabilities(endpoint))
        except Exception as e:
            logger.error(f"Error analyzing endpoint {endpoint.url}: {str(e)}")
            findings.append(SecurityFinding(
                vulnerability_type="ANALYSIS_ERROR",
                severity=Severity.LOW,
                endpoint=endpoint.url,
                description=f"Failed to complete authentication analysis: {str(e)}",
                evidence={"error": str(e)},
                remediation="Check endpoint accessibility and agent code"
            ))
        return findings

    # --- FUNCTIONAL VULNERABILITY CHECKS ---
    def _is_sensitive_endpoint(self, url: str) -> bool:
        path = url.replace(self.base_url, '').lower()
        if any(keyword in path for keyword in ['/admin', '/profile', '/users/', '/config', '/secret']):
            return True
        return False

    def _is_login_endpoint(self, url):
        return any(keyword in url.lower() for keyword in ['/login', '/auth', '/token'])
        
    def _test_missing_authentication(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        findings = []
        logger.info(f"Testing missing authentication on {endpoint.url}")
        if not self._is_sensitive_endpoint(endpoint.url):
            return findings
            
        try:
            unauth_headers = {k: v for k, v in endpoint.headers.items() if k.lower() != 'authorization'}
            response = self.session.request(
                method=endpoint.method, 
                url=endpoint.url, 
                headers=unauth_headers, 
                json=endpoint.body if endpoint.method in ["POST", "PUT", "PATCH"] else None,
                timeout=self.timeout
            )
            if response.status_code in [200, 201]:
                findings.append(SecurityFinding(
                    vulnerability_type="BROKEN_AUTHENTICATION_MISSING",
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.url,
                    description=f"Sensitive endpoint accessible without authentication. Status code: {response.status_code}",
                    evidence={"status_code": response.status_code, "response_sample": response.text[:250]},
                    remediation="Implement mandatory authentication for this endpoint."
                ))
                self._log(endpoint.url, "Missing-Auth", "VULNERABLE",
                         {"status": response.status_code})
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during missing auth test on {endpoint.url}: {e}")
        return findings

    def _test_auth_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        findings = []
        bypass_headers = [
            {"X-Custom-Auth": "admin"},
            {"X-Original-URL": "/admin/users"},
            {"X-Forwarded-For": "127.0.0.1"},
        ]
        for header_set in bypass_headers:
            headers = endpoint.headers.copy()
            used_header = next(iter(header_set))
            headers = {k: v for k, v in headers.items() if k.lower() != 'authorization'}
            headers.update(header_set)
            try:
                response = self.session.request(
                    method=endpoint.method, url=endpoint.url, headers=headers, timeout=self.timeout
                )
                if response.status_code == 200:
                    findings.append(SecurityFinding(
                        vulnerability_type="BROKEN_AUTHENTICATION_BYPASS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Authentication bypassed using header manipulation: {list(header_set.keys())[0]} resulted in 200 OK.",
                        evidence={"status_code": response.status_code, "request_headers": header_set},
                        remediation="Ensure all authentication checks occur before proxy header handling."
                    ))
                    self._log(endpoint.url, "Auth-Bypass", "VULNERABLE",
                             {"header": used_header, "status": response.status_code})
            except requests.exceptions.RequestException:
                pass
        return findings

    def _test_weak_auth_mechanisms(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        findings = []
        if not self._is_login_endpoint(endpoint.url) or endpoint.method != "POST":
            return []
        for weak_pass in self.weak_passwords:
            login_body = {"username": "admin", "password": weak_pass}
            try:
                response = self.session.post(url=endpoint.url, json=login_body, timeout=self.timeout)
                if response.status_code == 200 and ('token' in response.text or 'session' in response.text.lower()):
                    findings.append(SecurityFinding(
                        vulnerability_type="WEAK_DEFAULT_CREDENTIALS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Default admin credentials ('admin'/'{weak_pass}') successfully used to log in.",
                        evidence={"status_code": 200, "credentials": login_body},
                        remediation="Ensure default credentials are changed upon first use."
                    ))
                    break
            except requests.exceptions.RequestException:
                continue
        return findings

    def _test_jwt_vulnerabilities(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        findings = []
        auth_header = endpoint.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return []
        original_token = auth_header.split(' ')[1]
        try:
            header_b64, payload_b64, signature_b64 = original_token.split('.')
        except ValueError:
            return []

        # Alg=None test
        try:
            header_none = base64.urlsafe_b64encode(json.dumps({'typ': 'JWT', 'alg': 'none'}).encode()).rstrip(b'=').decode()
            token_none = f"{header_none}.{payload_b64}."
            headers_none = endpoint.headers.copy()
            headers_none['Authorization'] = f'Bearer {token_none}'
            response = self.session.request(
                method=endpoint.method, url=endpoint.url, headers=headers_none, timeout=self.timeout
            )
            if response.status_code == 200:
                findings.append(SecurityFinding(
                    vulnerability_type="JWT_ALGORITHM_NONE",
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.url,
                    description="The API accepts tokens signed with 'alg=none'.",
                    evidence={"status_code": 200, "token_used": token_none},
                    remediation="Restrict JWT algorithms and enforce signature validation."
                ))
                self._log(endpoint.url, "JWT-Weakness", "VULNERABLE", {"variant": "alg-none"})
        except Exception:
            pass

        # Weak secret brute-force
        for secret in self.weak_jwt_secrets:
            try:
                jwt.decode(original_token, secret, algorithms=["HS256", "HS384", "HS512"])
                findings.append(SecurityFinding(
                    vulnerability_type="JWT_WEAK_SECRET",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=f"JWT Secret is weak: '{secret}'.",
                    evidence={"weak_secret": secret},
                    remediation="Use a strong, long secret for JWT signing."
                ))
                self._log(endpoint.url, "JWT-Weakness", "VULNERABLE", {"variant": "weak-secret"})
                break
            except jwt.exceptions.InvalidSignatureError:
                continue
            except Exception:
                pass
        return findings

    def generate_report(self):
        return {}

    def _generate_recommendations(self):
        return []
    
    def _log(self, endpoint_url: str, vuln_type: str, status: str, extra: dict | None = None):
        from urllib.parse import urlparse
        path = urlparse(endpoint_url).path if endpoint_url else endpoint_url
        emit_agent_decision(
            trace_id=None,
            endpoint=path or endpoint_url,
            agent=self.name,
            rule=vuln_type,
            status=status,
            extra=extra
        )


# --- EXECUTION BLOCK FOR STANDALONE TESTING ---
if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    TEST_ENDPOINT_URL = "/admin/users"
    TEST_METHOD = "GET"
    
    print("=====================================================")
    print(f"🔑 Running AuthAgent Standalone Scan on: {TEST_ENDPOINT_URL}")
    print("=====================================================")
    
    agent = AuthAgent(target_base_url=TEST_TARGET_BASE_URL)
    
    try:
        findings = agent.run_scan(
            endpoint_url=TEST_ENDPOINT_URL, 
            endpoint_method=TEST_METHOD
        )
        print("\n--- AuthAgent Scan Complete ---")
        if findings:
            print(f"Found {len(findings)} Security Findings:")
            for finding in findings:
                print(f"  [{finding.get('severity', 'N/A')}] {finding.get('vuln', 'N/A')} on {finding.get('endpoint', 'N/A')}")
        else:
            print("No security findings reported.")
    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"AuthAgent failed during execution: {e}")
