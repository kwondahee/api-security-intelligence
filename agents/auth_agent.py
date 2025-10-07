#!/usr/bin/env python3
"""
AuthAgent - API Authentication Security Agent
Part of the API Security Intelligence Framework for Continuous API Vulnerability Assessment
"""

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
        
        # 1. Prepare the endpoint object (Using a mock token for base requests)
        endpoint = APIEndpoint(
            url=f"{self.base_url}{endpoint_url}", 
            method=endpoint_method,
            headers={"Authorization": "Bearer MOCK_TOKEN_FOR_TESTS", "Content-Type": "application/json"},
            body={} 
        )
        
        # 2. Call the original comprehensive analysis method
        initial_findings = self.analyze_endpoint(endpoint)

        # 3. Transform dataclass findings into the orchestrator's expected dictionary format
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
    
    # --- MAIN ANALYSIS METHOD ---
    def analyze_endpoint(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Main analysis method for an API endpoint
        """
        findings = []
        
        try:
            # Test 1: Check for missing authentication (Functional)
            findings.extend(self._test_missing_authentication(endpoint))
            
            # Test 2: Authentication bypass testing (Functional)
            findings.extend(self._test_auth_bypass(endpoint)) 

            # Test 3 & 4: Weak authentication and JWT testing (Functional)
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
        """Heuristically determines if an endpoint is sensitive."""
        path = url.replace(self.base_url, '').lower()
        if any(keyword in path for keyword in ['/admin', '/profile', '/users/', '/config', '/secret']):
            return True
        return False

    def _is_login_endpoint(self, url):
        """Checks if the endpoint is likely a login or token issuance endpoint."""
        return any(keyword in url.lower() for keyword in ['/login', '/auth', '/token'])
        
    def _test_missing_authentication(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Tests if the endpoint is accessible without any authentication headers.
        """
        findings = []
        logger.info(f"Testing missing authentication on {endpoint.url}")
        
        if not self._is_sensitive_endpoint(endpoint.url):
            return findings
            
        try:
            # Strip the Authorization header to make an unauthenticated request
            unauth_headers = {k: v for k, v in endpoint.headers.items() if k.lower() != 'authorization'}
            
            response = self.session.request(
                method=endpoint.method, 
                url=endpoint.url, 
                headers=unauth_headers, 
                json=endpoint.body if endpoint.method in ["POST", "PUT", "PATCH"] else None,
                timeout=self.timeout
            )
            
            # If a sensitive endpoint returns a successful status code (200, 201), it's a critical vulnerability
            if response.status_code in [200, 201]:
                findings.append(SecurityFinding(
                    vulnerability_type="BROKEN_AUTHENTICATION_MISSING",
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.url,
                    description=f"Sensitive endpoint accessible without authentication. Status code: {response.status_code}",
                    evidence={"status_code": response.status_code, "response_sample": response.text[:250]},
                    remediation="Implement mandatory authentication for this endpoint. Expected response: 401 Unauthorized or 403 Forbidden."
                ))
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error during missing auth test on {endpoint.url}: {e}")
        
        return findings

    def _test_auth_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Tests for authentication bypass using common proxy headers.
        """
        findings = []
        bypass_headers = [
            {"X-Custom-Auth": "admin"},
            {"X-Original-URL": "/admin/users"},
            {"X-Forwarded-For": "127.0.0.1"}, # Attempt to appear as localhost/internal
        ]

        for header_set in bypass_headers:
            headers = endpoint.headers.copy()
            # Remove existing Authorization to test if these headers grant access directly
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
                        remediation="Ensure all authentication and authorization checks occur before processing proxy/bypass headers."
                    ))
            except requests.exceptions.RequestException:
                pass
        
        return findings

    def _test_weak_auth_mechanisms(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Tests for weak passwords/credentials using common pairs on login endpoints.
        """
        findings = []
        if not self._is_login_endpoint(endpoint.url) or endpoint.method != "POST":
            return []

        # Assuming VAmPI uses a standard JSON body for login (username/password)
        # This test checks if any of the weak passwords are used for the 'admin' user.
        for weak_pass in self.weak_passwords:
            login_body = {"username": "admin", "password": weak_pass}
            
            try:
                response = self.session.post(
                    url=endpoint.url, 
                    json=login_body, 
                    timeout=self.timeout
                )
                
                # Check for successful login (usually 200 OK and a token/session ID in the response)
                if response.status_code == 200 and ('token' in response.text or 'session' in response.text.lower()):
                    findings.append(SecurityFinding(
                        vulnerability_type="WEAK_DEFAULT_CREDENTIALS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Default admin credentials ('admin'/'{weak_pass}') successfully used to log in.",
                        evidence={"status_code": 200, "credentials": login_body},
                        remediation="Ensure default credentials are changed or disallowed upon first use."
                    ))
                    # Stop after the first success
                    break
            except requests.exceptions.RequestException:
                continue

        return findings

    def _test_jwt_vulnerabilities(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Tests for JWT flaws like alg=None and weak secrets.
        """
        findings = []
        auth_header = endpoint.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return []
            
        original_token = auth_header.split(' ')[1]
        
        try:
            header_b64, payload_b64, signature_b64 = original_token.split('.')
        except ValueError:
            # Not a standard JWT format
            return []

        # --- Test 1: Alg=None Vulnerability ---
        try:
            header_none = base64.urlsafe_b64encode(json.dumps({'typ': 'JWT', 'alg': 'none'}).encode()).rstrip(b'=').decode()
            token_none = f"{header_none}.{payload_b64}." # Token with 'alg: none' and blank signature
            
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
                    description="The API accepts tokens signed with 'alg=none', allowing arbitrary authentication bypass.",
                    evidence={"status_code": 200, "token_used": token_none},
                    remediation="Validate JWT signature and ensure 'alg' is restricted to a set of secure algorithms."
                ))
        except Exception:
            pass
            
        # --- Test 2: Weak Secret Brute-Force ---
        # Note: Requires the jwt library to decode/encode.
        token_data = f"{header_b64}.{payload_b64}"
        for secret in self.weak_jwt_secrets:
            try:
                # Attempt to verify the token with the weak secret
                jwt.decode(original_token, secret, algorithms=["HS256", "HS384", "HS512"])

                findings.append(SecurityFinding(
                    vulnerability_type="JWT_WEAK_SECRET",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=f"JWT Secret is a known weak key: '{secret}'.",
                    evidence={"weak_secret": secret, "token_payload": json.loads(base64.urlsafe_b64decode(payload_b64 + '==').decode())},
                    remediation="Use a strong, long, and complex secret key (>32 characters) for signing JWTs."
                ))
                break # Stop after first success
            except jwt.exceptions.InvalidSignatureError:
                continue
            except Exception:
                # Other JWT errors (e.g., token expired, invalid format)
                pass
            
        return findings

    # --- REQUIRED HELPER/UTILITY METHODS TO COMPLETE THE CLASS ---
    
    def generate_report(self):
        """Generates a summary report of all findings."""
        return {}

    def _generate_recommendations(self):
        """Generates high-level security recommendations."""
        return []