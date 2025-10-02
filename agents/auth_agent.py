#!/usr/bin/env python3
"""
AuthAgent - API Authentication Security Agent
Part of the API Security Intelligence Framework for Continuous API Vulnerability Assessment

This agent specializes in authentication security analysis for APIs, detecting:
- Weak authentication mechanisms
- Missing authentication on sensitive endpoints
- JWT vulnerabilities
- Session management issues
- API key security problems
- OAuth implementation flaws
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
from dataclasses import dataclass, field
from enum import Enum
import logging

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
    
    def __init__(self, target_base_url: str, timeout: int = 30):
        self.base_url = target_base_url.rstrip('/')
        self.timeout = timeout
        self.findings: List[SecurityFinding] = []
        self.session = requests.Session()
        self.common_auth_headers = [
            'Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Access-Token',
            'Bearer', 'Cookie', 'X-Requested-With', 'X-CSRF-Token'
        ]
        
        # Common weak passwords for brute force testing
        self.weak_passwords = [
            'password', '123456', 'admin', 'password123', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'password1'
        ]
        
        logger.info(f"AuthAgent initialized for target: {self.base_url}")

    def analyze_endpoint(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Main analysis method for an API endpoint
        """
        findings = []
        
        try:
            # Test 1: Check for missing authentication
            findings.extend(self._test_missing_authentication(endpoint))
            
            # Test 2: Test weak authentication mechanisms
            findings.extend(self._test_weak_auth_mechanisms(endpoint))
            
            # Test 3: JWT vulnerability testing
            findings.extend(self._test_jwt_vulnerabilities(endpoint))
            
            # Test 4: Session management testing
            findings.extend(self._test_session_management(endpoint))
            
            # Test 5: API key security testing
            findings.extend(self._test_api_key_security(endpoint))
            
            # Test 6: Authentication bypass testing
            findings.extend(self._test_auth_bypass(endpoint))
            
            # Test 7: Brute force protection testing
            findings.extend(self._test_brute_force_protection(endpoint))
            
        except Exception as e:
            logger.error(f"Error analyzing endpoint {endpoint.url}: {str(e)}")
            findings.append(SecurityFinding(
                vulnerability_type="ANALYSIS_ERROR",
                severity=Severity.LOW,
                endpoint=endpoint.url,
                description=f"Failed to complete analysis: {str(e)}",
                evidence={"error": str(e)},
                remediation="Check endpoint accessibility and network connectivity"
            ))
        
        self.findings.extend(findings)
        return findings

    def _test_missing_authentication(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for endpoints that should require authentication but don't"""
        findings = []
        
        try:
            # Make request without any authentication
            response = self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.parameters,
                json=endpoint.body,
                timeout=self.timeout
            )
            
            # Check if sensitive endpoint allows access without authentication
            if self._is_sensitive_endpoint(endpoint.url) and response.status_code == 200:
                findings.append(SecurityFinding(
                    vulnerability_type="MISSING_AUTHENTICATION",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description="Sensitive endpoint accessible without authentication",
                    evidence={
                        "status_code": response.status_code,
                        "response_headers": dict(response.headers),
                        "endpoint_pattern": self._get_endpoint_pattern(endpoint.url)
                    },
                    remediation="Implement proper authentication mechanism for this endpoint"
                ))
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for missing auth test: {str(e)}")
        
        return findings

    def _test_weak_auth_mechanisms(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for weak authentication mechanisms"""
        findings = []
        
        # Test basic auth with common credentials
        weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        for username, password in weak_credentials:
            try:
                auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = endpoint.headers.copy()
                headers['Authorization'] = f'Basic {auth_header}'
                
                response = self.session.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    headers=headers,
                    params=endpoint.parameters,
                    json=endpoint.body,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    findings.append(SecurityFinding(
                        vulnerability_type="WEAK_CREDENTIALS",
                        severity=Severity.CRITICAL,
                        endpoint=endpoint.url,
                        description=f"Endpoint accepts weak credentials: {username}/{password}",
                        evidence={
                            "username": username,
                            "password": password,
                            "status_code": response.status_code
                        },
                        remediation="Enforce strong password policies and disable default credentials"
                    ))
                    break  # Stop after first successful weak auth
                    
            except requests.exceptions.RequestException:
                continue
        
        return findings

    def _test_jwt_vulnerabilities(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for JWT-related vulnerabilities"""
        findings = []
        
        # Look for JWT tokens in authorization headers
        auth_header = endpoint.headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            token = auth_header.replace('Bearer ', '').strip()
            if self._is_jwt_token(token):
                findings.extend(self._analyze_jwt_token(token, endpoint))
        
        # Test for JWT algorithm confusion attacks
        findings.extend(self._test_jwt_algorithm_confusion(endpoint))
        
        # Test for JWT none algorithm attack
        findings.extend(self._test_jwt_none_algorithm(endpoint))
        
        return findings

    def _analyze_jwt_token(self, token: str, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Analyze JWT token for vulnerabilities"""
        findings = []
        
        try:
            # Decode without verification to analyze structure
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Check for weak signing algorithm
            algorithm = header.get('alg', '').upper()
            if algorithm in ['HS256', 'HS384', 'HS512']:
                findings.append(SecurityFinding(
                    vulnerability_type="WEAK_JWT_ALGORITHM",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=f"JWT uses symmetric algorithm {algorithm} which may be vulnerable to key attacks",
                    evidence={"algorithm": algorithm, "header": header},
                    remediation="Consider using asymmetric algorithms like RS256 for better security"
                ))
            
            # Check for missing expiration
            if 'exp' not in payload:
                findings.append(SecurityFinding(
                    vulnerability_type="JWT_NO_EXPIRATION",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description="JWT token does not have expiration claim",
                    evidence={"payload_keys": list(payload.keys())},
                    remediation="Add expiration claim (exp) to JWT tokens"
                ))
            
            # Check for long expiration times
            elif 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                time_diff = exp_time - datetime.now()
                if time_diff.days > 30:
                    findings.append(SecurityFinding(
                        vulnerability_type="JWT_LONG_EXPIRATION",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"JWT token has long expiration time: {time_diff.days} days",
                        evidence={"expiration_days": time_diff.days},
                        remediation="Use shorter expiration times for JWT tokens"
                    ))
            
            # Check for sensitive information in JWT
            sensitive_keys = ['password', 'secret', 'key', 'token', 'ssn', 'credit_card']
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    findings.append(SecurityFinding(
                        vulnerability_type="JWT_SENSITIVE_DATA",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"JWT payload contains potentially sensitive field: {key}",
                        evidence={"sensitive_field": key},
                        remediation="Avoid storing sensitive information in JWT payload"
                    ))
            
        except jwt.DecodeError:
            findings.append(SecurityFinding(
                vulnerability_type="INVALID_JWT",
                severity=Severity.LOW,
                endpoint=endpoint.url,
                description="Invalid JWT token format detected",
                evidence={"token_prefix": token[:20] + "..."},
                remediation="Ensure JWT tokens are properly formatted"
            ))
        
        return findings

    def _test_jwt_algorithm_confusion(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for JWT algorithm confusion attacks"""
        findings = []
        
        # Create a malicious JWT with algorithm set to 'none'
        malicious_payload = {
            "sub": "1234567890",
            "name": "Test User",
            "admin": True,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        
        # Create JWT with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        encoded_payload = base64.urlsafe_b64encode(json.dumps(malicious_payload).encode()).decode().rstrip('=')
        malicious_token = f"{encoded_header}.{encoded_payload}."
        
        try:
            headers = endpoint.headers.copy()
            headers['Authorization'] = f'Bearer {malicious_token}'
            
            response = self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=headers,
                params=endpoint.parameters,
                json=endpoint.body,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                findings.append(SecurityFinding(
                    vulnerability_type="JWT_ALGORITHM_CONFUSION",
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.url,
                    description="Endpoint accepts JWT tokens with 'none' algorithm",
                    evidence={
                        "malicious_token": malicious_token,
                        "status_code": response.status_code
                    },
                    remediation="Explicitly whitelist allowed JWT algorithms and reject 'none' algorithm"
                ))
        
        except requests.exceptions.RequestException:
            pass
        
        return findings

    def _test_jwt_none_algorithm(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for JWT none algorithm vulnerability"""
        findings = []
        
        # This test is covered in _test_jwt_algorithm_confusion
        # but could be expanded for more specific none algorithm tests
        
        return findings

    def _test_session_management(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test session management security"""
        findings = []
        
        try:
            response = self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.parameters,
                json=endpoint.body,
                timeout=self.timeout
            )
            
            # Check for session cookies
            for cookie in response.cookies:
                # Check for missing secure flag
                if not cookie.secure:
                    findings.append(SecurityFinding(
                        vulnerability_type="INSECURE_COOKIE",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Session cookie '{cookie.name}' missing Secure flag",
                        evidence={"cookie_name": cookie.name},
                        remediation="Set Secure flag on all session cookies"
                    ))
                
                # Check for missing HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    findings.append(SecurityFinding(
                        vulnerability_type="NON_HTTPONLY_COOKIE",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Session cookie '{cookie.name}' missing HttpOnly flag",
                        evidence={"cookie_name": cookie.name},
                        remediation="Set HttpOnly flag on all session cookies"
                    ))
        
        except requests.exceptions.RequestException:
            pass
        
        return findings

    def _test_api_key_security(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test API key security"""
        findings = []
        
        # Check for API keys in query parameters
        for param, value in endpoint.parameters.items():
            if self._looks_like_api_key(param, value):
                findings.append(SecurityFinding(
                    vulnerability_type="API_KEY_IN_URL",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=f"API key exposed in URL parameter: {param}",
                    evidence={"parameter": param},
                    remediation="Move API keys to Authorization header or request body"
                ))
        
        # Test for weak API keys
        api_key_headers = ['X-API-Key', 'X-Auth-Token', 'API-Key']
        for header_name in api_key_headers:
            if header_name in endpoint.headers:
                api_key = endpoint.headers[header_name]
                if self._is_weak_api_key(api_key):
                    findings.append(SecurityFinding(
                        vulnerability_type="WEAK_API_KEY",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Weak API key detected in {header_name}",
                        evidence={"header": header_name, "key_length": len(api_key)},
                        remediation="Use strong, randomly generated API keys with sufficient entropy"
                    ))
        
        return findings

    def _test_auth_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        # Test HTTP verb tampering
        bypass_methods = ['HEAD', 'OPTIONS', 'TRACE']
        for method in bypass_methods:
            if method != endpoint.method:
                try:
                    response = self.session.request(
                        method=method,
                        url=endpoint.url,
                        headers=endpoint.headers,
                        params=endpoint.parameters,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        findings.append(SecurityFinding(
                            vulnerability_type="HTTP_VERB_TAMPERING",
                            severity=Severity.MEDIUM,
                            endpoint=endpoint.url,
                            description=f"Endpoint accessible via {method} method without authentication",
                            evidence={"method": method, "status_code": response.status_code},
                            remediation="Implement consistent authentication across all HTTP methods"
                        ))
                
                except requests.exceptions.RequestException:
                    continue
        
        # Test path traversal in authentication
        bypass_paths = [
            endpoint.url + '/../',
            endpoint.url + '/.',
            endpoint.url + '/./',
            endpoint.url.replace('/', '%2f'),
            endpoint.url.replace('/', '\\')
        ]
        
        for bypass_path in bypass_paths:
            try:
                response = self.session.request(
                    method=endpoint.method,
                    url=bypass_path,
                    headers={},  # No auth headers
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    findings.append(SecurityFinding(
                        vulnerability_type="PATH_TRAVERSAL_AUTH_BYPASS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Authentication bypass via path manipulation: {bypass_path}",
                        evidence={"bypass_path": bypass_path},
                        remediation="Normalize and validate all URL paths before authentication checks"
                    ))
            
            except requests.exceptions.RequestException:
                continue
        
        return findings

    def _test_brute_force_protection(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for brute force protection mechanisms"""
        findings = []
        
        # Only test login-like endpoints
        if not self._is_login_endpoint(endpoint.url):
            return findings
        
        # Attempt multiple failed logins
        failed_attempts = 0
        max_attempts = 5
        
        for i in range(max_attempts):
            try:
                # Use different weak credentials for each attempt
                username = f"testuser{i}"
                password = self.weak_passwords[i % len(self.weak_passwords)]
                
                auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers = endpoint.headers.copy()
                headers['Authorization'] = f'Basic {auth_header}'
                
                response = self.session.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    headers=headers,
                    params=endpoint.parameters,
                    json=endpoint.body,
                    timeout=self.timeout
                )
                
                if response.status_code in [401, 403]:
                    failed_attempts += 1
                elif response.status_code == 429:
                    # Rate limiting detected - this is good
                    break
                
                # Small delay between attempts
                time.sleep(0.5)
            
            except requests.exceptions.RequestException:
                continue
        
        # If we made multiple failed attempts without rate limiting
        if failed_attempts >= max_attempts:
            findings.append(SecurityFinding(
                vulnerability_type="NO_BRUTE_FORCE_PROTECTION",
                severity=Severity.HIGH,
                endpoint=endpoint.url,
                description=f"No brute force protection detected after {failed_attempts} failed attempts",
                evidence={"failed_attempts": failed_attempts},
                remediation="Implement rate limiting and account lockout mechanisms"
            ))
        
        return findings

    # Helper methods
    
    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if endpoint is considered sensitive"""
        sensitive_patterns = [
            r'/admin', r'/api/admin', r'/dashboard', r'/config',
            r'/users?', r'/user', r'/profile', r'/account',
            r'/payment', r'/billing', r'/order', r'/transaction',
            r'/delete', r'/remove', r'/update', r'/edit'
        ]
        
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in sensitive_patterns)

    def _get_endpoint_pattern(self, url: str) -> str:
        """Extract endpoint pattern from URL"""
        # Remove base URL and parameters
        pattern = url.replace(self.base_url, '')
        return re.sub(r'/\d+', '/{id}', pattern)

    def _is_jwt_token(self, token: str) -> bool:
        """Check if string looks like a JWT token"""
        parts = token.split('.')
        return len(parts) == 3 and all(part for part in parts[:2])

    def _looks_like_api_key(self, param_name: str, value: str) -> bool:
        """Check if parameter looks like an API key"""
        api_key_patterns = ['key', 'token', 'auth', 'secret', 'api']
        return (any(pattern in param_name.lower() for pattern in api_key_patterns) and 
                isinstance(value, str) and len(value) > 10)

    def _is_weak_api_key(self, api_key: str) -> bool:
        """Check if API key is weak"""
        return (len(api_key) < 16 or 
                api_key.isdigit() or 
                api_key.isalpha() or 
                api_key in ['test', 'demo', 'example', '12345'])

    def _is_login_endpoint(self, url: str) -> bool:
        """Check if endpoint is a login endpoint"""
        login_patterns = [r'/login', r'/auth', r'/signin', r'/authenticate']
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in login_patterns)

    def generate_report(self) -> Dict[str, Any]:
        """Generate security assessment report"""
        if not self.findings:
            return {
                "timestamp": datetime.now().isoformat(),
                "agent": "AuthAgent",
                "target": self.base_url,
                "total_findings": 0,
                "findings": [],
                "summary": "No authentication vulnerabilities detected"
            }
        
        # Group findings by severity
        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "agent": "AuthAgent",
            "target": self.base_url,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "findings": [
                {
                    "type": finding.vulnerability_type,
                    "severity": finding.severity.value,
                    "endpoint": finding.endpoint,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "timestamp": finding.timestamp
                }
                for finding in self.findings
            ],
            "summary": f"Found {len(self.findings)} authentication security issues",
            "recommendations": self._generate_recommendations()
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate high-level security recommendations"""
        recommendations = []
        
        finding_types = set(finding.vulnerability_type for finding in self.findings)
        
        if "MISSING_AUTHENTICATION" in finding_types:
            recommendations.append("Implement authentication for all sensitive endpoints")
        
        if "WEAK_CREDENTIALS" in finding_types:
            recommendations.append("Enforce strong password policies and disable default credentials")
        
        if any("JWT" in ft for ft in finding_types):
            recommendations.append("Review JWT implementation and use secure algorithms and practices")
        
        if "NO_BRUTE_FORCE_PROTECTION" in finding_types:
            recommendations.append("Implement rate limiting and account lockout mechanisms")
        
        if any("COOKIE" in ft for ft in finding_types):
            recommendations.append("Secure session cookies with proper flags (Secure, HttpOnly, SameSite)")
        
        if "API_KEY" in str(finding_types):
            recommendations.append("Use strong API keys and secure transmission methods")
        
        return recommendations


# Example usage and testing
def main():
    """Example usage of AuthAgent"""
    
    # Initialize agent
    agent = AuthAgent("https://api.example.com")
    
    # Define test endpoints
    test_endpoints = [
        APIEndpoint(
            url="https://api.example.com/auth/login",
            method="POST",
            headers={"Content-Type": "application/json"},
            body={"username": "test", "password": "test"}
        ),
        APIEndpoint(
            url="https://api.example.com/users/profile",
            method="GET",
            headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.example"}
        ),
        APIEndpoint(
            url="https://api.example.com/admin/users",
            method="GET"
        )
    ]
    
    # Analyze endpoints
    print("Starting authentication security analysis...")
    for endpoint in test_endpoints:
        print(f"\nAnalyzing: {endpoint.method} {endpoint.url}")
        findings = agent.analyze_endpoint(endpoint)
        
        for finding in findings:
            print(f"  [{finding.severity.value}] {finding.vulnerability_type}: {finding.description}")
    
    # Generate report
    report = agent.generate_report()
    print(f"\n=== AUTHENTICATION SECURITY REPORT ===")
    print(f"Target: {report['target']}")
    print(f"Total Findings: {report['total_findings']}")
    print(f"Severity Breakdown: {report['severity_breakdown']}")
    print(f"Summary: {report['summary']}")
    
    if report['recommendations']:
        print("\nRecommendations:")
        for rec in report['recommendations']:
            print(f"  - {rec}")


if __name__ == "__main__":
    main()
