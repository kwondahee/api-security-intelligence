#!/usr/bin/env python3
"""
RateAgent - API Rate Limiting Security Agent
Part of the API Security Intelligence Framework for Continuous API Vulnerability Assessment

This agent specializes in rate limiting and traffic protection analysis for APIs, detecting:
- Missing rate limiting mechanisms
- Insufficient rate limits
- Rate limit bypass techniques
- DDoS vulnerability assessment
- Resource exhaustion attacks
- Traffic throttling effectiveness
- Concurrent request handling
"""

import requests
import json
import time
import threading
import asyncio
import aiohttp # Kept for future async expansion, but currently unused
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import statistics
import random
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
    """Represents a security vulnerability finding (Internal to RateAgent)"""
    vulnerability_type: str
    severity: Severity
    endpoint: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

# Dataclass mirroring the Orchestrator's standardized finding format
@dataclass
class RateFinding:
    agent: str
    category: str
    vuln: str
    status: str
    severity: str
    endpoint: str
    method: str
    actor: str
    evidence: Dict[str, Any]
    recommendation: str

@dataclass
class APIEndpoint:
    """Represents an API endpoint to be tested"""
    url: str # Full URL
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None

@dataclass
class RateTestResult:
    """Results from rate limiting tests"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    rate_limited_requests: int
    average_response_time: float
    max_response_time: float
    min_response_time: float
    requests_per_second: float
    error_codes: Dict[int, int]
    rate_limit_threshold: Optional[int] = None
    rate_limit_window: Optional[int] = None

class RateAgent:
    """
    Rate Limiting Security Agent for API vulnerability assessment
    """
    
    def __init__(self, target_base_url: str, timeout: int = 30, max_workers: int = 50, name: str = "RateAgent"):
        self.name = name
        self.base_url = target_base_url.rstrip('/')
        self.timeout = timeout
        self.max_workers = max_workers
        self.internal_findings: List[SecurityFinding] = [] # Stores internal SecurityFinding objects
        self.session = requests.Session()
        
        # Rate limiting test configurations
        self.test_configurations = {
            'basic_rate_test': {'requests': 100, 'duration': 60},
            'burst_test': {'requests': 50, 'duration': 5},
            'sustained_test': {'requests': 1000, 'duration': 300},
            'concurrent_test': {'concurrent_users': 20, 'requests_per_user': 10}
        }
        
        # Common rate limit headers to check
        self.rate_limit_headers = [
            'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
            'X-Rate-Limit-Limit', 'X-Rate-Limit-Remaining', 'X-Rate-Limit-Reset',
            'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset',
            'Retry-After', 'X-Retry-After'
        ]
        
        logger.info(f"RateAgent initialized for target: {self.base_url}")

    def run_scan(self, endpoint_path: str, method: str) -> List[Dict[str, Any]]:
        """
        Wrapper method called by the orchestrator to initiate the rate limiting scan.
        It calls the main analysis method and formats the results for the orchestrator.
        
        FIX: Removed asyncio.run() and now calls analyze_endpoint synchronously.
        """
        self.internal_findings = [] 
        
        # 1. Prepare the endpoint object
        endpoint = APIEndpoint(
            url=f"{self.base_url}{endpoint_path}", 
            method=method,
            headers={"Content-Type": "application/json"}
        )
        
        # 2. Call the main analysis method synchronously
        try:
            findings = self.analyze_endpoint(endpoint)
            self.internal_findings.extend(findings) # Store findings
        except Exception as e:
            logger.error(f"RateAgent failed to run analysis: {e}")
        
        # 3. Transform dataclass findings into the orchestrator's expected dictionary format
        orchestrator_findings = []
        for finding in self.internal_findings:
            orchestrator_findings.append(self._convert_to_dict_finding(finding))
            
        logger.info(f"RateAgent finished scan on {endpoint_path}. Found {len(orchestrator_findings)} potential issues.")
        return orchestrator_findings

    # --- REPORTING HELPER ---
    def _convert_to_dict_finding(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Converts internal SecurityFinding to the standardized orchestrator dictionary format."""
        
        # Map RateAgent internal severity/status to common orchestrator values
        status = "VULNERABLE"
        if "NO_RATE_LIMITING" in finding.vulnerability_type or "NO_RATE_LIMIT_HEADERS" in finding.vulnerability_type:
             status = "MISCONFIGURATION"
        
        # Use a more descriptive vulnerability type for the final report
        vuln_map = {
            "NO_RATE_LIMITING": "Missing Rate Limiting Mechanism",
            "WEAK_RATE_LIMITING": "Insufficient Rate Limiting",
            "USER_AGENT_RATE_BYPASS": "Rate Limit Bypass (User-Agent)",
            "IP_SPOOFING_RATE_BYPASS": "Rate Limit Bypass (IP Spoofing Header)",
            "HEADER_MANIPULATION_BYPASS": "Rate Limit Bypass (Custom Header)",
            "CASE_SENSITIVITY_BYPASS": "Rate Limit Bypass (URL Case Sensitivity)",
            "HTTP_METHOD_BYPASS": "Rate Limit Bypass (HTTP Method)",
            "POOR_BURST_PROTECTION": "Poor Burst Traffic Protection",
            "SERVER_ERRORS_UNDER_LOAD": "Resource Exhaustion (Server Errors)",
            "POOR_CONCURRENT_HANDLING": "Poor Concurrent Request Handling",
            "LARGE_PAYLOAD_DOS": "Denial of Service (Large Payload)",
            "COMPLEX_PARAMETER_DOS": "Denial of Service (Complex Parameter)",
            "PERFORMANCE_DEGRADATION": "Resource Exhaustion (Performance Degradation)",
            "POTENTIAL_MEMORY_LEAK": "Resource Exhaustion (Potential Memory Leak)",
            "NO_RATE_LIMIT_HEADERS": "Missing Rate Limit Headers",
            "EXCESSIVE_RATE_LIMIT": "Excessive Rate Limit Configuration",
            "OVERLY_RESTRICTIVE_RATE_LIMIT": "Overly Restrictive Rate Limit Configuration",
            "POOR_DDOS_PROTECTION_SLOWLORIS": "Poor DDoS Protection (SlowLoris)",
            "POOR_DDOS_PROTECTION_HIGH_FREQUENCY": "Poor DDoS Protection (High Frequency)",
            "POOR_DDOS_PROTECTION_CONNECTION_FLOOD": "Poor DDoS Protection (Connection Flood)",
            "RESPONSE_TIME_DEGRADATION": "Performance Degradation under Load",
            "INCONSISTENT_RESPONSE_TIMES": "Inconsistent Response Times under Load",
            "LARGE_PAYLOAD_SERVER_ERROR": "Denial of Service (Large Payload Server Error)",
            "ANALYSIS_ERROR": "Rate Limiting Analysis Error"
        }

        return asdict(RateFinding(
            agent=self.name,
            category="Rate Limiting",
            vuln=vuln_map.get(finding.vulnerability_type, finding.vulnerability_type),
            status=status,
            severity=finding.severity.value,
            endpoint=finding.endpoint.replace(self.base_url, ''), # Clean up endpoint URL
            method=finding.endpoint.split(" ")[0] if " " in finding.endpoint else "",
            actor="traffic_fuzzer",
            evidence=finding.evidence,
            recommendation=finding.remediation
        ))

    # --- MAIN ANALYSIS METHOD (NOW SYNCHRONOUS) ---
    def analyze_endpoint(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """
        Main analysis method for an API endpoint (Now Synchronous)
        """
        findings = []
        
        try:
            # All calls are now synchronous, without session argument
            
            # Test 1: Basic rate limiting detection
            findings.extend(self._test_basic_rate_limiting(endpoint))
            
            # Test 2: Rate limit bypass techniques
            findings.extend(self._test_rate_limit_bypass(endpoint))
            
            # Test 3: Burst traffic handling
            findings.extend(self._test_burst_traffic(endpoint))
            
            # Test 4: Concurrent request handling
            findings.extend(self._test_concurrent_requests(endpoint))
            
            # Test 5: Resource exhaustion vulnerability
            findings.extend(self._test_resource_exhaustion(endpoint))
            
            # Test 6: Rate limit configuration analysis
            findings.extend(self._analyze_rate_limit_configuration(endpoint))
            
            # Test 7: DDoS resilience testing
            findings.extend(self._test_ddos_resilience(endpoint))
            
        except Exception as e:
            logger.error(f"Error analyzing endpoint {endpoint.url}: {str(e)}")
            findings.append(SecurityFinding(
                vulnerability_type="ANALYSIS_ERROR",
                severity=Severity.LOW,
                endpoint=endpoint.url,
                description=f"Failed to complete rate limiting analysis: {str(e)}",
                evidence={"error": str(e)},
                remediation="Check endpoint accessibility and network connectivity"
            ))
            
        return findings

    # --- HELPER METHODS ---
    
    # Helper method for alternating case (for _test_case_sensitivity_bypass)
    def _alternate_case(self, url: str) -> str:
        """Create alternating case version of URL"""
        result = ""
        upper = True
        for char in url:
            if char.isalpha():
                result += char.upper() if upper else char.lower()
                upper = not upper
            else:
                result += char
        return result

    def _make_request(self, endpoint: APIEndpoint) -> Optional[requests.Response]:
        """Make a single HTTP request to the endpoint"""
        try:
            response = self.session.request(
                method=endpoint.method,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.parameters,
                json=endpoint.body,
                timeout=self.timeout
            )
            return response
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request to {endpoint.url} failed: {str(e)}")
            return None
    
    # --- TEST METHODS (FIXED: All below methods are now SYNCHRONOUS and only take 'endpoint') ---

    def _test_basic_rate_limiting(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for basic rate limiting implementation"""
        findings = []
        
        # Configuration for basic test
        test_requests = 100
        test_duration = 60  # seconds
        
        logger.info(f"Testing basic rate limiting for {endpoint.url}")
        
        try:
            test_result = self._execute_rate_test(endpoint, test_requests, test_duration)
            
            # Analyze results
            rate_limited_percentage = (test_result.rate_limited_requests / test_result.total_requests) * 100
            
            # No rate limiting detected
            if test_result.rate_limited_requests == 0:
                findings.append(SecurityFinding(
                    vulnerability_type="NO_RATE_LIMITING",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=f"No rate limiting detected after {test_requests} requests in {test_duration} seconds",
                    evidence={
                        "total_requests": test_result.total_requests,
                        "successful_requests": test_result.successful_requests,
                        "requests_per_second": test_result.requests_per_second,
                        "rate_limited_requests": test_result.rate_limited_requests
                    },
                    remediation="Implement rate limiting to prevent abuse and resource exhaustion"
                ))
            
            # Weak rate limiting
            elif rate_limited_percentage < 10:
                findings.append(SecurityFinding(
                    vulnerability_type="WEAK_RATE_LIMITING",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=f"Weak rate limiting detected - only {rate_limited_percentage:.1f}% of requests were rate limited",
                    evidence={
                        "rate_limited_percentage": rate_limited_percentage,
                        "total_requests": test_result.total_requests,
                        "rate_limited_requests": test_result.rate_limited_requests
                    },
                    remediation="Strengthen rate limiting policies to better protect against abuse"
                ))
            
            # Check response time degradation
            if test_result.max_response_time > test_result.average_response_time * 5:
                findings.append(SecurityFinding(
                    vulnerability_type="RESPONSE_TIME_DEGRADATION",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=f"Significant response time degradation under load (max: {test_result.max_response_time:.2f}s, avg: {test_result.average_response_time:.2f}s)",
                    evidence={
                        "max_response_time": test_result.max_response_time,
                        "average_response_time": test_result.average_response_time,
                        "min_response_time": test_result.min_response_time
                    },
                    remediation="Optimize server performance and implement proper load balancing"
                ))
        
        except Exception as e:
            logger.error(f"Basic rate limiting test failed: {str(e)}")
        
        return findings

    def _test_rate_limit_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test various rate limit bypass techniques (FIXED: Removed async and session)"""
        findings = []
        
        # Test different bypass techniques
        bypass_techniques = [
            self._test_user_agent_bypass,
            self._test_ip_spoofing_bypass,
            self._test_header_manipulation_bypass,
            self._test_case_sensitivity_bypass,
            self._test_http_method_bypass
        ]
        
        for technique in bypass_techniques:
            try:
                # FIX: Call synchronous technique without session or await
                technique_findings = technique(endpoint) 
                findings.extend(technique_findings)
            except Exception as e:
                logger.warning(f"Bypass technique failed: {str(e)}")
        
        return findings

    def _test_user_agent_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test if changing User-Agent header bypasses rate limits (FIXED: Removed async and session)"""
        findings = []
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "curl/7.68.0",
            "PostmanRuntime/7.28.0"
        ]
        
        baseline_requests = 20
        bypass_requests = 50
        
        try:
            # Establish baseline rate limiting
            baseline_result = self._execute_rate_test(endpoint, baseline_requests, 10)
            baseline_rate_limited = baseline_result.rate_limited_requests
            
            # Test with different user agents
            for ua in user_agents:
                modified_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers={**endpoint.headers, "User-Agent": ua},
                    parameters=endpoint.parameters,
                    body=endpoint.body
                )
                
                bypass_result = self._execute_rate_test(modified_endpoint, bypass_requests, 10)
                
                # If bypass successful (fewer rate limited requests with more total requests)
                if bypass_result.rate_limited_requests < baseline_rate_limited and bypass_requests > baseline_requests:
                    findings.append(SecurityFinding(
                        vulnerability_type="USER_AGENT_RATE_BYPASS",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Rate limiting can be bypassed by changing User-Agent to: {ua}",
                        evidence={
                            "user_agent": ua,
                            "baseline_rate_limited": baseline_rate_limited,
                            "bypass_rate_limited": bypass_result.rate_limited_requests,
                            "bypass_requests": bypass_requests
                        },
                        remediation="Implement rate limiting based on IP address or authenticated user, not just User-Agent"
                    ))
                    break  # Found one bypass, that's enough
        
        except Exception as e:
            logger.warning(f"User-Agent bypass test failed: {str(e)}")
        
        return findings

    def _test_ip_spoofing_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test if IP spoofing headers bypass rate limits (FIXED: Removed async and session)"""
        findings = []
        
        spoofing_headers = [
            {"X-Forwarded-For": "192.168.1.100"},
            {"X-Real-IP": "10.0.0.50"},
            {"X-Client-IP": "172.16.0.25"},
            {"X-Originating-IP": "203.0.113.1"},
            {"CF-Connecting-IP": "198.51.100.1"}
        ]
        
        try:
            # Baseline test
            baseline_result = self._execute_rate_test(endpoint, 30, 10)
            
            for spoof_header in spoofing_headers:
                modified_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers={**endpoint.headers, **spoof_header},
                    parameters=endpoint.parameters,
                    body=endpoint.body
                )
                
                spoof_result = self._execute_rate_test(modified_endpoint, 50, 10)
                
                if spoof_result.rate_limited_requests < baseline_result.rate_limited_requests:
                    findings.append(SecurityFinding(
                        vulnerability_type="IP_SPOOFING_RATE_BYPASS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Rate limiting bypassed using IP spoofing header: {list(spoof_header.keys())[0]}",
                        evidence={
                            "spoofing_header": spoof_header,
                            "baseline_rate_limited": baseline_result.rate_limited_requests,
                            "bypass_rate_limited": spoof_result.rate_limited_requests
                        },
                        remediation="Validate and sanitize IP forwarding headers, use trusted proxy configurations"
                    ))
                    break
        
        except Exception as e:
            logger.warning(f"IP spoofing bypass test failed: {str(e)}")
        
        return findings

    def _test_header_manipulation_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test header manipulation for rate limit bypass (FIXED: Removed async and session)"""
        findings = []
        
        manipulation_techniques = [
            {"X-Bypass-Rate-Limit": "true"},
            {"X-Admin": "1"},
            {"X-Internal": "true"},
            {"Authorization": "Bearer admin-bypass-token"},
            {"X-Rate-Limit-Bypass": "enabled"}
        ]
        
        try:
            baseline_result = self._execute_rate_test(endpoint, 25, 10)
            
            for bypass_header in manipulation_techniques:
                modified_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers={**endpoint.headers, **bypass_header},
                    parameters=endpoint.parameters,
                    body=endpoint.body
                )
                
                bypass_result = self._execute_rate_test(modified_endpoint, 40, 10)
                
                if bypass_result.successful_requests > baseline_result.successful_requests * 1.5:
                    findings.append(SecurityFinding(
                        vulnerability_type="HEADER_MANIPULATION_BYPASS",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Rate limiting bypassed using header manipulation: {list(bypass_header.keys())[0]}",
                        evidence={
                            "bypass_header": bypass_header,
                            "baseline_successful": baseline_result.successful_requests,
                            "bypass_successful": bypass_result.successful_requests
                        },
                        remediation="Validate all headers and implement whitelist-based header processing"
                    ))
                    break
        
        except Exception as e:
            logger.warning(f"Header manipulation bypass test failed: {str(e)}")
        
        return findings

    def _test_case_sensitivity_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test case sensitivity in endpoint URLs for rate limit bypass (FIXED: Removed async and session)"""
        findings = []
        
        if not endpoint.url:
            return findings
        
        try:
            # Create case variations of the endpoint
            variations = [
                endpoint.url.upper(),
                endpoint.url.lower(),
                self._alternate_case(endpoint.url)
            ]
            
            baseline_result = self._execute_rate_test(endpoint, 20, 10)
            
            for variant_url in variations:
                if variant_url != endpoint.url:
                    variant_endpoint = APIEndpoint(
                        url=variant_url,
                        method=endpoint.method,
                        headers=endpoint.headers,
                        parameters=endpoint.parameters,
                        body=endpoint.body
                    )
                    
                    variant_result = self._execute_rate_test(variant_endpoint, 30, 10)
                    
                    # If variant gets more successful requests, it may bypass rate limiting
                    if variant_result.successful_requests > baseline_result.successful_requests * 1.2:
                        findings.append(SecurityFinding(
                            vulnerability_type="CASE_SENSITIVITY_BYPASS",
                            severity=Severity.LOW,
                            endpoint=endpoint.url,
                            description=f"Rate limiting may be bypassed using case variation: {variant_url}",
                            evidence={
                                "original_url": endpoint.url,
                                "variant_url": variant_url,
                                "baseline_successful": baseline_result.successful_requests,
                                "variant_successful": variant_result.successful_requests
                            },
                            remediation="Implement case-insensitive URL matching for rate limiting"
                        ))
        
        except Exception as e:
            logger.warning(f"Case sensitivity bypass test failed: {str(e)}")
        
        return findings

    def _test_http_method_bypass(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test if different HTTP methods bypass rate limits (FIXED: Removed async and session)"""
        findings = []
        
        alternative_methods = ['HEAD', 'OPTIONS', 'PATCH']
        if endpoint.method.upper() not in alternative_methods:
            alternative_methods.append(endpoint.method.upper())
        
        try:
            results = {}
            
            for method in alternative_methods:
                method_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=method,
                    headers=endpoint.headers,
                    parameters=endpoint.parameters,
                    body=endpoint.body if method in ['POST', 'PUT', 'PATCH'] else None
                )
                
                results[method] = self._execute_rate_test(method_endpoint, 30, 10)
            
            # Compare results between methods
            base_method = endpoint.method.upper()
            if base_method in results:
                base_successful = results[base_method].successful_requests
                
                for method, result in results.items():
                    if method != base_method and result.successful_requests > base_successful * 1.5:
                        findings.append(SecurityFinding(
                            vulnerability_type="HTTP_METHOD_BYPASS",
                            severity=Severity.MEDIUM,
                            endpoint=endpoint.url,
                            description=f"Rate limiting bypassed using {method} method instead of {base_method}",
                            evidence={
                                "base_method": base_method,
                                "bypass_method": method,
                                "base_successful": base_successful,
                                "bypass_successful": result.successful_requests
                            },
                            remediation="Apply consistent rate limiting across all HTTP methods for each endpoint"
                        ))
        
        except Exception as e:
            logger.warning(f"HTTP method bypass test failed: {str(e)}")
        
        return findings

    def _test_burst_traffic(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test handling of burst traffic patterns (FIXED: Removed async and session)"""
        findings = []
        
        # Burst test: many requests in short time
        burst_requests = 50
        burst_duration = 5
        
        logger.info(f"Testing burst traffic handling for {endpoint.url}")
        
        try:
            burst_result = self._execute_burst_test(endpoint, burst_requests, burst_duration)
            
            # Analyze burst handling
            success_rate = (burst_result.successful_requests / burst_result.total_requests) * 100
            
            if success_rate > 80:  # High success rate during burst
                findings.append(SecurityFinding(
                    vulnerability_type="POOR_BURST_PROTECTION",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=f"Endpoint handles burst traffic poorly - {success_rate:.1f}% success rate during burst",
                    evidence={
                        "burst_requests": burst_requests,
                        "burst_duration": burst_duration,
                        "success_rate": success_rate,
                        "successful_requests": burst_result.successful_requests
                    },
                    remediation="Implement burst protection mechanisms such as token bucket or sliding window rate limiting"
                ))
            
            # Check for server errors during burst
            server_error_rate = sum(count for code, count in burst_result.error_codes.items() if 500 <= code < 600)
            if server_error_rate > 0:
                findings.append(SecurityFinding(
                    vulnerability_type="SERVER_ERRORS_UNDER_LOAD",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=f"Server errors occurred during burst test: {server_error_rate} 5xx responses",
                    evidence={
                        "server_errors": server_error_rate,
                        "error_codes": burst_result.error_codes
                    },
                    remediation="Improve server capacity and error handling under high load conditions"
                ))
        
        except Exception as e:
            logger.error(f"Burst traffic test failed: {str(e)}")
        
        return findings

    def _test_concurrent_requests(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test concurrent request handling (FIXED: Removed async and session)"""
        findings = []
        
        concurrent_users = 20
        requests_per_user = 10
        
        logger.info(f"Testing concurrent request handling for {endpoint.url}")
        
        try:
            concurrent_result = self._execute_concurrent_test(endpoint, concurrent_users, requests_per_user)
            
            # total_expected = concurrent_users * requests_per_user # Unused variable removed
            success_rate = (concurrent_result.successful_requests / concurrent_result.total_requests) * 100
            
            # Poor concurrent handling
            if success_rate < 70:
                findings.append(SecurityFinding(
                    vulnerability_type="POOR_CONCURRENT_HANDLING",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=f"Poor concurrent request handling - only {success_rate:.1f}% success rate",
                    evidence={
                        "concurrent_users": concurrent_users,
                        "requests_per_user": requests_per_user,
                        "success_rate": success_rate,
                        "total_requests": concurrent_result.total_requests,
                        "successful_requests": concurrent_result.successful_requests
                    },
                    remediation="Optimize server for concurrent request handling and implement connection pooling"
                ))
            
            # High response time variation indicates poor load handling
            if concurrent_result.max_response_time > concurrent_result.average_response_time * 10:
                findings.append(SecurityFinding(
                    vulnerability_type="INCONSISTENT_RESPONSE_TIMES",
                    severity=Severity.LOW,
                    endpoint=endpoint.url,
                    description="High variation in response times under concurrent load",
                    evidence={
                        "max_response_time": concurrent_result.max_response_time,
                        "average_response_time": concurrent_result.average_response_time,
                        "response_time_ratio": concurrent_result.max_response_time / concurrent_result.average_response_time
                    },
                    remediation="Implement load balancing and optimize database queries for consistent performance"
                ))
        
        except Exception as e:
            logger.error(f"Concurrent request test failed: {str(e)}")
        
        return findings

    def _test_resource_exhaustion(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test for resource exhaustion vulnerabilities (FIXED: Removed async and session)"""
        findings = []
        
        # Test with large payloads if endpoint accepts POST/PUT
        if endpoint.method.upper() in ['POST', 'PUT', 'PATCH']:
            # FIX: Call synchronous method without session
            findings.extend(self._test_large_payload_handling(endpoint))
        
        # Test with complex parameters
        # FIX: Call synchronous method without session
        findings.extend(self._test_complex_parameters(endpoint))
        
        # Test sustained load
        # FIX: Call synchronous method without session
        findings.extend(self._test_sustained_load(endpoint))
        
        return findings

    def _test_large_payload_handling(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test handling of large payloads (FIXED: Removed async and session)"""
        findings = []
        
        # Create progressively larger payloads
        payload_sizes = [1024, 10240, 102400, 1048576]  # 1KB to 1MB
        
        try:
            for size in payload_sizes:
                large_payload = {"data": "A" * size}
                
                large_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers=endpoint.headers,
                    parameters=endpoint.parameters,
                    body=large_payload
                )
                
                start_time = time.time()
                response = self._make_request(large_endpoint)
                response_time = time.time() - start_time
                
                # Check for excessive response times
                if response_time > 30:  # 30 second timeout
                    findings.append(SecurityFinding(
                        vulnerability_type="LARGE_PAYLOAD_DOS",
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=f"Large payload ({size} bytes) causes excessive response time: {response_time:.2f}s",
                        evidence={
                            "payload_size": size,
                            "response_time": response_time,
                            "status_code": response.status_code if response else "timeout"
                        },
                        remediation="Implement payload size limits and request timeouts"
                    ))
                    break
                
                # Check for server errors
                if response and response.status_code >= 500:
                    findings.append(SecurityFinding(
                        vulnerability_type="LARGE_PAYLOAD_SERVER_ERROR",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Large payload ({size} bytes) causes server error: {response.status_code}",
                        evidence={
                            "payload_size": size,
                            "status_code": response.status_code,
                            "response_time": response_time
                        },
                        remediation="Implement proper payload validation and error handling"
                    ))
        
        except Exception as e:
            logger.warning(f"Large payload test failed: {str(e)}")
        
        return findings

    def _test_complex_parameters(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test handling of complex parameters (FIXED: Removed async and session)"""
        findings = []
        
        complex_params = {
            "nested": {"level1": {"level2": {"level3": "deep_nesting"}}},
            "large_array": list(range(1000)),
            "complex_string": "A" * 10000,
            "special_chars": "!@#$%^&*()[]{}|;':\",./<>?`~"
        }
        
        try:
            for param_name, param_value in complex_params.items():
                complex_endpoint = APIEndpoint(
                    url=endpoint.url,
                    method=endpoint.method,
                    headers=endpoint.headers,
                    parameters={**endpoint.parameters, param_name: param_value},
                    body=endpoint.body
                )
                
                start_time = time.time()
                response = self._make_request(complex_endpoint)
                response_time = time.time() - start_time
                
                if response_time > 10:  # Excessive processing time
                    findings.append(SecurityFinding(
                        vulnerability_type="COMPLEX_PARAMETER_DOS",
                        severity=Severity.MEDIUM,
                        endpoint=endpoint.url,
                        description=f"Complex parameter processing causes excessive response time: {response_time:.2f}s",
                        evidence={
                            "parameter_type": param_name,
                            "response_time": response_time,
                            "status_code": response.status_code if response else "timeout"
                        },
                        remediation="Implement parameter complexity limits and input validation"
                    ))
        
        except Exception as e:
            logger.warning(f"Complex parameter test failed: {str(e)}")
        
        return findings

    def _test_sustained_load(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test sustained load handling (FIXED: Removed async and session)"""
        findings = []
        
        sustained_requests = 200
        sustained_duration = 120  # 2 minutes
        
        try:
            sustained_result = self._execute_rate_test(endpoint, sustained_requests, sustained_duration)
            
            # Check for degradation over time
            if sustained_result.max_response_time > sustained_result.min_response_time * 5:
                findings.append(SecurityFinding(
                    vulnerability_type="PERFORMANCE_DEGRADATION",
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description="Performance degrades significantly under sustained load",
                    evidence={
                        "max_response_time": sustained_result.max_response_time,
                        "min_response_time": sustained_result.min_response_time,
                        "average_response_time": sustained_result.average_response_time,
                        "total_requests": sustained_result.total_requests
                    },
                    remediation="Implement caching, optimize database queries, and add horizontal scaling"
                ))
            
            # Check memory leak indicators (increasing response times)
            if sustained_result.average_response_time > 5.0:  # Average > 5 seconds
                findings.append(SecurityFinding(
                    vulnerability_type="POTENTIAL_MEMORY_LEAK",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description="High average response times may indicate memory leaks or resource exhaustion",
                    evidence={
                        "average_response_time": sustained_result.average_response_time,
                        "requests_per_second": sustained_result.requests_per_second
                    },
                    remediation="Monitor memory usage and investigate potential resource leaks"
                ))
        
        except Exception as e:
            logger.warning(f"Sustained load test failed: {str(e)}")
        
        return findings

    def _analyze_rate_limit_configuration(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Analyze rate limiting configuration and headers (FIXED: Removed async and session)"""
        findings = []
        
        try:
            response = self._make_request(endpoint)
            if not response:
                return findings
            
            # Check for rate limiting headers
            rate_headers = {}
            for header in self.rate_limit_headers:
                if header in response.headers:
                    rate_headers[header] = response.headers[header]
            
            if not rate_headers:
                findings.append(SecurityFinding(
                    vulnerability_type="NO_RATE_LIMIT_HEADERS",
                    severity=Severity.LOW,
                    endpoint=endpoint.url,
                    description="No rate limiting headers found in response",
                    evidence={"response_headers": dict(response.headers)},
                    remediation="Include rate limiting headers to inform clients about limits"
                ))
            else:
                # Analyze rate limit values
                # FIX: Call synchronous method without session
                findings.extend(self._analyze_rate_limit_values(endpoint, rate_headers))
        
        except Exception as e:
            logger.warning(f"Rate limit configuration analysis failed: {str(e)}")
        
        return findings

    def _analyze_rate_limit_values(self, endpoint: APIEndpoint, rate_headers: Dict[str, str]) -> List[SecurityFinding]:
        """Analyze rate limit header values for security issues (FIXED: Removed async and session)"""
        findings = []
        
        try:
            # Extract rate limit values
            limit = None
            remaining = None
            reset = None
            
            # Parse common rate limit header formats
            for header, value in rate_headers.items():
                if 'limit' in header.lower() and limit is None:
                    try:
                        limit = int(value)
                    except ValueError:
                        pass
                elif 'remaining' in header.lower() and remaining is None:
                    try:
                        remaining = int(value)
                    except ValueError:
                        pass
                elif 'reset' in header.lower() and reset is None:
                    try:
                        reset = int(value)
                    except ValueError:
                        pass
            
            # Analyze rate limit values
            if limit is not None:
                # Very high rate limits
                if limit > 10000:
                    findings.append(SecurityFinding(
                        vulnerability_type="EXCESSIVE_RATE_LIMIT",
                        severity=Severity.LOW,
                        endpoint=endpoint.url,
                        description=f"Rate limit is very high: {limit} requests per window",
                        evidence={"rate_limit": limit, "headers": rate_headers},
                        remediation="Consider lowering rate limits to prevent abuse"
                    ))
                
                # Very low rate limits (may indicate DoS vulnerability)
                elif limit < 10:
                    findings.append(SecurityFinding(
                        vulnerability_type="OVERLY_RESTRICTIVE_RATE_LIMIT",
                        severity=Severity.LOW,
                        endpoint=endpoint.url,
                        description=f"Rate limit may be too restrictive: {limit} requests per window",
                        evidence={"rate_limit": limit, "headers": rate_headers},
                        remediation="Balance rate limiting between security and usability"
                    ))
        
        except Exception as e:
            logger.warning(f"Rate limit value analysis failed: {str(e)}")
        
        return findings

    def _test_ddos_resilience(self, endpoint: APIEndpoint) -> List[SecurityFinding]:
        """Test DDoS resilience capabilities (FIXED: Removed async and session)"""
        findings = []
        
        # Simulate different DDoS attack patterns
        ddos_tests = [
            {"name": "slowloris", "requests": 100, "delay": 0.1},
            {"name": "high_frequency", "requests": 200, "delay": 0.01},
            {"name": "connection_flood", "requests": 500, "delay": 0.001}
        ]
        
        for test in ddos_tests:
            try:
                logger.info(f"Running DDoS resilience test: {test['name']}")
                
                ddos_result = self._execute_ddos_simulation(
                    endpoint, 
                    test['requests'], 
                    test['delay']
                )
                
                # Analyze DDoS test results
                success_rate = (ddos_result.successful_requests / ddos_result.total_requests) * 100
                
                if success_rate > 50:  # High success rate indicates poor DDoS protection
                    severity = Severity.HIGH if success_rate > 80 else Severity.MEDIUM
                    
                    findings.append(SecurityFinding(
                        vulnerability_type=f"POOR_DDOS_PROTECTION_{test['name'].upper()}",
                        severity=severity,
                        endpoint=endpoint.url,
                        description=f"Poor DDoS protection against {test['name']} attack - {success_rate:.1f}% success rate",
                        evidence={
                            "attack_type": test['name'],
                            "success_rate": success_rate,
                            "total_requests": ddos_result.total_requests,
                            "successful_requests": ddos_result.successful_requests
                        },
                        remediation=f"Implement DDoS protection mechanisms for {test['name']} style attacks"
                    ))
            
            except Exception as e:
                logger.warning(f"DDoS test {test['name']} failed: {str(e)}")
        
        return findings

    # Helper methods for executing tests (These are all synchronous and correct)

    def _execute_rate_test(self, endpoint: APIEndpoint, num_requests: int, duration: int) -> RateTestResult:
        """Execute rate limiting test with specified parameters"""
        results = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'rate_limited': 0,
            'response_times': [],
            'error_codes': {}
        }
        
        start_time = time.time()
        request_interval = duration / num_requests if num_requests > 0 else 1
        
        for i in range(num_requests):
            if time.time() - start_time >= duration:
                break
                
            try:
                request_start = time.time()
                response = self._make_request(endpoint)
                request_time = time.time() - request_start
                
                results['total'] += 1
                results['response_times'].append(request_time)
                
                if response:
                    if response.status_code == 200:
                        results['successful'] += 1
                    elif response.status_code == 429:  # Too Many Requests
                        results['rate_limited'] += 1
                    else:
                        results['failed'] += 1
                        results['error_codes'][response.status_code] = results['error_codes'].get(response.status_code, 0) + 1
                else:
                    results['failed'] += 1
                
                # Sleep to maintain request rate
                time.sleep(max(0, request_interval - request_time))
                
            except Exception as e:
                results['failed'] += 1
                logger.debug(f"Request failed: {str(e)}")
        
        # Calculate statistics
        response_times = results['response_times']
        avg_response_time = statistics.mean(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        
        actual_duration = time.time() - start_time
        requests_per_second = results['total'] / actual_duration if actual_duration > 0 else 0
        
        return RateTestResult(
            total_requests=results['total'],
            successful_requests=results['successful'],
            failed_requests=results['failed'],
            rate_limited_requests=results['rate_limited'],
            average_response_time=avg_response_time,
            max_response_time=max_response_time,
            min_response_time=min_response_time,
            requests_per_second=requests_per_second,
            error_codes=results['error_codes']
        )

    def _execute_burst_test(self, endpoint: APIEndpoint, num_requests: int, duration: int) -> RateTestResult:
        """Execute burst test - all requests as fast as possible"""
        results = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'rate_limited': 0,
            'response_times': [],
            'error_codes': {}
        }
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=min(num_requests, self.max_workers)) as executor:
            # Submit all requests at once
            futures = [executor.submit(self._make_request, endpoint) for _ in range(num_requests)]
            
            for future in as_completed(futures, timeout=duration):
                try:
                    response = future.result(timeout=1)
                    request_time = time.time() - start_time  # Approximate
                    
                    results['total'] += 1
                    results['response_times'].append(request_time)
                    
                    if response:
                        if response.status_code == 200:
                            results['successful'] += 1
                        elif response.status_code == 429:
                            results['rate_limited'] += 1
                        else:
                            results['failed'] += 1
                            results['error_codes'][response.status_code] = results['error_codes'].get(response.status_code, 0) + 1
                    else:
                        results['failed'] += 1
                
                except Exception as e:
                    results['failed'] += 1
                    logger.debug(f"Burst request failed: {str(e)}")
        
        # Calculate statistics
        response_times = results['response_times']
        avg_response_time = statistics.mean(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        
        actual_duration = time.time() - start_time
        requests_per_second = results['total'] / actual_duration if actual_duration > 0 else 0
        
        return RateTestResult(
            total_requests=results['total'],
            successful_requests=results['successful'],
            failed_requests=results['failed'],
            rate_limited_requests=results['rate_limited'],
            average_response_time=avg_response_time,
            max_response_time=max_response_time,
            min_response_time=min_response_time,
            requests_per_second=requests_per_second,
            error_codes=results['error_codes']
        )

    def _execute_concurrent_test(self, endpoint: APIEndpoint, concurrent_users: int, requests_per_user: int) -> RateTestResult:
        """Execute concurrent user simulation test"""
        results = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'rate_limited': 0,
            'response_times': [],
            'error_codes': {}
        }
        
        def user_session():
            """Simulate a single user making multiple requests"""
            session_results = []
            for _ in range(requests_per_user):
                try:
                    start_time = time.time()
                    response = self._make_request(endpoint)
                    response_time = time.time() - start_time
                    
                    session_results.append({
                        'response': response,
                        'response_time': response_time
                    })
                    
                    # Small delay between requests from same user
                    time.sleep(random.uniform(0.1, 0.5))
                
                except Exception as e:
                    session_results.append({
                        'response': None,
                        'response_time': 0,
                        'error': str(e)
                    })
            
            return session_results
        
        start_time = time.time()
        
        # Run concurrent user sessions
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(user_session) for _ in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    session_results = future.result()
                    
                    for result in session_results:
                        results['total'] += 1
                        
                        if 'response_time' in result:
                            results['response_times'].append(result['response_time'])
                        
                        response = result.get('response')
                        if response:
                            if response.status_code == 200:
                                results['successful'] += 1
                            elif response.status_code == 429:
                                results['rate_limited'] += 1
                            else:
                                results['failed'] += 1
                                results['error_codes'][response.status_code] = results['error_codes'].get(response.status_code, 0) + 1
                        else:
                            results['failed'] += 1
                
                except Exception as e:
                    logger.warning(f"Concurrent user session failed: {str(e)}")
        
        # Calculate statistics
        response_times = results['response_times']
        avg_response_time = statistics.mean(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        
        actual_duration = time.time() - start_time
        requests_per_second = results['total'] / actual_duration if actual_duration > 0 else 0
        
        return RateTestResult(
            total_requests=results['total'],
            successful_requests=results['successful'],
            failed_requests=results['failed'],
            rate_limited_requests=results['rate_limited'],
            average_response_time=avg_response_time,
            max_response_time=max_response_time,
            min_response_time=min_response_time,
            requests_per_second=requests_per_second,
            error_codes=results['error_codes']
        )

    def _execute_ddos_simulation(self, endpoint: APIEndpoint, num_requests: int, delay: float) -> RateTestResult:
        """Execute DDoS simulation with specified request pattern"""
        results = {
            'total': 0,
            'successful': 0,
            'failed': 0,
            'rate_limited': 0,
            'response_times': [],
            'error_codes': {}
        }
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent DDoS simulation
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Submit requests with specified delay pattern
            for i in range(num_requests):
                future = executor.submit(self._make_request, endpoint)
                futures.append(future)
                
                if delay > 0:
                    time.sleep(delay)
            
            # Collect results
            for future in as_completed(futures, timeout=300):  # 5 minute timeout
                try:
                    response = future.result(timeout=10)
                    request_time = time.time() - start_time
                    
                    results['total'] += 1
                    results['response_times'].append(request_time)
                    
                    if response:
                        if response.status_code == 200:
                            results['successful'] += 1
                        elif response.status_code == 429:
                            results['rate_limited'] += 1
                        else:
                            results['failed'] += 1
                            results['error_codes'][response.status_code] = results['error_codes'].get(response.status_code, 0) + 1
                    else:
                        results['failed'] += 1
                
                except Exception as e:
                    results['failed'] += 1
                    logger.debug(f"DDoS simulation request failed: {str(e)}")
        
        # Calculate statistics
        response_times = results['response_times']
        avg_response_time = statistics.mean(response_times) if response_times else 0
        max_response_time = max(response_times) if response_times else 0
        min_response_time = min(response_times) if response_times else 0
        
        actual_duration = time.time() - start_time
        requests_per_second = results['total'] / actual_duration if actual_duration > 0 else 0
        
        return RateTestResult(
            total_requests=results['total'],
            successful_requests=results['successful'],
            failed_requests=results['failed'],
            rate_limited_requests=results['rate_limited'],
            average_response_time=avg_response_time,
            max_response_time=max_response_time,
            min_response_time=min_response_time,
            requests_per_second=requests_per_second,
            error_codes=results['error_codes']
        )
        
    def generate_report(self) -> Dict[str, Any]:
        """Generate rate limiting security assessment report (kept for completeness)"""
        if not self.internal_findings:
            return {
                "timestamp": datetime.now().isoformat(),
                "agent": "RateAgent",
                "target": self.base_url,
                "total_findings": 0,
                "findings": [],
                "summary": "No rate limiting vulnerabilities detected"
            }
        
        # Group findings by severity
        severity_counts = {severity.value: 0 for severity in Severity}
        vulnerability_types = {}
        
        for finding in self.internal_findings:
            severity_counts[finding.severity.value] += 1
            vulnerability_types[finding.vulnerability_type] = vulnerability_types.get(finding.vulnerability_type, 0) + 1
        
        return {
            "timestamp": datetime.now().isoformat(),
            "agent": "RateAgent",
            "target": self.base_url,
            "total_findings": len(self.internal_findings),
            "severity_breakdown": severity_counts,
            "vulnerability_types": vulnerability_types,
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
                for finding in self.internal_findings
            ],
            "summary": f"Found {len(self.internal_findings)} rate limiting security issues",
            "recommendations": self._generate_recommendations()
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate high-level security recommendations"""
        recommendations = []
        
        finding_types = set(finding.vulnerability_type for finding in self.internal_findings)
        
        if "NO_RATE_LIMITING" in finding_types:
            recommendations.append("Implement comprehensive rate limiting across all API endpoints")
        
        if any("BYPASS" in ft for ft in finding_types):
            recommendations.append("Strengthen rate limiting implementation to prevent bypass techniques")
        
        if any("BURST" in ft or "CONCURRENT" in ft for ft in finding_types):
            recommendations.append("Implement burst protection and optimize concurrent request handling")
        
        if any("DOS" in ft or "DDOS" in ft for ft in finding_types):
            recommendations.append("Deploy DDoS protection mechanisms and resource limits")
        
        if "NO_RATE_LIMIT_HEADERS" in finding_types:
            recommendations.append("Include rate limiting headers in API responses for client awareness")
        
        if any("PAYLOAD" in ft for ft in finding_types):
            recommendations.append("Implement request size limits and payload validation")
        
        if any("PERFORMANCE" in ft or "DEGRADATION" in ft for ft in finding_types):
            recommendations.append("Optimize server performance and implement proper resource management")
        
        return recommendations
    
    # --- EXECUTION BLOCK FOR STANDALONE TESTING ---
if __name__ == "__main__":
    # Define a temporary target for direct testing
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    
    # Define a specific endpoint and method to test
    TEST_ENDPOINT_PATH = "/users/v1/profile/1"
    TEST_METHOD = "GET"
    
    print("=====================================================")
    print(f"🛡️ Running RateAgent Standalone Scan on: {TEST_ENDPOINT_PATH}")
    print("=====================================================")
    
    # 1. Initialize the Agent
    agent = RateAgent(target_base_url=TEST_TARGET_BASE_URL)
    
    # 2. Run the specific scan
    try:
        findings = agent.run_scan(
            endpoint_path=TEST_ENDPOINT_PATH, 
            method=TEST_METHOD
        )
        
        # 3. Print the results (using the agent's internal report generator, if available)
        print("\n--- RateAgent Scan Complete ---")
        if findings:
            print(f"Found {len(findings)} Security Findings:")
            for finding in findings:
                print(f"  [{finding['severity']}] {finding['vuln']} on {finding['endpoint']}")
        else:
            print("No security findings reported.")

    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"RateAgent failed during execution: {e}")