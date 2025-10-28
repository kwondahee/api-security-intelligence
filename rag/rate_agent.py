# agents/rate_agent.py
"""
Rate Limiting Detection Agent - Optimized Version
Tests for missing or inadequate rate limiting controls
"""

import logging
import time
import requests
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

class RateAgent:
    """Agent for detecting rate limiting vulnerabilities."""
    
    def __init__(self, target_base_url: str):
        self.target_base_url = target_base_url.rstrip('/')
        
        # Create optimized session with connection pooling
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        
        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,  # Connection pool size
            pool_maxsize=20,
            pool_block=False
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default timeout
        self.timeout = 2
        
        logger.info(f"RateAgent initialized for target: {self.target_base_url}")
    
    def __del__(self):
        """Clean up session on deletion."""
        if hasattr(self, 'session'):
            self.session.close()
    
    def run_scan(self, endpoint_path: str, method: str = "GET") -> List[Dict[str, Any]]:
        """
        Execute rate limiting vulnerability scan.
        
        Args:
            endpoint_path: API endpoint to test
            method: HTTP method to use
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test 1: Basic rate limiting (optimized)
        basic_finding = self._test_basic_rate_limit(endpoint_path, method)
        if basic_finding:
            findings.append(basic_finding)
        
        # Test 2: Burst traffic handling (concurrent)
        burst_finding = self._test_burst_traffic(endpoint_path, method)
        if burst_finding:
            findings.append(burst_finding)
        
        return findings
    
    def _test_basic_rate_limit(self, endpoint_path: str, method: str) -> Optional[Dict[str, Any]]:
        """
        Test if basic rate limiting is implemented.
        Uses connection pooling for efficiency.
        """
        logger.info(f"Testing basic rate limiting for {self.target_base_url}{endpoint_path}")
        
        # Reduced from 100 to 30 for faster testing
        num_requests = 30
        url = f"{self.target_base_url}{endpoint_path}"
        status_codes = []
        
        start_time = time.time()
        
        try:
            # Use session for connection reuse
            for i in range(num_requests):
                try:
                    response = self.session.request(
                        method, 
                        url, 
                        timeout=self.timeout
                    )
                    status_codes.append(response.status_code)
                    
                    # Early exit if rate limiting detected
                    if response.status_code == 429:
                        logger.info(f"Rate limiting detected at request {i+1}")
                        return None  # Rate limiting is present (GOOD)
                    
                    # Small delay to avoid overwhelming the server
                    time.sleep(0.01)  # 10ms between requests
                    
                except requests.Timeout:
                    logger.warning(f"Request {i+1} timed out")
                    status_codes.append('timeout')
                except requests.ConnectionError as e:
                    logger.error(f"Connection error at request {i+1}: {e}")
                    # If connection refused, API might be down
                    if i < 5:  # Only fail if early in the test
                        return None
                    break
                except Exception as e:
                    logger.error(f"Request {i+1} failed: {e}")
                    status_codes.append('error')
            
            elapsed = time.time() - start_time
            success_count = status_codes.count(200)
            
            logger.info(f"Rate limit test: {success_count}/{num_requests} successful in {elapsed:.1f}s")
            
            # If 90%+ requests succeeded without rate limiting
            if success_count >= num_requests * 0.9:
                return {
                    "agent": "RateAgent",
                    "vuln": "Missing Rate Limiting",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "endpoint": endpoint_path,
                    "method": method,
                    "details": f"Sent {num_requests} requests in {elapsed:.1f}s. {success_count} succeeded without rate limiting (429 status code not returned).",
                    "recommendation": "Implement rate limiting using token bucket or sliding window algorithm. Common limits: 100 requests per minute for authenticated users, 20 per minute for anonymous. Return HTTP 429 with Retry-After header when limit exceeded.",
                    "evidence": {
                        "requests_sent": num_requests,
                        "successful": success_count,
                        "duration_seconds": round(elapsed, 2),
                        "rate_limited": False
                    }
                }
            else:
                logger.info(f"Possible rate limiting or API issues detected")
                return None
        
        except Exception as e:
            logger.error(f"Basic rate limit test failed: {e}")
            return None
    
    def _test_burst_traffic(self, endpoint_path: str, method: str) -> Optional[Dict[str, Any]]:
        """
        Test handling of burst traffic using concurrent requests.
        Much faster than sequential requests.
        """
        logger.info(f"Testing burst traffic handling for {self.target_base_url}{endpoint_path}")
        
        burst_size = 15  # Concurrent requests
        url = f"{self.target_base_url}{endpoint_path}"
        
        def make_request():
            """Single request function for thread pool."""
            try:
                response = self.session.request(
                    method, 
                    url, 
                    timeout=self.timeout
                )
                return response.status_code
            except requests.Timeout:
                return 'timeout'
            except requests.ConnectionError:
                return 'connection_error'
            except Exception as e:
                logger.debug(f"Request error: {e}")
                return 'error'
        
        try:
            start_time = time.time()
            
            # Send concurrent requests using thread pool
            with ThreadPoolExecutor(max_workers=burst_size) as executor:
                # Submit all requests
                futures = [executor.submit(make_request) for _ in range(burst_size)]
                
                # Collect results with timeout
                results = []
                for future in as_completed(futures, timeout=10):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.error(f"Future result error: {e}")
                        results.append('error')
            
            elapsed = time.time() - start_time
            
            # Analyze results
            success_count = results.count(200)
            rate_limited = results.count(429)
            errors = results.count('error') + results.count('connection_error')
            
            logger.info(f"Burst test: {success_count}/{burst_size} successful, {rate_limited} rate limited in {elapsed:.1f}s")
            
            # If most requests succeeded without rate limiting
            if rate_limited == 0 and success_count >= burst_size * 0.8:
                return {
                    "agent": "RateAgent",
                    "vuln": "Inadequate Burst Traffic Handling",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "endpoint": endpoint_path,
                    "method": method,
                    "details": f"Burst of {burst_size} concurrent requests completed in {elapsed:.1f}s without rate limiting. This could enable DoS attacks.",
                    "recommendation": "Implement burst detection and throttling. Use algorithms like leaky bucket to smooth traffic spikes. Consider per-IP and per-user limits with burst allowances.",
                    "evidence": {
                        "burst_size": burst_size,
                        "successful": success_count,
                        "rate_limited": rate_limited,
                        "duration_seconds": round(elapsed, 2)
                    }
                }
            else:
                logger.info(f"Burst traffic appears to be handled ({rate_limited} rate limited)")
                return None
        
        except Exception as e:
            logger.error(f"Burst traffic test failed: {e}")
            return None
