"""
Rate Limiting Detection Agent - Optimized Version (Fixed)
Tests for missing or inadequate rate limiting controls.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import logging
import time
import requests
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urljoin
from telemetry.logger import emit_agent_decision


logger = logging.getLogger(__name__)


class RateAgent:
    """Agent for detecting rate limiting vulnerabilities."""

    def __init__(self, target_base_url: str):
        self.target_base_url = target_base_url.rstrip('/')

        # Optimized session with connection pooling
        self.session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20,
            pool_block=False
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.timeout = 2

        logger.info(f"RateAgent initialized for target: {self.target_base_url}")

    def __del__(self):
        """Clean up session on deletion."""
        if hasattr(self, 'session'):
            self.session.close()

    # ============================================================
    # ✅ Unified orchestrator entrypoint
    # ============================================================
    def analyze(self, api_payload: Dict[str, Any], trace_id: Optional[str] = None):
        """
        Unified entrypoint for orchestrator.
        Runs rate limit tests and logs results.
        """
        endpoint = api_payload.get("endpoint", "/")
        method = api_payload.get("method", "GET")

        # Normalize endpoint
        if not endpoint.startswith("http"):
            endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"

        logger.info(f"[RateAgent] Starting analysis for {endpoint} (trace_id={trace_id})")

        try:
            findings = self.run_scan(endpoint_path=endpoint, method=method)

            if not findings:
                logger.info(f"[RateAgent] No vulnerabilities detected for {endpoint}")
                emit_agent_decision(
                    trace_id=trace_id,
                    endpoint=endpoint,
                    agent="RateAgent",
                    rule="RateLimitCheck",
                    status="SECURE",
                    extra={"result": "No vulnerabilities found"}
                )
            else:
                logger.info(f"[RateAgent] Found {len(findings)} potential issues for {endpoint}")
                for finding in findings:
                    emit_agent_decision(
                        trace_id=trace_id,
                        endpoint=finding.get("endpoint", endpoint),
                        agent="RateAgent",
                        rule=finding.get("rule", "RateLimitIssue"),
                        status=finding.get("status", "VULNERABLE"),
                        extra=finding
                    )

        except Exception as e:
            logger.error(f"[RateAgent] Analysis failed for {endpoint}: {e}")
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=endpoint,
                agent="RateAgent",
                rule="RateLimitCheck",
                status="ERROR",
                extra={"exception": str(e)}
            )

    # ============================================================
    # Core scan logic
    # ============================================================

    def run_scan(self, endpoint_path: str, method: str = "GET") -> List[Dict[str, Any]]:
        """Execute all rate limiting tests."""
        findings = []

        basic_finding = self._test_basic_rate_limit(endpoint_path, method)
        if basic_finding:
            findings.append(basic_finding)

        burst_finding = self._test_burst_traffic(endpoint_path, method)
        if burst_finding:
            findings.append(burst_finding)

        return findings

    # ============================================================
    # ✅ Fixed URL joining logic here
    # ============================================================
    def _resolve_url(self, endpoint_path: str) -> str:
        """Safely construct full URL using urljoin."""
        if endpoint_path.startswith("http"):
            return endpoint_path
        return urljoin(f"{self.target_base_url}/", endpoint_path.lstrip("/"))

    # ============================================================
    # Basic Rate Limit Test
    # ============================================================
    def _test_basic_rate_limit(self, endpoint_path: str, method: str) -> Optional[Dict[str, Any]]:
        """Test if basic rate limiting is implemented."""
        full_url = self._resolve_url(endpoint_path)
        logger.info(f"Testing basic rate limiting for {full_url}")

        num_requests = 30
        status_codes = []
        start_time = time.time()

        try:
            for i in range(num_requests):
                try:
                    response = self.session.request(method, full_url, timeout=self.timeout)
                    status_codes.append(response.status_code)

                    if response.status_code == 429:
                        logger.info(f"Rate limiting detected at request {i+1}")
                        return None  # ✅ rate limiting present

                    time.sleep(0.01)

                except requests.Timeout:
                    logger.warning(f"Request {i+1} timed out")
                    status_codes.append('timeout')
                except requests.ConnectionError as e:
                    logger.error(f"Connection error at request {i+1}: {e}")
                    if i < 5:
                        return None
                    break
                except Exception as e:
                    logger.error(f"Request {i+1} failed: {e}")
                    status_codes.append('error')

            elapsed = time.time() - start_time
            success_count = status_codes.count(200)

            logger.info(f"Rate limit test: {success_count}/{num_requests} successful in {elapsed:.1f}s")

            if success_count >= num_requests * 0.9:
                return {
                    "agent": "RateAgent",
                    "rule": "NoRateLimit",
                    "vuln": "Missing Rate Limiting",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "endpoint": endpoint_path,
                    "method": method,
                    "details": f"Sent {num_requests} requests in {elapsed:.1f}s. {success_count} succeeded without rate limiting.",
                    "recommendation": "Implement rate limiting with token bucket or sliding window algorithm.",
                    "evidence": {
                        "requests_sent": num_requests,
                        "successful": success_count,
                        "duration_seconds": round(elapsed, 2),
                        "rate_limited": False
                    }
                }

            return None

        except Exception as e:
            logger.error(f"Basic rate limit test failed: {e}")
            return None

    # ============================================================
    # Burst Traffic Test
    # ============================================================
    def _test_burst_traffic(self, endpoint_path: str, method: str) -> Optional[Dict[str, Any]]:
        """Test handling of burst traffic using concurrent requests."""
        full_url = self._resolve_url(endpoint_path)
        logger.info(f"Testing burst traffic handling for {full_url}")

        burst_size = 15

        def make_request():
            try:
                response = self.session.request(method, full_url, timeout=self.timeout)
                return response.status_code
            except requests.Timeout:
                return 'timeout'
            except requests.ConnectionError:
                return 'connection_error'
            except Exception:
                return 'error'

        try:
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=burst_size) as executor:
                futures = [executor.submit(make_request) for _ in range(burst_size)]
                results = [f.result() for f in as_completed(futures, timeout=10)]

            elapsed = time.time() - start_time
            success_count = results.count(200)
            rate_limited = results.count(429)

            logger.info(f"Burst test: {success_count}/{burst_size} successful, {rate_limited} rate limited in {elapsed:.1f}s")

            if rate_limited == 0 and success_count >= burst_size * 0.8:
                return {
                    "agent": "RateAgent",
                    "rule": "BurstNoLimit",
                    "vuln": "Inadequate Burst Traffic Handling",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "endpoint": endpoint_path,
                    "method": method,
                    "details": f"Burst of {burst_size} concurrent requests completed in {elapsed:.1f}s without rate limiting.",
                    "recommendation": "Implement burst detection and throttling with leaky bucket algorithm.",
                    "evidence": {
                        "burst_size": burst_size,
                        "successful": success_count,
                        "rate_limited": rate_limited,
                        "duration_seconds": round(elapsed, 2)
                    }
                }

            return None

        except Exception as e:
            logger.error(f"Burst traffic test failed: {e}")
            return None
