# agents/input_agent.py

import requests
import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlencode, urlparse, parse_qs
from html import unescape
import logging
from telemetry.logger import emit_agent_decision

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@dataclass
class Finding:
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

class InputAgent:
    def __init__(self, target_base_url: str, name: str = "InputAgent", timeout: int = 8):
        self.name = name
        self.base_url = target_base_url.rstrip('/')
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []
        
        self.sqli_payloads = [
            "' OR 1=1 --",
            "' OR '1'='1' --",
            '" OR 1=1 --',
            "' UNION SELECT NULL, NULL --",
            "' OR 'x'='x",
        ]
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        self.path_traversal_payloads = [
            "../../etc/passwd",
            "../../../../../../etc/passwd",
            "%2e%2e/%2e%2e/etc/passwd",
            "..%2f..%2fetc%2fpasswd",
        ]
        self.sensitive_files = ["root:x", "www-data", "daemon:x"]

    # ============================================================
    # ✅ NEW: Standardized Orchestrator Entry Point
    # ============================================================
    def analyze(self, api_payload: Dict[str, Any], trace_id: Optional[str] = None):
        """
        Unified entrypoint for orchestrator.
        - Parses endpoint (path + query)
        - Infers parameter name from query/body
        - Runs active input validation tests
        """
        raw_endpoint = api_payload.get("endpoint", "/")
        method = (api_payload.get("method") or "GET").upper()
        body_payload = api_payload.get("payload") or {}

        # 1) Parse the endpoint into path + query string
        parsed = urlparse(raw_endpoint)
        # e.g. "/search?q=%27%20OR%201%3D1%20--"
        #  -> path="/search", query="q=%27%20OR%201%3D1%20--"
        qs = parse_qs(parsed.query)  # {"q": ["' OR 1=1 --"]}

        # Flatten query string into simple dict {"q": "<value>"}
        query_params = {k: v[0] for k, v in qs.items()} if qs else {}

        # 2) Merge query params + body payload (body wins on key conflicts)
        merged_payload: Dict[str, Any] = {**query_params, **(body_payload or {})}

        # 3) Choose a parameter to fuzz – fall back to "q" if nothing
        parameter = next(iter(merged_payload.keys()), "q")

        # Clean endpoint path (no query)
        clean_endpoint = parsed.path or raw_endpoint

        logger.info(
            f"[InputAgent] Starting analysis for {raw_endpoint} "
            f"(clean_endpoint={clean_endpoint}, parameter={parameter}, trace_id={trace_id})"
        )

        try:
            findings = self.run_scan(
                endpoint_path=clean_endpoint,
                parameter=parameter,
                method=method,
            )

            if not findings:
                emit_agent_decision(
                    trace_id=trace_id,
                    endpoint=clean_endpoint,
                    agent=self.name,
                    rule="InputValidationCheck",
                    status="SECURE",
                    extra={"message": "No input validation issues detected"}
                )
                logger.info(f"[InputAgent] No vulnerabilities detected for {clean_endpoint}")
            else:
                for finding in findings:
                    emit_agent_decision(
                        trace_id=trace_id,
                        endpoint=finding.get("endpoint", clean_endpoint),
                        agent=self.name,
                        rule=finding.get("vuln", "InputVuln"),
                        status=finding.get("status", "VULNERABLE"),
                        extra=finding
                    )
                logger.info(f"[InputAgent] Reported {len(findings)} findings for {clean_endpoint}")

        except Exception as e:
            logger.error(f"[InputAgent] Analysis failed for {raw_endpoint}: {e}")
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=clean_endpoint,
                agent=self.name,
                rule="InputValidationError",
                status="ERROR",
                extra={"exception": str(e)}
            )

    # ============================================================
    # Existing core scan logic
    # ============================================================

    def run_scan(self, endpoint_path: str, parameter: str, method: str = "GET"):
        """
        Wrapper method called by the orchestrator to initiate the input validation scan.
        It runs all relevant tests (SQLi, XSS, Path Traversal) on the specified endpoint.
        """
        full_url = urljoin(self.base_url, endpoint_path)
        
        print(f"[{self.name}] Starting full input validation scan on: {full_url}")
        
        self.test_sqli(full_url, parameter, method)
        self.test_xss(full_url, parameter, method)
        self.test_path_traversal(full_url, parameter, method)
        
        print(f"[{self.name}] Scan completed. Found {len(self.findings)} findings.")
        return self.findings

    # --- Reporting Helper Methods ---
    def _report_vuln(self, vuln, severity, endpoint, method, actor, evidence, recommendation):
        finding_dict = asdict(Finding(
            agent=self.name, category="Input Validation", vuln=vuln, status="VULNERABLE",
            severity=severity, endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation=recommendation
        ))
        self.findings.append(finding_dict)
        emit_agent_decision(
            trace_id=(evidence or {}).get("trace_id"),
            endpoint=endpoint,
            agent=self.name,
            rule=vuln,
            status="VULNERABLE",
            extra={"method": method, "actor": actor}
        )
        return finding_dict

    def _report_secure(self, vuln, endpoint, method, actor, evidence):
        finding_dict = asdict(Finding(
            agent=self.name,
            category="Input Validation",
            vuln=vuln,
            status="SECURE",
            severity="None",
            endpoint=endpoint,
            method=method,
            actor=actor,
            evidence=evidence,
            recommendation="No issue detected for this check."
        ))
        self.findings.append(finding_dict)
        logger.info(f"[{self.name}][SECURE] {vuln} on {endpoint}")
        emit_agent_decision(
            trace_id=(evidence or {}).get("trace_id"),
            endpoint=endpoint,
            agent=self.name,
            rule=vuln,
            status="SECURE",
            extra={"method": method, "actor": actor}
        )
        return finding_dict

    def _report_error(self, vuln, endpoint, method, actor, details="Request/transport error"):
        finding_dict = asdict(Finding(
            agent=self.name, category="Input Validation", vuln=vuln, status="ERROR",
            severity="Unknown", endpoint=endpoint, method=method, actor=actor,
            evidence={"details": details}, recommendation="Verify endpoint availability and configuration."
        ))
        self.findings.append(finding_dict)
        return finding_dict

    def _make_request(self, url, method, data):
        try:
            if '{' in url and '}' in url and data:
                path_key = next(iter(data.keys()), None)
                if path_key:
                    url = url.format(**{path_key: data[path_key]})
                response = requests.get(url, timeout=self.timeout)
            elif method.upper() == "GET":
                response = requests.get(url, params=data, timeout=self.timeout)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, timeout=self.timeout)
            else:
                return None, f"Unsupported method: {method}"
            return response, None
        except requests.exceptions.RequestException as e:
            return None, f"Request error: {e}"
        except Exception as e:
            return None, f"General error during request: {e}"

    def test_sqli(self, url: str, parameter: str, method: str = "GET"):
        sql_error_indicators = [
            "sql syntax", "sql error", "database error", "exception", 
            "unclosed quotation", "an error occurred", "access_token"
        ]
        for payload in self.sqli_payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                logger.error(f"SQLi test failed on {url}: {err}")
                continue
            if response and response.status_code == 200 and (
                any(ind.lower() in response.text.lower() for ind in sql_error_indicators)
            ):
                return self._report_vuln(
                    "SQL Injection", "Critical", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Use parameterized queries or prepared statements; validate and sanitize all inputs."
                )
        self._report_secure("SQL Injection", url, method, "payloads", {"note": "No SQLi payloads were successful."})

    def test_xss(self, url: str, parameter: str, method: str = "GET"):
        def check_payload_in_json(obj, payload):
            if isinstance(obj, dict):
                return any(check_payload_in_json(v, payload) for v in obj.values())
            elif isinstance(obj, list):
                return any(check_payload_in_json(item, payload) for item in obj)
            elif isinstance(obj, str):
                return payload in unescape(obj)
            return False
        for payload in self.xss_payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                return self._report_error("XSS", url, method, "payloads", err)
            vulnerable = False
            if response and response.status_code == 200:
                try:
                    json_resp = response.json()
                    if check_payload_in_json(json_resp, payload):
                        vulnerable = True
                except ValueError:
                    if payload in unescape(response.text):
                        vulnerable = True
            if vulnerable:
                return self._report_vuln(
                    "XSS (Reflected)", "Medium", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Implement strict Content Security Policies (CSP) and ensure all user-controlled data is properly output encoded/escaped."
                )
        self._report_secure("XSS", url, method, "payloads", {"note": "No payloads reflected in response."})

    def test_path_traversal(self, url: str, parameter: str, method: str = "GET"):
        test_file_payloads = ["../../app.py", "../README.md"]
        payloads = self.path_traversal_payloads + test_file_payloads
        for payload in payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                return self._report_error("Path Traversal", url, method, "payloads", err)
            if response and response.status_code == 200 and (
                any(sens.lower() in response.text.lower() for sens in self.sensitive_files)
            ):
                return self._report_vuln(
                    "Path Traversal", "Critical", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Validate and sanitize file path inputs; restrict file access to intended directories."
                )
        self._report_secure("Path Traversal", url, method, "payloads", {"note": "No path traversal payloads succeeded."})


if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001"
    TEST_ENDPOINT_PATH = "/rest/user/login"
    TEST_PARAMETER = "email"
    TEST_METHOD = "POST"
    
    print("=====================================================")
    print(f"🛡️ Running InputAgent Standalone Scan on: {TEST_ENDPOINT_PATH}")
    print("=====================================================")
    
    agent = InputAgent(target_base_url=TEST_TARGET_BASE_URL)
    try:
        findings = agent.run_scan(TEST_ENDPOINT_PATH, TEST_PARAMETER, TEST_METHOD)
        print("\n--- InputAgent Scan Complete ---")
        if findings:
            print(f"Found {len(findings)} Security Findings:")
            for finding in findings:
                print(f"  [{finding.get('severity', 'N/A')}] {finding.get('vuln', 'N/A')} on {finding.get('endpoint', 'N/A')}")
        else:
            print("No security findings reported.")
    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"InputAgent failed during execution: {e}")
