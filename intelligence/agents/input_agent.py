# agents/input_agent.py

import requests
import json
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlencode
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

    # --- ORCHESTRATOR ENTRY POINT ---
    def run_scan(self, endpoint_path: str, parameter: str, method: str = "GET"):
        """
        Wrapper method called by the orchestrator to initiate the input validation scan.
        It runs all relevant tests (SQLi, XSS, Path Traversal) on the specified endpoint.
        """
        # Construct the full URL for the tests
        full_url = urljoin(self.base_url, endpoint_path)
        
        print(f"[{self.name}] Starting full input validation scan on: {full_url}")
        
        # Run all input validation tests
        self.test_sqli(full_url, parameter, method)
        self.test_xss(full_url, parameter, method)
        self.test_path_traversal(full_url, parameter, method)
        
        print(f"[{self.name}] Scan completed. Found {len(self.findings)} findings.")
        return self.findings

    # --- Reporting Helper Methods ---
    # The reporting methods are simplified to return the final list of dicts.
    def _report_vuln(self, vuln, severity, endpoint, method, actor, evidence, recommendation):
        # We store the finding as a dictionary directly for easy orchestrator consumption
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
        """
        Record a SECURE finding. We append to self.findings so the runner
        can produce a full audit showing which tests were executed.
        """
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
        # Append secure check to findings so the output file records the test
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

    # --- Request Helper Method ---
    def _make_request(self, url, method, data):
        """Helper to make a request and handle common errors."""
        try:
            # Check for URL path parameter substitution (e.g., /books/v1/{book_title})
            if '{' in url and '}' in url and data:
                # The data dict must contain the key for the URL path parameter
                
                # Check if the key in 'data' is the one being used in the path
                path_key = next(iter(data.keys()), None) # Get the first key in the data dict
                
                # Format the URL path template with the value from the data dict
                # Example: url.format(book_title=payload_value)
                if path_key:
                    url = url.format(**{path_key: data[path_key]})
                
                # The actual request is now a simple GET since the data is in the path
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

    # --- Vulnerability Test Methods ---
    def test_sqli(self, url: str, parameter: str, method: str = "GET"):
        """Tests for SQL Injection vulnerability."""
        sql_error_indicators = [
            "sql syntax", "sql error", "database error", "exception", 
            "unclosed quotation", "an error occurred", "access_token"
        ]
        
        # Test for error-based SQLi (or successful logic-based)
        for payload in self.sqli_payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                logger.error(f"SQLi test failed on {url}: {err}")
                continue

            # Check for generic error indicators (VAmPI style)
            if response and response.status_code == 200 and (
                any(ind.lower() in response.text.lower() for ind in sql_error_indicators)
            ):
                return self._report_vuln(
                    "SQL Injection", "Critical", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Use parameterized queries or prepared statements; validate and sanitize all inputs."
                )

        # Test for logic-based SQLi (Juice Shop style - comparison is difficult without knowing baseline)
        try:
            # Only perform this comparison if the method is GET and expected to return JSON data
            if method.upper() == 'GET':
                # Attempt to retrieve baseline and injected counts (simulated)
                baseline_data = {parameter: "test"}
                baseline_response, _ = self._make_request(url, method, baseline_data)

                injected_payload = "' OR 1=1 --"
                injected_data = {parameter: injected_payload}
                injected_response, _ = self._make_request(url, method, injected_data)
                
                # A successful injection will often return *more* results or sensitive data
                if injected_response and injected_response.status_code == 200:
                    try:
                        baseline_data = baseline_response.json().get('data', [])
                        injected_data = injected_response.json().get('data', [])
                        
                        baseline_count = len(baseline_data) if isinstance(baseline_data, list) else 0
                        injected_count = len(injected_data) if isinstance(injected_data, list) else 0

                        # We report if the malicious query returns significantly more results (heuristic)
                        if injected_count > baseline_count and injected_count > 1:
                            return self._report_vuln(
                                "SQL Injection (Logic-based)", "High", url, method, "payloads",
                                {"payload": injected_payload, "note": f"Malicious query returned {injected_count} results, potentially bypassing logic."},
                                "Use parameterized queries or prepared statements; strictly enforce input type and length."
                            )
                    except (json.JSONDecodeError, AttributeError):
                        # The response wasn't a list of data, skip this check
                        pass

        except Exception as e:
            logger.error(f"Logic-based SQLi comparison failed: {e}")
            pass
        
        self._report_secure("SQL Injection", url, method, "payloads", {"note": "No SQLi payloads were successful."})


    def test_xss(self, url: str, parameter: str, method: str = "GET"):
        """Tests for Cross-Site Scripting (XSS) vulnerability."""
        def check_payload_in_json(obj, payload):
            """Recursively check if payload exists in JSON response."""
            if isinstance(obj, dict):
                return any(check_payload_in_json(v, payload) for v in obj.values())
            elif isinstance(obj, list):
                return any(check_payload_in_json(item, payload) for item in obj)
            elif isinstance(obj, str):
                # Check for reflection, unescaping HTML entities first
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
                    # Not JSON, check raw text
                    if payload in unescape(response.text):
                        vulnerable = True

            if vulnerable:
                return self._report_vuln(
                    "XSS (Reflected)", "Medium", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Implement strict Content Security Policies (CSP) and ensure all user-controlled data is properly output encoded/escaped before rendering."
                )
        
        self._report_secure("XSS", url, method, "payloads", {"note": "No payloads reflected in response."})


    def test_path_traversal(self, url: str, parameter: str, method: str = "GET"):
        """Tests for Path Traversal vulnerability."""
        test_file_payloads = [
            "../../app.py",
            "../README.md"
        ]
        payloads = self.path_traversal_payloads + test_file_payloads
        
        for payload in payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                return self._report_error("Path Traversal", url, method, "payloads", err)
            
            # Check for success indicators: status 200/400/500 + sensitive file content 
            # or known error messages indicating a failed path validation attempt.
            if response and response.status_code == 200 and (
                any(sens.lower() in response.text.lower() for sens in self.sensitive_files) 
            ):
                return self._report_vuln(
                    "Path Traversal", "Critical", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Validate and sanitize file path inputs; use canonicalization; restrict file access to the intended directory."
                )
        
        self._report_secure("Path Traversal", url, method, "payloads", {"note": "No path traversal payloads succeeded."})

    
# --- DELETED BLOCK: Removed the entire if __name__ == '__main__': block ---
# --- EXECUTION BLOCK FOR STANDALONE TESTING (Juice Shop) ---
if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    
    # # Target the vulnerable search endpoint in Juice Shop
    # TEST_ENDPOINT_PATH = "/rest/products/search" 
    # # The search parameter that accepts the user input
    # TEST_PARAMETER = "q"          
    # TEST_METHOD = "GET"
    TEST_ENDPOINT_PATH = "/rest/user/login"
    TEST_PARAMETER = "email"
    TEST_METHOD = "POST"
    
    print("=====================================================")
    print(f"🛡️ Running InputAgent Standalone Scan on: {TEST_ENDPOINT_PATH}")
    print("=====================================================")
    
    # 1. Initialize the Agent (assuming the class is InputAgent)
    # NOTE: Ensure InputAgent is correctly imported and accepts base_url
    agent = InputAgent(target_base_url=TEST_TARGET_BASE_URL)
    
    # 2. Run the specific scan
    try:
        # The agent will construct the full URL: http://localhost:5001/rest/products/search?q=PAYLOAD
        findings = agent.run_scan(
            endpoint_path=TEST_ENDPOINT_PATH, 
            parameter=TEST_PARAMETER,
            method=TEST_METHOD
        )
        
        # 3. Print the results
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
