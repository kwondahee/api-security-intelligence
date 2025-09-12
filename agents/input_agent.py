import requests
import json
from dataclasses import dataclass, asdict
from typing import Dict, Any, List
from urllib.parse import urljoin, urlencode
from html import unescape

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
    def __init__(self, name: str = "InputAgent", timeout: int = 8):
        self.name = name
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

    # --- Reporting Helper Methods ---
    def _report_vuln(self, vuln, severity, endpoint, method, actor, evidence, recommendation):
        f = Finding(
            agent=self.name, category="Input Validation", vuln=vuln, status="VULNERABLE",
            severity=severity, endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation=recommendation
        )
        self.findings.append(asdict(f))
        return asdict(f)

    def _report_secure(self, vuln, endpoint, method, actor, evidence):
        f = Finding(
            agent=self.name, category="Input Validation", vuln=vuln, status="SECURE",
            severity="None", endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation="No issue detected for this check."
        )
        self.findings.append(asdict(f))
        return asdict(f)

    def _report_error(self, vuln, endpoint, method, actor, details="Request/transport error"):
        f = Finding(
            agent=self.name, category="Input Validation", vuln=vuln, status="ERROR",
            severity="Unknown", endpoint=endpoint, method=method, actor=actor,
            evidence={"details": details}, recommendation="Verify endpoint availability and configuration."
        )
        self.findings.append(asdict(f))
        return asdict(f)

    # --- Request Helper Method ---
    def _make_request(self, url, method, data):
        """Helper to make a request and handle common errors."""
        try:
            if '{' in url and '}' in url:
                url = url.format(**data)
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

    # --- Vulnerability Test Methods ---
    def test_sqli(self, url: str, parameter: str, method: str = "GET"):
        """Tests for SQL Injection vulnerability."""
        print(f"[{self.name}] Testing SQL Injection on {url} (method: {method})...")
        sql_error_indicators = [
            "sql syntax", "sql error", "database error", "exception", 
            "unclosed quotation", "an error occurred", "access_token"
        ]
        
        # Test for error-based SQLi (like in VAmPI)
        for payload in self.sqli_payloads:
            data = {parameter: payload}
            response, err = self._make_request(url, method, data)
            if err:
                continue

            if response and response.status_code == 200 and (
                any(ind.lower() in response.text.lower() for ind in sql_error_indicators)
            ):
                return self._report_vuln(
                    "SQL Injection", "High", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Use parameterized queries or prepared statements."
                )

        # Test for logic-based SQLi (like in Juice Shop)
        try:
            # 1. Get baseline count
            baseline_data = {parameter: "a"}
            baseline_response = requests.get(url, params=baseline_data, timeout=self.timeout)
            baseline_count = len(baseline_response.json().get('data', []))

            # 2. Get injected count
            injected_payload = "' OR 1=1 --"
            injected_data = {parameter: injected_payload}
            injected_response = requests.get(url, params=injected_data, timeout=self.timeout)
            injected_count = len(injected_response.json().get('data', []))

            if injected_count > baseline_count:
                 return self._report_vuln(
                    "SQL Injection", "High", url, method, "payloads",
                    {"payload": injected_payload, "response_status": injected_response.status_code, "note": f"Malicious query returned {injected_count} results, which is more than the baseline of {baseline_count}."},
                    "Use parameterized queries or prepared statements."
                )

        except (requests.exceptions.RequestException, json.JSONDecodeError):
            pass

        return self._report_secure("SQL Injection", url, method, "payloads", {"note": "No SQLi payloads were successful."})


    def test_xss(self, url: str, parameter: str, method: str = "GET"):
        """Tests for Cross-Site Scripting (XSS) vulnerability."""
        print(f"[{self.name}] Testing XSS on {url} (method: {method})...")
        
        def check_payload_in_json(obj, payload):
            """Recursively check if payload exists in JSON response."""
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
            if response.status_code == 200:
                try:
                    json_resp = response.json()
                    if check_payload_in_json(json_resp, payload):
                        vulnerable = True
                except ValueError:
                    if payload in unescape(response.text):
                        vulnerable = True

            if vulnerable:
                return self._report_vuln(
                    "XSS", "Medium", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Implement strict Content Security Policies (CSP) and output encoding."
                )
        
        return self._report_secure("XSS", url, method, "payloads", {"note": "No payloads reflected in response."})


    def test_path_traversal(self, url: str, parameter: str, method: str = "GET"):
        """Tests for Path Traversal vulnerability."""
        print(f"[{self.name}] Testing Path Traversal on {url} (method: {method})...")
        
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
            
            if response.status_code == 200 and (
                any(sens.lower() in response.text.lower() for sens in self.sensitive_files) or
                "an error occurred" in response.text.lower()
            ):
                return self._report_vuln(
                    "Path Traversal", "Critical", url, method, "payloads",
                    {"payload": payload, "response_status": response.status_code, "response_body_sample": response.text[:300]},
                    "Validate and sanitize file path inputs; use canonicalization."
                )
        
        return self._report_secure("Path Traversal", url, method, "payloads", {"note": "No path traversal payloads succeeded."})
    
    def test_all_endpoints(self, endpoints: List[Dict[str, str]]):
        """Runs all relevant tests against a list of endpoints."""
        print("--- Running Full API Scan ---")
        for ep in endpoints:
            url = ep.get('url')
            parameter = ep.get('parameter')
            method = ep.get('method', 'GET')
            
            self.test_sqli(url, parameter, method)
            self.test_xss(url, parameter, method)
            self.test_path_traversal(url, parameter, method)
        
        print("\n--- All tests completed ---")

# Example Usage
if __name__ == '__main__':
    agent = InputAgent()
    
    # Define the endpoints for both VAmPI and Juice Shop
    all_endpoints_to_scan = [
        # --- VAmPI Endpoints (requires `docker run -e vulnerable=1 -p 5001:5000 erev0s/vampi`) ---
        # {"url": "http://localhost:5001/books/v1/{book_title}", "parameter": "book_title", "method": "GET"},
        # {"url": "http://localhost:5001/users/v1/login", "parameter": "username", "method": "POST"},
        
        # --- OWASP Juice Shop Endpoint (requires `docker run -p 3000:3000 bkimminich/juice-shop`) ---
        {"url": "http://localhost:3000/rest/products/search", "parameter": "q", "method": "GET"},
    ]

    # Run a full scan against all defined endpoints
    agent.test_all_endpoints(endpoints=all_endpoints_to_scan)
    
    # Access and print all findings
    print("\n--- All Agent Findings ---")
    print(json.dumps(agent.findings, indent=2))