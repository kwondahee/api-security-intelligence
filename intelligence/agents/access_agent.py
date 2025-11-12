import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List
import requests
import logging
from telemetry.logger import emit_agent_decision

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

@dataclass
class Finding:
    """Dataclass used exclusively by AccessAgent for Authorization findings."""
    agent: str
    category: str              # e.g., "Authorization"
    vuln: str                  # e.g., "BOLA", "BFLA"
    status: str                # VULNERABLE | SECURE | ERROR
    severity: str              # Low/Med/High/Critical
    endpoint: str
    method: str
    actor: str                 # which token/role used
    evidence: Dict[str, Any]   # redacted snippets, response meta
    recommendation: str


class AccessAgent:
    def __init__(self, target_base_url: str, name: str = "AccessAgent", timeout: int = 8):
        self.name = name
        self.base_url = target_base_url
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []
        self.session = requests.Session()
        logger.info(f"AccessAgent initialized for target: {self.base_url}")

    # --- UNIFIED ENTRY POINT (for orchestrator) ---
    def analyze(self, api_payload: Dict[str, Any], trace_id: Optional[str]) -> List[Dict[str, Any]]:
        """
        Unified entry point for orchestrator-triggered authorization analysis.
        Wraps run_scan() and emits telemetry events.
        """
        target_resource = api_payload.get("target_resource") or api_payload.get("endpoint") or "/"
        logger.info(f"[{self.name}] Starting authorization scan for {target_resource} (trace_id={trace_id})")

        try:
            findings = self.run_scan(target_resource)

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
                            "actor": finding.get("actor"),
                            "recommendation": finding.get("recommendation")
                        }
                    )
            else:
                emit_agent_decision(
                    trace_id=trace_id,
                    endpoint=target_resource,
                    agent=self.name,
                    rule="AuthorizationChecks",
                    status="SECURE",
                    extra={"message": "No authorization vulnerabilities found."}
                )

            return findings

        except Exception as e:
            logger.error(f"[{self.name}] analyze() failed: {e}", exc_info=True)
            emit_agent_decision(
                trace_id=trace_id,
                endpoint=target_resource,
                agent=self.name,
                rule="AgentError",
                status="ERROR",
                extra={"exception": str(e)}
            )
            return []

    # --- ORCHESTRATOR ENTRY POINT (ACTIVATED TESTS) ---
    def run_scan(self, target_resource: str):
        """
        Wrapper method called by the orchestrator to initiate authorization tests.
        """
        print(f"[ACCESS AGENT] Initiating Authorization tests for: {target_resource}")
        self.findings = []  # Reset findings

        MOCK_BASE = self.base_url
        MOCK_USER_A_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." 
        MOCK_USER_B_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." 
        MOCK_ADMIN_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." 
        
        # --- Test 1: Broken Object Level Authorization (BOLA) ---
        profile_path = "/rest/user/{id}"
        print(f"[ACCESS AGENT] Testing BOLA on '{profile_path}'...")
        self.test_bola(
            base=MOCK_BASE,
            path_template=profile_path,
            actor_token=MOCK_USER_A_TOKEN,
            authorized_id="24",
            unauthorized_id="1",
            method="GET"
        )
        
        # --- Test 2: Broken Function Level Authorization (BFLA) ---
        admin_path = "/rest/users"
        print(f"[ACCESS AGENT] Testing BFLA on '{admin_path}'...")
        self.test_bfla(
            base=MOCK_BASE,
            admin_only_path=admin_path,
            low_priv_token=MOCK_USER_A_TOKEN,
            method="GET"
        )
        
        # --- Test 3: Tenant Escape ---
        self.test_tenant_escape(
            base=MOCK_BASE,
            path_template="/v2/tenant/{tenantId}/resources/{id}",
            token_a=MOCK_USER_A_TOKEN,
            token_b=MOCK_USER_B_TOKEN,
            tenant_id_a="T001",
            resource_in_a="R101",
            method="GET"
        )
        
        return self.findings

    # --- helpers ---
    def _req(self, method: str, url: str, token: str, json_body: Optional[dict] = None):
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            r = self.session.request(method, url, headers=headers, json=json_body, timeout=self.timeout)
            meta = {
                "status": r.status_code,
                "len": int(r.headers.get("Content-Length", "0") or 0),
                "cache": r.headers.get("Cache-Control"),
                "etag": r.headers.get("ETag"),
            }
            try:
                body = r.json()
            except Exception:
                body = {"_non_json_sample": r.text[:300]}
            return r, meta, body
        except requests.RequestException as e:
            logger.error(f"Request error for {url}: {e}")
            return None, None, {"error": str(e)}

    def _is_forbidden(self, status: int, body: dict) -> bool:
        return status in (401, 403) or ("not authorized" in json.dumps(body).lower())

    def _redact(self, body: dict, fields: List[str] = ("token", "password", "secret", "key")) -> dict:
        redacted = {}
        if isinstance(body, dict):
            for k, v in body.items():
                redacted[k] = "***" if any(k.lower() == f for f in fields) else v
            return redacted
        return body

    def _looks_like_same_resource(self, body_a: Any, body_b: Any) -> bool:
        if not isinstance(body_a, dict) or not isinstance(body_b, dict):
            return False
        keys_a, keys_b = set(body_a.keys()), set(body_b.keys())
        common = len(keys_a & keys_b)
        return common >= max(3, min(len(keys_a), len(keys_b)) // 2)

    def _report_vuln(self, vuln, severity, endpoint, method, actor, evidence, recommendation):
        f = Finding(
            agent=self.name, category="Authorization", vuln=vuln, status="VULNERABLE",
            severity=severity, endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation=recommendation
        )
        self.findings.append(asdict(f))
        logger.warning(f"  [VULNERABLE: {vuln}] {endpoint} by {actor}")

        emit_agent_decision(
            trace_id=(evidence or {}).get("trace_id"),
            endpoint=endpoint,
            agent=self.name,
            rule=vuln,
            status="VULNERABLE",
            extra={"method": method, "actor": actor}
        )

        return asdict(f)

    def _report_secure(self, vuln, endpoint, method, actor, evidence):
        f = Finding(
            agent=self.name, category="Authorization", vuln=vuln, status="SECURE",
            severity="None", endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation="No issue detected for this check."
        )
        self.findings.append(asdict(f))
        logger.info(f"  [SECURE: {vuln}] {endpoint}")
        
        emit_agent_decision(
            trace_id=(evidence or {}).get("trace_id"),
            endpoint=endpoint,
            agent=self.name,
            rule=vuln,
            status="SECURE",
            extra={"method": method, "actor": actor}
        )

        return asdict(f)

    def _report_error(self, vuln, endpoint, method, actor):
        f = Finding(
            agent=self.name, category="Authorization", vuln=vuln, status="ERROR",
            severity="Unknown", endpoint=endpoint, method=method, actor=actor,
            evidence={"details": "Request/transport error. Check network/target availability."}, 
            recommendation="Verify endpoint availability and credentials."
        )
        self.findings.append(asdict(f))
        logger.error(f"  [ERROR: {vuln}] {endpoint} - Check target.")
        return asdict(f)

    # --- functional tests ---
    def test_bola(self, base: str, path_template: str, actor_token: str,
                  authorized_id: str, unauthorized_id: str, method: str = "GET"):
        endpoint_authz = base + path_template.format(id=authorized_id)
        endpoint_unauthz = base + path_template.format(id=unauthorized_id)

        r_ok, meta_ok, body_ok = self._req(method, endpoint_authz, actor_token)
        if r_ok is None:
            return self._report_error("BOLA", endpoint_authz, method, "self")

        r_bad, meta_bad, body_bad = self._req(method, endpoint_unauthz, actor_token)
        if r_bad is None:
            return self._report_error("BOLA", endpoint_unauthz, method, "self→other")

        forbidden = self._is_forbidden(r_bad.status_code, body_bad)
        looks_like_same_object = self._looks_like_same_resource(body_ok, body_bad)

        if not forbidden and looks_like_same_object:
            return self._report_vuln(
                vuln="BOLA", severity="CRITICAL", endpoint=endpoint_unauthz, method=method,
                actor="standard-user",
                evidence={"unauth_status": r_bad.status_code, "note": "Unauthorized ID returned similar resource.", "sample": self._redact(body_bad)},
                recommendation="Enforce object-level authorization checks using the user ID from the authentication token."
            )
        else:
            return self._report_secure(vuln="BOLA", endpoint=endpoint_unauthz, method=method, actor="standard-user", evidence={"unauth_status": r_bad.status_code})

    def test_bfla(self, base: str, admin_only_path: str, low_priv_token: str, method: str = "POST",
                  payload: Optional[dict] = None):
        endpoint = base + admin_only_path
        r, meta, body = self._req(method, endpoint, low_priv_token, json_body=payload or {})
        if r is None:
            return self._report_error("BFLA", endpoint, method, "low-priv")

        if not self._is_forbidden(r.status_code, body):
            return self._report_vuln(
                vuln="BFLA", severity="CRITICAL", endpoint=endpoint, method=method,
                actor="low-priv",
                evidence={"status": r.status_code, "body_sample": self._redact(body)},
                recommendation="Enforce strict role/permission checks before executing high-privilege functions."
            )
        else:
            return self._report_secure(vuln="BFLA", endpoint=endpoint, method=method, actor="low-priv", evidence={"status": r.status_code})

    def test_tenant_escape(self, base: str, path_template: str, token_a: str, token_b: str, tenant_id_a: str,
                           resource_in_a: str, method: str = "GET"):
        url = base + path_template.format(tenantId=tenant_id_a, id=resource_in_a)
        
        r_a, _, body_a = self._req(method, url, token_a)
        r_b, _, body_b = self._req(method, url, token_b)

        if r_a is None or r_b is None:
            return self._report_error("TenantEsc", url, method, "cross-tenant")

        forbidden = self._is_forbidden(r_b.status_code, body_b)
        similar = self._looks_like_same_resource(body_a, body_b)

        if not forbidden and similar:
            return self._report_vuln(
                vuln="TenantEscape", severity="HIGH", endpoint=url, method=method,
                actor="other-tenant",
                evidence={"other_tenant_status": r_b.status_code, "sample": self._redact(body_b)},
                recommendation="Enforce tenant scoping (tenantId from token/claims) for all data queries."
            )
        else:
            return self._report_secure(vuln="TenantEscape", endpoint=url, method=method, actor="other-tenant", evidence={"other_tenant_status": r_b.status_code})


# --- EXECUTION BLOCK FOR STANDALONE TESTING ---
if __name__ == "__main__":
    TEST_TARGET_BASE_URL = "http://localhost:5001" 
    TEST_RESOURCE = "/rest/user/1" 
    
    print("=====================================================")
    print(f"🔒 Running AccessAgent Standalone Scan on: {TEST_RESOURCE}")
    print("=====================================================")
    
    agent = AccessAgent(target_base_url=TEST_TARGET_BASE_URL)
    
    try:
        findings = agent.run_scan(target_resource=TEST_RESOURCE)
        print("\n--- AccessAgent Scan Complete ---")
        if findings:
            print(f"Found {len(findings)} Security Findings:")
            for finding in findings:
                print(f"  [{finding.get('severity', 'N/A')}] {finding.get('vuln', 'N/A')} on {finding.get('endpoint', 'N/A')}")
        else:
            print("No security findings reported.")
    except Exception as e:
        print(f"\n!!! STANDALONE AGENT CRITICAL ERROR !!!")
        print(f"AccessAgent failed during execution: {e}")
