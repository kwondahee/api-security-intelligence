import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List
import requests

@dataclass
class Finding:
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
    def __init__(self, name: str = "AccessAgent", timeout: int = 8):
        self.name = name
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []

    # --- helpers ---
    def _req(self, method: str, url: str, token: str, json_body: Optional[dict] = None):
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            r = requests.request(method, url, headers=headers, json=json_body, timeout=self.timeout)
            meta = {
                "status": r.status_code,
                "len": int(r.headers.get("Content-Length", "0") or 0),
                "cache": r.headers.get("Cache-Control"),
                "etag": r.headers.get("ETag"),
            }
            # try to parse JSON safely without logging secrets
            try:
                body = r.json()
            except Exception:
                body = {"_non_json_sample": r.text[:300]}
            return r, meta, body
        except requests.RequestException as e:
            return None, None, {"error": str(e)}

    def _is_forbidden(self, status: int, body: dict) -> bool:
        # Treat 401/403 as forbidden. Some APIs return 404 for unauthorized object discovery.
        return status in (401, 403) or ("not authorized" in json.dumps(body).lower())

    def _redact(self, body: dict, fields: List[str] = ("token", "password", "secret", "key")) -> dict:
        # shallow redaction
        redacted = {}
        for k, v in (body.items() if isinstance(body, dict) else []):
            redacted[k] = "***" if any(k.lower() == f for f in fields) else v
        return redacted if redacted else body

    # --- tests ---
    def test_bola(self, base: str, path_template: str, actor_token: str,
                  authorized_id: str, unauthorized_id: str, method: str = "GET"):
        """
        path_template example: '/api/users/{id}'
        """
        endpoint_authz = base + path_template.format(id=authorized_id)
        endpoint_unauthz = base + path_template.format(id=unauthorized_id)

        # Establish the "allowed" baseline for the actor on their OWN resource
        r_ok, meta_ok, body_ok = self._req(method, endpoint_authz, actor_token)
        if r_ok is None:
            return self._report_error("BOLA", endpoint_authz, method, "self")

        # Now try to access someone else’s object
        r_bad, meta_bad, body_bad = self._req(method, endpoint_unauthz, actor_token)
        if r_bad is None:
            return self._report_error("BOLA", endpoint_unauthz, method, "self→other")

        # Decision: consider both status and content similarity
        forbidden = self._is_forbidden(r_bad.status_code, body_bad)
        looks_like_same_object = self._looks_like_same_resource(body_ok, body_bad)

        if not forbidden and looks_like_same_object:
            return self._report_vuln(
                vuln="BOLA",
                severity="High",
                endpoint=endpoint_unauthz,
                method=method,
                actor="standard-user",
                evidence={
                    "unauth_status": r_bad.status_code,
                    "unauth_body_sample": self._redact(body_bad),
                    "baseline_status": r_ok.status_code,
                    "note": "Unauthorized ID returned resource similar to baseline.",
                },
                recommendation="Enforce object-level authorization checks (verify ownership/tenant) before returning resource."
            )
        else:
            return self._report_secure(
                vuln="BOLA",
                endpoint=endpoint_unauthz,
                method=method,
                actor="standard-user",
                evidence={"unauth_status": r_bad.status_code, "unauth_body_sample": self._redact(body_bad)}
            )

    def test_bfla(self, base: str, admin_only_path: str, low_priv_token: str, method: str = "POST",
                  payload: Optional[dict] = None):
        """
        Try an admin-only action (e.g., '/api/users/{id}/role') with a low-priv token.
        """
        endpoint = base + admin_only_path
        r, meta, body = self._req(method, endpoint, low_priv_token, json_body=payload or {})
        if r is None:
            return self._report_error("BFLA", endpoint, method, "low-priv")

        if not self._is_forbidden(r.status_code, body):
            return self._report_vuln(
                vuln="BFLA",
                severity="Critical",
                endpoint=endpoint,
                method=method,
                actor="low-priv",
                evidence={"status": r.status_code, "body_sample": self._redact(body)},
                recommendation="Enforce role/permission checks server-side; validate that only authorized roles can perform this action."
            )
        else:
            return self._report_secure(
                vuln="BFLA",
                endpoint=endpoint,
                method=method,
                actor="low-priv",
                evidence={"status": r.status_code, "body_sample": self._redact(body)}
            )

    def test_tenant_escape(self, base: str, path_template: str, token_a: str, token_b: str, tenant_id_a: str,
                           resource_in_a: str, method: str = "GET"):
        """
        Verify org/tenant scoping: token A must not read tenant B or cross-tenant resources.
        """
        url = base + path_template.format(tenantId=tenant_id_a, id=resource_in_a)
        r_a, _, body_a = self._req(method, url, token_a)  # allowed
        r_b, _, body_b = self._req(method, url, token_b)  # other-tenant token

        if r_a is None or r_b is None:
            return self._report_error("TenantEsc", url, method, "cross-tenant")

        forbidden = self._is_forbidden(r_b.status_code, body_b)
        similar = self._looks_like_same_resource(body_a, body_b)

        if not forbidden and similar:
            return self._report_vuln(
                vuln="TenantEscape",
                severity="High",
                endpoint=url,
                method=method,
                actor="other-tenant",
                evidence={"other_tenant_status": r_b.status_code, "sample": self._redact(body_b)},
                recommendation="Enforce tenant scoping (tenantId from token/claims). Do not rely on client-supplied tenant identifiers."
            )
        else:
            return self._report_secure(
                vuln="TenantEscape",
                endpoint=url,
                method=method,
                actor="other-tenant",
                evidence={"other_tenant_status": r_b.status_code}
            )

    # --- utilities for reporting & similarity ---
    def _looks_like_same_resource(self, body_a: Any, body_b: Any) -> bool:
        """
        Cheap similarity heuristic:
        - If both dicts and share many keys (e.g., name,email,role,id), treat as 'similar'.
        - Helps catch cases where API returns '200 OK' with someone else’s data.
        """
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
        return asdict(f)

    def _report_secure(self, vuln, endpoint, method, actor, evidence):
        f = Finding(
            agent=self.name, category="Authorization", vuln=vuln, status="SECURE",
            severity="None", endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation="No issue detected for this check."
        )
        self.findings.append(asdict(f))
        return asdict(f)

    def _report_error(self, vuln, endpoint, method, actor):
        f = Finding(
            agent=self.name, category="Authorization", vuln=vuln, status="ERROR",
            severity="Unknown", endpoint=endpoint, method=method, actor=actor,
            evidence={"details": "Request/transport error"}, recommendation="Verify endpoint availability and credentials."
        )
        self.findings.append(asdict(f))
        return asdict(f)


agent = AccessAgent()

# BOLA against /api/users/{id}
print(agent.test_bola(
    base="https://internal.example.com",
    path_template="/api/users/{id}",
    actor_token="eyJhbGciOi...",         # token for user A
    authorized_id="userA",
    unauthorized_id="userB",
    method="GET"
))

# BFLA: try admin-only action with low-priv token
print(agent.test_bfla(
    base="https://internal.example.com",
    admin_only_path="/api/admin/users/userB/role",
    low_priv_token="eyJhbGciOi...",      # non-admin token
    method="POST",
    payload={"role": "admin"}
))

# Tenant escape check
print(agent.test_tenant_escape(
    base="https://internal.example.com",
    path_template="/api/orgs/{tenantId}/invoices/{id}",
    token_a="token-for-tenantA",
    token_b="token-for-tenantB",
    tenant_id_a="tenantA",
    resource_in_a="invoice123",
    method="GET"
))

# All findings (JSON-serializable for your prompt-style report)
print(json.dumps(agent.findings, indent=2))
