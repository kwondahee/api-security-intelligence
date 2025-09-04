import requests
import time
import json
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List, Optional

# Singapore Timezone
SGT = timezone(timedelta(hours=8))

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
    timestamp: str = field(default_factory=lambda: datetime.now(SGT).strftime("%Y-%m-%d %H:%M:%S"))

class AuthAgent:
    def __init__(self, name="AuthAgent", timeout=8):
        self.name = name
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []

    # --- helpers ---
    def _req(self, method: str, url: str, token: Optional[str] = None, json_body: Optional[dict] = None):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            r = requests.request(method, url, headers=headers, json=json_body, timeout=self.timeout)
            # Build meta
            meta = {
                "status": r.status_code,
                "len": int(r.headers.get("Content-Length", "0") or 0),
                "cache": r.headers.get("Cache-Control"),
                "etag": r.headers.get("ETag"),
            }
            # Parse JSON safely
            try:
                body = r.json()
            except Exception:
                body = {"_non_json_sample": r.text[:300]}
            return r, meta, body
        except requests.RequestException as e:
            return None, None, {"error": str(e)}
        
    def _redact(self, body: dict, fields: List[str] = ("token", "password", "secret", "key")) -> dict:
        redacted = {}
        if isinstance(body, dict):
            for k, v in body.items():
                redacted[k] = "***" if any(k.lower() == f for f in fields) else v
        return redacted if redacted else body

    def _report_vuln(self, vuln, severity, endpoint, method, actor, evidence, recommendation):
        f = Finding(
            agent=self.name, category="Authentication", vuln=vuln,
            status="VULNERABLE", severity=severity,
            endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation=recommendation
        )
        self.findings.append(asdict(f))
        return asdict(f)

    def _report_secure(self, vuln, endpoint, method, actor, evidence):
        f = Finding(
            agent=self.name, category="Authentication", vuln=vuln,
            status="SECURE", severity="None",
            endpoint=endpoint, method=method, actor=actor,
            evidence=evidence, recommendation="No issue detected for this check."
        )
        self.findings.append(asdict(f))
        return asdict(f)

    def _report_error(self, vuln, endpoint, method, actor, details="Request error"):
        f = Finding(
            agent=self.name, category="Authentication", vuln=vuln,
            status="ERROR", severity="Unknown",
            endpoint=endpoint, method=method, actor=actor,
            evidence={"details": details},
            recommendation="Verify endpoint availability and test configuration."
        )
        self.findings.append(asdict(f))
        return asdict(f)

    # --- tests ---
    def test_no_auth_required(self, base: str, protected_path: str, method: str = "GET"):
        """
        Check if protected resource is accessible without a token.
        """
        url = base + protected_path
        r, meta, body = self._req(method, url)

        if r is None:
            return self._report_error(
                vuln="NoAuthRequired",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                details=body.get("error", "Request failed or timed out")
            )

        if r.status_code == 200:
            return self._report_vuln(
                vuln="NoAuthRequired",
                severity="Critical",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                evidence={
                    "status": r.status_code,
                    "meta": meta,
                    "body_sample": self._redact(body),
                    "note": "Protected resource accessible without token."
                },
                recommendation="Require authentication for all protected endpoints."
            )
        else:
            return self._report_secure(
                vuln="NoAuthRequired",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                evidence={
                    "status": r.status_code,
                    "meta": meta,
                    "body_sample": self._redact(body)
                }
            )


    def test_expired_token(self, base: str, path: str, expired_token: str, method: str = "GET"):
        """
        Send request with expired token and see if its still accepted.
        """
        url = base + path
        r, meta, body = self._req(method, url, expired_token)
        
        if r is None:
            return self._report_error(
                vuln="ExpiredTokenAccepted",
                endpoint=url,
                method=method,
                actor="expired-token",
                details="Request failed or timed out"
            )

        if r.status_code == 200:
            return self._report_vuln(
                vuln="ExpiredTokenAccepted",
                severity="High",
                endpoint=url,
                method=method,
                actor="expired-token",
                evidence={
                    "status": r.status_code,
                    "meta": meta,                      # response headers / content length
                    "body_sample": self._redact(body), # redacted JSON snippet
                    "note": "Server accepted expired token."
                },
                recommendation="Reject expired tokens; enforce proper expiration checks."
            )
        else:
            return self._report_secure(
                vuln="ExpiredTokenAccepted",
                endpoint=url,
                method=method,
                actor="expired-token",
                evidence={
                    "status": r.status_code,
                    "meta": meta,
                    "body_sample": self._redact(body)
                }
            )

    def test_invalid_signature_jwt(self, base: str, path: str, tampered_token: str, method: str = "GET"):
        """
        Send JWT with tampered signature, should be rejected.
        """
        url = base + path
        r, meta, body = self._req(method, url, token=tampered_token)

        if r is None:
            return self._report_error(
                vuln="InvalidSignatureAccepted",
                endpoint=url,
                method=method,
                actor="tampered-token",
                details=body.get("error", "Request failed or timed out")
            )

        if r.status_code == 200:
            return self._report_vuln(
                vuln="InvalidSignatureAccepted",
                severity="Critical",
                endpoint=url,
                method=method,
                actor="tampered-token",
                evidence={
                    "status": r.status_code,
                    "meta": meta,
                    "body_sample": self._redact(body),
                    "note": "Server accepted JWT with invalid signature."
                },
                recommendation="Reject tokens with invalid or missing signatures."
            )
        else:
            return self._report_secure(
                vuln="InvalidSignatureAccepted",
                endpoint=url,
                method=method,
                actor="tampered-token",
                evidence={
                    "status": r.status_code,
                    "meta": meta,
                    "body_sample": self._redact(body)
                }
            )

    def test_bruteforce_login(self, base: str, login_path: str, username: str, wrong_password: str, method: str = "POST"):
        """
        Try multiple wrong passwords to see if rate limiting exists.
        """
        url = base + login_path
        attempts = []
        metas = []

        try:
            for i in range(5):
                r, meta, body = self._req(method, url, json_body={"username": username, "password": wrong_password})
                if r:
                    attempts.append(r.status_code if r else "error")
                    metas.append(meta or {})
                else:
                    attempts.append(None)
                    metas.append(meta)
                time.sleep(0.5)  # small delay between attempts
        except Exception as e:
            return self._report_error(
                vuln="BruteforceNoProtection",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                details=str(e)
            )

        if all(code == 401 for code in attempts if code is not None):
            return self._report_secure(
                vuln="BruteforceNoProtection",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                evidence={"statuses": attempts, "metas": metas}
            )
        else:
            return self._report_vuln(
                vuln="BruteforceNoProtection",
                severity="Medium",
                endpoint=url,
                method=method,
                actor="unauthenticated",
                evidence={
                    "statuses": attempts,
                    "metas": metas,
                    "note": "Some login attempts were not properly rejected."
                },
                recommendation="Implement account lockout, CAPTCHA, or rate limiting on login."
            )

        
agent = AuthAgent()


# Check if a protected endpoint is accessible without a token
print(agent.test_no_auth_required(
    base="https://internal.example.com",
    protected_path="/api/users/me"
))

# Check if expired token is accepted
print(agent.test_expired_token(
    base="https://internal.example.com",
    path="/api/users/me",
    expired_token="eyJhbGciOi..."
))

# Check if tampered JWT is accepted
print(agent.test_invalid_signature_jwt(
    base="https://internal.example.com",
    path="/api/users/me",
    tampered_token="eyJhbGciOi..."
))

# Test login bruteforce protection
print(agent.test_bruteforce_login(
    base="https://internal.example.com",
    login_path="/api/login",
    username="userA",
    wrong_password="wrongpass123"
))

# All findings
print(json.dumps(agent.findings, indent=2))