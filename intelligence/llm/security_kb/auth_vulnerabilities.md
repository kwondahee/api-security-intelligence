# Common Authentication Vulnerabilities

Strong authentication is critical for API security. Below are the most frequent weaknesses.

---

## 1. Missing Authentication

Public endpoints allow access without enforcing authentication controls.

Symptoms:
- No Authorization header required
- Always returns HTTP 200
- No cookie/session validation

---

## 2. Weak Token Validation

JWT issues:
- Missing signature verification
- Accepting `alg=none`
- Expired tokens accepted
- Not verifying issuer or audience

---

## 3. Credential Stuffing Vulnerabilities

APIs lacking:
- Rate limiting
- IP reputation checks
- Account lockout mechanisms

---

## 4. Predictable or Reusable Tokens

If tokens are:
- Sequential
- Reusable across sessions
- Not bound to device/IP

Risk increases significantly.

---

## 5. Insecure Password Recovery

Common flaws:
- Reset endpoints accessible without auth
- Weak security questions
- Reset tokens not expiring

---

Automation in the LLM and AuthAgent should detect token format issues, missing verification, and misconfigurations.
