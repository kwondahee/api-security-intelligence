# OWASP API Security Top 10 (2023)

OWASP highlights the most critical API risks. These concepts help assess API security posture and guide automated reasoning.

---

## 1. Broken Object Level Authorization (BOLA)

APIs expose endpoints for object access. If access control is missing or weak, attackers can manipulate URLs to access others' data.

**Example:**
GET /users/123 → attacker changes to /users/122

**Detection Strategy (Automated):**
- Test multiple object IDs
- Compare privilege levels
- Look for horizontal privilege escalation

---

## 2. Broken Authentication

APIs commonly fail to validate tokens, sessions, or passwords correctly.

Signals:
- JWT not validated
- Weak session expiration
- Use of default or missing auth headers

---

## 3. Broken Object Property Level Authorization (BOPLA)

Even when object-level access is secure, individual fields may be exposed or modifiable.

Example:
- User can modify `role=admin` in PATCH request

---

## 4. Unrestricted Resource Consumption

Rate limits or quotas not enforced.

Indicators:
- Unlimited requests allowed
- No 429 response codes
- Endpoints supporting large payloads without controls

---

## 5. Broken Function Level Authorization (BFLA)

Difference between high-priv and low-priv functions not enforced.

Example:
Regular user calling:
DELETE /admin/user/5

---

## 6. Mass Assignment

Danger when client-provided fields map directly to internal models.

Example:
PATCH /user → payload includes `is_admin=true`

---

## 7. Server-Side Request Forgery

Improperly validated URLs can allow internal network access.

---

## 8. Security Misconfigurations

Includes:
- Disabled CORS
- Exposed debug endpoints
- Unpatched servers

---

## 9. Improper Inventory Management

Legacy endpoints or undocumented APIs introduce risk.

---

## 10. Unsafe Consumption of APIs

Risks from trusting external or third-party APIs.

---

This knowledge is foundational for routing agents and generating accurate security insights during RAG reasoning.
