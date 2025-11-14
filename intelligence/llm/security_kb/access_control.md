# Access Control: Best Practices & Common Failures

Proper authorization ensures users only perform actions within their privileges.

---

## 1. Role-Based Access Control (RBAC)

Rules must be enforced at:
- Endpoint level
- Data access level
- Action/operation level

Agents should analyze:
- GET vs POST vs DELETE paths
- Parameter-based role restrictions

---

## 2. Horizontal Privilege Escalation (BOLA)

Occurs when a user accesses resources belonging to another user.

Example: GET /orders/{id}

---

## 3. Vertical Privilege Escalation (BFLA)

Low-priv users accessing admin functionality.

Signals:
- Admin endpoints not protected
- Missing role validation middleware

---

## 4. Tenant Isolation

In multi-tenant systems:
- Tenant ID in URL must match the user’s tenant
- Cross-tenant reads should be blocked
- Writes must include scoped authorization

---

## 5. Access Control Testing Strategy

Automated agents should:
- Call endpoints as different privilege levels
- Swap user IDs or tenant IDs
- Check response variance (200 vs 403)

