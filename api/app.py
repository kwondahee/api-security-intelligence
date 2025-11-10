from flask import Flask, request, jsonify, g
import os
from datetime import datetime
import uuid
from telemetry.logger import emit_agent_decision

app = Flask(__name__)

# --- Config toggles (env) ---------------------------------------------------
PORT = int(os.getenv("PORT", "8080"))
VULN_MODE = os.getenv("VULN_MODE", "true").lower() in ("1","true","yes")
# VULN_MODE=True => purposely lenient behaviors to let agents find issues.

# --- Tiny in-memory data ----------------------------------------------------
USERS = {
    "1":  {"id":"1",  "name":"Ada",   "role":"user",  "tenant":"T001", "balance": 900},
    "24": {"id":"24", "name":"Babb",  "role":"user",  "tenant":"T001", "balance": 450},
    "99": {"id":"99", "name":"Root",  "role":"admin", "tenant":"TROOT","balance": 1_000_000},
}

TENANT_RES = {("T001","R101"): {"id":"R101","tenant":"T001","data":"alpha"}}

def log_decision(agent, rule, status="VULNERABLE", trace_id=None, extra=None):
    emit_agent_decision(
        trace_id=trace_id,
        endpoint=request.path,
        agent=agent,
        rule=rule,            # e.g. "SQLi-detect", "Missing-Auth", "Traversal-detect", "XSS-detect"
        status=status,
        extra=extra or {}
    )


def bearer_actor():
    """Accepts very loose 'Authorization: Bearer user:<id>'.
    In VULN_MODE, any 'Bearer <anything>' is treated as authenticated."""
    auth = request.headers.get("Authorization","")
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        tok = parts[1]
        # emulate AuthAgent's 'alg=none' acceptance by not verifying signature
        if tok.startswith("user:"):
            return tok.split("user:")[-1]
        return "unknown" if VULN_MODE else None
    return None

@app.before_request
def _assign_trace_id():
    # prefer client-provided id if present (from generator/harness), else generate one
    g.trace_id = request.headers.get("X-Trace-Id", str(uuid.uuid4()))
    
@app.after_request
def _echo_trace_id(resp):
    if hasattr(g, "trace_id"):
        resp.headers["X-Trace-Id"] = g.trace_id
    return resp


# --- Health & public --------------------------------------------------------
@app.get("/health")
def health():
    return "ok", 200

@app.get("/api/v1/public/status")
def public_status():
    # solid, unprotected endpoint -> RateAgent will hammer this
    return jsonify({"status":"OK","service":"api-vm","ts":datetime.utcnow().isoformat()}), 200

# --- AccessAgent: BOLA (object-level) --------------------------------------
@app.get("/rest/user/<uid>")
def get_user(uid):
    # No auth here by design -> easy BOLA leak for AccessAgent
    u = USERS.get(uid)
    if not u: return jsonify({"error":"not found"}), 404
    return jsonify(u), 200

# --- AccessAgent: BFLA (function-level) ------------------------------------
@app.get("/rest/users")
def list_users_admin_only():
    # Should require admin, but in VULN_MODE accept any token => BFLA
    actor = bearer_actor()
    if actor and actor != 'admin':
        log_decision("AccessAgent", "BOLA", status="VULNERABLE", extra={"actor": actor})
    if not actor and not VULN_MODE:
        return jsonify({"error":"unauthorized"}), 401
    # if actor exists but not admin, should be 403; in VULN_MODE, we leak
    if not VULN_MODE and USERS.get(actor,{}).get("role") != "admin":
        return jsonify({"error":"forbidden"}), 403

    # return trimmed user list
    log_decision("AccessAgent", "BOLA", status="VULNERABLE", extra={"view":"admin_list"})
    return jsonify([{"id":u["id"],"name":u["name"],"role":u["role"]} for u in USERS.values()]), 200

# --- AccessAgent: Tenant escape --------------------------------------------
@app.get("/v2/tenant/<tenantId>/resources/<rid>")
def get_tenant_resource(tenantId, rid):
    actor = bearer_actor()
    # a real check would read tenant from token; we skip/mis-check in VULN_MODE
    rec = TENANT_RES.get((tenantId, rid))
    if not rec: return jsonify({"error":"not found"}), 404

    if not actor and not VULN_MODE:
        return jsonify({"error":"unauthorized"}), 401

    # In VULN_MODE: return resource regardless of actor tenant => “tenant escape”
    # In secure mode: enforce tenant match (actor's tenant == tenantId)
    if not VULN_MODE:
        actor_tenant = USERS.get(actor,{}).get("tenant")
        if actor_tenant != tenantId:
            return jsonify({"error":"forbidden cross-tenant"}), 403

    return jsonify(rec), 200

# --- AuthAgent: privileged/admin path --------------------------------------
@app.route("/admin/users", methods=["GET","POST"])
def admin_users():
    actor = bearer_actor()
    # AuthAgent will try: missing auth, header bypass, odd JWT/alg=none, etc.
    if not actor:
        log_decision("AuthAgent", "Missing-Auth", status="VULNERABLE", extra={"status": 200})
    if not actor and not VULN_MODE:
        log_decision("AuthAgent", "Missing-Auth", status="VULNERABLE", extra={"status": 200})
        return jsonify({"error":"missing auth"}), 401

    # real world: require admin
    if not VULN_MODE and USERS.get(actor,{}).get("role") != "admin":
        return jsonify({"error":"forbidden"}), 403

    if request.method == "GET":
        return jsonify({"admin_view": [u for u in USERS.values()]}), 200
    else:
        body = request.get_json(silent=True) or {}
        return jsonify({"accepted": body}), 201

# --- InputAgent: SQLi/XSS/Traversal probes ---------------------------------
@app.get("/search")
def search():
    # InputAgent will call /search?q=<payload>
    q = request.args.get("q","")
    # Extremely naive echo to allow reflected payloads to show up
    results = [{"title":"hello"}, {"q": q}]
    # Simulate “more results” for classic ' OR 1=1 -- (heuristic)
    if "' OR 1=1" in q or '" OR 1=1' in q:
        log_decision("InputAgent", "SQLi-detect", extra={"payload": q})
        results += [{"id":i} for i in range(5)]  # inflate result count
    return jsonify({"data": results}), 200

@app.post("/echo")
def echo():
    # InputAgent can POST JSON with XSS payloads; we reflect it
    body = request.get_json(silent=True) or {}
    payload = str(body)
    if "<script" in payload.lower() or "onerror=" in payload.lower():
        log_decision("InputAgent", "XSS-detect", extra={"payload": payload[:120]})
    return jsonify({"echo": body}), 200

@app.get("/files")
def files():
    # InputAgent will try path traversal via ?path=...
    path = request.args.get("path","")
    # For PoC: if payload looks like passwd, leak signatures so agent can detect
    if "passwd" in path or ".." in path or "%2e" in path:
        log_decision("InputAgent", "Traversal-detect", extra={"path": path})
        sample = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        return jsonify({"path": path, "content": sample}), 200
    return jsonify({"path": path, "content": "ok"}), 200

# --- DocAccuracyAgent: OpenAPI (intentionally incomplete) -------------------
@app.get("/api-docs")
def openapi_doc():
    # Minimal doc that DELIBERATELY omits /users/v1/_debug to let the agent flag it
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title":"AETHER Test API","version":"0.1.0"},
        "paths": {
            "/health": {"get": {"responses": {"200":{"description":"ok"}}}},
            "/api/v1/public/status": {"get": {"responses": {"200":{"description":"ok"}}}},
            "/rest/user/{id}": {"get": {"parameters":[{"name":"id","in":"path","required":True,"schema":{"type":"string"}}],
                                        "responses":{"200":{"description":"ok"}}}},
            "/rest/users": {"get": {"responses":{"200":{"description":"ok"}}}},
            "/v2/tenant/{tenantId}/resources/{id}": {"get": {"responses":{"200":{"description":"ok"}}}},
            "/admin/users": {"get": {"responses":{"200":{"description":"ok"}}}},
            "/search": {"get": {"parameters":[{"name":"q","in":"query","required":False,"schema":{"type":"string"}}],
                                 "responses":{"200":{"description":"ok"}}}},
            "/echo": {"post": {"responses":{"200":{"description":"ok"}}}},
            "/files": {"get": {"parameters":[{"name":"path","in":"query","required":False,"schema":{"type":"string"}}],
                               "responses":{"200":{"description":"ok"}}}}
        }
    }), 200

# Undocumented debug endpoint to let DocAccuracyAgent scream
@app.get("/users/v1/_debug")
def debug_undocumented():
    log_decision("DocAccuracyAgent", "Undocumented-Endpoint", status="MISCONFIGURATION")
    return jsonify({"debug":"on","ts":datetime.utcnow().isoformat()}), 200

# --- Main -------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
