# mock_api.py
"""Simple mock vulnerable API for testing the orchestrator"""

from flask import Flask, jsonify, request

app = Flask(__name__)

# In-memory database
users = {
    "1": {"id": 1, "username": "admin", "email": "admin@test.com", "role": "admin"},
    "2": {"id": 2, "username": "user", "email": "user@test.com", "role": "user"}
}

books = [
    {"id": 1, "title": "Python Security", "author": "John Doe"},
    {"id": 2, "title": "API Testing", "author": "Jane Smith"},
    {"id": 3, "title": "Web Security", "author": "Bob Wilson"}
]

# New inventory items for IDOR/BOLA-style tests
inventory_items = {
    "1": {"id": 1, "name": "Server Config Backup", "owner_user_id": 1},
    "2": {"id": 2, "name": "User Purchase History", "owner_user_id": 2}
}



@app.route('/')
def home():
    return jsonify({
        "message": "Mock Vulnerable API for Security Testing",
        "version": "1.1",
        "endpoints": [
            "/openapi.json",
            "/books/v1/search",
            "/users/v1/profile/<id>",
            "/admin/users",
            "/api/users/v1",
            "/api/internal/debug",
            "/api/v1/login",
            "/payments/v1/charge",
            "/files/v1/download",
            "/inventory/v1/item/<id>",
            "/search/v1/ssrf",
            "/admin/config",
            "/debug/env",
            "/rate/v1/test",

            # Option C new endpoints
            "/api/v2/config/secure",
            "/api/v2/admin/roles",
            "/api/v2/logs/recent",
            "/api/v2/internal/metrics"
        ]
    })


@app.route('/openapi.json')
def openapi():
    """Return OpenAPI specification"""
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Mock Vulnerable API",
            "version": "1.1",
            "description": "Test API with intentional vulnerabilities"
        },
        "paths": {
            "/books/v1/search": {
                "get": {
                    "summary": "Search books by title",
                    "parameters": [{
                        "name": "book_title",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"}
                    }],
                    "responses": {"200": {"description": "Search results"}}
                }
            },
            "/users/v1/profile/{user_id}": {
                "get": {
                    "summary": "Get user profile",
                    "parameters": [{
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }],
                    "responses": {"200": {"description": "User profile"}}
                }
            },
            "/admin/users": {
                "get": {
                    "summary": "List all users (admin only)",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Users"}}
                }
            },
            "/api/v1/login": {
                "post": {
                    "summary": "Weak login endpoint",
                    "responses": {"200": {"description": "JWT-like token"}}
                }
            },
            "/payments/v1/charge": {
                "post": {
                    "summary": "Charge a payment",
                    "responses": {"201": {"description": "Payment processed"}}
                }
            },
            "/files/v1/download": {
                "get": {
                    "summary": "Download a file",
                    "responses": {"200": {"description": "File content"}}
                }
            },
            "/rate/v1/test": {
                "get": {
                    "summary": "Rate-limit test",
                    "responses": {"200": {"description": "Request count"}}
                }
            }
        }
    })


@app.route('/books/v1/search')
def search_books():
    """Intentionally vulnerable to SQL injection"""
    book_title = request.args.get('book_title', '')

    if "' OR" in book_title or "UNION" in book_title or "1=1" in book_title:
        return jsonify({
            "error": "SQL syntax error",
            "query": f"SELECT * FROM books WHERE title='{book_title}'",
            "vulnerable": True
        }), 500

    results = [b for b in books if book_title.lower() in b["title"].lower()]
    return jsonify({"results": results, "query": book_title, "count": len(results)})


@app.route('/users/v1/profile/<user_id>')
def get_profile(user_id):
    """BOLA vulnerability"""
    user = users.get(user_id)
    if user:
        return jsonify({"user": user, "vulnerable": "BOLA - No authorization"})
    return jsonify({"error": "User not found"}), 404


@app.route('/admin/users')
def admin_users():
    """Missing auth"""
    return jsonify({
        "users": list(users.values()),
        "vulnerable": "Missing authentication"
    })


@app.route('/api/users/v1')
def undocumented_users():
    return jsonify({
        "users": list(users.values()),
        "note": "Shadow API"
    })


@app.route('/api/internal/debug')
def debug_endpoint():
    return jsonify({"debug": True, "note": "Undocumented endpoint"})


@app.route('/api/v1/login', methods=['POST'])
def login():
    """Weak login"""
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username in ("admin", "user"):
        return jsonify({
            "access_token": f"fake-jwt-token-for-{username}",
            "role": "admin" if username == "admin" else "user",
            "vulnerable": "Password not verified"
        })

    return jsonify({"error": "User does not exist"}), 401


@app.route('/payments/v1/charge', methods=['POST'])
def charge_payment():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify({
        "status": "processed",
        "card_number": data.get("card_number"),
        "cvv": data.get("cvv"),
        "amount": data.get("amount"),
        "vulnerable": "PCI violation - sensitive data exposed"
    })


@app.route('/files/v1/download')
def download_file():
    path = request.args.get("path", "")
    if ".." in path or path.startswith("/"):
        return jsonify({
            "file": path,
            "content": "SECRET: simulated /etc/passwd",
            "vulnerable": "Path traversal"
        })
    return jsonify({
        "file": path,
        "content": f"Content of {path}",
        "vulnerable": "No whitelist"
    })


@app.route('/inventory/v1/item/<item_id>')
def get_inventory_item(item_id):
    item = inventory_items.get(item_id)
    if item:
        return jsonify({"item": item, "vulnerable": "IDOR/BOLA"})
    return jsonify({"error": "Item not found"}), 404


@app.route('/search/v1/ssrf')
def ssrf_search():
    url = request.args.get("url", "")
    try:
        import requests as _req
        r = _req.get(url, timeout=1)
        return jsonify({
            "target": url,
            "body_preview": r.text[:200],
            "vulnerable": "SSRF - No validation"
        })
    except:
        return jsonify({
            "target": url,
            "error": "Request failed",
            "vulnerable": "SSRF attempt"
        }), 502


@app.route('/admin/config')
def admin_config():
    return jsonify({
        "db_user": "root",
        "db_pass": "SuperSecret",
        "keys": ["key1", "key2"],
        "vulnerable": "Sensitive config exposed"
    })


@app.route('/debug/env')
def debug_env():
    import os
    return jsonify({
        "env": dict(list(os.environ.items())[:10]),
        "vulnerable": "Environment leak"
    })


# Rate-limit tracking
request_counts = {}
@app.before_request
def track_requests():
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1


@app.route('/rate/v1/test')
def rate_test():
    ip = request.remote_addr
    return jsonify({
        "ip": ip,
        "count": request_counts[ip],
        "vulnerable": "No rate limiting"
    })

# ============================================================
# 📌 OPTION C — NEW ENDPOINTS ADDED BELOW
# ============================================================

@app.route("/api/v2/config/secure")
def secure_config_v2():
    return jsonify({
        "system": "MockAPI",
        "mode": "insecure-demo",
        "vulnerable": "Configuration exposed without authentication"
    })


@app.route("/api/v2/admin/roles")
def admin_roles_v2():
    return jsonify({
        "roles": ["admin", "moderator", "user", "readonly"],
        "vulnerable": "Role management exposed to public"
    })


@app.route("/api/v2/logs/recent")
def recent_logs_v2():
    return jsonify({
        "logs": [
            "User admin logged in",
            "Payment processed",
            "Debug endpoint accessed"
        ],
        "vulnerable": "System logs exposed"
    })


@app.route("/api/v2/internal/metrics")
def internal_metrics_v2():
    return jsonify({
        "cpu": "12%",
        "memory": "1.2GB",
        "requests_total": sum(request_counts.values()),
        "vulnerable": "Internal metrics exposed"
    })

# ============================================================
# 📌 AUTHENTICATION ENDPOINTS (Missing in original file)
# ============================================================

@app.route("/auth/validate")
def validate_token():
    """Simulates JWT validation but is intentionally weak."""
    auth = request.headers.get("Authorization", "")

    if not auth:
        return jsonify({
            "valid": False,
            "reason": "Missing Authorization header",
            "vulnerable": "No authentication required"
        }), 401

    if "INVALID" in auth or "expired" in auth:
        return jsonify({
            "valid": False,
            "reason": "Invalid or expired token",
            "vulnerable": "Weak token validation"
        }), 403

    return jsonify({
        "valid": True,
        "token": auth,
        "vulnerable": "Token accepted without signature verification"
    })


@app.route("/auth/refresh")
def refresh_token():
    """Simulated refresh token endpoint."""
    auth = request.headers.get("Authorization", "")

    if not auth:
        return jsonify({
            "error": "Missing token",
            "vulnerable": "Refresh allowed without token"
        }), 401

    return jsonify({
        "new_token": "fake-refreshed-token",
        "vulnerable": "No expiry or signature checks"
    })


@app.route("/api/v1/register", methods=["POST"])
def register():
    """Simulates a weak registration endpoint."""
    data = request.get_json(force=True, silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Missing fields",
            "vulnerable": "No password policy"
        }), 400

    return jsonify({
        "status": "created",
        "username": username,
        "vulnerable": "User registered without validation"
    }), 201


# ============================================================
# 📌 RATE-LIMITING ENDPOINT SUITE (Missing in original file)
# ============================================================

@app.route("/rate/v1/login")
def rate_login():
    ip = request.remote_addr
    return jsonify({
        "action": "login",
        "ip": ip,
        "count": request_counts[ip],
        "vulnerable": "Rate-limits missing on login"
    })


@app.route("/rate/v1/checkout")
def rate_checkout():
    ip = request.remote_addr
    return jsonify({
        "action": "checkout",
        "ip": ip,
        "count": request_counts[ip],
        "vulnerable": "Checkout endpoint not rate-limited"
    })


@app.route("/rate/v1/queue")
def rate_queue():
    ip = request.remote_addr
    return jsonify({
        "action": "queue",
        "ip": ip,
        "count": request_counts[ip],
        "vulnerable": "Queue endpoint unprotected"
    })


@app.route("/rate/v1/order", methods=["POST"])
def rate_order():
    ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}

    return jsonify({
        "action": "order",
        "payload_received": data,
        "ip": ip,
        "count": request_counts[ip],
        "vulnerable": "Order action without throttling"
    })


@app.route("/rate/v1/report")
def rate_report():
    return jsonify({
        "total_requests": sum(request_counts.values()),
        "requests_by_ip": request_counts,
        "vulnerable": "Request logs exposed without auth"
    })


# ============================================================
# SERVER STARTUP
# ============================================================

if __name__ == "__main__":
    import threading, time
    print("=" * 70)
    print("[MOCK API] Vulnerable API Starting...")
    print("=" * 70)
    print("http://localhost:5001")
    print("Press CTRL+C to exit\n")

    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=5001, threads=10)
    except:
        app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
