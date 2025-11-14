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
            "/rate/v1/test"
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
                    "responses": {"200": {"description": "List of users"}}
                }
            },
            # NEW: some documented endpoints (others remain shadow / undocumented)
            "/api/v1/login": {
                "post": {
                    "summary": "Login (weak authentication)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"}
                                    },
                                    "required": ["username", "password"]
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "JWT-like token"}}
                }
            },
            "/payments/v1/charge": {
                "post": {
                    "summary": "Charge a payment (no auth, echoes card data)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "card_number": {"type": "string"},
                                        "cvv": {"type": "string"},
                                        "amount": {"type": "number"}
                                    },
                                    "required": ["card_number", "cvv", "amount"]
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Payment processed"}}
                }
            },
            "/files/v1/download": {
                "get": {
                    "summary": "Download file (path traversal)",
                    "parameters": [{
                        "name": "path",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"}
                    }],
                    "responses": {"200": {"description": "File content"}}
                }
            },
            "/rate/v1/test": {
                "get": {
                    "summary": "Rate-limiting test endpoint",
                    "responses": {"200": {"description": "Request count by IP"}}
                }
            }
        }
    })

@app.route('/books/v1/search')
def search_books():
    """Intentionally vulnerable to SQL injection"""
    book_title = request.args.get('book_title', '')
    
    # Simulate SQL injection vulnerability
    if "' OR" in book_title or "UNION" in book_title or "1=1" in book_title:
        return jsonify({
            "error": "SQL syntax error",
            "query": f"SELECT * FROM books WHERE title = '{book_title}'",
            "vulnerable": True,
            "message": "SQL Injection detected!"
        }), 500
    
    # Normal search
    results = [b for b in books if book_title.lower() in b['title'].lower()]
    return jsonify({
        "results": results,
        "query": book_title,
        "count": len(results)
    })

@app.route('/users/v1/profile/<user_id>')
def get_profile(user_id):
    """Intentionally vulnerable to BOLA (Broken Object Level Authorization)"""
    # No authorization check - any user can access any profile
    user = users.get(user_id)
    if user:
        return jsonify({
            "user": user,
            "vulnerable": "No authorization check - BOLA vulnerability"
        })
    return jsonify({"error": "User not found"}), 404

@app.route('/admin/users')
def admin_users():
    """Intentionally missing authentication"""
    # Should require admin authentication but doesn't
    return jsonify({
        "users": list(users.values()),
        "vulnerable": "Missing authentication",
        "warning": "This endpoint should require admin authentication"
    })

@app.route('/api/users/v1')
def undocumented_users():
    """Shadow API - not documented in OpenAPI spec"""
    return jsonify({
        "users": list(users.values()),
        "note": "This is an undocumented/shadow endpoint"
    })

@app.route('/api/internal/debug')
def debug_endpoint():
    """Another undocumented endpoint"""
    return jsonify({
        "debug": True,
        "env": "production",
        "note": "Undocumented debug endpoint"
    })

# ============================
# NEW VULNERABLE ENDPOINTS
# ============================

@app.route('/api/v1/login', methods=['POST'])
def login():
    """
    Weak login endpoint:
    - Accepts any password for existing user
    - Returns unsigned, fake JWT-like token
    - No rate limiting
    - User enumeration via error messages
    """
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "Missing credentials",
            "vulnerable": "No proper input validation"
        }), 400

    if username in ("admin", "user"):
        token = f"fake-jwt-token-for-{username}"
        return jsonify({
            "access_token": token,
            "role": "admin" if username == "admin" else "user",
            "vulnerable": "Password not actually verified, token not signed"
        })

    return jsonify({
        "error": "User does not exist",
        "vulnerable": "User enumeration via detailed error messages"
    }), 401


@app.route('/payments/v1/charge', methods=['POST'])
def charge_payment():
    """
    Payment endpoint with multiple issues:
    - No authentication required
    - Logs/echoes full card data back to client
    - No amount validation
    """
    data = request.get_json(force=True, silent=True) or {}
    amount = data.get("amount")
    card_number = data.get("card_number")
    cvv = data.get("cvv")

    return jsonify({
        "status": "processed",
        "amount": amount,
        "card_number": card_number,
        "cvv": cvv,
        "vulnerable": "No auth, no PCI compliance, sensitive card data echoed"
    }), 201


@app.route('/files/v1/download')
def download_file():
    """
    Path traversal-style file download:
    - Accepts raw path param, no sanitization
    - Simulates reading sensitive files when '../' or absolute paths are used
    (We don't actually read the host filesystem to keep it safe & portable.)
    """
    path = request.args.get('path', '')

    if not path:
        return jsonify({"error": "Missing 'path' parameter"}), 400

    # Simulate directory traversal
    if ".." in path or path.startswith("/"):
        return jsonify({
            "file": path,
            "content": "SECRET: simulated /etc/passwd content",
            "vulnerable": "Directory traversal allowed, no path validation"
        })

    # Normal-ish behavior (still vulnerable because no whitelisting)
    return jsonify({
        "file": path,
        "content": f"File content for {path}",
        "vulnerable": "No path validation or access control on files"
    })


@app.route('/inventory/v1/item/<item_id>')
def get_inventory_item(item_id):
    """
    Inventory endpoint with IDOR/BOLA:
    - Returns items regardless of caller identity
    - No ownership / tenant check
    """
    item = inventory_items.get(item_id)
    if item:
        return jsonify({
            "item": item,
            "vulnerable": "No ownership check - IDOR/BOLA vulnerability"
        })
    return jsonify({"error": "Item not found"}), 404


@app.route('/search/v1/ssrf')
def ssrf_search():
    """
    SSRF-like behavior:
    - Fetches arbitrary URL provided by client
    - No allowlist or validation
    """
    target = request.args.get("url", "")
    if not target:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        import requests as _req
        resp = _req.get(target, timeout=1)
        return jsonify({
            "target": target,
            "status_code": resp.status_code,
            "body_preview": resp.text[:200],
            "vulnerable": "Unvalidated URL fetch (SSRF)"
        })
    except Exception as e:
        return jsonify({
            "target": target,
            "error": str(e),
            "vulnerable": "SSRF attempt could reach internal services if accessible"
        }), 502


@app.route('/admin/config')
def admin_config():
    """
    Sensitive config endpoint:
    - Exposes fake DB credentials and API keys
    - No authentication required
    """
    return jsonify({
        "db_host": "localhost",
        "db_user": "admin",
        "db_password": "SuperSecretPassword!",
        "api_keys": ["test-api-key-1", "test-api-key-2"],
        "vulnerable": "Sensitive config exposed without authentication"
    })


@app.route('/debug/env')
def debug_env():
    """
    Debug endpoint:
    - Dumps a subset of environment variables
    - Typically sensitive in real deployments
    """
    import os
    env_sample = {k: v for k, v in list(os.environ.items())[:10]}
    return jsonify({
        "env": env_sample,
        "vulnerable": "Environment variables exposed via debug endpoint"
    })


# Request counter for rate limiting tests
request_counts = {}

@app.before_request
def track_requests():
    """Track requests for rate limiting detection"""
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1


@app.route('/rate/v1/test')
def rate_test():
    """
    Rate-limit test endpoint:
    - Just returns how many requests were seen from this IP
    - No actual blocking, used to detect missing rate limiting
    """
    ip = request.remote_addr
    count = request_counts.get(ip, 0)
    return jsonify({
        "ip": ip,
        "request_count": count,
        "vulnerable": "Only counting requests, no enforcement"
    })


if __name__ == '__main__':
    import threading
    import time
    
    print("=" * 70)
    print("[MOCK API] Vulnerable API Starting...")
    print("=" * 70)
    print("Running on: http://localhost:5001")
    print("")
    print("Available Endpoints:")
    print("  GET  /                          - API info")
    print("  GET  /openapi.json              - OpenAPI specification")
    print("  GET  /books/v1/search           - Search books (SQL Injection vuln)")
    print("  GET  /users/v1/profile/<id>     - User profile (BOLA vuln)")
    print("  GET  /admin/users               - Admin endpoint (Missing auth)")
    print("  GET  /api/users/v1              - Shadow API (Undocumented)")
    print("  GET  /api/internal/debug        - Debug endpoint (Undocumented)")
    print("  POST /api/v1/login              - Weak login (auth issues)")
    print("  POST /payments/v1/charge        - Payment (exposes card data)")
    print("  GET  /files/v1/download         - Path traversal simulation")
    print("  GET  /inventory/v1/item/<id>    - IDOR/BOLA inventory endpoint")
    print("  GET  /search/v1/ssrf            - SSRF-like URL fetch")
    print("  GET  /admin/config              - Sensitive config leak")
    print("  GET  /debug/env                 - Env leak debug endpoint")
    print("  GET  /rate/v1/test              - Rate-limit test endpoint")
    print("=" * 70)
    print("")
    
    # Use production-ready server
    try:
        from waitress import serve
        print("[INFO] Using Waitress production server (multi-threaded)")
        
        # Function to test if server is ready
        def check_server_ready():
            time.sleep(1)  # Wait for server to start
            try:
                import requests
                response = requests.get('http://localhost:5001', timeout=1)
                print("[OK] Server is ready and responding!")
                print("[OK] Waiting for requests... (Press Ctrl+C to stop)")
            except:
                print("[WARNING] Server may not be ready yet")
        
        # Start check in background thread
        threading.Thread(target=check_server_ready, daemon=True).start()
        
        # Start server (this blocks)
        serve(app, host='0.0.0.0', port=5001, threads=10)
        
    except ImportError:
        print("[WARNING] Waitress not installed. Using Flask dev server")
        print("[WARNING] Install waitress for better performance: pip install waitress")
        app.run(
            host='0.0.0.0', 
            port=5001, 
            debug=False,
            threaded=True,
            use_reloader=False
        )
