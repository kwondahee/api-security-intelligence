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

@app.route('/')
def home():
    return jsonify({
        "message": "Mock Vulnerable API for Security Testing",
        "version": "1.0",
        "endpoints": ["/openapi.json", "/books/v1/search", "/users/v1/profile/<id>", "/admin/users"]
    })

@app.route('/openapi.json')
def openapi():
    """Return OpenAPI specification"""
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Mock Vulnerable API",
            "version": "1.0",
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

# Request counter for rate limiting tests
request_counts = {}

@app.before_request
def track_requests():
    """Track requests for rate limiting detection"""
    ip = request.remote_addr
    request_counts[ip] = request_counts.get(ip, 0) + 1

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
