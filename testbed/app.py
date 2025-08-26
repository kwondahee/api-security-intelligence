from flask import Flask, jsonify, request

app = Flask(__name__)

# A simple "database" of user data
# In a real app, this would be a database
USERS = {
    "101": {"name": "Alice", "balance": 1500},
    "102": {"name": "Bob", "balance": 750},
    "103": {"name": "Charlie", "balance": 2200},
}

# Vulnerability 1: Unauthenticated Access
@app.route("/api/v1/users/<user_id>", methods=["GET"])
def get_user_data(user_id):
    """
    Vulnerable endpoint.
    It returns user data without checking if the user is authenticated.
    """
    if user_id in USERS:
        user_info = USERS[user_id]
        return jsonify(user_info)
    return jsonify({"error": "User not found"}), 404

# Vulnerability 2: Broken Object Level Authorization (BOLA)
# This endpoint requires a token, but doesn't check if the token belongs to the requested user
@app.route("/api/v2/transactions/<user_id>", methods=["GET"])
def get_user_transactions(user_id):
    """
    Vulnerable endpoint with BOLA.
    It returns transaction data if *any* valid token is provided,
    regardless of which user the token belongs to.
    """
    token = request.headers.get("Authorization")

    # In a real application, you'd validate the token's signature and expiration.
    # Here, we'll just check if a token exists to simulate a basic auth check.
    if not token or not token.startswith("Bearer"):
        return jsonify({"error": "Authentication required"}), 401

    # Simulate a successful authentication check and fail to verify authorization
    # The vulnerability is here: no check to see if 'token' matches 'user_id'
    if user_id in USERS:
        return jsonify({
            "transactions": [
                {"id": "t1", "amount": 50, "date": "2025-08-20"},
                {"id": "t2", "amount": -20, "date": "2025-08-22"},
            ]
        })

    return jsonify({"error": "User not found"}), 404

# A secure endpoint for comparison
@app.route("/api/v1/public/status", methods=["GET"])
def get_status():
    """
    A secure, public endpoint.
    """
    return jsonify({"status": "OK"})

if __name__ == "__main__":
    app.run(debug=True)