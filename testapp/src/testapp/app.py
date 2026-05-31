from flask import Flask, request, jsonify, session, redirect, url_for, render_template
from datetime import datetime
import json
import os
import time

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir)
app.secret_key = "test-secret-key-change-in-production"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

TRACE_HEADER = "X-Vulcan-Trace-Id"
GROUND_TRUTH_LOG = os.environ.get(
    "TESTAPP_GROUND_TRUTH_LOG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground_truth.jsonl"),
)


@app.before_request
def _record_trace():
    request.environ["_vulcan_start_ms"] = int(time.time() * 1000)


@app.after_request
def _log_trace(response):
    trace_id = request.headers.get(TRACE_HEADER)
    if not trace_id:
        return response
    record = {
        "trace_id": trace_id,
        "timestamp_ms": request.environ.get("_vulcan_start_ms", int(time.time() * 1000)),
        "method": request.method,
        "path": request.path,
        "status_code": response.status_code,
        "user_id": session.get("user_id"),
        "role": session.get("role"),
    }
    try:
        with open(GROUND_TRUTH_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass
    return response

users_db = {
    "1": {"username": "alice", "password": "password123", "role": "user", "email": "alice@test.com", "phone": "+1234567890"},
    "2": {"username": "bob", "password": "password456", "role": "user", "email": "bob@test.com", "phone": "+0987654321"},
    "3": {"username": "charlie", "password": "password789", "role": "user", "email": "charlie@test.com", "phone": "+1122334455"},
    "4": {"username": "admin", "password": "admin123", "role": "admin", "email": "admin@test.com", "phone": "+9998887776"},
}

orders_db = {
    "1": {"user_id": "1", "product": "Laptop", "price": 999.99, "status": "pending"},
    "2": {"user_id": "1", "product": "Mouse", "price": 29.99, "status": "shipped"},
    "3": {"user_id": "2", "product": "Keyboard", "price": 79.99, "status": "pending"},
    "4": {"user_id": "2", "product": "Monitor", "price": 299.99, "status": "delivered"},
    "5": {"user_id": "3", "product": "Headphones", "price": 149.99, "status": "pending"},
}

carts_db = {
    "1": {"user_id": "1", "items": [{"product": "Laptop", "qty": 1}]},
    "2": {"user_id": "2", "items": [{"product": "Keyboard", "qty": 2}]},
    "3": {"user_id": "3", "items": [{"product": "Headphones", "qty": 1}]},
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("index.html")

@app.route("/profile")
def profile_page():
    return render_template("profile.html")

@app.route("/orders")
def orders_page():
    return render_template("orders.html")

@app.route("/cart")
def cart_page():
    return render_template("cart.html")

@app.route("/products")
def products_page():
    return render_template("products.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    
    for user_id, user in users_db.items():
        if user["username"] == username and user["password"] == password:
            session["user_id"] = user_id
            session["username"] = user["username"]
            session["role"] = user["role"]
            return jsonify({
                "success": True,
                "user_id": user_id,
                "username": user["username"],
                "role": user["role"],
                "message": "Login successful"
            }), 200
    
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out"}), 200

@app.route("/api/profile", methods=["GET"])
def get_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = request.args.get("id") or session["user_id"]
    
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    user = users_db[user_id]
    return jsonify({
        "user_id": user_id,
        "username": user["username"],
        "email": user["email"],
        "phone": user["phone"],
        "role": user["role"]
    }), 200

@app.route("/api/profile", methods=["PUT"])
def update_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    user_id = data.get("user_id") or session["user_id"]
    
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    if "email" in data:
        users_db[user_id]["email"] = data["email"]
    if "phone" in data:
        users_db[user_id]["phone"] = data["phone"]
    
    return jsonify({"success": True, "message": "Profile updated"}), 200

@app.route("/api/orders", methods=["GET"])
def list_orders():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = request.args.get("user_id") or session["user_id"]
    
    user_orders = [{"order_id": oid, **order} for oid, order in orders_db.items() if order["user_id"] == user_id]
    return jsonify({"orders": user_orders}), 200

@app.route("/api/orders/<order_id>", methods=["GET"])
def get_order(order_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if order_id not in orders_db:
        return jsonify({"error": "Order not found"}), 404
    
    order = orders_db[order_id]
    return jsonify({"order_id": order_id, **order}), 200

@app.route("/api/orders/<order_id>", methods=["DELETE"])
def delete_order(order_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if order_id not in orders_db:
        return jsonify({"error": "Order not found"}), 404
    
    del orders_db[order_id]
    return jsonify({"success": True, "message": "Order deleted"}), 200

@app.route("/api/cart", methods=["GET"])
def get_cart():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    cart_id = request.args.get("cart_id") or session["user_id"]
    
    if cart_id not in carts_db:
        return jsonify({"error": "Cart not found"}), 404
    
    cart = carts_db[cart_id]
    return jsonify({"cart_id": cart_id, **cart}), 200

@app.route("/api/cart/add", methods=["POST"])
def add_to_cart():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    product = data.get("product")
    qty = data.get("qty", 1)
    
    user_id = session["user_id"]
    if user_id not in carts_db:
        carts_db[user_id] = {"user_id": user_id, "items": []}
    
    carts_db[user_id]["items"].append({"product": product, "qty": qty})
    return jsonify({"success": True, "message": "Item added to cart"}), 201

@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    
    all_users = {uid: {"user_id": uid, "username": u["username"], "role": u["role"]} for uid, u in users_db.items()}
    return jsonify({"users": all_users}), 200

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403
    
    if user_id not in users_db:
        return jsonify({"error": "User not found"}), 404
    
    del users_db[user_id]
    return jsonify({"success": True, "message": "User deleted"}), 200

@app.route("/api/products", methods=["GET"])
def list_products():
    products = [
        {"id": 1, "name": "Laptop", "price": 999.99},
        {"id": 2, "name": "Mouse", "price": 29.99},
        {"id": 3, "name": "Keyboard", "price": 79.99},
        {"id": 4, "name": "Monitor", "price": 299.99},
        {"id": 5, "name": "Headphones", "price": 149.99},
    ]
    return jsonify({"products": products}), 200

@app.route("/api/products/<product_id>", methods=["GET"])
def get_product(product_id):
    products = {
        "1": {"id": 1, "name": "Laptop", "price": 999.99, "description": "High-performance laptop"},
        "2": {"id": 2, "name": "Mouse", "price": 29.99, "description": "Wireless mouse"},
        "3": {"id": 3, "name": "Keyboard", "price": 79.99, "description": "Mechanical keyboard"},
        "4": {"id": 4, "name": "Monitor", "price": 299.99, "description": "4K monitor"},
        "5": {"id": 5, "name": "Headphones", "price": 149.99, "description": "Noise-cancelling headphones"},
    }
    
    if product_id not in products:
        return jsonify({"error": "Product not found"}), 404
    
    return jsonify(products[product_id]), 200

@app.route("/api/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    return jsonify({"query": query, "results": []}), 200

@app.route("/static/app.js", methods=["GET"])
def static_js():
    return jsonify({"content": "console.log('test');"}), 200

@app.route("/static/style.css", methods=["GET"])
def static_css():
    return jsonify({"content": "body { margin: 0; }"}), 200

def main():
    app.run(host="0.0.0.0", port=5001, debug=True)

if __name__ == "__main__":
    main()

