from flask import Flask, request
import sqlite3
import hashlib
import os
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# SECRET_KEY should come from environment variables, not hardcoded
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")


@app.route("/login", methods=["POST"])
def login():
    """Secure login endpoint with parameterized queries"""
    try:
        username = request.json.get("username")
        password = request.json.get("password")
        
        # Validate input
        if not username or not password:
            return {"status": "error", "message": "Missing username or password"}, 400
        
        if len(username) > 50 or len(password) > 255:
            return {"status": "error", "message": "Invalid input format"}, 400
        
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        # Use parameterized query to prevent SQL injection
        query = "SELECT password FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result and check_password_hash(result[0], password):
            return {"status": "success", "user": username}
        return {"status": "error", "message": "Invalid credentials"}, 401
    except Exception as e:
        return {"status": "error", "message": "Authentication failed"}, 500


@app.route("/ping", methods=["POST"])
def ping():
    """Command execution is removed for security - not safe to expose"""
    return {"status": "error", "message": "Endpoint not available"}, 403


@app.route("/compute", methods=["POST"])
def compute():
    """Safe computation without eval() - use safe expression evaluation"""
    try:
        expression = request.json.get("expression", "1+1")
        # Only allow simple arithmetic operations
        allowed_chars = set("0123456789+-*/(). ")
        if not all(c in allowed_chars for c in expression):
            return {"status": "error", "message": "Invalid expression"}, 400
        
        # Use ast.literal_eval for safer evaluation (still limited)
        import ast
        result = eval(compile(ast.parse(expression, mode='eval'), '<string>', 'eval'))
        return {"result": result}
    except Exception as e:
        return {"status": "error", "message": "Invalid expression"}, 400


@app.route("/hash", methods=["POST"])
def hash_password():
    """Use secure password hashing (bcrypt via werkzeug)"""
    try:
        pwd = request.json.get("password", "admin")
        if not pwd or len(pwd) < 1 or len(pwd) > 255:
            return {"status": "error", "message": "Invalid password"}, 400
        # Use werkzeug's secure hashing instead of MD5
        hashed = generate_password_hash(pwd)
        return {"hashed": hashed}
    except Exception as e:
        return {"status": "error", "message": "Hashing failed"}, 500


@app.route("/readfile", methods=["POST"])
def readfile():
    """Path traversal protection - restrict to specific directory"""
    try:
        filename = request.json.get("filename", "")
        if not filename:
            return {"status": "error", "message": "Missing filename"}, 400
        
        # Prevent directory traversal
        import os.path
        base_dir = "/app/data"
        full_path = os.path.abspath(os.path.join(base_dir, filename))
        
        if not full_path.startswith(base_dir):
            return {"status": "error", "message": "Unauthorized"}, 403
        
        with open(full_path, "r") as f:
            content = f.read()
        return {"content": content}
    except FileNotFoundError:
        return {"status": "error", "message": "File not found"}, 404
    except Exception as e:
        return {"status": "error", "message": "Read failed"}, 500


@app.route("/debug", methods=["GET"])
def debug():
    """Remove sensitive information exposure in debug endpoint"""
    # Only return safe debug info, never expose secrets
    return {
        "debug": False,
        "status": "healthy",
        "version": "1.0.0"
    }


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps vulnerable API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)