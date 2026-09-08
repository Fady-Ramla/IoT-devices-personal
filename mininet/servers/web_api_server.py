#!/usr/bin/env python3
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# BASIC ROUTES
# ============================================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "server": "IoT Web/API Server",
        "status": "running",
        "ip": "10.0.0.2",
        "port": 80
    })

@app.route('/api', methods=['GET'])
def api():
    return jsonify({
        "status": "success",
        "message": "IoT API is running"
    })

@app.route('/api/devices', methods=['GET'])
def devices():
    return jsonify({
        "devices": [
            {"id": 1, "ip": "10.0.0.5", "status": "normal"},
            {"id": 2, "ip": "10.0.0.6", "status": "normal"}
        ]
    })

# ============================================================
# AUTHENTICATION ROUTES
# ============================================================

# Login endpoint (supports both GET and POST for testing)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Support both JSON and form data
        if request.is_json:
            data = request.get_json(silent=True) or {}
        else:
            data = request.form.to_dict()
        
        username = data.get('username') or data.get('user')
        password = data.get('password') or data.get('pass')
        
        if username == "admin" and password == "admin":
            return jsonify({
                "status": "success",
                "message": "Login successful",
                "token": "fake-jwt-token-123"
            }), 200
        else:
            return jsonify({
                "status": "failed",
                "message": "Invalid credentials"
            }), 401
    
    return jsonify({
        "endpoint": "/login",
        "method": "POST (or GET for info)"
    })

# Auth endpoint (GET only for now)
@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        token = request.form.get('token') or request.args.get('token')
        if token and token.startswith("fake"):
            return jsonify({
                "message": "Token validated successfully",
                "status": "authenticated",
                "token": token
            })
        else:
            return jsonify({
                "message": "Invalid token",
                "status": "failed"
            }), 401
    else:
        return jsonify({
            "status": "authenticated",
            "message": "Authentication endpoint",
            "method": "GET"
        })

# ============================================================
# ADMIN ROUTE
# ============================================================

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        cmd = request.form.get('cmd') or request.args.get('cmd')
        return jsonify({
            "message": f"Admin command executed: {cmd}",
            "status": "success",
            "role": "admin"
        })
    else:
        return jsonify({
            "status": "success",
            "message": "Admin page",
            "role": "admin"
        })

# ============================================================
# HEALTH CHECK
# ============================================================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "IoT Web/API Server"
    })

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
