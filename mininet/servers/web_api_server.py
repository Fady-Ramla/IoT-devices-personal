from flask import Flask, request, jsonify

app = Flask(__name__)


# =========================
# LOGIN
# =========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}

        username = data.get('username')
        password = data.get('password')

        if username == 'admin' and password == 'admin':
            return jsonify({
                'status': 'success',
                'message': 'Login successful'
            }), 200

        return jsonify({
            'status': 'failed',
            'message': 'Invalid credentials'
        }), 401

    return jsonify({
        'endpoint': '/login',
        'method': 'POST'
    })


# =========================
# AUTHENTICATION
# =========================
@app.route('/auth', methods=['GET'])
def auth():
    return jsonify({
        'status': 'authenticated',
        'message': 'Authentication endpoint'
    })


# =========================
# ADMIN
# =========================
@app.route('/admin', methods=['GET'])
def admin():
    return jsonify({
        'status': 'success',
        'message': 'Admin page',
        'role': 'admin'
    })


# =========================
# API
# =========================
@app.route('/api', methods=['GET'])
def api():
    return jsonify({
        'status': 'success',
        'message': 'IoT API is running'
    })


# =========================
# API ENDPOINT
# =========================
@app.route('/api/devices', methods=['GET'])
def devices():
    return jsonify({
        'devices': [
            {'id': 1, 'ip': '10.0.0.5', 'status': 'normal'},
            {'id': 2, 'ip': '10.0.0.6', 'status': 'normal'}
        ]
    })


# =========================
# HEALTH CHECK
# =========================
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'server': 'IoT Web/API Server',
        'status': 'running',
        'ip': '10.0.0.2',
        'port': 80
    })


# =========================
# START SERVER
# =========================
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )
