from flask import Flask, request, jsonify
import sqlite3
import datetime
import hashlib
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a secure key

def init_db():
    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        duration_days INTEGER,
        max_devices INTEGER DEFAULT 1,
        used INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        first_used TEXT,
        expire_at TEXT,
        hwid TEXT,
        created_by TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS resellers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'reseller'
    )
    """)

    # Insert default admin if not exists
    c.execute("INSERT OR IGNORE INTO resellers (username, password, role) VALUES (?, ?, ?)", ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin'))

    conn.commit()
    conn.close()

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token.split()[1], app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user = data
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("SELECT * FROM resellers WHERE username=? AND password=?", (username, hashlib.sha256(password.encode()).hexdigest()))
    user = c.fetchone()
    conn.close()

    if user:
        token = jwt.encode({'username': username, 'role': user[3]}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route("/generate_key", methods=["POST"])
@token_required
def generate_key():
    data = request.json
    duration = data['duration_days']
    max_devices = data.get('max_devices', 1)
    created_by = request.user['username']  # from token

    key = hashlib.md5(str(datetime.datetime.now()).encode()).hexdigest()[:16]  # simple key generation

    # Calculate expire_at if duration is set
    expire_at = None
    if duration > 0:
        expire_time = datetime.datetime.now() + datetime.timedelta(days=duration)
        expire_at = expire_time.isoformat()

    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, duration_days, max_devices, created_by, expire_at) VALUES (?, ?, ?, ?, ?)", (key, duration, max_devices, created_by, expire_at))
    conn.commit()
    conn.close()

    return jsonify({'key': key})

@app.route("/dashboard", methods=["GET"])
@token_required
def dashboard():
    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM keys")
    total_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM keys WHERE status='active'")
    active_keys = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM keys WHERE status='Expired'")
    expired_keys = c.fetchone()[0]
    conn.close()

    return jsonify({'total_keys': total_keys, 'active_keys': active_keys, 'expired_keys': expired_keys})

@app.route("/keys", methods=["GET"])
@token_required
def get_all_keys():
    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("SELECT id, key, duration_days, max_devices, used, status, first_used, expire_at, hwid, created_by FROM keys ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    
    keys = []
    for row in rows:
        keys.append({
            'id': row[0],
            'key': row[1],
            'duration_days': row[2],
            'max_devices': row[3],
            'used': row[4],
            'status': row[5],
            'first_used': row[6],
            'expire_at': row[7],
            'hwid': row[8],
            'created_by': row[9]
        })
    
    return jsonify({'keys': keys})

@app.route("/check_key", methods=["POST"])
def check_key():
    data = request.json
    user_key = data["key"]
    hwid = data["hwid"]

    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key=?", (user_key,))
    row = c.fetchone()

    if not row:
        return jsonify({"status": "invalid"})

    duration = row[2]
    max_devices = row[3]
    used = row[4]
    first_used = row[6]
    expire_at = row[7]
    bound_hwid = row[8]

    now = datetime.datetime.now()

    # Device Binding: Check if HWID matches
    if bound_hwid and bound_hwid != hwid:
        return jsonify({"status": "invalid_device"})

    # First activation
    if not first_used:
        c.execute("""
            UPDATE keys
            SET hwid=?, first_used=?, used=1, status='active'
            WHERE key=?
        """, (hwid, now.isoformat(), user_key))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "activated",
            "expire_at": expire_at
        })

    # Check expiration
    if expire_at:
        try:
            expire_time = datetime.datetime.fromisoformat(expire_at.replace('Z', '+00:00'))
        except ValueError:
            expire_time = None

        if expire_time and now >= expire_time:
            c.execute("UPDATE keys SET status='Expired' WHERE key=?", (user_key,))
            conn.commit()
            conn.close()
            return jsonify({"status": "expired"})

        if expire_time:
            remaining = expire_time - now
            conn.close()
            return jsonify({
                "status": "success",
                "remaining_hours": round(remaining.total_seconds() / 3600, 2)
            })

    conn.close()
    return jsonify({"status": "success"})

@app.route("/verify", methods=["GET"])
def verify_key():
    """
    Endpoint for external applications to verify keys via URL parameters.
    Usage: /verify?key=YOUR_KEY&hwid=YOUR_HWID
    """
    user_key = request.args.get("key")
    hwid = request.args.get("hwid")

    if not user_key:
        return jsonify({"status": "error", "message": "Key parameter is required"}), 400

    conn = sqlite3.connect("serverkey.db")
    c = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key=?", (user_key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "invalid", "message": "Key not found"})

    duration = row[2]
    max_devices = row[3]
    used = row[4]
    first_used = row[6]
    expire_at = row[7]
    bound_hwid = row[8]
    key_status = row[5]

    now = datetime.datetime.now()

    # Device Binding: Check if HWID matches
    if bound_hwid and hwid and bound_hwid != hwid:
        conn.close()
        return jsonify({"status": "invalid_device", "message": "Key bound to different device"})

    # First activation
    if not first_used:
        if hwid:
            c.execute("""
                UPDATE keys
                SET hwid=?, first_used=?, used=1, status='active'
                WHERE key=?
            """, (hwid, now.isoformat(), user_key))
        else:
            c.execute("""
                UPDATE keys
                SET first_used=?, used=1, status='active'
                WHERE key=?
            """, (now.isoformat(), user_key))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "activated",
            "expire_at": expire_at,
            "message": "Key activated successfully"
        })

    # Check expiration
    if expire_at:
        try:
            expire_time = datetime.datetime.fromisoformat(expire_at.replace('Z', '+00:00'))
        except ValueError:
            expire_time = None

        if expire_time and now >= expire_time:
            c.execute("UPDATE keys SET status='Expired' WHERE key=?", (user_key,))
            conn.commit()
            conn.close()
            return jsonify({"status": "expired", "message": "Key has expired"})

        if expire_time:
            remaining = expire_time - now
            conn.close()
            return jsonify({
                "status": "success",
                "remaining_hours": round(remaining.total_seconds() / 3600, 2),
                "expire_at": expire_at,
                "message": "Key is valid"
            })

    conn.close()
    return jsonify({"status": "success", "message": "Key is valid"})
@app.route("/")
def home():
    return "Server Flask đang chạy"

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
