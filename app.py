"""
NetGuard AI - Main Flask Application
Backend server providing Web UI routes, Authentication, and REST APIs for
simulated network monitoring, Random Forest anomaly detection, and AI explanations.
"""

import os
import sys
import json
import datetime
import random
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from database.db import (
    init_db, get_db_connection, insert_anomaly,
    get_anomalies, get_anomaly_by_id, update_anomaly_status,
    create_inbox_email, get_inbox_emails, get_inbox_email_by_id,
    mark_inbox_email_read, clear_inbox
)
from traffic_model import model_engine, NORMAL_THRESHOLDS
from data_generator import (
    ENDPOINTS, ANOMALY_TYPES, generate_normal_event,
    generate_anomaly_event, generate_live_snapshot
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
app.secret_key = os.environ.get("NETGUARD_SECRET_KEY", "netguard-ai-cyber-secret-key-2026-hackathon")

# ProxyFix ensures HTTPS and correct client IP behind Vercel edge reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

@app.route("/static/<path:filename>")
def serve_static_asset(filename):
    """Guaranteed static asset delivery across local dev and Vercel serverless."""
    for folder in [
        os.path.join(BASE_DIR, "public", "static"),
        os.path.join(BASE_DIR, "static"),
        os.path.join(BASE_DIR, "public")
    ]:
        target = os.path.join(folder, filename)
        if os.path.exists(target):
            return send_from_directory(folder, filename)
    return send_from_directory(os.path.join(BASE_DIR, "static"), filename)

# In-memory circular buffer of live telemetry snapshots (keeps last 30 snapshots for charts)
TELEMETRY_HISTORY = []
MAX_HISTORY_LEN = 30

# Simulated application settings
APP_SETTINGS = {
    "polling_interval": 3,
    "traffic_sensitivity": "Standard",
    "auto_quarantine": False,
    "email_notifications": False,
    "dark_mode": True
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized. Please log in."}), 401
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------------------------
# INITIAL TELEMETRY BUFFER SEEDING
# ---------------------------------------------------------------------------
def seed_telemetry_history():
    """Seeds initial real-time history ticks for smooth Chart.js rendering on startup."""
    global TELEMETRY_HISTORY
    if not TELEMETRY_HISTORY:
        now = datetime.datetime.now()
        for i in range(MAX_HISTORY_LEN, 0, -1):
            t_str = (now - datetime.timedelta(seconds=i * 3)).strftime("%H:%M:%S")
            snapshot = []
            for ep_id in sorted(ENDPOINTS.keys()):
                ev = generate_normal_event(endpoint_id=ep_id)
                ev["time_label"] = t_str
                snapshot.append(ev)
            TELEMETRY_HISTORY.append({
                "timestamp": t_str,
                "endpoints": snapshot,
                "avg_bandwidth": round(sum(e["bandwidth"] for e in snapshot) / len(snapshot), 1),
                "avg_latency": round(sum(e["latency"] for e in snapshot) / len(snapshot), 1),
                "avg_loss": round(sum(e["packet_loss"] for e in snapshot) / len(snapshot), 2),
                "avg_cpu": round(sum(e["cpu_utilization"] for e in snapshot) / len(snapshot), 1)
            })

# Initialize database and seed initial telemetry snapshots at module load
try:
    init_db()
    seed_telemetry_history()
except Exception as _e:
    print(f"[NetGuard AI] Startup initialization: {_e}")

# ---------------------------------------------------------------------------
# PAGE ROUTES
# ---------------------------------------------------------------------------
@app.route("/")
@app.route("/login")
@app.route("/api/index")
@app.route("/api/index.py")
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/register")
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active_page="dashboard", user=session.get("username", "Admin"))

@app.route("/monitoring")
@login_required
def monitoring():
    return render_template("monitoring.html", active_page="monitoring", user=session.get("username", "Admin"))

@app.route("/endpoints")
@login_required
def endpoints():
    return render_template("endpoints.html", active_page="endpoints", user=session.get("username", "Admin"))

@app.route("/anomalies")
@login_required
def anomalies():
    return render_template("anomalies.html", active_page="anomalies", user=session.get("username", "Admin"))

@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", active_page="analytics", user=session.get("username", "Admin"))

@app.route("/ai-insights")
@login_required
def ai_insights():
    return render_template("ai_insights.html", active_page="ai_insights", user=session.get("username", "Admin"))

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html", active_page="settings", user=session.get("username", "Admin"), settings=APP_SETTINGS)

@app.route("/inbox")
@login_required
def inbox():
    """Simulated NOC Security Mailbox (Authenticated SOC operators only)."""
    return render_template("inbox.html", active_page="inbox", user=session.get("username", "Admin"))

# ---------------------------------------------------------------------------
# AUTHENTICATION APIs
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data = request.get_json() or {}
        username_or_email = data.get("username", "").strip()
        password = data.get("password", "")

        if not username_or_email or not password:
            return jsonify({"error": "Please provide both username/email and password."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users WHERE username = ? OR email = ?
        """, (username_or_email, username_or_email))
        user = cursor.fetchone()
        conn.close()

        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid username or password. Please verify your credentials."}), 401

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["email"] = user["email"]

        return jsonify({
            "message": "Login successful.",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "full_name": user["full_name"]
            }
        })
    except Exception as e:
        return jsonify({"error": f"An error occurred during login: {str(e)}"}), 500

@app.route("/api/register", methods=["POST"])
def api_register():
    try:
        data = request.get_json() or {}
        full_name = data.get("full_name", "").strip()
        email = data.get("email", "").strip().lower()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        confirm_password = data.get("confirm_password", "")

        # Validation
        if not full_name or not email or not username or not password:
            return jsonify({"error": "All fields are required."}), 400

        if "@" not in email or "." not in email:
            return jsonify({"error": "Please enter a valid email address."}), 400

        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long."}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long."}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": f"Username '{username}' is already taken."}), 409

        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": f"Email '{email}' is already registered."}), 409

        hashed = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (full_name, email, username, password_hash)
            VALUES (?, ?, ?, ?)
        """, (full_name, email, username, hashed))
        new_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Automatically log in after registration
        session["user_id"] = new_id
        session["username"] = username
        session["full_name"] = full_name
        session["email"] = email

        return jsonify({"message": "Account created successfully.", "username": username}), 201
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

# ---------------------------------------------------------------------------
# SIMULATED NOC SECURITY MAILBOX APIs
# ---------------------------------------------------------------------------
@app.route("/api/inbox")
@login_required
def api_inbox_list():
    """Returns all simulated emails dispatched by the platform."""
    emails = get_inbox_emails(limit=30)
    return jsonify({"emails": emails, "count": len(emails)})

@app.route("/api/inbox/<int:email_id>")
@login_required
def api_inbox_get(email_id):
    """Retrieves single email and marks as read."""
    email_obj = get_inbox_email_by_id(email_id)
    if not email_obj:
        return jsonify({"error": "Message not found."}), 404
    mark_inbox_email_read(email_id)
    return jsonify(email_obj)

@app.route("/api/inbox/clear", methods=["POST"])
@login_required
def api_inbox_clear():
    """Clears all simulated emails."""
    clear_inbox()
    return jsonify({"message": "Security mailbox cleared."})

# ---------------------------------------------------------------------------
# REAL-TIME NETWORK TELEMETRY APIS
# ---------------------------------------------------------------------------
@app.route("/api/network-data")
@app.route("/api/traffic")
@login_required
def api_network_data():
    """
    Returns latest real-time network telemetry snapshot across simulated endpoints.
    Appends a new tick to in-memory TELEMETRY_HISTORY buffer.
    """
    global TELEMETRY_HISTORY
    now = datetime.datetime.now()
    now_str = now.strftime("%H:%M:%S")

    # Generate current telemetry for all simulated endpoints
    current_endpoints = []

    # Continuous Autonomous Anomaly Simulation:
    # Naturally introduce realistic anomalies into live traffic (~10% probability per 3s tick, ~every 25-30s)
    should_inject_anomaly = random.random() < 0.10
    anomaly_target_ep = random.choice(list(ENDPOINTS.keys())) if should_inject_anomaly else None

    for ep_id in sorted(ENDPOINTS.keys()):
        if ep_id == anomaly_target_ep:
            telemetry = generate_anomaly_event(endpoint_id=ep_id)
            # Run Random Forest ML model in real time
            pred = model_engine.predict_and_explain(telemetry)
            if pred.get("prediction") == 1:
                try:
                    insert_anomaly(
                        endpoint_id=ep_id,
                        anomaly_type=pred.get("anomaly_type", "Abnormal Telemetry"),
                        severity=pred.get("severity", "High"),
                        confidence=pred.get("confidence", 0.92),
                        bandwidth=telemetry["bandwidth"],
                        latency=telemetry["latency"],
                        packet_loss=telemetry["packet_loss"],
                        cpu_utilization=telemetry["cpu_utilization"],
                        memory_utilization=telemetry["memory_utilization"],
                        active_connections=telemetry["active_connections"],
                        explanation=pred.get("explanation", "Autonomous real-time anomaly detected by Random Forest model."),
                        contributing_factors=json.dumps(pred.get("contributing_factors", []))
                    )
                except Exception as _e:
                    print(f"[NetGuard AI] Autonomous anomaly logging notice: {_e}")
        else:
            telemetry = generate_normal_event(endpoint_id=ep_id)

        telemetry["time_label"] = now_str
        telemetry["role"] = ENDPOINTS[ep_id]["role"]
        telemetry["location"] = ENDPOINTS[ep_id]["location"]
        current_endpoints.append(telemetry)

    # Compute network-wide snapshot aggregates
    avg_bandwidth = round(sum(e["bandwidth"] for e in current_endpoints) / len(current_endpoints), 1)
    total_bandwidth = round(sum(e["bandwidth"] for e in current_endpoints), 1)
    avg_latency = round(sum(e["latency"] for e in current_endpoints) / len(current_endpoints), 1)
    avg_loss = round(sum(e["packet_loss"] for e in current_endpoints) / len(current_endpoints), 2)
    avg_cpu = round(sum(e["cpu_utilization"] for e in current_endpoints) / len(current_endpoints), 1)
    total_conns = sum(e["active_connections"] for e in current_endpoints)
    total_packets = sum(e["packets_sent"] + e["packets_received"] for e in current_endpoints)

    # Buffer management
    TELEMETRY_HISTORY.append({
        "timestamp": now_str,
        "endpoints": current_endpoints,
        "avg_bandwidth": avg_bandwidth,
        "total_bandwidth": total_bandwidth,
        "avg_latency": avg_latency,
        "avg_loss": avg_loss,
        "avg_cpu": avg_cpu,
        "total_conns": total_conns
    })
    if len(TELEMETRY_HISTORY) > MAX_HISTORY_LEN:
        TELEMETRY_HISTORY.pop(0)

    # Fetch recent anomaly count and alerts
    all_anomalies = get_anomalies(limit=5)
    critical_count = len([a for a in all_anomalies if a["severity"] in ["High", "Critical"]])

    # Most recent alert
    latest_alert = all_anomalies[0] if all_anomalies else None

    # Get total anomaly count from db
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM anomalies")
    total_anomalies = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE severity IN ('High', 'Critical')")
    critical_alerts = c.fetchone()["cnt"]
    conn.close()

    return jsonify({
        "timestamp": now_str,
        "summary": {
            "total_endpoints": len(ENDPOINTS),
            "active_endpoints": len(ENDPOINTS),
            "current_bandwidth": f"{total_bandwidth} Mbps",
            "avg_latency": f"{avg_latency} ms",
            "avg_loss": f"{avg_loss}%",
            "detected_anomalies": total_anomalies,
            "critical_alerts": critical_alerts
        },
        "latest_alert": latest_alert,
        "endpoints": current_endpoints,
        "history": [
            {
                "time": item["timestamp"],
                "bandwidth": item.get("total_bandwidth", item.get("avg_bandwidth", 0)),
                "latency": item["avg_latency"],
                "packet_loss": item["avg_loss"],
                "cpu": item["avg_cpu"],
                "connections": item.get("total_conns", 150)
            }
            for item in TELEMETRY_HISTORY
        ]
    })

# ---------------------------------------------------------------------------
# ENDPOINTS APIS
# ---------------------------------------------------------------------------
@app.route("/api/endpoints")
@login_required
def api_endpoints():
    """Returns status, metrics, and anomaly counts for all 5 simulated endpoints."""
    # Count anomalies per endpoint from DB
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT endpoint_id, COUNT(*) as cnt, MAX(timestamp) as last_anomaly FROM anomalies GROUP BY endpoint_id")
    stats = {row["endpoint_id"]: {"count": row["cnt"], "last_anomaly": row["last_anomaly"]} for row in c.fetchall()}
    conn.close()

    endpoints_list = []
    # Use the most recent telemetry from TELEMETRY_HISTORY if available
    latest_snapshot = TELEMETRY_HISTORY[-1]["endpoints"] if TELEMETRY_HISTORY else generate_live_snapshot()

    for item in latest_snapshot:
        ep_id = item["endpoint_id"]
        ep_meta = ENDPOINTS.get(ep_id, {})
        anomaly_stat = stats.get(ep_id, {"count": 0, "last_anomaly": "None"})

        # Determine simulated status
        if anomaly_stat["count"] > 3 and item.get("cpu_utilization", 0) > 70:
            status = "Warning"
        elif item.get("label", 0) == 1:
            status = "Anomalous"
        else:
            status = "Normal"

        endpoints_list.append({
            "endpoint_id": ep_id,
            "ip_address": ep_meta.get("ip", item.get("ip_address")),
            "role": ep_meta.get("role", "Node"),
            "location": ep_meta.get("location", "Datacenter"),
            "status": status,
            "bandwidth": item.get("bandwidth", 0),
            "latency": item.get("latency", 0),
            "packet_loss": item.get("packet_loss", 0),
            "cpu_utilization": item.get("cpu_utilization", 0),
            "memory_utilization": item.get("memory_utilization", 0),
            "active_connections": item.get("active_connections", 0),
            "packets_sent": item.get("packets_sent", 0),
            "packets_received": item.get("packets_received", 0),
            "last_seen": "Just now",
            "anomaly_count": anomaly_stat["count"],
            "last_anomaly": anomaly_stat["last_anomaly"]
        })

    return jsonify({"endpoints": endpoints_list})

@app.route("/api/endpoints/<endpoint_id>")
@login_required
def api_endpoint_detail(endpoint_id):
    """Returns deep-dive telemetry and anomaly history for a single simulated endpoint."""
    if endpoint_id not in ENDPOINTS:
        return jsonify({"error": f"Endpoint '{endpoint_id}' not found."}), 404

    ep_meta = ENDPOINTS[endpoint_id]

    # Get recent anomalies for this endpoint
    anomalies = get_anomalies(limit=10, endpoint_id=endpoint_id)

    # Extract historical telemetry points for this endpoint
    history_points = []
    for snapshot in TELEMETRY_HISTORY:
        for ep in snapshot["endpoints"]:
            if ep["endpoint_id"] == endpoint_id:
                history_points.append({
                    "time": snapshot["timestamp"],
                    "bandwidth": ep["bandwidth"],
                    "latency": ep["latency"],
                    "packet_loss": ep["packet_loss"],
                    "cpu": ep["cpu_utilization"],
                    "memory": ep["memory_utilization"],
                    "connections": ep["active_connections"]
                })

    current = history_points[-1] if history_points else generate_normal_event(endpoint_id)

    return jsonify({
        "endpoint_id": endpoint_id,
        "ip_address": ep_meta["ip"],
        "role": ep_meta["role"],
        "location": ep_meta["location"],
        "current": current,
        "history": history_points,
        "anomalies": anomalies,
        "total_anomalies": len(anomalies)
    })

# ---------------------------------------------------------------------------
# ANOMALIES APIS
# ---------------------------------------------------------------------------
@app.route("/api/anomalies")
@login_required
def api_anomalies():
    """Returns anomaly logs with optional filters."""
    severity = request.args.get("severity")
    endpoint_id = request.args.get("endpoint_id")
    status = request.args.get("status")
    limit = int(request.args.get("limit", 50))

    anomalies_data = get_anomalies(limit=limit, severity=severity, endpoint_id=endpoint_id, status=status)
    return jsonify({"anomalies": anomalies_data, "total": len(anomalies_data)})

@app.route("/api/anomalies/<int:anomaly_id>")
@login_required
def api_anomaly_detail(anomaly_id):
    """Retrieves full record of an anomaly event."""
    anomaly = get_anomaly_by_id(anomaly_id)
    if not anomaly:
        return jsonify({"error": f"Anomaly ID {anomaly_id} not found."}), 404
    return jsonify(anomaly)

@app.route("/api/anomalies/<int:anomaly_id>/status", methods=["POST"])
@login_required
def api_anomaly_update_status(anomaly_id):
    """Updates status of an anomaly (e.g. Active, Investigating, Resolved)."""
    data = request.get_json() or {}
    new_status = data.get("status")
    if new_status not in ["Active", "Investigating", "Resolved"]:
        return jsonify({"error": "Invalid status. Allowed values: Active, Investigating, Resolved."}), 400

    success = update_anomaly_status(anomaly_id, new_status)
    if not success:
        return jsonify({"error": "Anomaly record not found."}), 404

    return jsonify({"message": f"Anomaly status updated to {new_status}.", "status": new_status})

# ---------------------------------------------------------------------------
# ML PREDICTION & DEMO ANOMALY GENERATION APIS
# ---------------------------------------------------------------------------
@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    POST /api/predict
    Evaluates telemetry via Random Forest model and generates explanation & action.
    """
    try:
        telemetry = request.get_json(silent=True) or {}
        if not telemetry:
            return jsonify({"error": "Empty or invalid JSON telemetry provided."}), 400

        result = model_engine.predict_telemetry(telemetry)
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

@app.route("/api/generate-anomaly", methods=["POST"])
def api_generate_anomaly():
    """
    Hackathon Demo Trigger:
    1. Generates abnormal synthetic telemetry.
    2. Runs through Random Forest prediction API.
    3. Analyzes abnormal features, calculates severity & ML confidence.
    4. Generates natural language AI explanation & recommended action.
    5. Stores anomaly in SQLite database.
    6. Returns detected anomaly event for real-time UI display.
    """
    try:
        data = request.get_json(silent=True) or {}
        endpoint_id = data.get("endpoint_id") or random.choice(list(ENDPOINTS.keys()))
        anomaly_type = data.get("anomaly_type") or random.choice(ANOMALY_TYPES)

        # 1. Generate abnormal synthetic telemetry
        raw_event = generate_anomaly_event(endpoint_id=endpoint_id, anomaly_type=anomaly_type)

        # 2. Run through ML Model & Explanation Engine
        prediction_result = model_engine.predict_telemetry(raw_event)

        # 3. Prepare DB Record
        record = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint_id": prediction_result["endpoint_id"],
            "ip_address": prediction_result["ip_address"],
            "anomaly_type": anomaly_type,
            "severity": prediction_result["severity"],
            "confidence": prediction_result["confidence"],
            "bandwidth": raw_event["bandwidth"],
            "latency": raw_event["latency"],
            "packet_loss": raw_event["packet_loss"],
            "cpu_utilization": raw_event["cpu_utilization"],
            "memory_utilization": raw_event["memory_utilization"],
            "active_connections": raw_event["active_connections"],
            "packets_sent": raw_event["packets_sent"],
            "packets_received": raw_event["packets_received"],
            "contributing_factors": prediction_result["contributing_factors"],
            "explanation": prediction_result["explanation"],
            "recommended_action": prediction_result["recommended_action"],
            "status": "Active"
        }

        # 4. Store in SQLite
        anomaly_id = insert_anomaly(record)
        record["id"] = anomaly_id
        record["abnormal_details"] = prediction_result["abnormal_details"]

        # 5. Inject into current live telemetry buffer for instant visual spike
        if TELEMETRY_HISTORY:
            # Update the latest snapshot
            for ep in TELEMETRY_HISTORY[-1]["endpoints"]:
                if ep["endpoint_id"] == endpoint_id:
                    ep.update(raw_event)
            TELEMETRY_HISTORY[-1]["total_bandwidth"] = round(sum(e["bandwidth"] for e in TELEMETRY_HISTORY[-1]["endpoints"]), 1)

        return jsonify({
            "message": "Anomaly successfully simulated, classified, and stored.",
            "anomaly": record
        }), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Anomaly generation failed: {str(e)}"}), 500

# ---------------------------------------------------------------------------
# ANALYTICS & AI INSIGHTS APIS
# ---------------------------------------------------------------------------
@app.route("/api/analytics")
@login_required
def api_analytics():
    """Aggregates historical metrics, severity distribution, and traffic patterns."""
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as cnt FROM anomalies")
    total_anomalies = c.fetchone()["cnt"]

    # Severity distribution
    c.execute("SELECT severity, COUNT(*) as cnt FROM anomalies GROUP BY severity")
    severity_dist = {row["severity"]: row["cnt"] for row in c.fetchall()}
    for s in ["Low", "Medium", "High", "Critical"]:
        severity_dist.setdefault(s, 0)

    # Anomaly types breakdown
    c.execute("SELECT anomaly_type, COUNT(*) as cnt FROM anomalies GROUP BY anomaly_type")
    type_dist = {row["anomaly_type"]: row["cnt"] for row in c.fetchall()}

    # Most affected endpoints
    c.execute("SELECT endpoint_id, COUNT(*) as cnt FROM anomalies GROUP BY endpoint_id ORDER BY cnt DESC")
    endpoint_impact = [{"endpoint_id": row["endpoint_id"], "count": row["cnt"]} for row in c.fetchall()]

    # Compute averages from recent buffer
    if TELEMETRY_HISTORY:
        avg_bw = round(sum(h.get("total_bandwidth", 350) for h in TELEMETRY_HISTORY) / len(TELEMETRY_HISTORY), 1)
        avg_lat = round(sum(h["avg_latency"] for h in TELEMETRY_HISTORY) / len(TELEMETRY_HISTORY), 1)
        avg_loss = round(sum(h["avg_loss"] for h in TELEMETRY_HISTORY) / len(TELEMETRY_HISTORY), 2)
        total_traffic_gb = round(sum(h.get("total_bandwidth", 0) for h in TELEMETRY_HISTORY) * 3 / 8000, 2)
    else:
        avg_bw, avg_lat, avg_loss, total_traffic_gb = 480.0, 24.5, 0.45, 12.8

    conn.close()

    return jsonify({
        "total_anomalies": total_anomalies,
        "total_traffic_gb": total_traffic_gb,
        "avg_bandwidth": avg_bw,
        "avg_latency": avg_lat,
        "avg_loss": avg_loss,
        "severity_distribution": severity_dist,
        "anomaly_types": type_dist,
        "endpoint_impact": endpoint_impact,
        "most_affected_endpoint": endpoint_impact[0]["endpoint_id"] if endpoint_impact else "None"
    })

@app.route("/api/ai-insights")
@login_required
def api_ai_insights():
    """Dynamically generates high-level network health insights and recommendations."""
    anomalies = get_anomalies(limit=20)
    high_crit_count = len([a for a in anomalies if a["severity"] in ["High", "Critical"]])
    active_count = len([a for a in anomalies if a.get("status") == "Active"])

    insights = []

    if high_crit_count > 0:
        insights.append({
            "category": "Critical Risk",
            "level": "high",
            "title": f"Elevated Threat Activity ({high_crit_count} High/Critical Events)",
            "description": f"The Random Forest model has flagged {high_crit_count} anomalous events with severe deviations in bandwidth, CPU saturation, or concurrent connections across simulated nodes. Immediate remediation is advised."
        })

    # Identify most impacted node
    ep_counts = {}
    for a in anomalies:
        ep_counts[a["endpoint_id"]] = ep_counts.get(a["endpoint_id"], 0) + 1

    if ep_counts:
        top_ep = max(ep_counts, key=ep_counts.get)
        insights.append({
            "category": "Endpoint Concentration",
            "level": "medium",
            "title": f"{top_ep} Recorded Highest Anomaly Frequency",
            "description": f"Simulated endpoint {top_ep} ({ENDPOINTS[top_ep]['ip']}) accounts for {ep_counts[top_ep]} abnormal events ({int(ep_counts[top_ep] / len(anomalies) * 100)}% of recent incidents). Recommend targeted socket inspection."
        })

    insights.append({
        "category": "Traffic Dynamics",
        "level": "low",
        "title": "Continuous Synthetic Telemetry Ingestion Active",
        "description": "5 simulated endpoints are streaming multi-dimensional telemetry at 3-second polling intervals. Random Forest inference is executing at sub-15ms latency per packet vector."
    })

    recommendations = [
        {"action": "Inspect Affected Endpoints", "priority": "High", "details": "Review active TCP connection tables and socket utilization on nodes exhibiting connection floods."},
        {"action": "Enforce Ingress Rate Limiting", "priority": "High", "details": "Throttle traffic bursts exceeding 800 Mbps on simulated edge ingress nodes to safeguard internal replica nodes."},
        {"action": "Simulated Gateway Diagnostic", "priority": "Medium", "details": "Run route latency trace and virtual MTU verification on gateways showing packet loss above 2.0%."},
        {"action": "Host Resource Scaling", "priority": "Medium", "details": "Monitor CPU and RAM allocations on nodes reaching >85% resource utilization."},
        {"action": "Model Retraining Verification", "priority": "Low", "details": "Random Forest model maintains 100% test evaluation score on 8 synthetic feature dimensions."}
    ]

    return jsonify({
        "insights": insights,
        "recommendations": recommendations,
        "active_anomalies": active_count,
        "analyzed_events": len(anomalies)
    })

@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    """Get or update application settings."""
    global APP_SETTINGS
    if request.method == "POST":
        data = request.get_json() or {}
        if "polling_interval" in data:
            APP_SETTINGS["polling_interval"] = max(1, min(10, int(data["polling_interval"])))
        if "traffic_sensitivity" in data:
            APP_SETTINGS["traffic_sensitivity"] = data["traffic_sensitivity"]
        if "auto_quarantine" in data:
            APP_SETTINGS["auto_quarantine"] = bool(data["auto_quarantine"])
        if "email_notifications" in data:
            APP_SETTINGS["email_notifications"] = bool(data["email_notifications"])
        return jsonify({"message": "Settings updated successfully.", "settings": APP_SETTINGS})
    return jsonify({"settings": APP_SETTINGS})

# ---------------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/") and request.path not in ["/api", "/api/", "/api/index", "/api/index.py"]:
        return jsonify({"error": "Requested resource was not found."}), 404
    if request.is_json:
        return jsonify({"error": "Requested resource was not found."}), 404
    return render_template("login.html"), 404

@app.errorhandler(500)
def server_error(e):
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({"error": "An internal server error occurred."}), 500
    return "An internal server error occurred. Please contact SOC support.", 500

# ---------------------------------------------------------------------------
# APPLICATION ENTRYPOINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Ensure database is initialized
    init_db()
    # Seed live telemetry history
    seed_telemetry_history()
    print("=============================================================")
    print("  NETGUARD AI - CYBERSECURITY OPERATIONS CENTER")
    print("  AI-Powered Network Management & Anomaly Detection")
    print("=============================================================")
    print("  * Local Web App: http://127.0.0.1:5000")
    print("  * Default Admin: admin  |  Password: Admin@123")
    print("  * Machine Learning: Random Forest Classifier Active")
    print("  * Scope: 100% Software-Only (Simulated Endpoints EP-001..005)")
    print("=============================================================")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
