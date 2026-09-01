"""
NetGuard AI - Database Access & Management
SQLite database operations for Users and Anomaly records.
"""

import os
import sqlite3
import json
import datetime
import tempfile
import shutil
from werkzeug.security import generate_password_hash

# Vercel Serverless environment support
IS_VERCEL = os.environ.get("VERCEL", "").lower() in ["1", "true"] or bool(os.environ.get("NOW_REGION"))

if IS_VERCEL:
    DB_DIR = tempfile.gettempdir()
    DB_PATH = os.path.join(DB_DIR, "netguard.db")
    bundled_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netguard.db")
    if not os.path.exists(DB_PATH) and os.path.exists(bundled_db):
        try:
            shutil.copy2(bundled_db, DB_PATH)
        except Exception:
            pass
else:
    DB_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(DB_DIR, "netguard.db")

def get_db_connection():
    """Returns a connection to the SQLite database with Row factory enabled."""
    if not IS_VERCEL:
        os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database tables and pre-seeds default admin user and initial anomalies."""
    if not IS_VERCEL:
        os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Anomalies Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            bandwidth REAL NOT NULL,
            latency REAL NOT NULL,
            packet_loss REAL NOT NULL,
            cpu_utilization REAL NOT NULL,
            memory_utilization REAL NOT NULL,
            active_connections INTEGER NOT NULL,
            packets_sent INTEGER NOT NULL,
            packets_received INTEGER NOT NULL,
            contributing_factors TEXT NOT NULL,
            explanation TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            status TEXT DEFAULT 'Active'
        )
    """)

    # Password Resets Table for Secure OTP Verification
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Simulated NOC Security Mailbox for Out-of-Band Verifications
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simulated_inbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_email TEXT NOT NULL,
            recipient_username TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_html TEXT NOT NULL,
            verification_code TEXT,
            timestamp TEXT NOT NULL,
            is_read INTEGER DEFAULT 0
        )
    """)

    # Seed default admin user if not exists
    cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if not cursor.fetchone():
        hashed = generate_password_hash("Admin@123")
        cursor.execute("""
            INSERT INTO users (full_name, email, username, password_hash)
            VALUES (?, ?, ?, ?)
        """, ("Security Operations Center", "admin@netguard.ai", "admin", hashed))
        print("[NetGuard DB] Seeded default administrator account: admin / Admin@123")

    # Seed realistic initial anomalies if table is empty
    cursor.execute("SELECT COUNT(*) as count FROM anomalies")
    count = cursor.fetchone()["count"]
    if count == 0:
        seed_anomalies(cursor)
        print("[NetGuard DB] Seeded initial network anomaly events")

    conn.commit()
    conn.close()

def seed_anomalies(cursor):
    """Inserts sample anomaly events for initial demonstration."""
    sample_records = [
        {
            "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=35)).strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint_id": "EP-004",
            "ip_address": "192.168.1.104",
            "anomaly_type": "Traffic Spike",
            "severity": "High",
            "confidence": 0.94,
            "bandwidth": 950.0,
            "latency": 180.0,
            "packet_loss": 14.0,
            "cpu_utilization": 94.0,
            "memory_utilization": 87.0,
            "active_connections": 420,
            "packets_sent": 50000,
            "packets_received": 46000,
            "contributing_factors": json.dumps([
                "Bandwidth: 950.0 Mbps (Normal: 50.0–450.0 Mbps)",
                "Active Connections: 420 conn (Normal: 25–180 conn)",
                "CPU Utilization: 94.0 % (Normal: 10.0–65.0 %)",
                "Packet Loss: 14.0 % (Normal: 0.0–2.0 %)"
            ]),
            "explanation": "EP-004 (192.168.1.104) experienced a massive traffic surge and resource saturation event exhibiting 950.0 Mbps bandwidth, 420 conn active connections, 94.0 % cpu utilization, and 14.0 % packet loss. These measurements significantly exceed established operational baselines, leading our Random Forest ML model to classify this event as a High-severity anomaly with 94% confidence.",
            "recommended_action": "Apply ingress rate limiting / QoS traffic shaping on endpoint socket. Inspect connection state tables for SYN/connection flood; enforce TCP connection limits. Inspect simulated host daemon processes, thread pools, and memory leaks. Run virtual route diagnostic and MTU/duplex verification on simulated gateway.",
            "status": "Active"
        },
        {
            "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=72)).strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint_id": "EP-002",
            "ip_address": "192.168.1.102",
            "anomaly_type": "Connection Flood",
            "severity": "High",
            "confidence": 0.92,
            "bandwidth": 680.0,
            "latency": 45.0,
            "packet_loss": 1.2,
            "cpu_utilization": 86.0,
            "memory_utilization": 74.0,
            "active_connections": 780,
            "packets_sent": 38000,
            "packets_received": 14000,
            "contributing_factors": json.dumps([
                "Active Connections: 780 conn (Normal: 25–180 conn)",
                "CPU Utilization: 86.0 % (Normal: 10.0–65.0 %)",
                "Bandwidth: 680.0 Mbps (Normal: 50.0–450.0 Mbps)"
            ]),
            "explanation": "EP-002 (192.168.1.102) experienced an abnormal connection flood targeting simulated ingress sockets exhibiting 780 conn active connections, 86.0 % cpu utilization, and 680.0 Mbps bandwidth. These measurements significantly exceed established operational baselines, leading our Random Forest ML model to classify this event as a High-severity anomaly with 92% confidence.",
            "recommended_action": "Inspect connection state tables for SYN/connection flood; enforce TCP connection limits. Apply ingress rate limiting / QoS traffic shaping on endpoint socket.",
            "status": "Investigating"
        },
        {
            "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=115)).strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint_id": "EP-005",
            "ip_address": "192.168.1.105",
            "anomaly_type": "High Latency",
            "severity": "Medium",
            "confidence": 0.88,
            "bandwidth": 180.0,
            "latency": 240.0,
            "packet_loss": 8.5,
            "cpu_utilization": 42.0,
            "memory_utilization": 51.0,
            "active_connections": 85,
            "packets_sent": 7200,
            "packets_received": 6500,
            "contributing_factors": json.dumps([
                "Latency: 240.0 ms (Normal: 8.0–50.0 ms)",
                "Packet Loss: 8.5 % (Normal: 0.0–2.0 %)"
            ]),
            "explanation": "EP-005 (192.168.1.105) experienced severe network degradation characterized by latency spikes and dropped packets exhibiting 240.0 ms latency, and 8.5 % packet loss. These measurements significantly exceed established operational baselines, leading our Random Forest ML model to classify this event as a Medium-severity anomaly with 88% confidence.",
            "recommended_action": "Run virtual route diagnostic and MTU/duplex verification on simulated gateway. Monitor endpoint telemetry for recurrent variance.",
            "status": "Resolved"
        },
        {
            "timestamp": (datetime.datetime.now() - datetime.timedelta(minutes=160)).strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint_id": "EP-003",
            "ip_address": "192.168.1.103",
            "anomaly_type": "Combined Severe Anomaly",
            "severity": "Critical",
            "confidence": 0.98,
            "bandwidth": 1280.0,
            "latency": 290.0,
            "packet_loss": 18.0,
            "cpu_utilization": 96.0,
            "memory_utilization": 92.0,
            "active_connections": 640,
            "packets_sent": 68000,
            "packets_received": 42000,
            "contributing_factors": json.dumps([
                "Bandwidth: 1280.0 Mbps (Normal: 50.0–450.0 Mbps)",
                "Active Connections: 640 conn (Normal: 25–180 conn)",
                "CPU Utilization: 96.0 % (Normal: 10.0–65.0 %)",
                "Memory Utilization: 92.0 % (Normal: 20.0–68.0 %)",
                "Latency: 290.0 ms (Normal: 8.0–50.0 ms)",
                "Packet Loss: 18.0 % (Normal: 0.0–2.0 %)"
            ]),
            "explanation": "EP-003 (192.168.1.103) experienced a massive traffic surge and resource saturation event exhibiting 1280.0 Mbps bandwidth, 640 conn active connections, 96.0 % cpu utilization, and 92.0 % memory utilization. These measurements significantly exceed established operational baselines, leading our Random Forest ML model to classify this event as a Critical-severity anomaly with 98% confidence.",
            "recommended_action": "Isolate simulated endpoint traffic and escalate to SOC tier 2 analyst. Apply ingress rate limiting / QoS traffic shaping on endpoint socket. Enforce TCP connection limits and verify memory leaks.",
            "status": "Active"
        }
    ]

    for item in sample_records:
        cursor.execute("""
            INSERT INTO anomalies (
                timestamp, endpoint_id, ip_address, anomaly_type, severity, confidence,
                bandwidth, latency, packet_loss, cpu_utilization, memory_utilization,
                active_connections, packets_sent, packets_received,
                contributing_factors, explanation, recommended_action, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item["timestamp"], item["endpoint_id"], item["ip_address"], item["anomaly_type"],
            item["severity"], item["confidence"], item["bandwidth"], item["latency"],
            item["packet_loss"], item["cpu_utilization"], item["memory_utilization"],
            item["active_connections"], item["packets_sent"], item["packets_received"],
            item["contributing_factors"], item["explanation"], item["recommended_action"],
            item["status"]
        ))

# Data access helper functions
def insert_anomaly(record):
    """Inserts a new anomaly record into SQLite and returns the inserted row id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    factors_json = json.dumps(record.get("contributing_factors", []))
    cursor.execute("""
        INSERT INTO anomalies (
            timestamp, endpoint_id, ip_address, anomaly_type, severity, confidence,
            bandwidth, latency, packet_loss, cpu_utilization, memory_utilization,
            active_connections, packets_sent, packets_received,
            contributing_factors, explanation, recommended_action, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["timestamp"], record["endpoint_id"], record["ip_address"],
        record.get("anomaly_type", "Anomaly"), record["severity"], record["confidence"],
        record["bandwidth"], record["latency"], record["packet_loss"],
        record["cpu_utilization"], record["memory_utilization"],
        record["active_connections"], record["packets_sent"], record["packets_received"],
        factors_json, record["explanation"], record["recommended_action"],
        record.get("status", "Active")
    ))
    anomaly_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return anomaly_id

def get_anomalies(limit=50, severity=None, endpoint_id=None, status=None):
    """Retrieves anomaly records with optional filters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM anomalies WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if endpoint_id:
        query += " AND endpoint_id = ?"
        params.append(endpoint_id)
    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        d = dict(row)
        try:
            d["contributing_factors"] = json.loads(d["contributing_factors"])
        except Exception:
            d["contributing_factors"] = [d["contributing_factors"]]
        results.append(d)
    return results

def get_anomaly_by_id(anomaly_id):
    """Retrieves single anomaly by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["contributing_factors"] = json.loads(d["contributing_factors"])
    except Exception:
        d["contributing_factors"] = [d["contributing_factors"]]
    return d

def update_anomaly_status(anomaly_id, new_status):
    """Updates status of an anomaly (e.g. Active, Investigating, Resolved)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE anomalies SET status = ? WHERE id = ?", (new_status, anomaly_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def create_password_reset_code(username, email, code, expires_at_str):
    """Inserts a new verification OTP code for password reset."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO password_resets (username, email, code, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
    """, (username, email, code, expires_at_str))
    conn.commit()
    conn.close()

def verify_and_consume_reset_code(identity, code):
    """
    Verifies that the provided 6-digit OTP code is valid, unexpired, and unused.
    Returns (True, user_dict) on success, or (False, error_message).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Look up the user first
    cursor.execute("SELECT id, username, email FROM users WHERE username = ? OR email = ?", (identity, identity))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False, "No operator account found matching that username or email."

    user_dict = dict(user)

    # Find the latest unused reset record for this user and code
    cursor.execute("""
        SELECT id, expires_at FROM password_resets
        WHERE (username = ? OR email = ?) AND code = ? AND used = 0
        ORDER BY id DESC LIMIT 1
    """, (user_dict["username"], user_dict["email"], code.strip()))
    reset_record = cursor.fetchone()

    if not reset_record:
        conn.close()
        return False, "Invalid or unrecognized security verification code."

    # Check expiration
    expires_at = datetime.datetime.strptime(reset_record["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.datetime.now() > expires_at:
        conn.close()
        return False, "Security verification code has expired. Please request a new code."

    # Mark as used (one-time verification token)
    cursor.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_record["id"],))
    conn.commit()
    conn.close()

    return True, user_dict

# ---------------------------------------------------------------------------
# SIMULATED NOC SECURITY MAILBOX CRUD
# ---------------------------------------------------------------------------
def create_inbox_email(recipient_email, recipient_username, sender, subject, body_html, verification_code=None):
    """Inserts a new message into the simulated security mailbox."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO simulated_inbox (
            recipient_email, recipient_username, sender, subject, body_html, verification_code, timestamp, is_read
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    """, (recipient_email, recipient_username, sender, subject, body_html, verification_code, now_str))
    conn.commit()
    conn.close()

def get_inbox_emails(limit=30):
    """Retrieves simulated mailbox messages in reverse chronological order."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM simulated_inbox ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_inbox_email_by_id(email_id):
    """Retrieves a specific email from the simulated mailbox."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM simulated_inbox WHERE id = ?", (email_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def mark_inbox_email_read(email_id):
    """Marks an email as read."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE simulated_inbox SET is_read = 1 WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()

def clear_inbox():
    """Clears all simulated emails."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM simulated_inbox")
    conn.commit()
    conn.close()


