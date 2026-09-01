"""
NetGuard AI - System Verification Script
Validates database initialization, machine learning model inference,
explanation generation, and API responses.
"""

import os
import sys
import json

def run_tests():
    print("==================================================")
    print("  NETGUARD AI - PRE-FLIGHT SYSTEM VERIFICATION")
    print("==================================================")

    # 1. Database Initialization
    print("[1/4] Testing Database Initialization...")
    from database.db import init_db, get_db_connection, get_anomalies
    init_db()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM users")
    user_cnt = c.fetchone()["cnt"]
    c.execute("SELECT COUNT(*) as cnt FROM anomalies")
    anom_cnt = c.fetchone()["cnt"]
    conn.close()
    print(f"      Users in DB: {user_cnt}, Anomalies in DB: {anom_cnt}")
    assert user_cnt > 0, "Users table should have default admin"
    assert anom_cnt > 0, "Anomalies table should have seeded records"
    print("      [OK] Database initialized successfully.")

    # 2. Machine Learning Model Loading & Inference
    print("[2/4] Testing ML Random Forest Model & Explanation Engine...")
    from traffic_model import model_engine
    assert model_engine.model is not None, "traffic_model.pkl must be loaded"

    # Test Anomaly Prediction
    sample_anomaly = {
        "endpoint_id": "EP-004",
        "ip_address": "192.168.1.104",
        "bandwidth": 950.0,
        "latency": 180.0,
        "packet_loss": 14.0,
        "cpu_utilization": 94.0,
        "memory_utilization": 87.0,
        "active_connections": 420,
        "packets_sent": 50000,
        "packets_received": 46000
    }
    result = model_engine.predict_telemetry(sample_anomaly)
    print(f"      Prediction: {result['prediction']}")
    print(f"      Severity: {result['severity']}")
    print(f"      Confidence: {result['confidence_percentage']}")
    print(f"      Contributing Factors Count: {len(result['contributing_factors'])}")
    print(f"      AI Explanation snippet: {result['explanation'][:90]}...")
    print(f"      Recommended Action snippet: {result['recommended_action'][:90]}...")

    assert result["is_anomaly"] is True, "Sample telemetry should be classified as Anomaly"
    assert result["severity"] in ["High", "Critical"], "Sample should be High or Critical severity"
    assert len(result["contributing_factors"]) > 0, "Should identify abnormal features"
    print("      [OK] Random Forest inference & explanation engine verified.")

    # 3. Test Normal Traffic Prediction
    sample_normal = {
        "endpoint_id": "EP-001",
        "ip_address": "192.168.1.101",
        "bandwidth": 150.0,
        "latency": 18.0,
        "packet_loss": 0.2,
        "cpu_utilization": 28.0,
        "memory_utilization": 35.0,
        "active_connections": 65,
        "packets_sent": 8000,
        "packets_received": 7800
    }
    normal_result = model_engine.predict_telemetry(sample_normal)
    print(f"      Normal Sample Prediction: {normal_result['prediction']}")
    assert normal_result["is_anomaly"] is False, "Normal sample should be classified as Normal"
    print("      [OK] Normal baseline correctly recognized.")

    # 4. Flask Application Test Client
    print("[3/4] Testing Flask Routes & REST APIs...")
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    # Unauthenticated access should redirect or return 401
    res = client.get("/dashboard")
    assert res.status_code in [302, 401], "Unauthenticated dashboard should redirect to login"

    # Test Login API
    res = client.post("/api/login", json={"username": "admin", "password": "Admin@123"})
    assert res.status_code == 200, f"Login API failed: {res.data}"
    login_data = json.loads(res.data)
    assert "user" in login_data, "Login response must contain user"
    print("      [OK] Session Authentication verified.")

    # Test Network Data API
    res = client.get("/api/network-data")
    assert res.status_code == 200, f"Network data API failed: {res.data}"
    net_data = json.loads(res.data)
    assert "endpoints" in net_data, "Network data must contain endpoints"
    assert "summary" in net_data, "Network data must contain summary"
    print(f"      Summary Bandwidth: {net_data['summary']['current_bandwidth']}")
    print("      [OK] Network Data streaming API verified.")

    # Test Demo Generate Anomaly API
    print("[4/4] Testing Demo Anomaly Generation API...")
    res = client.post("/api/generate-anomaly", json={"endpoint_id": "EP-004"})
    assert res.status_code == 201, f"Generate anomaly failed: {res.data}"
    gen_data = json.loads(res.data)
    assert "anomaly" in gen_data, "Response must contain anomaly"
    gen_anom = gen_data["anomaly"]
    print(f"      Generated Anomaly ID: {gen_anom['id']}, Severity: {gen_anom['severity']}, Conf: {gen_anom['confidence']}")
    print("      [OK] Universal demo anomaly generator verified.")

    print("\n==================================================")
    print("  ALL TESTS PASSED! SYSTEM IS 100% OPERATIONAL.")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
