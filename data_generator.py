"""
NetGuard AI - Synthetic Network Telemetry Generator
100% Software-based telemetry generation for simulated endpoints.
"""

import random
import datetime
import pandas as pd
import numpy as np

# Simulated Endpoints Mapping
ENDPOINTS = {
    "EP-001": {"ip": "192.168.1.101", "role": "Core Gateway & DNS", "location": "Datacenter Rack A"},
    "EP-002": {"ip": "192.168.1.102", "role": "App Services Cluster", "location": "Server Room 1"},
    "EP-003": {"ip": "192.168.1.103", "role": "Database Replica Node", "location": "Server Room 2"},
    "EP-004": {"ip": "192.168.1.104", "role": "Edge Proxy / API Ingress", "location": "DMZ Zone B"},
    "EP-005": {"ip": "192.168.1.105", "role": "Internal Storage Node", "location": "Storage SAN Cluster"}
}

NORMAL_RANGES = {
    "bandwidth": (70.0, 420.0),       # Mbps
    "latency": (10.0, 48.0),          # ms
    "packet_loss": (0.0, 1.8),        # %
    "cpu_utilization": (15.0, 58.0),  # %
    "memory_utilization": (25.0, 62.0),# %
    "active_connections": (30, 160),  # count
    "packets_sent": (3500, 18000),    # pps
    "packets_received": (3200, 17500) # pps
}

ANOMALY_TYPES = [
    "Traffic Spike",
    "High Latency",
    "Packet Loss Surge",
    "Resource Exhaustion",
    "Connection Flood",
    "Packet Rate Anomaly",
    "Combined Severe Anomaly"
]

def generate_normal_event(endpoint_id=None, timestamp=None):
    """Generates a realistic normal network telemetry event with natural variation."""
    if not endpoint_id:
        endpoint_id = random.choice(list(ENDPOINTS.keys()))
    
    ip_address = ENDPOINTS[endpoint_id]["ip"]
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Introduce Gaussian-like variations around typical operational baselines
    bandwidth = round(random.uniform(80.0, 380.0) + random.gauss(0, 15), 1)
    bandwidth = max(30.0, min(bandwidth, 480.0))

    latency = round(random.uniform(12.0, 40.0) + random.gauss(0, 3), 1)
    latency = max(8.0, min(latency, 55.0))

    packet_loss = round(max(0.0, random.uniform(0.0, 1.2) + random.gauss(0, 0.2)), 2)
    packet_loss = min(packet_loss, 2.0)

    cpu_utilization = round(random.uniform(18.0, 52.0) + random.gauss(0, 5), 1)
    cpu_utilization = max(10.0, min(cpu_utilization, 65.0))

    memory_utilization = round(random.uniform(28.0, 58.0) + random.gauss(0, 4), 1)
    memory_utilization = max(20.0, min(memory_utilization, 68.0))

    active_connections = int(random.uniform(40, 140) + random.gauss(0, 10))
    active_connections = max(20, min(active_connections, 180))

    packets_sent = int(random.uniform(4000, 16000) + random.gauss(0, 800))
    packets_sent = max(2000, packets_sent)

    # Receive packets should loosely correlate with sent packets in normal conditions
    ratio = random.uniform(0.92, 1.05)
    packets_received = int(packets_sent * ratio)

    return {
        "timestamp": timestamp,
        "endpoint_id": endpoint_id,
        "ip_address": ip_address,
        "bandwidth": bandwidth,
        "latency": latency,
        "packet_loss": packet_loss,
        "cpu_utilization": cpu_utilization,
        "memory_utilization": memory_utilization,
        "active_connections": active_connections,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "label": 0,
        "anomaly_type": "Normal"
    }

def generate_anomaly_event(endpoint_id=None, anomaly_type=None, timestamp=None):
    """Generates an anomalous telemetry event based on specific profile types."""
    if not endpoint_id:
        endpoint_id = random.choice(list(ENDPOINTS.keys()))
    
    ip_address = ENDPOINTS[endpoint_id]["ip"]
    if timestamp is None:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if not anomaly_type:
        anomaly_type = random.choice(ANOMALY_TYPES)

    # Start with base normal metrics
    base = generate_normal_event(endpoint_id, timestamp)
    base["label"] = 1
    base["anomaly_type"] = anomaly_type

    if anomaly_type == "Traffic Spike":
        base["bandwidth"] = round(random.uniform(850.0, 1950.0), 1)
        base["active_connections"] = int(random.uniform(280, 550))
        base["packets_sent"] = int(random.uniform(32000, 68000))
        base["packets_received"] = int(random.uniform(30000, 64000))
        base["cpu_utilization"] = round(random.uniform(65.0, 88.0), 1)

    elif anomaly_type == "High Latency":
        base["latency"] = round(random.uniform(175.0, 580.0), 1)
        base["packet_loss"] = round(random.uniform(5.0, 18.0), 2)
        base["bandwidth"] = round(random.uniform(120.0, 260.0), 1)

    elif anomaly_type == "Packet Loss Surge":
        base["packet_loss"] = round(random.uniform(10.0, 36.0), 2)
        base["latency"] = round(random.uniform(95.0, 280.0), 1)
        base["packets_received"] = int(base["packets_sent"] * random.uniform(0.4, 0.7))

    elif anomaly_type == "Resource Exhaustion":
        base["cpu_utilization"] = round(random.uniform(88.0, 99.5), 1)
        base["memory_utilization"] = round(random.uniform(86.0, 98.5), 1)
        base["latency"] = round(random.uniform(60.0, 150.0), 1)
        base["active_connections"] = int(random.uniform(180, 350))

    elif anomaly_type == "Connection Flood":
        base["active_connections"] = int(random.uniform(390, 1350))
        base["packets_sent"] = int(random.uniform(28000, 62000))
        base["packets_received"] = int(random.uniform(12000, 25000)) # Asymmetric
        base["bandwidth"] = round(random.uniform(650.0, 1250.0), 1)
        base["cpu_utilization"] = round(random.uniform(72.0, 94.0), 1)

    elif anomaly_type == "Packet Rate Anomaly":
        base["packets_sent"] = int(random.uniform(48000, 95000))
        base["packets_received"] = int(random.uniform(8000, 20000)) # Heavy outbound flood
        base["bandwidth"] = round(random.uniform(720.0, 1400.0), 1)
        base["cpu_utilization"] = round(random.uniform(68.0, 91.0), 1)

    elif anomaly_type == "Combined Severe Anomaly":
        base["bandwidth"] = round(random.uniform(920.0, 1850.0), 1)
        base["latency"] = round(random.uniform(160.0, 480.0), 1)
        base["packet_loss"] = round(random.uniform(8.5, 24.0), 2)
        base["cpu_utilization"] = round(random.uniform(89.0, 99.0), 1)
        base["memory_utilization"] = round(random.uniform(84.0, 97.0), 1)
        base["active_connections"] = int(random.uniform(420, 1100))
        base["packets_sent"] = int(random.uniform(38000, 85000))
        base["packets_received"] = int(random.uniform(25000, 72000))

    return base

def generate_dataset(n_samples=4000, anomaly_ratio=0.25, output_csv="network_data.csv"):
    """Generates synthetic dataset and writes it to a CSV file."""
    records = []
    start_time = datetime.datetime.now() - datetime.timedelta(hours=24)
    time_delta = datetime.timedelta(seconds=int((24 * 3600) / n_samples))

    current_time = start_time
    for i in range(n_samples):
        timestamp_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        is_anomaly = random.random() < anomaly_ratio
        
        if is_anomaly:
            event = generate_anomaly_event(timestamp=timestamp_str)
        else:
            event = generate_normal_event(timestamp=timestamp_str)
            
        records.append(event)
        current_time += time_delta

    df = pd.DataFrame(records)
    df.to_csv(output_csv, index=False)
    print(f"Generated {len(df)} synthetic records to {output_csv}")
    print(f"Normal: {len(df[df['label'] == 0])}, Anomalous: {len(df[df['label'] == 1])}")
    return df

def generate_live_snapshot(anomalous_endpoint=None, anomaly_type=None):
    """
    Generates a live snapshot of all simulated endpoints (EP-001..EP-005).
    Optionally makes one specific endpoint anomalous for demo or simulated spikes.
    """
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    snapshot = []
    
    for ep_id in sorted(ENDPOINTS.keys()):
        if anomalous_endpoint == ep_id:
            event = generate_anomaly_event(endpoint_id=ep_id, anomaly_type=anomaly_type, timestamp=now_str)
        else:
            event = generate_normal_event(endpoint_id=ep_id, timestamp=now_str)
        snapshot.append(event)
        
    return snapshot

if __name__ == "__main__":
    generate_dataset()
