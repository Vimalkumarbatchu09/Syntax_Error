# NetGuard AI

### AI-Powered Network Management & Anomaly Detection Platform

> **NetGuard AI** is a professional, software-only cybersecurity network operations center (NOC) and anomaly-detection platform. It continuously analyzes synthetic network telemetry across simulated endpoints, predicts abnormal network behaviors using a trained Random Forest machine learning classifier, computes severity and confidence, generates human-readable AI incident narratives explaining specific packet deviations, and recommends automated remediation actions.

---

## 1. Project Overview & Scope

### 100% Software-Only Architecture
NetGuard AI is **strictly a software-based cybersecurity project**.
* **NO physical devices, IoT hardware, ESP32, Arduino, or physical network sensors are used.**
* All endpoints (`EP-001` through `EP-005`) are **simulated virtual network nodes** producing synthetic multi-dimensional telemetry (bandwidth, latency, packet loss, host CPU/memory, active TCP sockets, packets transmitted/received).
* Runnable locally on **Windows using VS Code and Python**.

### Core Value Proposition
Traditional network monitoring solutions either overwhelm security analysts with raw numerical telemetry or act as opaque "black boxes" that merely output an alert badge without explaining *why* an event was flagged. NetGuard AI bridges this gap with an **Explainable AI (XAI) Telemetry Engine**: for every anomaly detected, it answers:
1. **WHAT** happened? (Event classification)
2. **WHERE** did it happen? (Affected endpoint & simulated IP)
3. **WHICH** network features deviated from baseline? (Observed metrics vs. normal operating thresholds)
4. **WHY** was it classified as anomalous? (Multi-dimensional variance)
5. **HOW** severe is it? (Dynamic severity classification: *Low*, *Medium*, *High*, *Critical*)
6. **HOW** confident is the ML model? (Empirical prediction probability)
7. **WHAT** action should the SOC analyst take? (Contextual remediation playbooks)

---

## 2. System Architecture

```text
               +-------------------------------------------+
               |  Synthetic Telemetry Generator            |
               |  (Normal Traffic + 7 Anomaly Profiles)    |
               +-------------------------------------------+
                                     |
                                     v
               +-------------------------------------------+
               |  Flask REST API Backend (app.py)          |
               |  Session Auth | Streaming Buffer | Routes |
               +-------------------------------------------+
                                     |
                                     v
               +-------------------------------------------+
               |  8-Dimensional Telemetry Vector           |
               |  [Bandwidth, Latency, Loss, CPU, RAM,     |
               |   Sockets, Packets Sent, Packets Recv]    |
               +-------------------------------------------+
                                     |
                                     v
               +-------------------------------------------+
               |  Random Forest ML Model                   |
               |  (traffic_model.pkl - 100 Estimators)     |
               +-------------------------------------------+
                                     |
                      +--------------+--------------+
                      |                             |
                      v                             v
               [Normal Telemetry]          [Anomaly Detected]
                                                    |
                                                    v
                                  +------------------------------------+
                                  |  XAI Feature Explanation Engine    |
                                  |  - Baseline Threshold Comparison   |
                                  |  - Severity Scoring (Low..Crit)    |
                                  |  - Contributing Factors Extraction |
                                  |  - Natural Language AI Narrative   |
                                  |  - Recommended SOC Action          |
                                  +------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |  SQLite Database (netguard.db)     |
                                  |  Persistent Anomaly Audit Records  |
                                  +------------------------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |  NOC Cyber Dashboard (Frontend)    |
                                  |  - Real-Time Chart.js Visualizers  |
                                  |  - Clickable Anomaly Modal         |
                                  |  - Universal Demo Spike Generator  |
                                  +------------------------------------+
```

---

## 3. Technology Stack

* **Frontend**: HTML5, Vanilla CSS3 (Custom Dark NOC Design System, Glassmorphism, Neon Glow accents, Responsive Layout), JavaScript (ES6+), [Chart.js](https://www.chartjs.org/) (4.4.x).
* **Backend**: Python 3.13 / Flask 3.1, Flask REST APIs, Werkzeug security password hashing (`generate_password_hash` / `check_password_hash`), Session-based authentication.
* **Machine Learning**: `scikit-learn` (Random Forest Classifier), `pandas`, `numpy`, `joblib`.
* **Database**: SQLite (`database/netguard.db`) with tables for `users` and `anomalies`.
* **Data Simulation**: Python synthetic network telemetry engine (`data_generator.py`).

---

## 4. Machine Learning & XAI Explanation Engine

### 8 Network Telemetry Dimensions
The Random Forest model is trained on 8 numerical dimensions extracted from packet telemetry:
1. `bandwidth`: Data transfer rate in Megabits per second (Mbps). Normal baseline: `50 – 450 Mbps`.
2. `latency`: Round-trip network ping in milliseconds (ms). Normal baseline: `8 – 50 ms`.
3. `packet_loss`: Percentage of dropped packets (%). Normal baseline: `0.0 – 2.0 %`.
4. `cpu_utilization`: Host CPU workload (%). Normal baseline: `10 – 65 %`.
5. `memory_utilization`: Host RAM allocation (%). Normal baseline: `20 – 68 %`.
6. `active_connections`: Concurrent open TCP sockets. Normal baseline: `25 – 180 conn`.
7. `packets_sent`: Outbound transmission rate (pps). Normal baseline: `2,000 – 20,000 pps`.
8. `packets_received`: Inbound reception rate (pps). Normal baseline: `2,000 – 19,000 pps`.

### Anomaly Profiles Simulated
1. **Traffic Spike**: Extreme bandwidth surge (`850 – 1950 Mbps`) with elevated concurrent sessions.
2. **High Latency**: Severe propagation delay (`175 – 580 ms`) and route packet dropping.
3. **Packet Loss Surge**: Major packet drops (`10 – 36 %`) causing heavy asymmetric loss.
4. **Resource Exhaustion**: Host CPU (`88 – 99.5 %`) and RAM saturation impacting socket queues.
5. **Connection Flood**: SYN/TCP socket flood (`390 – 1350` concurrent connections).
6. **Packet Rate Anomaly**: Asymmetric flood of transmitted packets (`48,000 – 95,000 pps`).
7. **Combined Severe Anomaly**: Simultaneous surge in bandwidth, CPU, latency, and socket counts.

### Severity Classification Matrix
* **Low**: Single minor metric deviation (e.g. slight latency elevation).
* **Medium**: Moderate deviation or 2 abnormal features.
* **High**: Major abnormal event (e.g. Traffic Spike > 800 Mbps, Connection Flood > 400 sockets).
* **Critical**: Multi-dimensional saturation (3+ severe indicators or extreme deviation scores).

### AI Narrative Generation (Deterministic XAI)
NetGuard AI **does not hallucinate** explanations. The explanation engine evaluates the actual observed telemetry values against operational reference baselines to generate structured, human-readable incident briefs:

```text
EP-004 (192.168.1.104) experienced a massive traffic surge and resource saturation event
exhibiting 950.0 Mbps bandwidth, 420 conn active connections, 94.0 % cpu utilization,
and 14.0 % packet loss. These measurements significantly exceed established operational
baselines, leading our Random Forest ML model to classify this event as a High-severity
anomaly with 94% confidence.
```

---

## 5. Application Pages

1. **Authentication Portal (`/login`)**: Cybersecurity NOC login card with demo credentials hint, "Remember Me", error banners, and secure session management.
2. **Registration (`/register`)**: New analyst onboarding with field validations (format, length, duplicates, mismatch).
3. **Forgot Password (`/forgot-password`)**: Direct password reset mechanism for local demonstration.
4. **Operations Dashboard (`/dashboard`)**:
   - 5 Top Summary Metric Cards (Total Endpoints, Active Endpoints, Network Bandwidth, Detected Anomalies, Critical Alerts).
   - Clickable Recent Anomaly Alert Banner (instant deep-dive).
   - Real-time Throughput and Latency/Loss line charts (Chart.js, 3s refresh).
   - 5 Simulated Endpoints Status Grid.
   - Universal **"⚡ Generate Anomaly"** demo button.
5. **Network Monitoring (`/monitoring`)**: 8 real-time Chart.js telemetry charts continuously tracking every feature dimension.
6. **Simulated Endpoints (`/endpoints`)**: Node inventory for `EP-001` through `EP-005` with live status, latency, CPU load, and deep-dive drawer with node-specific anomaly histories.
7. **Anomaly Logs (`/anomalies`)**: Searchable incident table with severity, endpoint, and status filters. Every row opens the Anomaly Inspector Modal.
8. **Analytics (`/analytics`)**: Cumulative traffic volume, averages, severity doughnut distribution, anomaly profile frequency bars, and node impact rankings.
9. **AI Insights (`/ai-insights`)**: Automated cognitive threat assessments, prioritized preventative SOC playbooks, and XAI methodology disclosures.
10. **Platform Settings (`/settings`)**: Configurable polling rates (1s, 3s, 5s, 10s), alert sensitivity, simulation scope disclosures, and analyst session info.

---

## 6. Simulated Endpoints Directory

| Endpoint ID | Simulated IP Address | Architecture Role | Topology Location |
| :--- | :--- | :--- | :--- |
| **EP-001** | `192.168.1.101` | Core Gateway & DNS | Datacenter Rack A |
| **EP-002** | `192.168.1.102` | App Services Cluster | Server Room 1 |
| **EP-003** | `192.168.1.103` | Database Replica Node | Server Room 2 |
| **EP-004** | `192.168.1.104` | Edge Proxy / API Ingress | DMZ Zone B |
| **EP-005** | `192.168.1.105` | Internal Storage Node | Storage SAN Cluster |

---

## 7. Setup & Running Instructions (Windows & VS Code)

### Prerequisites
* Windows 10 / 11
* Python 3.10+ (Python 3.13 supported)
* Visual Studio Code

### Step 1: Open Project in VS Code
Open the `NetGuard-AI` project folder in VS Code (`File` > `Open Folder...`).

### Step 2: Create a Virtual Environment (Optional but Recommended)
Open a terminal in VS Code (`Ctrl + \`` or `Terminal` > `New Terminal`):
```powershell
python -m venv venv
```

### Step 3: Activate Virtual Environment
```powershell
venv\Scripts\activate
```

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Generate Dataset & Train Model
Train the Random Forest Classifier on synthetic network telemetry:
```powershell
python train_model.py
```
*Output*: Generates `network_data.csv` (5,000 synthetic records) and saves `traffic_model.pkl` with 100% test evaluation score.

### Step 6: Start the Flask Application
```powershell
python app.py
```

### Step 7: Open Browser
Navigate to:
```text
http://127.0.0.1:5000
```

### Default Credentials
* **Username**: `admin`
* **Password**: `Admin@123`

*(You can also register a new account on `/register`)*

---

## 8. Hackathon Demonstration Flow (For Judges)

1. **Login**: Authenticate with `admin` / `Admin@123` on the dark cyber login portal.
2. **Dashboard Overview**:
   - Point out the 5 simulated endpoints (`EP-001` through `EP-005`).
   - Observe the live streaming bandwidth and latency charts updating every 3 seconds.
   - Show the summary cards (Total Endpoints, Bandwidth, Anomaly counts).
3. **Simulate Live Anomaly Injection**:
   - Click the prominent **"⚡ Generate Anomaly"** button in the top navigation header.
   - Watch the instant toast notification appear.
   - The **Anomaly Inspector Modal** opens automatically!
4. **Explain the 7 Core Questions (XAI Engine)**:
   - **WHAT**: Shows anomaly type (e.g. Traffic Spike, Connection Flood).
   - **WHERE**: Displays simulated Endpoint (`EP-004`) and simulated IP (`192.168.1.104`).
   - **WHICH**: Highlights abnormal telemetry metrics against normal reference ranges.
   - **WHY**: Shows the multi-dimensional deviation factors.
   - **SEVERITY**: Glowing badge indicating `HIGH` or `CRITICAL` severity.
   - **CONFIDENCE**: Shows Random Forest prediction confidence (e.g. `94%` or `100%`).
   - **ACTION**: Displays practical, context-specific remediation steps (e.g. QoS throttling, TCP socket limits).
5. **Explore Operational Views**:
   - Navigate to **Network Monitoring** (`/monitoring`) to show the 8 dynamic real-time Chart.js graphs.
   - Navigate to **Simulated Endpoints** (`/endpoints`) and click any node to view its trend chart and anomaly history.
   - Navigate to **Anomaly Logs** (`/anomalies`) to demonstrate filtering by severity or endpoint.
   - Navigate to **Analytics** (`/analytics`) to view the severity distribution doughnut and anomaly frequency charts.
   - Navigate to **AI Insights** (`/ai-insights`) to view automated cognitive threat assessments and SOC playbooks.

---

## 9. REST API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | Authenticates operator credentials | No |
| `POST` | `/api/register` | Registers new operator profile | No |
| `POST` | `/api/reset-password` | Resets password for development | No |
| `GET` | `/api/network-data` | Streaming telemetry snapshot for all nodes & history | Yes |
| `GET` | `/api/endpoints` | Summaries & metrics for EP-001..005 | Yes |
| `GET` | `/api/endpoints/<id>` | Deep-dive telemetry history for specific node | Yes |
| `GET` | `/api/anomalies` | Filtered list of detected anomalies | Yes |
| `GET` | `/api/anomalies/<id>` | Detailed record of an anomaly event | Yes |
| `POST` | `/api/anomalies/<id>/status` | Update status (`Active`, `Investigating`, `Resolved`) | Yes |
| `POST` | `/api/predict` | Runs telemetry through Random Forest & XAI engine | Yes |
| `POST` | `/api/generate-anomaly` | Injects synthetic anomaly, runs ML, stores to DB | Yes |
| `GET` | `/api/analytics` | Aggregated traffic metrics & distribution stats | Yes |
| `GET` | `/api/ai-insights` | Dynamic cognitive observations & recommendations | Yes |
| `GET/POST`| `/api/settings` | Retrieve or update monitoring settings | Yes |

---

## 10. Privacy by Design

NetGuard AI operates strictly on **network telemetry, statistical counters, and metadata** (bandwidth, latency, loss, CPU, sockets, packets).

> **Privacy Statement**:
> *"NetGuard AI analyzes network telemetry and metadata for anomaly detection. It does not inspect private messages, payload contents, or personal communication data."*
