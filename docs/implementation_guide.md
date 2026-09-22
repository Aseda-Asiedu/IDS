# Step-by-Step Implementation Guide

---

# Part 7: Implementation Details & Roadmap

This document serves as the developer blueprint for constructing the AI-Powered Network Intrusion Detection System from scratch on a Windows 11 environment.

---

## 7.1 Development Environment & Installation
To set up the workspace on a standard Windows 11 machine:

### 7.1.1 Install Python & Node.js
1. Download and run the Python 3.10.x installer from [python.org](https://www.python.org/). Ensure the checkbox **"Add Python to PATH"** is selected.
2. Download and run the Node.js (LTS version) installer from [nodejs.org](https://nodejs.org/). This installs both Node.js and NPM.

### 7.1.2 Install Npcap (Windows Packet Capture Driver)
1. Download and install Npcap from [npcap.com](https://npcap.com/).
2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"** to allow Scapy to find local network adapters.

### 7.1.3 Clone Project & Create Virtual Environment
Open PowerShell inside your project workspace folder `c:/Users/asied/Desktop/IDS-Sys` and run:

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip
```

### 7.1.4 Install Required Dependencies
Create a `requirements.txt` file in the workspace root and install:

```
fastapi>=0.100.0
uvicorn[standard]>=0.22.0
scapy>=2.5.0
river>=0.15.0
scikit-learn>=1.2.0
pandas>=2.0.0
numpy>=1.24.0
sqlalchemy>=2.0.0
passlib[bcrypt]>=1.7.4
python-jose[cryptography]>=3.3.0
python-multipart>=0.0.6
```

Run installation:
```powershell
pip install -r requirements.txt
```

---

## 7.2 Directory Structure Layout

The project uses a monorepo structure separating frontend UI assets from backend API routines:

```
IDS-Sys/
├── docs/                      # Thesis and planning documentation
├── backend/                   # Python FastAPI service
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py            # API entry point
│   │   ├── auth.py            # JWT and User controller
│   │   ├── database.py        # SQLAlchemy SQLite engine
│   │   ├── models.py          # DB schema declarations
│   │   ├── sniffer.py         # Scapy capture worker thread
│   │   ├── extractor.py       # Packet to flow aggregator
│   │   └── ai_engine.py       # River/Sklearn ML service
│   ├── models/
│   │   ├── baseline_rf.pkl    # Serialized offline classifier
│   │   └── online_hat.pkl     # Serialized streaming classifier
│   ├── data/
│   │   └── app.db             # Local SQLite database file
│   └── requirements.txt
├── frontend/                  # React SPA dashboard
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── components/        # Cards, Alert grids, charts
│   │   ├── views/             # Login, Dashboard, Settings
│   │   ├── App.jsx            # Routing and wrapper layout
│   │   ├── main.jsx
│   │   └── index.css          # Tailwind/CSS configurations
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## 7.3 Database Schema Declarations (SQLAlchemy)

Create `backend/app/models.py` to specify the local database tables:

```python
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)

class TrafficLog(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, nullable=False)
    dest_ip = Column(String, nullable=False)
    src_port = Column(Integer, nullable=False)
    dest_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    duration = Column(Integer, nullable=False)
    total_bytes = Column(Integer, nullable=False)
    prediction_label = Column(String, nullable=False)  # Normal, Suspicious, Malicious
    confidence_score = Column(Float, nullable=False)

    alert = relationship("Alert", back_populates="traffic_log", uselist=False)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    traffic_log_id = Column(Integer, ForeignKey("traffic_logs.id"))
    alert_time = Column(DateTime, default=datetime.utcnow)
    threat_level = Column(String, nullable=False)  # Medium, High
    notes = Column(String, nullable=True)
    is_resolved = Column(Boolean, default=False)

    traffic_log = relationship("TrafficLog", back_populates="alert")
```

---

## 7.4 Core API Specification (FastAPI)

FastAPI serves backend capabilities via REST and WebSockets.

### 7.4.1 Authentication APIs
* **POST `/api/auth/register`**: Registers a user (Developer usage).
* **POST `/api/auth/token`**: Accepts form data (username, password) and returns a signed JWT.

### 7.4.2 Dashboard and System Control APIs
* **GET `/api/system/status`**: Returns CPU, memory, and database record stats.
* **POST `/api/traffic/start`**: Begins Scapy packet Sniffer thread on a target interface card.
* **POST `/api/traffic/stop`**: Halts the Scapy sniffer thread.
* **POST `/api/traffic/upload`**: Uploads and queues a PCAP file for processing.

### 7.4.3 Data APIs
* **GET `/api/logs`**: Returns paginated lists of network traffic logs, filterable by IP.
* **GET `/api/alerts`**: Returns active intrusions and threat status summaries.

### 7.4.4 Real-Time Alerts WebSockets
* **WS `/api/ws/alerts`**: Keeps open client browser connections. The backend writes JSON payloads to this connection as alerts trigger.

---

## 7.5 Machine Learning Inference Loop

The backend executes a continuous flow pipeline:

```python
# Conceptual execution flow in backend/app/ai_engine.py

import pickle
from river import forest, drift
from .models import TrafficLog, Alert

class AIEngine:
    def __init__(self, offline_model_path, online_model_path):
        # Load pre-trained Random Forest (Offline)
        with open(offline_model_path, 'rb') as f:
            self.offline_rf = pickle.load(f)
            
        # Initialize River Hoeffding Adaptive Tree (Online)
        self.online_hat = forest.ARFClassifier(n_models=5) # Adaptive Random Forest
        self.drift_detector = drift.ADWIN()
        
    def classify_flow(self, flow_features):
        """
        Takes dynamic flow vectors and performs dual-stage analysis.
        """
        # 1. Offline Baseline Prediction
        offline_pred = self.offline_rf.predict([flow_features])[0]
        offline_proba = self.offline_rf.predict_proba([flow_features])[0]
        
        # 2. Online Adaptive Prediction
        # River model expects a dict of {feature_name: value}
        river_features = dict(zip(FEATURE_NAMES, flow_features))
        online_pred = self.online_hat.predict_one(river_features)
        
        # Determine consolidated label
        final_label = online_pred if online_pred is not None else offline_pred
        confidence = max(offline_proba)
        
        return final_label, confidence

    def update_online_model(self, flow_features, ground_truth):
        """
        Incremental learning step.
        """
        river_features = dict(zip(FEATURE_NAMES, flow_features))
        # Update classifier weights
        self.online_hat.learn_one(river_features, ground_truth)
        
        # Check for Concept Drift
        # Track accuracy over time (1 if correct prediction, 0 if wrong)
        prediction = self.online_hat.predict_one(river_features)
        is_error = 1.0 if prediction != ground_truth else 0.0
        
        # Feed error rate into ADWIN
        self.drift_detector.update(is_error)
        
        if self.drift_detector.drift_detected:
            print("Concept drift detected by ADWIN! Triggering update notify.")
            return True # Signal drift event
        return False
```

---

## 7.6 16-Week Implementation Roadmap

```
Week  1: Set up Windows dev tools, virtual environments, install Npcap, scaffold folders.
Week  2: Prepare UNSW-NB15 CSV datasets. Clean missing values and select optimal features.
Week  3: Design database schemas. Write SQLAlchemy SQLite connection modules.
Week  4: Code Scapy Sniffer script. Sniff raw sockets and verify header parsing.
Week  5: Implement Flow Aggregator. Group packets into 2-sec connection records.
Week  6: Build offline model. Train Random Forest in Jupyter, export as baseline_rf.pkl.
Week  7: Build online module. Implement River Hoeffding Tree and test incremental updates.
Week  8: Implement ADWIN drift detector. Create simulation dataset showing sudden drift.
Week  9: Create FastAPI application backend. Setup REST API endpoints and router views.
Week 10: Code FastAPI Authentication. Secure endpoints with bcrypt credentials and JWT.
Week 11: Setup WebSockets service on FastAPI to broadcast alerts.
Week 12: Scaffold React frontend. Setup Vite workspace, install Tailwind, setup router.
Week 13: Build dashboard components (Sidebar, Event log tables, metric cards).
Week 14: Connect Chart.js graphics to APIs. Set up WebSocket listeners in React UI.
Week 15: Run end-to-end integration tests. Validate PCAP uploads, check memory leaks.
Week 16: Draft system manual, record demo video, complete Chapter 4 & 5 write-ups.
```
