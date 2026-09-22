# NEXz — Network Intelligence, Education and eXploration System

> **Academic Title**: *NEXz: An Adaptive Network Security Monitoring and Learning Environment with an AI-Powered Intrusion Detection Engine*  
> **Institution**: Department of Computer Science, University of Ghana, Legon  
> **Author**: Aseda Asiedu ([@Aseda-Asiedu](https://github.com/Aseda-Asiedu))  
> **Degree**: B.Sc. Computer Science Capstone Project  

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![River ML](https://img.shields.io/badge/River-Online%20Streaming%20ML-orange.svg)](https://riverml.xyz/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. System Overview

**NEXz** is an enterprise-grade, lightweight Network Security Monitoring (NSM) and educational environment engineered to run on commodity workstation hardware. Traditional intrusion detection systems rely on static rule sets or batch-trained offline machine learning models that suffer catastrophic degradation due to **concept drift** in non-stationary traffic streams. NEXz resolves this challenge by combining real-time packet capture, bidirectional flow aggregation, online streaming machine learning, localized host anomaly profiling, sliding-window alert deduplication, and an interactive protocol academy.

```
                      +---------------------------------------+
                      |       Network Traffic Ingestion       |
                      |  - Live NIC Sniffing (Scapy L2/L3/L4)  |
                      |  - External Telemetry (PCAP/Zeek/EVE) |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      5-Tuple Flow Aggregation         |
                      |     (2.0s Inactivity Windowing)       |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |      Dual-Engine AI Classification    |
                      |  - Online Adaptive Random Forest (ARF)|
                      |  - Calibrated Offline Baseline (RF)   |
                      |  - ADWIN Concept Drift Monitoring     |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Behavioral Profiling & Triage     |
                      |  - Per-Device Half-Space Trees (HST)  |
                      |  - Sliding-Window Deduplication (30s) |
                      |  - Rule-Based Explainable AI (XAI)    |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |  Presentation & Pedagogical Learning  |
                      |  - Two-Tier Institutional Dashboard   |
                      |  - Interactive Protocol Academy       |
                      |  - Cyber Range Attack Simulator       |
                      |  - Research & Analytics Workbench     |
                      +---------------------------------------+
```

---

## 2. Core Pillars & Architecture

NEXz is architected around **Four Functional Pillars**:

### I. Monitoring (Network Visibility)
- **Asynchronous Live Capture**: Packet-level ingestion via Scapy across Ethernet, Wi-Fi, and virtual interfaces.
- **5-Tuple Flow Aggregation**: Directional aggregation (`src_ip`, `dest_ip`, `src_port`, `dest_port`, `protocol`) with 2.0-second inactivity session management.
- **Statistical Feature Extraction**: Generates 7-feature statistical vectors (`sbytes`, `dbytes`, `splt_mean`, `dplt_mean`, `proto_id`, `packet_count`, `avg_pkt_size`).

### II. Security (Intelligent Detection & Adaptation)
- **Adaptive Random Forest (River ARF)**: Streaming Hoeffding Tree ensemble that learns incrementally on every processed flow.
- **ADWIN Drift Detection**: Statistical concept drift monitoring that detects non-stationary shifts in error distribution and triggers model recalibration.
- **Per-Device Behavioral Profiling**: Half-Space Trees (HST) anomaly scoring bounded by a 200-device LRU memory cache.
- **Alert Deduplication Engine**: 30-second sliding-window aggregation achieving **99.7% alert noise reduction** during volumetric attacks, with a formal 4-state lifecycle (`New` -> `Active` -> `Acknowledged` -> `Resolved`).
- **Explainable AI (XAI)**: Diagnostic playbook mapping feature variances to MITRE ATT&CK tactical guidance.

### III. Learning (Pedagogical Academy & Cyber Range)
- **Interactive Protocol Academy**: Deep dive modules for 7 foundational network protocols (IPv4, TCP, UDP, ICMP, DNS, HTTP, ARP) with live packet dissectors and architectural breakdown.
- **Detection Explained**: Visual interactive workbench explaining how feature geometry influences classification thresholds.
- **Integrated Cyber Range**: Benign simulation harness for SYN Flood, Port Scan, DNS Tunneling, and Data Exfiltration attacks to study detector responses safely.

### IV. Research (Telemetry Ingestion & Longitudinal Workbench)
- **Universal External Telemetry Ingestion**: Native streaming parsers for `.pcap`/`.pcapng`, `.csv`, `.json`, `.jsonl`, Zeek `conn.log` TSV, and Suricata `eve.json`.
- **Zero-Fabrication Normalization**: Dynamic capability-based degradation ensuring missing features are never artificially faked.
- **Four Analytical Modes**:
  1. *Analyze Only*: Classifies external traffic with zero weight updates to live streaming models.
  2. *Historical Research*: Ingests records with full forensic provenance into SQLite for longitudinal analytics.
  3. *Controlled Replay*: Simulates live packet arrival with configurable speed multipliers ($0.5\times$ to $10\times$ and Max) with interactive pause/resume/cancel controls.
  4. *Label-Assisted Evaluation*: Automated benchmark evaluation computing multi-class confusion matrices, Accuracy, Precision, Recall, and F1-Score.
- **Watchlist & IOC Cross-Correlation**: In-memory threat indicator matching with sub-millisecond lookup latency.

---

## 3. Technology Stack

- **Backend**: Python 3.11+, FastAPI (Asynchronous REST API & WebSockets), Uvicorn ASGI.
- **Machine Learning**: River (Adaptive Random Forest, ADWIN, Half-Space Trees), Scikit-Learn, NumPy.
- **Packet Dissection**: Scapy, PcapReader.
- **Database**: SQLite (WAL Mode) with SQLAlchemy ORM and automatic PRAGMA migrations.
- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3 (Institutional University of Ghana palette), Chart.js.
- **Documentation**: Microsoft Word COM, ReportLab, Markdown.

---

## 4. Installation & Quickstart

### Prerequisites
- Python 3.11, 3.12, or 3.13 installed.
- Administrative / Root privileges (required for raw socket packet sniffing via Npcap / libpcap).
- On Windows: Install [Npcap](https://npcap.com/) (enable "WinPcap API-compatible mode").

### Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Aseda-Asiedu/NEXz.git
   cd NEXz
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   ```bash
   python run.py
   ```

5. **Access the Web Interface**:
   Open your browser and navigate to:
   ```
   http://localhost:8000
   ```
   Default administrative credentials:
   - **Username**: `admin`
   - **Password**: `admin123`

---

## 5. Running Automated Verification Tests

To verify all subsystems, run the automated test suite:

```bash
# Run External Telemetry Import & Normalization Test Suite (12 Tests)
python scratch/test_import_subsystem.py

# Run Phase 2 Backend Regression Test Suite
python scratch/test_phase2_backend.py

# Run UI & Information Architecture Verification Suite
python scratch/test_ui_elevation.py
```

---

## 6. Academic Documentation & Capstone Artifacts

Complete academic project documentation is available in the `docs/` directory:
- [`docs/NEXz_Final_Project_Documentation.docx`](docs/NEXz_Final_Project_Documentation.docx): Microsoft Word comprehensive final-year dissertation.
- [`docs/NEXz_Final_Project_Documentation.pdf`](docs/NEXz_Final_Project_Documentation.pdf): PDF version compiled with tables, figures, and APA 7th references.
- [`docs/system_architecture.md`](docs/system_architecture.md): Formal architectural specification and data flow.
- [`docs/technical_design.md`](docs/technical_design.md): Algorithmic definitions of ARF, ADWIN, and HST.

---

## 7. License & Acknowledgements

This project is licensed under the **MIT License**.

Developed in the **Department of Computer Science, University of Ghana, Legon**.  
Special thanks to the open-source maintainers of **River**, **FastAPI**, **Scapy**, and **Chart.js**.
