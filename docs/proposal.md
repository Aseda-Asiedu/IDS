# Proposal and Software Engineering Analysis

---

# Part 1: Project Proposal

## 1.1 Project Title
**Design and Implementation of an AI-Powered Adaptive Network Intrusion Detection System with Incremental Learning and a Real-Time Monitoring Dashboard**

---

## 1.2 Background of the Study
The rapid digitisation of public and private sector organisations in developing economies, including Ghana, has increased their vulnerability to cyber threats. Educational institutions, small-to-medium enterprises (SMEs), and public utilities rely heavily on computer networks for day-to-day operations. However, these networks are targeted by malicious actors using advanced scanning, brute force, Denial of Service (DoS), malware, and unauthorized access techniques.

Traditional defensive measures depend heavily on Network Intrusion Detection Systems (NIDS). Historically, these systems are categorized into:
1. **Signature-based detection:** Relying on databases of known attack patterns (e.g., Snort). These fail to detect zero-day exploits and require frequent signature updates.
2. **Static machine learning detection:** Trained on historic datasets (e.g., NSL-KDD) and deployed as static models. These suffer from performance degradation over time due to **concept drift**—changes in network traffic patterns and evolving attack vectors.

Enterprise-grade solutions (e.g., Cisco Firepower, Palo Alto Networks, Splunk SIEM) are financially out of reach for SMEs and educational institutions in Sub-Saharan Africa. Consequently, there is an urgent need for an open-source, lightweight, and adaptive software prototype that integrates machine learning with online learning capability to provide real-time network defense on consumer-grade hardware.

---

## 1.3 Introduction
Intrusion Detection Systems act as a critical layer of network security by monitoring traffic for policy violations and malicious actions. Implementing artificial intelligence in NIDS has shown promise, but deployment challenges persist. High computational resource requirements and the static nature of machine learning algorithms hinder their utility in dynamic environments. 

This project addresses these challenges by developing a functional, modular software prototype designed to run on a standard workstation. The application combines passive packet capture (using Scapy), feature engineering, offline baseline model training, and online incremental learning (using the River library) to adaptively detect anomalies in network flows. A user-friendly React dashboard visualises live traffic statistics, system alerts, performance metrics, and model status.

---

## 1.4 Problem Statement
Traditional NIDS suffer from three major vulnerabilities:
1. **Inability to Adapt (Static Models & Concept Drift):** Network environments are dynamic; normal usage changes, and hackers alter their techniques. A model trained offline on historical data becomes obsolete as new protocols emerge and attack strategies change, leading to a high rate of false positives and false negatives.
2. **High Infrastructure Costs:** Enterprise intrusion detection systems require dedicated high-performance hardware appliances, proprietary software licensing, and active threat feed subscriptions.
3. **Complexity of Interpretation:** Many open-source NIDS lack intuitive user interfaces, producing raw text logs that require certified security analysts to parse and understand, leaving non-technical system administrators without actionable insights.

---

## 1.5 Research Motivation
As final-year Computer Science students at the University of Ghana, we notice a massive gap between cybersecurity theories taught in the classroom and the practical tools accessible to local IT administrators. Most local organizations run unprotected networks because enterprise tools are priced in foreign currencies, exceeding local budgets. 

This research is motivated by the desire to build a local, affordable, and intelligent security monitoring tool. By combining classical machine learning with modern streaming models (Incremental Learning), we aim to show that adaptive network defense is possible without multi-million dollar investments, laying a foundation for local research in automated cyber defense.

---

## 1.6 Aim and Objectives

### 1.6.1 Aim
To design, implement, and evaluate a modular, low-cost, software-based Network Intrusion Detection System that utilizes incremental machine learning to detect network threats in real time and presents them through an interactive web-based monitoring dashboard.

### 1.6.2 Specific Objectives
1. To design a modular software architecture consisting of a packet-sniffing backend, a light database, an AI detection engine, and a web-based UI.
2. To extract and process packet features in real-time, grouping raw packets into statistical network flows (e.g., duration, byte counts, protocol details).
3. To train an offline baseline model using the UNSW-NB15 dataset to classify traffic into normal, suspicious, and malicious categories.
4. To implement an incremental learning module using the `River` framework to continuously update the classification model on new data streams.
5. To integrate a concept drift detection mechanism (ADWIN) to trigger model adaptation when network baseline behaviors shift.
6. To build an interactive dashboard using React and FastAPI to visualize alerts, model accuracy, attack timelines, and network statistics.
7. To validate the system using simulated traffic and standard PCAP datasets, measuring latency, memory usage, and detection performance.

---

## 1.7 Research Questions
1. How can a real-time network stream be processed and transformed into statistical flow features on standard commodity hardware?
2. What machine learning algorithms provide the optimal balance of classification accuracy and computational overhead for a local NIDS?
3. How can incremental learning algorithms be utilized to mitigate model performance degradation caused by concept drift?
4. How can complex AI prediction outputs and network security logs be simplified visually to allow non-security specialists to make decisions?

---

## 1.8 Scope of the Study
The project focuses on building a functional software prototype, not a rugged network gateway appliance. 
* **Data Sources:** Accepts live packet captures from a single local interface (e.g., Wi-Fi, Ethernet), imported PCAP files, and CSV datasets.
* **Classification Depth:** Traffic will be classified into three broad categories: Normal, Suspicious (e.g., port scans, unusual packet volumes), and Malicious (known attack profiles from datasets).
* **Environment:** Developed and validated on a standard Windows 11 workstation (Intel Core i5, 8GB RAM). It is not designed to handle multi-gigabit enterprise backbones.

---

## 1.9 Limitations of the Study
1. **Hardware Resource Constraints:** Sniffing and analyzing packets on a local machine using Python may result in packet loss at high network volumes (above 100 Mbps) due to the single-threaded nature of the Python Global Interpreter Lock (GIL).
2. **Encryption:** Deep packet payload inspection is limited, as a vast majority of modern web traffic is encrypted (HTTPS/TLS). The system will rely primarily on network layer header metadata (IPs, ports, packet sizes, arrival intervals, protocol types).
3. **Dataset Age:** While UNSW-NB15 is more modern than NSL-KDD, it may still fail to represent the absolute latest zero-day signatures.

---

## 1.10 Significance of the Study
This study contributes to the localization of cybersecurity tooling. It provides:
* **Academic Value:** Serves as a reference implementation for future students studying cybersecurity and machine learning at the University of Ghana.
* **Economic Value:** Offers an open-source alternative for local SMEs, schools, and non-profits that lack the budget for commercial security systems.
* **Technical Innovation:** Demonstrates the application of online machine learning (streaming algorithms) in network classification, proving that models can adapt without offline retraining.

---

## 1.11 Expected Contributions
1. A clean, documented Python implementation of online feature extraction from live packet streams.
2. A comparative analysis of batch training vs. incremental training performance under simulated concept drift conditions.
3. An open-source, highly visual React dashboard template tailored for low-resource network monitoring.

---

## 1.12 Expected Deliverables
1. **Documentation:** A complete undergraduate thesis document (Chapters 1 to 5) formatted to University of Ghana specifications.
2. **Source Code:** Fully commented repository containing backend (FastAPI, Scapy, River, SQLite) and frontend (React, Vite, Chart.js) code.
3. **Trained Models:** Serialized baseline models and trained online classifiers.
4. **Demonstration Video:** A walkthrough demonstrating PCAP import, live packet capture, alert generation, and concept drift visualization.

---

## 1.13 Project Timeline
A standard 16-week timeline mapped across two semesters:

| Week | Phase | Major Activities | Deliverables |
|---|---|---|---|
| Weeks 1-2 | Proposal & Setup | Literature review, requirement gathering, setting up development environments. | Approved Proposal |
| Weeks 3-4 | Research & Design | Database design, wireframing dashboards, selecting datasets. | Architecture Diagrams |
| Weeks 5-6 | Data Pipeline | Writing packet sniffer, feature extraction scripts, testing on sample PCAPs. | Packet processing module |
| Weeks 7-8 | AI Engine (Offline) | Data cleanup, training baseline models (Random Forest), model serialisation. | Baseline ML Model |
| Weeks 9-10 | AI Engine (Online) | Integrating River library, ADWIN drift detection, testing incremental updates. | Adaptive ML Engine |
| Weeks 11-12 | Backend API & DB | Building FastAPI endpoints, authentication, database storage for logs. | SQLite database & REST APIs |
| Weeks 13-14 | Dashboard Frontend | Building React screens, charts (Chart.js), real-time alerts using WebSockets. | Dashboard UI |
| Week 15 | Integration & Test | Combining frontend and backend, system testing, load testing. | Completed Software |
| Week 16 | Thesis Compilation | Finalizing thesis write-up, preparing presentation slides for defense. | Completed Thesis & Demo |

---

## 1.14 Risk Analysis

| Risk ID | Risk Description | Probability | Impact | Mitigation Strategy |
|---|---|---|---|---|
| R1 | High traffic volume causes packet loss in Scapy. | High | Medium | Implement packet dropping policies, optimize the packet processing thread, and test with moderate traffic. |
| R2 | Incremental model accuracy degrades due to catastrophic forgetting. | Medium | High | Maintain an ensemble model; keep a static offline model as a baseline voting mechanism alongside the adaptive stream model. |
| R3 | Hardware performance issues (8GB RAM limitation). | Low | High | Profile memory usage; avoid loading entire PCAPs into memory. Stream records line-by-line. |

---

## 1.15 Future Work
Future iterations of this project can extend capabilities by:
1. Moving from a single workstation deployment to a distributed containerized architecture (using Docker and Kubernetes).
2. Implementing automated firewall blocking (Active Prevention/IPS) via network interface scripts.
3. Integrating threat intelligence API feeds (e.g., AlienVault OTX, VirusTotal) to check IP reputations.

---
---

# Part 9: Software Engineering Analysis

## 9.1 Functional Requirements

| Req ID | Requirement Description | Priority |
|---|---|---|
| FR-01 | The system must sniff live traffic from a user-selected network interface. | High |
| FR-02 | The system must support importing and analyzing offline PCAP files. | High |
| FR-03 | The system must extract key network packet features (source IP, dest IP, ports, protocol, payload length, flags). | High |
| FR-04 | The AI model must classify flows into Normal, Suspicious, or Malicious in real-time. | High |
| FR-05 | The system must write classification logs and alerts to a persistent database. | High |
| FR-06 | The frontend must display visual charts representing traffic throughput and alert distribution. | High |
| FR-07 | Users must be able to log in securely to access the dashboard. | Medium |
| FR-08 | The model management panel must allow users to view current model metrics and trigger model retraining. | Medium |
| FR-09 | The alert engine must push critical security alerts immediately to the UI via WebSockets. | High |

---

## 9.2 Non-Functional Requirements

### 9.2.1 Performance
* The system should parse and classify standard packet streams with a processing latency of less than 200ms per flow.
* The backend memory consumption must not exceed 2GB under continuous operations.

### 9.2.2 Security
* Authentication keys and user passwords must be hashed using bcrypt before database storage.
* API endpoints must require JWT (JSON Web Tokens) for authorization.

### 9.2.3 Reliability
* The system must handle corrupted or malformed PCAP files gracefully, logging an error without crashing the backend thread.
* The SQLite database must support concurrent reads by the dashboard while the packet parser is writing logs.

### 9.2.4 Usability
* The user interface must be fully responsive, rendering correctly on layouts down to 1024px width.
* The visual dashboard must utilize clear, standardized colors for threat indicators (Red = Malicious, Orange = Suspicious, Green = Normal).

---

## 9.3 System Requirements

### 9.3.1 Hardware Requirements (Minimum target workstation)
* **Processor:** Intel Core i5 or AMD Ryzen 5 (quad-core, minimum 2.5 GHz).
* **RAM:** 8 GB DDR4 (16 GB recommended for running multiple heavy browsers during development).
* **Storage:** 20 GB of free hard drive space (SSD preferred) to store system software and training datasets.
* **Network Card:** Standard Gigabit Ethernet or 802.11ac Wi-Fi adapter supporting promiscuous mode (for packet sniffing).

### 9.3.2 Software Requirements
* **Operating System:** Windows 10/11 (64-bit).
* **Runtime Environment:** Python 3.10.x or 3.11.x.
* **Development Environment:** VS Code.
* **Libraries/Frameworks:** FastAPI, React (Vite), SQLite, Scapy, Scikit-Learn, River, Tailwind CSS, Chart.js.
* **Utilities:** Wireshark/Npcap (required for live Windows packet sniffing).

---

## 9.4 Actors
1. **Network Administrator / Security Analyst (User):** Logs in to the dashboard to monitor traffic, view metrics, and manage the system.
2. **System Developer:** Configures, tests, and deploys code changes to the pipeline.
3. **Network Interface (External System):** The physical or wireless network card streaming raw packets to the backend.

---

## 9.5 User Stories

1. *As a Security Analyst, I want to upload a PCAP file containing historic traffic, so that I can analyze past activities and see if any intrusion attempts went undetected.*
   - **Acceptance Criteria:** A file drop area exists. Invalid files return a 400 error. Successfully parsed PCAPs display an interactive timeline of events.
2. *As a Network Administrator, I want to see real-time alerts on the dashboard when a malicious packet is detected, so that I can block the offending IP address immediately.*
   - **Acceptance Criteria:** Alerts pop up dynamically without refreshing the page. Alerts highlight the classification level, source IP, target IP, and classification score.
3. *As an Analyst, I want to monitor the machine learning model's accuracy and concept drift status, so that I know when the model requires updating.*
   - **Acceptance Criteria:** Visual graphs show rolling accuracy. A visual indicator turns amber/red when ADWIN detects a concept drift event.

---

## 9.6 Use Case Description: Analyzing Network PCAP File

* **Use Case ID:** UC-02
* **Actor:** Security Analyst
* **Preconditions:** Analyst is logged in. System backend is active.
* **Basic Flow:**
  1. The analyst navigates to the "Traffic Import" panel.
  2. The analyst clicks "Upload File" and selects a `.pcap` file from their local file explorer.
  3. The backend validates the file extension and format.
  4. The packet processing module reads the packets, groups them into session flows, and extracts features.
  5. The AI classification engine scores each flow.
  6. The backend saves logs to SQLite.
  7. The frontend updates dashboard charts and populates the recent activities table.
* **Alternative Flow (Invalid File):**
  3a. If the file is not a valid PCAP, the system displays an "Invalid File Format" error to the user and halts processing.

---

## 9.7 SWOT Analysis

```
       STRENGTHS                                  WEAKNESSES
+----------------------------------------+ +----------------------------------------+
| 1. Low resource overhead (runs on 8GB).| | 1. Single-threaded Python packet       |
| 2. Adaptable through online learning.  | |    processing limits throughput.       |
| 3. Highly modular, modern web design.  | | 2. Dependency on Npcap on Windows.     |
| 4. Cost-effective (100% open-source).  | | 3. Relies on headers; payload blind.   |
+----------------------------------------+ +----------------------------------------+
       OPPORTUNITIES                              THREATS
+----------------------------------------+ +----------------------------------------+
| 1. Can scale into a local startup.     | | 1. Zero-day exploits may bypass the    |
| 2. Future integration with active IPS.  | |    feature representations.            |
| 3. Deployment in academic labs.        | | 2. Rapid changes in encryption protocols|
|                                        | |    render metadata less useful.         |
+----------------------------------------+ +----------------------------------------+
```

---

## 9.8 Feasibility Study

### 9.8.1 Technical Feasibility
Highly Feasible. The technology stack selected consists of Python (FastAPI, Scapy, River) and React, which are well-documented, popular, and have robust package ecosystems. The hardware limits (8GB RAM, Windows OS) are fully aligned with these lightweight frameworks.

### 9.8.2 Operational Feasibility
Highly Feasible. The target user is an IT administrator or researcher. The visual nature of the React dashboard reduces the training curve. System maintenance is simplified by using SQLite (file-based database) and a unified backend script.

### 9.8.3 Economic Feasibility
Highly Feasible. Development costs are zero, as we are using free, open-source software (OSS). The target environment is a standard PC, eliminating the need to purchase dedicated switches, routers, or servers.

---

## 9.9 Cost Analysis

| Component | Item Description | Cost (GHS) | Cost (USD) |
|---|---|---|---|
| Development Machine | Intel Core i5, 8GB RAM Laptop | Existing Asset | Existing Asset |
| Operating System | Windows 11 Home Edition | Pre-installed | Pre-installed |
| Backend Runtime | Python SDK (3.10) | Free (Open-Source) | Free |
| Database Engine | SQLite Database | Free (Open-Source) | Free |
| IDE | Visual Studio Code | Free (Open-Source) | Free |
| Packet Sniffing Driver| Npcap (OEM Light) | Free (Standard Use)| Free |
| **Total Cost** | | **GHS 0.00** | **USD 0.00** |

---

## 9.10 Ethical and Legal Considerations
1. **Consent & Privacy:** Sniffing network packets in a shared environment can intercept private data (emails, chats, login credentials). Developers must only run live captures on networks they own or have received written authorization to monitor.
2. **Npcap Licensing:** Npcap is free for standard educational/commercial use up to a specific seat capacity. Ensure adherence to the Npcap license requirements during research and demonstration.
3. **Responsible Disclosure:** If the system discovers vulnerability logs during testing on University of Ghana networks, findings must be privately shared with university IT administrators rather than publicised.

---

## 9.11 System Maintenance Plan
To keep the system operational:
* **Database Purging:** Implement an automated cron job or threshold rule to purge network logs older than 30 days to prevent disk space exhaustion.
* **Model Serialization Backups:** Set up daily backups of the `.pkl` or `.joblib` model state files so the system can recover to a stable state if a corruption occurs during online learning.
