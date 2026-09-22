# Technical Stack, AI Design, and Startup Roadmap

---

# Part 5: Technology Stack Evaluation and Recommendations

Selecting the software development stack is a critical architectural decision for an undergraduate capstone project. The selected stack must balance execution performance, ease of implementation, hardware limits (Intel Core i5, 8GB RAM, Windows 11), development velocity, and the modularity of the AI engine.

## 5.1 Programming Language Comparison

| Language | Execution Speed | Machine Learning Ecosystem | Learning Curve for Students | Memory Footprint | Recommendation |
|---|---|---|---|---|---|
| **Python** | Moderate (Interpreted) | Excellent (Scikit-Learn, PyTorch, River, Scapy) | Low | Low-to-Moderate | **Highly Recommended** |
| **Java** | High (JIT Compile) | Moderate (Weka, Deeplearning4j) | Moderate | High | Not Recommended |
| **C#** | High (Compiled) | Poor-to-Moderate (ML.NET) | Moderate | Moderate-to-High | Not Recommended |
| **Node.js (JavaScript)** | High (V8 Engine) | Poor (TensorFlow.js is limited) | Low | Low | Not Recommended |

### Justification:
Python is selected as the primary language for backend development. While languages like Java or C# offer superior concurrency, Python is the industry standard for Artificial Intelligence and Machine Learning. The availability of native packet processing libraries (`Scapy`) and online machine learning frameworks (`River`) eliminates the need to build mathematical algorithms from scratch.

---

## 5.2 Web Framework Comparison (Backend)

| Framework | Architecture Style | Async Support | Built-in Features | Performance | Recommendation |
|---|---|---|---|---|---|
| **Django** | Monolithic (MTV) | Limited | High (ORM, Admin Panel, Auth) | Moderate | Not Recommended (Too heavy for local deployment) |
| **Flask** | Microservice | Poor (Sync by default) | Minimal | High | Alternative Option |
| **FastAPI** | Modern Microservice | Excellent (Native Async) | Auto OpenAPI docs, validation | Extremely High | **Recommended** |

### Justification:
FastAPI is chosen over Flask and Django. It is built on modern ASGI standards, supporting native asynchronous operations. This is critical for real-time WebSocket communication and handling concurrent incoming packet data streams while serving API queries. It has a significantly lower memory footprint than Django and automatically generates interactive API documentation (Swagger UI).

---

## 5.3 Frontend Framework Comparison

| Framework | Paradigm | Data Binding | Bundle Size | Community Support | Recommendation |
|---|---|---|---|---|---|
| **React** | Component-based (SPA) | One-way | Small-to-Medium | Massive | **Recommended** |
| **Vue** | MVVM | Two-way | Very Small | Large | Alternative Option |
| **Angular** | Monolithic Framework | Two-way | Large | Large | Not Recommended (Overkill for a prototype dashboard) |

### Justification:
React (using Vite as a build tool) is selected. Its component-based virtual DOM architecture renders UI updates efficiently, which is critical when refreshing network traffic charts multiple times per second. TypeScript integration provides static type checking, preventing runtime crashes during demonstrations.

---

## 5.4 Database Engine Comparison

| Database | Data Model | Setup Overhead | RAM Overhead | Concurrent Write Support | Recommendation |
|---|---|---|---|---|---|
| **SQLite** | Relational (File-based) | Zero (In-process) | Near Zero | Moderate | **Recommended** |
| **PostgreSQL**| Relational (Server-client)| Low-to-Medium | Moderate | High | Alternative Option |
| **MongoDB** | Document-oriented | Medium | High | High | Not Recommended |

### Justification:
SQLite is recommended. It stores data as a single file, requiring zero database server setup or daemon background processes. This is highly suitable for an 8GB RAM Windows laptop where background RAM usage must be minimized. SQLite is capable of processing thousands of writes per second, which easily handles log insertions for this scale of prototype.

---

## 5.5 AI and Streaming Libraries Comparison
* **Scikit-Learn:** Excellent for the baseline offline model (Random Forest, Decision Trees). However, it is fundamentally designed for batch processing and cannot update its parameters incrementally.
* **River:** Specifically built for online, streaming machine learning. It supports incremental classification, regression, and concept drift detection algorithms. It runs instance-by-instance, allowing the system to update the classifier dynamically with a memory footprint of just a few kilobytes.
* **TensorFlow / PyTorch:** These deep learning frameworks are highly powerful but demand massive CPU/GPU resources and long training cycles, making them impractical for real-time inference on a low-end laptop.
* **Recommendation:** Combine **Scikit-Learn** for offline data preprocessing/baseline training, and **River** for real-time online learning and concept drift monitoring.

---

## 5.6 Data Visualization Comparison
* **Plotly:** Provides complex, highly analytical charts but has a large bundle size and higher rendering overhead.
* **Chart.js:** A lightweight, HTML5 Canvas-based charting library. It is exceptionally fast at rendering real-time line, bar, and doughnut charts, and works seamlessly with React wrappers (`react-chartjs-2`).
* **Recommendation:** **Chart.js** due to its low memory footprint and high responsiveness.

---

## 5.7 Packet Sniffing & Processing Tools
* **Wireshark:** A GUI network analyzer. We cannot embed it directly inside our custom dashboard code.
* **PyShark:** A Python wrapper for Wireshark’s tshark tool. It has high packet parsing latencies because it runs an external tshark process under the hood.
* **Scapy:** A powerful, pure-Python library for packet manipulation and sniffing. It allows direct hook callbacks for every captured packet, giving the developer complete control over real-time processing threads.
* **Recommendation:** **Scapy** for live capture hooks and PCAP ingestion, supported by **Npcap** as the underlying Windows packet capture driver.

---
---

# Part 6: Artificial Intelligence Engine Design

## 6.1 Dataset Selection
For this project, we select the **UNSW-NB15 dataset** (created by the Cyber Range Lab of UNSW Canberra).
* **Why not NSL-KDD/KDD99?** NSL-KDD is over 25 years old. It lacks modern application layer protocols and attack patterns (such as modern botnets, worms, and widespread web-based attacks).
* **UNSW-NB15 Characteristics:** It contains modern normal traffic profiles and 9 types of simulated attacks: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.

---

## 6.2 Preprocessing and Feature Engineering
Raw network packets must be aggregated into structured records representing "flows". A flow is defined by packets sharing the same 5-tuple: (Src IP, Dest IP, Src Port, Dest Port, Protocol) within a time window \(T\).

```
Raw Packets ---> [ 5-Tuple Grouper ] ---> [ Feature Calculator ] ---> ML Feature Vector
```

The system extracts the following numeric features for model consumption:
1. `sbytes`: Source-to-destination transaction bytes.
2. `dbytes`: Destination-to-source transaction bytes.
3. `splt`: Source packet inter-arrival time (mean).
4. `dplt`: Destination packet inter-arrival time (mean).
5. `proto_id`: Encoded protocol type (TCP = 1, UDP = 2, ICMP = 3, Others = 0).
6. `packet_count`: Total packets in the flow window.
7. `average_packet_size`: Net bytes divided by packet count.

---

## 6.3 Machine Learning Algorithms Evaluation (Classifier)

### 6.3.1 Offline Models (Scikit-Learn)
1. **Decision Tree (DT):** Fast training, but highly prone to overfitting on static datasets.
2. **Support Vector Machine (SVM):** High training latency on large datasets (scales quadratically with sample size).
3. **Random Forest (RF) - *Recommended for Offline Baseline*:** Builds an ensemble of decision trees. It is highly accurate, robust to outliers, and outputs feature importances, allowing security analysts to trace why an alert was triggered.

### 6.3.2 Online / Incremental Models (River)
1. **Naive Bayes (Online):** Extremely fast and low memory, but assumes complete feature independence, which is false in network traffic.
2. **Hoeffding Adaptive Tree (HAT) - *Recommended for Online Learn*:** An online decision tree that can grow branches incrementally as new samples arrive. It integrates ADWIN drift detection directly into its node splitting mechanism, enabling automatic branch pruning when network statistics shift.

---

## 6.4 The Adaptive Pipeline & Concept Drift Handling
The core innovations of this system lie in its adaptive learning pipeline:

```
            +--------------------------------------------+
            |             Incoming Flow Record           |
            +--------------------------------------------+
                                  |
                                  v
                    +----------------------------+
                    |    Predict Class Label     | (Hoeffding Tree)
                    +----------------------------+
                                  |
                                  v
                    +----------------------------+
                    |  Calculate Loss / Error    |
                    +----------------------------+
                                  |
            +---------------------+---------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
|  ADWIN Drift Monitor  |                   | Update Tree Weights   | (Learn Instance)
+-----------------------+                   +-----------------------+
            |                                           |
            v                                           |
  Drift Detected?                                       |
    /         \                                         |
 Yes           No                                       |
  |             |                                       |
  v             v                                       v
[Prune Tree] [Continue] <===============================+
```

1. **Prediction:** A new flow vector arrives. The Hoeffding Adaptive Tree predicts the label (Normal / Suspicious / Malicious).
2. **Evaluation:** The system compares the prediction against the ground truth (labeled by the analyst or validated via dataset comparison).
3. **Incremental Training:** The model calls `.learn_one(X, y)` to update tree splitting parameters immediately.
4. **Drift Detection:** The prediction error stream feeds into the **ADWIN** algorithm. If the error rate changes significantly, ADWIN triggers a drift flag, clearing outdated branches of the Hoeffding Tree to allow new, active patterns to dominate.

---
---

# Part 10: Commercialization and Startup Roadmap

This prototype holds commercial potential to become a localized cybersecurity SaaS product for SMEs in emerging markets.

## 10.1 Commercial Feature Enhancements
To shift the prototype from an academic capstone to a commercial product:
1. **Distributed Agent Sniffing:** Deploy lightweight, containerized Python sniffing agents on client subnetworks, centralizing analytical data processing into a cloud-hosted dashboard.
2. **Active IPS Actions:** Build automated response scripts that interface with standard routers or host firewalls (e.g., Windows Defender Firewall, iptables) to block malicious IPs upon classification.
3. **E-mail & SMS Notifications:** Integrate Twilio or SendGrid APIs to immediately notify network administrators of critical alerts when they are away from the console.

---

## 10.2 Target Market & Customer Segment
* **SMEs and Local Retailers:** Small businesses handling customer data (e.g., local pharmacies, microfinance institutions) that cannot afford a full SOC (Security Operations Center).
* **Educational Institutions:** Primary and secondary schools in Ghana requiring simple web filters and network visibility.
* **Managed Service Providers (MSPs):** Small IT support shops that want to offer security monitoring services to their existing client bases.

---

## 10.3 Business Model and Pricing Strategy
The venture operates on a **Freemium SaaS and Consulting Model**:

```
                       +----------------------------------+
                       |        Startup Revenue           |
                       +----------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
  +------------------------------+              +------------------------------+
  |    Subscription Licenses     |              |     Professional Services    |
  +------------------------------+              +------------------------------+
  - Community: Free, local, OSS.                 - Hardware appliance setup.
  - Professional: Cloud console ($29/mo).        - Custom network integration.
  - Enterprise: Multi-site agent ($99/mo).       - Threat incident response.
```

---

## 10.4 Go-to-Market Strategy & Development Phases

```
   PHASE 1 (Months 1-3)            PHASE 2 (Months 4-6)            PHASE 3 (Months 7-12)
+-------------------------+     +-------------------------+     +-------------------------+
| Open Source Launch      |     | Hardware Package        |     | Cloud SaaS Portal       |
| - Github Repository     | --> | - Pre-configured mini PC| --> | - Centralized console   |
| - Community forum       |     | - On-site installation  |     | - Automated threat feeds|
| - Free local dashboard  |     | - Direct IT training    |     | - Multi-tenant billing  |
+-------------------------+     +-------------------------+     +-------------------------+
```

By releasing the core dashboard engine under an open-source license (such as MIT), we build local developer trust, gather feature feedback, and recruit beta testers. Commercialization is funded through value-added cloud hosting, dedicated hardware sales, and enterprise support retainers.
