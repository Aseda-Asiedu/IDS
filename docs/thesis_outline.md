# Undergraduate Thesis Structure & Outlines

---

# Part 8: Thesis Chapter Headings and Structure

This document outlines the formal academic thesis structure required for submission to the Department of Computer Science at the University of Ghana. It provides the exact layout, subheadings, and writing expectations for Chapters 1 through 5.

---

## CHAPTER ONE: INTRODUCTION

### 1.1 Study Context & Background
*   **Focus:** Introduce the significance of cybersecurity in modern computer networking. Discuss the growing reliance of local businesses and academic systems in Ghana on web-based services. Explain why security auditing is a critical administrative task.
*   **Key Themes:** Network vulnerabilities, threat types, signature-based defense limitations, need for automated AI solutions.

### 1.2 Statement of the Problem
*   **Focus:** Describe the specific issue this study aims to resolve. State that static machine learning models degrade over time due to concept drift, traditional NIDS produce high false-positive rates, and commercial tools are cost-prohibitive.

### 1.3 Project Motivation
*   **Focus:** Detail the academic, practical, and financial motivations driving this research, focusing on the need for local, lightweight security toolkits in emerging markets.

### 1.4 Aim and Objectives
*   **1.4.1 General Aim:** Build a functional, adaptive software prototype with a visual dashboard.
*   **1.4.2 Specific Objectives:**
    1.  Scaffold a decoupled backend/frontend system.
    2.  Extract 5-tuple statistical flows from packet streams.
    3.  Implement offline baseline classification models.
    4.  Create online adaptive learning pipes with concept drift handles.
    5.  Build UI charts, grids, status cards, and settings.

### 1.5 Research Questions
*   **Focus:** State the questions guiding this study, focusing on flow compilation on commodity hardware, classifier performance trade-offs, and concept drift mitigation.

### 1.6 Scope of the Study
*   **Focus:** Define the limits of the software, identifying target classifications, protocols tracked, and execution boundaries.

### 1.7 Limitations of the Study
*   **Focus:** Disclose the boundaries out of the developers' control (e.g., Python thread limits, encryption shielding payload data, reliance on historical dataset distributions).

### 1.8 Significance of the Study
*   **Focus:** Highlight the academic contributions, economic benefits for SMEs, and innovation of streaming classifiers.

### 1.9 Organisation of the Thesis
*   **Focus:** Provide a brief summary of what each subsequent chapter covers.

---

## CHAPTER TWO: LITERATURE REVIEW

### 2.1 Overview of Computer Network Intrusions
*   **Focus:** Introduce common network attacks, their methods of execution, and modern defensive controls.

### 2.2 Classical Intrusion Detection Paradigms
*   **2.2.1 Signature-Based IDS (S-NIDS):** Detailed review of rule matching (Snort) and why it fails to flag zero-day threats.
*   **2.2.2 Anomaly-Based IDS (A-NIDS):** Analysis of baseline profiles and statistical thresholds.

### 2.3 Machine Learning Applications in Cyber Defense
*   **2.3.1 Batch Machine Learning:** Review of SVM, Random Forest, Naive Bayes models.
*   **2.3.2 Deep Learning Models:** Discussion of CNNs, LSTMs, Autoencoders, and their computational constraints.

### 2.4 Online Learning, Incremental Training, and Concept Drift
*   **2.4.1 Mechanics of Concept Drift:** Mathematical formulations of drift types and performance impact.
*   **2.4.2 Incremental Streaming Classifiers:** How streaming classifiers adapt dynamically.
*   **2.4.3 Drift Detection Algorithms:** Deep dive into ADWIN window adjustments.

### 2.5 Security Visualisation Dashboards
*   **Focus:** Critical analysis of terminal security tools vs. modern GUI interfaces, focusing on user accessibility.

### 2.6 Gaps in Existing Literature & Summary
*   **Focus:** Present a summary table showing what previous authors achieved, where their methodologies fall short, and how this project resolves those gaps.

---

## CHAPTER THREE: METHODOLOGY & DESIGN

### 3.1 Research Methodology Framework
*   **Focus:** Diagram the engineering model utilized (e.g., Agile/Iterative Software Development Life Cycle), detailing how iterations were run.

### 3.2 System Architecture
*   **Focus:** Present the 9 UML architectural diagrams (Context, Use Case, Activity, Sequence, Class, Component, Deployment, ERD, Network placement) with detailed descriptions of components.

### 3.3 Data Ingestion Pipeline & Preprocessing
*   **Focus:** Detail the feature engineering process. Explain how raw packet fields (TCP flags, ports, bytes) are parsed via Scapy and aggregated into 5-tuple flow vectors.

### 3.4 Baseline Classifier Training (Offline Phase)
*   **Focus:** Describe the UNSW-NB15 dataset selection, cleaning, feature scaling, model selection, hyperparameter validation, and export process.

### 3.5 Adaptive Stream Training (Online Phase)
*   **Focus:** Explain the implementation of the River library Hoeffding Tree and its integration with ADWIN.

### 3.6 Evaluation Metrics
*   **Focus:** Detail the mathematical formulations of the metrics used to evaluate the models:
    *   $$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
    *   $$\text{Precision} = \frac{TP}{TP + FP}$$
    *   $$\text{Recall} = \frac{TP}{TP + FN}$$
    *   $$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

### 3.7 Interface Wireframes and Mockups
*   **Focus:** Present diagram mockups of the main views (Login, Home, Alerts, Model Control).

---

## CHAPTER FOUR: IMPLEMENTATION & DISCUSSIONS

### 4.1 System Development Environment
*   **Focus:** List the hardware and software packages used during coding.

### 4.2 Backend & Frontend Code Implementations
*   **Focus:** Show key code segments representing the packet sniffer, AI classifier update loops, and WebSocket alert streams.

### 4.3 System Test Execution & Integration Results
*   **Focus:** Discuss the results of testing the integrated system. Document PCAP uploads, WebSocket delivery latency, and dashboard page loading times.

### 4.4 Machine Learning Classification Results
*   **Focus:** Detail the model's performance. Compare the offline Random Forest accuracy against the online Hoeffding Adaptive Tree under normal and anomalous conditions.

### 4.5 Concept Drift Simulation Analysis
*   **Focus:** Describe a simulated drift event (e.g., introducing a new attack vector not present in the training set). Show how the ADWIN detector reacts and how the online model recovers accuracy post-drift.

### 4.6 Performance & Computational Overhead Discussions
*   **Focus:** Present tables and charts showing CPU load, RAM footprint, and latency during peak sniffing rates on the target workstation.

---

## CHAPTER FIVE: CONCLUSION & RECOMMENDATIONS

### 5.1 Project Summary
*   **Focus:** Review the project, explaining how the objectives defined in Chapter 1 were achieved.

### 5.2 Summary of Experimental Findings
*   **Focus:** State the final metrics achieved by the baseline and online models, and the responsiveness of the drift detector.

### 5.3 Technical & Research Contributions
*   **Focus:** Highlight the value of the open-source pipeline, the lightweight UI framework, and the verification of online algorithms on consumer workstations.

### 5.4 Implementation Challenges
*   **Focus:** Discuss practical hurdles faced, such as handling encrypted payloads, managing Python thread pools, and Windows Npcap configurations.

### 5.5 Recommendations for Future Research
*   **Focus:** Provide suggestions for future work, including cloud deployments, automated active blocking, threat feed integrations, and SIEM connections.

### 5.6 Business and Entrepreneurial Prospects
*   **Focus:** Outline the startup commercialization strategy, potential revenue models, and transition from local application to enterprise subscription.
