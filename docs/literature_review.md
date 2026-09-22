# Literature Review

---

# Part 2: Literature Review

## 2.1 Introduction
The design and implementation of Network Intrusion Detection Systems (NIDS) has evolved over the past four decades, shifting from manual rule configuration to automated heuristics, and recently, to adaptive machine learning systems. This chapter reviews the historical paradigms of intrusion detection, evaluates contemporary research in streaming and incremental learning, and details the challenges of concept drift in network security. Finally, it analyzes research gaps and highlights how this project addresses these limitations within an undergraduate development scope.

---

## 2.2 Theoretical Framework of Intrusion Detection

```
                       +----------------------------------+
                       |    Intrusion Detection System    |
                       +----------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
  +------------------------------+              +------------------------------+
  |   Signature-Based (Misuse)   |              |      Anomaly-Based (Behavior) |
  +------------------------------+              +------------------------------+
  - Matches known bad patterns                  - Models normal baseline profiles
  - High accuracy for known threats             - Detects novel/zero-day attacks
  - Fails on zero-day attacks                   - High false-positive rate
```

### 2.2.1 Signature-Based Intrusion Detection Systems (S-NIDS)
Signature-based detection systems (also known as misuse detection) operate similarly to antivirus software. They inspect packet payloads and headers, matching them against a database of pre-defined patterns or signatures of known malicious activities.
* **Mechanism:** Snort and Suricata are classic open-source examples. They utilize structured rule languages to identify indicators of compromise (IoCs), such as specific byte sequences in the payload or anomalous TCP flag combinations.
* **Limitations:** Roesch (1999) highlighted that signature-based systems are highly effective at detecting known attacks with low false-positive rates. However, they are incapable of detecting novel (zero-day) attacks, and their storage and search latency scale linearly with the size of the signature database, making them computationally expensive as threat profiles grow.

### 2.2.2 Anomaly-Based Intrusion Detection Systems (A-NIDS)
Anomaly-based detection assumes that malicious behavior deviates statistically from normal network behavior.
* **Mechanism:** An A-NIDS establishes a baseline profile of "normal" network traffic (e.g., typical bandwidth usage, protocol distributions, active ports). Deviations exceeding a defined threshold are flagged as alerts.
* **Limitations:** Denning (1987) laid the foundation for anomaly detection models. While A-NIDS can identify zero-day attacks, they historically suffer from high **false-positive rates (FPR)**. Changes in normal user behavior (e.g., a sudden file transfer during a system backup) are frequently misclassified as malicious, causing alert fatigue for system administrators.

---

## 2.3 Evolution of Artificial Intelligence in NIDS

### 2.3.1 Machine Learning (ML) approaches
To reduce false positives and automate threshold selection, researchers integrated machine learning.
* **Classifiers:** Popular classifiers include Support Vector Machines (SVM), Random Forests (RF), Naive Bayes, and k-Nearest Neighbors (k-NN).
* **Research Contributions:** Sommer and Paxson (2010) discussed the challenges of applying machine learning to network intrusion detection, noting that ML classifiers require balanced training datasets and struggle with the high variability of normal traffic. Random Forest models, however, have emerged as a benchmark due to their high accuracy, resilience to overfitting, and relative interpretability (Buczak & Guven, 2016).

### 2.3.2 Deep Learning (DL) approaches
With the growth of computing power, Deep Learning (DL) models were introduced to eliminate manual feature engineering.
* **Architectures:** Artificial Neural Networks (ANN), Convolutional Neural Networks (CNN), and Long Short-Term Memory (LSTM) networks are frequently proposed to capture temporal sequences in network traffic.
* **Research Contributions:** Shone et al. (2018) proposed using deep autoencoders to extract features, showing high accuracy on the NSL-KDD dataset. However, deep learning models represent a "black box" that is difficult to interpret. Furthermore, their training phase is computationally intensive, requiring dedicated GPUs that are impractical for low-cost, local deployments on standard laptops.

---

## 2.4 Online Learning, Incremental Learning, and Concept Drift

### 2.4.1 The Static Model Assumption and Concept Drift
Traditional machine learning pipelines assume that the data distribution during training matches the data distribution during deployment. In live networks, this assumption is false. Network baselines shift due to:
* **Concept Drift:** Formally defined as a change in the joint probability distribution \(P(X, Y)\), where \(X\) represents the input packet features and \(Y\) represents the class labels.
* **Types of Drift:**
  1. *Sudden Drift:* A new device joins the network and starts a backup, causing a sudden surge in traffic volume.
  2. *Gradual/Incremental Drift:* Software updates slowly change background packet size averages.
  3. *Recurring Drift:* Workday vs. weekend usage patterns.

```
       Sudden Drift                 Gradual Drift                Recurring Drift
   |---Normal---|--Attack--|    |---Normal---\--Attack---|    |--Day--\__Night__/--Day--|
```

Gama et al. (2014) surveyed concept drift adaptation, highlighting that static models degrade significantly in accuracy when drift occurs, leading to undetected intrusions (false negatives) or spam alerts (false positives).

### 2.4.2 Online and Incremental Learning Solutions
Instead of retraining models offline from scratch—which requires storing gigabytes of raw traffic and running long batch training cycles—incremental learning updates model parameters dynamically as data flows in.
* **Streaming Classifiers:** Algorithms such as Hoeffding Trees (Very Fast Decision Trees) and online ensembles (e.g., Adaptive Random Forest) update their structures instance-by-instance.
* **Drift Detectors:** Algorithms like ADWIN (Adaptive Windowing) monitor rolling performance metrics. When ADWIN detects a statistically significant change in prediction error, it signals a drift event, prompting the classifier to discard outdated branches and prioritize newer data (Bifet & Gavaldà, 2007).
* **River Library:** Montiel et al. (2021) introduced *River*, a Python library merging `creme` and `scikit-multiflow` for online machine learning. River provides the foundational implementation of ADWIN and streaming classifiers, making incremental learning accessible in Python without enterprise infrastructure.

---

## 2.5 Network Monitoring Dashboards and Visualization
Effective security monitoring requires translating machine learning outputs into actionable insights.
* **Visualization Gaps:** Many open-source academic NIDS are command-line programs that output raw text logs. In contrast, modern security management relies on Security Information and Event Management (SIEM) systems (e.g., Kibana, Splunk) that require extensive configuration.
* **Undergraduate Design:** For a low-resource setting, lightweight dashboard frameworks built on React and Chart.js provide real-time updates via WebSockets without incurring licensing costs or heavy database storage footprints (Postgres or Elasticsearch).

---

## 2.6 Summary of Related Work & Research Gaps

| Author & Year | Methodology / Model | Strengths | Weaknesses / Gaps | This Project's Differentiator |
|---|---|---|---|---|
| **Sommer & Paxson (2010)** | Machine Learning for Intrusion Detection | Established foundational guidelines for ML in security. | Highlighted high false positive rates but offered no online adaptation. | Implements incremental learning to dynamically adapt and reduce false positives. |
| **Shone et al. (2018)** | Deep Learning with Autoencoders | Automated feature extraction, high accuracy on static datasets. | High GPU training overhead; black-box model. | Utilizes Random Forest and River classifiers that run efficiently on an 8GB RAM CPU. |
| **Bifet & Gavaldà (2007)** | ADWIN Concept Drift Detection | Mathematical proof of windowing for drift adaptation. | Theoretical model, not integrated into a practical NIDS dashboard. | Integrates ADWIN directly with a packet parser and a React visualization interface. |
| **Montiel et al. (2021)** | River Machine Learning Library | Created unified API for streaming algorithms. | General-purpose library; no built-in network packet processing pipeline. | Combines River with Scapy packet parser to build a complete end-to-end security application. |

---

## 2.7 Academic Citations & References
1. Bifet, A., & Gavaldà, R. (2007). Learning from time-changing data with adaptive windowing. *Proceedings of the SIAM International Conference on Data Mining (SDM)*, 443-448.
2. Buczak, A. L., & Guven, E. (2016). A survey of data mining and machine learning methods for cyber security intrusion detection. *IEEE Communications Surveys & Tutorials*, 18(2), 1153-1176.
3. Denning, D. E. (1987). An intrusion-detection model. *IEEE Transactions on Software Engineering*, (2), 222-232.
4. Gama, J., Žliobaitė, I., Bifet, A., Pechenizkiy, M., & Bouchachia, A. (2014). A survey on concept drift adaptation. *ACM Computing Surveys (CSUR)*, 46(4), 1-37.
5. Montiel, J., Halford, M., Mastelini, S. M., Read, J., Reback, B., Pfahringer, B., ... & Bifet, A. (2021). River: machine learning for streaming data in Python. *Journal of Machine Learning Research*, 22(110), 1-5.
6. Roesch, M. (1999). Snort: Lightweight intrusion detection for networks. *Proceedings of the 13th USENIX Conference on System Administration (LISA)*, 229-238.
7. Shone, N., Ngoc, T. N., Phai, V. D., & Shi, Q. (2018). A deep learning approach to network intrusion detection using deep autoencoders. *IEEE Transactions on Emerging Topics in Computational Intelligence*, 2(1), 47-57.
8. Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. *Proceedings of the IEEE Symposium on Security and Privacy*, 305-316.
