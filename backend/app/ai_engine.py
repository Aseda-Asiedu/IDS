import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from river import forest, drift

FEATURE_NAMES = ["sbytes", "dbytes", "splt_mean", "dplt_mean", "proto_id", "packet_count", "avg_pkt_size"]

class AIEngine:
    def __init__(self, models_dir="./backend/models"):
        self.models_dir = models_dir
        os.makedirs(self.models_dir, exist_ok=True)
        
        self.offline_model_path = os.path.join(self.models_dir, "baseline_rf.pkl")
        self.online_model_path = os.path.join(self.models_dir, "online_hat.pkl")
        
        # Load or create offline baseline Random Forest model
        self.offline_rf = self._load_or_create_offline_model()
        
        # Initialize River Adaptive Random Forest for online stream training
        self.online_hat = self._load_or_create_online_model()
        
        # Initialize ADWIN concept drift detector
        self.drift_detector = drift.ADWIN(delta=0.002)
        
        # Track accuracy metrics internally
        self.samples_seen = 0
        self.correct_predictions = 0

    # ==============================================================================
    # === ALGORITHM: Offline Random Forest Cold-Start Baseline (scikit-learn) ===
    # Purpose: Provides deterministic cold-start classification before stream warms up
    # ==============================================================================
    def _load_or_create_offline_model(self):
        """
        Loads the baseline Random Forest model, or trains a dummy baseline if missing.
        """
        if os.path.exists(self.offline_model_path):
            try:
                with open(self.offline_model_path, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading offline model: {e}. Re-creating baseline...")
        
        # Train a basic Random Forest on synthetic flow data to ensure it runs out of the box
        print("Training a baseline Random Forest on synthetic flow data...")
        X = []
        y = []
        
        # Helper to append synthetic flows
        # Normal traffic: low byte counts, standard packet counts, TCP/UDP
        for _ in range(100):
            X.append([np.random.randint(100, 1000), np.random.randint(100, 1000), np.random.uniform(0.01, 0.1), np.random.uniform(0.01, 0.1), np.random.choice([1.0, 2.0]), np.random.randint(5, 20), np.random.uniform(40, 100)])
            y.append("Normal")
            
        # DoS attack: high byte count, rapid packet arrival, large packet size
        for _ in range(50):
            X.append([np.random.randint(5000, 50000), np.random.randint(100, 1000), np.random.uniform(0.001, 0.01), 0.0, 1.0, np.random.randint(100, 500), np.random.uniform(500, 1500)])
            y.append("Malicious")
            
        # Port scan attack: single packets, rapid frequency, diverse ports
        for _ in range(50):
            X.append([64.0, 0.0, np.random.uniform(0.0001, 0.002), 0.0, 1.0, 1.0, 64.0])
            y.append("Suspicious")

        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        rf.fit(X, y)
        
        with open(self.offline_model_path, "wb") as f:
            pickle.dump(rf, f)
            
        print("Baseline Random Forest model saved.")
        return rf

    # ==============================================================================
    # === ALGORITHM: River Online ARFClassifier (Streaming Adaptive Random Forest) ===
    # Reference: Gomes et al. (2017). Adaptive random forests for evolving data stream
    # Purpose: Real-time incremental multi-tree flow classification for stream data
    # ==============================================================================
    def _load_or_create_online_model(self):
        """
        Loads the River streaming model or initializes a new Adaptive Random Forest.
        """
        if os.path.exists(self.online_model_path):
            try:
                with open(self.online_model_path, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Error loading online model: {e}. Re-initializing...")
                
        # Use Adaptive Random Forest classifier from River
        return forest.ARFClassifier(n_models=3, seed=42)

    def save_online_model(self):
        """
        Serializes the online model to disk.
        """
        try:
            with open(self.online_model_path, "wb") as f:
                pickle.dump(self.online_hat, f)
        except Exception as e:
            print(f"Failed to save online model: {e}")

    # ==============================================================================
    # === INFERENCE: Ensemble Flow Prediction (Online Stream with Offline Fallback) ===
    # ==============================================================================
    def predict(self, flow_features):
        """
        Inference step. Evaluates a network flow feature vector against the models.
        Returns: label (str), confidence (float)
        """
        # Convert features to dictionary for River
        river_x = dict(zip(FEATURE_NAMES, flow_features))
        
        # Get online prediction and probabilities
        online_pred = self.online_hat.predict_one(river_x)
        online_proba = self.online_hat.predict_proba_one(river_x)
        
        # If online model is still warming up or has observed fewer than 2 classes, fallback to offline
        if online_pred is None or not online_proba or len(online_proba) <= 1:
            # Fallback to offline Random Forest baseline
            offline_pred = self.offline_rf.predict([flow_features])[0]
            offline_probs = self.offline_rf.predict_proba([flow_features])[0]
            confidence = float(np.max(offline_probs))
            return str(offline_pred), confidence
            
        # Use online prediction
        confidence = float(online_proba.get(online_pred, 0.0))
        return online_pred, confidence

    # ==============================================================================
    # === ALGORITHM: Rule-Based Explainable AI (XAI) Diagnostic Playbook ===
    # Purpose: Translates statistical flow features into human-readable triage guidance
    # ==============================================================================
    def explain_prediction(self, flow_features, label):
        """
        Generates Explainable AI (XAI) diagnostics and recommendations based on flow features.
        flow_features: [sbytes, dbytes, splt_mean, dplt_mean, proto_id, packet_count, avg_pkt_size]
        """
        sbytes, dbytes, splt_mean, dplt_mean, proto_id, packet_count, avg_pkt_size = flow_features
        
        if label == "Normal":
            return {
                "threat_type": "Normal Traffic",
                "reason": "Traffic patterns match standard operational baselines (balanced payload size and normal timing).",
                "severity": "Low",
                "action": "No immediate response needed. Maintain active monitoring."
            }
        elif label == "Malicious":
            if sbytes > 15000 or packet_count > 100:
                reason = f"High source data volume ({sbytes:.0f} bytes) over {packet_count:.0f} packets. Characteristically observed in volumetric DoS floods or large unauthorized transfers."
                threat_type = "Potential DoS / Volumetric Flood"
                severity = "Critical"
                action = "Investigate source IP connection rates. Verify affected service health and socket states."
            elif avg_pkt_size > 1000:
                reason = f"Anomalously large average packet size ({avg_pkt_size:.1f} bytes) indicates heavy buffer utilization, characteristic of data staging or potential exfiltration."
                threat_type = "Anomalous Volume / Potential Exfiltration"
                severity = "High"
                action = "Inspect connection endpoint and audit active payload flows on the local subnet."
            else:
                reason = "Multi-feature statistical profile deviates significantly from established baseline characteristics."
                threat_type = "Anomalous Traffic Deviation"
                severity = "High"
                action = "Flag connection for investigation. Correlate with concurrent host activity logs."
            return {
                "threat_type": threat_type,
                "reason": reason,
                "severity": severity,
                "action": action
            }
        else: # Suspicious
            if splt_mean < 0.005 and packet_count > 5:
                reason = f"Abnormally compressed packet inter-arrival interval ({splt_mean:.6f}s) indicates automated probing or rapid connection sweeps."
                threat_type = "Possible Port Scan / Reconnaissance"
                severity = "Medium"
                action = "Investigate originating host. Check for sequential destination port connections."
            elif sbytes < 500 and packet_count <= 2:
                reason = f"Sparse single-packet flow ({sbytes:.0f} bytes, {packet_count:.0f} pkts) characteristic of exploratory TCP flag probing."
                threat_type = "Possible Port Probe"
                severity = "Medium"
                action = "Monitor source IP for broader scanning activity across other local hosts."
            else:
                reason = "Flow timing and packet size parameters exhibit minor divergence from typical traffic patterns."
                threat_type = "Unusual Flow Characteristic"
                severity = "Low"
                action = "Maintain passive observation. No immediate intervention required."
            return {
                "threat_type": threat_type,
                "reason": reason,
                "severity": severity,
                "action": action
            }

    # ==============================================================================
    # === ALGORITHM: Online Stream Learning & ADWIN Concept Drift Check ===
    # Reference: Bifet & Gavalda (2007). Learning from time-changing data with adaptive windowing
    # Purpose: Tracks prediction error rate distributions and signals concept drift
    # ==============================================================================
    def learn_incremental(self, flow_features, true_label):
        """
        Updates the streaming model with a new instance and checks for concept drift.
        Returns: drift_detected (bool)
        """
        river_x = dict(zip(FEATURE_NAMES, flow_features))
        
        # Get prediction before training (for accuracy metrics)
        pred = self.online_hat.predict_one(river_x)
        
        # Update classifier weights on the single instance
        self.online_hat.learn_one(river_x, true_label)
        self.save_online_model()
        
        # Update metrics
        self.samples_seen += 1
        is_error = 1.0 if pred != true_label else 0.0
        if is_error == 0.0:
            self.correct_predictions += 1
            
        # Update ADWIN drift detector with prediction error status (0 = success, 1 = failure)
        self.drift_detector.update(is_error)
        
        # Check if concept drift occurred
        drift_flag = self.drift_detector.drift_detected
        return drift_flag

    def get_metrics(self):
        """
        Returns prediction accuracy indicators.
        """
        accuracy = (self.correct_predictions / self.samples_seen) if self.samples_seen > 0 else 1.0
        return {
            "samples_processed": self.samples_seen,
            "rolling_accuracy": float(round(accuracy, 4)),
            "drift_width": getattr(self.drift_detector, "width", 0),
            "drift_estimation": round(float(getattr(self.drift_detector, "estimation", 0.0)), 4),
            "drift_variance": round(float(getattr(self.drift_detector, "variance", 0.0)), 4),
            "drift_detected": bool(getattr(self.drift_detector, "drift_detected", False))
        }
