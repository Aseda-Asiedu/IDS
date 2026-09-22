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
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String, nullable=False, index=True)
    dest_ip = Column(String, nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dest_port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False, index=True)
    duration = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    prediction_label = Column(String, nullable=False)  # Normal, Suspicious, Malicious
    confidence_score = Column(Float, nullable=False)
    info = Column(String, nullable=True)  # Store extracted HTTP Host, DNS Query, TLS SNI
    source = Column(String, default="live", nullable=False)
    connection_state = Column(String, default="N/A", nullable=False)
    import_batch_id = Column(Integer, ForeignKey("import_batches.id"), nullable=True, index=True)

    alert = relationship("Alert", back_populates="traffic_log", uselist=False)
    import_batch = relationship("ImportBatch", back_populates="traffic_logs")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    traffic_log_id = Column(Integer, ForeignKey("traffic_logs.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("device_profiles.id"), nullable=True)
    import_batch_id = Column(Integer, ForeignKey("import_batches.id"), nullable=True, index=True)
    alert_type = Column(String, default="flow_classification", index=True)  # flow_classification, device_behaviour, arp_mitm, watchlist_match
    alert_time = Column(DateTime, default=datetime.utcnow, index=True)
    last_seen = Column(DateTime, default=datetime.utcnow, index=True)
    threat_level = Column(String, nullable=False, index=True)  # Information, Low, Medium, High, Critical
    status = Column(String, default="New", index=True)  # New, Active, Acknowledged, Resolved
    is_simulated = Column(Boolean, default=False, index=True)
    notes = Column(String, nullable=True)
    is_resolved = Column(Boolean, default=False, index=True)
    count = Column(Integer, default=1)  # Deduplication count

    traffic_log = relationship("TrafficLog", back_populates="alert")
    device = relationship("DeviceProfile", back_populates="alerts")
    import_batch = relationship("ImportBatch", back_populates="alerts")


# ==============================================================================
# === NEXz ADDITION: Device Behaviour Profile Schema ===
# Mechanism: Tracks per-device identity, observation baseline, and anomaly counters
# ==============================================================================
class DeviceProfile(Base):
    __tablename__ = "device_profiles"

    id = Column(Integer, primary_key=True, index=True)
    device_ip = Column(String, unique=True, index=True, nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    sample_count = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)
    baseline_summary = Column(String, nullable=True)  # JSON summary of baseline activity

    alerts = relationship("Alert", back_populates="device")


class ModelMetrics(Base):
    __tablename__ = "model_metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    accuracy = Column(Float, default=0.0)
    precision = Column(Float, default=0.0)
    recall = Column(Float, default=0.0)
    f1_score = Column(Float, default=0.0)
    drift_detected = Column(Boolean, default=False)
    samples_processed = Column(Integer, default=0)


# ==============================================================================
# === NEXz EXTENSION: Telemetry Import Batches & Watchlist Schemas ===
# Architectural Role: Provenance tracking, batch lifecycle management,
# and IOC watchlist cross-correlation across live and imported traffic.
# ==============================================================================
class ImportBatch(Base):
    __tablename__ = "import_batches"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_type = Column(String, nullable=False)  # pcap, csv, json, jsonl, zeek, eve, txt_ioc
    file_size = Column(Integer, default=0)
    file_hash = Column(String, nullable=True, index=True)
    analysis_mode = Column(String, default="analyze_only")  # analyze_only, historical, replay, label_eval, isolated_model
    dataset_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    status = Column(String, default="pending", index=True)  # pending, validating, processing, paused, completed, cancelled, failed
    
    record_count = Column(Integer, default=0)
    valid_count = Column(Integer, default=0)
    invalid_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    
    normal_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    malicious_count = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)
    watchlist_matches = Column(Integer, default=0)
    drift_count = Column(Integer, default=0)
    alerts_count = Column(Integer, default=0)
    
    capabilities_json = Column(String, nullable=True)  # JSON summary of detected valid capabilities
    mapping_json = Column(String, nullable=True)       # JSON of field mapping
    eval_metrics_json = Column(String, nullable=True)  # JSON confusion matrix & evaluation scores
    
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_sec = Column(Float, default=0.0)

    traffic_logs = relationship("TrafficLog", back_populates="import_batch", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="import_batch", cascade="all, delete-orphan")
    watchlist_entries = relationship("WatchlistEntry", back_populates="import_batch", cascade="all, delete-orphan")


class WatchlistEntry(Base):
    __tablename__ = "watchlist_entries"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, nullable=False, index=True)  # IPv4, IPv6, Domain, Hostname
    entry_type = Column(String, default="ipv4", index=True)  # ipv4, ipv6, domain, hostname
    label = Column(String, default="Suspicious Host")
    description = Column(String, nullable=True)
    source = Column(String, default="manual")  # manual, txt_import, csv_import, threat_feed
    import_batch_id = Column(Integer, ForeignKey("import_batches.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    import_batch = relationship("ImportBatch", back_populates="watchlist_entries")


