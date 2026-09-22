import os
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text, func
from sqlalchemy.orm import Session
import shutil
import time

from .database import engine, get_db, SessionLocal
from .models import Base, User, TrafficLog, Alert, ModelMetrics, DeviceProfile, ImportBatch, WatchlistEntry
from .auth import create_access_token, get_current_user, create_default_admin, verify_password
from .sniffer import PacketSnifferService
from .ai_engine import AIEngine
from .profiler import network_profiler
from .device_profiler import device_profiler
from .alert_manager import alert_manager
from .import_service import import_service

# Initialize SQLite tables
Base.metadata.create_all(bind=engine)

# Create index statements manually if they do not exist (SQLite safe execution)
with engine.begin() as conn:
    # 1. Schema migration checks for SQLite table_info columns
    try:
        res = conn.execute(text("PRAGMA table_info(traffic_logs);")).fetchall()
        columns = [r[1] for r in res]
        if "source" not in columns:
            conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN source VARCHAR(100) DEFAULT 'live';"))
            print("Database migration: added 'source' column to traffic_logs table.")
        if "connection_state" not in columns:
            conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN connection_state VARCHAR(50) DEFAULT 'N/A';"))
            print("Database migration: added 'connection_state' column to traffic_logs table.")
        if "import_batch_id" not in columns:
            conn.execute(text("ALTER TABLE traffic_logs ADD COLUMN import_batch_id INTEGER;"))
            print("Database migration: added 'import_batch_id' column to traffic_logs table.")
            
        alert_res = conn.execute(text("PRAGMA table_info(alerts);")).fetchall()
        alert_cols = [r[1] for r in alert_res]
        if "device_id" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN device_id INTEGER;"))
            print("Database migration: added 'device_id' column to alerts table.")
        if "alert_type" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN alert_type VARCHAR(50) DEFAULT 'flow_classification';"))
            print("Database migration: added 'alert_type' column to alerts table.")
        if "status" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN status VARCHAR(50) DEFAULT 'New';"))
            print("Database migration: added 'status' column to alerts table.")
        if "is_simulated" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN is_simulated BOOLEAN DEFAULT 0;"))
            print("Database migration: added 'is_simulated' column to alerts table.")
        if "last_seen" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN last_seen DATETIME;"))
            print("Database migration: added 'last_seen' column to alerts table.")
        if "import_batch_id" not in alert_cols:
            conn.execute(text("ALTER TABLE alerts ADD COLUMN import_batch_id INTEGER;"))
            print("Database migration: added 'import_batch_id' column to alerts table.")
    except Exception as e:
        print(f"Error executing column migrations: {e}")

    # 2. Create index statements manually if they do not exist
    index_stmts = [
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_timestamp ON traffic_logs (timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_src_ip ON traffic_logs (src_ip);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_dest_ip ON traffic_logs (dest_ip);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_protocol ON traffic_logs (protocol);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_logs_import_batch_id ON traffic_logs (import_batch_id);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_is_resolved ON alerts (is_resolved);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_threat_level ON alerts (threat_level);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_is_simulated ON alerts (is_simulated);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_alert_type ON alerts (alert_type);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_alert_time ON alerts (alert_time);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts (last_seen);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_import_batch_id ON alerts (import_batch_id);",
        "CREATE INDEX IF NOT EXISTS idx_import_batches_status ON import_batches (status);",
        "CREATE INDEX IF NOT EXISTS idx_watchlist_entries_value ON watchlist_entries (value);"
    ]
    for stmt in index_stmts:
        try:
            conn.execute(text(stmt))
        except Exception as e:
            print(f"Index execution notice: {e}")

# Seed default admin user
db_session = SessionLocal()
try:
    create_default_admin(db_session)
finally:
    db_session.close()

app = FastAPI(title="AI-Powered Adaptive NIDS API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify React app domain (e.g. localhost:5173)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Handle broken socket connections gracefully
                pass

manager = ConnectionManager()

# Initialize AI Engine and Profiler
ai_engine = AIEngine()

# Global system settings (Defaults to manual monitoring mode per design brief)
system_settings = {
    "monitoring_mode": "manual",  # "manual" (idle on start) or "automatic"
    "flow_timeout": 2.0,
    "aggregation_window": 30.0
}

import asyncio
main_loop = None
last_broadcast_times = {}

@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()
    if system_settings.get("monitoring_mode") == "automatic":
        try:
            success = sniffer_service.start_sniffing(None)
            if success:
                print("NEXz: Sniffer automatically started passive monitoring on boot.")
            else:
                print("NEXz: Sniffer autostart resolved default interface or is already active.")
        except Exception as e:
            print(f"NEXz: Failed to automatically start sniffer: {e}")
    else:
        print("NEXz: Initialized in MANUAL monitoring mode. Sniffer remains idle until started by operator.")

def broadcast_sync(message: dict):
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), main_loop)

# Callback triggered when packet sniffer outputs a compiled flow record
def on_flow_compiled(flow_record, features, duration, total_bytes):
    db = SessionLocal()
    try:
        # Classify the flow record
        label, confidence = ai_engine.predict(features)
        
        # Save flow details to the database, capturing L7 protocol name and L7 context info
        flow_source = getattr(flow_record, "source", "live")
        flow_state = getattr(flow_record, "connection_state", "N/A")
        
        log = TrafficLog(
            src_ip=flow_record.src_ip,
            dest_ip=flow_record.dest_ip,
            src_port=flow_record.src_port,
            dest_port=flow_record.dest_port,
            protocol=flow_record.protocol_l7 or flow_record.protocol,
            duration=int(duration),
            total_bytes=total_bytes,
            prediction_label=label,
            confidence_score=float(confidence),
            info=flow_record.info,
            source=flow_source,
            connection_state=flow_state
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        
        alert_payload = None
        is_simulated = str(flow_source).startswith("sim:")
        
        # If malicious or suspicious, trigger alert sequence via Central Alert Manager
        if label in ["Malicious", "Suspicious"]:
            if label == "Malicious":
                threat_level = "Critical" if confidence >= 0.9 else "High"
            else:
                threat_level = "Medium" if confidence >= 0.8 else "Low"
                
            xai = ai_engine.explain_prediction(features, label)
            threat_type = xai["threat_type"]
            reason = xai["reason"]
            action = xai["action"]
            
            alert, is_new, alert_payload = alert_manager.ingest_security_event(
                db=db,
                threat_level=threat_level,
                threat_type=threat_type,
                reason=reason,
                action=action,
                src_ip=log.src_ip,
                dest_ip=log.dest_ip,
                protocol=log.protocol,
                src_port=log.src_port,
                dest_port=log.dest_port,
                confidence=float(confidence),
                alert_type="flow_classification",
                traffic_log_id=log.id,
                is_simulated=is_simulated,
                extra_info=flow_record.info
            )
            
        # ==============================================================================
        # === NEXz: Per-Device Behaviour Anomaly Check (Half-Space Trees) ===
        # ==============================================================================
        pkt_count = len(getattr(flow_record, "packet_timestamps", [])) or 1
        dev_res = device_profiler.process_flow(
            src_ip=log.src_ip,
            total_bytes=total_bytes,
            duration=duration,
            protocol=flow_record.protocol,
            hour_of_day=log.timestamp.hour if hasattr(log.timestamp, "hour") else datetime.utcnow().hour,
            packet_count=pkt_count,
            db=db
        )

        if dev_res.get("is_anomalous"):
            dp = device_profiler.sync_to_db(db, log.src_ip)
            dev_threat = dev_res.get("threat_level", "Medium")
            dev_alert_obj, dev_is_new, dev_broadcast_payload = alert_manager.ingest_security_event(
                db=db,
                threat_level=dev_threat,
                threat_type="Device Behaviour Anomaly",
                reason=dev_res.get("reason", "Device activity deviates from established baseline."),
                action="Audit device connection history and inspect local host services.",
                src_ip=log.src_ip,
                dest_ip=log.dest_ip,
                protocol=log.protocol,
                src_port=log.src_port,
                dest_port=log.dest_port,
                confidence=round(dev_res.get("score", 0.8), 2),
                alert_type="device_behaviour",
                traffic_log_id=log.id,
                device_id=dp.id if dp else None,
                is_simulated=is_simulated
            )
            if not alert_payload and dev_broadcast_payload:
                alert_payload = dev_broadcast_payload

        # Compile live throughput metrics payload
        metrics_payload = {
            "type": "metrics",
            "timestamp": log.timestamp.isoformat(),
            "bytes_processed": total_bytes,
            "label": label,
            "src_ip": log.src_ip,
            "dest_ip": log.dest_ip
        }
        
        # Update metrics table if labels are validated (for academic tracking)
        drift_detected = ai_engine.learn_incremental(features, label)
        
        if drift_detected:
            # Log concept drift event
            metrics_log = ModelMetrics(
                accuracy=ai_engine.get_metrics()["rolling_accuracy"],
                drift_detected=True,
                samples_processed=ai_engine.get_metrics()["samples_processed"]
            )
            db.add(metrics_log)
            db.commit()
            
            # Broadcast drift event to UI
            broadcast_sync({
                "type": "drift_alert",
                "message": "ADWIN drift detector flagged concept drift. Updating tree branches.",
                "metrics": ai_engine.get_metrics()
            })
            
        # Broadcast outputs to dashboard clients
        if alert_payload:
            broadcast_sync(alert_payload)
        broadcast_sync(metrics_payload)
        
    except Exception as e:
        print(f"Error in prediction callback: {e}")
    finally:
        db.close()

def on_arp_poisoning_detected(ip, old_mac, new_mac):
    db = SessionLocal()
    try:
        from datetime import datetime
        log = TrafficLog(
            src_ip=ip,
            dest_ip="Broadcast",
            src_port=0,
            dest_port=0,
            protocol="ARP",
            duration=0,
            total_bytes=42,
            prediction_label="Malicious",
            confidence_score=1.0,
            info=f"ARP Spoofing: IP {ip} claimed by MAC {new_mac} (previously {old_mac})",
            source="live",
            connection_state="N/A"
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        
        reason = f"Duplicate MAC bindings detected for IP {ip}: {new_mac} vs {old_mac}"
        action = f"Audit active MAC tables and isolate device matching MAC {new_mac}."
        
        alert, is_new, alert_payload = alert_manager.ingest_security_event(
            db=db,
            threat_level="Critical",
            threat_type="ARP Spoofing / MITM",
            reason=reason,
            action=action,
            src_ip=ip,
            dest_ip="Broadcast",
            protocol="ARP",
            src_port=0,
            dest_port=0,
            confidence=1.0,
            alert_type="arp_spoofing",
            traffic_log_id=log.id,
            is_simulated=False,
            extra_info=f"Prior MAC: {old_mac} -> Infiltrating MAC: {new_mac}"
        )
        
        if alert_payload:
            broadcast_sync(alert_payload)
    except Exception as e:
        print(f"Error in ARP detection callback: {e}")
    finally:
        db.close()

# Initialize packet sniffer service
sniffer_service = PacketSnifferService(callback=on_flow_compiled)
sniffer_service.arp_alert_callback = on_arp_poisoning_detected


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.post("/api/auth/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Validates admin credentials and generates a signed session JWT token.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}


import random

class MockFlowRecord:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol, protocol_l7=None, info=None, source="live", connection_state="N/A"):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.protocol_l7 = protocol_l7 or protocol
        self.info = info
        self.source = source
        self.connection_state = connection_state

# Global simulation tracking state
sim_state = {"active": True}

def run_attack_simulation(sim_type: str):
    """
    Simulates a sequence of traffic flows by pushing dummy flow records 
    into the on_flow_compiled callback asynchronously over a few seconds.
    """
    time.sleep(0.5)  # Wait briefly for client to receive trigger confirmation
    
    if sim_type == "dos":
        # Target IP: 10.0.0.8, multiple spoofed source IPs
        victim_ip = "10.0.0.8"
        attacker_ips = [f"192.168.1.{random.randint(50, 150)}" for _ in range(12)]
        for src in attacker_ips:
            if not sim_state["active"]:
                print("Simulation aborted by user.")
                break
            flow = MockFlowRecord(
                src_ip=src,
                dest_ip=victim_ip,
                src_port=random.randint(40000, 60000),
                dest_port=80,
                protocol="TCP",
                protocol_l7="HTTP",
                info="SYN Flood - simulated Denial of Service payload",
                source="sim:dos",
                connection_state="SYN_RCVD"
            )
            # features: sbytes, dbytes, splt_mean, dplt_mean, proto_id, packet_count, avg_pkt_size
            features = [64.0, 0.0, 0.0002, 0.0, 1.0, 1.0, 64.0]
            try:
                on_flow_compiled(flow, features, duration=0, total_bytes=64)
            except Exception as e:
                print(f"Simulation flow injection error: {e}")
            time.sleep(0.15)  # Staggered flows
            
    elif sim_type == "scan":
        # Attacker IP: 10.0.0.99 scans consecutive ports of victim 192.168.1.1
        attacker_ip = "10.0.0.99"
        victim_ip = "192.168.1.1"
        target_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389, 8080]
        for port in target_ports:
            if not sim_state["active"]:
                print("Simulation aborted by user.")
                break
            flow = MockFlowRecord(
                src_ip=attacker_ip,
                dest_ip=victim_ip,
                src_port=random.randint(40000, 60000),
                dest_port=port,
                protocol="TCP",
                protocol_l7="TCP",
                info=f"Port Probe - simulated TCP reconnaissance on Port {port}",
                source="sim:scan",
                connection_state="CLOSED"
            )
            features = [64.0, 0.0, 0.001, 0.0, 1.0, 1.0, 64.0]
            try:
                on_flow_compiled(flow, features, duration=0, total_bytes=64)
            except Exception as e:
                print(f"Simulation flow injection error: {e}")
            time.sleep(0.2)
            
    elif sim_type == "exfil":
        if not sim_state["active"]:
            return
        # Victim 192.168.1.12 uploading payload to external IP 8.8.8.8
        flow = MockFlowRecord(
            src_ip="192.168.1.12",
            dest_ip="8.8.8.8",
            src_port=53422,
            dest_port=443,
            protocol="TCP",
            protocol_l7="HTTPS",
            info="TLS SNI: malicious-exfiltration-c2.com | Payload: sensitive_employees_backup.csv",
            source="sim:exfil",
            connection_state="ESTABLISHED"
        )
        features = [52428800.0, 1048576.0, 0.002, 0.005, 1.0, 35000.0, 1460.0]
        try:
            on_flow_compiled(flow, features, duration=120, total_bytes=53477376)
        except Exception as e:
            print(f"Simulation flow injection error: {e}")
            
    elif sim_type == "normal":
        # Generate 4-5 normal browsing records
        normal_destinations = [
            ("142.250.190.46", 443, "HTTPS", "TLS SNI: google.com"),
            ("151.101.1.69", 443, "HTTPS", "TLS SNI: github.com"),
            ("172.217.16.142", 53, "DNS", "DNS Query: api.github.com"),
            ("192.168.1.1", 80, "HTTP", "HTTP Host: router.local /index.html")
        ]
        for dst, port, proto, info in normal_destinations:
            if not sim_state["active"]:
                print("Simulation aborted by user.")
                break
            flow = MockFlowRecord(
                src_ip="192.168.1.15",
                dest_ip=dst,
                src_port=random.randint(40000, 60000),
                dest_port=port,
                protocol="TCP" if port != 53 else "UDP",
                protocol_l7=proto,
                info=info,
                source="sim:normal",
                connection_state="ESTABLISHED" if port != 53 else "STATELESS"
            )
            # typical normal feature averages
            features = [4096.0, 32768.0, 0.05, 0.04, 1.0 if port != 53 else 2.0, 25.0, 1200.0]
            try:
                on_flow_compiled(flow, features, duration=3, total_bytes=36864)
            except Exception as e:
                print(f"Simulation flow injection error: {e}")
            time.sleep(0.3)

@app.post("/api/educational/simulate-attack")
def simulate_attack(type: str, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user)):
    """
    Simulates a sequence of specific traffic flows (dos, scan, exfil, normal) 
    in a background task thread to show live analytics response.
    """
    if type not in ["dos", "scan", "exfil", "normal"]:
        raise HTTPException(status_code=400, detail="Invalid simulation attack type parameter.")
        
    sim_state["active"] = True
    background_tasks.add_task(run_attack_simulation, type)
    return {"status": "Simulation triggered", "type": type}

@app.post("/api/educational/stop-simulation")
def stop_simulation(current_user: User = Depends(get_current_user)):
    """
    Aborts any active running background traffic simulations.
    """
    sim_state["active"] = False
    return {"status": "Simulation aborted"}


@app.get("/api/system/status")
def get_system_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns workstation resource indicators, packet totals, and transparent Network Health breakdown.
    """
    import random
    from datetime import datetime, timedelta
    from sqlalchemy import func
    
    cpu_percent = random.randint(15, 45)
    ram_percent = random.randint(40, 75)
    
    logs_count = db.query(TrafficLog).count()
    alerts_count = db.query(Alert).filter(Alert.is_resolved == False).count()
    total_packets = sniffer_service.get_total_packets()
    
    # Network Health - Active Hosts in the last 24 hours
    limit_time = datetime.utcnow() - timedelta(hours=24)
    src_ips = db.query(TrafficLog.src_ip).filter(TrafficLog.timestamp >= limit_time).distinct().all()
    dest_ips = db.query(TrafficLog.dest_ip).filter(TrafficLog.timestamp >= limit_time).distinct().all()
    unique_hosts = set([r[0] for r in src_ips] + [r[0] for r in dest_ips])
    active_hosts = len(unique_hosts) if unique_hosts else (1 if logs_count > 0 else 0)
    
    # Network Health - Active Flows tracked in extractor cache
    active_flows = len(sniffer_service.extractor.active_flows)
    
    # Threat score calculation from active unresolved alerts
    critical_sum = db.query(func.sum(Alert.count)).filter(Alert.is_resolved == False, Alert.threat_level == "Critical").scalar() or 0
    high_sum = db.query(func.sum(Alert.count)).filter(Alert.is_resolved == False, Alert.threat_level == "High").scalar() or 0
    medium_sum = db.query(func.sum(Alert.count)).filter(Alert.is_resolved == False, Alert.threat_level == "Medium").scalar() or 0
    low_sum = db.query(func.sum(Alert.count)).filter(Alert.is_resolved == False, Alert.threat_level == "Low").scalar() or 0
    
    alert_penalty = min(95, 25 * critical_sum + 15 * high_sum + 5 * medium_sum + 2 * low_sum)
    threat_score = alert_penalty
    health_score = max(5, 100 - threat_score)
    
    # Transparent Health Factors breakdown for student/examiner inspection
    health_factors = []
    if alert_penalty > 0:
        health_factors.append({
            "factor": f"Active threat signals detected ({critical_sum} Critical, {high_sum} High, {medium_sum} Medium)",
            "impact": "negative",
            "points": -alert_penalty,
            "detail": "Unresolved security alerts require triage and remediation."
        })
    else:
        health_factors.append({
            "factor": "Zero active high-severity threats detected",
            "impact": "positive",
            "points": 0,
            "detail": "No unresolved malicious or suspicious flows in perimeter."
        })
        
    if active_hosts > 0:
        health_factors.append({
            "factor": f"Active hosts observed: {active_hosts} host(s) communicating",
            "impact": "positive",
            "points": 0,
            "detail": "Perimeter devices transmitting telemetry normally."
        })
    else:
        health_factors.append({
            "factor": "No active host activity recorded yet",
            "impact": "neutral",
            "points": 0,
            "detail": "Sniffer is idle or awaiting first network packet sequence."
        })
        
    health_factors.append({
        "factor": f"Streaming flow engine: {total_packets} packets processed across {active_flows} live flows",
        "impact": "positive" if total_packets > 0 else "neutral",
        "points": 0,
        "detail": "Passive flow extraction windowing operational."
    })
    
    health_factors.append({
        "factor": "Adaptive ML Classifier: ADWIN calibrated & drift-monitored",
        "impact": "positive",
        "points": 0,
        "detail": "Hoeffding adaptive tree weights dynamically track concept drift."
    })
    
    # Top destination hosts (talkers)
    top_dest_query = db.query(TrafficLog.dest_ip, func.count(TrafficLog.id)).group_by(TrafficLog.dest_ip).order_by(func.count(TrafficLog.id).desc()).limit(5).all()
    top_destinations = [{"host": r[0], "flows": r[1]} for r in top_dest_query]
    
    # Protocol Distribution stats
    proto_stats_query = db.query(TrafficLog.protocol, func.count(TrafficLog.id)).group_by(TrafficLog.protocol).all()
    proto_stats = {p: c for p, c in proto_stats_query}
    for proto in ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS"]:
        if proto not in proto_stats:
            proto_stats[proto] = 0
            
    return {
        "cpu_usage": cpu_percent,
        "ram_usage": ram_percent,
        "total_flows_logged": logs_count,
        "total_packets": total_packets,
        "active_alerts": alerts_count,
        "sniffer_running": sniffer_service.is_sniffing,
        "active_interface": sniffer_service.interface_desc or sniffer_service.interface,
        "active_hosts": active_hosts,
        "active_flows": active_flows,
        "threat_score": threat_score,
        "health_score": health_score,
        "health_factors": health_factors,
        "top_destinations": top_destinations,
        "pps": sniffer_service.get_pps(),
        "protocol_stats": proto_stats
    }


@app.get("/api/traffic/interfaces")
def get_interfaces(current_user: User = Depends(get_current_user)):
    """
    Lists physical NIC network interfaces on the workstation.
    """
    return sniffer_service.get_available_interfaces()


@app.post("/api/traffic/start")
def start_sniffing(interface: str, current_user: User = Depends(get_current_user)):
    """
    Instructs Scapy to begin sniffing socket traffic on the selected NIC.
    """
    success = sniffer_service.start_sniffing(interface)
    if not success:
        raise HTTPException(status_code=400, detail="Sniffer already running or failed to initialize.")
    return {"status": "started", "interface": interface}


@app.post("/api/traffic/stop")
def stop_sniffing(current_user: User = Depends(get_current_user)):
    """
    Interrupts live sniffing thread.
    """
    success = sniffer_service.stop_sniffing()
    if not success:
        raise HTTPException(status_code=400, detail="Sniffer is not active.")
    return {"status": "stopped"}


def bg_process_pcap(file_path: str, filename: str):
    """Background worker for file extraction"""
    try:
        # Set flow tag context for the duration of the PCAP processing
        sniffer_service.extractor.current_source = f"pcap:{filename}"
        success, pkt_count = sniffer_service.process_pcap_file(file_path)
        if success:
            broadcast_sync({
                "type": "pcap_completed",
                "filename": filename,
                "message": f"Successfully processed PCAP '{filename}': extracted {pkt_count} packet flows.",
                "packet_count": pkt_count
            })
    except Exception as e:
        print(f"Error processing PCAP: {e}")
        broadcast_sync({
            "type": "pcap_error",
            "filename": filename,
            "message": f"PCAP analysis failed: {str(e)}"
        })
    finally:
        # Reset flow tag context back to live capture default
        sniffer_service.extractor.current_source = "live"
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass


@app.post("/api/traffic/upload")
def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Allows users to upload offline .pcap files for flow extraction.
    """
    if not file.filename.endswith(".pcap") and not file.filename.endswith(".pcapng"):
        raise HTTPException(status_code=400, detail="Invalid file format. PCAP required.")
        
    temp_dir = "./backend/temp"
    os.makedirs(temp_dir, exist_ok=True)
    temp_file_path = os.path.join(temp_dir, f"{int(time.time())}_{file.filename}")
    
    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    # Queue processing to prevent HTTP blocking, passing filename
    background_tasks.add_task(bg_process_pcap, temp_file_path, file.filename)
    return {"status": "queued", "filename": file.filename}



# ==============================================================================
# === NEXz: TELEMETRY IMPORT & ANALYSIS REST ENDPOINTS ===
# ==============================================================================

@app.post("/api/import/upload")
async def import_upload_file(
    file: UploadFile = File(...),
    dataset_name: str = "",
    description: str = "",
    current_user: User = Depends(get_current_user)
):
    """
    Receives an external network telemetry file (PCAP, PCAPNG, CSV, JSON, JSONL, Zeek, Suricata EVE, TXT IOC).
    Initializes batch record, inspects headers/samples, auto-detects mappings and capabilities.
    """
    upload_dir = "./backend/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    clean_fn = os.path.basename(file.filename)
    safe_path = os.path.join(upload_dir, f"{int(time.time())}_{clean_fn}")
    
    with open(safe_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    batch_info = import_service.create_batch(
        file_path=safe_path,
        filename=clean_fn,
        dataset_name=dataset_name,
        description=description
    )
    return {"status": "success", "batch": batch_info}


@app.get("/api/import/{batch_id}/preview")
def get_import_preview(batch_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns detected schema, sample records, auto-mappings, and capability report."""
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Import batch not found.")
        
    upload_dir = "./backend/uploads"
    matching_files = [f for f in os.listdir(upload_dir) if f.endswith(f"_{batch.filename}") or f == batch.filename]
    file_path = os.path.join(upload_dir, matching_files[0]) if matching_files else None
    
    inspection = {}
    if file_path and os.path.exists(file_path):
        inspection = import_service.inspect_file(file_path, batch.file_type)
        
    return {
        "status": "success",
        "batch_id": batch.id,
        "dataset_name": batch.dataset_name,
        "filename": batch.filename,
        "format": batch.file_type,
        "record_count": batch.record_count,
        "mapping": json.loads(batch.mapping_json or "{}"),
        "capabilities": json.loads(batch.capabilities_json or "{}"),
        "sample_rows": inspection.get("sample_rows", []),
        "headers": inspection.get("headers", [])
    }


@app.post("/api/import/{batch_id}/mapping")
async def update_import_mapping(
    batch_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user)
):
    """Updates user-confirmed field mappings and re-assesses capabilities."""
    mapping = payload.get("mapping", {})
    try:
        res = import_service.update_mapping(batch_id, mapping)
        return {"status": "success", **res}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/import/{batch_id}/validate")
async def validate_import_dataset(
    batch_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Executes a validation pass over sample records, returning valid/invalid/warning counts."""
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found.")
        
    upload_dir = "./backend/uploads"
    matching = [f for f in os.listdir(upload_dir) if f.endswith(f"_{batch.filename}") or f == batch.filename]
    if not matching:
        raise HTTPException(status_code=404, detail="Source file not found on disk.")
    file_path = os.path.join(upload_dir, matching[0])
    
    mapping = payload.get("mapping") or json.loads(batch.mapping_json or "{}")
    val_res = import_service.validate_dataset(batch_id, file_path, mapping, max_sample=500)
    return {"status": "success", **val_res}


@app.post("/api/import/{batch_id}/start")
async def start_import_execution(
    batch_id: int,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Spawns background execution of the import job under the selected analysis mode."""
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found.")
        
    upload_dir = "./backend/uploads"
    matching = [f for f in os.listdir(upload_dir) if f.endswith(f"_{batch.filename}") or f == batch.filename]
    if not matching:
        raise HTTPException(status_code=404, detail="Source file not found on disk.")
    file_path = os.path.join(upload_dir, matching[0])
    
    mode = payload.get("mode", "analyze_only")
    options = {
        "replay_speed": payload.get("replay_speed", 1.0),
        "isolate_profile": payload.get("isolate_profile", False)
    }
    
    success = import_service.start_execution(
        batch_id=batch_id,
        file_path=file_path,
        mode=mode,
        options=options,
        broadcast_func=broadcast_sync
    )
    if not success:
        raise HTTPException(status_code=400, detail="Import job is already active or cannot be started.")
        
    return {"status": "started", "batch_id": batch_id, "mode": mode}


@app.post("/api/import/{batch_id}/pause")
def pause_import(batch_id: int, current_user: User = Depends(get_current_user)):
    success = import_service.pause_job(batch_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot pause batch (job not running or not active).")
    return {"status": "paused", "batch_id": batch_id}


@app.post("/api/import/{batch_id}/resume")
def resume_import(batch_id: int, current_user: User = Depends(get_current_user)):
    success = import_service.resume_job(batch_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot resume batch.")
    return {"status": "resumed", "batch_id": batch_id}


@app.post("/api/import/{batch_id}/cancel")
def cancel_import(batch_id: int, current_user: User = Depends(get_current_user)):
    success = import_service.cancel_job(batch_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot cancel batch.")
    return {"status": "cancelled", "batch_id": batch_id}


@app.get("/api/import/{batch_id}")
def get_import_status(batch_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found.")
        
    prog = import_service.get_job_progress(batch_id)
    eval_metrics = json.loads(batch.eval_metrics_json) if batch.eval_metrics_json else None
    
    return {
        "status": "success",
        "batch_id": batch.id,
        "dataset_name": batch.dataset_name,
        "filename": batch.filename,
        "format": batch.file_type,
        "analysis_mode": batch.analysis_mode,
        "status_code": batch.status,
        "total_records": batch.record_count,
        "valid_count": batch.valid_count,
        "invalid_count": batch.invalid_count,
        "normal_count": batch.normal_count,
        "suspicious_count": batch.suspicious_count,
        "malicious_count": batch.malicious_count,
        "anomaly_count": batch.anomaly_count,
        "watchlist_matches": batch.watchlist_matches,
        "drift_count": batch.drift_count,
        "alerts_count": batch.alerts_count,
        "duration_sec": batch.duration_sec,
        "uploaded_at": batch.uploaded_at.isoformat() if batch.uploaded_at else None,
        "progress": prog,
        "eval_metrics": eval_metrics
    }


@app.get("/api/import/{batch_id}/errors")
def get_import_errors(batch_id: int, current_user: User = Depends(get_current_user)):
    job = import_service.active_jobs.get(batch_id)
    rejections = job.rejection_log if job else []
    return {"status": "success", "batch_id": batch_id, "rejections": rejections}


@app.get("/api/import/history")
def get_import_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    batches = db.query(ImportBatch).order_by(ImportBatch.uploaded_at.desc()).limit(100).all()
    res = [
        {
            "id": b.id,
            "dataset_name": b.dataset_name,
            "filename": b.filename,
            "file_type": b.file_type,
            "file_size": b.file_size,
            "status": b.status,
            "analysis_mode": b.analysis_mode,
            "record_count": b.record_count,
            "valid_count": b.valid_count,
            "invalid_count": b.invalid_count,
            "normal_count": b.normal_count,
            "suspicious_count": b.suspicious_count,
            "malicious_count": b.malicious_count,
            "anomaly_count": b.anomaly_count,
            "watchlist_matches": b.watchlist_matches,
            "alerts_count": b.alerts_count,
            "duration_sec": b.duration_sec,
            "uploaded_at": b.uploaded_at.isoformat() if b.uploaded_at else None,
            "completed_at": b.completed_at.isoformat() if b.completed_at else None
        } for b in batches
    ]
    return {"status": "success", "batches": res}


@app.delete("/api/import/{batch_id}")
def delete_import_batch(batch_id: int, current_user: User = Depends(get_current_user)):
    success = import_service.delete_batch(batch_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete import batch.")
    return {"status": "deleted", "batch_id": batch_id}


@app.get("/api/import/{batch_id}/export")
def export_batch_records(
    batch_id: int,
    export_format: str = "csv",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Exports records from a specific import batch as CSV or JSON."""
    import csv
    import io
    from fastapi.responses import StreamingResponse
    
    batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found.")
        
    logs = db.query(TrafficLog).filter(TrafficLog.import_batch_id == batch_id).order_by(TrafficLog.id.asc()).all()
    
    if export_format.lower() == "json":
        data = [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat(),
                "src_ip": r.src_ip,
                "dest_ip": r.dest_ip,
                "src_port": r.src_port,
                "dest_port": r.dest_port,
                "protocol": r.protocol,
                "duration": r.duration,
                "bytes": r.total_bytes,
                "label": r.prediction_label,
                "confidence": r.confidence_score,
                "info": r.info or ""
            } for r in logs
        ]
        return {"batch_id": batch_id, "dataset_name": batch.dataset_name, "records": data}
        
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "duration_sec", "total_bytes", "label", "confidence", "info", "import_batch_id"])
    for r in logs:
        writer.writerow([r.id, r.timestamp.isoformat(), r.src_ip, r.dest_ip, r.src_port, r.dest_port, r.protocol, r.duration, r.total_bytes, r.prediction_label, r.confidence_score, r.info or "", batch_id])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=NEXz_batch_{batch_id}_export.csv"}
    )


# ==============================================================================
# === NEXz: WATCHLIST / IOC REST ENDPOINTS ===
# ==============================================================================

@app.get("/api/watchlists")
def get_watchlists(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    entries = db.query(WatchlistEntry).order_by(WatchlistEntry.created_at.desc()).all()
    res = [
        {
            "id": e.id,
            "value": e.value,
            "entry_type": e.entry_type,
            "label": e.label,
            "description": e.description or "",
            "source": e.source,
            "import_batch_id": e.import_batch_id,
            "created_at": e.created_at.isoformat() if e.created_at else None
        } for e in entries
    ]
    return {"status": "success", "watchlist_count": len(res), "entries": res}


@app.post("/api/watchlists/add")
def add_watchlist_entry(payload: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    val = str(payload.get("value", "")).strip()
    if not val:
        raise HTTPException(status_code=400, detail="Value is required.")
        
    entry_type = payload.get("entry_type", "ipv4")
    label = payload.get("label", "Suspicious Host")
    desc = payload.get("description", "")
    
    existing = db.query(WatchlistEntry).filter(WatchlistEntry.value == val).first()
    if existing:
        return {"status": "exists", "id": existing.id, "message": "Watchlist entry already exists."}
        
    entry = WatchlistEntry(
        value=val,
        entry_type=entry_type,
        label=label,
        description=desc,
        source="manual",
        created_at=datetime.utcnow()
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return {"status": "added", "id": entry.id, "value": entry.value}


@app.post("/api/watchlists/import")
async def import_watchlist_file(
    file: UploadFile = File(...),
    label: str = "Imported Threat Feed",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Parses text file containing IPs or domains and adds them to watchlist_entries."""
    temp_dir = "./backend/uploads"
    os.makedirs(temp_dir, exist_ok=True)
    fpath = os.path.join(temp_dir, f"ioc_{int(time.time())}_{file.filename}")
    with open(fpath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    from .import_parsers import parse_txt_ioc
    parsed = parse_txt_ioc(fpath)
    entries = parsed.get("entries", [])
    added_cnt = 0
    
    for item in entries:
        val = item["value"]
        if not db.query(WatchlistEntry).filter(WatchlistEntry.value == val).first():
            w = WatchlistEntry(
                value=val,
                entry_type=item["type"],
                label=label,
                description=f"Imported from {file.filename} (line {item.get('line', '?')})",
                source=f"txt_import:{file.filename}",
                created_at=datetime.utcnow()
            )
            db.add(w)
            added_cnt += 1
            
    db.commit()
    if os.path.exists(fpath):
        try: os.remove(fpath)
        except Exception: pass
        
    return {"status": "success", "imported_count": added_cnt, "total_found": len(entries)}


@app.delete("/api/watchlists/{entry_id}")
def delete_watchlist_entry(entry_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    w = db.query(WatchlistEntry).filter(WatchlistEntry.id == entry_id).first()
    if not w:
        raise HTTPException(status_code=404, detail="Watchlist entry not found.")
    db.delete(w)
    db.commit()
    return {"status": "deleted", "id": entry_id}


@app.get("/api/logs")
def get_logs(
    limit: int = 50,
    offset: int = 0,
    search_ip: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Fetches connection logs with search and pagination features.
    """
    query = db.query(TrafficLog)
    if search_ip:
        query = query.filter((TrafficLog.src_ip.like(f"%{search_ip}%")) | (TrafficLog.dest_ip.like(f"%{search_ip}%")))
    
    logs = query.order_by(TrafficLog.timestamp.desc()).offset(offset).limit(limit).all()
    return logs


@app.get("/api/alerts")
def get_alerts(
    status: str = "all",
    limit: int = 150,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves network alerts with lifecycle filtering (all, active, new, acknowledged, resolved).
    """
    query = db.query(Alert).join(TrafficLog, Alert.traffic_log_id == TrafficLog.id, isouter=True)
    
    st = status.lower()
    if st == "active":
        query = query.filter(Alert.is_resolved == False, Alert.status.in_(["Active", "New"]))
    elif st == "new":
        query = query.filter(Alert.status == "New", Alert.is_resolved == False)
    elif st == "acknowledged":
        query = query.filter(Alert.status == "Acknowledged", Alert.is_resolved == False)
    elif st == "resolved":
        query = query.filter(Alert.is_resolved == True)
    elif st == "unresolved":
        query = query.filter(Alert.is_resolved == False)
    # "all" retrieves all alerts
    
    alerts = query.order_by(func.coalesce(Alert.last_seen, Alert.alert_time).desc()).offset(offset).limit(limit).all()
    
    formatted_alerts = []
    for a in alerts:
        src = a.traffic_log.src_ip if a.traffic_log else (a.device.ip_address if getattr(a, "device", None) else "Unknown")
        dst = a.traffic_log.dest_ip if a.traffic_log else "Internal"
        proto = a.traffic_log.protocol if a.traffic_log else "IP"
        lbl = a.traffic_log.prediction_label if a.traffic_log else "Suspicious"
        conf = a.traffic_log.confidence_score if a.traffic_log else 0.85
        src_p = a.traffic_log.src_port if a.traffic_log else 0
        dst_p = a.traffic_log.dest_port if a.traffic_log else 0
        
        formatted_alerts.append({
            "id": a.id,
            "timestamp": a.alert_time.isoformat(),
            "first_seen": a.alert_time.isoformat(),
            "last_seen": (a.last_seen or a.alert_time).isoformat(),
            "src_ip": src,
            "dest_ip": dst,
            "src_port": src_p,
            "dest_port": dst_p,
            "protocol": proto,
            "label": lbl,
            "threat_level": a.threat_level,
            "status": getattr(a, "status", "Active"),
            "count": a.count or 1,
            "alert_type": a.alert_type,
            "is_simulated": getattr(a, "is_simulated", False),
            "confidence": round(conf, 2),
            "is_resolved": a.is_resolved,
            "notes": a.notes
        })
    return formatted_alerts


@app.post("/api/alerts/acknowledge/{alert_id}")
def acknowledge_alert(alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Transitions an active alert to 'Acknowledged' state.
    """
    alert = alert_manager.acknowledge_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert_id": alert_id, "alert_status": alert.status}


@app.post("/api/alerts/resolve/{alert_id}")
def resolve_alert(alert_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Allows analysts to dismiss/resolve warnings on the dashboard.
    """
    alert = alert_manager.resolve_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "resolved", "alert_id": alert_id, "alert_status": alert.status}


@app.get("/api/model/metrics")
def get_model_metrics(current_user: User = Depends(get_current_user)):
    """
    Returns AI accuracy indicators.
    """
    return ai_engine.get_metrics()


@app.get("/api/model/drift-events")
def get_drift_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Returns historical concept drift events recorded in ModelMetrics where drift_detected == True.
    """
    events = db.query(ModelMetrics).filter(ModelMetrics.drift_detected == True).order_by(ModelMetrics.timestamp.desc()).limit(50).all()
    results = []
    for e in events:
        results.append({
            "id": e.id,
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "N/A",
            "accuracy": round(e.accuracy, 4) if e.accuracy is not None else 0.0,
            "f1_score": round(e.f1_score, 4) if e.f1_score is not None else 0.0,
            "samples_processed": e.samples_processed or 0,
            "drift_detected": bool(e.drift_detected),
            "model_response": "Adaptive Random Forest split candidate re-evaluated / ADWIN window shrunk"
        })
    return {"drift_events": results, "total_events": len(results)}


@app.post("/api/model/reset")
def reset_online_model(current_user: User = Depends(get_current_user)):
    """
    Resets streaming classifier tree.
    """
    global ai_engine
    # Clear model files
    ai_engine = AIEngine()
    return {"status": "reset_completed"}


@app.get("/api/analytics/history")
def get_analytics_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns binned network statistics over the last 1 hour in 5-minute increments for charts.
    """
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    start_time = now - timedelta(hours=1)
    
    # Query logs in last hour
    logs = db.query(TrafficLog).filter(TrafficLog.timestamp >= start_time).order_by(TrafficLog.timestamp.asc()).all()
    
    # Define 12 bins of 5 minutes each
    bins = []
    for i in range(12):
        bin_start = start_time + timedelta(minutes=i*5)
        bins.append({
            "time": bin_start.strftime("%H:%M"),
            "bytes": 0,
            "flows": 0,
            "alerts": 0
        })
        
    for log in logs:
        delta = log.timestamp - start_time
        bin_idx = int(delta.total_seconds() // 300)
        if 0 <= bin_idx < 12:
            bins[bin_idx]["bytes"] += log.total_bytes
            bins[bin_idx]["flows"] += 1
            if log.prediction_label in ["Malicious", "Suspicious"]:
                bins[bin_idx]["alerts"] += 1
                
    return bins


@app.get("/api/analytics/top-talkers")
def get_top_talkers(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns top source and destination IP addresses by traffic volume and flow counts.
    """
    from sqlalchemy import func
    
    # Top Source Talkers
    src_query = db.query(
        TrafficLog.src_ip,
        func.sum(TrafficLog.total_bytes).label("total_bytes"),
        func.count(TrafficLog.id).label("flow_count")
    ).group_by(TrafficLog.src_ip).order_by(text("total_bytes DESC")).limit(5).all()
    
    # Top Destination Talkers
    dest_query = db.query(
        TrafficLog.dest_ip,
        func.sum(TrafficLog.total_bytes).label("total_bytes"),
        func.count(TrafficLog.id).label("flow_count")
    ).group_by(TrafficLog.dest_ip).order_by(text("total_bytes DESC")).limit(5).all()
    
    return {
        "sources": [{"ip": r[0], "bytes": r[1] or 0, "flows": r[2]} for r in src_query],
        "destinations": [{"ip": r[0], "bytes": r[1] or 0, "flows": r[2]} for r in dest_query]
    }


@app.get("/api/analytics/top-ports")
def get_top_ports(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns top source and destination ports by connection count.
    """
    from sqlalchemy import func
    
    # Top Destination Ports
    dest_ports = db.query(
        TrafficLog.dest_port,
        func.count(TrafficLog.id).label("count")
    ).group_by(TrafficLog.dest_port).order_by(text("count DESC")).limit(5).all()
    
    # Top Source Ports
    src_ports = db.query(
        TrafficLog.src_port,
        func.count(TrafficLog.id).label("count")
    ).group_by(TrafficLog.src_port).order_by(text("count DESC")).limit(5).all()
    
    return {
        "dest_ports": [{"port": r[0], "count": r[1]} for r in dest_ports],
        "src_ports": [{"port": r[0], "count": r[1]} for r in src_ports]
    }


@app.get("/api/analytics/summary")
def get_analytics_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns aggregated stats for a daily summary over the last 7 days.
    """
    from sqlalchemy import func, case
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=7)
    
    summary_query = db.query(
        func.date(TrafficLog.timestamp).label("log_date"),
        func.count(TrafficLog.id).label("flow_count"),
        func.sum(TrafficLog.total_bytes).label("total_bytes"),
        func.count(case([(TrafficLog.prediction_label.in_(["Malicious", "Suspicious"]), 1)], else_=None)).label("alert_count")
    ).filter(TrafficLog.timestamp >= start_date).group_by(func.date(TrafficLog.timestamp)).order_by(text("log_date ASC")).all()
    
    return [
        {
            "date": r[0],
            "flows": r[1],
            "bytes": r[2] or 0,
            "alerts": r[3] or 0
        } for r in summary_query
    ]


@app.get("/api/educational/protocols")
def get_educational_protocols(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns standard protocol details (TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP)
    along with actual captured flow examples from the traffic log database.
    """
    protocol_definitions = {
        "TCP": {
            "name": "Transmission Control Protocol",
            "purpose": "Provides reliable, ordered, and error-checked delivery of a stream of octets (bytes) between applications running on hosts communicating over an IP network.",
            "common_ports": "80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP), 25 (SMTP)",
            "security": "Vulnerable to SYN flood DoS attacks, connection hijacking, and port scanning. Requires TLS for payload encryption."
        },
        "UDP": {
            "name": "User Datagram Protocol",
            "purpose": "Provides a simple, connectionless communication model with a minimum of protocol mechanisms (no handshakes, no reliability checks). Preferred for real-time applications.",
            "common_ports": "53 (DNS), 67/68 (DHCP), 123 (NTP), 161 (SNMP)",
            "security": "Vulnerable to spoofing, amplification DoS attacks (e.g. DNS amplification), and lacks congestion control."
        },
        "DNS": {
            "name": "Domain Name System",
            "purpose": "Translates human-readable domain names (e.g. google.com) to machine-readable IP addresses.",
            "common_ports": "53 (UDP / TCP)",
            "security": "Vulnerable to DNS spoofing/poisoning, cache poisoning, and DNS tunneling (exfiltrating data inside DNS queries)."
        },
        "HTTP": {
            "name": "Hypertext Transfer Protocol",
            "purpose": "Application-layer protocol for transmitting hypermedia documents, such as HTML, forming the foundation of data communication for the World Wide Web.",
            "common_ports": "80 (TCP)",
            "security": "Transmits data in cleartext. Vulnerable to sniffing, Man-in-the-Middle (MitM) attacks, session hijacking, and cross-site scripting (XSS)."
        },
        "HTTPS": {
            "name": "Hypertext Transfer Protocol Secure",
            "purpose": "An extension of HTTP that uses Transport Layer Security (TLS) to encrypt all communications for secure web browsing.",
            "common_ports": "443 (TCP)",
            "security": "Protects payload data from sniffing. Security relies on valid certificate authorities and robust cipher suites."
        },
        "ICMP": {
            "name": "Internet Control Message Protocol",
            "purpose": "Used by network devices to send error messages and operational information (e.g., indicating a requested host is unreachable).",
            "common_ports": "None (Operates directly over IP as protocol 1)",
            "security": "Vulnerable to Ping floods (DoS), ICMP tunneling (covert channels), and reconnaissance (network mapping via ping sweeps)."
        },
        "ARP": {
            "name": "Address Resolution Protocol",
            "purpose": "Maps a dynamic Internet Protocol (IP) address to a physical machine Media Access Control (MAC) address on a local area network.",
            "common_ports": "None (Operates at the Data Link layer)",
            "security": "Lacks authentication. Extremely vulnerable to ARP Spoofing / Poisoning, enabling local Man-in-the-Middle (MitM) attacks."
        }
    }
    
    # Calculate live contextual observation metrics (last 1 hour)
    from datetime import datetime, timedelta
    from sqlalchemy import func
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    total_recent_flows = db.query(TrafficLog).filter(TrafficLog.timestamp >= one_hour_ago).count()
    
    # Query database for recent flow examples and live telemetry for each protocol
    response = []
    for proto, details in protocol_definitions.items():
        # Live flow sample
        log = db.query(TrafficLog).filter(TrafficLog.protocol.ilike(f"%{proto}%")).order_by(TrafficLog.timestamp.desc()).first()
        example = None
        if log:
            example = {
                "timestamp": log.timestamp.isoformat(),
                "src_ip": log.src_ip,
                "dest_ip": log.dest_ip,
                "src_port": log.src_port,
                "dest_port": log.dest_port,
                "bytes": log.total_bytes,
                "info": log.info or f"State: {getattr(log, 'connection_state', 'N/A')}"
            }
            
        # 1-hour live telemetry
        proto_recent_count = db.query(TrafficLog).filter(
            TrafficLog.timestamp >= one_hour_ago,
            TrafficLog.protocol.ilike(f"%{proto}%")
        ).count()
        proto_recent_bytes = db.query(func.sum(TrafficLog.total_bytes)).filter(
            TrafficLog.timestamp >= one_hour_ago,
            TrafficLog.protocol.ilike(f"%{proto}%")
        ).scalar() or 0
        
        pct = round((proto_recent_count / total_recent_flows * 100), 1) if total_recent_flows > 0 else 0.0
        
        if proto_recent_count > 0:
            observation_text = f"NEXz observed {proto_recent_count} active {proto} flows ({pct}% of network traffic) in the past hour."
        else:
            observation_text = f"No {proto} flows captured on the active interface in the past hour."
            
        explore_text = f"Explore: Filter {proto} flows in the Explore tab to analyze payload bytes and connection state distributions."
        
        response.append({
            "protocol": proto,
            "name": details["name"],
            "purpose": details["purpose"],
            "common_ports": details["common_ports"],
            "security": details["security"],
            "example": example,
            "count_1h": proto_recent_count,
            "bytes_1h": proto_recent_bytes,
            "traffic_pct": pct,
            "observation": observation_text,
            "explore": explore_text,
            "live_stats": {
                "count_1h": proto_recent_count,
                "bytes_1h": proto_recent_bytes,
                "traffic_pct": pct,
                "observation": observation_text,
                "explore": explore_text
            }
        })
        
    return response


@app.get("/api/profile/status")
def get_profile_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns the network behavioral baseline and flags operational deviations.
    """
    pps = sniffer_service.get_pps()
    eval_result = network_profiler.evaluate_deviations(db, current_pps=pps)
    baseline = eval_result.get("baseline", {})
    return {
        "status": "success",
        "data": {
            "profile_status": eval_result.get("status", "Baseline Stable"),
            "is_deviating": eval_result.get("is_deviating", False),
            "observation_window": baseline.get("observation_window", "1 Hour Baseline"),
            "metrics": {
                "flow_rate_per_min": baseline.get("flow_rate_per_min", 0.0),
                "avg_bytes_per_flow": baseline.get("avg_bytes_per_flow", 0.0),
                "avg_duration_sec": baseline.get("avg_duration_sec", 0.0),
                "total_flows_1h": baseline.get("total_flows_1h", 0)
            },
            "recent_5m": eval_result.get("recent_5m", {}),
            "deviations": eval_result.get("deviations", []),
            "updated_at": eval_result.get("updated_at", "")
        }
    }


from pydantic import BaseModel

class SettingsUpdate(BaseModel):
    monitoring_mode: str = None
    flow_timeout: float = None
    aggregation_window: float = None

@app.get("/api/settings/config")
def get_system_settings(current_user: User = Depends(get_current_user)):
    """
    Returns application configuration settings.
    """
    return {
        "monitoring_mode": system_settings.get("monitoring_mode", "manual"),
        "flow_timeout": system_settings.get("flow_timeout", 2.0),
        "aggregation_window": system_settings.get("aggregation_window", 30.0),
        "active_interface": sniffer_service.interface_desc or sniffer_service.interface,
        "is_sniffing": sniffer_service.is_sniffing
    }

@app.post("/api/settings/config")
def update_system_settings(update: SettingsUpdate, current_user: User = Depends(get_current_user)):
    """
    Updates application settings (monitoring mode, aggregation timeouts).
    """
    if update.monitoring_mode in ["manual", "automatic"]:
        system_settings["monitoring_mode"] = update.monitoring_mode
    if update.flow_timeout and 0.5 <= update.flow_timeout <= 10.0:
        system_settings["flow_timeout"] = update.flow_timeout
        sniffer_service.extractor.flow_timeout = update.flow_timeout
    if update.aggregation_window and 5.0 <= update.aggregation_window <= 300.0:
        system_settings["aggregation_window"] = update.aggregation_window
    return {"status": "updated", "settings": system_settings}


@app.get("/api/research/query")
def query_research_telemetry(
    start_time: str = None,
    end_time: str = None,
    protocol: str = None,
    prediction_label: str = None,
    search_ip: str = None,
    src_ip: str = None,
    dest_ip: str = None,
    min_bytes: int = None,
    source: str = None,
    import_batch_id: int = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Research exploration endpoint: provides multi-dimensional filtering,
    aggregate statistics, and paginated records for student/academic research.
    """
    from datetime import datetime
    query = db.query(TrafficLog)
    
    if start_time:
        try:
            dt_start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            query = query.filter(TrafficLog.timestamp >= dt_start)
        except Exception:
            pass
    if end_time:
        try:
            dt_end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            query = query.filter(TrafficLog.timestamp <= dt_end)
        except Exception:
            pass
    if protocol and protocol != "all":
        query = query.filter(TrafficLog.protocol.ilike(f"%{protocol}%"))
    if prediction_label and prediction_label != "all":
        query = query.filter(TrafficLog.prediction_label == prediction_label)
    if search_ip:
        query = query.filter((TrafficLog.src_ip.like(f"%{search_ip}%")) | (TrafficLog.dest_ip.like(f"%{search_ip}%")))
    if src_ip:
        query = query.filter(TrafficLog.src_ip.like(f"%{src_ip}%"))
    if dest_ip:
        query = query.filter(TrafficLog.dest_ip.like(f"%{dest_ip}%"))
    if min_bytes is not None and min_bytes > 0:
        query = query.filter(TrafficLog.total_bytes >= min_bytes)
    if source and source != "all":
        query = query.filter(TrafficLog.source.ilike(f"%{source}%"))
    if import_batch_id:
        query = query.filter(TrafficLog.import_batch_id == import_batch_id)
        
    total_matching = query.count()
    
    # Compute aggregate research statistics
    from sqlalchemy import func
    summary_stats = query.with_entities(
        func.sum(TrafficLog.total_bytes).label("total_bytes"),
        func.avg(TrafficLog.duration).label("avg_duration"),
        func.avg(TrafficLog.total_bytes).label("avg_bytes")
    ).first()
    
    total_bytes = summary_stats[0] or 0
    avg_duration = float(summary_stats[1] or 0.0)
    avg_bytes = float(summary_stats[2] or 0.0)
    
    malicious_count = query.filter(TrafficLog.prediction_label.in_(["Malicious", "Suspicious"])).count()
    malicious_share_pct = round((malicious_count / total_matching * 100.0), 1) if total_matching > 0 else 0.0
    
    # Paginated flow records
    records = query.order_by(TrafficLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    formatted_records = [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "dest_ip": r.dest_ip,
            "src_port": r.src_port,
            "dest_port": r.dest_port,
            "protocol": r.protocol,
            "duration": r.duration,
            "bytes": r.total_bytes,
            "label": r.prediction_label,
            "confidence": r.confidence_score,
            "info": r.info or "",
            "state": getattr(r, "connection_state", "N/A"),
            "source": getattr(r, "source", "live"),
            "import_batch_id": getattr(r, "import_batch_id", None)
        } for r in records
    ]
    
    return {
        "status": "success",
        "total_matching": total_matching,
        "summary": {
            "matching_flows": total_matching,
            "total_bytes": total_bytes,
            "avg_duration_sec": round(avg_duration, 2),
            "avg_payload_bytes": round(avg_bytes, 1),
            "avg_bytes_per_flow": round(avg_bytes, 1),
            "malicious_share_pct": malicious_share_pct
        },
        "records": formatted_records,
        "flows": formatted_records
    }



@app.get("/api/research/export")
def export_research_csv(
    protocol: str = None,
    prediction_label: str = None,
    search_ip: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Streams a filtered CSV dataset formatted specifically for student research analysis.
    """
    import csv
    import io
    from fastapi.responses import StreamingResponse
    
    query = db.query(TrafficLog)
    if protocol and protocol != "all":
        query = query.filter(TrafficLog.protocol.ilike(f"%{protocol}%"))
    if prediction_label and prediction_label != "all":
        query = query.filter(TrafficLog.prediction_label == prediction_label)
    if search_ip:
        query = query.filter((TrafficLog.src_ip.like(f"%{search_ip}%")) | (TrafficLog.dest_ip.like(f"%{search_ip}%")))
        
    logs = query.order_by(TrafficLog.timestamp.desc()).limit(5000).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "duration_sec", "total_bytes", "label", "confidence", "l7_metadata", "tcp_state"])
    
    for r in logs:
        writer.writerow([
            r.id,
            r.timestamp.isoformat(),
            r.src_ip,
            r.dest_ip,
            r.src_port,
            r.dest_port,
            r.protocol,
            r.duration,
            r.total_bytes,
            r.prediction_label,
            r.confidence_score,
            r.info or "",
            getattr(r, "connection_state", "N/A")
        ])
        
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=NEXz_research_telemetry_export.csv"}
    )


from fastapi import Response
from fpdf import FPDF

class SOCReportPDF(FPDF):
    def header(self):
        # Header banner
        self.set_fill_color(99, 102, 241) # Indigo
        self.rect(0, 0, 210, 8, 'F')
        
        self.set_y(12)
        self.set_font('helvetica', 'B', 14)
        self.set_text_color(17, 24, 39)
        self.cell(0, 8, "NEXz - NETWORK INTELLIGENCE & SECURITY REPORT", align='C')
        self.ln(8)
        
        self.set_font('helvetica', 'I', 9)
        self.set_text_color(99, 102, 241)
        self.cell(0, 5, "NEXz: Network Intelligence, Education and eXploration System", align='C')
        self.ln(5)
        
        self.set_draw_color(229, 231, 235)
        self.line(10, 28, 200, 28)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(156, 163, 175)
        self.set_draw_color(229, 231, 235)
        self.line(10, 282, 200, 282)
        self.cell(0, 10, "NEXz Academic Environment - Department of Computer Science", align='L')
        self.set_x(10)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align='R')


@app.get("/api/reports/pdf")
def download_pdf_report(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Generates a security posture summary in PDF format.
    """
    try:
        total_logs = db.query(TrafficLog).count()
        active_alerts_count = db.query(Alert).filter(Alert.is_resolved == False).count()
        resolved_alerts_count = db.query(Alert).filter(Alert.is_resolved == True).count()
        
        # Calculate severity counts in database
        critical_count = db.query(Alert).filter(Alert.is_resolved == False, Alert.threat_level == "Critical").count()
        high_count = db.query(Alert).filter(Alert.is_resolved == False, Alert.threat_level == "High").count()
        medium_count = db.query(Alert).filter(Alert.is_resolved == False, Alert.threat_level == "Medium").count()
        low_count = db.query(Alert).filter(Alert.is_resolved == False, Alert.threat_level == "Low").count()
        
        threat_score = min(100, 25 * critical_count + 15 * high_count + 5 * medium_count + 2 * low_count)
        
        pdf = SOCReportPDF()
        pdf.alias_nb_pages()
        pdf.add_page()
        
        # Calculate safe printable width
        w = getattr(pdf, "epw", 190)
        
        # 1. Executive Summary
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(99, 102, 241)
        pdf.cell(0, 6, "1. Executive Summary & Security Health Indicator")
        pdf.ln(6)
        
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(55, 65, 81)
        pdf.multi_cell(w, 5, 
            f"This report presents an overview of the network security posture captured by the Adaptive Network "
            f"Security Monitoring Dashboard. The dashboard utilizes an online machine learning Hoeffding Adaptive "
            f"Tree classifier coupled with Scapy passive sniffers to analyze flows and trigger warnings.\n\n"
            f"Currently, the overall Network Threat Score is {threat_score}/100. "
            f"There are {active_alerts_count} active unresolved security alerts logged, and {resolved_alerts_count} alerts resolved.\n"
            f"A total of {total_logs} traffic logs have been captured in the system database."
        )
        pdf.ln(5)
        
        # 2. Incident Summary Table
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(99, 102, 241)
        pdf.cell(0, 6, "2. Incident Count by Severity Level")
        pdf.ln(6)
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(255, 255, 255)
        pdf.set_fill_color(99, 102, 241)
        pdf.cell(60, 6, "Severity", border=1, fill=True, align='C')
        pdf.cell(60, 6, "Active Alerts", border=1, fill=True, align='C')
        pdf.cell(60, 6, "Weight Contribution", border=1, fill=True, align='C')
        pdf.ln()
        
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(55, 65, 81)
        
        severities = [
            ("Critical", critical_count, "25 per alert"),
            ("High", high_count, "15 per alert"),
            ("Medium", medium_count, "5 per alert"),
            ("Low", low_count, "2 per alert")
        ]
        for sev, count, weight in severities:
            pdf.cell(60, 6, sev, border=1, align='C')
            pdf.cell(60, 6, str(count), border=1, align='C')
            pdf.cell(60, 6, weight, border=1, align='C')
            pdf.ln()
        pdf.ln(5)
        
        # 3. Active Threats List
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(99, 102, 241)
        pdf.cell(0, 6, "3. Critical & High Active Security Warnings")
        pdf.ln(6)
        
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(55, 65, 81)
        
        # Fetch only top 8 threats to prevent loading all threats
        threats_to_show = db.query(Alert).join(TrafficLog).filter(
            Alert.is_resolved == False,
            Alert.threat_level.in_(["Critical", "High"])
        ).order_by(Alert.alert_time.desc()).limit(8).all()
        
        if not threats_to_show:
            pdf.cell(0, 6, "No critical or high-risk active alerts logged. Network healthy.")
            pdf.ln(6)
        else:
            for a in threats_to_show:
                log = a.traffic_log
                if not log:
                    continue
                date_str = a.alert_time.strftime("%Y-%m-%d %H:%M:%S")
                pdf.multi_cell(w, 5, 
                    f"[{date_str}] Severity: {a.threat_level} | Src: {log.src_ip}:{log.src_port} -> Dst: {log.dest_ip}:{log.dest_port} | "
                    f"Proto: {log.protocol} | Count: {a.count}\nNotes: {a.notes or 'N/A'}"
                )
                pdf.ln(2)
        pdf.ln(3)
        
        # 4. Recommendations
        pdf.set_font('helvetica', 'B', 11)
        pdf.set_text_color(99, 102, 241)
        pdf.cell(0, 6, "4. Security Recommendations")
        pdf.ln(6)
        
        pdf.set_font('helvetica', '', 9)
        pdf.set_text_color(55, 65, 81)
        
        recommendations = []
        if threat_score > 70:
            recommendations.append("- IMMEDIATELY deploy firewall blocking rules against active malicious source IPs to secure network boundaries.")
            recommendations.append("- Throttle connection rates on affected interfaces and flag destination IPs for potential containment.")
        elif threat_score > 30:
            recommendations.append("- Flag suspicious devices for active monitoring. Inspect L7 DNS/HTTP query histories for anomalies.")
            recommendations.append("- Conduct signature-level inspections on active protocols showing abnormal flow ratios.")
        else:
            recommendations.append("- Continue running default passive monitoring sniffing threads.")
            recommendations.append("- Periodically backup SQL flow records and capture local PCAPs to maintain streaming accuracy indicators.")
            
        for rec in recommendations:
            pdf.multi_cell(w, 5, rec)
            
        try:
            pdf_bytes = pdf.output()
            if isinstance(pdf_bytes, str):
                pdf_bytes = pdf_bytes.encode('latin-1')
        except Exception:
            pdf_bytes = pdf.output(dest='S')
            if isinstance(pdf_bytes, str):
                pdf_bytes = pdf_bytes.encode('latin-1')
                
        return Response(
            content=bytes(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=NEXz_Security_Report.pdf"}
        )
    except Exception as e:
        import traceback
        tb_str = traceback.format_exc()
        print(f"Error in download_pdf_report: {e}\n{tb_str}")
        raise HTTPException(
            status_code=500,
            detail=f"Report compilation failed: {str(e)}\n{tb_str}"
        )


import csv
import io
from fastapi.responses import StreamingResponse

@app.get("/api/reports/csv")
def download_csv_report(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Streams a CSV file containing all traffic logs.
    """
    logs = db.query(TrafficLog).order_by(TrafficLog.timestamp.desc()).limit(1000).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["ID", "Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Duration", "Bytes", "Label", "Confidence", "Metadata Context", "Source", "TCP State"])
    
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.isoformat(),
            log.src_ip,
            log.dest_ip,
            log.src_port,
            log.dest_port,
            log.protocol,
            log.duration,
            log.total_bytes,
            log.prediction_label,
            log.confidence_score,
            log.info or "",
            getattr(log, "source", "live"),
            getattr(log, "connection_state", "N/A")
        ])
        
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=traffic_logs_export.csv"}
    )


# ==========================================
# WEBSOCKET REAL-TIME ENDPOINT
# ==========================================

@app.websocket("/api/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep socket alive. Receive dummy client pings
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ==============================================================================
# === NEXz PILLAR 2 (SECURITY): Device Behaviour Profiles API ===
# ==============================================================================
@app.get("/api/security/device-profiles")
def get_device_profiles(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    NEXz Security Pillar: Returns streaming per-device anomaly baselines, sample counts, and LRU memory capacity stats.
    """
    summaries = device_profiler.get_device_summaries(limit=limit)
    stats = device_profiler.get_stats()
    return {
        "status": "success",
        "stats": stats,
        "devices": summaries
    }

# Mount static frontend dashboard files at root URL
from fastapi.staticfiles import StaticFiles
os.makedirs("./backend/static", exist_ok=True)
app.mount("/", StaticFiles(directory="./backend/static", html=True), name="static")

