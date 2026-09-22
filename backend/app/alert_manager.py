import time
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import text
from .models import Alert, TrafficLog, DeviceProfile

# ==============================================================================
# === NEXz CENTRAL ALERT MANAGER ===
# Architectural Role: Single unified ingestion, deduplication, lifecycle, and 
# broadcast manager for all security observations (Streaming ML, Behaviour Profiles, 
# ARP Spoofing, Heuristics, and Cyber Range Simulations).
# ==============================================================================
class AlertManager:
    def __init__(self):
        self.last_broadcast_times: Dict[Tuple[str, str, str, str], float] = {}

    def ingest_security_event(
        self,
        db: Session,
        threat_level: str,
        threat_type: str,
        reason: str,
        action: str,
        src_ip: str,
        dest_ip: str,
        protocol: str,
        src_port: int = 0,
        dest_port: int = 0,
        confidence: float = 0.85,
        alert_type: str = "flow_classification",
        traffic_log_id: Optional[int] = None,
        device_id: Optional[int] = None,
        is_simulated: bool = False,
        extra_info: Optional[str] = None
    ) -> Tuple[Alert, bool, Optional[Dict[str, Any]]]:
        """
        Ingests an observation from any detection source into the central alert pipeline.
        Performs database-level deduplication over active alerts, advances alert lifecycle,
        and generates a rate-limited WebSocket notification payload.
        """
        # Deduplication query over active (unresolved) alerts matching signature
        query = db.query(Alert).filter(
            Alert.is_resolved == False,
            Alert.threat_level == threat_level,
            Alert.alert_type == alert_type
        )
        if device_id:
            query = query.filter(Alert.device_id == device_id)
        elif traffic_log_id:
            query = query.join(TrafficLog, Alert.traffic_log_id == TrafficLog.id).filter(TrafficLog.src_ip == src_ip)
        else:
            query = query.join(TrafficLog, Alert.traffic_log_id == TrafficLog.id, isouter=True).filter(
                (TrafficLog.src_ip == src_ip) | Alert.notes.contains(src_ip)
            )

        existing_alert = query.first()

        now = datetime.utcnow()
        sim_tag = "[SIMULATION] " if is_simulated else ""

        if existing_alert:
            existing_alert.count = (existing_alert.count or 1) + 1
            existing_alert.last_seen = now
            if traffic_log_id:
                existing_alert.traffic_log_id = traffic_log_id
            if is_simulated:
                existing_alert.is_simulated = True
                if "[SIMULATION]" not in (existing_alert.notes or ""):
                    existing_alert.notes = "[SIMULATION] " + (existing_alert.notes or "")
            
            # Lifecycle advancement: New -> Active on repeated occurrences
            if getattr(existing_alert, "status", None) == "New":
                existing_alert.status = "Active"
                
            db.commit()
            db.refresh(existing_alert)
            alert = existing_alert
            is_new = False
        else:
            notes = f"{sim_tag}[{src_ip} -> {dest_ip} | {protocol}] Diagnosis: {threat_type} | Reason: {reason} | Action: {action}"
            if extra_info:
                notes += f" | Context: {extra_info}"

            alert = Alert(
                traffic_log_id=traffic_log_id,
                device_id=device_id,
                alert_type=alert_type,
                threat_level=threat_level,
                status="New",
                is_simulated=is_simulated,
                notes=notes,
                is_resolved=False,
                count=1,
                alert_time=now,
                last_seen=now
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            is_new = True

        # Determine rate-limited broadcast payload (max once every 2 seconds for identical signature)
        broadcast_key = (src_ip, dest_ip, protocol, threat_level)
        now_ts = time.time()
        should_broadcast = True
        if broadcast_key in self.last_broadcast_times:
            if now_ts - self.last_broadcast_times[broadcast_key] < 2.0:
                should_broadcast = False

        broadcast_payload = None
        if should_broadcast:
            self.last_broadcast_times[broadcast_key] = now_ts
            broadcast_payload = {
                "type": "alert",
                "alert_id": alert.id,
                "timestamp": alert.alert_time.isoformat(),
                "first_seen": alert.alert_time.isoformat(),
                "last_seen": alert.last_seen.isoformat(),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "protocol": protocol,
                "threat_level": alert.threat_level,
                "status": getattr(alert, "status", "Active"),
                "confidence": round(confidence, 2),
                "count": alert.count,
                "alert_type": alert.alert_type,
                "is_simulated": is_simulated,
                "notes": alert.notes,
                "threat_type": threat_type,
                "reason": reason,
                "action": action
            }

        return alert, is_new, broadcast_payload

    def acknowledge_alert(self, db: Session, alert_id: int) -> Optional[Alert]:
        """
        Transitions an active alert to 'Acknowledged' state.
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None
        alert.status = "Acknowledged"
        db.commit()
        db.refresh(alert)
        return alert

    def resolve_alert(self, db: Session, alert_id: int) -> Optional[Alert]:
        """
        Transitions an active or acknowledged alert to 'Resolved' and sets is_resolved = True.
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None
        alert.status = "Resolved"
        alert.is_resolved = True
        db.commit()
        db.refresh(alert)
        return alert


# Global singleton alert manager
alert_manager = AlertManager()
