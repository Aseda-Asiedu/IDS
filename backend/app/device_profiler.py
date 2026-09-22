# ==============================================================================
# === NEXz ADDITION: Device Behaviour Profile (Per-Device Streaming Anomaly) ===
# Algorithm: Half-Space Trees (Tan, Ting & Liu, 2011, via river.anomaly.HalfSpaceTrees)
# Mechanism: LRU Device Capacity Bounded to 200 Devices to Prevent Memory Growth
# ==============================================================================

import time
import json
import logging
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Any, List, Optional
from river.anomaly import HalfSpaceTrees
from sqlalchemy.orm import Session
from .models import DeviceProfile

# Configure dedicated profiler logger
logger = logging.getLogger("nexz.device_profiler")
logger.setLevel(logging.INFO)

# Domain limits for random half-space partitions (Tan, Ting & Liu, 2011)
DEVICE_FEATURE_LIMITS = {
    "bytes": (0.0, 100_000_000.0),       # 0 to 100 MB
    "duration": (0.0, 3600.0),           # 0s to 1 hour
    "proto_id": (0.0, 255.0),            # Protocol space (ICMP=1, TCP=6, UDP=17)
    "hour": (0.0, 24.0),                 # 24-hour diurnal cycle
    "pkt_count": (0.0, 50_000.0)         # Packet count
}

class DeviceBehaviourProfiler:
    """
    Maintains per-device (IP address) streaming anomaly detection baselines.
    
    Algorithms & Principles:
    - Tan, S. C., Ting, K. M., & Liu, T. F. (2011). Fast anomaly detection for 
      streaming data. In Proceedings of the 22nd International Joint Conference 
      on Artificial Intelligence (IJCAI).
    - Uses river.anomaly.HalfSpaceTrees per distinct host IP with strict LRU memory cap.
    """
    def __init__(self, max_devices: int = 200, anomaly_threshold: float = 0.70, window_size: int = 20):
        self.max_devices = max_devices
        self.anomaly_threshold = anomaly_threshold
        self.window_size = window_size
        # Bounded LRU store: IP -> device record
        self.devices: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.evictions_count = 0
        self.total_flows_evaluated = 0

    def _get_proto_id(self, protocol_str: str) -> float:
        proto = str(protocol_str).upper()
        if "TCP" in proto: return 6.0
        if "UDP" in proto: return 17.0
        if "ICMP" in proto: return 1.0
        return 0.0

    def process_flow(
        self,
        src_ip: str,
        total_bytes: int,
        duration: float,
        protocol: str,
        hour_of_day: int,
        packet_count: int,
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Ingests a 5-tuple flow for the given source device.
        Updates its HalfSpaceTrees anomaly detector and flags operational shifts.
        """
        self.total_flows_evaluated += 1
        now = datetime.utcnow()

        # 1. LRU Capacity Check & Management
        if src_ip in self.devices:
            # Move to MRU position (end of OrderedDict)
            self.devices.move_to_end(src_ip)
            device = self.devices[src_ip]
        else:
            # Check if capacity cap reached
            if len(self.devices) >= self.max_devices:
                # Evict least-recently-seen device (first item in OrderedDict)
                evicted_ip, evicted_data = self.devices.popitem(last=False)
                self.evictions_count += 1
                logger.warning(
                    f"LRU Eviction: Device capacity limit ({self.max_devices}) reached. "
                    f"Evicted device {evicted_ip} from active memory (saw {evicted_data['sample_count']} flows)."
                )
                # Persist eviction update to DB if session provided
                if db:
                    try:
                        dp = db.query(DeviceProfile).filter(DeviceProfile.device_ip == evicted_ip).first()
                        if dp:
                            dp.last_seen = evicted_data["last_seen"]
                            dp.sample_count = evicted_data["sample_count"]
                            dp.anomaly_count = evicted_data["anomaly_count"]
                            db.commit()
                    except Exception as e:
                        logger.error(f"Error saving evicted device state: {e}")

            # Instantiate a new lightweight HalfSpaceTrees detector for this device
            hst_model = HalfSpaceTrees(
                n_trees=25,
                height=8,
                window_size=self.window_size,
                limits=DEVICE_FEATURE_LIMITS,
                seed=42
            )
            device = {
                "ip": src_ip,
                "model": hst_model,
                "first_seen": now,
                "last_seen": now,
                "sample_count": 0,
                "anomaly_count": 0,
                "total_bytes": 0,
                "total_duration": 0.0,
                "proto_counts": {},
                "recent_score": 0.0,
                "recent_alert": False
            }
            self.devices[src_ip] = device

        # 2. Update Device Telemetry Statistics
        device["last_seen"] = now
        device["sample_count"] += 1
        device["total_bytes"] += total_bytes
        device["total_duration"] += duration
        device["proto_counts"][protocol] = device["proto_counts"].get(protocol, 0) + 1

        # 3. Construct Feature Vector for HalfSpaceTrees
        features = {
            "bytes": float(min(total_bytes, 100_000_000.0)),
            "duration": float(min(duration, 3600.0)),
            "proto_id": self._get_proto_id(protocol),
            "hour": float(hour_of_day % 24),
            "pkt_count": float(min(packet_count, 50_000.0))
        }

        model: HalfSpaceTrees = device["model"]

        # 4. Warm-up vs Inference Phase
        # First window_size samples populate the reference window r_mass
        if device["sample_count"] <= self.window_size:
            model.learn_one(features)
            device["recent_score"] = 0.0
            device["recent_alert"] = False
            return {
                "is_anomalous": False,
                "score": 0.0,
                "status": "warming_up",
                "sample_count": device["sample_count"]
            }

        # Inference: score anomaly relative to device's personal history
        score = float(model.score_one(features))
        model.learn_one(features)
        device["recent_score"] = score

        is_anomalous = score >= self.anomaly_threshold
        device["recent_alert"] = is_anomalous

        if is_anomalous:
            device["anomaly_count"] += 1
            threat_level = "High" if score >= 0.85 else "Medium"
            reason = (
                f"Device {src_ip} showed anomalous flow behavior relative to its historical baseline "
                f"(HST score: {score:.2f} >= threshold {self.anomaly_threshold}). "
                f"Payload: {total_bytes}B, Protocol: {protocol}, Duration: {duration:.2f}s."
            )
            return {
                "is_anomalous": True,
                "score": score,
                "threat_level": threat_level,
                "reason": reason,
                "device_ip": src_ip,
                "sample_count": device["sample_count"],
                "anomaly_count": device["anomaly_count"]
            }

        return {
            "is_anomalous": False,
            "score": score,
            "status": "normal",
            "sample_count": device["sample_count"]
        }

    def sync_to_db(self, db: Session, src_ip: str) -> Optional[DeviceProfile]:
        """
        Creates or updates the DeviceProfile record in SQLite.
        """
        if src_ip not in self.devices:
            return None

        dev = self.devices[src_ip]
        dp = db.query(DeviceProfile).filter(DeviceProfile.device_ip == src_ip).first()
        if not dp:
            dp = DeviceProfile(
                device_ip=src_ip,
                first_seen=dev["first_seen"],
                last_seen=dev["last_seen"],
                sample_count=dev["sample_count"],
                anomaly_count=dev["anomaly_count"],
                baseline_summary=json.dumps({
                    "avg_bytes": round(dev["total_bytes"] / max(1, dev["sample_count"]), 1),
                    "avg_duration": round(dev["total_duration"] / max(1, dev["sample_count"]), 2),
                    "protocols": dev["proto_counts"],
                    "recent_score": round(dev["recent_score"], 2)
                })
            )
            db.add(dp)
        else:
            dp.last_seen = dev["last_seen"]
            dp.sample_count = dev["sample_count"]
            dp.anomaly_count = dev["anomaly_count"]
            dp.baseline_summary = json.dumps({
                "avg_bytes": round(dev["total_bytes"] / max(1, dev["sample_count"]), 1),
                "avg_duration": round(dev["total_duration"] / max(1, dev["sample_count"]), 2),
                "protocols": dev["proto_counts"],
                "recent_score": round(dev["recent_score"], 2)
            })
        db.commit()
        db.refresh(dp)
        return dp

    def get_device_summaries(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returns structured device summaries for presentation in the Security pillar.
        """
        summaries = []
        for ip, d in reversed(list(self.devices.items())):
            avg_b = round(d["total_bytes"] / max(1, d["sample_count"]), 1)
            avg_dur = round(d["total_duration"] / max(1, d["sample_count"]), 2)
            summaries.append({
                "ip": ip,
                "first_seen": d["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": d["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                "sample_count": d["sample_count"],
                "anomaly_count": d["anomaly_count"],
                "avg_bytes": avg_b,
                "avg_duration_sec": avg_dur,
                "total_bytes": d.get("total_bytes", 0),
                "total_duration": round(d.get("total_duration", 0.0), 2),
                "protocols": d.get("proto_counts", {}),
                "recent_score": round(d["recent_score"], 2),
                "recent_alert": d["recent_alert"],
                "status": "Anomalous" if d["recent_alert"] else ("Warming Up" if d["sample_count"] <= self.window_size else "Normal")
            })
            if len(summaries) >= limit:
                break
        return summaries

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns memory and operational metrics for the profiler.
        """
        return {
            "active_devices_tracked": len(self.devices),
            "max_device_capacity": self.max_devices,
            "total_evictions": self.evictions_count,
            "total_flows_evaluated": self.total_flows_evaluated
        }

# Global singleton profiler
device_profiler = DeviceBehaviourProfiler(max_devices=200, anomaly_threshold=0.70, window_size=20)
