"""
NEXz Network Behaviour Profiler
Component: Analytics & Behavioural Baseline Module
Purpose:
    Maintains an observable statistical baseline of regular network traffic 
    parameters over a rolling window (default: 1 hour) and flags meaningful 
    operational deviations distinctly from AI-generated threat alarms.

Data Pipeline:
    Flow Extractor / Database Logs -> NetworkBehaviourProfiler -> Deviation Indicators
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from .models import TrafficLog

class NetworkBehaviourProfiler:
    def __init__(self, window_hours: int = 1):
        self.window_hours = window_hours
        self.last_profile_time = 0
        self.cached_profile = {}
        self.cache_ttl_seconds = 30  # Recompute baseline every 30s to keep system lightweight

    def compute_baseline(self, db: Session) -> Dict[str, Any]:
        """
        Queries recent historical flows to establish normal operational parameters:
        - Average bytes per flow
        - Flow volume per minute
        - Protocol distribution baseline
        - Top active destination ports
        """
        now = datetime.utcnow()
        start_time = now - timedelta(hours=self.window_hours)
        
        # 1. Total flows and byte statistics over the window
        stats_query = db.query(
            func.count(TrafficLog.id).label("total_flows"),
            func.sum(TrafficLog.total_bytes).label("total_bytes"),
            func.avg(TrafficLog.total_bytes).label("avg_bytes_per_flow"),
            func.avg(TrafficLog.duration).label("avg_duration")
        ).filter(TrafficLog.timestamp >= start_time).first()
        
        total_flows = stats_query[0] or 0
        total_bytes = stats_query[1] or 0
        avg_bytes = float(stats_query[2] or 0.0)
        avg_duration = float(stats_query[3] or 0.0)
        
        # Flows per minute
        window_minutes = max(1, self.window_hours * 60)
        flow_rate_per_min = round(total_flows / window_minutes, 2)
        
        # 2. Protocol distribution percentages in the baseline
        proto_query = db.query(
            TrafficLog.protocol,
            func.count(TrafficLog.id)
        ).filter(TrafficLog.timestamp >= start_time).group_by(TrafficLog.protocol).all()
        
        proto_baseline = {}
        if total_flows > 0:
            for proto, count in proto_query:
                proto_baseline[proto] = round((count / total_flows) * 100, 1)
                
        # 3. Typical destination ports
        port_query = db.query(
            TrafficLog.dest_port,
            func.count(TrafficLog.id).label("count")
        ).filter(TrafficLog.timestamp >= start_time).group_by(TrafficLog.dest_port).order_by(func.count(TrafficLog.id).desc()).limit(5).all()
        
        common_ports = [int(r[0]) for r in port_query]
        
        return {
            "window_hours": self.window_hours,
            "total_flows_in_window": total_flows,
            "flow_rate_per_min": flow_rate_per_min,
            "avg_bytes_per_flow": round(avg_bytes, 1),
            "avg_duration_sec": round(avg_duration, 2),
            "protocol_baseline_pct": proto_baseline,
            "common_dest_ports": common_ports
        }

    def evaluate_deviations(self, db: Session, current_pps: int = 0) -> Dict[str, Any]:
        """
        Compares recent activity (last 5 minutes) against the 1-hour baseline 
        to detect non-malicious operational spikes or protocol anomalies.
        """
        now_ts = time.time()
        if now_ts - self.last_profile_time > self.cache_ttl_seconds or not self.cached_profile:
            self.cached_profile = self.compute_baseline(db)
            self.last_profile_time = now_ts
            
        baseline = self.cached_profile
        deviations: List[Dict[str, Any]] = []
        is_deviating = False
        
        now = datetime.utcnow()
        five_mins_ago = now - timedelta(minutes=5)
        
        # Query recent 5-minute activity
        recent_stats = db.query(
            func.count(TrafficLog.id).label("flows_5m"),
            func.sum(TrafficLog.total_bytes).label("bytes_5m"),
            func.avg(TrafficLog.total_bytes).label("avg_bytes_5m")
        ).filter(TrafficLog.timestamp >= five_mins_ago).first()
        
        flows_5m = recent_stats[0] or 0
        current_flow_rate_per_min = round(flows_5m / 5.0, 2)
        avg_bytes_5m = float(recent_stats[2] or 0.0)
        
        # Check 1: Flow creation velocity deviation
        baseline_flow_rate = baseline.get("flow_rate_per_min", 0.0)
        if baseline_flow_rate > 5.0 and current_flow_rate_per_min > (2.5 * baseline_flow_rate):
            is_deviating = True
            deviations.append({
                "metric": "Flow Creation Rate",
                "severity": "Warning",
                "detail": f"Flow velocity surged to {current_flow_rate_per_min} flows/min (baseline: {baseline_flow_rate} flows/min).",
                "implication": "Indicates network-wide connection surge, mass browser reload, or multi-threaded scans."
            })
            
        # Check 2: Packet rate (PPS) spike
        if current_pps > 150:
            is_deviating = True
            deviations.append({
                "metric": "Packet Velocity (PPS)",
                "severity": "Elevated",
                "detail": f"Packet velocity currently at {current_pps} PPS.",
                "implication": "High volume traffic generation; observe if accompanied by socket resets or buffer saturation."
            })
            
        # Check 3: Abnormal Byte Weight
        baseline_bytes = baseline.get("avg_bytes_per_flow", 0.0)
        if baseline_bytes > 0 and avg_bytes_5m > (4.0 * baseline_bytes) and flows_5m > 10:
            is_deviating = True
            deviations.append({
                "metric": "Payload Volume per Flow",
                "severity": "Notice",
                "detail": f"Average flow payload surged to {round(avg_bytes_5m)} B (baseline: {round(baseline_bytes)} B).",
                "implication": "Large file transfers, streaming video initialization, or potential data staging in progress."
            })
            
        status = "Deviation Detected" if is_deviating else "Baseline Stable"
        
        return {
            "status": status,
            "is_deviating": is_deviating,
            "baseline": baseline,
            "recent_5m": {
                "flow_rate_per_min": current_flow_rate_per_min,
                "current_pps": current_pps,
                "avg_bytes_per_flow": round(avg_bytes_5m, 1)
            },
            "deviations": deviations,
            "updated_at": datetime.utcnow().strftime("%H:%M:%S")
        }

# Global singleton profiler
network_profiler = NetworkBehaviourProfiler(window_hours=1)
