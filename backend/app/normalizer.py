# ==============================================================================
# === NEXz EXTERNAL NETWORK TELEMETRY NORMALIZER & CAPABILITY ENGINE ===
# Architectural Role: Canonical record definition, intelligent field alias mapping,
# strict data type validation, and capability detection without synthetic fabrication.
# ==============================================================================

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

@dataclass
class NormalizedNetworkRecord:
    timestamp: datetime
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    protocol: str
    duration: float
    src_bytes: int
    dest_bytes: int
    total_bytes: int
    src_pkts: int
    dest_pkts: int
    packet_count: int
    avg_pkt_size: float
    proto_num: float
    splt_mean: float = 0.0
    dplt_mean: float = 0.0
    ground_truth_label: Optional[str] = None
    source: str = "import"
    source_format: str = "csv"
    import_batch_id: Optional[int] = None
    original_filename: str = ""
    is_imported: bool = True
    info: Optional[str] = None
    connection_state: str = "N/A"
    raw_extra: Dict[str, Any] = field(default_factory=dict)

    def can_evaluate_ml(self) -> bool:
        """Determines if the record contains legitimate features for ML classification."""
        return self.total_bytes >= 0 and self.packet_count >= 1

    def to_ai_features(self) -> Tuple[List[float], float, int]:
        """
        Returns the 7-feature vector matching AIEngine expectations:
        [sbytes, dbytes, splt_mean, dplt_mean, proto_id, packet_count, avg_pkt_size]
        """
        return [
            float(self.src_bytes),
            float(self.dest_bytes),
            float(self.splt_mean),
            float(self.dplt_mean),
            float(self.proto_num),
            float(self.packet_count),
            float(self.avg_pkt_size)
        ], float(self.duration), int(self.total_bytes)


# Standard canonical fields expected by NEXz
CANONICAL_FIELDS = [
    "timestamp",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "protocol",
    "duration",
    "src_bytes",
    "dest_bytes",
    "total_bytes",
    "src_pkts",
    "dest_pkts",
    "packet_count",
    "label",
    "info"
]

# Field alias dictionaries for automated schema detection
FIELD_ALIASES: Dict[str, List[str]] = {
    "src_ip": [
        "src_ip", "source_ip", "sourceip", "source ip", "src", "s_ip", 
        "id.orig_h", "origin_ip", "client_ip", "src_addr", "source_address", 
        "ip.src", "source", "orig_ip", "saddr", "src_host"
    ],
    "dest_ip": [
        "dest_ip", "dst_ip", "destination_ip", "destinationip", "destination ip", 
        "dst", "d_ip", "id.resp_h", "destip", "dstip", "resp_ip", "server_ip", 
        "dest_addr", "destination_address", "ip.dst", "destination", "daddr", "dst_host"
    ],
    "src_port": [
        "src_port", "sport", "source_port", "sourceport", "source port", 
        "s_port", "id.orig_p", "srcport", "client_port", "orig_p"
    ],
    "dest_port": [
        "dest_port", "dport", "destination_port", "destinationport", "destination port", 
        "d_port", "id.resp_p", "destport", "dstport", "server_port", "resp_p"
    ],
    "protocol": [
        "protocol", "proto", "proto_name", "ip_proto", "transport", "protocol_name"
    ],
    "duration": [
        "duration", "flow_duration", "dur", "session_duration", "time_span", "length_sec"
    ],
    "src_bytes": [
        "src_bytes", "sbytes", "bytes_out", "orig_bytes", "orig_ip_bytes", 
        "bytes_sent", "fwd_bytes", "fwd_seg_size_avg", "out_bytes"
    ],
    "dest_bytes": [
        "dest_bytes", "dbytes", "bytes_in", "resp_bytes", "resp_ip_bytes", 
        "bytes_recv", "bwd_bytes", "bwd_seg_size_avg", "in_bytes"
    ],
    "total_bytes": [
        "total_bytes", "tot_bytes", "bytes", "octets", "flow_bytes", 
        "tot_len", "volume_bytes", "byte_count"
    ],
    "src_pkts": [
        "src_pkts", "spkts", "total_fwd_packets", "orig_pkts", "pkts_sent", "fwd_pkts"
    ],
    "dest_pkts": [
        "dest_pkts", "dpkts", "total_bwd_packets", "resp_pkts", "pkts_recv", "bwd_pkts"
    ],
    "packet_count": [
        "packet_count", "packets", "total_packets", "pkts", "tot_pkts", 
        "flow_packets", "count_pkts"
    ],
    "timestamp": [
        "timestamp", "time", "ts", "start_time", "datetime", "date", 
        "flow_start", "first_seen", "start_ts"
    ],
    "label": [
        "label", "class", "attack_type", "category", "ground_truth", 
        "target", "threat_label", "classification", "tag"
    ],
    "info": [
        "info", "query", "host", "sni", "uri", "url", "service", 
        "details", "notes", "summary", "dns_query", "http_host"
    ]
}

def clean_col_name(name: str) -> str:
    """Normalizes string for comparison (lowercase, alphanumeric only)."""
    return re.sub(r"[^a-z0-9]", "", str(name).strip().lower())

def auto_detect_mappings(headers: List[str]) -> Dict[str, str]:
    """
    Given a list of column headers from an external file,
    returns a dictionary mapping canonical_field -> detected_header.
    """
    mapping: Dict[str, str] = {}
    normalized_headers = {clean_col_name(h): h for h in headers}

    for canonical, aliases in FIELD_ALIASES.items():
        matched = None
        for alias in aliases:
            clean_alias = clean_col_name(alias)
            if clean_alias in normalized_headers:
                matched = normalized_headers[clean_alias]
                break
        if matched:
            mapping[canonical] = matched

    return mapping

def validate_ip(val: Any) -> Tuple[bool, Optional[str]]:
    """Validates IPv4 or IPv6 string."""
    if not val:
        return False, None
    s = str(val).strip()
    try:
        ipaddress.ip_address(s)
        return True, s
    except ValueError:
        return False, None

def validate_port(val: Any) -> Tuple[bool, Optional[int]]:
    """Validates port integer (0 to 65535)."""
    if val is None or str(val).strip() == "":
        return True, 0
    try:
        p = int(float(val))
        if 0 <= p <= 65535:
            return True, p
        return False, None
    except (ValueError, TypeError):
        return False, None

def normalize_protocol(val: Any) -> Tuple[str, float]:
    """
    Resolves protocol string/number to normalized name and proto_id.
    TCP = 1, UDP = 2, ICMP = 3, Others = 0.
    """
    if not val:
        return "OTHER", 0.0
    p = str(val).strip().upper()
    if p in ["TCP", "6", "IPPROTO_TCP"]:
        return "TCP", 1.0
    elif p in ["UDP", "17", "IPPROTO_UDP"]:
        return "UDP", 2.0
    elif p in ["ICMP", "1", "IPPROTO_ICMP"]:
        return "ICMP", 3.0
    elif p in ["DNS", "HTTP", "HTTPS", "TLS", "ARP"]:
        return p, 1.0 if p in ["HTTP", "HTTPS", "TLS"] else 2.0
    return p, 0.0

def normalize_timestamp(val: Any) -> Tuple[bool, datetime]:
    """
    Parses various timestamp formats (Unix epoch, ISO 8601, common string formats).
    """
    now = datetime.now(timezone.utc)
    if not val:
        return True, now

    # Try numeric Unix epoch (seconds or milliseconds)
    try:
        num = float(val)
        if num > 1e11:  # Milliseconds
            return True, datetime.fromtimestamp(num / 1000.0, tz=timezone.utc)
        elif num > 1e8:  # Seconds
            return True, datetime.fromtimestamp(num, tz=timezone.utc)
    except (ValueError, TypeError):
        pass

    s = str(val).strip()
    # Try ISO formats
    try:
        return True, datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass

    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S"
    ]:
        try:
            return True, datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue

    return False, now

def normalize_numerical(val: Any, default: float = 0.0, min_val: float = 0.0) -> float:
    """Safely converts input to a float, clamping to min_val."""
    if val is None or str(val).strip() == "":
        return default
    try:
        v = float(val)
        return max(min_val, v)
    except (ValueError, TypeError):
        return default

def detect_capabilities(mapping: Dict[str, str], sample_records: List[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """
    Capability-based dataset compatibility detection without synthetic fabrication.
    """
    has_src = bool(mapping.get("src_ip"))
    has_dst = bool(mapping.get("dest_ip"))
    has_proto = bool(mapping.get("protocol"))
    has_ts = bool(mapping.get("timestamp"))
    has_dur = bool(mapping.get("duration"))
    has_bytes = bool(mapping.get("total_bytes") or (mapping.get("src_bytes") and mapping.get("dest_bytes")))
    has_pkts = bool(mapping.get("packet_count") or (mapping.get("src_pkts") and mapping.get("dest_pkts")))
    has_label = bool(mapping.get("label"))

    caps = {}

    # 1. Traffic Visualization
    if has_ts and has_src and has_dst:
        caps["traffic_visualization"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Timestamp, source, and destination endpoints are mapped."
        }
    else:
        caps["traffic_visualization"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Missing timestamp or network endpoints."
        }

    # 2. IP Relationship & Graph Analytics
    if has_src and has_dst:
        caps["ip_analytics"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Source and destination IP addresses are mapped."
        }
    else:
        caps["ip_analytics"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Source or destination IP address is missing."
        }

    # 3. Protocol Analytics
    if has_proto:
        caps["protocol_analytics"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Protocol field is mapped."
        }
    else:
        caps["protocol_analytics"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Protocol column is unmapped."
        }

    # 4. Device Inventory & Behaviour Profiling
    if has_src and has_bytes:
        caps["device_inventory"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Source IP and flow byte volumes available for device tracking."
        }
        caps["behaviour_profiling"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Per-device telemetry available for Half-Space Trees baseline."
        }
    elif has_src:
        caps["device_inventory"] = {
            "supported": True,
            "status": "partial",
            "reason": "Source IP is available, but byte volumes are unmapped."
        }
        caps["behaviour_profiling"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Requires byte volumes and timing to model host profiles."
        }
    else:
        caps["device_inventory"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Source IP is missing."
        }
        caps["behaviour_profiling"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Source IP is missing."
        }

    # 5. Adaptive Random Forest (ARF) Classification
    # Strictly requires byte and packet features without fabrication
    if has_bytes and has_pkts:
        caps["arf_classification"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "All essential volumetric flow features (bytes and packet counts) are mapped."
        }
    elif has_bytes or has_pkts:
        caps["arf_classification"] = {
            "supported": False,
            "status": "partial",
            "reason": "Partial flow features present (either bytes or packets missing). In accordance with academic rigor, feature fabrication is disabled."
        }
    else:
        caps["arf_classification"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Volumetric flow statistics (bytes and packet counts) are missing. Classification disabled."
        }

    # 6. IOC / Watchlist Cross-Correlation
    if has_src or has_dst:
        caps["ioc_correlation"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Network IP endpoints are available for watchlist cross-referencing."
        }
    else:
        caps["ioc_correlation"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "No IP address columns available for watchlist lookup."
        }

    # 7. Ground Truth Label-Assisted Evaluation
    if has_label:
        caps["label_evaluation"] = {
            "supported": True,
            "status": "fully_supported",
            "reason": "Ground truth label column is mapped for supervised metric evaluation."
        }
    else:
        caps["label_evaluation"] = {
            "supported": False,
            "status": "unsupported",
            "reason": "Ground truth label is unmapped. Supervised evaluation disabled."
        }

    return caps
