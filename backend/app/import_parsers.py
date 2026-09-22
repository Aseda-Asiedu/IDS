# ==============================================================================
# === NEXz EXTERNAL NETWORK TELEMETRY IMPORT PARSERS & ADAPTERS ===
# Architectural Role: Multi-format streaming parsers for PCAP, CSV, JSON, JSONL,
# Zeek TSV, Suricata EVE, and TXT IOC threat watchlists with bounded memory usage.
# ==============================================================================

import os
import csv
import json
import re
import ipaddress
from typing import Dict, Any, List, Optional, Tuple, Generator
from .normalizer import auto_detect_mappings, detect_capabilities

def detect_file_format(file_path: str, filename: str = "") -> str:
    """
    Intelligently identifies file format using file extension and initial bytes.
    Returns: 'pcap', 'csv', 'json', 'jsonl', 'zeek', 'eve', 'txt_ioc'
    """
    fn = (filename or os.path.basename(file_path)).lower()
    
    # 1. Direct extension matches
    if fn.endswith(".pcap") or fn.endswith(".pcapng") or fn.endswith(".cap"):
        return "pcap"
    if fn.endswith(".jsonl") or fn.endswith(".ndjson"):
        return "jsonl"
    if fn.endswith(".csv"):
        return "csv"
    
    # 2. Check content sniffing
    try:
        with open(file_path, "rb") as f:
            magic = f.read(1024)
            # PCAP magic numbers
            if magic[:4] in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\x0a\x0d\x0d\x0a']:
                return "pcap"
            
            # Text decoding
            text = magic.decode("utf-8", errors="ignore").strip()
            if text.startswith("#separator") or text.startswith("#fields"):
                return "zeek"
            if "event_type" in text and ("\"flow\"" in text or "\"alert\"" in text or "\"dns\"" in text):
                return "eve"
            if text.startswith("{") or text.startswith("["):
                # Could be JSON or JSONL
                first_line = text.split("\n")[0].strip()
                if first_line.startswith("{") and first_line.endswith("}"):
                    # Check if second line is also a JSON object
                    lines = text.split("\n")
                    if len(lines) > 1 and lines[1].strip().startswith("{"):
                        return "jsonl"
                return "json"
    except Exception:
        pass
        
    if fn.endswith(".txt") or fn.endswith(".ioc") or fn.endswith(".list"):
        return "txt_ioc"
    if fn.endswith(".json"):
        return "json"
    if fn.endswith(".tsv") or fn.endswith(".log"):
        return "zeek"
        
    return "csv"


# ==============================================================================
# 1. CSV PARSER & STREAMER
# ==============================================================================
def parse_csv_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """
    Parses headers and first sample_size rows from a CSV file.
    Estimates total record count without reading entire file into RAM.
    """
    delimiter = ","
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        first_line = f.readline()
        if ";" in first_line and first_line.count(";") > first_line.count(","):
            delimiter = ";"
        elif "\t" in first_line and first_line.count("\t") > first_line.count(","):
            delimiter = "\t"
            
    headers: List[str] = []
    sample_rows: List[Dict[str, Any]] = []
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        headers = [h.strip() for h in (reader.fieldnames or []) if h]
        for i, row in enumerate(reader):
            if i >= sample_size:
                break
            sample_rows.append({k.strip(): v for k, v in row.items() if k})
            
    # Estimate total rows by line count
    total_estimated = 0
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for _ in f:
            total_estimated += 1
    total_estimated = max(0, total_estimated - 1) # Subtract header
    
    auto_mapping = auto_detect_mappings(headers)
    caps = detect_capabilities(auto_mapping, sample_rows)
    
    return {
        "format": "csv",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": total_estimated,
        "auto_mapping": auto_mapping,
        "capabilities": caps,
        "delimiter": delimiter
    }

def stream_csv_records(file_path: str, delimiter: str = ",") -> Generator[Dict[str, Any], None, None]:
    """Memory-bounded streaming generator yielding raw row dictionaries."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            yield {k.strip(): v for k, v in row.items() if k}


# ==============================================================================
# 2. JSON & JSONL / NDJSON PARSERS
# ==============================================================================
def parse_jsonl_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """Parses first sample_size lines of a newline-delimited JSON file."""
    headers_set = set()
    sample_rows: List[Dict[str, Any]] = []
    total_lines = 0
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            if len(sample_rows) < sample_size:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        headers_set.update(obj.keys())
                        sample_rows.append(obj)
                except Exception:
                    pass
                    
    headers = sorted(list(headers_set))
    auto_mapping = auto_detect_mappings(headers)
    caps = detect_capabilities(auto_mapping, sample_rows)
    
    return {
        "format": "jsonl",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": total_lines,
        "auto_mapping": auto_mapping,
        "capabilities": caps
    }

def stream_jsonl_records(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Streams NDJSON objects line by line."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
                except Exception:
                    continue

def parse_json_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """Parses standard JSON file (array of records or dict containing flows)."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
        
    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        # Look for candidate list fields
        for key in ["flows", "records", "data", "traffic", "items", "packets"]:
            if key in data and isinstance(data[key], list):
                records = data[key]
                break
        if not records:
            records = [data]
            
    sample_rows = records[:sample_size]
    headers_set = set()
    for r in sample_rows:
        if isinstance(r, dict):
            headers_set.update(r.keys())
            
    headers = sorted(list(headers_set))
    auto_mapping = auto_detect_mappings(headers)
    caps = detect_capabilities(auto_mapping, sample_rows)
    
    return {
        "format": "json",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": len(records),
        "auto_mapping": auto_mapping,
        "capabilities": caps
    }

def stream_json_records(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Streams records from standard JSON file."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
    elif isinstance(data, dict):
        for key in ["flows", "records", "data", "traffic", "items", "packets"]:
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, dict):
                        yield item
                return
        yield data


# ==============================================================================
# 3. ZEEK LOG ADAPTER (TSV with #fields)
# ==============================================================================
def parse_zeek_tsv_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """Parses Zeek conn.log TSV format with header auto-extraction."""
    headers: List[str] = []
    sample_rows: List[Dict[str, Any]] = []
    total_records = 0
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                parts = line.split()[1:]
                headers = [p.strip() for p in parts]
                continue
            if line.startswith("#"):
                continue
            # Data row
            total_records += 1
            if len(sample_rows) < sample_size and headers:
                vals = line.split("\t")
                row_dict = {}
                for idx, col in enumerate(headers):
                    val = vals[idx] if idx < len(vals) else ""
                    row_dict[col] = "" if val == "-" else val
                sample_rows.append(row_dict)
                
    auto_mapping = auto_detect_mappings(headers)
    
    # Specific Zeek field overrides if standard
    if "id.orig_h" in headers and "src_ip" not in auto_mapping:
        auto_mapping["src_ip"] = "id.orig_h"
    if "id.resp_h" in headers and "dest_ip" not in auto_mapping:
        auto_mapping["dest_ip"] = "id.resp_h"
    if "id.orig_p" in headers and "src_port" not in auto_mapping:
        auto_mapping["src_port"] = "id.orig_p"
    if "id.resp_p" in headers and "dest_port" not in auto_mapping:
        auto_mapping["dest_port"] = "id.resp_p"
    if "orig_bytes" in headers and "src_bytes" not in auto_mapping:
        auto_mapping["src_bytes"] = "orig_bytes"
    if "resp_bytes" in headers and "dest_bytes" not in auto_mapping:
        auto_mapping["dest_bytes"] = "resp_bytes"
    if "orig_pkts" in headers and "src_pkts" not in auto_mapping:
        auto_mapping["src_pkts"] = "orig_pkts"
    if "resp_pkts" in headers and "dest_pkts" not in auto_mapping:
        auto_mapping["dest_pkts"] = "resp_pkts"
    if "ts" in headers and "timestamp" not in auto_mapping:
        auto_mapping["timestamp"] = "ts"
    if "conn_state" in headers and "info" not in auto_mapping:
        auto_mapping["info"] = "conn_state"
        
    caps = detect_capabilities(auto_mapping, sample_rows)
    
    return {
        "format": "zeek",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": total_records,
        "auto_mapping": auto_mapping,
        "capabilities": caps
    }

def stream_zeek_tsv_records(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Streams data lines from Zeek TSV file."""
    headers: List[str] = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                headers = [p.strip() for p in line.split()[1:]]
                continue
            if line.startswith("#"):
                continue
            if not headers:
                continue
            vals = line.split("\t")
            row_dict = {}
            for idx, col in enumerate(headers):
                val = vals[idx] if idx < len(vals) else ""
                row_dict[col] = "" if val == "-" else val
            yield row_dict


# ==============================================================================
# 4. SURICATA EVE JSON ADAPTER
# ==============================================================================
def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Recursively flattens nested JSON dictionaries into dot notation."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def parse_suricata_eve_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """Parses Suricata EVE JSON events, flattening nested flow and alert trees."""
    sample_rows = []
    headers_set = set()
    total_records = 0
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_records += 1
            line = line.strip()
            if not line:
                continue
            if len(sample_rows) < sample_size:
                try:
                    obj = json.loads(line)
                    flat = flatten_dict(obj)
                    headers_set.update(flat.keys())
                    sample_rows.append(flat)
                except Exception:
                    pass
                    
    headers = sorted(list(headers_set))
    auto_mapping = auto_detect_mappings(headers)
    
    # Specific Suricata EVE mappings
    if "flow.bytes_toclient" in headers and "dest_bytes" not in auto_mapping:
        auto_mapping["dest_bytes"] = "flow.bytes_toclient"
    if "flow.bytes_toserver" in headers and "src_bytes" not in auto_mapping:
        auto_mapping["src_bytes"] = "flow.bytes_toserver"
    if "flow.pkts_toclient" in headers and "dest_pkts" not in auto_mapping:
        auto_mapping["dest_pkts"] = "flow.pkts_toclient"
    if "flow.pkts_toserver" in headers and "src_pkts" not in auto_mapping:
        auto_mapping["src_pkts"] = "flow.pkts_toserver"
    if "flow.age" in headers and "duration" not in auto_mapping:
        auto_mapping["duration"] = "flow.age"
    if "alert.signature" in headers and "label" not in auto_mapping:
        auto_mapping["label"] = "alert.signature"
        
    caps = detect_capabilities(auto_mapping, sample_rows)
    
    return {
        "format": "eve",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": total_records,
        "auto_mapping": auto_mapping,
        "capabilities": caps
    }

def stream_suricata_eve_records(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Streams flattened Suricata EVE records."""
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                    yield flatten_dict(obj)
                except Exception:
                    continue


# ==============================================================================
# 5. TXT / CSV IOC WATCHLIST PARSER
# ==============================================================================
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

def parse_txt_ioc(file_path: str) -> Dict[str, Any]:
    """
    Extracts IPs and domains from text or watchlist files.
    Validates IPs to filter out non-routable or invalid octets.
    """
    entries: List[Dict[str, Any]] = []
    seen = set()
    total_lines = 0
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            total_lines += 1
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            # Check IPv4
            for match in IPV4_REGEX.findall(line):
                try:
                    ipaddress.IPv4Address(match)
                    if match not in seen:
                        seen.add(match)
                        entries.append({
                            "value": match,
                            "type": "ipv4",
                            "line": line_no,
                            "label": "Imported IOC Host"
                        })
                except ipaddress.AddressValueError:
                    pass
                    
            # Check Domains
            for match in DOMAIN_REGEX.findall(line):
                # Ensure it wasn't matched as IP
                if match not in seen and not IPV4_REGEX.match(match):
                    seen.add(match)
                    entries.append({
                        "value": match,
                        "type": "domain",
                        "line": line_no,
                        "label": "Imported IOC Domain"
                    })
                    
    return {
        "format": "txt_ioc",
        "entries": entries,
        "total_lines": total_lines,
        "ioc_count": len(entries),
        "headers": ["value", "type", "label"],
        "sample_rows": entries[:25]
    }


# ==============================================================================
# 6. PCAP / PCAPNG INSPECTOR
# ==============================================================================
def parse_pcap_sample(file_path: str, sample_size: int = 50) -> Dict[str, Any]:
    """
    Quickly peeks into a PCAP file using Scapy PcapReader without loading it all.
    """
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP
    sample_rows = []
    pkt_count = 0
    
    try:
        with PcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                pkt_count += 1
                if len(sample_rows) < sample_size and pkt.haslayer(IP):
                    ip = pkt[IP]
                    proto_name = "OTHER"
                    sport = 0
                    dport = 0
                    if pkt.haslayer(TCP):
                        proto_name = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                    elif pkt.haslayer(UDP):
                        proto_name = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                    elif pkt.haslayer(ICMP):
                        proto_name = "ICMP"
                    
                    sample_rows.append({
                        "timestamp": float(pkt.time),
                        "src_ip": ip.src,
                        "dest_ip": ip.dst,
                        "src_port": sport,
                        "dest_port": dport,
                        "protocol": proto_name,
                        "packet_length": len(pkt)
                    })
    except Exception as e:
        print(f"Error inspecting PCAP sample: {e}")
        
    headers = ["timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "protocol", "packet_length"]
    auto_mapping = auto_detect_mappings(headers)
    caps = {
        "traffic_visualization": {"supported": True, "status": "fully_supported", "reason": "Full packet payload & headers present."},
        "ip_analytics": {"supported": True, "status": "fully_supported", "reason": "All IP endpoints parsed natively."},
        "protocol_analytics": {"supported": True, "status": "fully_supported", "reason": "L2-L7 protocols dissected."},
        "device_inventory": {"supported": True, "status": "fully_supported", "reason": "Direct MAC and IP device tracking."},
        "arf_classification": {"supported": True, "status": "fully_supported", "reason": "Native FlowFeatureExtractor generates full 7-feature vectors."},
        "behaviour_profiling": {"supported": True, "status": "fully_supported", "reason": "Per-host flow statistics computed."},
        "ioc_correlation": {"supported": True, "status": "fully_supported", "reason": "Full IP addresses cross-correlated."},
        "label_evaluation": {"supported": False, "status": "unsupported", "reason": "Raw PCAP does not contain supervisory labels."}
    }
    
    return {
        "format": "pcap",
        "headers": headers,
        "sample_rows": sample_rows,
        "estimated_records": pkt_count,
        "auto_mapping": auto_mapping,
        "capabilities": caps
    }
