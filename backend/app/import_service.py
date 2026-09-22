# ==============================================================================
# === NEXz EXTERNAL NETWORK TELEMETRY IMPORT SERVICE ===
# Architectural Role: Orchestrates external telemetry ingestion, schema validation,
# capability evaluation, bounded streaming execution, multi-mode analysis (Analyze Only,
# Replay, Historical, Label Evaluation), watchlist IOC correlation, and provenance.
# ==============================================================================

import os
import time
import json
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Generator
from sqlalchemy.orm import Session
from sqlalchemy import text

from .database import SessionLocal
from .models import ImportBatch, TrafficLog, Alert, WatchlistEntry, DeviceProfile
from .normalizer import (
    NormalizedNetworkRecord, CANONICAL_FIELDS,
    auto_detect_mappings, validate_ip, validate_port,
    normalize_protocol, normalize_timestamp, normalize_numerical,
    detect_capabilities
)
from .import_parsers import (
    detect_file_format, parse_csv_sample, stream_csv_records,
    parse_json_sample, stream_json_records,
    parse_jsonl_sample, stream_jsonl_records,
    parse_zeek_tsv_sample, stream_zeek_tsv_records,
    parse_suricata_eve_sample, stream_suricata_eve_records,
    parse_txt_ioc, parse_pcap_sample
)
from .ai_engine import AIEngine
from .profiler import network_profiler
from .device_profiler import device_profiler
from .alert_manager import alert_manager

class ActiveImportJob:
    def __init__(self, batch_id: int):
        self.batch_id = batch_id
        self.thread: Optional[threading.Thread] = None
        self.pause_event = threading.Event()
        self.pause_event.set() # Unpaused by default
        self.cancel_event = threading.Event()
        self.is_paused = False
        self.is_running = False
        self.progress: Dict[str, Any] = {
            "batch_id": batch_id,
            "processed": 0,
            "total": 0,
            "percentage": 0.0,
            "valid": 0,
            "rejected": 0,
            "normal_count": 0,
            "suspicious_count": 0,
            "malicious_count": 0,
            "anomaly_count": 0,
            "watchlist_matches": 0,
            "drift_count": 0,
            "alerts_count": 0,
            "records_per_sec": 0.0,
            "status": "pending"
        }
        self.rejection_log: List[Dict[str, Any]] = []

class ImportService:
    def __init__(self, upload_dir: str = "./backend/uploads"):
        self.upload_dir = upload_dir
        os.makedirs(self.upload_dir, exist_ok=True)
        self.active_jobs: Dict[int, ActiveImportJob] = {}
        self.lock = threading.Lock()
        
    def _compute_sha256(self, file_path: str) -> str:
        """Computes SHA-256 hash of a file for duplicate detection."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def create_batch(self, file_path: str, filename: str, dataset_name: str = "", description: str = "") -> Dict[str, Any]:
        """
        Registers an uploaded file, creates the database record, and runs initial schema inspection.
        """
        file_size = os.path.getsize(file_path)
        file_hash = self._compute_sha256(file_path)
        detected_format = detect_file_format(file_path, filename)
        name = dataset_name.strip() or os.path.splitext(filename)[0]
        
        db = SessionLocal()
        try:
            # Check for existing duplicate batch by hash
            existing = db.query(ImportBatch).filter(ImportBatch.file_hash == file_hash).first()
            if existing:
                print(f"[IMPORT] Duplicate file detected (matches batch ID={existing.id}).")
                
            batch = ImportBatch(
                filename=filename,
                file_type=detected_format,
                file_size=file_size,
                file_hash=file_hash,
                dataset_name=name,
                description=description,
                status="pending",
                analysis_mode="analyze_only",
                uploaded_at=datetime.utcnow()
            )
            db.add(batch)
            db.commit()
            db.refresh(batch)
            batch_id = batch.id
            
            print(f"[IMPORT] Batch created | ID={batch_id} | file={filename} | format={detected_format.upper()}")
            
            # Initial inspection
            inspection = self.inspect_file(file_path, detected_format)
            
            batch.record_count = inspection.get("estimated_records", 0)
            batch.mapping_json = json.dumps(inspection.get("auto_mapping", {}))
            batch.capabilities_json = json.dumps(inspection.get("capabilities", {}))
            db.commit()
            
            num_cols = len(inspection.get("headers", []))
            auto_mapped = len(inspection.get("auto_mapping", {}))
            print(f"[IMPORT] Schema detected | {num_cols} columns | ~{batch.record_count} records")
            print(f"[IMPORT] Auto-mapped {auto_mapped} canonical fields")
            
            return {
                "batch_id": batch_id,
                "dataset_name": name,
                "filename": filename,
                "format": detected_format,
                "size_bytes": file_size,
                "estimated_records": batch.record_count,
                "headers": inspection.get("headers", []),
                "sample_rows": inspection.get("sample_rows", []),
                "auto_mapping": inspection.get("auto_mapping", {}),
                "capabilities": inspection.get("capabilities", {})
            }
        finally:
            db.close()

    def inspect_file(self, file_path: str, format_type: str) -> Dict[str, Any]:
        """Inspects sample rows and generates capability detection."""
        if format_type == "csv":
            return parse_csv_sample(file_path)
        elif format_type == "jsonl":
            return parse_jsonl_sample(file_path)
        elif format_type == "json":
            return parse_json_sample(file_path)
        elif format_type == "zeek":
            return parse_zeek_tsv_sample(file_path)
        elif format_type == "eve":
            return parse_suricata_eve_sample(file_path)
        elif format_type == "txt_ioc":
            return parse_txt_ioc(file_path)
        elif format_type == "pcap":
            return parse_pcap_sample(file_path)
        return parse_csv_sample(file_path)

    def update_mapping(self, batch_id: int, mapping: Dict[str, str]) -> Dict[str, Any]:
        """Saves user-corrected mappings and recalibrates capabilities."""
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            if not batch:
                raise ValueError("Batch not found")
                
            caps = detect_capabilities(mapping)
            batch.mapping_json = json.dumps(mapping)
            batch.capabilities_json = json.dumps(caps)
            db.commit()
            
            return {
                "batch_id": batch_id,
                "mapping": mapping,
                "capabilities": caps
            }
        finally:
            db.close()

    def validate_dataset(self, batch_id: int, file_path: str, mapping: Dict[str, str], max_sample: int = 200) -> Dict[str, Any]:
        """
        Runs validation pass over rows, identifying valid, invalid, and warning rows.
        """
        valid_cnt = 0
        invalid_cnt = 0
        warning_cnt = 0
        rejections = []
        
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            fmt = batch.file_type if batch else "csv"
        finally:
            db.close()
            
        streamer = self._get_streamer(file_path, fmt)
        
        for idx, raw_row in enumerate(streamer):
            if idx >= max_sample:
                break
            record, errors, warnings = self._normalize_single_record(raw_row, mapping, fmt, batch_id, "")
            if errors:
                invalid_cnt += 1
                if len(rejections) < 50:
                    rejections.append({"row_index": idx + 1, "errors": errors, "sample": raw_row})
            else:
                valid_cnt += 1
            if warnings:
                warning_cnt += 1
                
        print(f"[IMPORT] Validation sample completed | valid={valid_cnt} | rejected={invalid_cnt} | warnings={warning_cnt}")
        return {
            "sample_validated": idx + 1 if "idx" in locals() else 0,
            "valid_count": valid_cnt,
            "invalid_count": invalid_cnt,
            "warning_count": warning_cnt,
            "rejections": rejections
        }

    def _get_streamer(self, file_path: str, format_type: str) -> Generator[Dict[str, Any], None, None]:
        """Returns the appropriate memory-bounded generator for the format."""
        if format_type == "csv":
            return stream_csv_records(file_path)
        elif format_type == "jsonl":
            return stream_jsonl_records(file_path)
        elif format_type == "json":
            return stream_json_records(file_path)
        elif format_type == "zeek":
            return stream_zeek_tsv_records(file_path)
        elif format_type == "eve":
            return stream_suricata_eve_records(file_path)
        return stream_csv_records(file_path)

    def _normalize_single_record(
        self,
        raw_row: Dict[str, Any],
        mapping: Dict[str, str],
        format_type: str,
        batch_id: int,
        filename: str
    ) -> Tuple[Optional[NormalizedNetworkRecord], List[str], List[str]]:
        """
        Converts a single raw external row into a NormalizedNetworkRecord.
        Returns: (record, error_list, warning_list)
        """
        errors = []
        warnings = []
        
        # 1. IP validation
        src_ip_raw = raw_row.get(mapping.get("src_ip", ""))
        dest_ip_raw = raw_row.get(mapping.get("dest_ip", ""))
        
        valid_src, clean_src = validate_ip(src_ip_raw)
        if not valid_src:
            errors.append(f"Invalid source IP: '{src_ip_raw}'")
            
        valid_dst, clean_dst = validate_ip(dest_ip_raw)
        if not valid_dst:
            errors.append(f"Invalid destination IP: '{dest_ip_raw}'")
            
        # 2. Port validation
        src_port_raw = raw_row.get(mapping.get("src_port", ""))
        dest_port_raw = raw_row.get(mapping.get("dest_port", ""))
        
        valid_sport, clean_sport = validate_port(src_port_raw)
        if not valid_sport:
            warnings.append(f"Malformed source port '{src_port_raw}' defaulted to 0")
            clean_sport = 0
            
        valid_dport, clean_dport = validate_port(dest_port_raw)
        if not valid_dport:
            warnings.append(f"Malformed destination port '{dest_port_raw}' defaulted to 0")
            clean_dport = 0
            
        # 3. Protocol normalization
        proto_raw = raw_row.get(mapping.get("protocol", "OTHER"))
        proto_name, proto_id = normalize_protocol(proto_raw)
        
        # 4. Timestamp normalization
        ts_raw = raw_row.get(mapping.get("timestamp", ""))
        valid_ts, clean_ts = normalize_timestamp(ts_raw)
        if not valid_ts:
            warnings.append(f"Unparseable timestamp '{ts_raw}' defaulted to UTC now")
            
        # 5. Volumetric metrics (bytes, packets, duration)
        src_b = int(normalize_numerical(raw_row.get(mapping.get("src_bytes", ""))))
        dest_b = int(normalize_numerical(raw_row.get(mapping.get("dest_bytes", ""))))
        tot_b_mapped = int(normalize_numerical(raw_row.get(mapping.get("total_bytes", ""))))
        tot_b = tot_b_mapped if tot_b_mapped > 0 else (src_b + dest_b)
        
        src_p = int(normalize_numerical(raw_row.get(mapping.get("src_pkts", ""))))
        dest_p = int(normalize_numerical(raw_row.get(mapping.get("dest_pkts", ""))))
        pkt_cnt_mapped = int(normalize_numerical(raw_row.get(mapping.get("packet_count", ""))))
        pkt_cnt = pkt_cnt_mapped if pkt_cnt_mapped > 0 else max(1, src_p + dest_p)
        
        dur = normalize_numerical(raw_row.get(mapping.get("duration", "")), default=0.0)
        
        avg_pkt = float(tot_b / pkt_cnt) if pkt_cnt > 0 else 0.0
        
        label_raw = raw_row.get(mapping.get("label", ""))
        clean_label = str(label_raw).strip() if label_raw is not None else None
        
        info_raw = raw_row.get(mapping.get("info", ""))
        clean_info = str(info_raw).strip() if info_raw else None
        
        if errors:
            return None, errors, warnings
            
        record = NormalizedNetworkRecord(
            timestamp=clean_ts,
            src_ip=clean_src,
            dest_ip=clean_dst,
            src_port=clean_sport,
            dest_port=clean_dport,
            protocol=proto_name,
            duration=dur,
            src_bytes=src_b,
            dest_bytes=dest_b,
            total_bytes=tot_b,
            src_pkts=src_p,
            dest_pkts=dest_p,
            packet_count=pkt_cnt,
            avg_pkt_size=avg_pkt,
            proto_num=proto_id,
            ground_truth_label=clean_label,
            source="import",
            source_format=format_type,
            import_batch_id=batch_id,
            original_filename=filename,
            is_imported=True,
            info=clean_info
        )
        return record, errors, warnings

    def start_execution(
        self,
        batch_id: int,
        file_path: str,
        mode: str = "analyze_only",
        options: Optional[Dict[str, Any]] = None,
        broadcast_func=None
    ) -> bool:
        """
        Spawns background execution for the import batch.
        """
        options = options or {}
        with self.lock:
            if batch_id in self.active_jobs and self.active_jobs[batch_id].is_running:
                return False
                
            job = ActiveImportJob(batch_id)
            self.active_jobs[batch_id] = job
            job.is_running = True
            
            t = threading.Thread(
                target=self._run_import_worker,
                args=(job, file_path, mode, options, broadcast_func),
                daemon=True
            )
            job.thread = t
            t.start()
            return True

    def pause_job(self, batch_id: int) -> bool:
        with self.lock:
            job = self.active_jobs.get(batch_id)
            if not job or not job.is_running:
                return False
            job.pause_event.clear()
            job.is_paused = True
            job.progress["status"] = "paused"
            return True

    def resume_job(self, batch_id: int) -> bool:
        with self.lock:
            job = self.active_jobs.get(batch_id)
            if not job or not job.is_running:
                return False
            job.pause_event.set()
            job.is_paused = False
            job.progress["status"] = "processing"
            return True

    def cancel_job(self, batch_id: int) -> bool:
        with self.lock:
            job = self.active_jobs.get(batch_id)
            if not job or not job.is_running:
                return False
            job.cancel_event.set()
            job.pause_event.set() # Unblock if paused
            job.progress["status"] = "cancelling"
            return True

    def get_job_progress(self, batch_id: int) -> Dict[str, Any]:
        with self.lock:
            job = self.active_jobs.get(batch_id)
            if job:
                return job.progress
            
        # Fallback to DB record
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            if batch:
                return {
                    "batch_id": batch.id,
                    "processed": batch.valid_count + batch.invalid_count,
                    "total": batch.record_count,
                    "percentage": 100.0 if batch.status == "completed" else 0.0,
                    "valid": batch.valid_count,
                    "rejected": batch.invalid_count,
                    "normal_count": batch.normal_count,
                    "suspicious_count": batch.suspicious_count,
                    "malicious_count": batch.malicious_count,
                    "anomaly_count": batch.anomaly_count,
                    "watchlist_matches": batch.watchlist_matches,
                    "drift_count": batch.drift_count,
                    "alerts_count": batch.alerts_count,
                    "status": batch.status
                }
            return {}
        finally:
            db.close()

    def _run_import_worker(
        self,
        job: ActiveImportJob,
        file_path: str,
        mode: str,
        options: Dict[str, Any],
        broadcast_func
    ):
        """Worker thread executing the dataset import pipeline."""
        batch_id = job.batch_id
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            if not batch:
                return
            batch.status = "processing"
            batch.started_at = datetime.utcnow()
            batch.analysis_mode = mode
            db.commit()
            
            mapping = json.loads(batch.mapping_json or "{}")
            caps = json.loads(batch.capabilities_json or "{}")
            can_ml = caps.get("arf_classification", {}).get("supported", False)
            can_profile = caps.get("behaviour_profiling", {}).get("supported", False)
            filename = batch.filename
            fmt = batch.file_type
            
            # Load active watchlists into memory set for O(1) cross-referencing
            watchlist_items = db.query(WatchlistEntry).all()
            watch_ips = {w.value: w for w in watchlist_items if w.entry_type in ["ipv4", "ipv6"]}
            watch_domains = {w.value.lower(): w for w in watchlist_items if w.entry_type in ["domain", "hostname"]}
        finally:
            db.close()

        print(f"[IMPORT] Starting pipeline worker | Batch ID={batch_id} | Mode={mode.upper()}")
        
        # Instantiate AIEngine instance
        ai = AIEngine()
        
        # Supervised evaluation confusion matrix storage: matrix[true_label][pred_label]
        confusion_matrix = {"Normal": {"Normal": 0, "Suspicious": 0, "Malicious": 0},
                            "Suspicious": {"Normal": 0, "Suspicious": 0, "Malicious": 0},
                            "Malicious": {"Normal": 0, "Suspicious": 0, "Malicious": 0}}
        eval_total = 0
        eval_correct = 0

        # Timing & throttle parameters
        replay_speed = options.get("replay_speed", 1.0)
        isolate_profile = options.get("isolate_profile", False)
        streamer = self._get_streamer(file_path, fmt)
        
        total_estimate = batch.record_count or 1
        processed_count = 0
        valid_count = 0
        invalid_count = 0
        warning_count = 0
        
        normal_cnt = 0
        susp_cnt = 0
        mal_cnt = 0
        anomaly_cnt = 0
        watchlist_cnt = 0
        drift_cnt = 0
        alerts_cnt = 0
        
        start_ts = time.time()
        last_progress_broadcast = time.time()
        last_log_print = time.time()
        
        # Buffer for transaction batching
        logs_buffer: List[TrafficLog] = []
        alerts_buffer: List[Alert] = []
        
        for raw_row in streamer:
            # 1. Check Pause / Cancel
            job.pause_event.wait()
            if job.cancel_event.is_set():
                print(f"[IMPORT] Batch cancelled safely | ID={batch_id}")
                break
                
            processed_count += 1
            
            # 2. Normalize and Validate
            record, errors, warnings = self._normalize_single_record(raw_row, mapping, fmt, batch_id, filename)
            if errors:
                invalid_count += 1
                if len(job.rejection_log) < 100:
                    job.rejection_log.append({"row": processed_count, "errors": errors})
                continue
                
            valid_count += 1
            if warnings:
                warning_count += 1
                
            # 3. Watchlist IOC Correlation
            watchlist_hit = None
            if record.src_ip in watch_ips:
                watchlist_hit = watch_ips[record.src_ip]
            elif record.dest_ip in watch_ips:
                watchlist_hit = watch_ips[record.dest_ip]
            elif record.info:
                info_lower = record.info.lower()
                for dom, w_entry in watch_domains.items():
                    if dom in info_lower:
                        watchlist_hit = w_entry
                        break
                        
            if watchlist_hit:
                watchlist_cnt += 1
                print(f"[WATCHLIST] Match | Endpoint={record.src_ip}->{record.dest_ip} | IOC={watchlist_hit.value} | Batch={batch_id}")
                
            # 4. Machine Learning Classification (Strictly Inference Only unless Replay/Eval)
            label = "Normal"
            confidence = 0.85
            if can_ml and record.can_evaluate_ml():
                features, dur, tot_b = record.to_ai_features()
                pred_label, conf = ai.predict(features)
                label = str(pred_label)
                confidence = float(conf)
            elif watchlist_hit:
                label = "Suspicious"
                confidence = 0.90
                
            if label == "Normal": normal_cnt += 1
            elif label == "Suspicious": susp_cnt += 1
            elif label == "Malicious": mal_cnt += 1
            
            # Supervised evaluation tracking
            if mode == "label_eval" and record.ground_truth_label:
                gt = record.ground_truth_label.strip().capitalize()
                # Normalize ground truth aliases
                if gt in ["0", "Benign", "Normal"]: gt = "Normal"
                elif gt in ["1", "Attack", "Malicious", "Dos", "Ddos", "Portscan", "Botnet"]: gt = "Malicious"
                elif gt in ["Suspicious", "Probe"]: gt = "Suspicious"
                
                if gt in confusion_matrix and label in confusion_matrix[gt]:
                    confusion_matrix[gt][label] += 1
                    eval_total += 1
                    if gt == label:
                        eval_correct += 1
                        
            # 5. Device Behaviour Profiling (Controlled isolation)
            is_anomaly = False
            if can_profile and not isolate_profile:
                dev_res = device_profiler.process_flow(
                    src_ip=record.src_ip,
                    total_bytes=record.total_bytes,
                    duration=record.duration,
                    protocol=record.protocol,
                    hour_of_day=record.timestamp.hour if hasattr(record.timestamp, "hour") else 12,
                    packet_count=record.packet_count
                )
                if dev_res.get("is_anomalous"):
                    is_anomaly = True
                    anomaly_cnt += 1
                    
            # 6. Build TrafficLog model
            flow_source = f"replay:{filename}" if mode == "replay" else f"import:{batch_id}"
            t_log = TrafficLog(
                timestamp=record.timestamp,
                src_ip=record.src_ip,
                dest_ip=record.dest_ip,
                src_port=record.src_port,
                dest_port=record.dest_port,
                protocol=record.protocol,
                duration=int(record.duration),
                total_bytes=record.total_bytes,
                prediction_label=label,
                confidence_score=confidence,
                info=record.info or (f"Watchlist Match: {watchlist_hit.value}" if watchlist_hit else ""),
                source=flow_source,
                connection_state="N/A",
                import_batch_id=batch_id
            )
            logs_buffer.append(t_log)
            
            # 7. Check Alerts & Deduplication via Central Alert Manager
            # We flush DB periodically and attach alerts
            if len(logs_buffer) >= 200:
                self._flush_batch(logs_buffer, alerts_buffer, batch_id, mode, broadcast_func)
                
            # 8. Replay Speed Delay Throttling
            if mode == "replay" and replay_speed != "max":
                try:
                    delay = 0.05 / float(replay_speed)
                    time.sleep(delay)
                except Exception:
                    pass
                    
            # 9. Periodic Progress Updates
            now = time.time()
            if now - last_progress_broadcast >= 0.25 or processed_count == total_estimate:
                last_progress_broadcast = now
                elapsed = max(0.001, now - start_ts)
                rps = round(processed_count / elapsed, 1)
                pct = min(100.0, round((processed_count / total_estimate) * 100.0, 1))
                
                job.progress.update({
                    "processed": processed_count,
                    "total": total_estimate,
                    "percentage": pct,
                    "valid": valid_count,
                    "rejected": invalid_count,
                    "normal_count": normal_cnt,
                    "suspicious_count": susp_cnt,
                    "malicious_count": mal_cnt,
                    "anomaly_count": anomaly_cnt,
                    "watchlist_matches": watchlist_cnt,
                    "drift_count": drift_cnt,
                    "alerts_count": alerts_cnt,
                    "records_per_sec": rps,
                    "status": "cancelling" if job.cancel_event.is_set() else ("paused" if job.is_paused else "processing")
                })
                
                if broadcast_func:
                    broadcast_func({
                        "type": "import_progress",
                        "batch_id": batch_id,
                        "progress": job.progress
                    })
                    
            if now - last_log_print >= 5.0:
                last_log_print = now
                pct = round((processed_count / total_estimate) * 100.0, 1) if total_estimate > 0 else 0
                print(f"[IMPORT] Progress | {processed_count}/{total_estimate} | {pct}%")

        # Final Buffer Flush
        if logs_buffer or alerts_buffer:
            self._flush_batch(logs_buffer, alerts_buffer, batch_id, mode, broadcast_func)
            
        duration_total = time.time() - start_ts
        final_status = "cancelled" if job.cancel_event.is_set() else "completed"
        
        # Build Evaluation Metrics Object if label_eval
        eval_metrics = {}
        if mode == "label_eval" and eval_total > 0:
            acc = round(eval_correct / eval_total, 4)
            # Binary precision/recall for Malicious/Suspicious
            tp = confusion_matrix["Malicious"]["Malicious"]
            fp = confusion_matrix["Normal"]["Malicious"] + confusion_matrix["Suspicious"]["Malicious"]
            fn = confusion_matrix["Malicious"]["Normal"] + confusion_matrix["Malicious"]["Suspicious"]
            prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
            rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
            f1 = round(2 * (prec * rec) / (prec + rec), 4) if (prec + rec) > 0 else 0.0
            eval_metrics = {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1_score": f1,
                "total_evaluated": eval_total,
                "confusion_matrix": confusion_matrix
            }
            
        # Update Batch DB record
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            if batch:
                batch.status = final_status
                batch.completed_at = datetime.utcnow()
                batch.duration_sec = round(duration_total, 2)
                batch.valid_count = valid_count
                batch.invalid_count = invalid_count
                batch.warning_count = warning_count
                batch.normal_count = normal_cnt
                batch.suspicious_count = susp_cnt
                batch.malicious_count = mal_cnt
                batch.anomaly_count = anomaly_cnt
                batch.watchlist_matches = watchlist_cnt
                batch.drift_count = drift_cnt
                batch.alerts_count = db.query(Alert).filter(Alert.import_batch_id == batch_id).count()
                if eval_metrics:
                    batch.eval_metrics_json = json.dumps(eval_metrics)
                db.commit()
        finally:
            db.close()
            
        job.progress["status"] = final_status
        job.is_running = False
        
        if broadcast_func:
            broadcast_func({
                "type": "import_completed" if final_status == "completed" else "import_cancelled",
                "batch_id": batch_id,
                "final_summary": {
                    "batch_id": batch_id,
                    "filename": filename,
                    "status": final_status,
                    "total_processed": processed_count,
                    "valid_count": valid_count,
                    "invalid_count": invalid_count,
                    "normal_count": normal_cnt,
                    "suspicious_count": susp_cnt,
                    "malicious_count": mal_cnt,
                    "anomaly_count": anomaly_cnt,
                    "watchlist_matches": watchlist_cnt,
                    "duration_sec": round(duration_total, 2),
                    "eval_metrics": eval_metrics
                }
            })
            
        print(f"[IMPORT] Batch {final_status} | ID={batch_id} | Processed {processed_count} rows in {duration_total:.2f}s")

    def _flush_batch(
        self,
        logs_buffer: List[TrafficLog],
        alerts_buffer: List[Alert],
        batch_id: int,
        mode: str,
        broadcast_func
    ):
        """Flushes buffered records to SQLite in a single transaction."""
        if not logs_buffer:
            return
        db = SessionLocal()
        try:
            db.add_all(logs_buffer)
            db.flush() # Populate log.id
            
            alerts_to_add = []
            for log in logs_buffer:
                is_watch = bool(log.info and "Watchlist Match" in log.info)
                is_threat = log.prediction_label in ["Malicious", "Suspicious"]
                
                if is_watch or is_threat:
                    if is_watch:
                        alert_type = "watchlist_match"
                        threat_level = "High"
                        threat_type = "IOC Watchlist Cross-Correlation Hit"
                    else:
                        alert_type = "flow_classification"
                        threat_level = "Critical" if log.prediction_label == "Malicious" else "Medium"
                        threat_type = "Imported Volumetric / Flow Anomaly"
                        
                    notes = f"[IMPORT BATCH #{batch_id}] {threat_type} on {log.src_ip}->{log.dest_ip} ({log.protocol})"
                    if log.info:
                        notes += f" | Context: {log.info}"
                        
                    alert_obj = Alert(
                        traffic_log_id=log.id,
                        import_batch_id=batch_id,
                        alert_type=alert_type,
                        threat_level=threat_level,
                        status="New",
                        is_simulated=False,
                        notes=notes,
                        is_resolved=False,
                        count=1,
                        alert_time=log.timestamp,
                        last_seen=log.timestamp
                    )
                    alerts_to_add.append(alert_obj)
                    
            if alerts_to_add:
                db.add_all(alerts_to_add)
                
            db.commit()
            logs_buffer.clear()
            alerts_buffer.clear()
        except Exception as e:
            db.rollback()
            print(f"Error flushing import batch {batch_id}: {e}")
        finally:
            db.close()

    def delete_batch(self, batch_id: int) -> bool:
        """
        Cascading batch deletion: deletes all TrafficLog and Alert records tied
        to import_batch_id, deletes the batch record, and cleans up uploaded file.
        Leaves live/system traffic completely untouched.
        """
        db = SessionLocal()
        try:
            batch = db.query(ImportBatch).filter(ImportBatch.id == batch_id).first()
            if not batch:
                return False
                
            # If running, cancel first
            if batch_id in self.active_jobs:
                self.cancel_job(batch_id)
                
            # Delete alerts and traffic logs
            db.query(Alert).filter(Alert.import_batch_id == batch_id).delete(synchronize_session=False)
            db.query(TrafficLog).filter(TrafficLog.import_batch_id == batch_id).delete(synchronize_session=False)
            db.query(WatchlistEntry).filter(WatchlistEntry.import_batch_id == batch_id).delete(synchronize_session=False)
            
            # Remove file if exists
            fn = batch.filename
            fpath = os.path.join(self.upload_dir, fn)
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
                    
            db.delete(batch)
            db.commit()
            print(f"[IMPORT] Batch deleted safely | ID={batch_id}")
            return True
        except Exception as e:
            db.rollback()
            print(f"Error deleting import batch {batch_id}: {e}")
            return False
        finally:
            db.close()

# Global singleton import service
import_service = ImportService()
