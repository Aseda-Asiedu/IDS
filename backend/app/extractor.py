import time
from scapy.all import IP, TCP, UDP, ICMP

class FlowRecord:
    def __init__(self, src_ip, dest_ip, src_port, dest_port, protocol):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.protocol_l7 = None
        self.info = None
        self.connection_state = "INIT" if protocol == 'TCP' else "STATELESS"
        
        # Timing
        self.start_time = time.time()
        self.last_seen = time.time()
        
        # Statistics
        self.sbytes = 0  # Bytes from source to destination
        self.dbytes = 0  # Bytes from destination to source
        self.splt = []   # Packet inter-arrival times for source
        self.dplt = []   # Packet inter-arrival times for destination
        self.packet_count = 0
        
        self.src_last_time = None
        self.dest_last_time = None

    def extract_l7_info(self, packet):
        """
        Attempts to extract L7 protocols and metadata (HTTP Host, DNS Query, TLS SNI).
        """
        try:
            # Check DNS
            if self.protocol == 'UDP':
                from scapy.layers.dns import DNS
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    if dns.qd:
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode('utf-8', errors='ignore')
                        if qname.endswith('.'):
                            qname = qname[:-1]
                        self.protocol_l7 = "DNS"
                        self.info = f"DNS Query: {qname}"
                        return
            
            # Check TCP
            if self.protocol == 'TCP':
                from scapy.all import TCP
                if packet.haslayer(TCP) and packet[TCP].payload:
                    payload = bytes(packet[TCP].payload)
                    # Check HTTP
                    if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HTTP/1."):
                        self.protocol_l7 = "HTTP"
                        host = None
                        for line in payload.split(b"\r\n"):
                            if line.lower().startswith(b"host:"):
                                host = line[5:].strip().decode('utf-8', errors='ignore')
                                break
                        req_line = payload.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                        if host:
                            self.info = f"HTTP Host: {host}"
                        else:
                            self.info = f"HTTP: {req_line}"
                        return
                    
                    # Check TLS/HTTPS
                    if self.src_port == 443 or self.dest_port == 443:
                        self.protocol_l7 = "HTTPS"
                        sni = self.parse_tls_sni(payload)
                        if sni:
                            self.info = f"HTTPS/TLS SNI: {sni}"
                        else:
                            self.info = "HTTPS/TLS Session"
                        return
        except Exception:
            pass

    def parse_tls_sni(self, payload):
        """
        Parses TLS Client Hello handshake raw bytes to extract Server Name Indication (SNI).
        """
        try:
            if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
                return None
            pos = 43
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            
            cipher_suites_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
            pos += 2 + cipher_suites_len
            
            comp_len = payload[pos]
            pos += 1 + comp_len
            
            if pos + 2 > len(payload):
                return None
            ext_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
            pos += 2
            
            end_pos = pos + ext_len
            while pos + 4 <= end_pos and pos + 4 <= len(payload):
                ext_type = int.from_bytes(payload[pos:pos+2], byteorder='big')
                ext_data_len = int.from_bytes(payload[pos+2:pos+4], byteorder='big')
                pos += 4
                
                if ext_type == 0x00:  # Server Name extension
                    if pos + 2 > len(payload):
                        return None
                    list_len = int.from_bytes(payload[pos:pos+2], byteorder='big')
                    pos += 2
                    
                    if pos + 3 > len(payload):
                        return None
                    name_type = payload[pos]
                    name_len = int.from_bytes(payload[pos+1:pos+3], byteorder='big')
                    pos += 3
                    
                    if name_type == 0x00 and pos + name_len <= len(payload):
                        return payload[pos:pos+name_len].decode('utf-8', errors='ignore')
                pos += ext_data_len
        except Exception:
            pass
        return None

    def add_packet(self, packet, direction):
        """
        direction: 'src_to_dst' or 'dst_to_src'
        """
        now = time.time()
        self.last_seen = now
        self.packet_count += 1
        
        # Packet length
        pkt_len = len(packet)
        
        if direction == 'src_to_dst':
            self.sbytes += pkt_len
            if self.src_last_time is not None:
                self.splt.append(now - self.src_last_time)
            self.src_last_time = now
        else:
            self.dbytes += pkt_len
            if self.dest_last_time is not None:
                self.dplt.append(now - self.dest_last_time)
            self.dest_last_time = now
            
        # Update TCP connection state
        if self.protocol == 'TCP' and packet.haslayer(TCP):
            try:
                flags = packet[TCP].flags
                flag_str = str(flags)
                
                if "S" in flag_str and "A" not in flag_str:
                    self.connection_state = "SYN_SENT"
                elif "S" in flag_str and "A" in flag_str:
                    self.connection_state = "SYN_RCVD"
                elif "F" in flag_str:
                    self.connection_state = "FIN_WAIT"
                elif "R" in flag_str:
                    self.connection_state = "RESET"
                elif "A" in flag_str:
                    if self.connection_state in ["SYN_SENT", "SYN_RCVD", "INIT"]:
                        self.connection_state = "ESTABLISHED"
                    elif self.connection_state == "FIN_WAIT":
                        self.connection_state = "CLOSED"
            except Exception:
                pass
            
        # Attempt L7 parsing if not yet resolved
        if not self.info:
            self.extract_l7_info(packet)

    def get_features(self):
        """
        Returns a list of numeric features matching our model inputs:
        [sbytes, dbytes, splt_mean, dplt_mean, proto_id, packet_count, avg_pkt_size]
        """
        duration = max(0.001, self.last_seen - self.start_time)
        splt_mean = sum(self.splt) / len(self.splt) if self.splt else 0.0
        dplt_mean = sum(self.dplt) / len(self.dplt) if self.dplt else 0.0
        
        # Protocol encoding: TCP = 1, UDP = 2, ICMP = 3, Others = 0
        if self.protocol == 'TCP':
            proto_id = 1
        elif self.protocol == 'UDP':
            proto_id = 2
        elif self.protocol == 'ICMP':
            proto_id = 3
        else:
            proto_id = 0
            
        total_bytes = self.sbytes + self.dbytes
        avg_pkt_size = total_bytes / self.packet_count if self.packet_count > 0 else 0.0
        
        return [
            float(self.sbytes),
            float(self.dbytes),
            float(splt_mean),
            float(dplt_mean),
            float(proto_id),
            float(self.packet_count),
            float(avg_pkt_size)
        ], duration, total_bytes



class FlowFeatureExtractor:
    def __init__(self, flow_timeout=2.0, callback=None):
        """
        flow_timeout: Timeout in seconds to declare a flow complete.
        callback: Function to call when a flow is compiled and ready for classification.
        """
        self.active_flows = {}
        self.flow_timeout = flow_timeout
        self.callback = callback
        self.current_source = "live"

    def process_packet(self, packet):
        """
        Decodes a Scapy packet and routes it to the appropriate flow.
        """
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dest_ip = ip_layer.dst
        
        # Determine protocol and ports
        protocol = 'OTHER'
        src_port = 0
        dest_port = 0
        
        if packet.haslayer(TCP):
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
            
        # Create flow keys (forward and backward directions)
        key_fwd = (src_ip, dest_ip, src_port, dest_port, protocol)
        key_bwd = (dest_ip, src_ip, dest_port, src_port, protocol)
        
        # Route packet
        if key_fwd in self.active_flows:
            self.active_flows[key_fwd].add_packet(packet, 'src_to_dst')
        elif key_bwd in self.active_flows:
            self.active_flows[key_bwd].add_packet(packet, 'dst_to_src')
        else:
            # New flow
            new_flow = FlowRecord(src_ip, dest_ip, src_port, dest_port, protocol)
            new_flow.add_packet(packet, 'src_to_dst')
            self.active_flows[key_fwd] = new_flow

        # Periodically check and clean expired flows
        self.check_expired_flows()

    def check_expired_flows(self, force=False):
        """
        Checks active flows and removes any that have exceeded the timeout window.
        Expired flows are compiled and passed to the callback function.
        """
        now = time.time()
        expired_keys = []
        
        for key, flow in list(self.active_flows.items()):
            if force or (now - flow.last_seen >= self.flow_timeout):
                # Compile features
                features, duration, total_bytes = flow.get_features()
                
                # Trigger callback (Inference pipeline)
                flow.source = getattr(self, "current_source", "live")
                if self.callback:
                    self.callback(flow, features, duration, total_bytes)
                    
                expired_keys.append(key)
                
        for key in expired_keys:
            if key in self.active_flows:
                del self.active_flows[key]
