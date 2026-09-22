import threading
from scapy.all import sniff, PcapReader, get_if_list
from .extractor import FlowFeatureExtractor
import time

class PacketSnifferService:
    def __init__(self, callback=None):
        """
        callback: Function that receives the FlowRecord and its extracted features.
        """
        self.extractor = FlowFeatureExtractor(flow_timeout=2.0, callback=callback)
        self.sniff_thread = None
        self.is_sniffing = False
        self.interface = None
        self.interface_desc = None
        self.arp_alert_callback = None
        self.arp_table = {}
        
        # PPS and packet volume tracking variables
        self.packet_counter = 0
        self.total_packets_captured = 0
        self.last_pps_time = time.time()
        self.counter_lock = threading.Lock()

    def get_available_interfaces(self):
        """
        Returns a list of local interface names.
        """
        try:
            from scapy.all import IFACES
            interfaces = []
            for iface in IFACES.values():
                desc = iface.description or iface.name
                if desc:
                    if iface.ip and iface.ip != "127.0.0.1" and iface.ip != "0.0.0.0":
                        desc = f"{desc} ({iface.ip})"
                    interfaces.append(desc)
            if not interfaces:
                return ["Wi-Fi", "Ethernet", "Loopback"]
            return sorted(list(set(interfaces)))
        except Exception as e:
            print(f"Error fetching interfaces: {e}")
            return ["Wi-Fi", "Ethernet", "Loopback"]

    def _process_sniffed_packet(self, packet):
        """
        Safely increments the packet counter and processes the packet.
        """
        if self.is_sniffing:
            with self.counter_lock:
                self.packet_counter += 1
                self.total_packets_captured += 1
            
            # ==============================================================================
            # === ALGORITHM: Passive Layer-2 ARP Spoofing / MitM Detector ===
            # Purpose: Detects duplicate IP-to-MAC associations across gratuitous/unicast ARP replies
            # ==============================================================================
            try:
                from scapy.all import ARP
                if packet.haslayer(ARP):
                    arp_pkt = packet[ARP]
                    # op = 2 is ARP reply
                    if arp_pkt.op == 2:
                        ip_src = arp_pkt.psrc
                        mac_src = arp_pkt.hwsrc
                        if ip_src and mac_src:
                            if ip_src in self.arp_table:
                                old_mac = self.arp_table[ip_src]
                                if old_mac != mac_src:
                                    # Trigger MitM detection alert callback
                                    if self.arp_alert_callback:
                                        self.arp_alert_callback(ip_src, old_mac, mac_src)
                            else:
                                self.arp_table[ip_src] = mac_src
            except Exception as e:
                print(f"Error checking ARP spoofing: {e}")
                
            self.extractor.process_packet(packet)

    def _sniff_worker(self):
        """
        The sniffing loop running in a background thread.
        """
        print(f"Sniffer thread started on interface: {self.interface} ({self.interface_desc})")
        try:
            while self.is_sniffing:
                sniff(
                    iface=self.interface,
                    prn=self._process_sniffed_packet,
                    timeout=1.0,
                    store=False
                )
        except Exception as e:
            print(f"Error in sniff worker: {e}")
            self.is_sniffing = False
        print("Sniffer thread terminated.")

    def get_pps(self):
        """
        Calculates packets per second since the last call and resets the counter.
        """
        now = time.time()
        with self.counter_lock:
            elapsed = now - self.last_pps_time
            if elapsed <= 0.05:
                return 0
            pps = int(self.packet_counter / elapsed)
            self.packet_counter = 0
            self.last_pps_time = now
        return pps

    def get_total_packets(self):
        """
        Returns the cumulative count of raw packets processed by the sensor.
        """
        with self.counter_lock:
            return self.total_packets_captured

    def start_sniffing(self, interface_name=None):
        """
        Spawns a new background thread to sniff live traffic.
        """
        if self.is_sniffing or (self.sniff_thread and self.sniff_thread.is_alive()):
            print("Sniffer is already running or stopping.")
            return False

        real_iface_name = None
        resolved_desc = None

        # Try to resolve user-friendly dropdown description back to raw system interface GUID/name
        if interface_name and interface_name != "None":
            try:
                from scapy.all import IFACES
                for iface in IFACES.values():
                    desc = iface.description or iface.name
                    desc_with_ip = f"{desc} ({iface.ip})" if iface.ip and iface.ip != "127.0.0.1" and iface.ip != "0.0.0.0" else desc
                    
                    if interface_name in [desc, desc_with_ip, iface.name]:
                        real_iface_name = iface.name
                        resolved_desc = desc
                        break
            except Exception as e:
                print(f"Error resolving interface description: {e}")

        # Autoselect default active interface if none resolved
        if not real_iface_name:
            try:
                from scapy.all import get_working_if
                working_iface = get_working_if()
                if working_iface:
                    real_iface_name = working_iface.name
                    resolved_desc = working_iface.description or working_iface.name
            except Exception as e:
                print(f"Error resolving default working interface: {e}")
                
        if not real_iface_name:
            interfaces = self.get_available_interfaces()
            if interfaces:
                # Find matching interface for the first friendly option
                first_opt = interfaces[0]
                try:
                    from scapy.all import IFACES
                    for iface in IFACES.values():
                        desc = iface.description or iface.name
                        desc_with_ip = f"{desc} ({iface.ip})" if iface.ip and iface.ip != "127.0.0.1" and iface.ip != "0.0.0.0" else desc
                        if first_opt in [desc, desc_with_ip, iface.name]:
                            real_iface_name = iface.name
                            resolved_desc = desc
                            break
                except Exception:
                    pass

        if not real_iface_name:
            real_iface_name = "Wi-Fi"  # Graceful fallback
            resolved_desc = "Wi-Fi"

        self.interface = real_iface_name
        self.interface_desc = resolved_desc
        self.is_sniffing = True
        self.sniff_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self.sniff_thread.start()
        return True

    def stop_sniffing(self):
        """
        Terminates the live sniffing thread and forces flushing of active flows.
        """
        if not self.is_sniffing:
            print("Sniffer is not running.")
            return False

        self.is_sniffing = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2.0)
            if not self.sniff_thread.is_alive():
                self.sniff_thread = None
            
        # Clear remaining flows in cache instead of flushing to prevent alert flood on pause
        self.extractor.active_flows.clear()
        print("Sniffer stopped successfully.")
        return True

    def process_pcap_file(self, file_path):
        """
        Streams packets from an offline PCAP file. Runs synchronously or as a separate task.
        """
        print(f"Starting PCAP file parsing: {file_path}")
        start_time = time.time()
        pkt_count = 0
        
        try:
            # Use PcapReader for streaming to prevent memory exhaustion
            with PcapReader(file_path) as pcap_reader:
                for packet in pcap_reader:
                    self.extractor.process_packet(packet)
                    pkt_count += 1
                    
                    # Yield CPU control occasionally
                    if pkt_count % 1000 == 0:
                        time.sleep(0.01)
                        
            # Flush final remaining flows
            self.extractor.check_expired_flows(force=True)
            duration = time.time() - start_time
            print(f"Completed PCAP parse: {pkt_count} packets processed in {duration:.2f} seconds.")
            return True, pkt_count
        except Exception as e:
            print(f"Error reading PCAP file: {e}")
            return False, 0
            
    def get_status(self):
        return {
            "is_sniffing": self.is_sniffing,
            "active_interface": self.interface,
            "active_flows_count": len(self.extractor.active_flows)
        }
