import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import Ether, IP, IPv6, TCP, UDP, sniff
from scapy.utils import PcapWriter
from scapy.layers.inet import TCP, UDP, ICMP 
from scapy.layers.inet6 import IPv6
from scapy.layers.sctp import SCTP
import time
import threading
import os
import csv
import sys
import socket
import queue
import argparse

class PacketSniffer:
    
    PROTO_TABLE = {
        1: "ICMP",          # Internet Control Message Protocol (IPv4)
        2: "IGMP",          # Internet Group Management Protocol
        6: "TCP",           # Transmission Control Protocol
        17: "UDP",          # User Datagram Protocol
        41: "IPv6 Encapsulation",
        47: "GRE",          # Generic Routing Encapsulation
        50: "ESP",          # Encapsulating Security Payload
        51: "AH",           # Authentication Header
        58: "ICMPv6",       # Internet Control Message Protocol (IPv6)
        89: "OSPF",         # Open Shortest Path First
        132: "SCTP"         # Stream Control Transmission Protocol
    }
    
    def __init__(self, count: int = 0, duration: int = 0, packet_logging: bool = True, terminal_logging: bool = False, file_name: str = "pcap_file", ext: str = ".txt", filter_str: str = None, outfile: str = None):
        
        # User set attributes, feel free to change in code
        self.count = count
        self.duration = duration
        self.packet_logging = packet_logging
        self.terminal_logging = terminal_logging
        self.file_name = file_name
        self.ext = ext
        self.filter_str = filter_str
        self.outfile = outfile 
        
        # You should not change these attributes' values directly
        self._packets_sniffed = 0    # Total packets seen by sniff() (including those not logged)
        self._packet_count = 0       # Number of packets successfully processed and counted/logged
        self._captured_packets = []  # In-memory list to store captured packets if needed (unused by default)
        self._pcap_file = None       # File handle for .txt/.csv logging (None when no log is open)
        self._pcap_writer = None     # For writing in pcap files
        self._stop_event = None      # threading.Event used to signal threads (animation) to stop
        self._prev_file = None       # Path to the most recently created log file
        self._csv_writer = None      # csv.writer instance used when logging to CSV
        self._first_packet_time = None # Tracks time that first packet arrives
        self.dns_cache = {}          # Stores names of host names we already came across, IP : hostname
        self.dns_queue = queue.Queue()  # Queue to resolve IP lookups
        self.cache_lock = threading.Lock() # kinda like Mutex
        
    # HANDLING PACKETS AND INFORMATION - SECTION 1
    
    def get_ethernet_info(self, packet):
        if Ether in packet:
            dst_mac = packet[Ether].dst
            src_mac = packet[Ether].src
            ethernet_frame = packet[Ether].type
            return dst_mac, src_mac, ethernet_frame
        
        else:
            return None

    def get_transport_info(self, packet):
        # Table for referencing well known protocols
        proto_table = {
            6:   (TCP, "TCP"),
            17:  (UDP, "UDP"),
            132: (SCTP, "SCTP"),
        }

        ip_layer = IP if IP in packet else IPv6 if IPv6 in packet else None

        if ip_layer is None:
            return None

        else:
            
            # Sine IPv6 and IPv4 grab protocol differently, heres handle case
            if ip_layer is IP:
                proto = packet[ip_layer].proto
            else:
                proto = packet[ip_layer].nh
                
            dst_ip = packet[ip_layer].dst
            src_ip = packet[ip_layer].src
            
            # Refer to proto table for special protocols
            if proto in proto_table and proto_table[proto][0] in packet:
                layer, label = proto_table[proto]
                src_port = packet[layer].sport
                dst_port = packet[layer].dport
                return src_ip, dst_ip, src_port, dst_port, label
            else:
                return src_ip, dst_ip, None, None, proto


    def process_packet(self, packet, track : bool = True, printing : bool = True):
        try:
            if self.count and self._packet_count >= self.count:
                return
            
            if self._first_packet_time is None:
                self._first_packet_time = time.monotonic()
                
            timestamp = time.strftime("%H:%M:%S", time.localtime()) # Changed to Time Only for cleaner GUI
            ethernet_info = self.get_ethernet_info(packet)
            ip_info = self.get_transport_info(packet)
            
            ethernet_data = ip_data = None
        
            # getting ethernet obv
            if ethernet_info:
                dst_mac, src_mac, ether_proto = ethernet_info
                ethernet_data = f"[{timestamp}] Ethernet | {src_mac} -> {dst_mac}"
            else:
                dst_mac = src_mac = ether_proto = None
            
            # a little complicated here so comments for myself
            if ip_info:
                src_ip, dst_ip, src_port, dst_port, ip_proto = ip_info
                hostname = self.get_hostname(dst_ip)
                
                # this part was cuz ip protocol num might be a str or int cuz scapy is weird
                if isinstance(ip_proto, str):
                    
                    # if its a string we can try to format it properly
                    # try to find the numeric code that matches this label
                    proto_num = next((num for num, name in self.PROTO_TABLE.items() if name == ip_proto), None)
                    if proto_num is not None:
                        proto_display = f"{ip_proto}" # Removed ID for cleaner look
                    else:
                        proto_display = ip_proto
                else:
                    # otherwise, look it up in our class proto table. Then its cool to display
                    proto_name = self.PROTO_TABLE.get(ip_proto, "Unknown")
                    proto_display = f"{proto_name}"
                    
                # diff protos have different displays, make it consistent (ICP and ICMP ex.)
                src_repr = f"{src_ip}:{src_port}" if src_port is not None else src_ip
                dst_repr = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
                
                ip_data = f"[{timestamp}] {proto_display} | {src_repr} -> {dst_repr} | Host: {hostname}"
            else:
                src_ip = dst_ip = src_port = dst_port = ip_proto = None
            
            if printing:
                self.print_data(ethernet_data, ip_data)
                
            if ip_info is not None and ethernet_info is not None:
                self._packet_count += 1
                        
            if track: # if we even want a log file
                
                if self.ext == ".csv" and ip_info and ethernet_info: #.csv
                    
                    # normalize protocol name again for CSV output
                    if isinstance(ip_proto, str):
                        # Try to map the label back to a number
                        proto_num = next((num for num, name in self.PROTO_TABLE.items()
                                          if name == ip_proto), None)
                        if proto_num is not None:
                            proto_display = f"{ip_proto} ({proto_num})"
                        else:
                            proto_display = ip_proto
                    else:
                        proto_name = self.PROTO_TABLE.get(ip_proto, "Unknown")
                        proto_display = f"{proto_name} ({ip_proto})"

                    # make sure blank cells stay blank instead of showing "None"
                    src_port = src_port if src_port is not None else ""
                    dst_port = dst_port if dst_port is not None else ""
                    
                    self._csv_writer.writerow([
                        timestamp,
                        proto_display,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        hostname,
                        src_mac,
                        dst_mac,
                        ether_proto
                    ])
                    self._pcap_file.flush()
                    return
                
                elif self.ext == ".pcap": #.pcap obv
                    if self._pcap_writer is not None:
                        self._pcap_writer.write(packet)
                    return
                
                else: #.txt handling
                        
                    if self._pcap_file is not None:
                        if ethernet_info:
                            self._pcap_file.write(f"[{timestamp}] Ethernet | DST = {dst_mac}, SRC = {src_mac}, EtherType = {ether_proto}" + "\n")
                        else:
                            self._pcap_file.write("Ethernet info for this packet was lost!\n")
                            
                        if ip_info:
                            src_repr = f"{src_ip}:{src_port}" if src_port is not None else src_ip
                            dst_repr = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
                            file_ip_data = f"[{timestamp}] IP Info | Hostname = {hostname}, Proto = {proto_display}, SRC = {src_repr} -> DST = {dst_repr}"
                            self._pcap_file.write(file_ip_data + "\n")
                        else:
                            self._pcap_file.write("IP info for this packet was lost!\n")
                            
                        self._pcap_file.write("\n")
                        self._pcap_file.flush()
        except Exception as e:
            # print(f"[DEBUG] Failed to process packet: {e}") 
            return
                    
                        

    # LOGGING FUNCTIONS - SECTION 2
    
    def print_data(self, ethernet_data, ip_data):
        if ip_data:
            print(ip_data, flush=True)
        elif ethernet_data:
            print(ethernet_data, flush=True)
    
    def _dedupe_path(self, full_file: str):
        if not os.path.exists(full_file):
            return full_file

        folder = os.path.dirname(full_file) or "."
        base = os.path.splitext(os.path.basename(full_file))[0]
        ext = os.path.splitext(full_file)[1]

        i = 1
        while True:
            candidate = os.path.join(folder, f"{base}({i}){ext}")
            if not os.path.exists(candidate):
                return candidate
            i += 1
    
    def enable_logging(self, track=True):
        if not track:
            return

        # if user supplied a full output path, use it exactly
        if self.outfile:
            full_file = self._dedupe_path(self.outfile)
            _, out_ext = os.path.splitext(full_file)
            if out_ext:
                self.ext = out_ext.lower()
                
        else:
            # determine where to write log files.
            
            if getattr(sys, "frozen", False):
                base_dir = os.getcwd()
            else:
                base_dir = os.path.dirname(__file__)

            full_file = os.path.join(base_dir, f"{self.file_name}{self.ext}")

            file_instances = 1
            
            while os.path.exists(full_file):
                full_file = os.path.join(base_dir, f"{self.file_name}({file_instances}){self.ext}")
                file_instances += 1

        self._prev_file = full_file

        if self.ext == ".csv":
            self._pcap_file = open(full_file, "w", newline="")
            self._csv_writer = csv.writer(self._pcap_file)
            self._csv_writer.writerow([
                "Timestamp", "Protocol", "Source IP", "Source Port",
                "Destination IP",  "Destination Port", "Hostname", "Source MAC", 
                "Destination MAC", "EtherType"
            ])
        elif self.ext == ".pcap":
            self._pcap_writer = PcapWriter(full_file, append=False, sync=True)
            self._pcap_file = None
        else: # .txt
            self._pcap_file = open(full_file, "w")
            self._pcap_file.write("Packet capture log\n\n")
    
    def close_log(self):
        if self._pcap_file is not None:
                self._pcap_file.close()
                self._pcap_file = None
        if hasattr(self, "_pcap_writer") and self._pcap_writer is not None:
            self._pcap_writer.close()
            self._pcap_writer = None
            

    # HOST-NAME FINDER - SECTION 3
    def _stdin_stop_listener(self):
        try:
            for line in sys.stdin:
                if line.strip().upper() == "STOP":
                    self._stop_event.set()
                    break
        except Exception:
            pass
    
    def dns_worker(self):
        while True:
            ip_to_resolve = self.dns_queue.get()
            try:
                
                # if already cached skip resolving
                with self.cache_lock:
                    if ip_to_resolve in self.dns_cache:
                        continue

                try:
                    hostname, _ = socket.getnameinfo((ip_to_resolve, 0), 0)
                except Exception:
                    hostname = "N/A"

                with self.cache_lock:
                    self.dns_cache[ip_to_resolve] = hostname

            except Exception:
                # osha violation if worker dies
                pass
            
            finally:
                try:
                    self.dns_queue.task_done()
                except Exception:
                    pass
    def get_hostname(self, ip_addr):
        with self.cache_lock:
            if ip_addr in self.dns_cache:
                return self.dns_cache[ip_addr]
    
        self.dns_queue.put(ip_addr)
        
        return "Unknown"

    # PACKET SNIFFER - SECTION 4

    def start(self):
        
        self.enable_logging(self.packet_logging)
        
        # Shows where file should be saved
        if self.packet_logging and self._prev_file:
            print(f"[FILE] {self._prev_file}", flush=True)
        else:
            print("[FILE] (not saving)", flush=True)
            
        self._first_packet_time = None
        
        # creates 50 threads 0_0
        for _ in range(50):
            t = threading.Thread(target=self.dns_worker, daemon=True)
            t.start()
        
        try:
            self._stop_event = threading.Event()
            listener = threading.Thread(target=self._stdin_stop_listener, daemon=True)
            listener.start()    
            
            deadline = None
            
            def should_stop(pkt):
                if self._stop_event.is_set():
                    return True

                if self.count and self._packet_count >= self.count:
                    return True

                if self.duration and self.duration > 0 and self._first_packet_time is not None:
                    if time.monotonic() >= (self._first_packet_time + self.duration):
                        return True

                return False
                
            while not self._stop_event.is_set():
                
                if deadline is None and self.duration and self.duration > 0 and self._first_packet_time is not None:
                    deadline = self._first_packet_time + self.duration
    
                # stop on duration
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sniff_timeout = min(0.05, remaining)
                else:
                    sniff_timeout = 0.25

                if self.count and self.count > 0 and self._packet_count >= self.count:
                    break
                
                # sniff in short bursts so we can notice STOP quickly
                _ = sniff(
                    prn=lambda pkt: self.process_packet(pkt, track=self.packet_logging, printing=self.terminal_logging),
                    timeout=sniff_timeout,
                    filter=self.filter_str,
                    store=0,
                    stop_filter=should_stop
                )

            self._packets_sniffed = self._packet_count
            
        except Exception as e:
            print(f"[ERROR] {e}")
            
        finally:
            
            self._stop_event.set()
            
            end_time = time.monotonic()
            if self._first_packet_time is not None:
                elapsed_time = end_time - self._first_packet_time
            else:
                elapsed_time = 0.0
            
            # just adding the final line in a .csv if it is a .csv file, idk where else to place it
            if self.ext == ".csv" and self._pcap_file is not None:
                try:
                    self._csv_writer.writerow([])
                    self._csv_writer.writerow(["Summary", f"Total Packets: {self._packet_count} | Total Duration: {elapsed_time}"])
                    self._pcap_file.flush()
                except Exception as e:
                    pass
            
            self.close_log()
            
            print(f"[SUMMARY] Packets: {self._packet_count} | Duration: {elapsed_time:.2f}s | File: {self._prev_file}")
            
            self._packet_count = 0 # For if the user wanted to run the packet sniffer again
    
# For GUI use later I thinks        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer Engine")
    
    parser.add_argument("--duration", type = int, default = 0, help = "Sniffing duration in seconds (0 for infinite)")
    parser.add_argument("--count", type = int, default = 0, help = "Number of packets to capture")
    parser.add_argument("--filter", type = str, default = None, help = "BPF Filter string (e.g. 'tcp port 80')")
    parser.add_argument("--filename", type = str, default = "packet_capture", help = "Output filename base")
    parser.add_argument("--format", type = str, default = ".csv", help="Output format (.txt, .csv, .pcap)")
    parser.add_argument("--outfile", type=str, default=None, help="Full output file path (overrides --filename/--format)")
    parser.add_argument("--save", action="store_true", help="Enable saving to file")
    
    args = parser.parse_args()
    
    sniffer = PacketSniffer(
        count=args.count,
        duration=args.duration,
        packet_logging=args.save,
        terminal_logging=True,
        file_name=args.filename,
        ext=args.format,
        outfile=args.outfile,
        filter_str=args.filter
    )
    
    sniffer.start()