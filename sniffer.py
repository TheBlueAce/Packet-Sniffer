from scapy.all import Ether, IP, IPv6, TCP, UDP, sniff
from scapy.utils import PcapWriter
from scapy.layers.inet import TCP, UDP, ICMP 
from scapy.layers.inet6 import IPv6
from scapy.layers.sctp import SCTP
import time
import threading
import os
import csv

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
    
    def __init__(self, count: int = 0, duration: int = 0, packet_logging: bool = True, terminal_logging: bool = False, file_name: str = "pcap_file", ext: str = ".txt", filter_str: str = None):
        
        # User set attributes, feel free to change in code
        self.count = count
        self.duration = duration
        self.packet_logging = packet_logging
        self.terminal_logging = terminal_logging
        self.file_name = file_name
        self.ext = ext
        self.filter_str = filter_str
        
        # You should not change these attributes' values directly
        self._packets_sniffed = 0    # Total packets seen by sniff() (including those not logged)
        self._packet_count = 0       # Number of packets successfully processed and counted/logged
        self._captured_packets = []  # In-memory list to store captured packets if needed (unused by default)
        self._pcap_file = None       # File handle for .txt/.csv logging (None when no log is open)
        self._stop_event = None      # threading.Event used to signal threads (animation) to stop
        self._prev_file = None       # Path to the most recently created log file
        self._csv_writer = None      # csv.writer instance used when logging to CSV
        
    # HANDLING PACKETS AND INFORMATION - SECTION 1
    
    def get_ethernet_info(self, packet):
        """
        Summary: A Helper method to obtain the ethernet frame information in a packet and
            returns it for logging purposes within process_packet
            
        Args:
            packet: Gets an IP Packet, within it might be an ethernet frame

        Returns:
            None: If there is no ethernet frame within a packet, we move on
            dst_mac, src_mac, proto: If there is an ethernet frame, gets the destination, source,
                and ethernet type of the packet, then returns it for use in process_packet func
        """

        if Ether in packet:
            dst_mac = packet[Ether].dst
            src_mac = packet[Ether].src
            ethernet_frame = packet[Ether].type
            return dst_mac, src_mac, ethernet_frame
        
        else:
            return None

    def get_transport_info(self, packet):
        """
        Summary: A Helper method to obtain the IP information in a packet and
            returns it for logging purposes within process_packet
            
        Args:
            packet: An IP Packet where within the header might be the source and destination IP

        Returns:
            None: If there is no IP src or dst within a packet, we move on
            dst_ip, src_ip, proto: If there is a IP information, gets the destination, source,
                and protocol of the packet, then returns it for use in process_packet func
        """

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
        """
        Summary: The main method that brings together all the data that will be printed/logged, the funcation that
                the packet is passed to
        
        Args:
            packet: An IP Packet where within the header might be the source and destination IP
            track: a bool where it checks if

        Returns:
            N/A
            Once again, this function kinda just digests information.
        """
        try:
            timestamp = time.strftime("%m/%d/%Y %H:%M:%S", time.localtime())
            ethernet_info = self.get_ethernet_info(packet)
            ip_info = self.get_transport_info(packet)
            
            ethernet_data = ip_data = None
        
            # getting ethernet obv
            if ethernet_info:
                dst_mac, src_mac, ether_proto = ethernet_info
                ethernet_data = f"[{timestamp}] Ethernet | DST = {dst_mac}, SRC = {src_mac}, EtherType = {ether_proto}"
            else:
                dst_mac = src_mac = ether_proto = None
            
            # a little complicated here so comments for myself
            if ip_info:
                src_ip, dst_ip, src_port, dst_port, ip_proto = ip_info
                
                # this part was cuz ip protocol num might be a str or int cuz scapy is weird
                if isinstance(ip_proto, str):
                    
                    # if its a string we can try to format it properly
                    # try to find the numeric code that matches this label
                    proto_num = next((num for num, name in self.PROTO_TABLE.items() if name == ip_proto), None)
                    if proto_num is not None:
                        proto_display = f"{ip_proto} ({proto_num})"
                    else:
                        proto_display = ip_proto
                else:
                    # otherwise, look it up in our class proto table. Then its cool to display
                    proto_name = self.PROTO_TABLE.get(ip_proto, "Unknown")
                    proto_display = f"{proto_name} ({ip_proto})"
                    
                # diff protos have different displays, make it consistent (ICP and ICMP ex.)
                src_repr = f"{src_ip}:{src_port}" if src_port is not None else src_ip
                dst_repr = f"{dst_ip}:{dst_port}" if dst_port is not None else dst_ip
                
                ip_data = f"[{timestamp}] IP Info | Proto = {proto_display}, SRC = {src_repr} -> DST = {dst_repr}"
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
                            self._pcap_file.write(ethernet_data + "\n")
                        else:
                            self._pcap_file.write("Ethernet info for this packet was lost!\n")
                            
                        if ip_info:
                            self._pcap_file.write(ip_data + "\n")
                        else:
                            self._pcap_file.write("IP info for this packet was lost!\n")
                            
                        self._pcap_file.write("\n")
                        self._pcap_file.flush()
        except Exception as e:
            print(f"[DEBUG] Failed to process packet: {e}")
            return
            
                        

    # LOGGING FUNCTIONS - SECTION 2
    
    def print_data(self, ethernet_data, ip_data):
        
        if ethernet_data:
            print(ethernet_data)
            
        if ip_data:
            print(ip_data)
                
        print()
        
    def enable_logging(self, track=True):
        """
        Summary: Initializes file logging for packet capture with support for CSV, PCAP, and TXT formats. 
        Creates a new file with an incremented filename if a file already exists.
        
        
        Args: track (bool): A boolean flag to enable or disable file logging. Defaults to True. When True, creates and initializes a log file; 
            when False, returns immediately without creating any file.
        
        Returns: None, This method does not return any value. It configures internal file handles and writers as side effects.
        
        Quick Note: The method automatically handles file naming conflicts by appending an incremented counter to the filename (e.g., filename(1), filename(2)). 
        The file format (CSV, PCAP, or TXT) is determined by the instance's `self.ext` attribute and initializes the appropriate writer accordingly.
        """
        if not track:
            return
        
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
                "Destination IP", "Destination Port", "Source MAC", 
                "Destination MAC", "EtherType"
            ])
        elif self.ext == ".pcap":
            self._pcap_writer = PcapWriter(full_file, append=False, sync=True)
            self._pcap_file = None
        else: # .txt
            self._pcap_file = open(full_file, "w")
            self._pcap_file.write("Packet capture log\n\n")
    
    def close_log(self):
        """
        Summary: This method is called at the end of the packet sniffer in the "finally" block, closes file if it was even open

        Args: None

        Returns: N/A
        """
        if self._pcap_file is not None:
                self._pcap_file.close()
                self._pcap_file = None
        if hasattr(self, "_pcap_writer") and self._pcap_writer is not None:
            self._pcap_writer.close()
            self._pcap_writer = None
            

    def listening_animation(self):
        """
        Summary: Simply for the listening animation, used if terminal logging is off. Kinda cool, this is how I learn threading

        Args:
            stop_event: A threading event used to act as a flag for the function to run, while it is not set then this will run
            
        Returns: N/A
        """

        dots = 0
        period = "."
        while not self._stop_event.is_set():
            print(f"\rListening{period * dots}   ", end="")
            dots += 1
            if (dots % 4 == 0):
                dots = 0
            
            self._stop_event.wait(timeout=1)

    # PACKET SNIFFER - SECTION 3

    def start(self):
        """
        Summary: The method used to start the packet sniffer is in here
                If we want to get technical, the stop is in the finally block

        Args:
            count: an int, determines how many packets you track, for infinite leave as is or 0
            duration: an int, determines how long (in seconds) the sniffer runs for. If 0, runs infinitely
            packet_logging: a bool, determines if there is a file that keeps track of packets
            terminal_logging: a bool, decides if terminal is printing contents or not
        """
        
        self.enable_logging(self.packet_logging)
        start_time = time.monotonic()

        try:
            self._stop_event = threading.Event()
            animation = threading.Thread(target=self.listening_animation)
            
            if not self.terminal_logging:
                animation.start()
            
            # prn = pkt, basically the packet passes into process packet then it gets "digested"
            # count = how many packets you want
            # timeout = the actual supported timeout function by scapy
            # 
            
            packets = sniff(prn=lambda pkt: self.process_packet(pkt, track=self.packet_logging, printing = self.terminal_logging),
                            count=self.count,
                            timeout=self.duration if self.duration>0 else None,
                            filter=self.filter_str,
                            store=0
                            )
            self._packets_sniffed = self._packet_count
            
        except Exception as e:
            print(f"\nError during sniffing: {e}")
            
        finally:
            
            self._stop_event.set()
            
            if animation.is_alive():
                animation.join()
            
            # just adding the final line in a .csv if it is a .csv file, idk where else to place it
            if self.ext == ".csv" and self._pcap_file is not None:
                try:
                    self._csv_writer.writerow([])
                    self._csv_writer.writerow(["Summary", f"Total Packets: {self._packet_count}"])
                    self._pcap_file.flush()
                except Exception as e:
                    print(f"Error: could not write summary row ({e})")
                    
            self.close_log()
            
            end_time = time.monotonic()
            elapsed_time = end_time - start_time
            
            print("\rListening Done!        ")
            print("Results this session...")
            print(f"{self._packets_sniffed} sniffed, {self._packet_count} packets successfully collected after {elapsed_time:.2f}s!")
            
            self._packet_count = 0 # For if the user wanted to run the packet sniffer again
