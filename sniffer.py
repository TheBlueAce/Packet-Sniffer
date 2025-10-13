from scapy.all import Ether, IP, IPv6, TCP, UDP, sniff
import time
import threading
import os

class PacketSniffer:

    def __init__(self, count: int = 0, duration: int = 0, packet_logging: bool = True, terminal_logging: bool = False):
        
        # User set attributes, feel free to change in code
        self.count = count
        self.duration = duration
        self.packet_logging = packet_logging
        self.terminal_logging = terminal_logging
        
        # You should not change these attributes' values directly
        self._packets_sniffed = 0
        self._packet_count = 0
        self._pcap_file = None
        self._stop_event = None
        
    # HANDLING PACKETS AND INFORMATION - SECTION 1
    
    # For ethernet information
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
            6: (TCP, "TCP"),
            17: (UDP, "UDP")
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
        Summary: The main method that brings together all the data that will be printed/logged, shows
        Timestamps
        Ethernet info
        IP info
        
        Args:
            packet: An IP Packet where within the header might be the source and destination IP
            track: a bool where it checks if

        Returns:
            N/A
            Once again, this function kinda just digests information.
        """

        timestamp = time.strftime("%m/%d/%Y %H:%M:%S", time.localtime())
        ethernet_info = self.get_ethernet_info(packet)
        ip_info = self.get_transport_info(packet)

        if ethernet_info is not None:
            dst_mac, src_mac, ether_proto = ethernet_info
            ethernet_data = f"[{timestamp}] Ethernet | DST = {dst_mac}, SRC = {src_mac}, EtherType = {ether_proto}"
            
            if printing:
                print(ethernet_data)
            if track and self._pcap_file is not None:
                self._pcap_file.write(ethernet_data + "\n")
                self._pcap_file.flush()

        if ip_info is not None:
            src_ip, dst_ip, src_port, dst_port, ip_proto = ip_info
            ip_data = f"[{timestamp}] IP Info | Proto = {ip_proto}, SRC = {src_ip} : {src_port} -> DST = {dst_ip} : {dst_port}"
            
            if printing:
                print(ip_data)
                
            if track and self._pcap_file is not None:
                self._pcap_file.write(ip_data + "\n")
                self._pcap_file.flush()
                
        if track and self._pcap_file is not None:
            self._pcap_file.write("\n") 
            
        if ip_info is not None and ethernet_info is not None:
            self._packet_count += 1
            
        if printing:
            print()

    # LOGGING FUNCTIONS - SECTION 2

    def enable_logging(self, track=True, file_name="pcap_file.txt"):
        """
        Summary: The method that enables file logging of packets received, opens the file in the directory that the script is ran in
            Use the global variable pcap_file where the file is opened and closed, set to None initially
        Args:
            track: a boolean value that is set to True automatically, True means a file will be created and storing packets
            if false, has no file

        Returns:
            None: If track is set to false
            Otherwise: N/A

        This function does not return anything if set to true, it is just to enable the creation of the file
        """

        base_dir = os.path.dirname(__file__)

        if track:
            base_dir = os.path.dirname(__file__)
            file_name = os.path.join(base_dir, "pcap_file.txt")
            print(f"File will be saved at: {os.path.abspath(file_name)}")
            
            self._pcap_file = open(file_name, "w")
            self._pcap_file.write("Save Packet details before running again!\nOtherwise, data will be lost upon running again!\n\n")
        

    def close_log(self):
        """
        Summary: This method is called at the end of the packet sniffer in the "finally" block, closes file if it was even open

        Args: None

        Returns: N/A
        """

        if self._pcap_file is not None:
            self._pcap_file.close()


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
            
            time.sleep(1)

    def sniffing_duration(self):
        """
        Summary: This is to make the sniffer stop after x seconds. Sets the stop flag after x seconds
                 Works by running the loop for the duration set by user, for every check, sees if
                 the flag was set, if so then just exit the function
                 if reaches the bottom before flag is set, sets it here
        Args: N/A
        
        Returns: _
        """
        for _ in range(self.duration):
            if self._stop_event.is_set():
                return
            time.sleep(1)
        
        self._stop_event.set()

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
        start_time = time.time()

        try:
            self._stop_event = threading.Event()
            animation = threading.Thread(target=self.listening_animation)
            timer = threading.Thread(target=self.sniffing_duration)
            
            if not self.terminal_logging:
                animation.start()
                
            if self.duration != 0:
                timer.start()
            
            # prn = pkt, basically the packet passes into process packet then it gets "digested"
            # count = how many packets you want
            # stop_filter = stop once the stop event flag is set
            
            packets = sniff(prn=lambda pkt: self.process_packet(pkt, track=self.packet_logging, printing = self.terminal_logging),
                            count=self.count,
                            stop_filter= lambda _: self._stop_event.is_set()
                            )
            
            self._stop_event.set()
            self._packets_sniffed = len(packets)

        finally:
            self.close_log()
            self._stop_event.set()
            if not self.terminal_logging:
                animation.join()
                
            if self.duration != 0:
                timer.join()
            
            end_time = time.time()
            elapsed_time = end_time - start_time
            
            print("\rListening Done!        ")
            print("Results this session...")
            print(f"{self._packets_sniffed} sniffed, {self._packet_count} packets successfully collected after {elapsed_time:.2f}s!")
        
