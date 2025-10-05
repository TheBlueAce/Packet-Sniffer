from scapy.all import Ether, IP, IPv6, TCP, UDP, sniff
import time
import threading
import os

pcap_file = None
packet_count = 0

# HANDLING PACKETS AND INFORMATION - SECTION 1

# For ethernet information
def get_ethernet_info(packet):
    """
    Summary: A Helper function to obtain the ethernet frame information in a packet and
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

def get_transport_info(packet):
    """
    Summary: A Helper function to obtain the IP information in a packet and
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


def process_packet(packet, track = False, printing = True):
    """
    Summary: The main function that brings together all the data that will 
        
    Args:
        packet: An IP Packet where within the header might be the source and destination IP

    Returns:
        None: If there is no IP src or dst within a packet, we move on
        dst_ip, src_ip, proto: If there is a IP information, gets the destination, source,
            and protocol of the packet, then returns it for use in process_packet func
    """
    
    timestamp = time.strftime("%m:%d:%y, %H:%M:%S", time.localtime())
    ethernet_info = get_ethernet_info(packet)
    ip_info = get_transport_info(packet)
    
    if ethernet_info is not None:
        dst_mac, src_mac, ether_proto = ethernet_info
        ethernet_data = f"[{timestamp}] Ethernet | DST = {dst_mac}, SRC = {src_mac}, EtherType = {ether_proto}"
        
        if printing:
            print(ethernet_data)
        if track and pcap_file is not None:
            pcap_file.write(ethernet_data + "\n")
            pcap_file.flush()

    if ip_info is not None:
        src_ip, dst_ip, src_port, dst_port, ip_proto = ip_info
        ip_data = f"[{timestamp}] IP Info | Proto = {ip_proto}, SRC = {src_ip} : {src_port} -> DST = {dst_ip} : {dst_port}"
        
        if printing:
            print(ip_data)
            
        if track and pcap_file is not None:
            pcap_file.write(ip_data + "\n")
            pcap_file.flush()
            
    if track and pcap_file is not None:
        pcap_file.write("\n") 
        
    if ip_info is not None and ethernet_info is not None:
        global packet_count
        packet_count += 1
        
    if printing:
        print()
    
# LOGGING FUNCTIONS - SECTION 2

def enable_logging(track=True, file_name="pcap_file.txt"):
    """
    Summary: The function that enables file logging of packets received, opens the file in the directory that the script is ran in
        Use the global variable pcap_file where the file is opened and closed, set to None initially
    Args:
        track: a boolean value that is set to True automatically, True means a file will be created and storing packets
        if false, has no file

    Returns:
        None: If track is set to false
        Otherwise: N/A
    
    This function does not return anything if set to true, it is just to enable the creation of the file
    """
    
    global pcap_file
    base_dir = os.path.dirname(__file__)
    
    if track:
        base_dir = os.path.dirname(__file__)
        file_name = os.path.join(base_dir, "pcap_file.txt")
        print(f"File will be saved at: {os.path.abspath(file_name)}")
        
        pcap_file = open(file_name, "w")
        pcap_file.write("Save Packet details before running again!\nOtherwise, data will be lost upon running again!\n\n")
        #print(f"pcap_file opened: {not pcap_file.closed}") Debugging
        #print(f"Logging enabled, writing to {file_name}")
        
    else:
        pcap_file = None
    
def close_log():
    """
    Summary: This function is called at the end of the packet sniffer in the "finally" block, closes file if it was even open
    
    Args: None
    
    Returns: N/A
    """
    
    global pcap_file
    if pcap_file is not None:
        pcap_file.close()


def listening_animation(stop_event):
    """
    Summary: Simply for the listening animation, used if terminal logging is off

    Args:
        stop_event: A threading event used to act as a flag for the function to run, while it is not set then this will run
        
    Returns: N/A
    """
    
    dots = 0
    period = "."
    while not stop_event.is_set():
        print(f"\rListening{period * dots}   ", end="")
        dots += 1
        if (dots % 4 == 0):
            dots = 0
        
        time.sleep(2)
    
# PACKET SNIFFER - SECTION 3

# The packet sniffer itself
def packet_sniffer(count=0, packet_logging = True, terminal_logging = False):
    """
    Summary: The packet sniffer uses a combination of all the functions above,
    
    Args:
        count: an int, determines how many packets you track, for infinite leave as is or 0
        packet_logging: a bool, determines if there is a file that keeps track of packets
        terminal_logging: a bool, decides if terminal is printing contents or not
    """
    
    enable_logging(packet_logging)
    start_time = time.time()
    
    try:
        stop_event = threading.Event()
        animation = threading.Thread(target=listening_animation, args=(stop_event,))
        
        if not terminal_logging:
            animation.start()
        
        packets = sniff(prn=lambda pkt: process_packet(pkt, track=packet_logging, printing = terminal_logging), count=count)
        packets_sniffed = len(packets)

        
    finally:
        close_log()
        stop_event.set()
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        
        print("\rListening Done!        ")
        print(f"{packets_sniffed} sniffed, {packet_count} packets successfully collected after {elapsed_time:.2f}s!")
        packet_count = 0
        
