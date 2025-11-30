import argparse
from sniffer import PacketSniffer

def main():
    
    # CLI parser, grabs args in certain format
    parser = argparse.ArgumentParser(description="Headless Mode for Packet Sniffer")
    
    parser.add_argument("--duration", type=int, default=10, help="Sniff duration in seconds")
    parser.add_argument("--filename", type=str, default="capture", help="Name of log-file")
    parser.add_argument("--filter", type=str, default="", help="BPF Filter (tcp port 80)")
    parser.add_argument("--format", type=str, default=".csv", help="File extension (.txt, .csv, .pcap)")
    
    args = parser.parse_args()
    
    
    print(f"Starting Sniffer... Duration: {args.duration}s | Filter: '{args.filter}'")
    
    sniffer = PacketSniffer(
        duration=args.duration,
        file_name=args.filename,
        ext=args.format,
        filter_str=args.filter,
        terminal_logging=True, 
        packet_logging=True
    )
    
    sniffer.start()
    
if __name__ == "__main__":
    main()