import sniffer

# Run this file!
# Edit count to 0 if you want infinite run time, or to any amount to sniff that many packets
packet_sniffer = sniffer.PacketSniffer(count=0, duration=10, packet_logging = True, terminal_logging=False)
packet_sniffer.start()

