
# Packet-Sniffer

Packet Sniffer that can be run in terminal easily.

  

### To start the program, run the main.py file.

 You can edit some of the variables as you like.

**count (int)**: Set to 0 to capture as long as you don't stop the program, otherwise set to how many packets you want to sniff

**packet_logging (bool)**: Set to False if you do not want to log the packets captured in a file, otherwise if True it will create a "pcap_file.txt" file and log everything in there.

 - Running the file again with this option will reset the contents of the file for every session!

**terminal_logging (bool)**: Set to False if you do not want to flood the terminal with all the packet data (imo preferable), otherwise shows all the packets in terminal.

Until a proper way to stop the program is implemented, the only way to stop sniffing is

&emsp;*Windows + Linux*: Ctrl + "C"<br>

&emsp;*Mac*: Command + "."

WIP Project btw