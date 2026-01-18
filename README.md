

# Packet-Sniffer

Packet Sniffer that can be run in terminal easily. Compatible with .txt, .pcap, and .csv formats!

Works with Wireshark, Excel, and Splunk. More tools that support .pcap, .csv, and .txt formats accepted (I hope)!

### To start the program, run menu.py OR sniffer.py
For menu.py
&emsp;- You still need to download sniffer.py <br>
&emsp;- Run it, it has everything...did not test for bugs though to be honest...<br>
For sniffer.py
&emsp;- Running it with arguments in CLI works so...<br>
&emsp;- "--duration" (int) = How long in seconds to run <br>
&emsp;- "--count" (int) = How many packets do you want to capture <br>
&emsp;- "--filter" (str) = BPF Filter string (e.g. 'tcp port 80') <br>
&emsp;- "--filename" (str) = Name of file that info will be stored in<br>
&emsp;- "--format" (str) = File format <br>
Heres an example for Filtering for traffic on Port 80, running for 60s or capturing 5k packets, file name is going to be test, and will be a pcap file:
python sniffer.py --filter "port 80" --duration 60 --count 5000 --filename "test" --format ".pcap"<br>
*You can check the code for their default values too!*

If you set the packet sniffer to run infinitely, in Terminal, to stop it, use...<br>
&emsp;*Windows + Linux*: Ctrl + "C"<br>
&emsp;*Mac*: Command + "."<br>
Planning on adding...<br>
&emsp;- Graphic User Interface compatible on all platforms (Avalonia UI coming soon)<br>
&emsp;- An actual name instead of just "Packet Sniffer"<br>

Thanks for reading, hope you enjoy! If you find any bugs, please let me know. FYI My machine is Windows so idk how it works on Mac.
