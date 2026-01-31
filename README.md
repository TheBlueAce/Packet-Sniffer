# Packet Sniffer Pro

A cross-platform network traffic analyzer that took longer than it should have :.)
Built with a **C# (Avalonia UI)** frontend and a **Python (Scapy)** backend.

## Features
* **Real-Time Monitoring:** View packet headers, protocols (TCP, UDP, ICMP, etc.), and IPs.
* **Cross-Platform:** Runs seamlessly on Windows, Linux, and macOS via Docker.
* **File Logging:** Save captures to `.csv`, `.txt`, or `.pcap` for analysis in Splunk/Excel/Wireshark.
* **Filtering:** Apply BPF filters (e.g., `tcp port 80`) to isolate traffic.

## Docker Mode (Recommended for Devs)
This is the safest way to run the application in Development Mode or on non-Windows systems. It ensures all dependencies (Python, Scapy, Drivers) are pre-installed in an isolated container.

 **[Click here for the Docker Setup Guide](DOCKER_README.md)**

*(Includes instructions for Windows, Linux, and macOS saving paths)*

---

## Windows Native Release
**[Download the latest Windows Release (.zip)](https://github.com/TheBlueAce/Packet-Sniffer/releases/latest)**
1.  **Download** and unzip the file.
2.  **Install** [Npcap](https://npcap.com/) (Required driver).
3.  **Run** `SnifferAvalonia.exe`.

##  Bug Reports
If you encounter any issues with the Docker build or the packet analysis, please open an Issue in this repository!
