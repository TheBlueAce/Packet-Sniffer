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

## Coming Soon: Windows Native Release
The fully compiled, standalone Windows version (`.exe`) is currently in the final stages of packaging. It will require no Docker or Python installationjust download and run. Unfortunately, this is only for a Windows machine so MacOS and Linux users will need to use the Docker version to run this project--so if you fall under that category, consider this the final release (if it does work). This will finally mark the end of the long-awaited final release of the project (for the 0 people who anticipated the release).

##  Bug Reports
If you encounter any issues with the Docker build or the packet analysis, please open an Issue in this repository!