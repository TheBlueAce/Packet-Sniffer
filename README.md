# Packet Sniffer Pro

A cross-platform network traffic analyzer. 
Built with a **C# (Avalonia UI)** frontend and a **Python (Scapy)** engine.

## Prerequisite Windows !
**You MUST have [Npcap](https://npcap.com/#download) installed.**
* During installation, check the box: **"Install Npcap in WinPcap API-compatible Mode"**.
* Without this driver, the app cannot see network traffic.

---

## Dev Mode (If you just wanna run it or Tinker with it)

If you want to modify the code + run the app, follow these steps.

### 1. Python Setup (The Engine)
The C# app relies on a backend Python script. You need to set up the environment so `python` commands have the required libraries (Scapy).

# 1. Navigate to the root folder
cd Packet-Sniffer

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the environment
# Windows (Command Prompt):
.venv\Scripts\activate.bat
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Mac/Linux (Not too sure if it works yet for yall):
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Compile
"pyinstaller --noconfirm --clean --onedir --name sniffer_engine sniffer_gui.py"

# 6. Follow the instructions inside the README.md 
Make sure that sniffer_engine.exe is inside engine folder AND _internal is inside it with all the contents

# 7. Run the GUI
(Optional) You can run the python.exe to test if it works ".\engine\sniffer_engine.exe --duration 3 --count 5"
dotnet build
dotnet run

Whazam
