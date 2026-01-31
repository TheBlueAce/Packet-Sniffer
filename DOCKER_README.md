
# Packet Sniffer Pro - Docker Edition

This guide explains how to run the Packet Sniffer in Docker container.

## Prereqs
1.  **Docker Desktop** installed and running.
2.  **VcXsrv (XLaunch)** installed (Required to see the GUI on Windows).

## Setup (Do this once)
1.  **Build the Image:**
    Open your terminal in the project folder and run:
    ```powershell
    docker build -t packet-sniffer-pro .
    ```

# Packet Sniffer Pro - Docker Edition

This guide explains how to run the Packet Sniffer in Docker container.

## Prereqs
1.  **Docker Desktop** installed and running.
2.  **VcXsrv (XLaunch)** installed (Required to see the GUI on Windows).

## Setup (Do this once)
1.  **Build the Image:**
    Open your terminal in the project folder and run:
    ```powershell
    docker build -t packet-sniffer-pro .
    ```

## How to Launch the App?
To see the window, you must start the X-Server first.

### 1. Start XLaunch
Run **XLaunch** and use these EXACT settings:
* **Display Settings:** Multiple windows (Next)
* **Client Startup:** Start no client (Next)
* **Extra Settings:**
    * Native opengl (**UNCHECK THIS** - Fixes disappearing buttons)
    * Disable access control (**CHECK THIS** - Required)
* **Finish**

### 2. Run the Container
Paste this command into PowerShell:
```powershell
docker run -it --rm --net=host --privileged -e DISPLAY=host.docker.internal:0.0 -v ${PWD}:/data packet-sniffer-pro
```
To see the window, you must start the X-Server first.


### 1. Start XLaunch
Run **XLaunch** and use these EXACT settings:
* **Display Settings:** Multiple windows (Next)
* **Client Startup:** Start no client (Next)
* **Extra Settings:**
    * Native opengl (**UNCHECK THIS** - Fixes disappearing buttons)
    * Disable access control (**CHECK THIS** - Required)
* **Finish**

### 2. Run the Container
Paste this command into PowerShell:
```powershell
docker run -it --rm --net=host --privileged -e DISPLAY=host.docker.internal:0.0 -v ${PWD}:/data packet-sniffer-pro
```

---
 
## Cross-Platform Saving Guide
To save files successfully, you must map your current folder to the container's `/data` folder. The command flag changes slightly depending on your Operating System:

| OS / Terminal | Flag to use in `docker run` | Where to save in GUI |
| :--- | :--- | :--- |
| **Windows (PowerShell)** | `-v ${PWD}:/data` | `/data/my_capture` |
| **Windows (CMD)** | `-v %cd%:/data` | `/data/my_capture` |
| **Linux / macOS** | `-v $(pwd):/data` | `/data/my_capture` |

**Example (MacOS/Linux):**
```bash
docker run -it --rm --net=host --privileged -e DISPLAY=$DISPLAY -v $(pwd):/data packet-sniffer-pro
