# Sniffer Engine Folder

This folder is meant to contain the compiled Python backend (`sniffer_gui.exe`).
The executable is **not included** in this repository to keep the download size small and secure.

## How to Build the Engine
If you are a developer and want to build the engine yourself:

1. Navigate to the root folder of this repository.
2. Install Python dependencies:
   `pip install -r requirements.txt`
3. Run PyInstaller:
   `pyinstaller --onefile --noconsole --name sniffer_gui sniffer_gui.py`
4. Move the resulting `.exe` from `dist/` into this folder (`SnifferAvalonia/engine/`).

In the end, it should look like:
    \engine
        \_internal
        README.md
        sniffer_engine.exe