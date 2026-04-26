# Downpour v28 Titanium — Launcher Guide

## Available Launchers

### Recommended: `LAUNCH.bat`

The unified launcher. Run as Administrator for full functionality.

```cmd
LAUNCH.bat
```

What it does:
1. Locates your Python installation automatically
2. Applies a Defender path exclusion for the project folder
3. Installs `psutil` and `cryptography` if missing
4. Launches `downpour_v28_titanium.py`

### Direct Python launch

```cmd
python downpour_v28_titanium.py
```

### Python launchers (legacy — use LAUNCH.bat instead)

| File | Notes |
|---|---|
| `launch_downpour_v28_ultimate.py` | Installs deps then launches |
| `launch_downpour_v28_error_free.py` | Conservative import guards |
| `working_ultimate_launcher.py` | Minimal launcher |

---

## Troubleshooting Launch Failures

**Python not found**
Make sure Python 3.9+ is on your PATH. Download from https://python.org.

**Missing packages**
```cmd
pip install -r requirements.txt
```

**GUI does not appear**
Check `downpour.log` in the project folder for the startup error.

**Access denied / UAC prompt**
Right-click `LAUNCH.bat` and choose "Run as administrator".

**Defender quarantining files**
Run `LAUNCH.bat` as Administrator once — it adds a path exclusion automatically.
Wait about 60 seconds for the exclusion to take effect, then relaunch.

---

## Verifying a Successful Launch

The application opens a Tkinter window titled "Downpour v28 Titanium".
The status bar at the bottom shows the active module count.
Log output goes to `downpour.log` in the project folder.
