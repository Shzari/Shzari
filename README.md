# Network Web SSH Automation App

A web-based network engineering app that lets you log in, select routers/switches (all/some/by group), and run troubleshooting commands over SSH. Output opens in a new window.

## Features implemented
- Login page with auth mode selection:
  - **ISE credentials** (UI mode selector)
  - **Local device login**
- Device inventory with group tags (routers, switches, branches, ATM, etc.)
- Selection controls:
  - Select all
  - Clear
  - Select by group
  - Choose specific devices
- Command execution panel:
  - Built-in troubleshooting/show command buttons
  - Add your own command button dynamically
  - Manual command box for any typed command
- Output page opens in a **new window/tab** and shows per-device execution results

## Important note about PuTTY
Web apps cannot directly automate PuTTY GUI sessions in-browser. This app uses backend **SSH** (Paramiko), which is the correct approach for browser-based automation.

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```
Open:
- http://localhost:8080

## Configure your devices
Edit `devices_web.json`:
```json
[
  {
    "name": "branch-rtr-01",
    "host": "10.10.10.1",
    "port": 22,
    "groups": ["branches", "routers"]
  }
]
```

## How to use
1. Login with your local or ISE credentials.
2. Select one/many devices or a group.
3. Click a predefined button OR type a manual command.
4. Submit to run command via SSH on selected devices.
5. Output opens in a new window.

## Security recommendations
- Replace default Flask secret via `APP_SECRET_KEY` environment variable.
- Use HTTPS/reverse proxy in production.
- Prefer read-only show commands for troubleshooting profiles.
- Integrate real ISE/AAA verification if needed (current ISE option is UI-mode selection).
