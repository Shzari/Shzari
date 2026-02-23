# Network Web SSH Automation App

A web-based network engineering app to authenticate users, select routers/switches (all/some/by group), and run troubleshooting commands over SSH.

## Key Features
- Login supports:
  - **Local login**
  - **Cisco ISE (RADIUS) authentication**
- Built-in **ISE network settings** page section in login UI:
  - ISE server
  - RADIUS auth port
  - shared secret (key)
  - timeout
  - NAS-IP-Address
- Device controls:
  - select all / clear
  - select by group
  - select specific devices
- Command controls:
  - predefined buttons
  - add custom command buttons
  - rename existing button names from GUI
  - RUN button
- Output behavior:
  - output window opens first run
  - next runs reuse same window
  - cumulative outputs append down the page

## Configure devices
Edit `devices_web.json`.

## Configure ISE auth
Open login page and use **ISE Network Settings** submenu.
Set:
- ISE server address
- RADIUS port (default 1812)
- shared secret key
- timeout
- NAS-IP

Then select **ISE Credentials (RADIUS)** in Auth Mode and login with username/password.

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Security Notes
- Set `APP_SECRET_KEY` in environment.
- Put app behind HTTPS reverse proxy for production.
- Prefer least-privilege and read-only command profiles.
- `ise_settings.json` contains secret material; secure file permissions and storage.
