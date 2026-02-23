# Network Web SSH Automation App

A web-based network engineering app to authenticate users, select routers/switches, run troubleshooting commands over SSH, and manage Cisco ISE auth settings with super-admin protection.

## Key Features
- Login supports:
  - Local login
  - Cisco ISE (RADIUS) login
- Super Admin security workflow:
  - First run requires creating a super admin account
  - Settings page requires super admin verification
- ISE settings page supports:
  - Primary ISE server/port/shared-secret
  - Secondary ISE server/port/shared-secret
  - Timeout and NAS-IP
- Category/group workflow:
  - split view: Groups list on left and Devices list on right
  - drag-select one or more groups, then devices list updates
  - devices list shows 15 rows with scroll for larger inventories
  - create category from GUI
  - add devices to category from GUI
  - delete category from GUI
  - Add Device popup (hostname + IP + category drag-list)
  - Add Device popup includes **Test** button for dual connectivity checks (ICMP ping + SSH TCP/22)
  - ICMP ping test supports both Linux/macOS and Windows hosts running the web app
  - duplicate hostname/IP validation when adding device
  - edit and delete devices from GUI
- Command workflow:
  - command buttons and custom buttons
  - command preview before RUN
  - RUN button
  - output window opens first run, then reuses
  - output history appends down page

## First-Time Setup
1. Start app.
2. Open web UI.
3. Create Super Admin account.
4. From login page click **Settings (Super Admin)**.
5. Verify Super Admin and configure primary/secondary ISE.

## Run
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Security Notes
- Set `APP_SECRET_KEY`.
- Protect `super_admin.json` and `ise_settings.json` permissions.
- Use HTTPS/reverse-proxy in production.
