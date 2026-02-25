# Network Web SSH Automation App

A web-based network engineering app to authenticate users, select routers/switches, run troubleshooting commands over SSH, and manage Cisco ISE auth settings with super-admin protection.

## Key Features
- Login supports:
  - Local login
  - Cisco ISE (RADIUS) login
  - remembers the last logged-in username in browser storage (username only; never password), even after logout
- Super Admin security workflow:
  - First run requires creating a super admin account
  - Settings page requires super admin verification
- Super Admin Settings page provides popup windows for Users, ISE, NTP, and Idle Logout
- ISE settings page supports:
  - Primary ISE server/port/shared-secret
  - Secondary ISE server/port/shared-secret
  - Timeout and NAS-IP
- Super Admin local-user controls:
  - create local users with username only (no initial password)
  - list all created users with password-set and force-change status
  - edit popup default action is blank (must choose action), supports reset password, force-change next login, delete user, and set allowed categories per user
  - per-user category access control (all categories / selected categories / no categories) with Select All / Deselect All and per-category checkbox rows
  - users with blank/reset password are forced to set password at next login
- NTP workflow:
  - dashboard top row shows centered live numeric clock
  - NTP configuration is available only in Super Admin settings (choose NTP server sync or set manual time)
  - super admin settings launcher layout: first row Users + ISE, second row NTP + Idle Logout
- Idle Logout workflow:
  - super admin can set global idle timeout (minutes) for all users
  - any dashboard inactivity auto-logout is enforced by frontend and backend
- Devices workflow:
  - top-right settings icon on Devices panel opens popup for add/edit/delete devices and category actions
  - bottom inline devices/category management section removed from devices panel
- Category/group workflow:
  - split view: Groups list on left and Devices list on right
  - drag-select one or more groups, then devices list updates
  - devices list shows 15 rows with scroll for larger inventories
  - create category from GUI
  - Uncategorized category is protected and cannot be deleted (even by super admin)
  - Uncategorized always appears in the Groups list
  - add devices to category from GUI
  - delete category from GUI
  - Add Device popup (hostname + IP + category drag-list)
  - new devices default to Uncategorized category
  - Add Device popup includes **Test** button for dual connectivity checks (ICMP ping + SSH TCP/22)
  - ICMP ping test supports both Linux/macOS and Windows hosts running the web app
  - duplicate hostname/IP validation when adding device
  - adding, editing, and deleting devices requires super admin password confirmation popup every time (masked password field, not plain text)
  - device add/edit/delete is also restricted by user category access (even with super admin password)
  - edit and delete devices from GUI
  - edit device form auto-fills current hostname/IP/categories from selected device
  - when editing, you can change category only (hostname/IP can stay unchanged)
- Dashboard device credential popup:
  - button in user strip (left of User) to open credential popup
  - set ISE login/SSH username + password + enable password used by RUN device connections
  - device credentials are stored per logged-in account (each user must set their own)
- Data/security storage:
  - local users, devices, categories, and per-user device credentials are stored in SQLite (`app_data.db`)
  - legacy `users.json` / `devices_web.json` / `device_credentials.json` are auto-migrated to DB on startup
  - sensitive saved secrets (ISE shared secrets and stored device passwords) are encrypted before writing to disk
- Command workflow:
  - two in-panel modes: Show Commands and Config Commands (no popup)
  - settings icon on top-right of Commands panel opens popup to add/rename/delete buttons
  - edit button command text directly from settings popup
  - button selectors in settings popup default to blank (`-- Select Button --`)
  - command buttons appear for all devices/users based on each user's personal saved dashboard button set
  - command preview before RUN
  - add-button command and manual command support multiple lines
  - Ping button (in Devices panel) runs 5 ICMP probes for selected devices and shows CMD-style popup output (`!` success, `.` loss)
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
