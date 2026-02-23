# Network Web SSH Automation App

A web-based network engineering app to authenticate users, select routers/switches, run troubleshooting commands over SSH, and manage Cisco ISE auth settings with super-admin protection.

## Key Features
- Login supports:
  - Local login
  - Cisco ISE (RADIUS) login
- Super Admin security workflow:
  - First run requires creating a super admin account
  - Settings page requires super admin verification
- Super Admin Settings page now provides separate Users and ISE popup windows
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
  - dashboard top row includes NTP button + live clock + NTP status chip
  - NTP popup lets you set server/port/timeout and run synchronize
  - super admin settings has Users / ISE / NTP buttons in one equal row
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
- Command workflow:
  - two in-panel modes: Show Commands and Config Commands (no popup)
  - settings icon on top-right of Commands panel opens popup to add/rename/delete buttons
  - edit button command text directly from settings popup
  - button selectors in settings popup default to blank (`-- Select Button --`)
  - command buttons appear for all devices/users based on each user's personal saved dashboard button set
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
