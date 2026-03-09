from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEVICES_FILE = PROJECT_ROOT / "devices_web.json"
ISE_SETTINGS_FILE = PROJECT_ROOT / "ise_settings.json"
SUPER_ADMIN_FILE = PROJECT_ROOT / "super_admin.json"
USERS_FILE = PROJECT_ROOT / "users.json"
DEVICE_CREDS_FILE = PROJECT_ROOT / "device_credentials.json"
USER_BUTTONS_FILE = PROJECT_ROOT / "user_buttons.json"
NTP_SETTINGS_FILE = PROJECT_ROOT / "ntp_settings.json"
SESSION_SETTINGS_FILE = PROJECT_ROOT / "session_settings.json"
EXTERNAL_LOGGING_SETTINGS_FILE = PROJECT_ROOT / "external_logging_settings.json"
MONITORING_SETTINGS_FILE = PROJECT_ROOT / "monitoring_settings.json"
IP_BRANCHES_FILE = PROJECT_ROOT / "ip_branches.json"

SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")
PRIMARY_SQL_SERVER_DRIVER = os.environ.get("APP_SQL_DRIVER", "ODBC Driver 18 for SQL Server")
PRIMARY_SQL_SERVER_HOST = os.environ.get("APP_SQL_HOST", r"localhost\EVENG")
PRIMARY_SQL_SERVER_PORT = int(os.environ.get("APP_SQL_PORT", "1433") or "1433")
PRIMARY_SQL_SERVER_DB = os.environ.get("APP_SQL_DATABASE", "ndmc")
PRIMARY_SQL_SERVER_USER = os.environ.get("APP_SQL_USER", "ndmc")
PRIMARY_SQL_SERVER_PASSWORD = os.environ.get("APP_SQL_PASSWORD", "test")
PRIMARY_SQL_SERVER_CLIENT = os.environ.get("APP_SQL_CLIENT", "auto").strip().lower() or "auto"
