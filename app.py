#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import re
import secrets
import socket
import sqlite3
import struct
import threading
import subprocess
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DEVICES_FILE = BASE_DIR / "devices_web.json"
ISE_SETTINGS_FILE = BASE_DIR / "ise_settings.json"
SUPER_ADMIN_FILE = BASE_DIR / "super_admin.json"
USERS_FILE = BASE_DIR / "users.json"
DEVICE_CREDS_FILE = BASE_DIR / "device_credentials.json"
DB_FILE = BASE_DIR / "app_data.db"
USER_BUTTONS_FILE = BASE_DIR / "user_buttons.json"
NTP_SETTINGS_FILE = BASE_DIR / "ntp_settings.json"
SESSION_SETTINGS_FILE = BASE_DIR / "session_settings.json"
IP_BRANCHES_FILE = BASE_DIR / "ip_branches.json"
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
SERVICE_TYPE_LOGIN = 1
DEFAULT_CATEGORY = "Uncategorized"
RUNTIME_SSH_SESSIONS: dict[str, dict[str, dict[str, Any]]] = {}
RUNTIME_SSH_LOCK = threading.Lock()


@dataclass
class SSHResult:
    device: str
    host: str
    status: str
    output: str


def _hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200000
    ).hex()


def _crypto_key() -> bytes:
    return hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()


def _keystream(length: int, nonce: bytes) -> bytes:
    key = _crypto_key()
    stream = b""
    counter = 0
    while len(stream) < length:
        stream += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return stream[:length]


def encrypt_secret(value: str) -> str:
    if value == "":
        return ""
    raw = value.encode("utf-8")
    nonce = os.urandom(16)
    cipher = bytes(a ^ b for a, b in zip(raw, _keystream(len(raw), nonce)))
    return f"enc:v1:{urlsafe_b64encode(nonce).decode('ascii')}:{urlsafe_b64encode(cipher).decode('ascii')}"


def decrypt_secret(value: str) -> str:
    text = str(value or "")
    if not text.startswith("enc:v1:"):
        return text
    parts = text.split(":", 3)
    if len(parts) != 4:
        return ""
    try:
        nonce = urlsafe_b64decode(parts[2].encode("ascii"))
        cipher = urlsafe_b64decode(parts[3].encode("ascii"))
    except Exception:
        return ""
    plain = bytes(a ^ b for a, b in zip(cipher, _keystream(len(cipher), nonce)))
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def is_valid_ipv4(value: str) -> bool:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", text):
        return False
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if len(part) == 0 or len(part) > 3:
            return False
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL DEFAULT 'operator',
                salt TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT '',
                must_change_password INTEGER NOT NULL DEFAULT 1,
                allowed_categories TEXT,
                admin_permissions TEXT,
                category_panel_access TEXT,
                account_privileges TEXT
            )
            """
        )
        try:
            conn.execute("ALTER TABLE users ADD COLUMN admin_permissions TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN category_panel_access TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN account_privileges TEXT")
        except sqlite3.OperationalError:
            pass
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                hostname TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_groups (
                hostname TEXT NOT NULL,
                group_name TEXT NOT NULL,
                PRIMARY KEY(hostname, group_name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_credentials (
                account_key TEXT PRIMARY KEY,
                username TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                enable_password_enc TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS super_admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                username TEXT NOT NULL DEFAULT '',
                salt TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ise_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                primary_server TEXT NOT NULL DEFAULT '',
                primary_port INTEGER NOT NULL DEFAULT 1812,
                primary_shared_secret TEXT NOT NULL DEFAULT '',
                secondary_server TEXT NOT NULL DEFAULT '',
                secondary_port INTEGER NOT NULL DEFAULT 1812,
                secondary_shared_secret TEXT NOT NULL DEFAULT '',
                timeout INTEGER NOT NULL DEFAULT 5,
                nas_ip TEXT NOT NULL DEFAULT '127.0.0.1'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_device_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_username TEXT NOT NULL,
                requester_role TEXT NOT NULL,
                device_name TEXT NOT NULL,
                original_hostname TEXT NOT NULL,
                original_ip TEXT NOT NULL,
                original_categories TEXT NOT NULL,
                proposed_hostname TEXT NOT NULL,
                proposed_ip TEXT NOT NULL,
                proposed_categories TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                approver_username TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                decided_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_command_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_username TEXT NOT NULL,
                requester_role TEXT NOT NULL,
                command_mode TEXT NOT NULL,
                command_text TEXT NOT NULL,
                target_devices TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                approver_username TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                decided_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                requester TEXT NOT NULL,
                approver TEXT NOT NULL,
                device_name TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
    migrate_legacy_json_to_db()


def migrate_legacy_json_to_db() -> None:
    with db_conn() as conn:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0 and USERS_FILE.exists():
            try:
                data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    username = str(item.get("username", "")).strip()
                    if not username:
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO users(username, role, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            str(item.get("role", "operator")),
                            str(item.get("salt", "")),
                            str(item.get("password_hash", "")),
                            1 if bool(item.get("must_change_password", True)) else 0,
                            json.dumps(item.get("allowed_categories")),
                            json.dumps(item.get("admin_permissions", [])),
                            json.dumps(item.get("category_panel_access", {})),
                            json.dumps(item.get("account_privileges", ["devices", "ip_addressing"])),
                        ),
                    )

        device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if device_count == 0 and DEVICES_FILE.exists():
            try:
                data = json.loads(DEVICES_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    hostname = str(item.get("name", item.get("hostname", ""))).strip()
                    ip_address = str(item.get("host", item.get("ip_address", ""))).strip()
                    if not hostname or not ip_address:
                        continue
                    conn.execute("INSERT OR REPLACE INTO devices(hostname, ip_address) VALUES (?, ?)", (hostname, ip_address))
                    for group in item.get("groups", []):
                        group_name = str(group).strip()
                        if group_name:
                            conn.execute("INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)", (hostname, group_name))

        creds_count = conn.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0]
        if creds_count == 0 and DEVICE_CREDS_FILE.exists():
            try:
                data = json.loads(DEVICE_CREDS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                for key, value in data.items():
                    if not isinstance(value, dict):
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO device_credentials(account_key, username, password_enc, enable_password_enc)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            str(key),
                            str(value.get("username", "")).strip(),
                            encrypt_secret(str(value.get("password", ""))),
                            encrypt_secret(str(value.get("enable_password", ""))),
                        ),
                    )

        super_admin_count = conn.execute("SELECT COUNT(*) FROM super_admin").fetchone()[0]
        if super_admin_count == 0 and SUPER_ADMIN_FILE.exists():
            try:
                data = json.loads(SUPER_ADMIN_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                username = str(data.get("username", "")).strip()
                salt = str(data.get("salt", ""))
                password_hash = str(data.get("password_hash", ""))
                if username and salt and password_hash:
                    conn.execute(
                        "INSERT OR REPLACE INTO super_admin(id, username, salt, password_hash) VALUES (1, ?, ?, ?)",
                        (username, salt, password_hash),
                    )

        ise_count = conn.execute("SELECT COUNT(*) FROM ise_settings").fetchone()[0]
        if ise_count == 0 and ISE_SETTINGS_FILE.exists():
            try:
                data = json.loads(ISE_SETTINGS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ise_settings(
                        id, primary_server, primary_port, primary_shared_secret,
                        secondary_server, secondary_port, secondary_shared_secret,
                        timeout, nas_ip
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(data.get("primary_server", "")).strip(),
                        int(data.get("primary_port", 1812) or 1812),
                        encrypt_secret(decrypt_secret(str(data.get("primary_shared_secret", "")))),
                        str(data.get("secondary_server", "")).strip(),
                        int(data.get("secondary_port", 1812) or 1812),
                        encrypt_secret(decrypt_secret(str(data.get("secondary_shared_secret", "")))),
                        int(data.get("timeout", 5) or 5),
                        str(data.get("nas_ip", "127.0.0.1")).strip(),
                    ),
                )


init_db()


def super_admin_exists() -> bool:
    with db_conn() as conn:
        row = conn.execute("SELECT username FROM super_admin WHERE id = 1").fetchone()
    return bool(row and str(row["username"]).strip())


def load_super_admin() -> dict[str, Any]:
    with db_conn() as conn:
        row = conn.execute("SELECT username, salt, password_hash FROM super_admin WHERE id = 1").fetchone()
    if not row:
        return {}
    return {
        "username": str(row["username"] or "").strip(),
        "salt": str(row["salt"] or ""),
        "password_hash": str(row["password_hash"] or ""),
    }


def save_super_admin(username: str, password: str) -> None:
    salt = secrets.token_hex(16)
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO super_admin(id, username, salt, password_hash) VALUES (1, ?, ?, ?)",
            (username.strip(), salt, _hash_password(password, salt)),
        )


def verify_super_admin(username: str, password: str) -> bool:
    data = load_super_admin()
    if not data:
        return False
    if username.strip() != str(data.get("username", "")):
        return False
    salt = str(data.get("salt", ""))
    expected = str(data.get("password_hash", ""))
    if not salt or not expected:
        return False
    actual = _hash_password(password, salt)
    return hmac.compare_digest(actual, expected)


def load_users() -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT username, role, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges FROM users ORDER BY username"
        ).fetchall()

    for row in rows:
        allowed_raw = row["allowed_categories"]
        try:
            allowed_categories = json.loads(allowed_raw) if allowed_raw else None
        except Exception:
            allowed_categories = None
        admin_raw = row["admin_permissions"]
        try:
            admin_permissions = json.loads(admin_raw) if admin_raw else []
        except Exception:
            admin_permissions = []
        panel_raw = row["category_panel_access"] if "category_panel_access" in row.keys() else None
        try:
            category_panel_access = json.loads(panel_raw) if panel_raw else {}
        except Exception:
            category_panel_access = {}
        account_raw = row["account_privileges"] if "account_privileges" in row.keys() else None
        try:
            account_privileges = json.loads(account_raw) if account_raw else ["devices", "ip_addressing"]
        except Exception:
            account_privileges = ["devices", "ip_addressing"]
        user: dict[str, Any] = {
            "username": row["username"],
            "role": normalize_role(str(row["role"])),
            "salt": row["salt"],
            "password_hash": row["password_hash"],
            "must_change_password": bool(row["must_change_password"]),
            "allowed_categories": allowed_categories,
            "admin_permissions": admin_permissions,
            "category_panel_access": category_panel_access,
            "account_privileges": [str(item).strip() for item in account_privileges if str(item).strip()],
        }
        user["role"] = normalize_role(str(user.get("role", "junior")))
        user.setdefault("salt", "")
        user.setdefault("password_hash", "")
        user.setdefault("must_change_password", True)
        user.setdefault("allowed_categories", None)
        user.setdefault("admin_permissions", [])
        user.setdefault("category_panel_access", {})
        user.setdefault("account_privileges", ["devices", "ip_addressing"])
        normalized.append(user)
    return normalized


def save_users(users: list[dict[str, Any]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM users")
        for user in users:
            conn.execute(
                """
                INSERT INTO users(username, role, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(user.get("username", "")).strip(),
                    normalize_role(str(user.get("role", "junior"))),
                    str(user.get("salt", "")),
                    str(user.get("password_hash", "")),
                    1 if bool(user.get("must_change_password", True)) else 0,
                    json.dumps(user.get("allowed_categories")),
                    json.dumps(user.get("admin_permissions", [])),
                    json.dumps(user.get("category_panel_access", {})),
                    json.dumps(user.get("account_privileges", ["devices", "ip_addressing"])),
                ),
            )


def load_device_creds_store() -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT account_key, username, password_enc, enable_password_enc FROM device_credentials"
        ).fetchall()

    for row in rows:
        normalized[str(row["account_key"])] = {
            "username": str(row["username"] or "").strip(),
            "password": decrypt_secret(str(row["password_enc"] or "")),
            "enable_password": decrypt_secret(str(row["enable_password_enc"] or "")),
        }
    return normalized


def save_device_creds_store(store: dict[str, dict[str, str]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM device_credentials")
        for account_key, value in store.items():
            conn.execute(
                """
                INSERT INTO device_credentials(account_key, username, password_enc, enable_password_enc)
                VALUES (?, ?, ?, ?)
                """,
                (
                    str(account_key),
                    str(value.get("username", "")).strip(),
                    encrypt_secret(str(value.get("password", ""))),
                    encrypt_secret(str(value.get("enable_password", ""))),
                ),
            )


def device_creds_key(account_username: str, auth_mode: str) -> str:
    return f"{auth_mode.strip().lower()}::{account_username.strip().lower()}"


def load_user_device_creds(account_username: str, auth_mode: str) -> dict[str, str]:
    store = load_device_creds_store()
    return dict(store.get(device_creds_key(account_username, auth_mode), {}))


def save_user_device_creds(account_username: str, auth_mode: str, creds: dict[str, str]) -> None:
    store = load_device_creds_store()
    store[device_creds_key(account_username, auth_mode)] = {
        "username": str(creds.get("username", "")).strip(),
        "password": str(creds.get("password", "")),
        "enable_password": str(creds.get("enable_password", "")),
    }
    save_device_creds_store(store)


def load_user_buttons_store() -> dict[str, list[dict[str, Any]]]:
    if not USER_BUTTONS_FILE.exists():
        return {}
    with USER_BUTTONS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {}

    normalized: dict[str, list[dict[str, Any]]] = {}
    for key, value in data.items():
        normalized[str(key)] = normalize_buttons(value)
    return normalized


def save_user_buttons_store(store: dict[str, list[dict[str, Any]]]) -> None:
    with USER_BUTTONS_FILE.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)


def load_user_buttons(account_username: str, auth_mode: str) -> list[dict[str, Any]]:
    key = device_creds_key(account_username, auth_mode)
    store = load_user_buttons_store()
    return normalize_buttons(store.get(key, []))


def save_user_buttons(account_username: str, auth_mode: str, buttons: list[dict[str, Any]]) -> None:
    key = device_creds_key(account_username, auth_mode)
    store = load_user_buttons_store()
    store[key] = normalize_buttons(buttons)
    save_user_buttons_store(store)


def default_session_settings() -> dict[str, Any]:
    return {
        "idle_timeout_minutes": 15,
    }


def load_session_settings() -> dict[str, Any]:
    if not SESSION_SETTINGS_FILE.exists():
        return default_session_settings()
    with SESSION_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_session_settings()
    defaults.update(data if isinstance(data, dict) else {})
    defaults["idle_timeout_minutes"] = int(defaults.get("idle_timeout_minutes", 15) or 15)
    return defaults


def save_session_settings(settings: dict[str, Any]) -> None:
    payload = {
        "idle_timeout_minutes": max(1, int(settings.get("idle_timeout_minutes", 15) or 15)),
    }
    with SESSION_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def default_ntp_settings() -> dict[str, Any]:
    return {
        "mode": "ntp",
        "server": "",
        "port": 123,
        "sync_timeout": 3,
        "manual_time": "",
        "last_sync": "",
        "last_status": "Not synchronized yet.",
    }


def load_ntp_settings() -> dict[str, Any]:
    if not NTP_SETTINGS_FILE.exists():
        return default_ntp_settings()
    with NTP_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_ntp_settings()
    if isinstance(data, dict):
        defaults.update(data)
    return defaults


def save_ntp_settings(settings: dict[str, Any]) -> None:
    payload = {
        "mode": str(settings.get("mode", "ntp")).strip().lower() or "ntp",
        "server": str(settings.get("server", "")).strip(),
        "port": int(settings.get("port", 123) or 123),
        "sync_timeout": int(settings.get("sync_timeout", 3) or 3),
        "manual_time": str(settings.get("manual_time", "")),
        "last_sync": str(settings.get("last_sync", "")),
        "last_status": str(settings.get("last_status", "")),
    }
    with NTP_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def sync_ntp_time(server: str, port: int, timeout: int) -> tuple[bool, str, str]:
    if not server:
        return False, "NTP server is required.", ""

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, "Invalid NTP response.", ""

        ntp_seconds = struct.unpack("!I", data[40:44])[0]
        unix_seconds = ntp_seconds - 2208988800
        dt = datetime.fromtimestamp(unix_seconds, timezone.utc)
        return True, f"NTP synchronized with {server}:{port}.", dt.isoformat()
    except OSError as exc:
        return False, f"NTP sync failed: {exc}", ""
    finally:
        sock.close()


def test_ntp_connectivity(server: str, port: int, timeout: int) -> tuple[bool, str]:
    if not server:
        return False, "NTP server is required."

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, f"NTP test failed: invalid response from {server}:{port}."
        return True, f"NTP test success: connected to {server}:{port}."
    except OSError as exc:
        return False, f"NTP test failed: {exc}"
    finally:
        sock.close()


def run_ping_for_host(host: str, count: int = 5) -> str:
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return f"PING {host}\n.....\nPing command error: {exc}\n"

    output = result.stdout or ""
    lines = output.splitlines()
    rendered: list[str] = [f"PING {host}"]
    marks: list[str] = []

    for line in lines:
        lower = line.lower()
        if "ttl=" in lower and ("time=" in lower or "time<" in lower):
            marks.append("!")
            bytes_match = re.search(r"bytes[=< ](\d+)", lower)
            time_match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", lower)
            ttl_match = re.search(r"ttl[=< ](\d+)", lower)
            bytes_val = bytes_match.group(1) if bytes_match else "32"
            ttl_val = ttl_match.group(1) if ttl_match else "64"
            if time_match:
                time_fragment = f"time={time_match.group(1)}ms"
            elif "time<" in lower:
                time_fragment = "time<1ms"
            else:
                time_fragment = "time<1ms"
            rendered.append(f"Reply from {host}: bytes={bytes_val} {time_fragment} TTL={ttl_val}")

    if not marks:
        marks = ["."] * count
    elif len(marks) < count:
        marks.extend(["."] * (count - len(marks)))

    rendered.insert(1, "".join(marks[:count]))
    return "\n".join(rendered) + "\n"


def find_user(users: list[dict[str, Any]], username: str) -> dict[str, Any] | None:
    normalized = username.strip().lower()
    for user in users:
        if str(user.get("username", "")).strip().lower() == normalized:
            return user
    return None


def set_user_password(user: dict[str, Any], password: str) -> None:
    salt = secrets.token_hex(16)
    user["salt"] = salt
    user["password_hash"] = _hash_password(password, salt)


def is_super_admin_password(password: str) -> bool:
    username = str(load_super_admin().get("username", "")).strip()
    if not username or not password:
        return False
    return verify_super_admin(username, password)


def is_current_session_super_admin() -> bool:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip().lower()
    super_username = str(load_super_admin().get("username", "")).strip().lower()
    return bool(current_username and super_username and current_username == super_username)


def normalize_role(role: str) -> str:
    raw = str(role or "").strip().lower()
    if raw in {"senior", "junior", "helpdesk"}:
        return raw
    if raw in {"super_admin", "admin"}:
        return "senior"
    return "junior"


def current_user_role() -> str:
    if is_current_session_super_admin():
        return "senior"
    if str(session.get("auth_mode", "local")) != "local":
        return "junior"
    username = str(session.get("creds", {}).get("username", "")).strip()
    users = load_users()
    user = find_user(users, username)
    if not user:
        return "junior"
    return normalize_role(str(user.get("role", "junior")))


def is_senior_user() -> bool:
    return current_user_role() == "senior"


def notify_user(username: str, message: str) -> None:
    target = str(username or "").strip().lower()
    if not target or not message:
        return
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO user_notifications(username, message, created_at, is_read) VALUES (?, ?, ?, 0)",
            (target, str(message), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
        )


def load_senior_notification_targets() -> list[str]:
    targets: list[str] = []
    users = load_users()
    for user in users:
        if normalize_role(str(user.get("role", ""))) == "senior":
            username = str(user.get("username", "")).strip()
            if username and username not in targets:
                targets.append(username)

    super_admin_username = str(load_super_admin().get("username", "")).strip()
    if super_admin_username and super_admin_username not in targets:
        targets.append(super_admin_username)

    return targets


def notify_seniors_new_pending_request(
    request_id: int,
    requester_username: str,
    device_name: str,
    original_hostname: str,
    proposed_hostname: str,
    original_ip: str,
    proposed_ip: str,
    original_categories: list[str],
    proposed_categories: list[str],
) -> None:
    message = (
        f"New pending request #{request_id} from {requester_username} for device '{device_name}'. "
        f"Hostname: {original_hostname} → {proposed_hostname}; "
        f"IP: {original_ip} → {proposed_ip}; "
        f"Categories: {', '.join(original_categories) or '-'} → {', '.join(proposed_categories) or '-'}."
    )
    for senior_username in load_senior_notification_targets():
        if senior_username.strip().lower() == str(requester_username).strip().lower():
            continue
        notify_user(senior_username, message)


def clear_senior_pending_request_notifications(request_id: int) -> None:
    if request_id <= 0:
        return
    with db_conn() as conn:
        conn.execute(
            "DELETE FROM user_notifications WHERE message LIKE ?",
            (f"%pending request #{int(request_id)}%",),
        )


def load_unread_notifications(username: str) -> list[dict[str, Any]]:
    target = str(username or "").strip().lower()
    if not target:
        return []
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT id, message, created_at FROM user_notifications WHERE lower(username) = lower(?) AND is_read = 0 ORDER BY id DESC",
            (target,),
        ).fetchall()
    return [
        {"id": int(row["id"]), "message": str(row["message"]), "created_at": str(row["created_at"])}
        for row in rows
    ]


def mark_notifications_read(username: str, notification_ids: list[int] | None = None) -> None:
    target = str(username or "").strip().lower()
    if not target:
        return
    with db_conn() as conn:
        if notification_ids:
            conn.executemany(
                "UPDATE user_notifications SET is_read = 1 WHERE lower(username) = lower(?) AND id = ?",
                [(target, int(item)) for item in notification_ids],
            )
        else:
            conn.execute("UPDATE user_notifications SET is_read = 1 WHERE lower(username) = lower(?)", (target,))


def delete_notification(username: str, notification_id: int) -> None:
    target = str(username or "").strip().lower()
    if not target:
        return
    with db_conn() as conn:
        conn.execute("DELETE FROM user_notifications WHERE lower(username) = lower(?) AND id = ?", (target, int(notification_id)))


def write_audit_log(action: str, requester: str, approver: str, device_name: str, details: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO audit_logs(action, requester, approver, device_name, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(action),
                str(requester or ""),
                str(approver or ""),
                str(device_name or ""),
                json.dumps(details),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ),
        )


def create_pending_device_request(*, requester_username: str, requester_role: str, original_device: dict[str, Any], proposed_hostname: str, proposed_ip: str, proposed_categories: list[str]) -> None:
    request_id = 0
    with db_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO pending_device_requests(
                requester_username, requester_role, device_name,
                original_hostname, original_ip, original_categories,
                proposed_hostname, proposed_ip, proposed_categories,
                status, approver_username, created_at, decided_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '', ?, '')
            """,
            (
                str(requester_username),
                normalize_role(requester_role),
                str(original_device.get("name", "")),
                str(original_device.get("name", "")),
                str(original_device.get("host", "")),
                json.dumps([str(g).strip() for g in original_device.get("groups", []) if str(g).strip()]),
                str(proposed_hostname),
                str(proposed_ip),
                json.dumps([str(g).strip() for g in proposed_categories if str(g).strip()]),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ),
        )
        request_id = int(cursor.lastrowid or 0)

    if request_id > 0:
        original_hostname = str(original_device.get("name", "")).strip()
        original_ip = str(original_device.get("host", "")).strip()
        original_categories = [str(g).strip() for g in original_device.get("groups", []) if str(g).strip()]
        normalized_proposed_categories = [str(g).strip() for g in proposed_categories if str(g).strip()]
        notify_seniors_new_pending_request(
            request_id=request_id,
            requester_username=str(requester_username),
            device_name=original_hostname,
            original_hostname=original_hostname,
            proposed_hostname=str(proposed_hostname).strip() or original_hostname,
            original_ip=original_ip,
            proposed_ip=str(proposed_ip).strip() or original_ip,
            original_categories=original_categories,
            proposed_categories=normalized_proposed_categories,
        )


def load_pending_device_requests(status: str = "pending") -> list[dict[str, Any]]:
    with db_conn() as conn:
        if status == "all":
            rows = conn.execute("SELECT * FROM pending_device_requests ORDER BY id DESC").fetchall()
        elif status == "closed":
            rows = conn.execute("SELECT * FROM pending_device_requests WHERE status IN ('approved','rejected') ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pending_device_requests WHERE status = 'pending' ORDER BY id DESC"
            ).fetchall()
    pending: list[dict[str, Any]] = []
    for row in rows:
        try:
            original_categories = json.loads(str(row["original_categories"] or "[]"))
        except Exception:
            original_categories = []
        try:
            proposed_categories = json.loads(str(row["proposed_categories"] or "[]"))
        except Exception:
            proposed_categories = []
        pending.append({
            "id": int(row["id"]),
            "requester_username": str(row["requester_username"]),
            "requester_role": normalize_role(str(row["requester_role"])),
            "device_name": str(row["device_name"]),
            "original_hostname": str(row["original_hostname"]),
            "original_ip": str(row["original_ip"]),
            "original_categories": original_categories,
            "proposed_hostname": str(row["proposed_hostname"]),
            "proposed_ip": str(row["proposed_ip"]),
            "proposed_categories": proposed_categories,
            "created_at": str(row["created_at"]),
            "status": str(row["status"]),
        })
    return pending


def load_pending_command_requests(status: str = "pending") -> list[dict[str, Any]]:
    with db_conn() as conn:
        if status == "all":
            rows = conn.execute("SELECT * FROM pending_command_requests ORDER BY id DESC").fetchall()
        elif status == "closed":
            rows = conn.execute("SELECT * FROM pending_command_requests WHERE status IN ('approved','rejected') ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pending_command_requests WHERE status = 'pending' ORDER BY id DESC"
            ).fetchall()

    pending: list[dict[str, Any]] = []
    for row in rows:
        try:
            target_devices = json.loads(str(row["target_devices"] or "[]"))
        except Exception:
            target_devices = []
        pending.append({
            "id": int(row["id"]),
            "requester_username": str(row["requester_username"]),
            "requester_role": normalize_role(str(row["requester_role"])),
            "command_mode": str(row["command_mode"]),
            "command_text": str(row["command_text"]),
            "target_devices": [str(item).strip() for item in target_devices if str(item).strip()],
            "status": str(row["status"]),
            "approver_username": str(row["approver_username"]),
            "created_at": str(row["created_at"]),
            "decided_at": str(row["decided_at"]),
        })
    return pending


def clear_senior_command_request_notifications(request_id: int) -> None:
    if request_id <= 0:
        return
    with db_conn() as conn:
        conn.execute(
            "DELETE FROM user_notifications WHERE message LIKE ? OR message LIKE ?",
            (
                f"%pending request #{int(request_id)}%",
                f"%approval request #{int(request_id)}%",
            ),
        )


def load_pending_command_request_by_id(request_id: int) -> dict[str, Any] | None:
    if request_id <= 0:
        return None
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_command_requests WHERE id = ?", (int(request_id),)).fetchone()
    if not row:
        return None
    try:
        target_devices = json.loads(str(row["target_devices"] or "[]"))
    except Exception:
        target_devices = []
    return {
        "id": int(row["id"]),
        "requester_username": str(row["requester_username"]),
        "requester_role": normalize_role(str(row["requester_role"])),
        "command_mode": str(row["command_mode"]),
        "command_text": str(row["command_text"]),
        "target_devices": [str(item).strip() for item in target_devices if str(item).strip()],
        "status": str(row["status"]),
        "approver_username": str(row["approver_username"]),
        "created_at": str(row["created_at"]),
        "decided_at": str(row["decided_at"]),
    }


def validate_local_user(username: str, password: str) -> tuple[bool, str, str]:
    if verify_super_admin(username, password):
        return True, "", "super_admin"

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return False, "Local user not found.", ""

    user_role = str(user.get("role", "operator"))
    password_hash = str(user.get("password_hash", ""))
    salt = str(user.get("salt", ""))

    if not password_hash or not salt:
        return False, "PASSWORD_SETUP_REQUIRED", user_role

    actual = _hash_password(password, salt)
    if not hmac.compare_digest(actual, password_hash):
        return False, "Invalid local username or password.", ""

    if bool(user.get("must_change_password", False)):
        return False, "PASSWORD_SETUP_REQUIRED", user_role

    return True, "", user_role


def upsert_user(username: str, role: str = "junior") -> tuple[bool, str]:
    users = load_users()
    if find_user(users, username) is not None:
        return False, "User already exists."
    users.append({
        "username": username.strip(),
        "role": normalize_role(role),
        "salt": "",
        "password_hash": "",
        "must_change_password": True,
        "allowed_categories": None,
        "admin_permissions": [],
        "category_panel_access": {},
        "account_privileges": ["devices", "ip_addressing"],
    })
    save_users(users)
    return True, f"User '{username}' created. Password will be set on first login."

def default_ip_branches() -> list[str]:
    return ["B701", "B702", "B703", "B704"]


def load_ip_branches() -> list[str]:
    if not IP_BRANCHES_FILE.exists():
        branches = default_ip_branches()
        IP_BRANCHES_FILE.write_text(json.dumps(branches, indent=2), encoding="utf-8")
        return branches
    try:
        raw = json.loads(IP_BRANCHES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return default_ip_branches()
    if not isinstance(raw, list):
        return default_ip_branches()
    branches = [str(item).strip() for item in raw if str(item).strip()]
    return branches or default_ip_branches()


def save_ip_branches(branches: list[str]) -> None:
    normalized = []
    seen: set[str] = set()
    for item in branches:
        name = str(item).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        normalized.append(name)
    IP_BRANCHES_FILE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")


def load_devices() -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute("SELECT hostname, ip_address FROM devices ORDER BY hostname").fetchall()
        group_rows = conn.execute("SELECT hostname, group_name FROM device_groups").fetchall()

    group_map: dict[str, list[str]] = {}
    for row in group_rows:
        group_map.setdefault(str(row["hostname"]), []).append(str(row["group_name"]))

    for row in rows:
        hostname = str(row["hostname"])
        devices.append({
            "name": hostname,
            "host": str(row["ip_address"]),
            "port": 22,
            "groups": sorted(group_map.get(hostname, [])),
        })
    return devices


def save_devices(devices: list[dict[str, Any]], conn: sqlite3.Connection | None = None) -> None:
    def _save(target_conn: sqlite3.Connection) -> None:
        target_conn.execute("DELETE FROM device_groups")
        target_conn.execute("DELETE FROM devices")
        for device in devices:
            hostname = str(device.get("name", device.get("hostname", ""))).strip()
            ip_address = str(device.get("host", device.get("ip_address", ""))).strip()
            if not hostname or not ip_address:
                continue
            target_conn.execute("INSERT INTO devices(hostname, ip_address) VALUES (?, ?)", (hostname, ip_address))
            for group in device.get("groups", []):
                group_name = str(group).strip()
                if group_name:
                    target_conn.execute(
                        "INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)",
                        (hostname, group_name),
                    )

    if conn is None:
        with db_conn() as own_conn:
            _save(own_conn)
        return

    _save(conn)


def grouped_devices(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for group in device.get("groups", []):
            groups.setdefault(group, []).append(device)
    return groups




def all_categories(devices: list[dict[str, Any]]) -> list[str]:
    categories: set[str] = {DEFAULT_CATEGORY}
    for device in devices:
        for group in device.get("groups", []):
            group_name = str(group).strip()
            if group_name:
                categories.add(group_name)
    return sorted(categories)


def user_allowed_categories(username: str, auth_mode: str) -> list[str] | None:
    if auth_mode != "local":
        return None

    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return None

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return None
    if normalize_role(str(user.get("role", "junior"))) == "senior":
        return None

    allowed = user.get("allowed_categories")
    if allowed is None:
        return None
    if isinstance(allowed, list):
        return [str(item).strip() for item in allowed if str(item).strip()]
    return []


def filter_devices_for_user(devices: list[dict[str, Any]], username: str, auth_mode: str) -> list[dict[str, Any]]:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return devices

    allowed_set = set(allowed)
    filtered: list[dict[str, Any]] = []
    for device in devices:
        groups = {str(g).strip() for g in device.get("groups", []) if str(g).strip()}
        if groups & allowed_set:
            filtered.append(device)
    return filtered




def user_has_panel_access(username: str, auth_mode: str, panel_name: str) -> bool:
    if auth_mode != "local":
        return True

    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return True

    user = find_user(load_users(), username)
    if user is None:
        return True

    if normalize_role(str(user.get("role", "junior"))) == "senior":
        return True

    privileges = user.get("account_privileges")
    if not isinstance(privileges, list):
        privileges = ["devices", "ip_addressing"]

    panel = str(panel_name or "devices").strip().lower()
    normalized = {str(item).strip().lower() for item in privileges if str(item).strip()}
    return panel in normalized



def user_allowed_categories_by_panel(username: str, auth_mode: str, panel_name: str) -> list[str] | None:
    if not user_has_panel_access(username, auth_mode, panel_name):
        return []
    return user_allowed_categories(username, auth_mode)

def user_can_access_device(device: dict[str, Any], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return True

    allowed_set = set(allowed)
    groups = {str(g).strip() for g in device.get("groups", []) if str(g).strip()}
    if not groups:
        return DEFAULT_CATEGORY in allowed_set
    return bool(groups & allowed_set)


def user_can_assign_categories(categories: list[str], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories(username, auth_mode)
    if allowed is None:
        return True
    allowed_set = set(allowed)
    return all(category in allowed_set for category in categories)

def user_admin_permissions(username: str, auth_mode: str) -> set[str]:
    if auth_mode != "local":
        return set()

    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return {"create_category", "edit_device", "move_device_category", "delete_device", "delete_category"}

    user = find_user(load_users(), username)
    if user is None:
        return set()

    perms = user.get("admin_permissions", [])
    if isinstance(perms, list):
        return {str(item).strip() for item in perms if str(item).strip()}
    return set()


def current_user_has_admin_permission(permission_name: str) -> bool:
    if is_current_session_super_admin():
        return True
    creds = session.get("creds", {})
    username = str(creds.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local")).strip().lower()
    if not username:
        return False
    if current_user_role() == "senior":
        return True
    return permission_name in user_admin_permissions(username, auth_mode)

def default_buttons() -> list[dict[str, Any]]:
    return [
        {"id": "show-version", "label": "Show Version", "command": "show version", "mode": "show", "categories": []},
        {"id": "show-ip-int-brief", "label": "IP Interface Brief", "command": "show ip interface brief", "mode": "show", "categories": []},
        {"id": "show-int-status", "label": "Interfaces Status", "command": "show interfaces status", "mode": "show", "categories": []},
        {"id": "show-logging", "label": "Show Logging", "command": "show logging | tail 50", "mode": "show", "categories": []},
        {"id": "show-hostname", "label": "Show Hostname", "command": "show running-config | include hostname", "mode": "show", "categories": []},
        {"id": "show-arp", "label": "Show ARP", "command": "show arp", "mode": "show", "categories": []},
        {"id": "show-cdp", "label": "CDP Neighbors", "command": "show cdp neighbors", "mode": "show", "categories": []},
        {"id": "show-route", "label": "IP Route", "command": "show ip route", "mode": "show", "categories": []},
        {"id": "config-hostname", "label": "Set Hostname", "command": "configure terminal\nhostname NEW-HOSTNAME", "mode": "config", "categories": []},
        {"id": "config-int-desc", "label": "Interface Description", "command": "configure terminal\ninterface Gi0/1\ndescription UPDATED_BY_TOOL", "mode": "config", "categories": []},
        {"id": "config-save", "label": "Save Config", "command": "write memory", "mode": "config", "categories": []},
    ]


def normalize_buttons(raw_buttons: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_buttons, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_buttons:
        if not isinstance(item, dict):
            continue
        button_id = str(item.get("id", "")).strip()
        label = str(item.get("label", "")).strip()
        command = str(item.get("command", "")).strip()
        if not button_id or not label or not command:
            continue

        mode = str(item.get("mode", "show")).strip().lower()
        if mode not in {"show", "config"}:
            mode = "show"

        categories_raw = item.get("categories", [])
        categories: list[str] = []
        if isinstance(categories_raw, list):
            categories = [str(cat).strip() for cat in categories_raw if str(cat).strip()]

        if mode == "config":
            command = normalize_config_command_text(command)
        normalized.append({
            "id": button_id,
            "label": label,
            "command": command,
            "mode": mode,
            "categories": categories,
        })
    return normalized


def get_buttons() -> list[dict[str, Any]]:
    buttons = normalize_buttons(session.get("buttons"))
    if buttons:
        session["buttons"] = buttons
        return buttons
    buttons = default_buttons()
    session["buttons"] = buttons
    return buttons


def persist_current_user_buttons(buttons: list[dict[str, Any]]) -> None:
    account = session.get("creds", {})
    account_username = str(account.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if account_username:
        save_user_buttons(account_username, auth_mode, buttons)


def default_ise_settings() -> dict[str, Any]:
    return {
        "primary_server": "",
        "primary_port": 1812,
        "primary_shared_secret": "",
        "secondary_server": "",
        "secondary_port": 1812,
        "secondary_shared_secret": "",
        "timeout": 5,
        "nas_ip": "127.0.0.1",
    }


def load_ise_settings() -> dict[str, Any]:
    defaults = default_ise_settings()
    with db_conn() as conn:
        row = conn.execute(
            """
            SELECT primary_server, primary_port, primary_shared_secret,
                   secondary_server, secondary_port, secondary_shared_secret,
                   timeout, nas_ip
            FROM ise_settings WHERE id = 1
            """
        ).fetchone()

    if not row:
        return defaults

    defaults.update({
        "primary_server": str(row["primary_server"] or "").strip(),
        "primary_port": int(row["primary_port"] or 1812),
        "primary_shared_secret": decrypt_secret(str(row["primary_shared_secret"] or "")),
        "secondary_server": str(row["secondary_server"] or "").strip(),
        "secondary_port": int(row["secondary_port"] or 1812),
        "secondary_shared_secret": decrypt_secret(str(row["secondary_shared_secret"] or "")),
        "timeout": int(row["timeout"] or 5),
        "nas_ip": str(row["nas_ip"] or "127.0.0.1").strip(),
    })
    return defaults


def save_ise_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ise_settings(
                id, primary_server, primary_port, primary_shared_secret,
                secondary_server, secondary_port, secondary_shared_secret,
                timeout, nas_ip
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(settings.get("primary_server", "")).strip(),
                int(settings.get("primary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("primary_shared_secret", ""))),
                str(settings.get("secondary_server", "")).strip(),
                int(settings.get("secondary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("secondary_shared_secret", ""))),
                int(settings.get("timeout", 5) or 5),
                str(settings.get("nas_ip", "127.0.0.1")).strip(),
            ),
        )


def _radius_attr(attr_type: int, value: bytes) -> bytes:
    length = len(value) + 2
    return bytes([attr_type, length]) + value


def _radius_encrypt_user_password(password: str, secret: bytes, request_authenticator: bytes) -> bytes:
    pwd_bytes = password.encode("utf-8")
    padding = 16 - (len(pwd_bytes) % 16)
    if padding != 16:
        pwd_bytes += b"\x00" * padding

    encrypted = b""
    last = request_authenticator
    for i in range(0, len(pwd_bytes), 16):
        block = pwd_bytes[i : i + 16]
        digest = hashlib.md5(secret + last).digest()
        cipher = bytes(a ^ b for a, b in zip(block, digest))
        encrypted += cipher
        last = cipher
    return encrypted


def _authenticate_radius_server(
    username: str,
    password: str,
    server: str,
    port: int,
    shared_secret: str,
    timeout: int,
    nas_ip: str,
) -> tuple[bool, str]:
    if not server or not shared_secret:
        return False, "Server/secret missing"

    secret = shared_secret.encode("utf-8")
    identifier = random.randint(0, 255)
    request_authenticator = os.urandom(16)

    attrs = b""
    attrs += _radius_attr(ATTR_USER_NAME, username.encode("utf-8"))
    attrs += _radius_attr(ATTR_USER_PASSWORD, _radius_encrypt_user_password(password, secret, request_authenticator))

    try:
        attrs += _radius_attr(ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip))
    except OSError:
        pass

    attrs += _radius_attr(ATTR_NAS_PORT, struct.pack("!I", 0))
    attrs += _radius_attr(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_LOGIN))

    packet_len = 20 + len(attrs)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, packet_len) + request_authenticator + attrs

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        return False, f"Timeout from ISE {server}:{port}"
    except OSError as exc:
        return False, f"Connection error to ISE {server}:{port}: {exc}"
    finally:
        sock.close()

    if len(response) < 20:
        return False, f"Invalid response from ISE {server}:{port}"

    code, recv_identifier, recv_length = struct.unpack("!BBH", response[:4])
    recv_authenticator = response[4:20]
    response_attrs = response[20:recv_length]

    if recv_identifier != identifier:
        return False, f"Identifier mismatch from ISE {server}:{port}"

    expected_auth = hmac.new(secret, response[:4] + request_authenticator + response_attrs, hashlib.md5).digest()
    if expected_auth != recv_authenticator:
        return False, f"Authenticator check failed from ISE {server}:{port}"

    if code == ACCESS_ACCEPT:
        return True, f"Authenticated by ISE {server}:{port}"
    if code == ACCESS_REJECT:
        return False, f"Rejected by ISE {server}:{port}"
    return False, f"Unsupported response code {code} from ISE {server}:{port}"


def authenticate_with_ise(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    timeout = int(settings.get("timeout", 5) or 5)
    nas_ip = str(settings.get("nas_ip", "127.0.0.1")).strip()

    primary_server = str(settings.get("primary_server", "")).strip()
    primary_port = int(settings.get("primary_port", 1812) or 1812)
    primary_secret = str(settings.get("primary_shared_secret", ""))

    secondary_server = str(settings.get("secondary_server", "")).strip()
    secondary_port = int(settings.get("secondary_port", 1812) or 1812)
    secondary_secret = str(settings.get("secondary_shared_secret", ""))

    if not primary_server or not primary_secret:
        return False, "Primary ISE server and primary secret are required."

    ok, message = _authenticate_radius_server(
        username, password, primary_server, primary_port, primary_secret, timeout, nas_ip
    )
    if ok:
        return True, message

    if secondary_server and secondary_secret:
        ok2, msg2 = _authenticate_radius_server(
            username,
            password,
            secondary_server,
            secondary_port,
            secondary_secret,
            timeout,
            nas_ip,
        )
        if ok2:
            return True, msg2
        return False, f"Primary failed: {message}. Secondary failed: {msg2}."

    return False, message


def runtime_session_id() -> str:
    sid = str(session.get("runtime_session_id", "")).strip()
    if sid:
        return sid
    sid = secrets.token_hex(16)
    session["runtime_session_id"] = sid
    return sid


def close_runtime_ssh_sessions(runtime_id: str) -> None:
    if not runtime_id:
        return
    with RUNTIME_SSH_LOCK:
        sessions = RUNTIME_SSH_SESSIONS.pop(runtime_id, {})
    for item in sessions.values():
        client = item.get("client")
        try:
            if client:
                client.close()
        except Exception:
            pass


def get_runtime_device_session(runtime_id: str, device_name: str) -> dict[str, Any] | None:
    with RUNTIME_SSH_LOCK:
        return RUNTIME_SSH_SESSIONS.get(runtime_id, {}).get(device_name)


def open_runtime_device_session(runtime_id: str, device: dict[str, Any], creds: dict[str, Any]) -> tuple[bool, str]:
    import paramiko

    existing = get_runtime_device_session(runtime_id, str(device.get("name", "")))
    if existing is not None:
        return True, "session already active"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timeout = int(creds.get("timeout", 8))
    try:
        client.connect(
            hostname=str(device.get("host", "")),
            port=int(device.get("port", 22)),
            username=str(creds.get("username", "")),
            password=str(creds.get("password", "")),
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        channel = client.invoke_shell(width=180, height=40)
        time.sleep(0.2)
        warmup = ""
        while channel.recv_ready():
            warmup += channel.recv(4096).decode("utf-8", errors="replace")

        with RUNTIME_SSH_LOCK:
            runtime_store = RUNTIME_SSH_SESSIONS.setdefault(runtime_id, {})
            runtime_store[str(device.get("name", ""))] = {
                "client": client,
                "channel": channel,
                "host": str(device.get("host", "")),
                "port": int(device.get("port", 22)),
                "opened_at": time.time(),
            }
        return True, warmup.strip() or "SSH shell connected"
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return False, str(exc)


def run_runtime_device_command(runtime_id: str, device: dict[str, Any], creds: dict[str, Any], command: str) -> tuple[str, str]:
    device_name = str(device.get("name", ""))
    ok, message = open_runtime_device_session(runtime_id, device, creds)
    if not ok:
        return "FAIL", message

    runtime = get_runtime_device_session(runtime_id, device_name)
    if runtime is None:
        return "FAIL", "SSH session is not available."

    channel = runtime.get("channel")
    if channel is None:
        return "FAIL", "SSH channel is not available."

    try:
        timeout = max(2, int(creds.get("timeout", 8)))
        commands = split_cli_commands(command)
        if not commands:
            return "FAIL", "No command provided."
        output_parts: list[str] = []
        for cmd in commands:
            channel.send(cmd + "\n")
            text = _read_shell_output(channel, timeout)
            if text:
                output_parts.append(text)
        joined = "\n".join(output_parts).strip()
        return "PASS", joined or "(no output)"
    except Exception as exc:
        with RUNTIME_SSH_LOCK:
            runtime_store = RUNTIME_SSH_SESSIONS.get(runtime_id, {})
            runtime_item = runtime_store.pop(device_name, None)
        client = runtime_item.get("client") if runtime_item else None
        try:
            if client:
                client.close()
        except Exception:
            pass
        return "FAIL", str(exc)


def split_cli_commands(command: str) -> list[str]:
    text = str(command or "").replace("\r", "\n")
    segments: list[str] = []
    for line in text.split("\n"):
        for part in line.split(";"):
            candidate = part.strip()
            if candidate:
                segments.append(candidate)
    return segments


def normalize_config_command_text(command: str) -> str:
    commands = split_cli_commands(command)
    return "\n".join(commands)


def _read_shell_output(channel: Any, timeout_seconds: int) -> str:
    end_at = time.time() + max(2, timeout_seconds)
    chunks: list[str] = []
    while time.time() < end_at:
        time.sleep(0.15)
        got_data = False
        while channel.recv_ready():
            got_data = True
            chunks.append(channel.recv(4096).decode("utf-8", errors="replace"))
        if chunks and not got_data:
            break
    return "".join(chunks).strip()




def parse_branch_delete_command(command_text: str) -> str:
    raw = str(command_text or '').strip()
    if raw.startswith('DELETE_BRANCH::'):
        return raw.split('::', 1)[1].strip()
    return ''

def command_requires_senior_approval(command_text: str) -> bool:
    commands = [item.strip().lower() for item in split_cli_commands(command_text)]
    if not commands:
        return False

    for cmd in commands:
        if not cmd:
            continue
        if re.search(r"\breload\b", cmd) or re.search(r"\breboot\b", cmd):
            return True
        if re.search(r"\bshutdown\b", cmd) and not re.search(r"\bno\s+shutdown\b", cmd):
            return True
    return False


def notify_seniors_new_pending_command_request(
    request_id: int,
    requester_username: str,
    command_mode: str,
    command_text: str,
    device_names: list[str],
) -> None:
    message = (
        f"New pending request #{request_id} from {requester_username} for DANGEROUS command approval. "
        f"Devices: {', '.join(device_names) or '-'}; Command: '{str(command_text).strip()}'."
    )
    for senior_username in load_senior_notification_targets():
        if senior_username.strip().lower() == str(requester_username).strip().lower():
            continue
        notify_user(senior_username, message)


def create_pending_command_request(
    *,
    requester_username: str,
    requester_role: str,
    command_mode: str,
    command_text: str,
    device_names: list[str],
) -> int:
    normalized_devices = [str(name).strip() for name in device_names if str(name).strip()]
    with db_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO pending_command_requests(
                requester_username, requester_role, command_mode, command_text,
                target_devices, status, approver_username, created_at, decided_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', '', ?, '')
            """,
            (
                str(requester_username),
                normalize_role(requester_role),
                str(command_mode or 'show').strip().lower(),
                str(command_text),
                json.dumps(normalized_devices),
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ),
        )
        request_id = int(cursor.lastrowid or 0)

    if request_id > 0:
        notify_seniors_new_pending_command_request(
            request_id=request_id,
            requester_username=str(requester_username),
            command_mode=str(command_mode or 'show').strip().lower(),
            command_text=str(command_text).strip(),
            device_names=normalized_devices,
        )
    return request_id


def run_config_commands(
    host: str,
    port: int,
    username: str,
    password: str,
    command_text: str,
    timeout: int,
    enable_password: str = "",
) -> tuple[str, str]:
    import paramiko

    commands = split_cli_commands(command_text)
    if not commands:
        return "FAIL", "No command provided."

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        channel = client.invoke_shell(width=180, height=40)
        time.sleep(0.25)
        while channel.recv_ready():
            channel.recv(4096)

        output_parts: list[str] = []

        channel.send("terminal length 0\n")
        text = _read_shell_output(channel, timeout)
        if text:
            output_parts.append(text)

        lower_cmds = [cmd.strip().lower() for cmd in commands]
        if any(cmd.startswith(("configure terminal", "conf t", "interface ")) for cmd in lower_cmds):
            channel.send("enable\n")
            enable_prompt = _read_shell_output(channel, timeout)
            if enable_prompt:
                output_parts.append(enable_prompt)
                if "password" in enable_prompt.lower() and enable_password:
                    channel.send(enable_password + "\n")
                    post_enable = _read_shell_output(channel, timeout)
                    if post_enable:
                        output_parts.append(post_enable)

        for cmd in commands:
            channel.send(cmd + "\n")
            text = _read_shell_output(channel, timeout)
            if text:
                output_parts.append(text)

        return "PASS", "\n".join(output_parts).strip() or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass


def run_ssh_command(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
    timeout: int,
    command_mode: str = "show",
    enable_password: str = "",
) -> tuple[str, str]:
    import paramiko

    commands = split_cli_commands(command)
    mode = str(command_mode or "show").strip().lower()
    if mode == "config":
        return run_config_commands(
            host=host,
            port=port,
            username=username,
            password=password,
            command_text=command,
            timeout=timeout,
            enable_password=enable_password,
        )

    if not commands:
        return "FAIL", "No command provided."

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        _, stdout, stderr = client.exec_command(commands[0], timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        text = out if out.strip() else err
        return "PASS", text or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        client.close()


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str, command_mode: str = "show") -> SSHResult:
    status, output = run_ssh_command(
        host=device["host"],
        port=int(device.get("port", 22)),
        username=creds["username"],
        password=creds["password"],
        command=command,
        timeout=int(creds.get("timeout", 8)),
        command_mode=command_mode,
        enable_password=str(creds.get("enable_password", "")),
    )
    return SSHResult(device=device["name"], host=device["host"], status=status, output=output)


@app.route("/")
def root() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if "auth_mode" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.before_request
def enforce_dashboard_session_timeout() -> Any:
    if "creds" not in session:
        return None

    endpoint = request.endpoint or ""
    if endpoint in {"static", "login", "logout", "setup_super_admin", "change_password"}:
        return None

    settings = load_session_settings()
    timeout_seconds = max(60, int(settings.get("idle_timeout_minutes", 15)) * 60)
    now = int(time.time())
    last_activity = int(session.get("last_activity_ts", now))

    if now - last_activity > timeout_seconds:
        session.clear()
        session["login_info"] = "Session expired due to inactivity. Please log in again."
        return redirect(url_for("login"))

    session["last_activity_ts"] = now
    return None


@app.route("/super-admin/setup", methods=["GET", "POST"])
def setup_super_admin() -> Any:
    if super_admin_exists():
        return redirect(url_for("login"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            error = "Username and password are required."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            save_super_admin(username, password)
            return redirect(url_for("login"))

    return render_template("super_admin_setup.html", error=error)


@app.route("/super-admin/verify", methods=["GET", "POST"])
def verify_super_admin_route() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_super_admin(username, password):
            session["super_admin_verified"] = True
            return redirect(url_for("ise_settings_page"))
        error = "Invalid super admin credentials."

    return render_template("super_admin_verify.html", error=error)


@app.route("/settings/ise", methods=["GET", "POST"])
def ise_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    info = session.pop("settings_info", "")
    error = session.pop("settings_error", "")
    settings = load_ise_settings()

    if request.method == "POST":
        data = {
            "primary_server": request.form.get("primary_server", "").strip(),
            "primary_port": request.form.get("primary_port", "1812").strip(),
            "primary_shared_secret": request.form.get("primary_shared_secret", ""),
            "secondary_server": request.form.get("secondary_server", "").strip(),
            "secondary_port": request.form.get("secondary_port", "1812").strip(),
            "secondary_shared_secret": request.form.get("secondary_shared_secret", ""),
            "timeout": request.form.get("timeout", "5").strip(),
            "nas_ip": request.form.get("nas_ip", "127.0.0.1").strip(),
        }
        try:
            save_ise_settings(data)
            settings = load_ise_settings()
            info = "ISE settings updated."
        except Exception as exc:
            error = f"Failed to save settings: {exc}"

    devices = load_devices()
    return render_template(
        "ise_settings.html",
        ise=settings,
        info=info,
        error=error,
        users=load_users(),
        available_categories=all_categories(devices),
        selected_modal=request.args.get("modal", ""),
        ntp=load_ntp_settings(),
        session_settings=load_session_settings(),
    )


@app.route("/settings/ntp/test", methods=["POST"])
def ntp_test_page() -> Any:
    if not super_admin_exists():
        return jsonify({"ok": False, "message": "Super admin setup is required."}), 403
    if not session.get("super_admin_verified"):
        return jsonify({"ok": False, "message": "Super admin verification is required."}), 403

    server = request.form.get("ntp_server", "").strip()
    port_raw = request.form.get("ntp_port", "123").strip()
    timeout_raw = request.form.get("ntp_timeout", "3").strip()

    try:
        port = int(port_raw or 123)
        timeout = int(timeout_raw or 3)
    except ValueError:
        return jsonify({"ok": False, "message": "NTP port/timeout must be numbers."}), 400

    ok, message = test_ntp_connectivity(server, port, timeout)
    return jsonify({"ok": ok, "message": message})


@app.route("/settings/ntp", methods=["POST"])
def ntp_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    settings = load_ntp_settings()
    mode = request.form.get("ntp_mode", "ntp").strip().lower()
    if mode not in {"ntp", "manual"}:
        mode = "ntp"

    server = request.form.get("ntp_server", "").strip()
    port_raw = request.form.get("ntp_port", "123").strip()
    timeout_raw = request.form.get("ntp_timeout", "3").strip()
    manual_time_raw = request.form.get("manual_time", "").strip()

    try:
        port = int(port_raw or 123)
        timeout = int(timeout_raw or 3)
    except ValueError:
        session["settings_error"] = "NTP port/timeout must be numbers."
        return redirect(url_for("ise_settings_page", modal="ntp"))

    settings["mode"] = mode
    settings["server"] = server
    settings["port"] = port
    settings["sync_timeout"] = timeout
    settings["manual_time"] = manual_time_raw

    action = request.form.get("action", "save").strip()
    if action == "sync":
        ok, message, ntp_time = sync_ntp_time(server, port, timeout)
        if ok:
            settings["mode"] = "ntp"
            settings["last_sync"] = ntp_time
            settings["last_status"] = message
            session["settings_info"] = message
        else:
            settings["last_status"] = message
            session["settings_error"] = message
    elif action == "set_manual":
        if not manual_time_raw:
            session["settings_error"] = "Manual time is required."
        else:
            try:
                parsed = datetime.fromisoformat(manual_time_raw)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                settings["mode"] = "manual"
                settings["last_sync"] = parsed.isoformat()
                settings["last_status"] = "Manual time saved by super admin."
                session["settings_info"] = "Manual time saved."
            except ValueError:
                session["settings_error"] = "Invalid manual time format."
    else:
        session["settings_info"] = "NTP settings saved."

    save_ntp_settings(settings)
    return redirect(url_for("ise_settings_page", modal="ntp"))





@app.route("/settings/session", methods=["POST"])
def session_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    timeout_raw = request.form.get("idle_timeout_minutes", "15").strip()
    try:
        timeout_minutes = int(timeout_raw or 15)
        if timeout_minutes < 1:
            raise ValueError
    except ValueError:
        session["settings_error"] = "Session timeout must be a positive number of minutes."
        return redirect(url_for("ise_settings_page", modal="session"))

    save_session_settings({
        "idle_timeout_minutes": timeout_minutes,
    })
    session["settings_info"] = "Idle logout settings updated."
    return redirect(url_for("ise_settings_page", modal="session"))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))

    error = ""
    info = session.pop("login_info", "")
    if request.args.get("expired") == "1":
        info = "Session expired due to inactivity. Please log in again."
    settings = load_ise_settings()

    if request.method == "POST":
        auth_mode = request.form.get("auth_mode", "local")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not username:
            error = "Username is required."
        elif auth_mode == "ise":
            if not password:
                error = "Password is required for ISE login."
            else:
                ok, message = authenticate_with_ise(username, password, settings)
                if not ok:
                    error = message
        else:
            ok, local_message, role = validate_local_user(username, password)
            if not ok and local_message == "PASSWORD_SETUP_REQUIRED":
                session["pending_password_user"] = username
                session["pending_password_role"] = role or "operator"
                return redirect(url_for("change_password"))
            if not ok:
                error = local_message

        if not error:
            session["auth_mode"] = auth_mode
            session["creds"] = {"username": username, "password": password, "timeout": timeout}
            session["device_creds"] = load_user_device_creds(username, auth_mode)
            session["buttons"] = load_user_buttons(username, auth_mode) or default_buttons()
            session.setdefault("run_history", [])
            session["last_activity_ts"] = int(time.time())
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error, info=info)


@app.route("/change-password", methods=["GET", "POST"])
def change_password() -> Any:
    username = session.get("pending_password_user", "")
    if not username:
        return redirect(url_for("login"))

    error = ""
    info = ""
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not new_password:
            error = "New password is required."
        elif new_password != confirm_password:
            error = "Passwords do not match."
        else:
            if verify_super_admin(username, new_password):
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = load_user_device_creds(username, "local")
                session["buttons"] = load_user_buttons(username, "local") or default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

            users = load_users()
            user = find_user(users, username)
            if user is None:
                error = "User no longer exists."
            else:
                set_user_password(user, new_password)
                user["must_change_password"] = False
                save_users(users)
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = load_user_device_creds(username, "local")
                session["buttons"] = load_user_buttons(username, "local") or default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

    return render_template("change_password.html", username=username, error=error, info=info)


@app.route("/settings/users", methods=["POST"])
def manage_users() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    action = request.form.get("action", "").strip()
    users = load_users()

    if action == "create":
        username = request.form.get("new_username", "").strip()
        create_role = normalize_role(request.form.get("create_role", "junior"))
        if not username:
            session["settings_error"] = "Username is required to create user."
        elif load_super_admin().get("username", "").strip().lower() == username.lower():
            session["settings_error"] = "This username is reserved for super admin."
        else:
            ok, message = upsert_user(username, create_role)
            if ok:
                session["settings_info"] = f"{message} Role set to '{create_role}'."
            else:
                session["settings_error"] = message

    elif action == "delete":
        username = request.form.get("selected_username", "").strip()
        before = len(users)
        users = [u for u in users if str(u.get("username", "")).strip().lower() != username.lower()]
        if len(users) == before:
            session["settings_error"] = "User not found."
        else:
            save_users(users)
            session["settings_info"] = f"User '{username}' deleted."

    elif action == "reset_password":
        username = request.form.get("selected_username", "").strip()
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["salt"] = ""
            user["password_hash"] = ""
            user["must_change_password"] = True
            save_users(users)
            session["settings_info"] = f"Password reset for '{username}'. User must set password on next login."

    elif action == "force_change":
        username = request.form.get("selected_username", "").strip()
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["must_change_password"] = True
            save_users(users)
            session["settings_info"] = f"User '{username}' will be forced to change password at next login."

    elif action == "set_role":
        username = request.form.get("selected_username", "").strip()
        role_value = normalize_role(request.form.get("role_value", "junior"))
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["role"] = role_value
            save_users(users)
            session["settings_info"] = f"Updated role for '{username}' to '{role_value}'."

    elif action == "set_user_rights":
        username = request.form.get("selected_username", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("allowed_categories") if c.strip()]
        selected_account_privileges = [p.strip() for p in request.form.getlist("account_privileges") if p.strip()]
        allowed_account_privileges = {"devices", "ip_addressing"}
        selected_account_privileges = [p for p in selected_account_privileges if p in allowed_account_privileges]
        selected_permissions = [p.strip() for p in request.form.getlist("admin_permissions") if p.strip()]
        allowed_permissions = {"create_category", "edit_device", "move_device_category", "delete_device", "delete_category"}
        selected_permissions = [p for p in selected_permissions if p in allowed_permissions]
        if "move_device_category" in selected_permissions and "edit_device" not in selected_permissions:
            selected_permissions.append("edit_device")

        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["allowed_categories"] = selected_categories
            user["category_panel_access"] = {}
            user["account_privileges"] = selected_account_privileges
            user["admin_permissions"] = selected_permissions
            save_users(users)
            session["settings_info"] = f"Updated user rights for '{username}'."

    return redirect(url_for("ise_settings_page", modal="users"))


@app.route("/notifications/read", methods=["POST"])
def mark_notifications_read_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    mark_notifications_read(username)
    session["dashboard_info"] = "Notifications marked as read."
    return redirect(url_for("dashboard"))


@app.route("/notifications/delete", methods=["POST"])
def delete_notification_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    notification_id = int(request.form.get("notification_id", "0") or 0)
    if notification_id > 0:
        delete_notification(username, notification_id)
        session["dashboard_info"] = "Notification deleted."
    return redirect(url_for("dashboard"))


@app.route("/pending-requests/cleanup", methods=["POST"])
def pending_requests_cleanup() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if not is_senior_user():
        session["dashboard_error"] = "Only Senior users can delete processed requests."
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "").strip()
    request_id = int(request.form.get("request_id", "0") or 0)
    with db_conn() as conn:
        if action == "delete_one" and request_id > 0:
            conn.execute("DELETE FROM pending_device_requests WHERE id = ? AND status IN ('approved','rejected')", (request_id,))
            session["dashboard_info"] = f"Processed request #{request_id} deleted."
        elif action == "delete_all_closed":
            conn.execute("DELETE FROM pending_device_requests WHERE status IN ('approved','rejected')")
            session["dashboard_info"] = "All processed requests deleted."
    return redirect(url_for("dashboard"))


@app.route("/pending-requests", methods=["POST"])
def pending_requests_action() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if not is_senior_user():
        session["dashboard_error"] = "Only Senior users can review pending requests."
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "").strip().lower()
    request_id = int(request.form.get("request_id", "0") or 0)
    request_type = request.form.get("request_type", "device").strip().lower() or "device"
    if request_id <= 0 or action not in {"approve", "reject"} or request_type not in {"device", "command"}:
        session["dashboard_error"] = "Invalid pending request action."
        return redirect(url_for("dashboard"))

    if request_type == "command":
        with db_conn() as conn:
            row = conn.execute("SELECT * FROM pending_command_requests WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
        if not row:
            session["dashboard_error"] = "Request not found or already decided. A request can be approved/rejected only once."
            return redirect(url_for("dashboard"))

        requester = str(row["requester_username"])
        approver = str(session.get("creds", {}).get("username", ""))
        command_mode = str(row["command_mode"])
        command_text = str(row["command_text"])
        try:
            target_devices = json.loads(str(row["target_devices"] or "[]"))
        except Exception:
            target_devices = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        new_status = "approved" if action == "approve" else "rejected"

        with db_conn() as conn:
            updated = conn.execute(
                "UPDATE pending_command_requests SET status = ?, approver_username = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                (new_status, approver, now, request_id),
            )
        if updated.rowcount == 0:
            session["dashboard_error"] = "Request already decided by another Senior user."
            return redirect(url_for("dashboard"))

        is_branch_delete = str(command_mode).strip().lower() == "branch_delete"
        branch_name = parse_branch_delete_command(command_text) if is_branch_delete else ""
        if new_status == "approved":
            if is_branch_delete:
                notify_user(
                    requester,
                    f"Command request #{request_id} was approved for branch delete '{branch_name}'. Continue delete (Run) or Cancel (Discard) from Notifications.",
                )
            else:
                notify_user(
                    requester,
                    f"Command request #{request_id} was approved. Run command or Discard from Notifications. Command: '{str(command_text).strip()}'.",
                )
        else:
            if is_branch_delete:
                notify_user(
                    requester,
                    f"Command request #{request_id} for branch delete '{branch_name}' was rejected.",
                )
            else:
                notify_user(
                    requester,
                    f"Command request #{request_id} was rejected. Command: '{str(command_text).strip()}'.",
                )
        write_audit_log(
            f"command_request_{new_status}",
            requester,
            approver,
            ",".join(str(d).strip() for d in target_devices if str(d).strip()),
            {
                "request_id": request_id,
                "command_mode": command_mode,
                "command_text": command_text,
                "target_devices": target_devices,
            },
        )
        clear_senior_command_request_notifications(request_id)
        session["dashboard_info"] = f"{new_status.title()} request #{request_id}."
        return redirect(url_for("dashboard"))

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_device_requests WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
    if not row:
        session["dashboard_error"] = "Request not found or already decided. A request can be approved/rejected only once."
        return redirect(url_for("dashboard"))

    requester = str(row["requester_username"])
    device_name = str(row["device_name"])
    original_ip = str(row["original_ip"])
    proposed_ip = str(row["proposed_ip"])
    try:
        original_categories = json.loads(str(row["original_categories"] or "[]"))
    except Exception:
        original_categories = []
    try:
        proposed_categories = json.loads(str(row["proposed_categories"] or "[]"))
    except Exception:
        proposed_categories = []

    approver = str(session.get("creds", {}).get("username", ""))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if action == "approve":
        devices = load_devices()
        target = next((d for d in devices if str(d.get("name", "")).strip() == device_name), None)

        if target is None:
            with db_conn() as conn:
                update_missing = conn.execute(
                    "UPDATE pending_device_requests SET status = 'rejected', approver_username = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                    (approver, now, request_id),
                )
            if update_missing.rowcount == 0:
                session["dashboard_error"] = "Request already decided by another Senior user."
                return redirect(url_for("dashboard"))
            notify_user(requester, f"Your request #{request_id} was rejected because device no longer exists.")
            write_audit_log("request_rejected", requester, approver, device_name, {
                "request_id": request_id,
                "reason": "device_missing",
            })
            clear_senior_pending_request_notifications(request_id)
            session["dashboard_error"] = "Device not found. Request rejected."
            return redirect(url_for("dashboard"))

        target["name"] = str(row["proposed_hostname"])
        target["host"] = proposed_ip
        target["groups"] = [str(g).strip() for g in proposed_categories if str(g).strip()]

        with db_conn() as conn:
            update_approved = conn.execute(
                "UPDATE pending_device_requests SET status = 'approved', approver_username = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                (approver, now, request_id),
            )
            if update_approved.rowcount == 0:
                session["dashboard_error"] = "Request already decided by another Senior user."
                return redirect(url_for("dashboard"))
            save_devices(devices, conn=conn)

        notify_user(
            requester,
            f"Your request #{request_id} for device '{device_name}' was approved. "
            f"Requested IP: {original_ip} → {proposed_ip}; categories: {', '.join(original_categories) or '-'} → {', '.join(proposed_categories) or '-'}.",
        )
        write_audit_log("request_approved", requester, approver, device_name, {
            "request_id": request_id,
            "fields": {
                "ip": {"from": original_ip, "to": proposed_ip},
                "categories": {"from": original_categories, "to": proposed_categories},
            },
        })
        clear_senior_pending_request_notifications(request_id)
        session["dashboard_info"] = f"Approved request #{request_id}."
        return redirect(url_for("dashboard"))

    with db_conn() as conn:
        update_rejected = conn.execute(
            "UPDATE pending_device_requests SET status = 'rejected', approver_username = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
            (approver, now, request_id),
        )
    if update_rejected.rowcount == 0:
        session["dashboard_error"] = "Request already decided by another Senior user."
        return redirect(url_for("dashboard"))

    notify_user(
        requester,
        f"Your request #{request_id} for device '{device_name}' was rejected. "
        f"Requested IP: {original_ip} → {proposed_ip}; categories: {', '.join(original_categories) or '-'} → {', '.join(proposed_categories) or '-'}.",
    )
    write_audit_log("request_rejected", requester, approver, device_name, {
        "request_id": request_id,
        "fields": {
            "ip": {"from": original_ip, "to": proposed_ip},
            "categories": {"from": original_categories, "to": proposed_categories},
        },
    })

    clear_senior_pending_request_notifications(request_id)
    session["dashboard_info"] = f"Rejected request #{request_id}."
    return redirect(url_for("dashboard"))


@app.route("/pending-command/decision", methods=["POST"])
def pending_command_decision() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip().lower()
    request_id = int(request.form.get("request_id", "0") or 0)
    if action not in {"run", "discard", "reject"} or request_id <= 0:
        session["dashboard_error"] = "Invalid command decision."
        return redirect(url_for("dashboard"))

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    request_item = load_pending_command_request_by_id(request_id)
    if not request_item:
        session["dashboard_error"] = "Command request not found."
        return redirect(url_for("dashboard"))

    if str(request_item.get("requester_username", "")).strip().lower() != current_username.lower():
        session["dashboard_error"] = "You can only act on your own command requests."
        return redirect(url_for("dashboard"))

    if str(request_item.get("status", "")).strip().lower() != "approved":
        session["dashboard_error"] = "This command request is no longer available."
        return redirect(url_for("dashboard"))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if action in {"discard", "reject"}:
        with db_conn() as conn:
            updated = conn.execute(
                "UPDATE pending_command_requests SET status = 'discarded', decided_at = ? WHERE id = ? AND status = 'approved'",
                (now, request_id),
            )
        if updated.rowcount == 0:
            session["dashboard_error"] = "This command request was already handled."
            return redirect(url_for("dashboard"))
        mark_notifications_read(current_username)
        command_mode = str(request_item.get("command_mode", "show")).strip().lower()
        if command_mode == "branch_delete":
            branch_name = parse_branch_delete_command(str(request_item.get("command_text", ""))) or "selected branch"
            session["dashboard_info"] = f"Branch delete request #{request_id} canceled for '{branch_name}'."
            return redirect(url_for("ip_addressing_dashboard"))
        session["dashboard_info"] = f"Command request #{request_id} discarded."
        return redirect(url_for("dashboard"))

    # action == run
    command_mode = str(request_item.get("command_mode", "show")).strip().lower()
    if command_mode == "branch_delete":
        branch_name = parse_branch_delete_command(str(request_item.get("command_text", "")))
        if not branch_name:
            session["dashboard_error"] = "Approved branch delete request has invalid payload."
            return redirect(url_for("dashboard"))

        branches = load_ip_branches()
        updated = [item for item in branches if item.strip().lower() != branch_name.lower()]
        if len(updated) == len(branches):
            session["dashboard_error"] = f"Branch '{branch_name}' was not found in central list."
            return redirect(url_for("dashboard"))

        with db_conn() as conn:
            updated_status = conn.execute(
                "UPDATE pending_command_requests SET status = 'executing', decided_at = ? WHERE id = ? AND status = 'approved'",
                (now, request_id),
            )
        if updated_status.rowcount == 0:
            session["dashboard_error"] = "This branch delete request was already handled."
            return redirect(url_for("dashboard"))

        save_ip_branches(updated)
        with db_conn() as conn:
            conn.execute(
                "UPDATE pending_command_requests SET status = 'executed', decided_at = ? WHERE id = ? AND status = 'executing'",
                (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), request_id),
            )
        write_audit_log(
            "branch_delete_executed",
            current_username,
            str(request_item.get("approver_username", "")),
            branch_name,
            {"request_id": request_id, "branch_name": branch_name},
        )
        mark_notifications_read(current_username)
        session["dashboard_info"] = f"Approved branch delete request #{request_id} executed for '{branch_name}'."
        return redirect(url_for("ip_addressing_dashboard"))

    all_devices = load_devices()
    auth_mode = str(session.get("auth_mode", "local"))
    allowed_devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    allowed_by_name = {str(device.get("name", "")).strip(): device for device in allowed_devices}
    requested_device_names = [str(name).strip() for name in request_item.get("target_devices", []) if str(name).strip()]
    target_devices: list[dict[str, Any]] = []
    missing_or_denied: list[str] = []
    for name in requested_device_names:
        matched = allowed_by_name.get(name)
        if matched is None:
            missing_or_denied.append(name)
            continue
        target_devices.append(matched)

    if not requested_device_names:
        session["dashboard_error"] = "Approved command request has no target devices."
        return redirect(url_for("dashboard"))

    if missing_or_denied:
        session["dashboard_error"] = (
            "Approved command can only run on the originally requested devices. "
            f"Unavailable/unauthorized: {', '.join(missing_or_denied)}."
        )
        return redirect(url_for("dashboard"))

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }
    if not creds["username"] or not creds["password"]:
        session["dashboard_error"] = "Set device SSH credentials first from the dashboard user-strip button."
        return redirect(url_for("dashboard"))

    with db_conn() as conn:
        updated = conn.execute(
            "UPDATE pending_command_requests SET status = 'executing', decided_at = ? WHERE id = ? AND status = 'approved'",
            (now, request_id),
        )
    if updated.rowcount == 0:
        session["dashboard_error"] = "This command request was already handled."
        return redirect(url_for("dashboard"))

    results: list[SSHResult] = []
    command_text = str(request_item.get("command_text", ""))
    command_mode = str(request_item.get("command_mode", "show"))
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(target_devices)))) as executor:
        futures = [executor.submit(execute_for_device, device, creds, command_text, command_mode) for device in target_devices]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda result: result.device)

    run_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": command_text,
        "results": [asdict(result) for result in results],
    }
    run_history = session.get("run_history", [])
    run_history.append(run_entry)
    session["run_history"] = run_history[-50:]

    with db_conn() as conn:
        conn.execute(
            "UPDATE pending_command_requests SET status = 'executed', decided_at = ? WHERE id = ? AND status = 'executing'",
            (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), request_id),
        )
    mark_notifications_read(current_username)
    session["dashboard_info"] = f"Approved command request #{request_id} executed once."
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout() -> Any:
    expired = request.args.get("expired") == "1"
    rid = str(session.get("runtime_session_id", ""))
    close_runtime_ssh_sessions(rid)
    session.clear()
    if expired:
        session["login_info"] = "Session expired due to inactivity. Please log in again."
    return redirect(url_for("login"))


@app.route("/ip-addressing", methods=["GET"])
def ip_addressing_dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        if user_has_panel_access(current_username, auth_mode, "devices"):
            session["dashboard_error"] = "You do not have access to the IP Addressing panel."
            return redirect(url_for("dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    branches = load_ip_branches()
    return render_template(
        "ip_addressing.html",
        current_user=current_username,
        current_user_role=current_user_role(),
        auth_mode=auth_mode,
        branches=branches,
        info=session.pop("dashboard_info", ""),
        error=session.pop("dashboard_error", ""),
        unread_notifications_count=len(load_unread_notifications(current_username)),
    )


@app.route("/ip-branches", methods=["POST"])
def manage_ip_branches() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = str(request.form.get("action", "")).strip().lower()
    current_username_value = str(session.get("creds", {}).get("username", "")).strip()
    branches = load_ip_branches()

    if action == "add":
        branch_name = str(request.form.get("branch_name", "")).strip()
        if not branch_name:
            session["dashboard_error"] = "Branch name is required."
            return redirect(url_for("ip_addressing_dashboard"))
        if any(branch_name.lower() == item.lower() for item in branches):
            session["dashboard_error"] = "Branch already exists."
            return redirect(url_for("ip_addressing_dashboard"))
        branches.append(branch_name)
        save_ip_branches(branches)
        session["dashboard_info"] = f"Branch '{branch_name}' added."
        return redirect(url_for("ip_addressing_dashboard"))

    if action == "delete":
        branch_name = str(request.form.get("branch_name", "")).strip()
        if not branch_name:
            session["dashboard_error"] = "Select a branch to delete."
            return redirect(url_for("ip_addressing_dashboard"))

        if not any(item.lower() == branch_name.lower() for item in branches):
            session["dashboard_error"] = "Branch not found."
            return redirect(url_for("ip_addressing_dashboard"))

        if is_senior_user():
            updated = [item for item in branches if item.lower() != branch_name.lower()]
            save_ip_branches(updated)
            write_audit_log("branch_delete_direct", current_username_value, current_username_value, branch_name, {"branch_name": branch_name})
            session["dashboard_info"] = f"Branch '{branch_name}' deleted."
            return redirect(url_for("ip_addressing_dashboard"))

        request_id = create_pending_command_request(
            requester_username=current_username_value,
            requester_role=current_user_role(),
            command_mode="branch_delete",
            command_text=f"DELETE_BRANCH::{branch_name}",
            device_names=[],
        )
        if request_id <= 0:
            session["dashboard_error"] = "Could not create delete approval request."
            return redirect(url_for("ip_addressing_dashboard"))

        session["dashboard_info"] = (
            f"Branch delete request #{request_id} sent to Senior for approval. "
            "After approval, use Notifications to Continue delete or Cancel."
        )
        return redirect(url_for("ip_addressing_dashboard"))

    session["dashboard_error"] = "Unknown branch action."
    return redirect(url_for("ip_addressing_dashboard"))


@app.route("/ip-branches/request-delete", methods=["POST"])
def request_ip_branch_delete() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403

    branch_name = str(request.form.get("branch_name", "")).strip()
    if not branch_name:
        return jsonify({"ok": False, "error": "Select a branch to delete."}), 400

    if is_senior_user():
        branches = load_ip_branches()
        updated = [item for item in branches if item.strip().lower() != branch_name.lower()]
        if len(updated) == len(branches):
            return jsonify({"ok": False, "error": "Branch not found."}), 404
        save_ip_branches(updated)
        write_audit_log("branch_delete_direct", current_username, current_username, branch_name, {"branch_name": branch_name})
        return jsonify({"ok": True, "deleted": True, "message": f"Branch '{branch_name}' deleted."})

    request_id = create_pending_command_request(
        requester_username=current_username,
        requester_role=current_user_role(),
        command_mode="branch_delete",
        command_text=f"DELETE_BRANCH::{branch_name}",
        device_names=[],
    )
    if request_id <= 0:
        return jsonify({"ok": False, "error": "Could not create delete approval request."}), 500

    return jsonify({
        "ok": True,
        "deleted": False,
        "request_id": request_id,
        "message": (
            f"Branch delete request #{request_id} sent to Senior for approval. "
            "After approval, use Notifications to Continue (Run) or Cancel (Discard)."
        ),
    })


@app.route("/dashboard", methods=["GET"])
def dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    groups = grouped_devices(devices)
    categories = all_categories(devices)
    info = session.pop("dashboard_info", "")
    error = session.pop("dashboard_error", "")
    role = current_user_role()
    unread_notifications = load_unread_notifications(current_username)
    pending_requests = load_pending_device_requests() if role == "senior" else []
    pending_command_requests = load_pending_command_requests() if role == "senior" else []
    pending_request_ids: set[int] = set(int(item.get("id", 0)) for item in pending_requests)
    pending_command_request_ids: set[int] = set(int(item.get("id", 0)) for item in pending_command_requests)
    approved_command_request_ids: set[int] = set()

    all_command_requests = load_pending_command_requests(status="all")
    approved_command_request_ids = {
        int(item.get("id", 0))
        for item in all_command_requests
        if str(item.get("status", "")).strip().lower() == "approved"
        and str(item.get("requester_username", "")).strip().lower() == current_username.strip().lower()
    }

    for item in unread_notifications:
        item["pending_request_id"] = 0
        item["pending_request_type"] = ""
        item["pending_request_actionable"] = False
        item["junior_command_actionable"] = False
        msg = str(item.get("message", ""))
        match = re.search(r"request\s*#(\d+)", msg, flags=re.IGNORECASE)
        if not match:
            continue
        req_id = int(match.group(1) or 0)
        if req_id <= 0:
            continue

        lower_msg = msg.lower()
        is_command_request = (
            "critical command approval request" in lower_msg
            or "dangerous command approval" in lower_msg
            or "critical command request" in lower_msg
        )
        item["pending_request_id"] = req_id
        item["pending_request_type"] = "command" if is_command_request else "device"

        if role == "senior":
            if is_command_request:
                item["pending_request_actionable"] = req_id in pending_command_request_ids
            else:
                item["pending_request_actionable"] = req_id in pending_request_ids
        else:
            lower_msg = msg.lower()
            is_approved_notice = (
                "was approved" in lower_msg
                and ("critical command request" in lower_msg or "command request" in lower_msg)
            )
            if is_approved_notice:
                item["junior_command_actionable"] = req_id in approved_command_request_ids
    return render_template(
        "dashboard.html",
        devices=devices,
        groups=groups,
        categories=categories,
        buttons=get_buttons(),
        info=info,
        error=error,
        device_creds=session.get("device_creds", {}),
        ntp=load_ntp_settings(),
        user_admin_permissions=sorted(user_admin_permissions(current_username, auth_mode)),
        selected_modal=request.args.get("modal", ""),
        session_timeout_seconds=max(60, int(load_session_settings().get("idle_timeout_minutes", 15)) * 60),
        run_history=session.get("run_history", []),
        current_user_role=role,
        pending_requests=pending_requests,
        pending_command_requests=pending_command_requests,
        unread_notifications=unread_notifications,
        unread_notifications_count=len(unread_notifications),
    )


@app.route("/devices", methods=["POST"])
def manage_devices() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "add").strip()
    devices = load_devices()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")
    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))

    if action == "add":
        hostname = request.form.get("hostname", "").strip()
        if not is_senior_user():
            session["dashboard_error"] = "Only Senior users can add new devices."
            return redirect(dashboard_modal_url)
        ip_address = request.form.get("ip_address", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("new_device_categories") if c.strip()]
        if not selected_categories:
            selected_categories = [DEFAULT_CATEGORY]
        if not user_can_assign_categories(selected_categories, current_username, auth_mode):
            session["dashboard_error"] = "You can only add devices to categories you are allowed to access."
            return redirect(dashboard_modal_url)

        if not hostname or not ip_address:
            session["dashboard_error"] = "Hostname and IP address are required."
            return redirect(dashboard_modal_url)

        if not is_valid_ipv4(ip_address):
            session["dashboard_error"] = "IP address must be a valid IPv4 value (each octet 0-255)."
            return redirect(dashboard_modal_url)

        if any(str(device.get("name", "")).strip().lower() == hostname.lower() for device in devices):
            session["dashboard_error"] = "Duplicate hostname is not allowed."
            return redirect(dashboard_modal_url)

        if any(str(device.get("host", "")).strip() == ip_address for device in devices):
            session["dashboard_error"] = "Duplicate IP address is not allowed."
            return redirect(dashboard_modal_url)

        devices.append({"name": hostname, "host": ip_address, "port": 22, "groups": selected_categories})
        save_devices(devices)
        session["dashboard_info"] = f"Device '{hostname}' added successfully."
        return redirect(dashboard_modal_url)

    if action == "edit":
        original_name = request.form.get("original_device_name", "").strip()
        requested_name = request.form.get("edit_hostname", "").strip()
        requested_ip = request.form.get("edit_ip_address", "").strip()
        new_categories = [c.strip() for c in request.form.getlist("edit_device_categories") if c.strip()]
        if not original_name:
            session["dashboard_error"] = "Select a device to edit."
            return redirect(dashboard_modal_url)

        target = None
        for device in devices:
            if str(device.get("name", "")).strip() == original_name:
                target = device
                break

        if target is None:
            session["dashboard_error"] = "Device to edit not found."
            return redirect(dashboard_modal_url)

        if not user_can_access_device(target, current_username, auth_mode):
            session["dashboard_error"] = "You can only edit devices in categories you are allowed to access."
            return redirect(dashboard_modal_url)

        new_name = requested_name or str(target.get("name", "")).strip()
        new_ip = requested_ip or str(target.get("host", "")).strip()
        if not new_name or not new_ip:
            session["dashboard_error"] = "Edited device must keep hostname and IP."
            return redirect(dashboard_modal_url)

        if not is_valid_ipv4(new_ip):
            session["dashboard_error"] = "IP address must be a valid IPv4 value (each octet 0-255)."
            return redirect(dashboard_modal_url)

        if not new_categories:
            new_categories = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]

        if not user_can_assign_categories(new_categories, current_username, auth_mode):
            session["dashboard_error"] = "You can only assign categories you are allowed to access."
            return redirect(dashboard_modal_url)

        original_ip = str(target.get("host", "")).strip()
        original_categories = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]
        ip_changed = new_ip != original_ip
        categories_changed = sorted(new_categories) != sorted(original_categories)
        role = current_user_role()
        if role != "senior" and (ip_changed or categories_changed):
            create_pending_device_request(
                requester_username=current_username,
                requester_role=role,
                original_device=target,
                proposed_hostname=new_name,
                proposed_ip=new_ip,
                proposed_categories=new_categories,
            )
            session["dashboard_info"] = "Your IP/category edit request was submitted for Senior approval."
            return redirect(dashboard_modal_url)

        for device in devices:
            if device is target:
                continue
            if str(device.get("name", "")).strip().lower() == new_name.lower():
                session["dashboard_error"] = "Cannot rename: hostname already exists."
                return redirect(dashboard_modal_url)
            if str(device.get("host", "")).strip() == new_ip:
                session["dashboard_error"] = "Cannot change IP: IP already exists."
                return redirect(dashboard_modal_url)

        target["name"] = new_name
        target["host"] = new_ip
        target["groups"] = new_categories
        save_devices(devices)
        session["dashboard_info"] = f"Device '{original_name}' updated."
        return redirect(dashboard_modal_url)

    if action == "delete":
        delete_name = request.form.get("delete_device_name", "").strip()
        admin_password = request.form.get("super_admin_password", "")

        if not current_user_has_admin_permission("delete_device") and not is_super_admin_password(admin_password):
            session["dashboard_error"] = "Deleting devices requires valid super admin password."
            return redirect(dashboard_modal_url)

        if not delete_name:
            session["dashboard_error"] = "Select a device to delete."
            return redirect(dashboard_modal_url)

        delete_target = None
        for device in devices:
            if str(device.get("name", "")).strip() == delete_name:
                delete_target = device
                break

        if delete_target is not None and not user_can_access_device(delete_target, current_username, auth_mode):
            session["dashboard_error"] = "You can only delete devices in categories you are allowed to access."
            return redirect(dashboard_modal_url)

        before = len(devices)
        devices = [d for d in devices if str(d.get("name", "")).strip() != delete_name]
        if len(devices) == before:
            session["dashboard_error"] = "Device not found for deletion."
            return redirect(dashboard_modal_url)

        save_devices(devices)
        session["dashboard_info"] = f"Device '{delete_name}' deleted."
        return redirect(dashboard_modal_url)

    session["dashboard_error"] = "Unknown device action."
    return redirect(dashboard_modal_url)


@app.route("/categories", methods=["POST"])
def manage_categories() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip()
    devices = load_devices()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")

    if action == "create_category":
        if not is_senior_user():
            session["dashboard_error"] = "Only Senior users can create categories."
            return redirect(dashboard_modal_url)

        category_name = request.form.get("category_name", "").strip()
        if category_name:
            found = any(category_name in d.get("groups", []) for d in devices)
            if not found and devices:
                devices[0].setdefault("groups", []).append(category_name)
            save_devices(devices)

    elif action == "assign_device":
        device_name = request.form.get("device_name", "").strip()
        category_name = request.form.get("target_category", "").strip()
        if device_name and category_name:
            target = next((d for d in devices if str(d.get("name", "")).strip() == device_name), None)
            if target is None:
                session["dashboard_error"] = "Device not found for category update."
                return redirect(dashboard_modal_url)

            groups = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]
            if category_name not in groups:
                groups.append(category_name)

            if current_user_role() != "senior":
                requester = str(session.get("creds", {}).get("username", "")).strip()
                create_pending_device_request(
                    requester_username=requester,
                    requester_role=current_user_role(),
                    original_device=target,
                    proposed_hostname=str(target.get("name", "")),
                    proposed_ip=str(target.get("host", "")),
                    proposed_categories=groups,
                )
                session["dashboard_info"] = "Category update submitted for Senior approval."
                return redirect(dashboard_modal_url)

            target["groups"] = groups
            save_devices(devices)

    elif action == "delete_category":
        category_name = request.form.get("delete_category_name", "").strip()
        if category_name.strip().lower() == DEFAULT_CATEGORY.lower():
            session["dashboard_error"] = f"'{DEFAULT_CATEGORY}' category cannot be deleted."
            return redirect(dashboard_modal_url)
        if category_name:
            admin_password = request.form.get("super_admin_password", "")
            if not current_user_has_admin_permission("delete_category") and not is_super_admin_password(admin_password):
                session["dashboard_error"] = "Deleting categories requires valid super admin password."
                return redirect(dashboard_modal_url)
            for device in devices:
                groups = device.setdefault("groups", [])
                device["groups"] = [g for g in groups if g != category_name]
            save_devices(devices)

    return redirect(dashboard_modal_url)


@app.route("/buttons", methods=["POST"])
def buttons_menu() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "")
    buttons = get_buttons()

    if action == "add":
        label = request.form.get("new_label", "").strip()
        command = request.form.get("new_command", "").strip()
        mode = request.form.get("new_mode", "show").strip().lower()
        selected_categories: list[str] = []
        if mode not in {"show", "config"}:
            mode = "show"
        if label and command:
            button_id = f"custom-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
            buttons.append({
                "id": button_id,
                "label": label,
                "command": command,
                "mode": mode,
                "categories": selected_categories,
            })
            session["buttons"] = buttons
    elif action == "rename":
        button_id = request.form.get("button_id", "").strip()
        new_label = request.form.get("rename_label", "").strip()
        if button_id and new_label:
            for item in buttons:
                if item.get("id") == button_id:
                    item["label"] = new_label
                    break
            session["buttons"] = buttons
    elif action == "delete":
        button_id = request.form.get("button_id", "").strip()
        if button_id:
            buttons = [item for item in buttons if str(item.get("id", "")).strip() != button_id]
            session["buttons"] = buttons
            persist_current_user_buttons(buttons)
    elif action == "edit_command":
        button_id = request.form.get("button_id", "").strip()
        new_command_text = request.form.get("edit_command_text", "").strip()
        if button_id and new_command_text:
            for item in buttons:
                if str(item.get("id", "")).strip() == button_id:
                    item["command"] = new_command_text
                    break
            session["buttons"] = buttons
            persist_current_user_buttons(buttons)
    elif action == "clear_history":
        session["run_history"] = []

    if action in {"add", "rename"}:
        persist_current_user_buttons(session.get("buttons", buttons))

    return redirect(url_for("dashboard"))


@app.route("/device-credentials", methods=["POST"])
def update_device_credentials() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    ssh_username = request.form.get("device_ssh_username", "").strip()
    ssh_password = request.form.get("device_ssh_password", "")
    enable_password = request.form.get("device_enable_password", "")

    if not ssh_username or not ssh_password:
        session["dashboard_error"] = "Device SSH username and password are required."
        return redirect(url_for("dashboard"))

    updated_creds = {
        "username": ssh_username,
        "password": ssh_password,
        "enable_password": enable_password,
    }
    session["device_creds"] = updated_creds

    account = session.get("creds", {})
    account_username = str(account.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if account_username:
        save_user_device_creds(account_username, auth_mode, updated_creds)
    session["dashboard_info"] = "Device credentials updated. New RUN actions will use these credentials."
    return redirect(url_for("dashboard"))


@app.route("/devices/test-connectivity", methods=["POST"])
def test_device_connectivity() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "message": "Not authenticated."}), 401

    payload = request.get_json(silent=True) or {}
    ip_address = str(payload.get("ip_address", "")).strip()
    if not ip_address:
        return jsonify({"ok": False, "message": "IP address is required."}), 400
    if not is_valid_ipv4(ip_address):
        return jsonify({"ok": False, "message": "Enter a valid IPv4 address (each octet 0-255)."}), 400

    icmp_ok = False
    ssh_ok = False

    if os.name == "nt":
        ping_cmd = ["ping", "-n", "1", "-w", "2000", ip_address]
    else:
        ping_cmd = ["ping", "-c", "1", "-W", "2", ip_address]

    try:
        ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, check=False)
        if ping_result.returncode == 0:
            icmp_ok = True
    except OSError:
        icmp_ok = False

    try:
        with socket.create_connection((ip_address, 22), timeout=4):
            pass
        ssh_ok = True
    except OSError:
        ssh_ok = False

    status_lines = [
        "ICMP successfully" if icmp_ok else "ICMP fail",
        "SSH successfully" if ssh_ok else "SSH fail",
    ]
    return jsonify({
        "ok": icmp_ok and ssh_ok,
        "message": " | ".join(status_lines),
        "icmp_ok": icmp_ok,
        "ssh_ok": ssh_ok,
    })


@app.route("/ping-selected", methods=["POST"])
def ping_selected_devices() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "message": "Not authenticated."}), 401

    payload = request.get_json(silent=True) or {}
    selected_names = payload.get("selected_devices", [])
    if not isinstance(selected_names, list):
        selected_names = []

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {str(device.get("name", "")): device for device in devices}

    chosen = [by_name[name] for name in selected_names if name in by_name]
    if not chosen:
        return jsonify({"ok": False, "message": "Select at least one device to ping."}), 400

    sections: list[str] = []
    any_success = False
    for device in chosen:
        host = str(device.get("host", "")).strip()
        name = str(device.get("name", "")).strip()
        if not host:
            sections.append(f"{name}: .....\nNo host configured.\n")
            continue
        ping_text = run_ping_for_host(host, count=5)
        if "!" in ping_text.splitlines()[1] if len(ping_text.splitlines()) > 1 else False:
            any_success = True
        sections.append(f"Device: {name} ({host})\n{ping_text}")

    return jsonify({"ok": any_success, "output": "\n".join(sections)})


@app.route("/run", methods=["POST"])
def run_commands() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {device["name"]: device for device in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()
    command_mode = str(request.form.get("command_mode", "show")).strip().lower() or "show"

    command = manual_command or selected_command
    if not command:
        return render_template("output.html", run_history=session.get("run_history", []), error="No command provided.")

    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        return render_template("output.html", run_history=session.get("run_history", []), error="No devices selected.")

    if current_user_role() == "junior" and command_requires_senior_approval(command):
        request_id = create_pending_command_request(
            requester_username=current_username,
            requester_role=current_user_role(),
            command_mode=command_mode,
            command_text=command,
            device_names=[str(device.get("name", "")).strip() for device in selected_devices],
        )
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error=f"Critical command blocked. Approval request #{request_id} sent to senior users.",
        )

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="Set device SSH credentials first from the dashboard user-strip button.",
        )

    results: list[SSHResult] = []

    with ThreadPoolExecutor(max_workers=min(20, max(1, len(selected_devices)))) as executor:
        futures = [executor.submit(execute_for_device, device, creds, command, command_mode) for device in selected_devices]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda result: result.device)
    run_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": command,
        "results": [asdict(result) for result in results],
    }
    run_history = session.get("run_history", [])
    run_history.append(run_entry)
    session["run_history"] = run_history[-50:]

    return render_template("output.html", run_history=session.get("run_history", []), error="")


@app.route("/run-api", methods=["POST"])
def run_commands_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {device["name"]: device for device in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()
    command_mode = str(request.form.get("command_mode", "show")).strip().lower() or "show"

    command = manual_command or selected_command
    if not command:
        return jsonify({"ok": False, "error": "No command provided."}), 400

    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        return jsonify({"ok": False, "error": "No devices selected."}), 400

    if current_user_role() == "junior" and command_requires_senior_approval(command):
        request_id = create_pending_command_request(
            requester_username=current_username,
            requester_role=current_user_role(),
            command_mode=command_mode,
            command_text=command,
            device_names=[str(device.get("name", "")).strip() for device in selected_devices],
        )
        return jsonify({
            "ok": False,
            "requires_approval": True,
            "request_id": request_id,
            "error": f"Critical command blocked. Approval request #{request_id} sent to senior users.",
        }), 202

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    results: list[SSHResult] = []
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(selected_devices)))) as executor:
        futures = [executor.submit(execute_for_device, device, creds, command, command_mode) for device in selected_devices]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda result: result.device)
    run_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": command,
        "results": [asdict(result) for result in results],
    }
    run_history = session.get("run_history", [])
    run_history.append(run_entry)
    session["run_history"] = run_history[-50:]

    return jsonify({"ok": True, "timestamp": run_entry["timestamp"], "command": command, "results": run_entry["results"]})


@app.route("/ssh-session-open", methods=["POST"])
def open_ssh_sessions_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    payload = request.get_json(silent=True) or {}
    selected_names = payload.get("selected_devices") or []
    if not isinstance(selected_names, list):
        selected_names = []
    selected_names = [str(name).strip() for name in selected_names if str(name).strip()]
    if not selected_names:
        return jsonify({"ok": False, "error": "No devices selected."}), 400

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {str(device.get("name", "")).strip(): device for device in devices}

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    rid = runtime_session_id()
    opened: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for name in selected_names:
        device = by_name.get(name)
        if device is None:
            failed.append({"device": name, "error": "Not found or not allowed."})
            continue
        ok, message = open_runtime_device_session(rid, device, creds)
        if ok:
            opened.append({"device": name, "message": message})
        else:
            failed.append({"device": name, "error": message})

    return jsonify({
        "ok": bool(opened),
        "opened": opened,
        "failed": failed,
        "error": "Could not open SSH session for selected devices." if not opened else "",
    })


@app.route("/run-session-api", methods=["POST"])
def run_session_command_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    device_name = request.form.get("device_name", "").strip()
    command = request.form.get("command", "").strip()

    if not device_name:
        return jsonify({"ok": False, "error": "Select a device session first."}), 400

    if not command:
        return jsonify({"ok": False, "error": "Command is required."}), 400

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    target_device = next((device for device in devices if str(device.get("name", "")).strip() == device_name), None)

    if target_device is None:
        return jsonify({"ok": False, "error": "Device session is not available for your account."}), 404

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    rid = runtime_session_id()
    status, output = run_runtime_device_command(rid, target_device, creds, command)
    result = SSHResult(device=target_device["name"], host=target_device["host"], status=status, output=output)
    run_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": command,
        "results": [asdict(result)],
    }
    run_history = session.get("run_history", [])
    run_history.append(run_entry)
    session["run_history"] = run_history[-50:]

    return jsonify({"ok": True, "timestamp": run_entry["timestamp"], "command": command, "results": run_entry["results"]})


@app.context_processor
def inject_common_context() -> dict[str, Any]:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    can_access_devices = bool(current_username) and user_has_panel_access(current_username, auth_mode, "devices")
    return {
        "current_user": current_username,
        "auth_mode": auth_mode,
        "is_super_admin_session": is_current_session_super_admin(),
        "can_access_devices_panel": can_access_devices,
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
