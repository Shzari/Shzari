#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import secrets
import socket
import struct
import subprocess
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


def super_admin_exists() -> bool:
    return SUPER_ADMIN_FILE.exists()


def load_super_admin() -> dict[str, Any]:
    if not SUPER_ADMIN_FILE.exists():
        return {}
    with SUPER_ADMIN_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_super_admin(username: str, password: str) -> None:
    salt = secrets.token_hex(16)
    payload = {
        "username": username.strip(),
        "salt": salt,
        "password_hash": _hash_password(password, salt),
    }
    with SUPER_ADMIN_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


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
    if not USERS_FILE.exists():
        return []
    with USERS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        user = dict(item)
        user.setdefault("role", "operator")
        user.setdefault("salt", "")
        user.setdefault("password_hash", "")
        user.setdefault("must_change_password", True)
        user.setdefault("allowed_categories", None)
        normalized.append(user)
    return normalized


def save_users(users: list[dict[str, Any]]) -> None:
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


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


def upsert_user(username: str) -> tuple[bool, str]:
    users = load_users()
    if find_user(users, username) is not None:
        return False, "User already exists."
    users.append({
        "username": username.strip(),
        "role": "operator",
        "salt": "",
        "password_hash": "",
        "must_change_password": True,
        "allowed_categories": None,
    })
    save_users(users)
    return True, f"User '{username}' created. Password will be set on first login."

def load_devices() -> list[dict[str, Any]]:
    if not DEVICES_FILE.exists():
        return []
    with DEVICES_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("devices_web.json must be a JSON array")
    return data


def save_devices(devices: list[dict[str, Any]]) -> None:
    with DEVICES_FILE.open("w", encoding="utf-8") as f:
        json.dump(devices, f, indent=2)


def grouped_devices(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for group in device.get("groups", []):
            groups.setdefault(group, []).append(device)
    return groups




def all_categories(devices: list[dict[str, Any]]) -> list[str]:
    categories: set[str] = set()
    for device in devices:
        for group in device.get("groups", []):
            categories.add(str(group))
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

    allowed = user.get("allowed_categories")
    if allowed is None:
        return None
    if isinstance(allowed, list):
        return [str(item).strip() for item in allowed if str(item).strip()]
    return []


def filter_devices_for_user(devices: list[dict[str, Any]], username: str, auth_mode: str) -> list[dict[str, Any]]:
    allowed = user_allowed_categories(username, auth_mode)
    if allowed is None:
        return devices

    allowed_set = set(allowed)
    filtered: list[dict[str, Any]] = []
    for device in devices:
        groups = {str(g).strip() for g in device.get("groups", []) if str(g).strip()}
        if groups & allowed_set:
            filtered.append(device)
    return filtered

def default_buttons() -> list[dict[str, str]]:
    return [
        {"id": "show-version", "label": "Show Version", "command": "show version"},
        {"id": "show-ip-int-brief", "label": "IP Interface Brief", "command": "show ip interface brief"},
        {"id": "show-int-status", "label": "Interfaces Status", "command": "show interfaces status"},
        {"id": "show-logging", "label": "Show Logging", "command": "show logging | tail 50"},
        {"id": "show-hostname", "label": "Show Hostname", "command": "show running-config | include hostname"},
        {"id": "show-arp", "label": "Show ARP", "command": "show arp"},
        {"id": "show-cdp", "label": "CDP Neighbors", "command": "show cdp neighbors"},
        {"id": "show-route", "label": "IP Route", "command": "show ip route"},
    ]


def get_buttons() -> list[dict[str, str]]:
    buttons = session.get("buttons")
    if isinstance(buttons, list) and buttons:
        return buttons
    buttons = default_buttons()
    session["buttons"] = buttons
    return buttons


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
    if not ISE_SETTINGS_FILE.exists():
        return default_ise_settings()
    with ISE_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_ise_settings()
    defaults.update(data)
    return defaults


def save_ise_settings(settings: dict[str, Any]) -> None:
    payload = {
        "primary_server": str(settings.get("primary_server", "")).strip(),
        "primary_port": int(settings.get("primary_port", 1812) or 1812),
        "primary_shared_secret": str(settings.get("primary_shared_secret", "")),
        "secondary_server": str(settings.get("secondary_server", "")).strip(),
        "secondary_port": int(settings.get("secondary_port", 1812) or 1812),
        "secondary_shared_secret": str(settings.get("secondary_shared_secret", "")),
        "timeout": int(settings.get("timeout", 5) or 5),
        "nas_ip": str(settings.get("nas_ip", "127.0.0.1")).strip(),
    }
    with ISE_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


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


def run_ssh_command(host: str, port: int, username: str, password: str, command: str, timeout: int) -> tuple[str, str]:
    import paramiko

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
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        text = out if out.strip() else err
        return "PASS", text or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        client.close()


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str) -> SSHResult:
    status, output = run_ssh_command(
        host=device["host"],
        port=int(device.get("port", 22)),
        username=creds["username"],
        password=creds["password"],
        command=command,
        timeout=int(creds.get("timeout", 8)),
    )
    return SSHResult(device=device["name"], host=device["host"], status=status, output=output)


@app.route("/")
def root() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if "auth_mode" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


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
    )


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))

    error = ""
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
            session.setdefault("buttons", default_buttons())
            session.setdefault("run_history", [])
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


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
                session.setdefault("buttons", default_buttons())
                session.setdefault("run_history", [])
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
                session.setdefault("buttons", default_buttons())
                session.setdefault("run_history", [])
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
        if not username:
            session["settings_error"] = "Username is required to create user."
        elif load_super_admin().get("username", "").strip().lower() == username.lower():
            session["settings_error"] = "This username is reserved for super admin."
        else:
            ok, message = upsert_user(username)
            if ok:
                session["settings_info"] = message
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

    elif action == "set_categories":
        username = request.form.get("selected_username", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("allowed_categories") if c.strip()]
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["allowed_categories"] = selected_categories
            save_users(users)
            if selected_categories:
                session["settings_info"] = f"Updated category access for '{username}'."
            else:
                session["settings_info"] = f"'{username}' now has no category access."

    return redirect(url_for("ise_settings_page"))


@app.route("/logout")
def logout() -> Any:
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
def dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    groups = grouped_devices(devices)
    info = session.pop("dashboard_info", "")
    error = session.pop("dashboard_error", "")
    return render_template(
        "dashboard.html",
        devices=devices,
        groups=groups,
        buttons=get_buttons(),
        info=info,
        error=error,
        device_creds=session.get("device_creds", {}),
    )


@app.route("/devices", methods=["POST"])
def manage_devices() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "add").strip()
    devices = load_devices()

    if action == "add":
        hostname = request.form.get("hostname", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("new_device_categories") if c.strip()]

        if not hostname or not ip_address:
            session["dashboard_error"] = "Hostname and IP address are required."
            return redirect(url_for("dashboard"))

        if any(str(device.get("name", "")).strip().lower() == hostname.lower() for device in devices):
            session["dashboard_error"] = "Duplicate hostname is not allowed."
            return redirect(url_for("dashboard"))

        if any(str(device.get("host", "")).strip() == ip_address for device in devices):
            session["dashboard_error"] = "Duplicate IP address is not allowed."
            return redirect(url_for("dashboard"))

        devices.append({"name": hostname, "host": ip_address, "port": 22, "groups": selected_categories})
        save_devices(devices)
        session["dashboard_info"] = f"Device '{hostname}' added successfully."
        return redirect(url_for("dashboard"))

    if action == "edit":
        original_name = request.form.get("original_device_name", "").strip()
        new_name = request.form.get("edit_hostname", "").strip()
        new_ip = request.form.get("edit_ip_address", "").strip()
        new_categories = [c.strip() for c in request.form.getlist("edit_device_categories") if c.strip()]

        if not original_name or not new_name or not new_ip:
            session["dashboard_error"] = "Device edit requires original name, new hostname, and new IP."
            return redirect(url_for("dashboard"))

        target = None
        for device in devices:
            if str(device.get("name", "")).strip() == original_name:
                target = device
                break

        if target is None:
            session["dashboard_error"] = "Device to edit not found."
            return redirect(url_for("dashboard"))

        for device in devices:
            if device is target:
                continue
            if str(device.get("name", "")).strip().lower() == new_name.lower():
                session["dashboard_error"] = "Cannot rename: hostname already exists."
                return redirect(url_for("dashboard"))
            if str(device.get("host", "")).strip() == new_ip:
                session["dashboard_error"] = "Cannot change IP: IP already exists."
                return redirect(url_for("dashboard"))

        target["name"] = new_name
        target["host"] = new_ip
        target["groups"] = new_categories
        save_devices(devices)
        session["dashboard_info"] = f"Device '{original_name}' updated."
        return redirect(url_for("dashboard"))

    if action == "delete":
        delete_name = request.form.get("delete_device_name", "").strip()
        if not delete_name:
            session["dashboard_error"] = "Select a device to delete."
            return redirect(url_for("dashboard"))

        before = len(devices)
        devices = [d for d in devices if str(d.get("name", "")).strip() != delete_name]
        if len(devices) == before:
            session["dashboard_error"] = "Device not found for deletion."
            return redirect(url_for("dashboard"))

        save_devices(devices)
        session["dashboard_info"] = f"Device '{delete_name}' deleted."
        return redirect(url_for("dashboard"))

    session["dashboard_error"] = "Unknown device action."
    return redirect(url_for("dashboard"))


@app.route("/categories", methods=["POST"])
def manage_categories() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip()
    devices = load_devices()

    if action == "create_category":
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
            for device in devices:
                if device.get("name") == device_name:
                    groups = device.setdefault("groups", [])
                    if category_name not in groups:
                        groups.append(category_name)
                    break
            save_devices(devices)

    elif action == "delete_category":
        category_name = request.form.get("delete_category_name", "").strip()
        if category_name:
            for device in devices:
                groups = device.setdefault("groups", [])
                device["groups"] = [g for g in groups if g != category_name]
            save_devices(devices)

    return redirect(url_for("dashboard"))


@app.route("/buttons", methods=["POST"])
def buttons_menu() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "")
    buttons = get_buttons()

    if action == "add":
        label = request.form.get("new_label", "").strip()
        command = request.form.get("new_command", "").strip()
        if label and command:
            button_id = f"custom-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
            buttons.append({"id": button_id, "label": label, "command": command})
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
    elif action == "clear_history":
        session["run_history"] = []

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

    session["device_creds"] = {
        "username": ssh_username,
        "password": ssh_password,
        "enable_password": enable_password,
    }
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


@app.route("/run", methods=["POST"])
def run_commands() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {device["name"]: device for device in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()

    command = manual_command or selected_command
    if not command:
        return render_template("output.html", run_history=session.get("run_history", []), error="No command provided.")

    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        return render_template("output.html", run_history=session.get("run_history", []), error="No devices selected.")

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
        futures = [executor.submit(execute_for_device, device, creds, command) for device in selected_devices]
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


@app.context_processor
def inject_common_context() -> dict[str, Any]:
    creds = session.get("creds", {})
    return {
        "current_user": creds.get("username", ""),
        "auth_mode": session.get("auth_mode", "local"),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
