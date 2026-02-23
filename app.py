#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DEVICES_FILE = BASE_DIR / "devices_web.json"
ISE_SETTINGS_FILE = BASE_DIR / "ise_settings.json"
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


def load_devices() -> list[dict[str, Any]]:
    if not DEVICES_FILE.exists():
        return []
    with DEVICES_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("devices_web.json must be a JSON array")
    return data


def grouped_devices(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for group in device.get("groups", []):
            groups.setdefault(group, []).append(device)
    return groups


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
        "server": "",
        "port": 1812,
        "shared_secret": "",
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
        "server": str(settings.get("server", "")).strip(),
        "port": int(settings.get("port", 1812) or 1812),
        "shared_secret": str(settings.get("shared_secret", "")),
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


def authenticate_with_ise(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    server = str(settings.get("server", "")).strip()
    secret_text = str(settings.get("shared_secret", ""))
    if not server or not secret_text:
        return False, "ISE settings missing: server and shared secret are required."

    port = int(settings.get("port", 1812) or 1812)
    timeout = int(settings.get("timeout", 5) or 5)
    nas_ip = str(settings.get("nas_ip", "127.0.0.1")).strip()

    secret = secret_text.encode("utf-8")
    identifier = random.randint(0, 255)
    request_authenticator = os.urandom(16)

    attrs = b""
    attrs += _radius_attr(ATTR_USER_NAME, username.encode("utf-8"))
    attrs += _radius_attr(ATTR_USER_PASSWORD, _radius_encrypt_user_password(password, secret, request_authenticator))

    try:
        nas_ip_bytes = socket.inet_aton(nas_ip)
        attrs += _radius_attr(ATTR_NAS_IP_ADDRESS, nas_ip_bytes)
    except OSError:
        pass

    attrs += _radius_attr(ATTR_NAS_PORT, struct.pack("!I", 0))
    attrs += _radius_attr(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_LOGIN))

    length = 20 + len(attrs)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, length) + request_authenticator + attrs

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        return False, "ISE authentication timeout."
    except OSError as exc:
        return False, f"ISE connection error: {exc}"
    finally:
        sock.close()

    if len(response) < 20:
        return False, "Invalid response from ISE server."

    code, recv_identifier, recv_length = struct.unpack("!BBH", response[:4])
    recv_authenticator = response[4:20]
    response_attrs = response[20:recv_length]

    if recv_identifier != identifier:
        return False, "ISE response identifier mismatch."

    expected_auth = hmac.new(secret, response[:4] + request_authenticator + response_attrs, hashlib.md5).digest()
    if expected_auth != recv_authenticator:
        return False, "ISE response authenticator verification failed."

    if code == ACCESS_ACCEPT:
        return True, "Authenticated by ISE."
    if code == ACCESS_REJECT:
        return False, "ISE rejected username/password."
    return False, f"ISE returned unsupported code {code}."


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
    if "auth_mode" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/ise-settings", methods=["POST"])
def ise_settings() -> Any:
    settings = {
        "server": request.form.get("ise_server", "").strip(),
        "port": request.form.get("ise_port", "1812").strip(),
        "shared_secret": request.form.get("ise_secret", ""),
        "timeout": request.form.get("ise_timeout", "5").strip(),
        "nas_ip": request.form.get("ise_nas_ip", "127.0.0.1").strip(),
    }
    try:
        save_ise_settings(settings)
        session["ise_message"] = "ISE settings saved."
    except Exception as exc:
        session["ise_message"] = f"Failed to save ISE settings: {exc}"
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    error = ""
    info = session.pop("ise_message", "")
    settings = load_ise_settings()

    if request.method == "POST":
        auth_mode = request.form.get("auth_mode", "local")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not username or not password:
            error = "Username and password are required."
        elif auth_mode == "ise":
            ok, message = authenticate_with_ise(username, password, settings)
            if not ok:
                error = message
            else:
                info = message

        if not error:
            session["auth_mode"] = auth_mode
            session["creds"] = {"username": username, "password": password, "timeout": timeout}
            session.setdefault("buttons", default_buttons())
            session.setdefault("run_history", [])
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error, info=info, ise=settings)


@app.route("/logout")
def logout() -> Any:
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
def dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    devices = load_devices()
    groups = grouped_devices(devices)
    return render_template("dashboard.html", devices=devices, groups=groups, buttons=get_buttons())


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


@app.route("/run", methods=["POST"])
def run_commands() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    devices = load_devices()
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

    creds = session["creds"]
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
