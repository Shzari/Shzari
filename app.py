#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko
from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DEVICES_FILE = BASE_DIR / "devices_web.json"
SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")

app = Flask(__name__)
app.secret_key = SECRET_KEY


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
        {
            "id": "show-ip-int-brief",
            "label": "IP Interface Brief",
            "command": "show ip interface brief",
        },
        {
            "id": "show-int-status",
            "label": "Interfaces Status",
            "command": "show interfaces status",
        },
        {"id": "show-logging", "label": "Show Logging", "command": "show logging | tail 50"},
        {
            "id": "show-hostname",
            "label": "Show Hostname",
            "command": "show running-config | include hostname",
        },
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


def run_ssh_command(host: str, port: int, username: str, password: str, command: str, timeout: int) -> tuple[str, str]:
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


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    error = ""
    if request.method == "POST":
        auth_mode = request.form.get("auth_mode", "local")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not username or not password:
            error = "Username and password are required."
        else:
            session["auth_mode"] = auth_mode
            session["creds"] = {"username": username, "password": password, "timeout": timeout}
            session.setdefault("buttons", default_buttons())
            session.setdefault("run_history", [])
            return redirect(url_for("dashboard"))

    return render_template("login.html", error=error)


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
    return render_template(
        "dashboard.html",
        devices=devices,
        groups=groups,
        buttons=get_buttons(),
    )


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
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="No devices selected.",
        )

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
