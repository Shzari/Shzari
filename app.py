#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
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
    for d in devices:
        for g in d.get("groups", []):
            groups.setdefault(g, []).append(d)
    return groups


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


def get_predefined_commands() -> list[str]:
    return [
        "show version",
        "show ip interface brief",
        "show interfaces status",
        "show logging | tail 50",
        "show running-config | include hostname",
        "show arp",
        "show cdp neighbors",
        "show ip route",
    ]


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
        auth_mode=session.get("auth_mode", "local"),
        commands=get_predefined_commands(),
        devices=devices,
        groups=groups,
    )


@app.route("/run", methods=["POST"])
def run_commands() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    devices = load_devices()
    by_name = {d["name"]: d for d in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()

    custom_buttons = session.get("custom_buttons", [])

    custom_button_cmd = request.form.get("custom_button_command", "").strip()
    if custom_button_cmd:
        if custom_button_cmd not in custom_buttons:
            custom_buttons.append(custom_button_cmd)
            session["custom_buttons"] = custom_buttons

    command = manual_command or selected_command
    if not command:
        return render_template("output.html", command="", results=[], error="No command provided.")

    selected_devices = [by_name[n] for n in selected_names if n in by_name]
    if not selected_devices:
        return render_template("output.html", command=command, results=[], error="No devices selected.")

    creds = session["creds"]
    results: list[SSHResult] = []

    with ThreadPoolExecutor(max_workers=min(20, max(1, len(selected_devices)))) as ex:
        futures = [ex.submit(execute_for_device, d, creds, command) for d in selected_devices]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r.device)
    return render_template("output.html", command=command, results=results, error="")


@app.context_processor
def inject_custom_buttons() -> dict[str, Any]:
    return {"custom_buttons": session.get("custom_buttons", [])}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
