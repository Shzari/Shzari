from __future__ import annotations

import re
import time
from typing import Any

from flask import session

from core_models import SSHResult
from app.services.legacy_pending_helpers import load_senior_notification_targets, notify_user


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
    raw = str(command_text or "").strip()
    if raw.startswith("DELETE_BRANCH::"):
        return raw.split("::", 1)[1].strip()
    return ""


def command_requires_senior_approval(command_text: str) -> bool:
    _ = command_text
    return False


def notify_seniors_new_pending_command_request(
    request_id: int,
    requester_username: str,
    command_mode: str,
    command_text: str,
    device_names: list[str],
) -> None:
    _ = command_mode
    message = (
        f"New pending request #{request_id} from {requester_username} for DANGEROUS command approval. "
        f"Devices: {', '.join(device_names) or '-'}; Command: '{str(command_text).strip()}'."
    )
    for senior_username in load_senior_notification_targets():
        if senior_username.strip().lower() == str(requester_username).strip().lower():
            continue
        notify_user(senior_username, message)


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str, command_mode: str = "show") -> SSHResult:
    from app.services.legacy_command_handlers import run_ssh_command

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


def _normalize_interface_key(name: str) -> str:
    value = str(name or "").strip().lower()
    value = value.replace(" ", "")
    replacements = (
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("port-channel", "po"),
    )
    for old, new in replacements:
        value = value.replace(old, new)
    return re.sub(r"[^a-z0-9/.\-]", "", value)


def _normalize_interface_status(status_raw: str) -> str:
    value = str(status_raw or "").strip().lower()
    if "err-disabled" in value or "errdisable" in value:
        return "Err-disable"
    if "disabled" in value:
        return "disable"
    if "notconnect" in value or "not-connected" in value:
        return "notconnected"
    if "connected" in value:
        return "connected"
    return str(status_raw or "").strip() or "-"


def _parse_show_mac_table(output: str) -> dict[str, set[str]]:
    mac_by_interface: dict[str, set[str]] = {}
    for raw_line in str(output or "").splitlines():
        line = str(raw_line or "").strip()
        match = re.match(r"^\S+\s+([0-9A-Fa-f:\.\-]{4,})\s+\S+\s+(\S+)$", line)
        if not match:
            continue
        mac = match.group(1)
        interface_name = match.group(2)
        key = _normalize_interface_key(interface_name)
        if not key:
            continue
        mac_by_interface.setdefault(key, set()).add(mac)
    return mac_by_interface


def _helpdesk_device_creds() -> dict[str, Any]:
    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    return {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }
