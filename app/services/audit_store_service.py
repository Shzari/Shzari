from __future__ import annotations

import json
import re
from typing import Any, Callable


def write_primary_audit_log(
    db_conn_factory: Callable[[], Any],
    action: str,
    requester: str,
    approver: str,
    device_name: str,
    details: dict[str, Any],
    created_at: str,
) -> None:
    try:
        with db_conn_factory() as conn:
            conn.execute(
                "INSERT INTO audit_logs(action, requester, approver, device_name, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(action or "").strip() or "action",
                    str(requester or "").strip(),
                    str(approver or "").strip(),
                    str(device_name or "").strip(),
                    json.dumps(details if isinstance(details, dict) else {}),
                    str(created_at or ""),
                ),
            )
    except Exception:
        pass


def write_primary_login_audit_log(
    db_conn_factory: Callable[[], Any],
    username: str,
    auth_source: str,
    success: bool,
    reason: str,
    client_ip: str,
    user_agent: str,
    created_at: str,
) -> None:
    try:
        with db_conn_factory() as conn:
            conn.execute(
                "INSERT INTO login_audit_logs(username, auth_source, success, reason, client_ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(username or "").strip(),
                    str(auth_source or "unknown").strip().lower() or "unknown",
                    1 if bool(success) else 0,
                    str(reason or "").strip(),
                    str(client_ip or "").strip(),
                    str(user_agent or "")[:512],
                    str(created_at or ""),
                ),
            )
    except Exception:
        pass


def write_primary_action_log(
    db_conn_factory: Callable[[], Any],
    normalize_role_fn: Callable[[str], str],
    username: str,
    role: str,
    action: str,
    device_name: str,
    interface_name: str,
    status: str,
    payload: dict[str, Any],
    client_ip: str,
    user_agent: str,
    created_at: str,
) -> None:
    try:
        with db_conn_factory() as conn:
            conn.execute(
                """
                INSERT INTO action_logs(username, role, action, device_name, interface_name, status, details_json, client_ip, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(username or "").strip(),
                    normalize_role_fn(str(role or "unknown")),
                    str(action or "").strip() or "action",
                    str(device_name or "").strip(),
                    str(interface_name or "").strip(),
                    str(status or "").strip() or "unknown",
                    json.dumps(payload if isinstance(payload, dict) else {}),
                    str(client_ip or "").strip(),
                    str(user_agent or "")[:512],
                    str(created_at or ""),
                ),
            )
    except Exception:
        pass


def build_audit_log_summary(action: str, device_name: str, details: dict[str, Any]) -> str:
    label = str(action or "").replace("_", " ").strip().title()
    target = str(device_name or "").strip() or "N/A"

    if action in {"command_request_approved", "command_request_rejected", "command_request_executed"}:
        mode = str(details.get("command_mode", "")).strip() or "command"
        devices = details.get("target_devices", [])
        count = len(devices) if isinstance(devices, list) else 0
        cmd = str(details.get("command_text", "")).strip()
        if cmd:
            cmd = re.sub(r"\s+", " ", cmd)
            if len(cmd) > 180:
                cmd = cmd[:180] + "..."
            return f"{label} for {mode}. Target devices: {count}. Command sent: {cmd}"
        return f"{label} for {mode}. Target devices: {count}."

    if action in {"branch_delete_direct", "branch_delete_executed", "branch_add"}:
        branch = str(details.get("branch_name", "")).strip() or target
        return f"{label} for branch '{branch}'."

    if action in {"request_approved", "request_rejected"}:
        fields = details.get("fields", {}) if isinstance(details.get("fields", {}), dict) else {}
        ip_change = fields.get("ip", {}) if isinstance(fields.get("ip", {}), dict) else {}
        ip_from = str(ip_change.get("from", "")).strip()
        ip_to = str(ip_change.get("to", "")).strip()
        categories_change = fields.get("categories", {}) if isinstance(fields.get("categories", {}), dict) else {}
        cat_from = categories_change.get("from", [])
        cat_to = categories_change.get("to", [])
        requester_name = str(details.get("requester", "")).strip()

        parts = [f"{label} for '{target}'."]
        if requester_name:
            parts.append(f"Requested by junior/user: {requester_name}.")
        if ip_from or ip_to:
            parts.append(f"IP change: {ip_from or '-'} -> {ip_to or '-'}.")
        if cat_from or cat_to:
            from_txt = ", ".join(str(x) for x in cat_from) if isinstance(cat_from, list) and cat_from else "-"
            to_txt = ", ".join(str(x) for x in cat_to) if isinstance(cat_to, list) and cat_to else "-"
            parts.append(f"Categories: {from_txt} -> {to_txt}.")
        if len(parts) == 1:
            parts.append("No field details.")
        return " ".join(parts)

    return f"{label} for '{target}'."


def rows_to_audit_logs(rows: list[Any]) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    for row in rows:
        details_raw = str(row["details_json"] or "")
        try:
            details = json.loads(details_raw) if details_raw else {}
        except Exception:
            details = {"raw": details_raw}
        action = str(row["action"])
        device_name = str(row["device_name"])
        logs.append(
            {
                "id": int(row["id"]),
                "action": action,
                "requester": str(row["requester"]),
                "approver": str(row["approver"]),
                "device_name": device_name,
                "summary": build_audit_log_summary(action, device_name, details),
                "created_at": str(row["created_at"]),
            }
        )
    return logs


def load_audit_logs_page(
    db_conn_factory: Callable[[], Any],
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], bool]:
    safe_limit = max(1, min(500, int(limit or 100)))
    safe_offset = max(0, int(offset or 0))
    rows: list[Any] = []
    try:
        with db_conn_factory() as conn:
            rows = conn.execute(
                """
                SELECT id, action, requester, approver, device_name, details_json, created_at
                FROM audit_logs
                ORDER BY id DESC
                OFFSET ? ROWS FETCH NEXT ? ROWS ONLY
                """,
                (safe_offset, safe_limit + 1),
            ).fetchall()
    except Exception:
        return [], False
    has_more = len(rows) > safe_limit
    if has_more:
        rows = rows[:safe_limit]
    return rows_to_audit_logs(rows), has_more
