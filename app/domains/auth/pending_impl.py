from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Hard-bind critical symbols so this module does not depend on
# legacy runtime import order during startup.
from app.services.auth_service import (
    find_user,
    is_privileged_role,
    load_users,
    normalize_auth_source,
    normalize_role,
    save_users,
    verify_super_admin,
)
from app.services.db_service import db_conn
from app.services.legacy_core_helpers import load_super_admin
from app.utils.security import _hash_password

import hmac


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
        if is_privileged_role(str(user.get("role", ""))):
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
    return [{"id": int(row["id"]), "message": str(row["message"]), "created_at": str(row["created_at"])} for row in rows]


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


def create_pending_device_request(
    *,
    requester_username: str,
    requester_role: str,
    original_device: dict[str, Any],
    proposed_hostname: str,
    proposed_ip: str,
    proposed_categories: list[str],
) -> None:
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
            rows = conn.execute("SELECT * FROM pending_device_requests WHERE status = 'pending' ORDER BY id DESC").fetchall()
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
        pending.append(
            {
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
            }
        )
    return pending


def load_pending_command_requests(status: str = "pending") -> list[dict[str, Any]]:
    with db_conn() as conn:
        if status == "all":
            rows = conn.execute("SELECT * FROM pending_command_requests ORDER BY id DESC").fetchall()
        elif status == "closed":
            rows = conn.execute(
                "SELECT * FROM pending_command_requests WHERE status IN ('approved','rejected') ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM pending_command_requests WHERE status = 'pending' ORDER BY id DESC").fetchall()

    pending: list[dict[str, Any]] = []
    for row in rows:
        try:
            target_devices = json.loads(str(row["target_devices"] or "[]"))
        except Exception:
            target_devices = []
        pending.append(
            {
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
        )
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


def upsert_user(username: str, role: str = "junior", auth_source: str = "ldap") -> tuple[bool, str]:
    users = load_users()
    if find_user(users, username) is not None:
        return False, "User already exists."
    normalized_auth = normalize_auth_source(auth_source)
    normalized_role = normalize_role(role)
    manager_menu_permissions = {
        "ip_branches": "read",
        "ip_hq": "read",
        "na_system": "read",
        "na_system_ho": "read",
        "na_system_ho_vm": "read",
        "na_system_ho_physical": "read",
        "na_system_ho_storage": "read",
        "na_system_drs": "read",
        "na_system_drs_vm": "read",
        "na_system_drs_physical": "read",
        "na_system_drs_storage": "read",
        "na_network": "read",
        "na_network_devices": "read",
        "na_isp": "read",
        "na_isp_branches": "read",
        "na_isp_atm": "read",
        "na_isp_internet": "read",
        "na_dmvpn": "read",
        "na_dmvpn_branches": "read",
        "na_dmvpn_atms": "read",
        "na_sim_cards": "read",
        "na_site_to_site": "read",
        "na_nat": "read",
        "nd_all_devices": "read",
        "nd_categories": "read",
    }
    manager_panel_access = {
        "panel_permissions": {
            "ip_addressing": "read",
            "network_addressing": "read",
            "net_devices": "read",
            "monitoring": "read",
        },
        "menu_permissions": manager_menu_permissions,
        "menu_access": {key: True for key in manager_menu_permissions},
    }
    users.append(
        {
            "username": username.strip(),
            "role": normalized_role,
            "auth_source": normalized_auth,
            "salt": "",
            "password_hash": "",
            "must_change_password": True if normalized_auth == "local" else False,
            "allowed_categories": None,
            "admin_permissions": [],
            "category_panel_access": manager_panel_access if normalized_role == "manager" else {},
            "account_privileges": ["ip_addressing", "network_addressing", "net_devices", "monitoring"],
        }
    )
    save_users(users)
    if normalized_auth == "local":
        return True, f"User '{username}' created with Local auth. User must set password on first login."
    return True, f"User '{username}' created with LDAP auth."


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
                str(command_mode or "show").strip().lower(),
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
            command_mode=str(command_mode or "show").strip().lower(),
            command_text=str(command_text).strip(),
            device_names=normalized_devices,
        )
    return request_id
