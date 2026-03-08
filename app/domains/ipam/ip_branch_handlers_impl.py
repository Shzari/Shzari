from __future__ import annotations

import os
import socket
import subprocess
from typing import Any

from flask import jsonify, redirect, request, session, url_for

from security_utils import is_valid_ipv4
from app.services.legacy_audit_helpers import write_audit_log, write_audit_log_safe
from app.services.legacy_core_helpers import (
    current_user_role,
    load_ip_branches,
    normalize_role,
    save_ip_branches,
    save_user_device_creds,
    user_can_write_menu,
    user_can_write_panel,
    user_has_panel_access,
    user_menu_access,
)
from app.services.legacy_ip_branch_state_helpers import load_ip_branch_state, save_ip_branch_state
from app.services.legacy_network_rows_helpers import (
    load_isp_atm_rows,
    load_isp_branch_rows,
    load_isp_internet_rows,
    save_isp_atm_rows,
    save_isp_branch_rows,
    save_isp_internet_rows,
)
from app.services.legacy_pending_helpers import create_pending_command_request


def _is_senior_user() -> bool:
    return current_user_role() in {"senior", "sysadmin"}


def _is_read_only_role(role: str) -> bool:
    return normalize_role(role) in {"audit", "manager"}


def manage_ip_branches() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = str(request.form.get("action", "")).strip().lower()
    current_username_value = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    current_role = current_user_role()
    if _is_read_only_role(current_role):
        session["dashboard_error"] = "This role is read-only."
        return redirect(url_for("ip_addressing_dashboard"))
    if not user_can_write_panel(current_username_value, auth_mode, "ip_addressing"):
        session["dashboard_error"] = "Write access to IP Addressing is disabled for your account."
        return redirect(url_for("ip_addressing_dashboard"))
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

        if _is_senior_user():
            updated = [item for item in branches if item.lower() != branch_name.lower()]
            save_ip_branches(updated)
            write_audit_log(
                "branch_delete_direct",
                current_username_value,
                current_username_value,
                branch_name,
                {"branch_name": branch_name},
            )
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
            "After approval, use Notifications to Execute delete or Cancel."
        )
        return redirect(url_for("ip_addressing_dashboard"))

    session["dashboard_error"] = "Unknown branch action."
    return redirect(url_for("ip_addressing_dashboard"))


def request_ip_branch_add() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if _is_read_only_role(role):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403

    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403
    if not user_can_write_panel(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "Write access to IP Addressing is disabled for your account."}), 403

    branch_name = str(request.form.get("branch_name", "")).strip()
    if not branch_name:
        return jsonify({"ok": False, "error": "Branch name is required."}), 400

    branches = load_ip_branches()
    if any(branch_name.lower() == item.lower() for item in branches):
        return jsonify({"ok": False, "error": "Branch already exists."}), 409

    branches.append(branch_name)
    save_ip_branches(branches)
    write_audit_log("branch_add", current_username, current_username, branch_name, {"branch_name": branch_name})
    return jsonify({"ok": True, "message": f"Branch '{branch_name}' added."})


def request_ip_branch_delete() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if _is_read_only_role(role):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403

    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403
    if not user_can_write_panel(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "Write access to IP Addressing is disabled for your account."}), 403

    branch_name = str(request.form.get("branch_name", "")).strip()
    if not branch_name:
        return jsonify({"ok": False, "error": "Select a branch to delete."}), 400

    if _is_senior_user():
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

    return jsonify(
        {
            "ok": True,
            "deleted": False,
            "request_id": request_id,
            "message": (
                f"Branch delete request #{request_id} sent to Senior for approval. "
                "After approval, use Notifications to Continue (Execute) or Cancel."
            ),
        }
    )


def ip_branch_state_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403

    if request.method == "GET":
        return jsonify({"ok": True, "branches": load_ip_branch_state()})
    if _is_read_only_role(current_user_role()):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403
    if not user_can_write_panel(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "Write access to IP Addressing is disabled for your account."}), 403

    payload = request.get_json(silent=True) or {}
    branches = payload.get("branches", [])
    if not isinstance(branches, list):
        return jsonify({"ok": False, "error": "Invalid branch payload."}), 400
    save_ip_branch_state(branches)
    write_audit_log_safe(
        "branch_state_saved",
        details={"branch_count": len(branches)},
        requester=current_username,
    )
    return jsonify({"ok": True, "message": "Branch state saved."})


def network_isp_branches_state_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to Network Addressing."}), 403

    access = user_menu_access(current_username, auth_mode)
    if not bool(access.get("na_isp_branches", access.get("na_branches_isp", False))):
        return jsonify({"ok": False, "error": "You do not have access to ISP Branches."}), 403

    if request.method == "GET":
        try:
            return jsonify({"ok": True, "rows": load_isp_branch_rows()})
        except Exception as exc:
            return jsonify({"ok": False, "error": f"ISP Branches DB read failed: {exc}"}), 500
    if _is_read_only_role(current_user_role()):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403
    if not user_can_write_panel(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "Write access to Network Addressing is disabled for your account."}), 403
    if not user_can_write_menu(current_username, auth_mode, "na_isp_branches"):
        return jsonify({"ok": False, "error": "Write access to ISP Branches is disabled for your account."}), 403

    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return jsonify({"ok": False, "error": "Invalid table payload."}), 400

    try:
        save_isp_branch_rows(rows)
        return jsonify({"ok": True, "message": "ISP Branches table saved."})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"ISP Branches DB save failed: {exc}"}), 500


def network_isp_atms_state_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to Network Addressing."}), 403

    access = user_menu_access(current_username, auth_mode)
    if not bool(access.get("na_isp_atm", access.get("na_branches_isp", False))):
        return jsonify({"ok": False, "error": "You do not have access to ISP ATM-s."}), 403

    if request.method == "GET":
        try:
            return jsonify({"ok": True, "rows": load_isp_atm_rows()})
        except Exception as exc:
            return jsonify({"ok": False, "error": f"ISP ATM-s DB read failed: {exc}"}), 500
    if _is_read_only_role(current_user_role()):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403
    if not user_can_write_panel(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "Write access to Network Addressing is disabled for your account."}), 403
    if not user_can_write_menu(current_username, auth_mode, "na_isp_atm"):
        return jsonify({"ok": False, "error": "Write access to ISP ATM-s is disabled for your account."}), 403

    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return jsonify({"ok": False, "error": "Invalid table payload."}), 400

    try:
        save_isp_atm_rows(rows)
        return jsonify({"ok": True, "message": "ISP ATM-s table saved."})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"ISP ATM-s DB save failed: {exc}"}), 500


def network_isp_internet_state_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to Network Addressing."}), 403

    access = user_menu_access(current_username, auth_mode)
    if not bool(access.get("na_isp_internet", access.get("na_branches_isp", False))):
        return jsonify({"ok": False, "error": "You do not have access to ISP Internet."}), 403

    if request.method == "GET":
        try:
            return jsonify({"ok": True, "rows": load_isp_internet_rows()})
        except Exception as exc:
            return jsonify({"ok": False, "error": f"ISP Internet DB read failed: {exc}"}), 500
    if _is_read_only_role(current_user_role()):
        return jsonify({"ok": False, "error": "This role is read-only."}), 403
    if not user_can_write_panel(current_username, auth_mode, "network_addressing"):
        return jsonify({"ok": False, "error": "Write access to Network Addressing is disabled for your account."}), 403
    if not user_can_write_menu(current_username, auth_mode, "na_isp_internet"):
        return jsonify({"ok": False, "error": "Write access to ISP Internet is disabled for your account."}), 403

    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        return jsonify({"ok": False, "error": "Invalid table payload."}), 400

    try:
        save_isp_internet_rows(rows)
        return jsonify({"ok": True, "message": "ISP Internet table saved."})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"ISP Internet DB save failed: {exc}"}), 500


def update_device_credentials() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    ssh_username = request.form.get("device_ssh_username", "").strip()
    ssh_password = request.form.get("device_ssh_password", "")
    enable_password = request.form.get("device_enable_password", "")
    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if _is_read_only_role(current_user_role()) or not user_can_write_panel(current_username, auth_mode, "net_devices"):
        session["dashboard_error"] = "This role is read-only."
        next_page = str(request.form.get("next", "")).strip().lower()
        if next_page == "ip_addressing":
            return redirect(url_for("ip_addressing_dashboard"))
        return redirect(url_for("dashboard"))

    if not ssh_username or not ssh_password:
        write_audit_log_safe(
            "device_credentials_update_failed",
            details={"reason": "username_or_password_missing"},
            requester=current_username,
        )
        session["dashboard_error"] = "Device SSH username and password are required."
        next_page = str(request.form.get("next", "")).strip().lower()
        if next_page == "ip_addressing":
            return redirect(url_for("ip_addressing_dashboard"))
        return redirect(url_for("dashboard"))

    updated_creds = {
        "username": ssh_username,
        "password": ssh_password,
        "enable_password": enable_password,
    }
    session["device_creds"] = updated_creds

    account = session.get("creds", {})
    account_username = str(account.get("username", "")).strip()
    if account_username:
        save_user_device_creds(account_username, auth_mode, updated_creds)
    write_audit_log_safe(
        "device_credentials_updated",
        details={
            "ssh_username": ssh_username,
            "has_enable_password": bool(enable_password),
        },
        requester=current_username,
    )
    session["dashboard_info"] = "Device credentials updated. New RUN actions will use these credentials."
    next_page = str(request.form.get("next", "")).strip().lower()
    if next_page == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard"))
    return redirect(url_for("dashboard"))


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
    return jsonify(
        {
            "ok": icmp_ok and ssh_ok,
            "message": " | ".join(status_lines),
            "icmp_ok": icmp_ok,
            "ssh_ok": ssh_ok,
        }
    )
