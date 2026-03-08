from __future__ import annotations
# ruff: noqa: F821

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "db_conn" not in globals():
    from app.services.db_service import db_conn
if "user_can_write_panel" not in globals() or "user_can_write_menu" not in globals():
    from app.services.legacy_core_helpers import user_can_write_menu, user_can_write_panel


def pending_requests_action() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    return_to_ip = str(request.form.get("next", "")).strip().lower() == "ip_addressing"
    post_action_redirect = url_for("ip_addressing_dashboard", modal="notifications") if return_to_ip else url_for("dashboard")
    if not is_senior_user():
        session["dashboard_error"] = "Only Senior/SysAdmin users can review pending requests."
        return redirect(post_action_redirect)

    action = request.form.get("action", "").strip().lower()
    request_id = int(request.form.get("request_id", "0") or 0)
    request_type = request.form.get("request_type", "device").strip().lower() or "device"
    if request_id <= 0 or action not in {"approve", "reject"} or request_type not in {"device", "command"}:
        session["dashboard_error"] = "Invalid pending request action."
        return redirect(post_action_redirect)

    if request_type == "command":
        with db_conn() as conn:
            row = conn.execute("SELECT * FROM pending_command_requests WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
        if not row:
            session["dashboard_error"] = "Request not found or already decided. A request can be approved/rejected only once."
            return redirect(post_action_redirect)

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
            return redirect(post_action_redirect)

        is_branch_delete = str(command_mode).strip().lower() == "branch_delete"
        branch_name = parse_branch_delete_command(command_text) if is_branch_delete else ""
        if new_status == "approved":
            if is_branch_delete:
                notify_user(
                    requester,
                    f"Command request #{request_id} was approved for branch delete '{branch_name}'. Continue delete (Execute) or Cancel from Notifications.",
                )
            else:
                notify_user(
                    requester,
                    f"Command request #{request_id} was approved. Execute command or Cancel from Notifications. Command: '{str(command_text).strip()}'.",
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
                "requester": requester,
            },
        )
        clear_senior_command_request_notifications(request_id)
        session["dashboard_info"] = f"{new_status.title()} request #{request_id}."
        return redirect(post_action_redirect)

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM pending_device_requests WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
    if not row:
        session["dashboard_error"] = "Request not found or already decided. A request can be approved/rejected only once."
        return redirect(post_action_redirect)

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
                return redirect(post_action_redirect)
            notify_user(requester, f"Your request #{request_id} was rejected because device no longer exists.")
            write_audit_log(
                "request_rejected",
                requester,
                approver,
                device_name,
                {
                    "request_id": request_id,
                    "requester": requester,
                    "reason": "device_missing",
                },
            )
            clear_senior_pending_request_notifications(request_id)
            session["dashboard_error"] = "Device not found. Request rejected."
            return redirect(post_action_redirect)

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
                return redirect(post_action_redirect)
            save_devices(devices, conn=conn)

        notify_user(
            requester,
            f"Your request #{request_id} for device '{device_name}' was approved. "
            f"Requested IP: {original_ip} → {proposed_ip}; categories: {', '.join(original_categories) or '-'} → {', '.join(proposed_categories) or '-'}.",
        )
        write_audit_log(
            "request_approved",
            requester,
            approver,
            device_name,
            {
                "request_id": request_id,
                "requester": requester,
                "fields": {
                    "ip": {"from": original_ip, "to": proposed_ip},
                    "categories": {"from": original_categories, "to": proposed_categories},
                },
            },
        )
        clear_senior_pending_request_notifications(request_id)
        session["dashboard_info"] = f"Approved request #{request_id}."
        return redirect(post_action_redirect)

    with db_conn() as conn:
        update_rejected = conn.execute(
            "UPDATE pending_device_requests SET status = 'rejected', approver_username = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
            (approver, now, request_id),
        )
    if update_rejected.rowcount == 0:
        session["dashboard_error"] = "Request already decided by another Senior user."
        return redirect(post_action_redirect)

    notify_user(
        requester,
        f"Your request #{request_id} for device '{device_name}' was rejected. "
        f"Requested IP: {original_ip} → {proposed_ip}; categories: {', '.join(original_categories) or '-'} → {', '.join(proposed_categories) or '-'}.",
    )
    write_audit_log(
        "request_rejected",
        requester,
        approver,
        device_name,
        {
            "request_id": request_id,
            "requester": requester,
            "fields": {
                "ip": {"from": original_ip, "to": proposed_ip},
                "categories": {"from": original_categories, "to": proposed_categories},
            },
        },
    )

    clear_senior_pending_request_notifications(request_id)
    session["dashboard_info"] = f"Rejected request #{request_id}."
    return redirect(post_action_redirect)


def pending_command_decision() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip().lower()
    request_id = int(request.form.get("request_id", "0") or 0)
    return_to_ip = str(request.form.get("next", "")).strip().lower() == "ip_addressing"
    post_action_redirect = url_for("ip_addressing_dashboard", modal="notifications") if return_to_ip else url_for("dashboard")
    if action not in {"run", "discard", "reject"} or request_id <= 0:
        session["dashboard_error"] = "Invalid command decision."
        return redirect(post_action_redirect)

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    request_item = load_pending_command_request_by_id(request_id)
    if not request_item:
        session["dashboard_error"] = "Command request not found."
        return redirect(post_action_redirect)

    if str(request_item.get("requester_username", "")).strip().lower() != current_username.lower():
        session["dashboard_error"] = "You can only act on your own command requests."
        return redirect(post_action_redirect)

    if str(request_item.get("status", "")).strip().lower() != "approved":
        session["dashboard_error"] = "This command request is no longer available."
        return redirect(post_action_redirect)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if action in {"discard", "reject"}:
        with db_conn() as conn:
            updated = conn.execute(
                "UPDATE pending_command_requests SET status = 'discarded', decided_at = ? WHERE id = ? AND status = 'approved'",
                (now, request_id),
            )
        if updated.rowcount == 0:
            session["dashboard_error"] = "This command request was already handled."
            return redirect(post_action_redirect)
        mark_notifications_read(current_username)
        command_mode = str(request_item.get("command_mode", "show")).strip().lower()
        if command_mode == "branch_delete":
            branch_name = parse_branch_delete_command(str(request_item.get("command_text", ""))) or "selected branch"
            session["dashboard_info"] = f"Branch delete request #{request_id} canceled for '{branch_name}'."
            return redirect(post_action_redirect if return_to_ip else url_for("ip_addressing_dashboard"))
        session["dashboard_info"] = f"Command request #{request_id} discarded."
        return redirect(post_action_redirect)

    # action == run
    command_mode = str(request_item.get("command_mode", "show")).strip().lower()
    if command_mode == "branch_delete":
        branch_name = parse_branch_delete_command(str(request_item.get("command_text", "")))
        if not branch_name:
            session["dashboard_error"] = "Approved branch delete request has invalid payload."
            return redirect(post_action_redirect)

        branches = load_ip_branches()
        updated = [item for item in branches if item.strip().lower() != branch_name.lower()]
        if len(updated) == len(branches):
            session["dashboard_error"] = f"Branch '{branch_name}' was not found in central list."
            return redirect(post_action_redirect)

        with db_conn() as conn:
            updated_status = conn.execute(
                "UPDATE pending_command_requests SET status = 'executing', decided_at = ? WHERE id = ? AND status = 'approved'",
                (now, request_id),
            )
        if updated_status.rowcount == 0:
            session["dashboard_error"] = "This branch delete request was already handled."
            return redirect(post_action_redirect)

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
        return redirect(post_action_redirect if return_to_ip else url_for("ip_addressing_dashboard"))

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
        return redirect(post_action_redirect)

    if missing_or_denied:
        session["dashboard_error"] = (
            "Approved command can only run on the originally requested devices. "
            f"Unavailable/unauthorized: {', '.join(missing_or_denied)}."
        )
        return redirect(post_action_redirect)

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
        return redirect(post_action_redirect)

    with db_conn() as conn:
        updated = conn.execute(
            "UPDATE pending_command_requests SET status = 'executing', decided_at = ? WHERE id = ? AND status = 'approved'",
            (now, request_id),
        )
    if updated.rowcount == 0:
        session["dashboard_error"] = "This command request was already handled."
        return redirect(post_action_redirect)

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
    return redirect(post_action_redirect)


def ip_addressing_dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if role == "audit":
        return redirect(url_for("audit_dashboard"))

    can_access_devices_panel = user_has_panel_access(current_username, auth_mode, "net_devices")
    can_access_monitoring_panel = user_has_panel_access(current_username, auth_mode, "monitoring")
    can_access_ip_panel = user_has_panel_access(current_username, auth_mode, "ip_addressing")
    can_access_network_addressing_panel = user_has_panel_access(current_username, auth_mode, "network_addressing")
    can_write_network_addressing_panel = user_can_write_panel(current_username, auth_mode, "network_addressing")
    can_write_na_isp_branches = can_write_network_addressing_panel and user_can_write_menu(
        current_username, auth_mode, "na_isp_branches"
    )
    can_write_na_isp_atm = can_write_network_addressing_panel and user_can_write_menu(current_username, auth_mode, "na_isp_atm")
    can_write_na_isp_internet = can_write_network_addressing_panel and user_can_write_menu(
        current_username, auth_mode, "na_isp_internet"
    )
    if (
        not can_access_ip_panel
        and not can_access_network_addressing_panel
        and not can_access_devices_panel
        and not can_access_monitoring_panel
    ):
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))

    all_devices = load_devices()
    visible_devices = filter_devices_for_user(all_devices, current_username, auth_mode) if can_access_devices_panel else []
    monitoring_status_map = load_latest_monitoring_status_map() if (can_access_devices_panel or can_access_monitoring_panel) else {}
    if can_access_devices_panel and monitoring_status_map:
        for device in visible_devices:
            name_key = str(device.get("name", "")).strip().lower()
            latest = monitoring_status_map.get(name_key)
            if not latest:
                continue
            device["monitor_status"] = str(latest.get("status", "unknown")).strip().lower() or "unknown"
            device["status"] = device["monitor_status"]
            device["monitor_severity"] = str(latest.get("severity", "warning")).strip().lower() or "warning"
            device["monitor_cpu_percent"] = latest.get("cpu_percent")
            device["monitor_memory_percent"] = latest.get("memory_percent")
            device["monitor_interfaces_up"] = latest.get("interfaces_up")
            device["monitor_interfaces_down"] = latest.get("interfaces_down")
            device["monitor_sla_ms"] = latest.get("sla_ms")
            device["monitor_last_collected_at"] = str(latest.get("collected_at", ""))
    monitoring_settings = load_monitoring_settings()
    monitored_device_names = (
        [str(item).strip() for item in monitoring_settings.get("monitored_devices", []) if str(item).strip()]
        if can_access_monitoring_panel
        else []
    )
    monitoring_profiles_raw = load_monitoring_device_profiles()
    all_by_name = {str(item.get("name", "")).strip().lower(): item for item in all_devices if str(item.get("name", "")).strip()}
    monitoring_names: list[str] = []
    seen_monitoring: set[str] = set()
    for item in monitored_device_names:
        key = str(item).strip().lower()
        if key and key not in seen_monitoring:
            seen_monitoring.add(key)
            monitoring_names.append(str(item).strip())
    for key in monitoring_profiles_raw.keys():
        if key not in seen_monitoring:
            seen_monitoring.add(key)
            monitoring_names.append(str(monitoring_profiles_raw[key].get("device_name", key)))
    monitoring_visible_devices: list[dict[str, Any]] = []
    monitoring_profiles: dict[str, dict[str, Any]] = {}
    for raw_name in monitoring_names:
        name = str(raw_name).strip()
        key = name.lower()
        if not name:
            continue
        base = all_by_name.get(key, {})
        profile = monitoring_profiles_raw.get(key, {})
        host = str(profile.get("host", "")).strip() or str(base.get("host", "")).strip()
        if not host:
            continue
        category = str(profile.get("category", "")).strip()
        if not category:
            groups = base.get("groups", []) if isinstance(base, dict) else []
            category = str(groups[0]).strip() if isinstance(groups, list) and groups else DEFAULT_CATEGORY
        node = {
            "name": name,
            "host": host,
            "port": 22,
            "groups": [category] if category else [DEFAULT_CATEGORY],
        }
        latest = monitoring_status_map.get(key)
        if latest:
            node["monitor_status"] = str(latest.get("status", "unknown")).strip().lower() or "unknown"
            node["status"] = node["monitor_status"]
            node["monitor_severity"] = str(latest.get("severity", "warning")).strip().lower() or "warning"
            node["monitor_cpu_percent"] = latest.get("cpu_percent")
            node["monitor_memory_percent"] = latest.get("memory_percent")
            node["monitor_interfaces_up"] = latest.get("interfaces_up")
            node["monitor_interfaces_down"] = latest.get("interfaces_down")
            node["monitor_sla_ms"] = latest.get("sla_ms")
            node["monitor_last_collected_at"] = str(latest.get("collected_at", ""))
        else:
            node["monitor_status"] = "unknown"
            node["status"] = "unknown"
            node["monitor_severity"] = "warning"
            node["monitor_sla_ms"] = None
        if can_access_monitoring_panel:
            monitoring_visible_devices.append(node)
        if isinstance(profile, dict):
            monitoring_profiles[name] = profile
    fixed_monitoring_categories = load_monitoring_category_options()
    monitoring_editable_device_names: list[str] = []
    if can_manage_monitoring_nodes(role):
        if normalize_role(role) == "sysadmin":
            for node in monitoring_visible_devices:
                groups = node.get("groups", []) if isinstance(node, dict) else []
                category_name = str(groups[0]).strip().lower() if isinstance(groups, list) and groups else ""
                if category_name in {"server", "servers"}:
                    name = str(node.get("name", "")).strip()
                    if name:
                        monitoring_editable_device_names.append(name)
        else:
            monitoring_editable_device_names = [
                str(node.get("name", "")).strip() for node in monitoring_visible_devices if str(node.get("name", "")).strip()
            ]
    monitoring_category_options: list[str] = []
    for item in fixed_monitoring_categories + [str(node.get("groups", ["Uncategorized"])[0]) for node in monitoring_visible_devices]:
        label = str(item).strip()
        if label and label not in monitoring_category_options:
            monitoring_category_options.append(label)
    visible_groups = grouped_devices(visible_devices) if can_access_devices_panel else {}
    visible_categories = all_categories(visible_devices) if can_access_devices_panel else []
    menu_access = user_menu_access(current_username, auth_mode)
    if not can_access_ip_panel:
        menu_access["ip_branches"] = False
        menu_access["ip_hq"] = False
    if not can_access_network_addressing_panel:
        for key in list(menu_access.keys()):
            if str(key).startswith("na_"):
                menu_access[key] = False
    if not can_access_devices_panel:
        for key in list(menu_access.keys()):
            if str(key).startswith("nd_"):
                menu_access[key] = False
    unread_notifications = load_unread_notifications(current_username)
    pending_requests = load_pending_device_requests() if is_privileged_role(role) else []
    pending_command_requests = load_pending_command_requests() if is_privileged_role(role) else []
    if can_access_devices_panel and current_username:
        session["buttons"] = load_user_buttons(current_username, auth_mode) or default_buttons()
    all_command_buttons = get_buttons() if can_access_devices_panel else []
    run_command_buttons = buttons_for_role(role) if can_access_devices_panel else []
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
        if is_privileged_role(role):
            if is_command_request:
                item["pending_request_actionable"] = req_id in pending_command_request_ids
            else:
                item["pending_request_actionable"] = req_id in pending_request_ids
        else:
            is_approved_notice = "was approved" in lower_msg and ("critical command request" in lower_msg or "command request" in lower_msg)
            if is_approved_notice:
                item["junior_command_actionable"] = req_id in approved_command_request_ids
    branches = load_ip_branches()
    return render_template(
        "ip_addressing.html",
        current_user=current_username,
        current_user_role=role,
        auth_mode=auth_mode,
        branches=branches,
        devices=visible_devices,
        groups=visible_groups,
        categories=visible_categories,
        buttons=run_command_buttons,
        manage_buttons=all_command_buttons,
        can_access_devices_panel=can_access_devices_panel,
        can_access_monitoring_panel=can_access_monitoring_panel,
        menu_access=menu_access,
        can_write_na_isp_branches=can_write_na_isp_branches,
        can_write_na_isp_atm=can_write_na_isp_atm,
        can_write_na_isp_internet=can_write_na_isp_internet,
        device_creds=session.get("device_creds", {}),
        monitored_device_names=monitored_device_names,
        monitoring_devices=monitoring_visible_devices,
        monitoring_category_options=monitoring_category_options,
        monitoring_profiles=monitoring_profiles,
        monitoring_editable_device_names=monitoring_editable_device_names,
        monitoring_can_manage=can_manage_monitoring_nodes(role),
        monitoring_servers_only=sysadmin_monitoring_servers_only(role),
        monitoring_category_manage_senior=(normalize_role(role) == "senior"),
        unread_notifications=unread_notifications,
        selected_modal=request.args.get("modal", ""),
        info=session.pop("dashboard_info", ""),
        error=session.pop("dashboard_error", ""),
        unread_notifications_count=len(unread_notifications),
    )


def ip_addressing_live_data_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()

    can_access_devices_panel = user_has_panel_access(current_username, auth_mode, "net_devices")
    can_access_monitoring_panel = user_has_panel_access(current_username, auth_mode, "monitoring")
    can_access_ip_panel = user_has_panel_access(current_username, auth_mode, "ip_addressing")
    can_access_network_addressing_panel = user_has_panel_access(current_username, auth_mode, "network_addressing")
    if (
        not can_access_ip_panel
        and not can_access_network_addressing_panel
        and not can_access_devices_panel
        and not can_access_monitoring_panel
    ):
        return jsonify({"ok": False, "error": "No panel access."}), 403

    all_devices = load_devices()
    visible_devices = filter_devices_for_user(all_devices, current_username, auth_mode) if can_access_devices_panel else []
    monitoring_status_map = load_latest_monitoring_status_map() if (can_access_devices_panel or can_access_monitoring_panel) else {}

    if can_access_devices_panel and monitoring_status_map:
        for device in visible_devices:
            name_key = str(device.get("name", "")).strip().lower()
            latest = monitoring_status_map.get(name_key)
            if not latest:
                continue
            device["monitor_status"] = str(latest.get("status", "unknown")).strip().lower() or "unknown"
            device["status"] = device["monitor_status"]
            device["monitor_severity"] = str(latest.get("severity", "warning")).strip().lower() or "warning"
            device["monitor_cpu_percent"] = latest.get("cpu_percent")
            device["monitor_memory_percent"] = latest.get("memory_percent")
            device["monitor_interfaces_up"] = latest.get("interfaces_up")
            device["monitor_interfaces_down"] = latest.get("interfaces_down")
            device["monitor_sla_ms"] = latest.get("sla_ms")
            device["monitor_last_collected_at"] = str(latest.get("collected_at", ""))

    monitoring_settings = load_monitoring_settings()
    monitored_device_names = (
        [str(item).strip() for item in monitoring_settings.get("monitored_devices", []) if str(item).strip()]
        if can_access_monitoring_panel
        else []
    )
    monitoring_profiles_raw = load_monitoring_device_profiles()
    all_by_name = {str(item.get("name", "")).strip().lower(): item for item in all_devices if str(item.get("name", "")).strip()}
    monitoring_names: list[str] = []
    seen_monitoring: set[str] = set()
    for item in monitored_device_names:
        key = str(item).strip().lower()
        if key and key not in seen_monitoring:
            seen_monitoring.add(key)
            monitoring_names.append(str(item).strip())
    for key in monitoring_profiles_raw.keys():
        if key not in seen_monitoring:
            seen_monitoring.add(key)
            monitoring_names.append(str(monitoring_profiles_raw[key].get("device_name", key)))

    monitoring_visible_devices: list[dict[str, Any]] = []
    monitoring_profiles: dict[str, dict[str, Any]] = {}
    for raw_name in monitoring_names:
        name = str(raw_name).strip()
        key = name.lower()
        if not name:
            continue
        base = all_by_name.get(key, {})
        profile = monitoring_profiles_raw.get(key, {})
        host = str(profile.get("host", "")).strip() or str(base.get("host", "")).strip()
        if not host:
            continue
        category = str(profile.get("category", "")).strip()
        if not category:
            groups = base.get("groups", []) if isinstance(base, dict) else []
            category = str(groups[0]).strip() if isinstance(groups, list) and groups else DEFAULT_CATEGORY
        node = {"name": name, "host": host, "port": 22, "groups": [category] if category else [DEFAULT_CATEGORY]}
        latest = monitoring_status_map.get(key)
        if latest:
            node["monitor_status"] = str(latest.get("status", "unknown")).strip().lower() or "unknown"
            node["status"] = node["monitor_status"]
            node["monitor_severity"] = str(latest.get("severity", "warning")).strip().lower() or "warning"
            node["monitor_cpu_percent"] = latest.get("cpu_percent")
            node["monitor_memory_percent"] = latest.get("memory_percent")
            node["monitor_interfaces_up"] = latest.get("interfaces_up")
            node["monitor_interfaces_down"] = latest.get("interfaces_down")
            node["monitor_sla_ms"] = latest.get("sla_ms")
            node["monitor_last_collected_at"] = str(latest.get("collected_at", ""))
        else:
            ping_state, latency = ping_host_status(host, 2)
            node["monitor_status"] = ping_state
            node["status"] = ping_state
            node["monitor_severity"] = "ok" if ping_state == "up" else "critical"
            node["monitor_sla_ms"] = latency
        if can_access_monitoring_panel:
            monitoring_visible_devices.append(node)
        if isinstance(profile, dict):
            monitoring_profiles[name] = profile

    fixed_monitoring_categories = load_monitoring_category_options()
    monitoring_editable_device_names: list[str] = []
    if can_manage_monitoring_nodes(role):
        if normalize_role(role) == "sysadmin":
            for node in monitoring_visible_devices:
                groups = node.get("groups", []) if isinstance(node, dict) else []
                category_name = str(groups[0]).strip().lower() if isinstance(groups, list) and groups else ""
                if category_name in {"server", "servers"}:
                    name = str(node.get("name", "")).strip()
                    if name:
                        monitoring_editable_device_names.append(name)
        else:
            monitoring_editable_device_names = [
                str(node.get("name", "")).strip() for node in monitoring_visible_devices if str(node.get("name", "")).strip()
            ]

    monitoring_category_options: list[str] = []
    for item in fixed_monitoring_categories + [str(node.get("groups", ["Uncategorized"])[0]) for node in monitoring_visible_devices]:
        label = str(item).strip()
        if label and label not in monitoring_category_options:
            monitoring_category_options.append(label)

    unread_count = len(load_unread_notifications(current_username))
    return jsonify(
        {
            "ok": True,
            "devices": visible_devices,
            "categories": all_categories(visible_devices) if can_access_devices_panel else [],
            "monitoring_devices": monitoring_visible_devices,
            "monitoring_profiles": monitoring_profiles,
            "monitored_device_names": monitored_device_names,
            "monitoring_category_options": monitoring_category_options,
            "monitoring_editable_device_names": monitoring_editable_device_names,
            "unread_notifications_count": unread_count,
        }
    )


def manage_devices() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "add").strip()
    devices = load_devices()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = (
        url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")
    )
    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))

    if action == "add":
        hostname = request.form.get("hostname", "").strip()
        if not is_senior_user():
            write_audit_log_safe(
                "device_add_denied",
                hostname,
                {"reason": "only_privileged_can_add"},
                requester=current_username,
            )
            session["dashboard_error"] = "Only Senior/SysAdmin users can add new devices."
            return redirect(dashboard_modal_url)
        ip_address = request.form.get("ip_address", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("new_device_categories") if c.strip()]
        if not selected_categories:
            selected_categories = [DEFAULT_CATEGORY]
        if not user_can_assign_categories(selected_categories, current_username, auth_mode):
            write_audit_log_safe(
                "device_add_denied",
                hostname,
                {"reason": "categories_not_allowed", "categories": selected_categories},
                requester=current_username,
            )
            session["dashboard_error"] = "You can only add devices to categories you are allowed to access."
            return redirect(dashboard_modal_url)

        if not hostname or not ip_address:
            write_audit_log_safe(
                "device_add_failed",
                hostname,
                {"reason": "hostname_or_ip_missing"},
                requester=current_username,
            )
            session["dashboard_error"] = "Hostname and IP address are required."
            return redirect(dashboard_modal_url)

        if not is_valid_ipv4(ip_address):
            write_audit_log_safe(
                "device_add_failed",
                hostname,
                {"reason": "invalid_ipv4", "ip_address": ip_address},
                requester=current_username,
            )
            session["dashboard_error"] = "IP address must be a valid IPv4 value (each octet 0-255)."
            return redirect(dashboard_modal_url)

        if any(str(device.get("name", "")).strip().lower() == hostname.lower() for device in devices):
            write_audit_log_safe(
                "device_add_failed",
                hostname,
                {"reason": "duplicate_hostname", "ip_address": ip_address},
                requester=current_username,
            )
            session["dashboard_error"] = "Duplicate hostname is not allowed."
            return redirect(dashboard_modal_url)

        if any(str(device.get("host", "")).strip() == ip_address for device in devices):
            write_audit_log_safe(
                "device_add_failed",
                hostname,
                {"reason": "duplicate_ip", "ip_address": ip_address},
                requester=current_username,
            )
            session["dashboard_error"] = "Duplicate IP address is not allowed."
            return redirect(dashboard_modal_url)

        devices.append({"name": hostname, "host": ip_address, "port": 22, "groups": selected_categories})
        save_devices(devices)
        write_audit_log_safe(
            "device_added",
            hostname,
            {"ip_address": ip_address, "categories": selected_categories},
            requester=current_username,
        )
        session["dashboard_info"] = f"Device '{hostname}' added successfully."
        return redirect(dashboard_modal_url)

    if action == "import_csv":
        if not is_senior_user():
            write_audit_log_safe(
                "device_import_denied",
                details={"reason": "only_privileged_can_import"},
                requester=current_username,
            )
            session["dashboard_error"] = "Only Senior/SysAdmin users can import devices."
            return redirect(dashboard_modal_url)

        uploaded = request.files.get("devices_csv")
        if uploaded is None or not str(uploaded.filename or "").strip():
            write_audit_log_safe(
                "device_import_failed",
                details={"reason": "file_missing"},
                requester=current_username,
            )
            session["dashboard_error"] = "Select a CSV file to import."
            return redirect(dashboard_modal_url)

        try:
            content = uploaded.read().decode("utf-8-sig")
        except Exception:
            write_audit_log_safe(
                "device_import_failed",
                details={"reason": "invalid_encoding"},
                requester=current_username,
            )
            session["dashboard_error"] = "CSV file must be UTF-8 text."
            return redirect(dashboard_modal_url)

        lines = [line for line in content.splitlines() if line.strip()]
        if not lines:
            write_audit_log_safe(
                "device_import_failed",
                details={"reason": "empty_file"},
                requester=current_username,
            )
            session["dashboard_error"] = "CSV file is empty."
            return redirect(dashboard_modal_url)

        def _norm_header(value: str) -> str:
            return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())

        name_headers = {"name", "hostname", "devicename"}
        ip_headers = {"ip", "ipaddress", "host", "address"}
        category_headers = {"category", "categories", "group", "groups"}

        reader = csv.DictReader(lines)
        mapped_rows: list[dict[str, str]] = []
        if reader.fieldnames:
            normalized = {_norm_header(h): h for h in reader.fieldnames if h is not None}
            name_col = next((normalized[h] for h in name_headers if h in normalized), None)
            ip_col = next((normalized[h] for h in ip_headers if h in normalized), None)
            category_col = next((normalized[h] for h in category_headers if h in normalized), None)
            if name_col and ip_col:
                for row in reader:
                    mapped_rows.append(
                        {
                            "name": str(row.get(name_col, "") or "").strip(),
                            "ip": str(row.get(ip_col, "") or "").strip(),
                            "category": str(row.get(category_col, "") or "").strip() if category_col else "",
                        }
                    )

        if not mapped_rows:
            plain = csv.reader(lines)
            for parts in plain:
                if len(parts) < 2:
                    continue
                mapped_rows.append(
                    {
                        "name": str(parts[0]).strip(),
                        "ip": str(parts[1]).strip(),
                        "category": str(parts[2]).strip() if len(parts) > 2 else "",
                    }
                )

        if not mapped_rows:
            write_audit_log_safe(
                "device_import_failed",
                details={"reason": "invalid_format"},
                requester=current_username,
            )
            session["dashboard_error"] = "CSV must include at least name and ip_address columns."
            return redirect(dashboard_modal_url)

        existing_names = {str(d.get("name", "")).strip().lower() for d in devices}
        existing_ips = {str(d.get("host", "")).strip() for d in devices}
        batch_names: set[str] = set()
        batch_ips: set[str] = set()

        imported = 0
        skipped: list[str] = []

        for idx, row in enumerate(mapped_rows, start=2):
            hostname = str(row.get("name", "")).strip()
            ip_address = str(row.get("ip", "")).strip()
            category_raw = str(row.get("category", "")).strip()
            categories = [c.strip() for c in re.split(r"[;,]", category_raw) if c.strip()] if category_raw else [DEFAULT_CATEGORY]
            if not hostname or not ip_address:
                skipped.append(f"row {idx}: missing name or ip")
                continue
            if not is_valid_ipv4(ip_address):
                skipped.append(f"row {idx}: invalid ip '{ip_address}'")
                continue
            if hostname.lower() in existing_names or hostname.lower() in batch_names:
                skipped.append(f"row {idx}: duplicate hostname '{hostname}'")
                continue
            if ip_address in existing_ips or ip_address in batch_ips:
                skipped.append(f"row {idx}: duplicate ip '{ip_address}'")
                continue
            if not user_can_assign_categories(categories, current_username, auth_mode):
                skipped.append(f"row {idx}: category not allowed")
                continue

            devices.append({"name": hostname, "host": ip_address, "port": 22, "groups": categories})
            batch_names.add(hostname.lower())
            batch_ips.add(ip_address)
            imported += 1

        if imported > 0:
            save_devices(devices)
            write_audit_log_safe(
                "device_import_completed",
                details={
                    "imported_count": imported,
                    "skipped_count": len(skipped),
                    "skipped_samples": skipped[:5],
                },
                requester=current_username,
            )
            msg = f"Imported {imported} device(s) from CSV."
            if skipped:
                msg += f" Skipped {len(skipped)} row(s)."
            session["dashboard_info"] = msg
        else:
            write_audit_log_safe(
                "device_import_failed",
                details={"reason": "all_rows_skipped", "skipped_count": len(skipped), "skipped_samples": skipped[:5]},
                requester=current_username,
            )
            session["dashboard_error"] = "No devices were imported. " + ("; ".join(skipped[:3]) if skipped else "Check CSV format.")
        return redirect(dashboard_modal_url)

    if action == "edit":
        original_name = request.form.get("original_device_name", "").strip()
        requested_name = request.form.get("edit_hostname", "").strip()
        requested_ip = request.form.get("edit_ip_address", "").strip()
        new_categories = [c.strip() for c in request.form.getlist("edit_device_categories") if c.strip()]
        if not original_name:
            write_audit_log_safe(
                "device_edit_failed",
                details={"reason": "device_not_selected"},
                requester=current_username,
            )
            session["dashboard_error"] = "Select a device to edit."
            return redirect(dashboard_modal_url)

        target = None
        for device in devices:
            if str(device.get("name", "")).strip() == original_name:
                target = device
                break

        if target is None:
            write_audit_log_safe(
                "device_edit_failed",
                original_name,
                {"reason": "device_not_found"},
                requester=current_username,
            )
            session["dashboard_error"] = "Device to edit not found."
            return redirect(dashboard_modal_url)

        if not user_can_access_device(target, current_username, auth_mode):
            write_audit_log_safe(
                "device_edit_denied",
                original_name,
                {"reason": "access_denied_for_device"},
                requester=current_username,
            )
            session["dashboard_error"] = "You can only edit devices in categories you are allowed to access."
            return redirect(dashboard_modal_url)

        new_name = requested_name or str(target.get("name", "")).strip()
        new_ip = requested_ip or str(target.get("host", "")).strip()
        if not new_name or not new_ip:
            write_audit_log_safe(
                "device_edit_failed",
                original_name,
                {"reason": "hostname_or_ip_missing"},
                requester=current_username,
            )
            session["dashboard_error"] = "Edited device must keep hostname and IP."
            return redirect(dashboard_modal_url)

        if not is_valid_ipv4(new_ip):
            write_audit_log_safe(
                "device_edit_failed",
                original_name,
                {"reason": "invalid_ipv4", "ip_address": new_ip},
                requester=current_username,
            )
            session["dashboard_error"] = "IP address must be a valid IPv4 value (each octet 0-255)."
            return redirect(dashboard_modal_url)

        if not new_categories:
            new_categories = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]

        if not user_can_assign_categories(new_categories, current_username, auth_mode):
            write_audit_log_safe(
                "device_edit_denied",
                original_name,
                {"reason": "categories_not_allowed", "categories": new_categories},
                requester=current_username,
            )
            session["dashboard_error"] = "You can only assign categories you are allowed to access."
            return redirect(dashboard_modal_url)

        original_ip = str(target.get("host", "")).strip()
        original_categories = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]
        ip_changed = new_ip != original_ip
        categories_changed = sorted(new_categories) != sorted(original_categories)
        role = current_user_role()
        if not is_privileged_role(role) and (ip_changed or categories_changed):
            create_pending_device_request(
                requester_username=current_username,
                requester_role=role,
                original_device=target,
                proposed_hostname=new_name,
                proposed_ip=new_ip,
                proposed_categories=new_categories,
            )
            write_audit_log_safe(
                "device_edit_requested",
                original_name,
                {
                    "proposed_name": new_name,
                    "proposed_ip": new_ip,
                    "proposed_categories": new_categories,
                    "ip_changed": ip_changed,
                    "categories_changed": categories_changed,
                },
                requester=current_username,
            )
            session["dashboard_info"] = "Your IP/category edit request was submitted for Senior/SysAdmin approval."
            return redirect(dashboard_modal_url)

        for device in devices:
            if device is target:
                continue
            if str(device.get("name", "")).strip().lower() == new_name.lower():
                write_audit_log_safe(
                    "device_edit_failed",
                    original_name,
                    {"reason": "duplicate_hostname", "proposed_name": new_name},
                    requester=current_username,
                )
                session["dashboard_error"] = "Cannot rename: hostname already exists."
                return redirect(dashboard_modal_url)
            if str(device.get("host", "")).strip() == new_ip:
                write_audit_log_safe(
                    "device_edit_failed",
                    original_name,
                    {"reason": "duplicate_ip", "proposed_ip": new_ip},
                    requester=current_username,
                )
                session["dashboard_error"] = "Cannot change IP: IP already exists."
                return redirect(dashboard_modal_url)

        target["name"] = new_name
        target["host"] = new_ip
        target["groups"] = new_categories
        save_devices(devices)
        write_audit_log_safe(
            "device_updated",
            original_name,
            {
                "new_name": new_name,
                "new_ip": new_ip,
                "new_categories": new_categories,
                "old_ip": original_ip,
                "old_categories": original_categories,
            },
            requester=current_username,
        )
        session["dashboard_info"] = f"Device '{original_name}' updated."
        return redirect(dashboard_modal_url)

    if action == "delete":
        delete_name = request.form.get("delete_device_name", "").strip()
        if not is_privileged_role(current_user_role()):
            write_audit_log_safe(
                "device_delete_denied",
                delete_name,
                {"reason": "only_privileged_can_delete"},
                requester=current_username,
            )
            session["dashboard_error"] = "Only Senior/SysAdmin users can delete devices."
            return redirect(dashboard_modal_url)

        if not delete_name:
            write_audit_log_safe(
                "device_delete_failed",
                details={"reason": "device_not_selected"},
                requester=current_username,
            )
            session["dashboard_error"] = "Select a device to delete."
            return redirect(dashboard_modal_url)

        delete_target = None
        for device in devices:
            if str(device.get("name", "")).strip() == delete_name:
                delete_target = device
                break

        if delete_target is not None and not user_can_access_device(delete_target, current_username, auth_mode):
            write_audit_log_safe(
                "device_delete_denied",
                delete_name,
                {"reason": "access_denied_for_device"},
                requester=current_username,
            )
            session["dashboard_error"] = "You can only delete devices in categories you are allowed to access."
            return redirect(dashboard_modal_url)

        before = len(devices)
        devices = [d for d in devices if str(d.get("name", "")).strip() != delete_name]
        if len(devices) == before:
            write_audit_log_safe(
                "device_delete_failed",
                delete_name,
                {"reason": "device_not_found"},
                requester=current_username,
            )
            session["dashboard_error"] = "Device not found for deletion."
            return redirect(dashboard_modal_url)

        save_devices(devices)
        write_audit_log_safe(
            "device_deleted",
            delete_name,
            {"remaining_devices": len(devices)},
            requester=current_username,
        )
        session["dashboard_info"] = f"Device '{delete_name}' deleted."
        return redirect(dashboard_modal_url)

    write_audit_log_safe(
        "device_action_unknown",
        details={"action": action},
        requester=current_username,
    )
    session["dashboard_error"] = "Unknown device action."
    return redirect(dashboard_modal_url)


def manage_categories() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip()
    devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", "")).strip()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = (
        url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")
    )

    if action == "create_category":
        if not is_senior_user():
            write_audit_log_safe(
                "category_create_denied",
                details={"reason": "only_privileged_can_create"},
                requester=current_username,
            )
            session["dashboard_error"] = "Only Senior/SysAdmin users can create categories."
            return redirect(dashboard_modal_url)

        category_name = request.form.get("category_name", "").strip()
        if category_name:
            found = any(category_name in d.get("groups", []) for d in devices)
            if not found and devices:
                devices[0].setdefault("groups", []).append(category_name)
            save_devices(devices)
            write_audit_log_safe(
                "category_created",
                category_name,
                {"already_present": found},
                requester=current_username,
            )

    elif action == "assign_device":
        device_name = request.form.get("device_name", "").strip()
        category_name = request.form.get("target_category", "").strip()
        if device_name and category_name:
            target = next((d for d in devices if str(d.get("name", "")).strip() == device_name), None)
            if target is None:
                write_audit_log_safe(
                    "category_assign_failed",
                    device_name,
                    {"reason": "device_not_found", "category": category_name},
                    requester=current_username,
                )
                session["dashboard_error"] = "Device not found for category update."
                return redirect(dashboard_modal_url)

            groups = [str(g).strip() for g in target.get("groups", []) if str(g).strip()]
            if category_name not in groups:
                groups.append(category_name)

            if not is_privileged_role(current_user_role()):
                create_pending_device_request(
                    requester_username=current_username,
                    requester_role=current_user_role(),
                    original_device=target,
                    proposed_hostname=str(target.get("name", "")),
                    proposed_ip=str(target.get("host", "")),
                    proposed_categories=groups,
                )
                write_audit_log_safe(
                    "category_assign_requested",
                    device_name,
                    {"category": category_name, "proposed_categories": groups},
                    requester=current_username,
                )
                session["dashboard_info"] = "Category update submitted for Senior/SysAdmin approval."
                return redirect(dashboard_modal_url)

            target["groups"] = groups
            save_devices(devices)
            write_audit_log_safe(
                "category_assigned",
                device_name,
                {"category": category_name, "updated_categories": groups},
                requester=current_username,
            )

    elif action == "delete_category":
        category_name = request.form.get("delete_category_name", "").strip()
        if not is_privileged_role(current_user_role()):
            write_audit_log_safe(
                "category_delete_denied",
                category_name,
                {"reason": "only_privileged_can_delete"},
                requester=current_username,
            )
            session["dashboard_error"] = "Only Senior/SysAdmin users can delete categories."
            return redirect(dashboard_modal_url)
        if category_name.strip().lower() == DEFAULT_CATEGORY.lower():
            write_audit_log_safe(
                "category_delete_denied",
                category_name,
                {"reason": "default_category"},
                requester=current_username,
            )
            session["dashboard_error"] = f"'{DEFAULT_CATEGORY}' category cannot be deleted."
            return redirect(dashboard_modal_url)
        if category_name:
            for device in devices:
                groups = device.setdefault("groups", [])
                device["groups"] = [g for g in groups if g != category_name]
            save_devices(devices)
            write_audit_log_safe(
                "category_deleted",
                category_name,
                {},
                requester=current_username,
            )
    else:
        write_audit_log_safe(
            "category_action_unknown",
            details={"action": action},
            requester=current_username,
        )

    return redirect(dashboard_modal_url)


def buttons_menu() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    role = current_user_role()
    if normalize_role(role) != "senior":
        requester = str(session.get("creds", {}).get("username", "")).strip()
        write_audit_log_safe(
            "command_button_management_denied",
            details={"reason": "senior_role_required", "role": role},
            requester=requester,
        )
        session["dashboard_error"] = "Only Senior users can manage command buttons."
        next_page = str(request.form.get("next", "")).strip().lower()
        if next_page == "ip_addressing":
            return redirect(url_for("ip_addressing_dashboard"))
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "")
    buttons = get_buttons()
    current_username = str(session.get("creds", {}).get("username", "")).strip()

    if action == "add":
        label = request.form.get("new_label", "").strip()
        command = request.form.get("new_command", "").strip()
        mode = request.form.get("new_mode", "show").strip().lower()
        audience = request.form.get("new_audience", "senior").strip().lower()
        selected_categories: list[str] = []
        if mode not in {"show", "config"}:
            mode = "show"
        if audience not in {"junior", "senior", "both"}:
            audience = "senior"
        if label and command:
            button_id = f"custom-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
            buttons.append(
                {
                    "id": button_id,
                    "label": label,
                    "command": command,
                    "mode": mode,
                    "categories": selected_categories,
                    "audience": audience,
                }
            )
            session["buttons"] = buttons
            write_audit_log_safe(
                "command_button_added",
                label,
                {"button_id": button_id, "mode": mode, "audience": audience},
                requester=current_username,
            )
    elif action == "rename":
        button_id = request.form.get("button_id", "").strip()
        new_label = request.form.get("rename_label", "").strip()
        if button_id and new_label:
            old_label = ""
            for item in buttons:
                if item.get("id") == button_id:
                    old_label = str(item.get("label", "")).strip()
                    item["label"] = new_label
                    break
            session["buttons"] = buttons
            write_audit_log_safe(
                "command_button_renamed",
                new_label,
                {"button_id": button_id, "old_label": old_label},
                requester=current_username,
            )
    elif action == "delete":
        button_id = request.form.get("button_id", "").strip()
        if button_id:
            deleted = next((item for item in buttons if str(item.get("id", "")).strip() == button_id), None)
            buttons = [item for item in buttons if str(item.get("id", "")).strip() != button_id]
            session["buttons"] = buttons
            persist_current_user_buttons(buttons)
            write_audit_log_safe(
                "command_button_deleted",
                str((deleted or {}).get("label", "")).strip(),
                {"button_id": button_id},
                requester=current_username,
            )
    elif action == "edit_command":
        button_id = request.form.get("button_id", "").strip()
        new_command_text = request.form.get("edit_command_text", "").strip()
        new_audience = request.form.get("edit_audience", "").strip().lower()
        if new_audience not in {"junior", "senior", "both"}:
            new_audience = ""
        if button_id and (new_command_text or new_audience):
            old_command = ""
            button_label = ""
            old_audience = ""
            for item in buttons:
                if str(item.get("id", "")).strip() == button_id:
                    old_command = str(item.get("command", "")).strip()
                    button_label = str(item.get("label", "")).strip()
                    old_audience = str(item.get("audience", "senior")).strip().lower()
                    if new_command_text:
                        item["command"] = new_command_text
                    if new_audience:
                        item["audience"] = new_audience
                    break
            session["buttons"] = buttons
            persist_current_user_buttons(buttons)
            write_audit_log_safe(
                "command_button_updated",
                button_label,
                {
                    "button_id": button_id,
                    "old_command": old_command,
                    "new_command": new_command_text or old_command,
                    "old_audience": old_audience,
                    "new_audience": new_audience or old_audience,
                },
                requester=current_username,
            )
    elif action == "clear_history":
        before_count = len(session.get("run_history", []))
        session["run_history"] = []
        write_audit_log_safe(
            "run_history_cleared",
            details={"entries_removed": before_count},
            requester=current_username,
        )
    else:
        write_audit_log_safe(
            "button_action_unknown",
            details={"action": action},
            requester=current_username,
        )

    if action in {"add", "rename"}:
        persist_current_user_buttons(session.get("buttons", buttons))

    next_page = str(request.form.get("next", "")).strip().lower()
    if next_page == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard"))
    return redirect(url_for("dashboard"))
