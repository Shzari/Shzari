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


def monitoring_node_add_page() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        session["dashboard_error"] = "You do not have access to Monitoring."
        return redirect(url_for("ip_addressing_dashboard"))
    role = current_user_role()
    if not can_manage_monitoring_nodes(role):
        session["dashboard_error"] = "Only senior/sysadmin users can manage monitoring devices."
        return redirect(url_for("ip_addressing_dashboard"))

    original_device_name = str(request.form.get("original_device_name", "")).strip()
    device_name = str(request.form.get("device_name", "")).strip()
    ip_address = str(request.form.get("ip_address", "")).strip()
    category = str(request.form.get("category", "")).strip() or "Router"
    polling_method = str(request.form.get("polling_method", "status_only")).strip().lower() or "status_only"
    snmp_version = str(request.form.get("snmp_version", "2c")).strip().lower() or "2c"
    snmp_port = str(request.form.get("snmp_port", "161")).strip() or "161"
    community = str(request.form.get("community", "")).strip()
    rw_community = str(request.form.get("rw_community", "")).strip()
    snmpv3_username = str(request.form.get("snmpv3_username", "")).strip()
    snmpv3_auth_password = str(request.form.get("snmpv3_auth_password", "")).strip()
    snmpv3_priv_password = str(request.form.get("snmpv3_priv_password", "")).strip()
    snmpv3_auth_protocol = str(request.form.get("snmpv3_auth_protocol", "sha")).strip().lower() or "sha"
    snmpv3_priv_protocol = str(request.form.get("snmpv3_priv_protocol", "aes128")).strip().lower() or "aes128"
    ssh_username = str(request.form.get("ssh_username", "")).strip()
    ssh_password = str(request.form.get("ssh_password", "")).strip()
    api_token = str(request.form.get("api_token", "")).strip()
    winrm_port_raw = str(request.form.get("winrm_port", "5985")).strip() or "5985"
    winrm_username = str(request.form.get("winrm_username", "")).strip()
    winrm_password = str(request.form.get("winrm_password", "")).strip()
    winrm_auth = str(request.form.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
    metrics_override = str(request.form.get("metrics_override", "")).strip()
    interfaces_watch = str(request.form.get("interfaces_watch", "")).strip()
    cpu_warn_raw = str(request.form.get("cpu_warn", "")).strip()
    memory_warn_raw = str(request.form.get("memory_warn", "")).strip()
    notes = str(request.form.get("notes", "")).strip()
    interval_raw = str(request.form.get("interval_seconds", "30")).strip() or "30"
    if normalize_role(role) == "sysadmin" and not original_device_name:
        # In UI add-mode, category select is locked to Servers and may be disabled;
        # disabled form fields are not submitted, so enforce this server-side.
        category = "Servers"
    is_windows_server = is_windows_servers_category(category)
    if is_windows_server:
        polling_method = "winrm_icmp"

    if not device_name:
        session["dashboard_error"] = "Device name is required."
        return redirect(url_for("ip_addressing_dashboard"))
    if original_device_name:
        existing_category = _monitoring_effective_category(original_device_name)
        if not monitoring_user_allowed_for_category(current_username, auth_mode, existing_category):
            session["dashboard_error"] = "You are not allowed to edit this monitoring device category."
            return redirect(url_for("ip_addressing_dashboard"))
    if original_device_name and normalize_role(role) == "sysadmin":
        if not category_allowed_for_monitoring_add(role, existing_category):
            session["dashboard_error"] = "SysAdmin can edit only monitoring devices in Servers category."
            return redirect(url_for("ip_addressing_dashboard"))
        if not category_allowed_for_monitoring_add(role, category):
            session["dashboard_error"] = "SysAdmin can keep edited monitoring devices only in Servers category."
            return redirect(url_for("ip_addressing_dashboard"))
    if not original_device_name and not category_allowed_for_monitoring_add(role, category):
        session["dashboard_error"] = "SysAdmin can add monitoring devices only in Servers category."
        return redirect(url_for("ip_addressing_dashboard"))
    if not monitoring_user_allowed_for_category(current_username, auth_mode, category):
        session["dashboard_error"] = "You are not allowed to assign this monitoring category."
        return redirect(url_for("ip_addressing_dashboard"))
    if not is_valid_ipv4(ip_address):
        session["dashboard_error"] = "Valid IPv4 address is required."
        return redirect(url_for("ip_addressing_dashboard"))
    if polling_method not in {"status_only", "snmp_v2", "snmp_v3", "ssh", "api", "telemetry", "winrm_icmp"}:
        session["dashboard_error"] = "Invalid polling method."
        return redirect(url_for("ip_addressing_dashboard"))
    if polling_method == "winrm_icmp" and not is_windows_server:
        session["dashboard_error"] = "WinRM + ICMP is allowed only for Windows Servers category."
        return redirect(url_for("ip_addressing_dashboard"))
    try:
        interval_seconds = max(5, min(3600, int(interval_raw)))
    except Exception:
        interval_seconds = 30
    try:
        snmp_port_int = max(1, min(65535, int(snmp_port)))
    except Exception:
        snmp_port_int = 161
    try:
        winrm_port_int = max(1, min(65535, int(winrm_port_raw)))
    except Exception:
        winrm_port_int = 5985
    if winrm_auth not in {"ntlm", "kerberos", "basic", "credssp"}:
        winrm_auth = "ntlm"
    try:
        cpu_warn = max(1, min(100, int(cpu_warn_raw))) if cpu_warn_raw else 90
    except Exception:
        cpu_warn = 90
    try:
        memory_warn = max(1, min(100, int(memory_warn_raw))) if memory_warn_raw else 90
    except Exception:
        memory_warn = 90

    if original_device_name and original_device_name.lower() != device_name.lower():
        rename_device_everywhere(original_device_name, device_name, ip_address)
    ensure_monitoring_category_exists(category)
    upsert_device_and_category_for_monitoring(device_name, ip_address, category)
    profile = {
        "category": category,
        "category_key": "windows_server" if is_windows_server else str(category).strip().lower().replace(" ", "_"),
        "polling_method": polling_method,
        "snmp_version": snmp_version,
        "snmp_port": snmp_port_int,
        "community": community,
        "rw_community": rw_community,
        "snmpv3_username": snmpv3_username,
        "snmpv3_auth_password": snmpv3_auth_password,
        "snmpv3_priv_password": snmpv3_priv_password,
        "snmpv3_auth_protocol": snmpv3_auth_protocol,
        "snmpv3_priv_protocol": snmpv3_priv_protocol,
        "ssh_username": ssh_username,
        "ssh_password": ssh_password,
        "api_token": api_token,
        "winrm_port": winrm_port_int,
        "winrm_username": winrm_username,
        "winrm_password": winrm_password,
        "winrm_auth": winrm_auth,
        "metrics_override": metrics_override,
        "interfaces_watch": interfaces_watch,
        "cpu_warn": cpu_warn,
        "memory_warn": memory_warn,
        "interval_seconds": interval_seconds,
        "notes": notes,
    }
    save_monitoring_device_profile(device_name, ip_address, profile)
    seed_monitoring_sample_async(device_name, ip_address, category, profile, current_username)

    settings = load_monitoring_settings()
    selected = [str(item).strip() for item in settings.get("monitored_devices", []) if str(item).strip()]
    if original_device_name and original_device_name.lower() != device_name.lower():
        selected = [device_name if str(item).strip().lower() == original_device_name.lower() else str(item).strip() for item in selected]
    if device_name not in selected:
        selected.append(device_name)
    settings["monitored_devices"] = selected
    settings["enabled"] = True
    save_monitoring_settings(settings)

    write_audit_log_safe(
        "monitoring_node_added",
        details={
            "device_name": device_name,
            "ip_address": ip_address,
            "category": category,
            "polling_method": polling_method,
            "snmp_version": snmp_version,
            "interval_seconds": interval_seconds,
        },
        requester=current_username,
    )
    session["dashboard_info"] = f"Monitoring node '{device_name}' saved."
    return redirect(url_for("ip_addressing_dashboard"))


def monitoring_node_delete_page() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        session["dashboard_error"] = "You do not have access to Monitoring."
        return redirect(url_for("ip_addressing_dashboard"))
    if not can_manage_monitoring_nodes(role):
        session["dashboard_error"] = "Only senior/sysadmin users can manage monitoring devices."
        return redirect(url_for("ip_addressing_dashboard"))

    device_name = str(request.form.get("device_name", "")).strip()
    if not device_name:
        session["dashboard_error"] = "Device name is required for delete."
        return redirect(url_for("ip_addressing_dashboard"))
    device_category = _monitoring_effective_category(device_name)
    if not category_allowed_for_monitoring_add(role, device_category):
        session["dashboard_error"] = "You can delete monitoring devices only in allowed categories."
        return redirect(url_for("ip_addressing_dashboard"))
    if not monitoring_user_allowed_for_category(current_username, auth_mode, device_category):
        session["dashboard_error"] = "You are not allowed to delete this monitoring device category."
        return redirect(url_for("ip_addressing_dashboard"))

    delete_device_everywhere(device_name)
    settings = load_monitoring_settings()
    settings["monitored_devices"] = [
        str(item).strip() for item in settings.get("monitored_devices", []) if str(item).strip().lower() != device_name.lower()
    ]
    save_monitoring_settings(settings)
    write_audit_log_safe(
        "monitoring_node_deleted",
        details={"device_name": device_name},
        requester=current_username,
    )
    session["dashboard_info"] = f"Monitoring node '{device_name}' deleted."
    return redirect(url_for("ip_addressing_dashboard"))


def monitoring_category_add_page() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if normalize_role(current_user_role()) != "senior":
        session["dashboard_error"] = "Only Senior users can manage monitoring categories."
        return redirect(url_for("ip_addressing_dashboard"))
    category_name = str(request.form.get("category_name", "")).strip()
    if not category_name:
        session["dashboard_error"] = "Category name is required."
        return redirect(url_for("ip_addressing_dashboard"))
    settings = load_monitoring_settings()
    raw = settings.get("category_options", [])
    categories = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    if category_name in categories:
        session["dashboard_error"] = f"Category '{category_name}' already exists."
        return redirect(url_for("ip_addressing_dashboard"))
    categories.append(category_name)
    settings["category_options"] = categories
    save_monitoring_settings(settings)
    session["dashboard_info"] = f"Monitoring category '{category_name}' added."
    return redirect(url_for("ip_addressing_dashboard"))


def monitoring_category_delete_page() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if normalize_role(current_user_role()) != "senior":
        session["dashboard_error"] = "Only Senior users can manage monitoring categories."
        return redirect(url_for("ip_addressing_dashboard"))
    category_name = str(request.form.get("category_name", "")).strip()
    if not category_name:
        session["dashboard_error"] = "Category is required."
        return redirect(url_for("ip_addressing_dashboard"))
    protected = {"uncategorized"}
    if category_name.strip().lower() in protected:
        session["dashboard_error"] = "Uncategorized cannot be deleted."
        return redirect(url_for("ip_addressing_dashboard"))

    settings = load_monitoring_settings()
    raw = settings.get("category_options", [])
    categories = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    categories = [item for item in categories if item.strip().lower() != category_name.strip().lower()]
    settings["category_options"] = categories
    save_monitoring_settings(settings)

    profiles = load_monitoring_device_profiles()
    with db_conn() as conn:
        for key, profile in profiles.items():
            current_category = str(profile.get("category", "")).strip()
            if current_category.lower() != category_name.strip().lower():
                continue
            device_name = str(profile.get("device_name", key)).strip()
            host = str(profile.get("host", "")).strip()
            if not device_name or not host:
                continue
            profile["category"] = "Uncategorized"
            save_monitoring_device_profile(device_name, host, profile)
            conn.execute(
                "UPDATE device_groups SET group_name = ? WHERE hostname = ? AND lower(group_name) = lower(?)",
                ("Uncategorized", device_name, category_name),
            )

    session["dashboard_info"] = f"Monitoring category '{category_name}' deleted."
    return redirect(url_for("ip_addressing_dashboard"))


def monitoring_category_rename_page() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if normalize_role(current_user_role()) != "senior":
        session["dashboard_error"] = "Only Senior users can manage monitoring categories."
        return redirect(url_for("ip_addressing_dashboard"))

    old_name = str(request.form.get("old_category_name", "")).strip()
    new_name = str(request.form.get("new_category_name", "")).strip()
    if not old_name or not new_name:
        session["dashboard_error"] = "Both old and new category names are required."
        return redirect(url_for("ip_addressing_dashboard"))
    if old_name.strip().lower() == "uncategorized":
        session["dashboard_error"] = "Uncategorized cannot be renamed."
        return redirect(url_for("ip_addressing_dashboard"))
    if old_name.strip().lower() == new_name.strip().lower():
        session["dashboard_error"] = "Old and new category names are the same."
        return redirect(url_for("ip_addressing_dashboard"))

    settings = load_monitoring_settings()
    raw = settings.get("category_options", [])
    categories = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    if not any(item.lower() == old_name.lower() for item in categories):
        session["dashboard_error"] = f"Category '{old_name}' not found."
        return redirect(url_for("ip_addressing_dashboard"))
    if any(item.lower() == new_name.lower() for item in categories):
        session["dashboard_error"] = f"Category '{new_name}' already exists."
        return redirect(url_for("ip_addressing_dashboard"))
    settings["category_options"] = [new_name if item.lower() == old_name.lower() else item for item in categories]
    save_monitoring_settings(settings)

    profiles = load_monitoring_device_profiles()
    with db_conn() as conn:
        for key, profile in profiles.items():
            current_category = str(profile.get("category", "")).strip()
            if current_category.lower() != old_name.lower():
                continue
            device_name = str(profile.get("device_name", key)).strip()
            host = str(profile.get("host", "")).strip()
            if not device_name or not host:
                continue
            profile["category"] = new_name
            save_monitoring_device_profile(device_name, host, profile)
            conn.execute(
                "UPDATE device_groups SET group_name = ? WHERE hostname = ? AND lower(group_name) = lower(?)",
                (new_name, device_name, old_name),
            )

    session["dashboard_info"] = f"Monitoring category '{old_name}' renamed to '{new_name}'."
    return redirect(url_for("ip_addressing_dashboard"))


def monitoring_node_test_snmp_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if not can_manage_monitoring_nodes(role):
        return jsonify({"ok": False, "error": "Only Senior/SysAdmin can test SNMP settings."}), 403

    payload = request.get_json(silent=True) or {}
    host = str(payload.get("host", "")).strip()
    snmp_version = str(payload.get("snmp_version", "2c")).strip().lower() or "2c"
    community = str(payload.get("community", "")).strip()
    username = str(payload.get("snmpv3_username", "")).strip()
    auth_password = str(payload.get("snmpv3_auth_password", "")).strip()
    priv_password = str(payload.get("snmpv3_priv_password", "")).strip()
    auth_protocol = str(payload.get("snmpv3_auth_protocol", "sha")).strip().lower() or "sha"
    priv_protocol = str(payload.get("snmpv3_priv_protocol", "aes128")).strip().lower() or "aes128"
    try:
        snmp_port = max(1, min(65535, int(payload.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161

    if not is_valid_ipv4(host):
        return jsonify({"ok": False, "error": "Valid polling IP is required."}), 400

    settings: dict[str, Any]
    if snmp_version in {"3", "v3", "snmpv3"}:
        if not username:
            return jsonify({"ok": False, "error": "SNMPv3 username is required."}), 400
        if auth_protocol != "none" and not auth_password:
            return jsonify({"ok": False, "error": "SNMPv3 auth password is required."}), 400
        if priv_protocol != "none" and not priv_password:
            return jsonify({"ok": False, "error": "SNMPv3 privacy password is required."}), 400
        settings = {
            "collection_mode": "snmp_v3",
            "username": username,
            "password": auth_password,
            "token": priv_password,
            "snmpv3_auth_protocol": auth_protocol,
            "snmpv3_priv_protocol": priv_protocol,
            "snmp_port": snmp_port,
        }
    else:
        if not community:
            return jsonify({"ok": False, "error": "SNMPv2c community (RO) is required."}), 400
        settings = {
            "collection_mode": "snmp_v2",
            "password": "",
            "token": community,
            "snmp_port": snmp_port,
        }

    sysname, err1 = snmp_get_value(host, settings, "1.3.6.1.2.1.1.5.0")
    ifnumber, err2 = snmp_get_value(host, settings, "1.3.6.1.2.1.2.1.0")
    cpu, err3 = snmp_get_value(host, settings, "1.3.6.1.4.1.9.2.1.58.0")

    errors = [item for item in [err1, err2] if str(item or "").strip()]
    if errors:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"SNMP test failed: {errors[0]}",
                    "details": {
                        "host": host,
                        "snmp_version": "v3" if snmp_version in {"3", "v3", "snmpv3"} else "v2c",
                        "sysname_error": err1,
                        "ifnumber_error": err2,
                        "cpu_error": err3,
                    },
                }
            ),
            400,
        )

    cpu_value: float | None = None
    try:
        if cpu is not None:
            cpu_value = _cap_percent(float(int(cpu)))
    except Exception:
        cpu_value = None

    return jsonify(
        {
            "ok": True,
            "message": "SNMP test successful.",
            "details": {
                "host": host,
                "snmp_version": "v3" if snmp_version in {"3", "v3", "snmpv3"} else "v2c",
                "sysname": str(sysname) if sysname is not None else "-",
                "if_number": int(ifnumber) if ifnumber is not None else None,
                "cpu_percent": cpu_value,
                "cpu_note": "CPU OID may be unsupported on some models." if cpu_value is None else "",
            },
        }
    )


def monitoring_node_resources_pull_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if not can_manage_monitoring_nodes(role):
        return jsonify({"ok": False, "error": "Only Senior/SysAdmin can manage monitoring resources."}), 403

    payload = request.get_json(silent=True) or {}
    device_name = str(payload.get("device_name", "")).strip()
    force_refresh = bool(payload.get("force_refresh", False))
    if not device_name:
        return jsonify({"ok": False, "error": "Device name is required."}), 400

    _base_device, profile, host = _monitoring_device_lookup(device_name)
    profile_category = _monitoring_effective_category(device_name)
    if not category_allowed_for_monitoring_add(role, profile_category):
        return jsonify({"ok": False, "error": "You can manage resources only for allowed monitoring categories."}), 403
    if not monitoring_user_allowed_for_category(current_username, auth_mode, profile_category):
        return jsonify({"ok": False, "error": "You are not allowed to access this device category."}), 403
    if not host:
        return jsonify({"ok": False, "error": "Device host/IP is not configured."}), 400

    interfaces: list[dict[str, Any]] = []
    source = "ssh"
    ssh_error = ""
    timeout = 8
    try:
        timeout = max(3, min(30, int(profile.get("timeout", 8) or 8)))
    except Exception:
        timeout = 8

    creds = _monitoring_pull_ssh_creds(profile, current_username, auth_mode)
    username = str(creds.get("username", "")).strip()
    password = str(creds.get("password", ""))
    if username and password:
        status_state, status_output = run_ssh_command(
            host=host,
            port=22,
            username=username,
            password=password,
            command="show interfaces status",
            timeout=timeout,
            command_mode="show",
            enable_password=str(creds.get("enable_password", "")),
        )
        mac_state, mac_output = run_ssh_command(
            host=host,
            port=22,
            username=username,
            password=password,
            command="show mac address-table",
            timeout=timeout,
            command_mode="show",
            enable_password=str(creds.get("enable_password", "")),
        )
        if status_state == "PASS":
            rows_map = _parse_show_interfaces_status(status_output)
            mac_map = _parse_show_mac_table(mac_output if mac_state == "PASS" else "")
            for item in rows_map.values():
                key = _normalize_interface_key(str(item.get("interface", "")))
                macs = sorted(mac_map.get(key, set()))
                clone = dict(item)
                clone["mac_addresses"] = ", ".join(macs) if macs else "-"
                interfaces.append(clone)
            interfaces.sort(key=lambda row: str(row.get("interface", "")).lower())
        else:
            ssh_error = str(status_output or "ssh_command_failed")
    else:
        ssh_error = "ssh_credentials_missing"

    # SNMP fallback for environments that don't use SSH for discovery.
    if not interfaces:
        source = "snmp"
        snmp_settings = monitoring_effective_settings(load_monitoring_settings(), profile)
        name_map, name_err = snmp_walk_indexed_values(host, snmp_settings, "1.3.6.1.2.1.31.1.1.1.1", max_rows=4096)
        if not name_map:
            # fallback to ifDescr
            name_map, name_err = snmp_walk_indexed_values(host, snmp_settings, "1.3.6.1.2.1.2.2.1.2", max_rows=4096)
        alias_map, _ = snmp_walk_indexed_values(host, snmp_settings, "1.3.6.1.2.1.31.1.1.1.18", max_rows=4096)
        oper_map, oper_err = snmp_walk_indexed_values(host, snmp_settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)

        if not name_map:
            details = {
                "device_name": device_name,
                "host": host,
                "ssh_error": ssh_error[:300] if ssh_error else "",
                "snmp_name_error": str(name_err)[:300] if name_err else "",
                "snmp_oper_error": str(oper_err)[:300] if oper_err else "",
            }
            write_audit_log_safe("monitoring_resources_pull_failed", details=details, requester=current_username)
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "Failed to pull resources via SSH and SNMP. Check SSH credentials or SNMP v2/v3 settings.",
                    }
                ),
                400,
            )

        status_map = {1: "connected", 2: "disable", 3: "notconnected", 4: "unknown", 5: "unknown", 6: "unknown", 7: "unknown"}
        for idx in sorted(name_map.keys()):
            iface_name = str(name_map.get(idx, "")).strip()
            if not iface_name:
                continue
            alias = str(alias_map.get(idx, "")).strip()
            oper_raw = oper_map.get(idx)
            try:
                oper_code = int(oper_raw)
            except Exception:
                oper_code = 4
            interfaces.append(
                {
                    "interface": iface_name,
                    "description": alias or "-",
                    "status": status_map.get(oper_code, "unknown"),
                    "vlan": "-",
                    "mode": "-",
                    "mac_addresses": "-",
                }
            )
        interfaces.sort(key=lambda row: str(row.get("interface", "")).lower())

    global_metrics = parse_monitoring_metrics(str(load_monitoring_settings().get("metrics", "")))
    metrics_override = str(profile.get("metrics_override", "")).strip()
    selected_metrics = parse_monitoring_metrics(metrics_override) if metrics_override else set(global_metrics)
    selected_resources = profile.get("selected_resources", {}) if isinstance(profile.get("selected_resources", {}), dict) else {}
    metrics_saved = selected_resources.get("metrics", []) if isinstance(selected_resources.get("metrics", []), list) else []
    if metrics_saved:
        selected_metrics = {str(item).strip().lower() for item in metrics_saved if str(item).strip()}

    selected_interfaces: set[str] = set()
    interfaces_saved = selected_resources.get("interfaces", []) if isinstance(selected_resources.get("interfaces", []), list) else []
    if interfaces_saved:
        selected_interfaces = {str(item).strip() for item in interfaces_saved if str(item).strip()}
    else:
        interfaces_watch = str(profile.get("interfaces_watch", "")).strip()
        if interfaces_watch and interfaces_watch.lower() != "all":
            selected_interfaces = {str(item).strip() for item in interfaces_watch.split(",") if str(item).strip()}

    write_audit_log_safe(
        "monitoring_resources_pulled",
        details={"device_name": device_name, "host": host, "interfaces_found": len(interfaces), "source": source},
        requester=current_username,
    )
    return jsonify(
        {
            "ok": True,
            "device_name": device_name,
            "host": host,
            "source": source,
            "metrics": ["cpu", "memory", "interfaces", "sla"],
            "selected_metrics": sorted(selected_metrics),
            "interfaces": interfaces,
            "selected_interfaces": sorted(selected_interfaces),
        }
    )


def monitoring_node_resources_save_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if not can_manage_monitoring_nodes(role):
        return jsonify({"ok": False, "error": "Only Senior/SysAdmin can save monitoring resources."}), 403

    payload = request.get_json(silent=True) or {}
    device_name = str(payload.get("device_name", "")).strip()
    if not device_name:
        return jsonify({"ok": False, "error": "Device name is required."}), 400

    selected_metrics_raw = payload.get("metrics", [])
    selected_interfaces_raw = payload.get("interfaces", [])
    selected_metrics = [
        item
        for item in {str(v).strip().lower() for v in (selected_metrics_raw if isinstance(selected_metrics_raw, list) else [])}
        if item in {"cpu", "memory", "interfaces", "sla"}
    ]
    selected_interfaces = sorted(
        {
            str(v).strip()
            for v in (selected_interfaces_raw if isinstance(selected_interfaces_raw, list) else [])
            if str(v).strip() and re.match(r"^[A-Za-z][A-Za-z0-9/.\-]+$", str(v).strip())
        }
    )

    base_device, profile, host = _monitoring_device_lookup(device_name)
    profile_category = _monitoring_effective_category(device_name)
    if not category_allowed_for_monitoring_add(role, profile_category):
        return jsonify({"ok": False, "error": "You can manage resources only for allowed monitoring categories."}), 403
    if not monitoring_user_allowed_for_category(current_username, auth_mode, profile_category):
        return jsonify({"ok": False, "error": "You are not allowed to access this device category."}), 403
    if not host:
        host = str(base_device.get("host", "")).strip()
    if not host:
        try:
            with db_conn() as conn:
                row = conn.execute(
                    "SELECT TOP (1) host FROM monitoring_metrics WHERE LOWER(device_name)=LOWER(?) ORDER BY collected_at DESC",
                    (device_name,),
                ).fetchone()
            host = str(row["host"] or "").strip() if row else ""
        except Exception:
            host = ""
    if not host:
        return jsonify({"ok": False, "error": "Device host/IP is not configured and no historical data found."}), 400
    profile["selected_resources"] = {
        "metrics": selected_metrics,
        "interfaces": selected_interfaces,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    profile["metrics_override"] = ",".join(selected_metrics)
    profile["interfaces_watch"] = ",".join(selected_interfaces) if selected_interfaces else "all"
    save_monitoring_device_profile(device_name, host, profile)
    write_audit_log_safe(
        "monitoring_resources_saved",
        details={
            "device_name": device_name,
            "metrics": selected_metrics,
            "interfaces_count": len(selected_interfaces),
        },
        requester=current_username,
    )
    return jsonify({"ok": True, "message": "Monitoring resources saved."})


def monitoring_alert_ack_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if not can_manage_monitoring_nodes(role):
        return jsonify({"ok": False, "error": "Only Senior/SysAdmin can acknowledge alerts."}), 403

    payload = request.get_json(silent=True) or {}
    try:
        alert_id = int(payload.get("alert_id", 0) or 0)
    except Exception:
        alert_id = 0
    if alert_id <= 0:
        return jsonify({"ok": False, "error": "Valid alert_id is required."}), 400

    now_iso = datetime.now(timezone.utc).isoformat()
    acked_ok = False
    try:
        with db_conn() as conn:
            conn.execute(
                """
                UPDATE monitoring_alerts
                SET status = 'acked', acked_by = ?, acked_at = ?, updated_at = ?
                WHERE id = ? AND status = 'open'
                """,
                (current_username, now_iso, now_iso, alert_id),
            )
            row = conn.execute("SELECT status FROM monitoring_alerts WHERE id = ?", (alert_id,)).fetchone()
            acked_ok = bool(row and str(row["status"] or "").strip().lower() == "acked")
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Failed to acknowledge alert: {exc}"}), 500

    if not acked_ok:
        return jsonify({"ok": False, "error": "Alert not found or already acknowledged/cleared."}), 404

    write_audit_log_safe(
        "monitoring_alert_acknowledged",
        details={"alert_id": alert_id},
        requester=current_username,
    )
    return jsonify({"ok": True, "message": "Alert acknowledged."})


def monitoring_node_dashboard_data_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403

    payload = request.get_json(silent=True) or {}
    device_name = str(payload.get("device_name", "")).strip()
    force_refresh = bool(payload.get("force_refresh", False))
    try:
        limit = max(10, min(500, int(payload.get("limit", 120) or 120)))
    except Exception:
        limit = 120
    range_start_raw = str(payload.get("range_start", "")).strip()
    range_end_raw = str(payload.get("range_end", "")).strip()

    def _parse_payload_dt(raw: str) -> datetime | None:
        text = str(raw or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    range_start_dt = _parse_payload_dt(range_start_raw)
    range_end_dt = _parse_payload_dt(range_end_raw)
    if range_start_dt and range_end_dt and range_start_dt >= range_end_dt:
        range_start_dt = None
        range_end_dt = None
    if not device_name:
        return jsonify({"ok": False, "error": "Device name is required."}), 400

    base_device, profile, host = _monitoring_device_lookup(device_name)
    if not host:
        host = str(base_device.get("host", "")).strip()
    if not host:
        try:
            with db_conn() as conn:
                row = conn.execute(
                    "SELECT TOP (1) host FROM monitoring_metrics WHERE LOWER(device_name)=LOWER(?) ORDER BY collected_at DESC",
                    (device_name,),
                ).fetchone()
            host = str(row["host"] or "").strip() if row else ""
        except Exception:
            host = ""
    if not host:
        return jsonify({"ok": False, "error": "Device host/IP is not configured and no historical data found."}), 400
    profile_category = str(profile.get("category", "")).strip()
    if not profile_category:
        base_groups = base_device.get("groups", []) if isinstance(base_device.get("groups", []), list) else []
        profile_category = str(base_groups[0]).strip() if base_groups else DEFAULT_CATEGORY
    if not monitoring_user_allowed_for_category(current_username, auth_mode, profile_category):
        return jsonify({"ok": False, "error": "You are not allowed to access this device category."}), 403
    is_windows_node = is_windows_servers_category(profile_category)

    def _selected_interface_set() -> set[str]:
        selected_resources = profile.get("selected_resources", {}) if isinstance(profile.get("selected_resources", {}), dict) else {}
        interfaces_saved = selected_resources.get("interfaces", []) if isinstance(selected_resources.get("interfaces", []), list) else []
        if interfaces_saved:
            return {str(item).strip() for item in interfaces_saved if str(item).strip()}
        interfaces_watch = str(profile.get("interfaces_watch", "")).strip()
        if interfaces_watch and interfaces_watch.lower() != "all":
            return {str(item).strip() for item in interfaces_watch.split(",") if str(item).strip()}
        return set()

    def _parse_collected_at(raw: str) -> datetime | None:
        text = str(raw or "").strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    def _is_up_status(status_raw: str) -> bool:
        state = str(status_raw or "").strip().lower()
        return state in {"up", "warning", "connected", "ok", "online"}

    def _compute_availability_windows() -> dict[str, float | None]:
        now_utc = datetime.now(timezone.utc)
        windows = {
            "week": now_utc - timedelta(days=7),
            "month": now_utc - timedelta(days=30),
            "half_year": now_utc - timedelta(days=182),
            "year": now_utc - timedelta(days=365),
        }
        earliest = windows["year"]
        earliest_iso = earliest.isoformat()

        with db_conn() as conn:
            prev_row = conn.execute(
                """
                SELECT TOP (1) status, collected_at
                FROM monitoring_metrics
                WHERE LOWER(device_name) = LOWER(?) AND collected_at < ?
                ORDER BY collected_at DESC
                """,
                (device_name, earliest_iso),
            ).fetchone()
            event_rows = conn.execute(
                """
                SELECT status, collected_at
                FROM monitoring_metrics
                WHERE LOWER(device_name) = LOWER(?) AND collected_at >= ?
                ORDER BY collected_at ASC
                """,
                (device_name, earliest_iso),
            ).fetchall()

        events: list[tuple[datetime, bool]] = []
        for row in event_rows:
            ts = _parse_collected_at(str(row["collected_at"] or ""))
            if ts is None:
                continue
            events.append((ts, _is_up_status(str(row["status"] or ""))))

        prev_state: bool | None = None
        prev_ts: datetime | None = None
        if prev_row:
            prev_ts = _parse_collected_at(str(prev_row["collected_at"] or ""))
            if prev_ts is not None:
                prev_state = _is_up_status(str(prev_row["status"] or ""))

        def _window_availability(start_dt: datetime) -> float | None:
            state_at_start: bool | None = prev_state if prev_ts is not None and prev_ts <= start_dt else None
            for ts, state in events:
                if ts <= start_dt:
                    state_at_start = state
                else:
                    break
            if state_at_start is None:
                return None

            up_seconds = 0.0
            down_seconds = 0.0
            cursor = start_dt
            current_state = state_at_start
            for ts, next_state in events:
                if ts <= start_dt:
                    continue
                if ts > now_utc:
                    break
                duration = max(0.0, (ts - cursor).total_seconds())
                if current_state:
                    up_seconds += duration
                else:
                    down_seconds += duration
                cursor = ts
                current_state = next_state
            tail = max(0.0, (now_utc - cursor).total_seconds())
            if current_state:
                up_seconds += tail
            else:
                down_seconds += tail
            total = up_seconds + down_seconds
            if total <= 0:
                return None
            return (up_seconds / total) * 100.0

        return {
            "week": _window_availability(windows["week"]),
            "month": _window_availability(windows["month"]),
            "half_year": _window_availability(windows["half_year"]),
            "year": _window_availability(windows["year"]),
        }

    def _load_interface_utilization(series_rows: list[dict[str, Any]], latest_row: dict[str, Any]) -> list[dict[str, Any]]:
        selected_ifaces_raw = [str(v).strip() for v in _selected_interface_set() if str(v).strip()]
        selected_ifaces_exact = {v.lower() for v in selected_ifaces_raw}
        selected_ifaces_normalized = {_normalize_interface_key(v) for v in selected_ifaces_raw if _normalize_interface_key(v)}
        normalized: list[dict[str, Any]] = []

        # Primary source: dedicated per-interface history table.
        try:
            with db_conn() as conn:
                if range_start_dt and range_end_dt:
                    db_rows = conn.execute(
                        """
                        SELECT TOP (10000) interface_name, interface_description, oper_status, tx_percent, rx_percent, collected_at_utc
                        FROM monitoring_interface_metrics
                        WHERE LOWER(device_name) = LOWER(?) AND collected_at_utc >= ? AND collected_at_utc <= ?
                        ORDER BY collected_at_utc DESC
                        """,
                        (device_name, range_start_dt.isoformat(), range_end_dt.isoformat()),
                    ).fetchall()
                else:
                    db_rows = conn.execute(
                        """
                        SELECT TOP (10000) interface_name, interface_description, oper_status, tx_percent, rx_percent, collected_at_utc
                        FROM monitoring_interface_metrics
                        WHERE LOWER(device_name) = LOWER(?)
                        ORDER BY collected_at_utc DESC
                        """,
                        (device_name,),
                    ).fetchall()
            per_iface: dict[str, dict[str, Any]] = {}
            for row in db_rows:
                iface = str(row["interface_name"] or "").strip()
                if not iface:
                    continue
                iface_lower = iface.lower()
                iface_key = _normalize_interface_key(iface) or iface_lower
                if iface_key in per_iface:
                    continue
                if selected_ifaces_exact or selected_ifaces_normalized:
                    if iface_lower not in selected_ifaces_exact and iface_key not in selected_ifaces_normalized:
                        continue
                status_raw = str(row["oper_status"] or "unknown").strip().lower()
                if status_raw in {"connected"}:
                    status_value = "up"
                elif status_raw in {"disable", "err-disable", "notconnected"}:
                    status_value = "down"
                elif status_raw in {"up", "down", "unknown"}:
                    status_value = status_raw
                else:
                    status_value = "unknown"
                try:
                    tx_val = row["tx_percent"]
                    tx_percent = max(0.0, min(100.0, float(tx_val))) if tx_val is not None else None
                except Exception:
                    tx_percent = None
                try:
                    rx_val = row["rx_percent"]
                    rx_percent = max(0.0, min(100.0, float(rx_val))) if rx_val is not None else None
                except Exception:
                    rx_percent = None
                per_iface[iface_key] = {
                    "status": status_value,
                    "interface": iface,
                    "description": str(row["interface_description"] or "").strip(),
                    "tx_percent": tx_percent,
                    "rx_percent": rx_percent,
                }
            normalized = sorted(per_iface.values(), key=lambda item: str(item.get("interface", "")).lower())
            if normalized:
                return normalized
        except Exception:
            pass

        # Backward-compatible fallback: legacy JSON details stored in monitoring_metrics.
        if not series_rows and not latest_row:
            return []
        raw_rows: list[Any] = []
        for sample in reversed(series_rows):
            details_obj = sample.get("details", {}) if isinstance(sample, dict) else {}
            if not isinstance(details_obj, dict):
                continue
            candidate = details_obj.get("interface_utilization", [])
            if isinstance(candidate, list) and candidate:
                raw_rows = candidate
                break
        if not raw_rows and isinstance(latest_row, dict):
            details_obj = latest_row.get("details", {})
            if isinstance(details_obj, dict):
                candidate = details_obj.get("interface_utilization", [])
                if isinstance(candidate, list) and candidate:
                    raw_rows = candidate
        if not raw_rows:
            return []
        normalized = []
        for row in raw_rows:
            if not isinstance(row, dict):
                continue
            interface_name = str(row.get("interface", "")).strip()
            if not interface_name:
                continue
            interface_lower = interface_name.lower()
            interface_key = _normalize_interface_key(interface_name) or interface_lower
            if selected_ifaces_exact or selected_ifaces_normalized:
                if interface_lower not in selected_ifaces_exact and interface_key not in selected_ifaces_normalized:
                    continue
            status_value = str(row.get("status", "unknown") or "unknown").strip().lower()
            if status_value not in {"up", "down", "unknown"}:
                status_value = "unknown"
            try:
                tx_val = row.get("tx_percent")
                tx_percent = max(0.0, min(100.0, float(tx_val))) if tx_val is not None else None
            except Exception:
                tx_percent = None
            try:
                rx_val = row.get("rx_percent")
                rx_percent = max(0.0, min(100.0, float(rx_val))) if rx_val is not None else None
            except Exception:
                rx_percent = None
            normalized.append(
                {
                    "status": status_value,
                    "interface": interface_name,
                    "description": str(row.get("description", "")).strip(),
                    "tx_percent": tx_percent,
                    "rx_percent": rx_percent,
                }
            )
        normalized.sort(key=lambda item: str(item.get("interface", "")).lower())
        return normalized

    def _extract_windows_server_data(latest_row: dict[str, Any]) -> dict[str, Any]:
        details = latest_row.get("details", {}) if isinstance(latest_row, dict) else {}
        winrm = details.get("winrm", {}) if isinstance(details, dict) else {}
        if not isinstance(winrm, dict):
            winrm = {}
        raw_disks = winrm.get("disk_usage", [])
        disks = raw_disks if isinstance(raw_disks, list) else []
        out_disks: list[dict[str, Any]] = []
        for disk in disks:
            if not isinstance(disk, dict):
                continue
            label = str(disk.get("label", "")).strip() or "-"
            try:
                used_percent = float(disk.get("used_percent")) if disk.get("used_percent") is not None else None
            except Exception:
                used_percent = None
            try:
                free_gb = float(disk.get("free_gb")) if disk.get("free_gb") is not None else None
            except Exception:
                free_gb = None
            out_disks.append({"label": label, "used_percent": used_percent, "free_gb": free_gb})
        return {
            "is_windows_server": is_windows_node,
            "uptime_seconds": winrm.get("uptime_seconds"),
            "last_boot": str(winrm.get("last_boot", "")).strip(),
            "network_rx_mbps": winrm.get("network_rx_mbps"),
            "network_tx_mbps": winrm.get("network_tx_mbps"),
            "windows_caption": str(winrm.get("windows_caption", "")).strip(),
            "windows_version": str(winrm.get("windows_version", "")).strip(),
            "windows_build": str(winrm.get("windows_build", "")).strip(),
            "windows_arch": str(winrm.get("windows_arch", "")).strip(),
            "computer_name": str(winrm.get("computer_name", "")).strip(),
            "computer_model": str(winrm.get("computer_model", "")).strip(),
            "domain": str(winrm.get("domain", "")).strip(),
            "total_memory_gb": winrm.get("total_memory_gb"),
            "free_memory_gb": winrm.get("free_memory_gb"),
            "disk_usage": out_disks,
        }

    def _serialize_sample_ts(raw_value: Any) -> str:
        if isinstance(raw_value, datetime):
            dt = raw_value
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        text = str(raw_value or "").strip()
        if not text:
            return ""
        parsed = _parse_collected_at(text)
        return parsed.isoformat() if parsed is not None else text

    def _row_to_sample(sample_row: Any, include_details: bool = True) -> dict[str, Any]:
        details: dict[str, Any] = {}
        if include_details:
            try:
                details_json = str(sample_row["details_json"] or "{}")
            except Exception:
                details_json = "{}"
            try:
                loaded = json.loads(details_json)
            except Exception:
                loaded = {}
            if isinstance(loaded, dict):
                details = loaded
        collected_value = ""
        try:
            collected_value = _serialize_sample_ts(sample_row["collected_at_utc"])
        except Exception:
            pass
        if not collected_value:
            try:
                collected_value = _serialize_sample_ts(sample_row["collected_at"])
            except Exception:
                collected_value = ""
        return {
            "status": str(sample_row["status"] or "").strip().lower(),
            "severity": str(sample_row["severity"] or "").strip().lower(),
            "cpu_percent": _cap_percent(sample_row["cpu_percent"]),
            "memory_percent": sample_row["memory_percent"],
            "interfaces_up": sample_row["interfaces_up"],
            "interfaces_down": sample_row["interfaces_down"],
            "sla_ms": sample_row["sla_ms"],
            "details": details,
            "collected_at": collected_value,
        }

    def _load_latest_sample() -> dict[str, Any]:
        queries = [
            """
            SELECT TOP (1) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc
            FROM monitoring_metrics
            WHERE LOWER(device_name) = LOWER(?)
            ORDER BY collected_at_utc DESC
            """,
            """
            SELECT TOP (1) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at
            FROM monitoring_metrics
            WHERE LOWER(device_name) = LOWER(?)
            ORDER BY collected_at DESC
            """,
        ]
        for sql_text in queries:
            try:
                with db_conn() as conn:
                    latest_row = conn.execute(sql_text, (device_name,)).fetchone()
                if latest_row:
                    return _row_to_sample(latest_row, include_details=True)
            except Exception:
                continue
        return {}

    def _load_samples() -> list[dict[str, Any]]:
        out_rows: list[dict[str, Any]] = []
        using_rollup = False
        range_start_iso = range_start_dt.isoformat() if range_start_dt else ""
        range_end_iso = range_end_dt.isoformat() if range_end_dt else ""
        range_seconds = max(0.0, (range_end_dt - range_start_dt).total_seconds()) if (range_start_dt and range_end_dt) else 0.0

        with db_conn() as conn:
            sample_rows: list[Any] = []

            # For long windows, use hourly rollups when available.
            if range_start_dt and range_end_dt and range_seconds >= (48 * 3600):
                try:
                    sample_rows = conn.execute(
                        """
                        SELECT bucket_start_utc, cpu_avg AS cpu_percent, memory_avg AS memory_percent, sla_avg_ms AS sla_ms, availability_pct
                        FROM monitoring_rollup_hourly
                        WHERE LOWER(device_name) = LOWER(?) AND bucket_start_utc >= ? AND bucket_start_utc <= ?
                        ORDER BY bucket_start_utc ASC
                        """,
                        (device_name, range_start_iso, range_end_iso),
                    ).fetchall()
                    using_rollup = bool(sample_rows)
                except Exception:
                    sample_rows = []
                    using_rollup = False

            if not sample_rows:
                if range_start_dt and range_end_dt:
                    try:
                        sample_rows = conn.execute(
                            """
                            SELECT TOP (20000) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc
                            FROM monitoring_metrics
                            WHERE LOWER(device_name) = LOWER(?) AND collected_at_utc >= ? AND collected_at_utc <= ?
                            ORDER BY collected_at_utc DESC
                            """,
                            (device_name, range_start_iso, range_end_iso),
                        ).fetchall()
                    except Exception:
                        sample_rows = conn.execute(
                            """
                            SELECT TOP (20000) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at
                            FROM monitoring_metrics
                            WHERE LOWER(device_name) = LOWER(?) AND collected_at >= ? AND collected_at <= ?
                            ORDER BY collected_at DESC
                            """,
                            (device_name, range_start_iso, range_end_iso),
                        ).fetchall()
                else:
                    try:
                        sample_rows = conn.execute(
                            """
                            SELECT TOP (?) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc
                            FROM monitoring_metrics
                            WHERE LOWER(device_name) = LOWER(?)
                            ORDER BY collected_at_utc DESC
                            """,
                            (limit, device_name),
                        ).fetchall()
                    except Exception:
                        sample_rows = conn.execute(
                            """
                            SELECT TOP (?) status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at
                            FROM monitoring_metrics
                            WHERE LOWER(device_name) = LOWER(?)
                            ORDER BY collected_at DESC
                            """,
                            (limit, device_name),
                        ).fetchall()

        if using_rollup:
            for row in sample_rows:
                out_rows.append(
                    {
                        "status": "up",
                        "severity": "ok",
                        "cpu_percent": _cap_percent(row["cpu_percent"]),
                        "memory_percent": row["memory_percent"],
                        "interfaces_up": None,
                        "interfaces_down": None,
                        "sla_ms": row["sla_ms"],
                        "details": {},
                        "collected_at": _serialize_sample_ts(row["bucket_start_utc"]),
                    }
                )
            return out_rows

        for sample_row in sample_rows:
            out_rows.append(_row_to_sample(sample_row, include_details=True))
        out_rows.reverse()
        return out_rows

    rows: list[dict[str, Any]] = _load_samples()
    latest = _load_latest_sample()
    interval_seconds = int(profile.get("interval_seconds", 30) or 30)
    if force_refresh:
        try:
            poll_device = {
                "name": device_name,
                "host": host,
                "groups": [profile_category or DEFAULT_CATEGORY],
                "port": 22,
            }
            effective = monitoring_effective_settings(load_monitoring_settings(), profile)
            ping_state, ping_latency = ping_host_status(host, 2)
            if ping_state != "up":
                forced_sample = {
                    "device_name": device_name,
                    "host": host,
                    "collection_mode": str(effective.get("collection_mode", "status_only")).strip().lower() or "status_only",
                    "status": "down",
                    "severity": "critical",
                    "cpu_percent": None,
                    "memory_percent": None,
                    "interfaces_up": None,
                    "interfaces_down": None,
                    "sla_ms": ping_latency,
                    "cpu_warn": max(1, min(100, int(effective.get("cpu_warn", 90) or 90))),
                    "memory_warn": max(1, min(100, int(effective.get("memory_warn", 90) or 90))),
                    "details_json": json.dumps(
                        {"ping_latency_ms": ping_latency, "poll_skipped_reason": "icmp_down", "forced_refresh": True}
                    ),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }
            else:
                forced_sample = poll_device_monitoring_sample(poll_device, effective, pre_ping=(ping_state, ping_latency))
            save_monitoring_sample(forced_sample)
            rows = _load_samples()
            latest = _load_latest_sample()
        except Exception as exc:
            write_audit_log_safe(
                "monitoring_dashboard_force_refresh_failed",
                details={"device_name": device_name, "host": host, "error": str(exc)},
                requester=current_username,
            )
    availability = _compute_availability_windows()
    interface_utilization = _load_interface_utilization(rows, latest)
    windows_server = _extract_windows_server_data(latest)
    active_alerts = load_monitoring_alerts(device_name, ["open", "acked"], limit=50)
    write_audit_log_safe(
        "monitoring_dashboard_data_viewed",
        details={
            "device_name": device_name,
            "sample_count": len(rows),
            "interface_rows": len(interface_utilization),
            "windows_server": bool(windows_server.get("is_windows_server")),
            "active_alerts": len(active_alerts),
        },
        requester=current_username,
    )
    return jsonify(
        {
            "ok": True,
            "device": {
                "name": device_name,
                "host": host,
                "category": profile_category,
                "polling_method": str(profile.get("polling_method", "status_only")).strip().lower() or "status_only",
                "interval_seconds": interval_seconds,
                "notes": str(profile.get("notes", "")).strip(),
            },
            "latest": latest,
            "series": rows,
            "availability": availability,
            "interface_utilization": interface_utilization,
            "windows_server": windows_server,
            "alerts": active_alerts,
        }
    )


def monitoring_node_live_gauges_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "monitoring"):
        return jsonify({"ok": False, "error": "Access denied."}), 403

    payload = request.get_json(silent=True) or {}
    device_name = str(payload.get("device_name", "")).strip()
    if not device_name:
        return jsonify({"ok": False, "error": "Device name is required."}), 400

    base_device, profile, host = _monitoring_device_lookup(device_name)
    if not host:
        host = str(base_device.get("host", "")).strip()
    if not host:
        return jsonify({"ok": False, "error": "Device host/IP is not configured."}), 400

    profile_category = str(profile.get("category", "")).strip()
    if not profile_category:
        base_groups = base_device.get("groups", []) if isinstance(base_device.get("groups", []), list) else []
        profile_category = str(base_groups[0]).strip() if base_groups else DEFAULT_CATEGORY
    if not monitoring_user_allowed_for_category(current_username, auth_mode, profile_category):
        return jsonify({"ok": False, "error": "You are not allowed to access this device category."}), 403
    if not is_windows_servers_category(profile_category):
        return jsonify({"ok": False, "error": "Live gauges are available only for Windows Servers."}), 400

    now_iso = datetime.now(timezone.utc).isoformat()
    effective = monitoring_effective_settings(load_monitoring_settings(), profile)
    effective["collection_mode"] = "winrm"
    ping_state, ping_latency = ping_host_status(host, 1)
    live_metrics, live_errors = winrm_collect_live_gauges(host, effective, timeout_seconds=6)
    winrm_obj = live_metrics if isinstance(live_metrics, dict) else {}
    live_has_data = any(
        winrm_obj.get(k) not in (None, "")
        for k in (
            "cpu_percent",
            "memory_percent",
            "uptime_seconds",
            "last_boot",
            "windows_caption",
            "network_rx_mbps",
            "network_tx_mbps",
        )
    )
    status_value = "up" if (ping_state == "up" or live_has_data) else "down"
    sample = {
        "status": status_value,
        "cpu_percent": winrm_obj.get("cpu_percent"),
        "memory_percent": winrm_obj.get("memory_percent"),
        "sla_ms": ping_latency,
        "collected_at": now_iso,
    }
    if live_errors:
        sample["details_json"] = json.dumps({"winrm_errors": live_errors, "live_only": True})

    # Fallback to latest stored sample if live WinRM returned empty fields.
    if not live_has_data:
        try:
            with db_conn() as conn:
                latest_row = conn.execute(
                    """
                    SELECT TOP (1) status, cpu_percent, memory_percent, sla_ms, details_json, collected_at_utc, collected_at
                    FROM monitoring_metrics
                    WHERE LOWER(device_name)=LOWER(?)
                    ORDER BY collected_at_utc DESC
                    """,
                    (device_name,),
                ).fetchone()
            if latest_row:
                sample["status"] = str(latest_row["status"] or sample.get("status", "unknown")).strip().lower() or "unknown"
                sample["cpu_percent"] = latest_row["cpu_percent"] if latest_row["cpu_percent"] is not None else sample.get("cpu_percent")
                sample["memory_percent"] = (
                    latest_row["memory_percent"] if latest_row["memory_percent"] is not None else sample.get("memory_percent")
                )
                sample["sla_ms"] = latest_row["sla_ms"] if latest_row["sla_ms"] is not None else sample.get("sla_ms")
                collected = str(latest_row["collected_at_utc"] or latest_row["collected_at"] or "").strip()
                if collected:
                    sample["collected_at"] = collected
                try:
                    details_obj = json.loads(str(latest_row["details_json"] or "{}"))
                except Exception:
                    details_obj = {}
                if isinstance(details_obj, dict):
                    prev_winrm = details_obj.get("winrm", {})
                    if isinstance(prev_winrm, dict):
                        merged = dict(prev_winrm)
                        for key, value in winrm_obj.items():
                            if value not in (None, ""):
                                merged[key] = value
                        winrm_obj = merged
        except Exception:
            pass

    sampled_at = str(sample.get("collected_at", "")).strip() or now_iso
    return jsonify(
        {
            "ok": True,
            "device_name": device_name,
            "host": host,
            "status": str(sample.get("status", "unknown") or "unknown").strip().lower(),
            "cpu_percent": _cap_percent(sample.get("cpu_percent")),
            "memory_percent": _cap_percent(sample.get("memory_percent")),
            "sla_ms": sample.get("sla_ms"),
            "sampled_at": sampled_at,
            "network_rx_mbps": winrm_obj.get("network_rx_mbps"),
            "network_tx_mbps": winrm_obj.get("network_tx_mbps"),
            "uptime_seconds": winrm_obj.get("uptime_seconds"),
            "last_boot": str(winrm_obj.get("last_boot", "")).strip(),
            "windows_caption": str(winrm_obj.get("windows_caption", "")).strip(),
            "windows_version": str(winrm_obj.get("windows_version", "")).strip(),
            "windows_build": str(winrm_obj.get("windows_build", "")).strip(),
            "windows_arch": str(winrm_obj.get("windows_arch", "")).strip(),
            "computer_name": str(winrm_obj.get("computer_name", "")).strip(),
            "computer_model": str(winrm_obj.get("computer_model", "")).strip(),
            "domain": str(winrm_obj.get("domain", "")).strip(),
            "total_memory_gb": winrm_obj.get("total_memory_gb"),
            "free_memory_gb": winrm_obj.get("free_memory_gb"),
        }
    )
