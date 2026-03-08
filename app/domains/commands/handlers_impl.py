from __future__ import annotations
# ruff: noqa: F821

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

def open_runtime_device_session(runtime_id: str, device: dict[str, Any], creds: dict[str, Any]) -> tuple[bool, str]:
    import paramiko

    existing = get_runtime_device_session(runtime_id, str(device.get("name", "")))
    if existing is not None:
        return True, "session already active"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    timeout = int(creds.get("timeout", 8))
    try:
        client.connect(
            hostname=str(device.get("host", "")),
            port=int(device.get("port", 22)),
            username=str(creds.get("username", "")),
            password=str(creds.get("password", "")),
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        channel = client.invoke_shell(width=180, height=40)
        time.sleep(0.2)
        warmup = ""
        while channel.recv_ready():
            warmup += channel.recv(4096).decode("utf-8", errors="replace")

        with RUNTIME_SSH_LOCK:
            runtime_store = RUNTIME_SSH_SESSIONS.setdefault(runtime_id, {})
            runtime_store[str(device.get("name", ""))] = {
                "client": client,
                "channel": channel,
                "host": str(device.get("host", "")),
                "port": int(device.get("port", 22)),
                "opened_at": time.time(),
            }
        return True, warmup.strip() or "SSH shell connected"
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return False, str(exc)


def run_config_commands(
    host: str,
    port: int,
    username: str,
    password: str,
    command_text: str,
    timeout: int,
    enable_password: str = "",
) -> tuple[str, str]:
    import paramiko

    commands = split_cli_commands(command_text)
    if not commands:
        return "FAIL", "No command provided."

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
        channel = client.invoke_shell(width=180, height=40)
        time.sleep(0.25)
        while channel.recv_ready():
            channel.recv(4096)

        output_parts: list[str] = []

        channel.send("terminal length 0\n")
        text = _read_shell_output(channel, timeout)
        if text:
            output_parts.append(text)

        lower_cmds = [cmd.strip().lower() for cmd in commands]
        if any(cmd.startswith(("configure terminal", "conf t", "interface ")) for cmd in lower_cmds):
            channel.send("enable\n")
            enable_prompt = _read_shell_output(channel, timeout)
            if enable_prompt:
                output_parts.append(enable_prompt)
                if "password" in enable_prompt.lower() and enable_password:
                    channel.send(enable_password + "\n")
                    post_enable = _read_shell_output(channel, timeout)
                    if post_enable:
                        output_parts.append(post_enable)

        for cmd in commands:
            channel.send(cmd + "\n")
            text = _read_shell_output(channel, timeout)
            if text:
                output_parts.append(text)

        return "PASS", "\n".join(output_parts).strip() or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass


def run_errdisable_recovery_sequence(
    host: str,
    port: int,
    username: str,
    password: str,
    interfaces: list[str],
    timeout: int,
    enable_password: str = "",
) -> tuple[str, str]:
    import paramiko

    cleaned = [str(item).strip() for item in interfaces if str(item).strip()]
    if not cleaned:
        return "FAIL", "No interface selected."
    for interface_name in cleaned:
        if not re.match(r"^[A-Za-z][A-Za-z0-9/.\-]+$", interface_name):
            return "FAIL", f"Invalid interface name: {interface_name}"

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
        channel = client.invoke_shell(width=180, height=40)
        time.sleep(0.25)
        while channel.recv_ready():
            channel.recv(4096)

        output_parts: list[str] = []
        channel.send("terminal length 0\n")
        text = _read_shell_output(channel, timeout)
        if text:
            output_parts.append(text)

        channel.send("enable\n")
        enable_prompt = _read_shell_output(channel, timeout)
        if enable_prompt:
            output_parts.append(enable_prompt)
            if "password" in enable_prompt.lower() and enable_password:
                channel.send(enable_password + "\n")
                post_enable = _read_shell_output(channel, timeout)
                if post_enable:
                    output_parts.append(post_enable)

        for interface_name in cleaned:
            channel.send(f"clear port-security sticky interface {interface_name}\n")
            clear_out = _read_shell_output(channel, timeout)
            if clear_out:
                output_parts.append(clear_out)

            channel.send("configure terminal\n")
            conf_out = _read_shell_output(channel, timeout)
            if conf_out:
                output_parts.append(conf_out)

            channel.send(f"interface {interface_name}\n")
            intf_out = _read_shell_output(channel, timeout)
            if intf_out:
                output_parts.append(intf_out)

            channel.send("shutdown\n")
            shut_out = _read_shell_output(channel, timeout)
            if shut_out:
                output_parts.append(shut_out)

            time.sleep(1.0)
            channel.send("no shutdown\n")
            no_shut_out = _read_shell_output(channel, timeout)
            if no_shut_out:
                output_parts.append(no_shut_out)

            channel.send("end\n")
            end_out = _read_shell_output(channel, timeout)
            if end_out:
                output_parts.append(end_out)

        return "PASS", "\n".join(output_parts).strip() or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass


def run_ssh_command(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
    timeout: int,
    command_mode: str = "show",
    enable_password: str = "",
) -> tuple[str, str]:
    import paramiko

    commands = split_cli_commands(command)
    mode = str(command_mode or "show").strip().lower()
    if mode == "config":
        return run_config_commands(
            host=host,
            port=port,
            username=username,
            password=password,
            command_text=command,
            timeout=timeout,
            enable_password=enable_password,
        )

    if not commands:
        return "FAIL", "No command provided."

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
        _, stdout, stderr = client.exec_command(commands[0], timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        text = out if out.strip() else err
        return "PASS", text or "(no output)"
    except Exception as exc:
        return "FAIL", str(exc)
    finally:
        client.close()


def ping_selected_devices() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "message": "Not authenticated."}), 401

    payload = request.get_json(silent=True) or {}
    selected_names = payload.get("selected_devices", [])
    if not isinstance(selected_names, list):
        selected_names = []

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        write_audit_log_safe(
            "device_ping_denied",
            details={"reason": "devices_panel_access_denied"},
            requester=current_username,
        )
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {str(device.get("name", "")): device for device in devices}

    chosen = [by_name[name] for name in selected_names if name in by_name]
    if not chosen:
        write_audit_log_safe(
            "device_ping_failed",
            details={"reason": "no_devices_selected_or_allowed", "requested_devices": selected_names},
            requester=current_username,
        )
        return jsonify({"ok": False, "message": "Select at least one device to ping."}), 400

    sections: list[str] = []
    any_success = False
    for device in chosen:
        host = str(device.get("host", "")).strip()
        name = str(device.get("name", "")).strip()
        if not host:
            sections.append(f"{name}: .....\nNo host configured.\n")
            continue
        ping_text = run_ping_for_host(host, count=5)
        if "!" in ping_text.splitlines()[1] if len(ping_text.splitlines()) > 1 else False:
            any_success = True
        sections.append(f"Device: {name} ({host})\n{ping_text}")

    write_audit_log_safe(
        "device_ping_executed",
        details={
            "requested_devices": selected_names,
            "executed_devices": [str(item.get("name", "")).strip() for item in chosen],
            "any_success": any_success,
        },
        requester=current_username,
    )
    return jsonify({"ok": any_success, "output": "\n".join(sections)})


def _parse_show_interfaces_status(output: str) -> dict[str, dict[str, str]]:
    lines = str(output or "").splitlines()
    header_idx = -1
    header_line = ""
    for idx, line in enumerate(lines):
        text = str(line or "")
        if "Port" in text and "Status" in text and "Vlan" in text:
            header_idx = idx
            header_line = text
            break

    rows: dict[str, dict[str, str]] = {}
    if header_idx < 0:
        return rows

    starts = {
        "port": header_line.find("Port"),
        "name": header_line.find("Name"),
        "status": header_line.find("Status"),
        "vlan": header_line.find("Vlan"),
        "duplex": header_line.find("Duplex"),
    }
    if starts["port"] < 0 or starts["name"] < 0 or starts["status"] < 0 or starts["vlan"] < 0:
        return rows

    for raw_line in lines[header_idx + 1 :]:
        line = str(raw_line or "")
        if not line.strip():
            continue
        if line.strip().startswith(("Port", "---")):
            continue
        if line.strip().endswith(("#", ">")) and line.strip().count(" ") == 0:
            continue

        try:
            port = line[starts["port"] : starts["name"]].strip()
            name = line[starts["name"] : starts["status"]].strip()
            status = line[starts["status"] : starts["vlan"]].strip()
            vlan_end = starts["duplex"] if starts["duplex"] > starts["vlan"] else len(line)
            vlan = line[starts["vlan"] : vlan_end].strip()
        except Exception:
            continue
        if not port or not re.match(r"^[A-Za-z]", port):
            continue

        key = _normalize_interface_key(port)
        if not key:
            continue
        rows[key] = {
            "interface": port,
            "description": name,
            "status": _normalize_interface_status(status),
            "vlan": vlan or "-",
            "mode": "access" if re.match(r"^\d+$", vlan or "") else ((vlan or "").lower() if vlan else "-"),
            "mac_addresses": "-",
        }

    return rows


def _collect_helpdesk_targets(payload: dict[str, Any]) -> tuple[dict[str, list[str]], dict[str, dict[str, str]], dict[str, dict[str, int]]]:
    selected = payload.get("selected_interfaces", [])
    descriptions = payload.get("descriptions", [])
    vlans = payload.get("vlans", [])
    selected_by_device: dict[str, list[str]] = {}
    description_by_device: dict[str, dict[str, str]] = {}
    vlan_by_device: dict[str, dict[str, int]] = {}

    if isinstance(selected, list):
        for item in selected:
            if not isinstance(item, dict):
                continue
            device_name = str(item.get("device", "")).strip()
            interface_name = str(item.get("interface", "")).strip()
            if not device_name or not interface_name:
                continue
            if not re.match(r"^[A-Za-z][A-Za-z0-9/.\-]+$", interface_name):
                continue
            selected_by_device.setdefault(device_name, [])
            if interface_name not in selected_by_device[device_name]:
                selected_by_device[device_name].append(interface_name)

    if isinstance(descriptions, list):
        for item in descriptions:
            if not isinstance(item, dict):
                continue
            device_name = str(item.get("device", "")).strip()
            interface_name = str(item.get("interface", "")).strip()
            description = re.sub(r"[\r\n]+", " ", str(item.get("description", ""))).strip()
            description = description[:120]
            if not device_name or not interface_name:
                continue
            if not re.match(r"^[A-Za-z][A-Za-z0-9/.\-]+$", interface_name):
                continue
            description_by_device.setdefault(device_name, {})
            description_by_device[device_name][interface_name] = description

    if isinstance(vlans, list):
        for item in vlans:
            if not isinstance(item, dict):
                continue
            device_name = str(item.get("device", "")).strip()
            interface_name = str(item.get("interface", "")).strip()
            vlan_raw = str(item.get("vlan", "")).strip()
            if not device_name or not interface_name or not vlan_raw.isdigit():
                continue
            if not re.match(r"^[A-Za-z][A-Za-z0-9/.\-]+$", interface_name):
                continue
            vlan_id = int(vlan_raw)
            if vlan_id < 1 or vlan_id > 4094:
                continue
            vlan_by_device.setdefault(device_name, {})
            vlan_by_device[device_name][interface_name] = vlan_id

    return selected_by_device, description_by_device, vlan_by_device


def _load_helpdesk_interfaces_for_device(device: dict[str, Any], creds: dict[str, Any]) -> dict[str, Any]:
    show_status_state, show_status_output = run_ssh_command(
        host=str(device.get("host", "")),
        port=int(device.get("port", 22)),
        username=str(creds.get("username", "")),
        password=str(creds.get("password", "")),
        command="show interfaces status",
        timeout=int(creds.get("timeout", 8) or 8),
        command_mode="show",
        enable_password=str(creds.get("enable_password", "")),
    )
    show_mac_state, show_mac_output = run_ssh_command(
        host=str(device.get("host", "")),
        port=int(device.get("port", 22)),
        username=str(creds.get("username", "")),
        password=str(creds.get("password", "")),
        command="show mac address-table",
        timeout=int(creds.get("timeout", 8) or 8),
        command_mode="show",
        enable_password=str(creds.get("enable_password", "")),
    )

    rows = _parse_show_interfaces_status(show_status_output if show_status_state == "PASS" else "")
    mac_rows = _parse_show_mac_table(show_mac_output if show_mac_state == "PASS" else "")
    for key, values in rows.items():
        macs = sorted(mac_rows.get(key, set()))
        values["mac_addresses"] = ", ".join(macs[:3]) if macs else "-"

    access_only = [row for row in rows.values() if str(row.get("mode", "")).strip().lower() == "access"]
    if not access_only and rows:
        # Some switch outputs do not expose an explicit "mode" column.
        # Keep access-like rows and exclude obvious trunk rows.
        fallback_rows: list[dict[str, Any]] = []
        for row in rows.values():
            mode = str(row.get("mode", "")).strip().lower()
            status = str(row.get("status", "")).strip().lower()
            vlan = str(row.get("vlan", "")).strip().lower()
            interface_name = str(row.get("interface", "")).strip()
            if not interface_name:
                continue
            if "trunk" in mode or "trunk" in status or vlan == "trunk":
                continue
            fallback_rows.append(row)
        access_only = fallback_rows
    return {
        "device": str(device.get("name", "")),
        "host": str(device.get("host", "")),
        "status_state": show_status_state,
        "mac_state": show_mac_state,
        "interfaces": sorted(access_only, key=lambda item: str(item.get("interface", "")).lower()),
    }


def helpdesk_interfaces_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if not is_helpdesk_action_user(role):
        write_audit_log_safe(
            "helpdesk_interface_denied",
            details={"reason": "role_not_allowed", "role": role},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "This endpoint is available for Helpdesk Action roles only."}), 403
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        write_audit_log_safe(
            "helpdesk_interface_denied",
            details={"reason": "devices_panel_access_denied"},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "You do not have access to the Devices panel."}), 403

    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action", "show")).strip().lower() or "show"
    selected_names = payload.get("selected_devices", [])
    if not isinstance(selected_names, list):
        selected_names = []
    selected_names = [str(name).strip() for name in selected_names if str(name).strip()]
    if not selected_names:
        write_audit_log_safe(
            "helpdesk_interface_failed",
            details={"reason": "no_devices_selected", "action": action},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Select at least one device."}), 400

    devices = filter_devices_for_user(load_devices(), current_username, auth_mode)
    by_name = {str(device.get("name", "")).strip(): device for device in devices}
    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        write_audit_log_safe(
            "helpdesk_interface_failed",
            details={
                "reason": "selected_devices_not_allowed",
                "action": action,
                "requested_devices": selected_names,
            },
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Selected devices are not available for your account."}), 400
    selected_device_names = [str(device.get("name", "")).strip() for device in selected_devices]
    selected_device_set = {name for name in selected_device_names if name}

    if action == "remove_errdisable":
        last_show_devices_raw = session.get("helpdesk_last_show_devices", [])
        last_show_devices = (
            [str(item).strip() for item in last_show_devices_raw if str(item).strip()] if isinstance(last_show_devices_raw, list) else []
        )
        last_show_set = set(last_show_devices)
        if not last_show_set or selected_device_set != last_show_set:
            write_audit_log_safe(
                "helpdesk_interface_denied",
                details={
                    "reason": "remove_errdisable_requires_matching_show_context",
                    "selected_devices": selected_device_names,
                    "last_show_devices": last_show_devices,
                },
                requester=current_username,
            )
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "Run Show Err-disable on the currently selected device(s) first, then run Remove Err-disable without changing selection.",
                    }
                ),
                400,
            )

    creds = _helpdesk_device_creds()
    if not creds["username"] or not creds["password"]:
        write_audit_log_safe(
            "helpdesk_interface_failed",
            details={"reason": "device_credentials_missing", "action": action},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Set device SSH credentials first from settings."}), 400

    selected_interfaces_by_device, descriptions_by_device, vlans_by_device = _collect_helpdesk_targets(payload)
    action_results: list[dict[str, Any]] = []

    if action in {"remove_errdisable", "set_description", "set_vlan", "shut", "no_shut"}:
        if action in {"shut", "no_shut", "set_vlan"} and not is_privileged_role(role):
            write_action_log(
                current_username,
                role,
                action,
                "",
                "",
                "denied",
                {"reason": "privileged_role_required"},
            )
            write_audit_log_safe(
                "helpdesk_interface_denied",
                details={"reason": "privileged_role_required_for_toggle", "action": action},
                requester=current_username,
            )
            return jsonify({"ok": False, "error": "Only Senior/SysAdmin users can run this HelpDesk Action."}), 403
        for device in selected_devices:
            device_name = str(device.get("name", "")).strip()
            interfaces = selected_interfaces_by_device.get(device_name, [])
            if action == "set_description":
                desc_map = descriptions_by_device.get(device_name, {})
                if not desc_map:
                    continue
                lines = ["configure terminal"]
                for interface_name, description in desc_map.items():
                    lines.append(f"interface {interface_name}")
                    if description:
                        lines.append(f"description {description}")
                    else:
                        lines.append("no description")
                lines.append("end")
                cmd = "\n".join(lines)
                state, output = run_ssh_command(
                    host=str(device.get("host", "")),
                    port=int(device.get("port", 22)),
                    username=str(creds.get("username", "")),
                    password=str(creds.get("password", "")),
                    command=cmd,
                    timeout=int(creds.get("timeout", 8) or 8),
                    command_mode="config",
                    enable_password=str(creds.get("enable_password", "")),
                )
                save_state = ""
                save_output = ""
                if state == "PASS":
                    save_state, save_output = run_ssh_command(
                        host=str(device.get("host", "")),
                        port=int(device.get("port", 22)),
                        username=str(creds.get("username", "")),
                        password=str(creds.get("password", "")),
                        command="write memory",
                        timeout=int(creds.get("timeout", 8) or 8),
                        command_mode="show",
                        enable_password=str(creds.get("enable_password", "")),
                    )
                    if save_state != "PASS":
                        output = f"{output}\n\n[CONFIG SAVE FAILED]\n{save_output}"
                    else:
                        output = f"{output}\n\n[CONFIG SAVED]\n{save_output}"
            elif action == "set_vlan":
                vlan_map = vlans_by_device.get(device_name, {})
                if not vlan_map:
                    continue
                lines = ["configure terminal"]
                for interface_name, vlan_id in vlan_map.items():
                    lines.append(f"interface {interface_name}")
                    lines.append("switchport mode access")
                    lines.append(f"switchport access vlan {int(vlan_id)}")
                lines.append("end")
                state, output = run_ssh_command(
                    host=str(device.get("host", "")),
                    port=int(device.get("port", 22)),
                    username=str(creds.get("username", "")),
                    password=str(creds.get("password", "")),
                    command="\n".join(lines),
                    timeout=int(creds.get("timeout", 8) or 8),
                    command_mode="config",
                    enable_password=str(creds.get("enable_password", "")),
                )
                if state == "PASS":
                    save_state, save_output = run_ssh_command(
                        host=str(device.get("host", "")),
                        port=int(device.get("port", 22)),
                        username=str(creds.get("username", "")),
                        password=str(creds.get("password", "")),
                        command="write memory",
                        timeout=int(creds.get("timeout", 8) or 8),
                        command_mode="show",
                        enable_password=str(creds.get("enable_password", "")),
                    )
                    if save_state != "PASS":
                        output = f"{output}\n\n[CONFIG SAVE FAILED]\n{save_output}"
                    else:
                        output = f"{output}\n\n[CONFIG SAVED]\n{save_output}"
            else:
                if not interfaces:
                    continue
                if action == "remove_errdisable":
                    state, output = run_errdisable_recovery_sequence(
                        host=str(device.get("host", "")),
                        port=int(device.get("port", 22)),
                        username=str(creds.get("username", "")),
                        password=str(creds.get("password", "")),
                        interfaces=interfaces,
                        timeout=int(creds.get("timeout", 8) or 8),
                        enable_password=str(creds.get("enable_password", "")),
                    )
                else:
                    lines = ["configure terminal"]
                    for interface_name in interfaces:
                        lines.append(f"interface {interface_name}")
                        if action == "shut":
                            lines.append("shutdown")
                        else:
                            lines.append("no shutdown")
                    lines.append("end")
                    state, output = run_ssh_command(
                        host=str(device.get("host", "")),
                        port=int(device.get("port", 22)),
                        username=str(creds.get("username", "")),
                        password=str(creds.get("password", "")),
                        command="\n".join(lines),
                        timeout=int(creds.get("timeout", 8) or 8),
                        command_mode="config",
                        enable_password=str(creds.get("enable_password", "")),
                    )
            action_results.append(
                {
                    "device": device_name,
                    "status": state,
                    "output_preview": str(output or "")[:700],
                }
            )

    interface_tables = [_load_helpdesk_interfaces_for_device(device, creds) for device in selected_devices]
    success_count = sum(1 for item in action_results if str(item.get("status", "")).upper() == "PASS")
    action_name = {
        "show": "helpdesk_interfaces_viewed",
        "remove_errdisable": "helpdesk_errdisable_recovery_executed",
        "set_description": "helpdesk_interface_description_updated",
        "set_vlan": "helpdesk_interface_vlan_updated",
        "shut": "helpdesk_interface_shut_executed",
        "no_shut": "helpdesk_interface_no_shut_executed",
    }.get(action, "helpdesk_interface_action")
    write_audit_log_safe(
        action_name,
        details={
            "action": action,
            "devices": [str(item.get("name", "")) for item in selected_devices],
            "selected_interfaces": selected_interfaces_by_device,
            "description_changes": descriptions_by_device,
            "vlan_changes": vlans_by_device,
            "result_count": len(action_results),
            "result_success_count": success_count,
            "action_results": action_results,
            "interface_counts": [
                {
                    "device": str(item.get("device", "")),
                    "count": len(item.get("interfaces", []) if isinstance(item.get("interfaces", []), list) else []),
                }
                for item in interface_tables
            ],
        },
        requester=current_username,
    )
    if action != "show":
        for result in action_results:
            device_name = str(result.get("device", ""))
            selected_ifaces = selected_interfaces_by_device.get(device_name, [])
            if action == "set_description":
                selected_ifaces = list(descriptions_by_device.get(device_name, {}).keys())
            if action == "set_vlan":
                selected_ifaces = list(vlans_by_device.get(device_name, {}).keys())
            write_action_log(
                current_username,
                role,
                action,
                device_name,
                ",".join(selected_ifaces),
                "success" if str(result.get("status", "")).upper() == "PASS" else "failed",
                {
                    "output_preview": str(result.get("output_preview", "")),
                    "selected_interfaces": selected_ifaces,
                    "description_changes": descriptions_by_device.get(device_name, {}),
                    "vlan_changes": vlans_by_device.get(device_name, {}),
                },
            )

    if action == "show":
        session["helpdesk_last_show_devices"] = selected_device_names
        return jsonify(
            {
                "ok": True,
                "message": "Interface status loaded.",
                "devices": interface_tables,
            }
        )
    return jsonify(
        {
            "ok": True,
            "message": f"Action '{action}' completed on {success_count}/{len(action_results) or 0} device(s).",
            "actions": action_results,
            "devices": interface_tables,
        }
    )


def run_commands() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        write_audit_log_safe(
            "command_run_denied",
            details={"reason": "devices_panel_access_denied"},
            requester=current_username,
        )
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {device["name"]: device for device in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()
    command_mode = str(request.form.get("command_mode", "show")).strip().lower() or "show"
    role = current_user_role()

    if is_restricted_command_user(role) and manual_command:
        write_audit_log_safe(
            "command_run_denied",
            details={"reason": "restricted_manual_command", "role": role, "command": manual_command},
            requester=current_username,
        )
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="Junior/Helpdesk users can run only pre-configured commands.",
        )

    if is_restricted_command_user(role) and not selected_command:
        write_audit_log_safe(
            "command_run_denied",
            details={"reason": "restricted_preconfigured_command_required", "role": role},
            requester=current_username,
        )
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="Junior/Helpdesk users can run only pre-configured command buttons.",
        )

    if is_restricted_command_user(role) and selected_command not in allowed_preconfigured_commands(role):
        write_audit_log_safe(
            "command_run_denied",
            details={"reason": "restricted_command_not_whitelisted", "role": role, "command": selected_command},
            requester=current_username,
        )
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="Junior/Helpdesk users can run only commands from configured command buttons.",
        )

    command = manual_command or selected_command
    if not command:
        write_audit_log_safe(
            "command_run_failed",
            details={"reason": "command_missing"},
            requester=current_username,
        )
        return render_template("output.html", run_history=session.get("run_history", []), error="No command provided.")

    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        write_audit_log_safe(
            "command_run_failed",
            details={"reason": "no_devices_selected_or_allowed", "requested_devices": selected_names},
            requester=current_username,
        )
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
        write_audit_log_safe(
            "command_run_failed",
            details={
                "reason": "device_credentials_missing",
                "command_mode": command_mode,
                "command": command,
                "target_devices": [str(device.get("name", "")).strip() for device in selected_devices],
            },
            requester=current_username,
        )
        return render_template(
            "output.html",
            run_history=session.get("run_history", []),
            error="Set device SSH credentials first from the dashboard user-strip button.",
        )

    results: list[SSHResult] = []

    with ThreadPoolExecutor(max_workers=min(20, max(1, len(selected_devices)))) as executor:
        futures = [executor.submit(execute_for_device, device, creds, command, command_mode) for device in selected_devices]
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
    success_count = sum(1 for result in results if str(result.status).strip().lower() == "success")
    write_audit_log_safe(
        "command_run_executed",
        details={
            "command_mode": command_mode,
            "command": command,
            "target_devices": [str(device.get("name", "")).strip() for device in selected_devices],
            "success_count": success_count,
            "failure_count": len(results) - success_count,
            "results": [
                {
                    "device": result.device,
                    "host": result.host,
                    "status": result.status,
                    "output_preview": str(result.output or "")[:600],
                }
                for result in results
            ],
        },
        requester=current_username,
    )

    return render_template("output.html", run_history=session.get("run_history", []), error="")


def run_commands_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        write_audit_log_safe(
            "command_run_api_denied",
            details={"reason": "devices_panel_access_denied"},
            requester=current_username,
        )
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {device["name"]: device for device in devices}
    selected_names = request.form.getlist("selected_devices")
    manual_command = request.form.get("manual_command", "").strip()
    selected_command = request.form.get("selected_command", "").strip()
    command_mode = str(request.form.get("command_mode", "show")).strip().lower() or "show"
    role = current_user_role()

    if is_restricted_command_user(role) and manual_command:
        write_audit_log_safe(
            "command_run_api_denied",
            details={"reason": "restricted_manual_command", "role": role, "command": manual_command},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Junior/Helpdesk users can run only pre-configured commands."}), 403

    if is_restricted_command_user(role) and not selected_command:
        write_audit_log_safe(
            "command_run_api_denied",
            details={"reason": "restricted_preconfigured_command_required", "role": role},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Junior/Helpdesk users can run only pre-configured command buttons."}), 403

    if is_restricted_command_user(role) and selected_command not in allowed_preconfigured_commands(role):
        write_audit_log_safe(
            "command_run_api_denied",
            details={"reason": "restricted_command_not_whitelisted", "role": role, "command": selected_command},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Junior/Helpdesk users can run only commands from configured command buttons."}), 403

    command = manual_command or selected_command
    if not command:
        write_audit_log_safe(
            "command_run_api_failed",
            details={"reason": "command_missing"},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "No command provided."}), 400

    selected_devices = [by_name[name] for name in selected_names if name in by_name]
    if not selected_devices:
        write_audit_log_safe(
            "command_run_api_failed",
            details={"reason": "no_devices_selected_or_allowed", "requested_devices": selected_names},
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "No devices selected."}), 400

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        write_audit_log_safe(
            "command_run_api_failed",
            details={
                "reason": "device_credentials_missing",
                "command_mode": command_mode,
                "command": command,
                "target_devices": [str(device.get("name", "")).strip() for device in selected_devices],
            },
            requester=current_username,
        )
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    results: list[SSHResult] = []
    with ThreadPoolExecutor(max_workers=min(20, max(1, len(selected_devices)))) as executor:
        futures = [executor.submit(execute_for_device, device, creds, command, command_mode) for device in selected_devices]
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
    success_count = sum(1 for result in results if str(result.status).strip().lower() == "success")
    write_audit_log_safe(
        "command_run_api_executed",
        details={
            "command_mode": command_mode,
            "command": command,
            "target_devices": [str(device.get("name", "")).strip() for device in selected_devices],
            "success_count": success_count,
            "failure_count": len(results) - success_count,
            "results": [
                {
                    "device": result.device,
                    "host": result.host,
                    "status": result.status,
                    "output_preview": str(result.output or "")[:600],
                }
                for result in results
            ],
        },
        requester=current_username,
    )

    return jsonify({"ok": True, "timestamp": run_entry["timestamp"], "command": command, "results": run_entry["results"]})


def open_ssh_sessions_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401
    if is_restricted_command_user(current_user_role()):
        return jsonify({"ok": False, "error": "Junior/Helpdesk users are not allowed to open interactive SSH sessions."}), 403

    payload = request.get_json(silent=True) or {}
    selected_names = payload.get("selected_devices") or []
    if not isinstance(selected_names, list):
        selected_names = []
    selected_names = [str(name).strip() for name in selected_names if str(name).strip()]
    if not selected_names:
        return jsonify({"ok": False, "error": "No devices selected."}), 400

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    by_name = {str(device.get("name", "")).strip(): device for device in devices}

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    rid = runtime_session_id()
    opened: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for name in selected_names:
        device = by_name.get(name)
        if device is None:
            failed.append({"device": name, "error": "Not found or not allowed."})
            continue
        ok, message = open_runtime_device_session(rid, device, creds)
        if ok:
            opened.append({"device": name, "message": message})
        else:
            failed.append({"device": name, "error": message})

    return jsonify(
        {
            "ok": bool(opened),
            "opened": opened,
            "failed": failed,
            "error": "Could not open SSH session for selected devices." if not opened else "",
        }
    )


def run_session_command_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Please login first."}), 401
    if is_restricted_command_user(current_user_role()):
        return jsonify({"ok": False, "error": "Junior/Helpdesk users can run only pre-configured command buttons."}), 403

    device_name = request.form.get("device_name", "").strip()
    command = request.form.get("command", "").strip()

    if not device_name:
        return jsonify({"ok": False, "error": "Select a device session first."}), 400

    if not command:
        return jsonify({"ok": False, "error": "Command is required."}), 400

    all_devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    if not user_has_panel_access(current_username, auth_mode, "devices"):
        if user_has_panel_access(current_username, auth_mode, "ip_addressing"):
            session["dashboard_error"] = "You do not have access to the Devices panel."
            return redirect(url_for("ip_addressing_dashboard"))
        session.clear()
        session["login_error"] = "Your account has no panel access configured."
        return redirect(url_for("login"))
    devices = filter_devices_for_user(all_devices, current_username, auth_mode)
    target_device = next((device for device in devices if str(device.get("name", "")).strip() == device_name), None)

    if target_device is None:
        return jsonify({"ok": False, "error": "Device session is not available for your account."}), 404

    dashboard_creds = session.get("creds", {})
    device_creds = session.get("device_creds", {})
    creds = {
        "username": str(device_creds.get("username", "")).strip() or str(dashboard_creds.get("username", "")).strip(),
        "password": str(device_creds.get("password", "")) or str(dashboard_creds.get("password", "")),
        "timeout": int(dashboard_creds.get("timeout", 8) or 8),
        "enable_password": str(device_creds.get("enable_password", "")),
    }

    if not creds["username"] or not creds["password"]:
        return jsonify({"ok": False, "error": "Set device SSH credentials first from the dashboard user-strip button."}), 400

    rid = runtime_session_id()
    status, output = run_runtime_device_command(rid, target_device, creds, command)
    result = SSHResult(device=target_device["name"], host=target_device["host"], status=status, output=output)
    run_entry = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "command": command,
        "results": [asdict(result)],
    }
    run_history = session.get("run_history", [])
    run_history.append(run_entry)
    session["run_history"] = run_history[-50:]

    return jsonify({"ok": True, "timestamp": run_entry["timestamp"], "command": command, "results": run_entry["results"]})
