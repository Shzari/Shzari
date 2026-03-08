from __future__ import annotations
# ruff: noqa: F821

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "super_admin_exists" not in globals():
    from app.services.auth_service import super_admin_exists
if "load_users" not in globals():
    from app.services.auth_service import load_users
if "load_ldap_settings" not in globals():
    from app.services.auth_service import load_ldap_settings
if "load_session_settings" not in globals():
    from app.domains.settings.session_acl_impl import load_session_settings
if "load_ise_settings" not in globals() or "save_ise_settings" not in globals():
    import app.services.legacy_core_helpers as _core_helpers

    for _name, _value in _core_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "load_sql_server_settings" not in globals() or "save_sql_server_settings" not in globals():
    import app.services.legacy_audit_helpers as _audit_helpers

    for _name, _value in _audit_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "load_ntp_settings" not in globals() or "save_ntp_settings" not in globals():
    import app.services.legacy_file_settings_helpers as _file_settings_helpers

    for _name, _value in _file_settings_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "load_monitoring_settings" not in globals() or "save_monitoring_settings" not in globals():
    import app.services.legacy_monitoring_config_helpers as _monitoring_config_helpers

    for _name, _value in _monitoring_config_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "test_ntp_connectivity" not in globals() or "sync_ntp_time" not in globals():
    import app.services.legacy_network_checks_helpers as _network_checks_helpers

    for _name, _value in _network_checks_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "upsert_user" not in globals():
    import app.services.legacy_pending_helpers as _pending_helpers

    for _name, _value in _pending_helpers.__dict__.items():
        if _name.startswith("__"):
            continue
        globals().setdefault(_name, _value)
if "write_audit_log_safe" not in globals():
    from app.services.logs_service import write_audit_log_safe
if "_normalize_web_acl_entries" not in globals() or "_is_client_ip_allowed_by_acl" not in globals() or "_schedule_self_restart" not in globals():
    from app.domains.settings.session_acl_impl import _is_client_ip_allowed_by_acl, _normalize_web_acl_entries, _schedule_self_restart

def ise_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    info = session.pop("settings_info", "")
    error = session.pop("settings_error", "")
    settings = load_ise_settings()
    ldap_settings = load_ldap_settings()
    sql_settings = load_sql_server_settings()

    if request.method == "POST":
        actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
        data = {
            "primary_server": request.form.get("primary_server", "").strip(),
            "primary_port": request.form.get("primary_port", "1812").strip(),
            "primary_shared_secret": request.form.get("primary_shared_secret", ""),
            "secondary_server": request.form.get("secondary_server", "").strip(),
            "secondary_port": request.form.get("secondary_port", "1812").strip(),
            "secondary_shared_secret": request.form.get("secondary_shared_secret", ""),
            "timeout": request.form.get("timeout", "5").strip(),
            "nas_ip": request.form.get("nas_ip", "127.0.0.1").strip(),
        }
        try:
            save_ise_settings(data)
            settings = load_ise_settings()
            write_audit_log_safe(
                "ise_settings_updated",
                details={
                    "primary_server": data.get("primary_server", ""),
                    "primary_port": data.get("primary_port", ""),
                    "secondary_server": data.get("secondary_server", ""),
                    "secondary_port": data.get("secondary_port", ""),
                    "timeout": data.get("timeout", ""),
                    "nas_ip": data.get("nas_ip", ""),
                },
                requester=actor,
            )
            info = "ISE settings updated."
        except Exception as exc:
            write_audit_log_safe(
                "ise_settings_update_failed",
                details={"error": str(exc)},
                requester=actor,
            )
            error = f"Failed to save settings: {exc}"

    devices = load_devices()
    return render_template(
        "ise_settings.html",
        ise=settings,
        ldap=ldap_settings,
        sql_server=sql_settings,
        external_logging=load_external_logging_settings(),
        monitoring=load_monitoring_settings(),
        info=info,
        error=error,
        users=load_users(),
        available_categories=all_categories(devices),
        selected_modal=request.args.get("modal", ""),
        ntp=load_ntp_settings(),
        session_settings=load_session_settings(),
    )


def sql_server_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
    enabled = request.form.get("enabled") == "on"
    driver = request.form.get("driver", "ODBC Driver 18 for SQL Server").strip()
    server = request.form.get("server", "").strip()
    database_name = request.form.get("database_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    encrypt = request.form.get("encrypt") == "on"
    trust_server_certificate = request.form.get("trust_server_certificate") == "on"
    table_name = normalize_sql_table_name(request.form.get("table_name", "audit_logs"))

    try:
        port = int(request.form.get("port", "1433").strip() or 1433)
        timeout = int(request.form.get("timeout", "5").strip() or 5)
        if port < 1 or port > 65535:
            raise ValueError
        if timeout < 1 or timeout > 30:
            raise ValueError
    except ValueError:
        write_audit_log_safe(
            "sql_settings_update_failed",
            details={"reason": "invalid_port_or_timeout"},
            requester=actor,
        )
        session["settings_error"] = "SQL Server port must be 1-65535 and timeout must be 1-30."
        return redirect(url_for("ise_settings_page", modal="sql"))

    data = {
        "enabled": enabled,
        "driver": driver or "ODBC Driver 18 for SQL Server",
        "server": server,
        "port": port,
        "database_name": database_name,
        "username": username,
        "password": password,
        "encrypt": encrypt,
        "trust_server_certificate": trust_server_certificate,
        "timeout": timeout,
        "table_name": table_name,
    }

    if enabled and (not server or not database_name or not username or not password):
        write_audit_log_safe(
            "sql_settings_update_failed",
            details={"reason": "required_fields_missing_when_enabled"},
            requester=actor,
        )
        session["settings_error"] = "When SQL logging is enabled, server/database/username/password are required."
        return redirect(url_for("ise_settings_page", modal="sql"))

    action = request.form.get("action", "save").strip().lower()
    try:
        save_sql_server_settings(data)
    except Exception as exc:
        write_audit_log_safe(
            "sql_settings_update_failed",
            details={"reason": "save_failed", "error": str(exc)},
            requester=actor,
        )
        session["settings_error"] = f"Failed to save SQL Server settings: {exc}"
        return redirect(url_for("ise_settings_page", modal="sql"))

    if action == "test":
        ok, message = test_sql_server_logging_connection(data)
        write_audit_log_safe(
            "sql_settings_tested",
            details={"ok": bool(ok), "message": str(message), "server": server, "database": database_name, "port": port},
            requester=actor,
        )
        if ok:
            session["settings_info"] = message
        else:
            session["settings_error"] = message
        return redirect(url_for("ise_settings_page", modal="sql"))

    write_audit_log_safe(
        "sql_settings_updated",
        details={
            "enabled": enabled,
            "server": server,
            "database": database_name,
            "username": username,
            "port": port,
            "timeout": timeout,
            "encrypt": encrypt,
            "trust_server_certificate": trust_server_certificate,
            "table_name": table_name,
        },
        requester=actor,
    )
    session["settings_info"] = "SQL Server logging settings updated."
    return redirect(url_for("ise_settings_page", modal="sql"))


def sql_server_test_page() -> Any:
    if not super_admin_exists():
        return jsonify({"ok": False, "message": "Super admin is not configured."}), 403
    if not session.get("super_admin_verified"):
        return jsonify({"ok": False, "message": "Super admin verification is required."}), 403

    server = request.form.get("server", "").strip()
    database_name = request.form.get("database_name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    table_name = normalize_sql_table_name(request.form.get("table_name", "audit_logs"))

    try:
        port = int(request.form.get("port", "1433").strip() or 1433)
        timeout = int(request.form.get("timeout", "5").strip() or 5)
        if port < 1 or port > 65535:
            raise ValueError
        if timeout < 1 or timeout > 30:
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "message": "SQL Server port must be 1-65535 and timeout must be 1-30."}), 400

    if not server or not database_name or not username or not password:
        return jsonify({"ok": False, "message": "Server, database, username, and password are required for testing."}), 400

    data = {
        "enabled": request.form.get("enabled") == "on",
        "driver": request.form.get("driver", "ODBC Driver 18 for SQL Server").strip() or "ODBC Driver 18 for SQL Server",
        "server": server,
        "port": port,
        "database_name": database_name,
        "username": username,
        "password": password,
        "encrypt": request.form.get("encrypt") == "on",
        "trust_server_certificate": request.form.get("trust_server_certificate") == "on",
        "timeout": timeout,
        "table_name": table_name,
    }
    ok, message = test_sql_server_logging_connection(data)
    actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
    write_audit_log_safe(
        "sql_settings_tested",
        details={"ok": bool(ok), "message": str(message), "server": server, "database": database_name, "port": port},
        requester=actor,
    )
    return jsonify({"ok": bool(ok), "message": str(message)})


def ldap_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
    server = request.form.get("server", "").strip()
    base_dn = request.form.get("base_dn", "").strip()
    user_dn_template = request.form.get("user_dn_template", "").strip()
    user_search_filter = request.form.get("user_search_filter", "(sAMAccountName={username})").strip()
    bind_dn = request.form.get("bind_dn", "").strip()
    bind_password = request.form.get("bind_password", "")
    use_ssl = request.form.get("use_ssl") == "on"
    start_tls = request.form.get("start_tls") == "on"

    if use_ssl and start_tls:
        write_audit_log_safe(
            "ldap_settings_update_failed",
            details={"reason": "ssl_and_starttls_both_enabled"},
            requester=actor,
        )
        session["settings_error"] = "Enable either SSL or StartTLS, not both."
        return redirect(url_for("ise_settings_page", modal="ldap"))

    try:
        port = int(request.form.get("port", "389").strip() or 389)
        timeout = int(request.form.get("timeout", "5").strip() or 5)
        if port < 1 or port > 65535:
            raise ValueError
        if timeout < 1 or timeout > 30:
            raise ValueError
    except ValueError:
        write_audit_log_safe(
            "ldap_settings_update_failed",
            details={"reason": "invalid_port_or_timeout"},
            requester=actor,
        )
        session["settings_error"] = "LDAP port must be 1-65535 and timeout must be 1-30."
        return redirect(url_for("ise_settings_page", modal="ldap"))

    if server and not user_dn_template and not base_dn:
        write_audit_log_safe(
            "ldap_settings_update_failed",
            details={"reason": "lookup_config_missing"},
            requester=actor,
        )
        session["settings_error"] = "Set either User DN Template or Base DN for LDAP user lookup."
        return redirect(url_for("ise_settings_page", modal="ldap"))
    if user_dn_template and "{username}" not in user_dn_template:
        write_audit_log_safe(
            "ldap_settings_update_failed",
            details={"reason": "user_dn_template_missing_username_placeholder"},
            requester=actor,
        )
        session["settings_error"] = "LDAP user DN template must include {username}."
        return redirect(url_for("ise_settings_page", modal="ldap"))

    try:
        save_ldap_settings(
            {
                "server": server,
                "port": port,
                "use_ssl": use_ssl,
                "start_tls": start_tls,
                "timeout": timeout,
                "base_dn": base_dn,
                "user_dn_template": user_dn_template,
                "user_search_filter": user_search_filter,
                "bind_dn": bind_dn,
                "bind_password": bind_password,
            }
        )
        write_audit_log_safe(
            "ldap_settings_updated",
            details={
                "server": server,
                "port": port,
                "use_ssl": use_ssl,
                "start_tls": start_tls,
                "timeout": timeout,
                "base_dn": base_dn,
                "user_dn_template": user_dn_template,
                "bind_dn": bind_dn,
            },
            requester=actor,
        )
        session["settings_info"] = "LDAP settings updated."
    except Exception as exc:
        write_audit_log_safe(
            "ldap_settings_update_failed",
            details={"reason": "save_failed", "error": str(exc)},
            requester=actor,
        )
        session["settings_error"] = f"Failed to save LDAP settings: {exc}"

    return redirect(url_for("ise_settings_page", modal="ldap"))


def ntp_test_page() -> Any:
    if not super_admin_exists():
        return jsonify({"ok": False, "message": "Super admin setup is required."}), 403
    if not session.get("super_admin_verified"):
        return jsonify({"ok": False, "message": "Super admin verification is required."}), 403

    server = request.form.get("ntp_server", "").strip()
    port_raw = request.form.get("ntp_port", "123").strip()
    timeout_raw = request.form.get("ntp_timeout", "3").strip()

    try:
        port = int(port_raw or 123)
        timeout = int(timeout_raw or 3)
    except ValueError:
        return jsonify({"ok": False, "message": "NTP port/timeout must be numbers."}), 400

    ok, message = test_ntp_connectivity(server, port, timeout)
    return jsonify({"ok": ok, "message": message})


def ntp_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    settings = load_ntp_settings()
    mode = request.form.get("ntp_mode", "ntp").strip().lower()
    if mode not in {"ntp", "manual"}:
        mode = "ntp"

    server = request.form.get("ntp_server", "").strip()
    port_raw = request.form.get("ntp_port", "123").strip()
    timeout_raw = request.form.get("ntp_timeout", "3").strip()
    manual_time_raw = request.form.get("manual_time", "").strip()

    try:
        port = int(port_raw or 123)
        timeout = int(timeout_raw or 3)
    except ValueError:
        session["settings_error"] = "NTP port/timeout must be numbers."
        return redirect(url_for("ise_settings_page", modal="ntp"))

    settings["mode"] = mode
    settings["server"] = server
    settings["port"] = port
    settings["sync_timeout"] = timeout
    settings["manual_time"] = manual_time_raw

    action = request.form.get("action", "save").strip()
    if action == "sync":
        ok, message, ntp_time = sync_ntp_time(server, port, timeout)
        if ok:
            settings["mode"] = "ntp"
            settings["last_sync"] = ntp_time
            settings["last_status"] = message
            session["settings_info"] = message
        else:
            settings["last_status"] = message
            session["settings_error"] = message
    elif action == "set_manual":
        if not manual_time_raw:
            session["settings_error"] = "Manual time is required."
        else:
            try:
                parsed = datetime.fromisoformat(manual_time_raw)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                settings["mode"] = "manual"
                settings["last_sync"] = parsed.isoformat()
                settings["last_status"] = "Manual time saved by super admin."
                session["settings_info"] = "Manual time saved."
            except ValueError:
                session["settings_error"] = "Invalid manual time format."
    else:
        session["settings_info"] = "NTP settings saved."

    save_ntp_settings(settings)
    return redirect(url_for("ise_settings_page", modal="ntp"))


def session_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    current_settings = load_session_settings()
    timeout_raw = request.form.get("idle_timeout_minutes", "15").strip()
    http_port_raw = request.form.get("http_port", "8080").strip()
    https_port_raw = request.form.get("https_port", "8443").strip()
    web_acl_enabled = request.form.get("web_acl_enabled") == "on"
    web_acl_raw = request.form.get("web_acl_entries", "")
    http_enabled = request.form.get("http_enabled") == "on"
    https_enabled = request.form.get("https_enabled") == "on"
    if not http_enabled and not https_enabled:
        session["settings_error"] = "Select at least one active web mode (HTTP or HTTPS)."
        return redirect(url_for("ise_settings_page", modal="session"))
    try:
        timeout_minutes = int(timeout_raw or 15)
        if timeout_minutes < 1:
            raise ValueError
    except ValueError:
        session["settings_error"] = "Session timeout must be a positive number of minutes."
        return redirect(url_for("ise_settings_page", modal="session"))

    current_http_port = int(current_settings.get("http_port", 8080) or 8080)
    current_https_port = int(current_settings.get("https_port", 8443) or 8443)

    if http_enabled:
        try:
            http_port = int(http_port_raw or current_http_port)
            if http_port < 1 or http_port > 65535:
                raise ValueError
        except ValueError:
            session["settings_error"] = "HTTP port must be between 1 and 65535."
            return redirect(url_for("ise_settings_page", modal="session"))
    else:
        http_port = current_http_port

    if https_enabled:
        try:
            https_port = int(https_port_raw or current_https_port)
            if https_port < 1 or https_port > 65535:
                raise ValueError
        except ValueError:
            session["settings_error"] = "HTTPS port must be between 1 and 65535."
            return redirect(url_for("ise_settings_page", modal="session"))
    else:
        https_port = current_https_port

    acl_entries, acl_invalid = _normalize_web_acl_entries(web_acl_raw)
    if web_acl_enabled:
        if acl_invalid:
            session["settings_error"] = f"Invalid ACL entry: {acl_invalid[0]}. Use IP or CIDR (example: 192.168.1.10 or 192.168.1.0/24)."
            return redirect(url_for("ise_settings_page", modal="session"))
        if not acl_entries:
            session["settings_error"] = "Web ACL is enabled but no allowed IP/CIDR was provided."
            return redirect(url_for("ise_settings_page", modal="session"))
        current_ip = str(request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "")
        if not _is_client_ip_allowed_by_acl(current_ip, acl_entries):
            session["settings_error"] = f"Your current IP {current_ip or 'unknown'} is not in ACL list. Add it before enabling ACL."
            return redirect(url_for("ise_settings_page", modal="session"))

    save_session_settings(
        {
            "idle_timeout_minutes": timeout_minutes,
            "http_enabled": http_enabled,
            "https_enabled": https_enabled,
            "http_port": http_port,
            "https_port": https_port,
            "web_acl_enabled": web_acl_enabled,
            "web_acl_entries": acl_entries,
        }
    )
    active_modes: list[str] = []
    if http_enabled:
        active_modes.append(f"HTTP:{http_port}")
    if https_enabled:
        active_modes.append(f"HTTPS:{https_port}")
    modes_text = ", ".join(active_modes)
    listener_changed = (
        bool(current_settings.get("http_enabled", True)) != http_enabled
        or bool(current_settings.get("https_enabled", False)) != https_enabled
        or int(current_settings.get("http_port", 8080) or 8080) != int(http_port)
        or int(current_settings.get("https_port", 8443) or 8443) != int(https_port)
    )
    if listener_changed and _schedule_self_restart(1.0):
        session["settings_info"] = f"Settings updated. Applying web listeners automatically ({modes_text}). Reconnect in a few seconds."
    else:
        session["settings_info"] = f"Settings updated. Active web listeners: {modes_text}."
    return redirect(url_for("ise_settings_page", modal="session"))


def external_logging_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
    enabled = request.form.get("enabled") == "on"
    server = request.form.get("server", "").strip()
    protocol = request.form.get("protocol", "udp").strip().lower() or "udp"
    source_name = request.form.get("source_name", "ndmc-app").strip() or "ndmc-app"
    notes = request.form.get("notes", "").strip()

    try:
        port = int(request.form.get("port", "514").strip() or 514)
        if port < 1 or port > 65535:
            raise ValueError
    except ValueError:
        session["settings_error"] = "External logging port must be between 1 and 65535."
        return redirect(url_for("ise_settings_page", modal="external_logging"))

    if protocol not in {"udp", "tcp", "tls"}:
        session["settings_error"] = "Protocol must be UDP, TCP, or TLS."
        return redirect(url_for("ise_settings_page", modal="external_logging"))

    if enabled and not server:
        session["settings_error"] = "Server is required when external logging is enabled."
        return redirect(url_for("ise_settings_page", modal="external_logging"))

    save_external_logging_settings(
        {
            "enabled": enabled,
            "server": server,
            "port": port,
            "protocol": protocol,
            "source_name": source_name,
            "notes": notes,
        }
    )
    write_audit_log_safe(
        "external_logging_settings_updated",
        details={
            "enabled": enabled,
            "server": server,
            "port": port,
            "protocol": protocol,
            "source_name": source_name,
            "notes": notes,
        },
        requester=actor,
    )
    session["settings_info"] = "External logging settings updated."
    return redirect(url_for("ise_settings_page", modal="external_logging"))


def monitoring_settings_page() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    actor = str(session.get("creds", {}).get("username", "")).strip() or "super_admin"
    enabled = request.form.get("enabled") == "on"
    collection_mode = str(request.form.get("collection_mode", "telemetry")).strip().lower() or "telemetry"
    collector_host = str(request.form.get("collector_host", "")).strip()
    transport = str(request.form.get("transport", "grpc")).strip().lower() or "grpc"
    username = str(request.form.get("username", "")).strip()
    password = str(request.form.get("password", ""))
    token = str(request.form.get("token", "")).strip()
    metrics = str(request.form.get("metrics", "cpu,memory,interfaces,sla")).strip() or "cpu,memory,interfaces,sla"
    notes = str(request.form.get("notes", "")).strip()

    try:
        collector_port = int(str(request.form.get("collector_port", "57000")).strip() or 57000)
        interval_seconds = int(str(request.form.get("interval_seconds", "30")).strip() or 30)
        if collector_port < 1 or collector_port > 65535:
            raise ValueError
        if interval_seconds < 5 or interval_seconds > 3600:
            raise ValueError
    except ValueError:
        session["settings_error"] = "Collector port must be 1-65535 and interval must be 5-3600 seconds."
        return redirect(url_for("ise_settings_page", modal="monitoring"))

    if collection_mode not in {"telemetry", "snmp", "snmp_v2", "snmp_v3", "ssh", "api", "winrm"}:
        session["settings_error"] = "Collection mode must be telemetry, snmp, snmp_v2, snmp_v3, ssh, api, or winrm."
        return redirect(url_for("ise_settings_page", modal="monitoring"))
    if transport not in {"grpc", "tcp", "udp", "http"}:
        session["settings_error"] = "Transport must be grpc, tcp, udp, or http."
        return redirect(url_for("ise_settings_page", modal="monitoring"))
    if enabled and collection_mode in {"telemetry", "api"} and not collector_host:
        session["settings_error"] = "Collector host is required for telemetry/api monitoring mode."
        return redirect(url_for("ise_settings_page", modal="monitoring"))

    current_settings = load_monitoring_settings()
    save_monitoring_settings(
        {
            "enabled": enabled,
            "collection_mode": collection_mode,
            "collector_host": collector_host,
            "collector_port": collector_port,
            "transport": transport,
            "username": username,
            "password": password,
            "token": token,
            "interval_seconds": interval_seconds,
            "metrics": metrics,
            "monitored_devices": current_settings.get("monitored_devices", []),
            "notes": notes,
        }
    )
    write_audit_log_safe(
        "monitoring_settings_updated",
        details={
            "enabled": enabled,
            "collection_mode": collection_mode,
            "collector_host": collector_host,
            "collector_port": collector_port,
            "transport": transport,
            "username": username,
            "interval_seconds": interval_seconds,
            "metrics": metrics,
            "notes": notes,
        },
        requester=actor,
    )
    session["settings_info"] = "Monitoring settings updated."
    return redirect(url_for("ise_settings_page", modal="monitoring"))


def manage_users() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if not session.get("super_admin_verified"):
        return redirect(url_for("verify_super_admin_route"))

    action = request.form.get("action", "").strip()
    users = load_users()

    if action == "create":
        username = request.form.get("new_username", "").strip()
        create_role = normalize_role(request.form.get("create_role", "junior"))
        create_auth_source = normalize_auth_source(request.form.get("create_auth_source", "ldap"))
        if not username:
            session["settings_error"] = "Username is required to create user."
        elif load_super_admin().get("username", "").strip().lower() == username.lower():
            session["settings_error"] = "This username is reserved for super admin."
        else:
            ok, message = upsert_user(username, create_role, create_auth_source)
            if ok:
                session["settings_info"] = f"{message} Role set to '{create_role}'. Auth source is locked after creation."
            else:
                session["settings_error"] = message

    elif action == "delete":
        username = request.form.get("selected_username", "").strip()
        before = len(users)
        users = [u for u in users if str(u.get("username", "")).strip().lower() != username.lower()]
        if len(users) == before:
            session["settings_error"] = "User not found."
        else:
            save_users(users)
            session["settings_info"] = f"User '{username}' deleted."

    elif action == "reset_password":
        username = request.form.get("selected_username", "").strip()
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        elif normalize_auth_source(user.get("auth_source", "ldap")) != "local":
            session["settings_error"] = "Password reset is only available for Local-auth users."
        else:
            user["salt"] = ""
            user["password_hash"] = ""
            user["must_change_password"] = True
            save_users(users)
            session["settings_info"] = f"Password reset for '{username}'. Use only for Local (testing) login."

    elif action == "force_change":
        username = request.form.get("selected_username", "").strip()
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        elif normalize_auth_source(user.get("auth_source", "ldap")) != "local":
            session["settings_error"] = "Force-change is only available for Local-auth users."
        else:
            user["must_change_password"] = True
            save_users(users)
            session["settings_info"] = f"User '{username}' will be forced to change password at next Local (testing) login."

    elif action == "set_role":
        username = request.form.get("selected_username", "").strip()
        role_value = normalize_role(request.form.get("role_value", "junior"))
        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["role"] = role_value
            if role_value == "manager":
                manager_panel_permissions = {key: "read" for key in default_panel_permissions().keys()}
                manager_menu_permissions = {key: "read" for key in default_menu_permissions().keys()}
                user["allowed_categories"] = None
                user["category_panel_access"] = {
                    "panel_permissions": manager_panel_permissions,
                    "menu_permissions": manager_menu_permissions,
                    "menu_access": normalize_menu_access(manager_menu_permissions),
                }
                user["account_privileges"] = [key for key in manager_panel_permissions.keys()]
                user["admin_permissions"] = []
            save_users(users)
            session["settings_info"] = f"Updated role for '{username}' to '{role_value}'."

    elif action == "set_user_rights":
        username = request.form.get("selected_username", "").strip()
        selected_categories: list[str] | None = None
        panel_defaults = default_panel_permissions()
        menu_defaults = default_menu_permissions()
        binary_panel_keys = {"net_devices"}
        binary_menu_keys = {"nd_all_devices", "nd_categories"}

        def _binary(level: Any) -> str:
            return "both" if normalize_access_level(level, "none") in {"read", "write", "both"} else "none"

        panel_permissions_input: dict[str, str] = {}
        has_panel_permission_inputs = False
        for key in panel_defaults.keys():
            field_name = f"panel_permission__{key}"
            if field_name in request.form:
                panel_permissions_input[key] = request.form.get(field_name, panel_defaults[key])
                has_panel_permission_inputs = True
        if has_panel_permission_inputs:
            panel_permissions = normalize_panel_permissions(panel_permissions_input)
        else:
            # Backward compatibility with old checkbox model.
            selected_account_privileges = [p.strip() for p in request.form.getlist("account_privileges") if p.strip()]
            panel_permissions = normalize_panel_permissions(selected_account_privileges)
        for key in binary_panel_keys:
            if key in panel_permissions:
                panel_permissions[key] = _binary(panel_permissions.get(key, "none"))

        menu_permissions_input: dict[str, str] = {}
        has_menu_permission_inputs = False
        for key in menu_defaults.keys():
            field_name = f"menu_permission__{key}"
            if field_name in request.form:
                menu_permissions_input[key] = request.form.get(field_name, menu_defaults[key])
                has_menu_permission_inputs = True
        if has_menu_permission_inputs:
            menu_permissions = normalize_menu_permissions(menu_permissions_input)
        else:
            selected_menu_access = [m.strip() for m in request.form.getlist("menu_access") if m.strip()]
            menu_permissions = normalize_menu_permissions({key: (key in selected_menu_access) for key in menu_defaults.keys()})
        for key in binary_menu_keys:
            if key in menu_permissions:
                menu_permissions[key] = _binary(menu_permissions.get(key, "none"))

        if panel_permissions.get("ip_addressing", "none") not in {"read", "write", "both"}:
            menu_permissions["ip_branches"] = "none"
            menu_permissions["ip_hq"] = "none"
        if panel_permissions.get("network_addressing", "none") not in {"read", "write", "both"}:
            for key in list(menu_permissions.keys()):
                if str(key).startswith("na_"):
                    menu_permissions[key] = "none"
        if panel_permissions.get("net_devices", "none") not in {"read", "write", "both"}:
            for key in list(menu_permissions.keys()):
                if str(key).startswith("nd_"):
                    menu_permissions[key] = "none"
            selected_categories = []

        # Net Devices category-level rights (tree rows in form).
        category_permissions: dict[str, str] = {}
        category_prefix = "device_category_permission__"
        category_key_prefix = "device_category_key__"
        for field_name in request.form.keys():
            if not str(field_name).startswith(category_prefix):
                continue
            category_key = str(field_name)[len(category_prefix):]
            category_name = str(request.form.get(f"{category_key_prefix}{category_key}", "")).strip()
            if not category_name:
                continue
            category_permissions[category_name] = _binary(request.form.get(field_name))
        if category_permissions:
            selected_categories = sorted([name for name, level in category_permissions.items() if level in {"read", "write", "both"}])
            nd_categories_access = menu_permissions.get("nd_categories", "none") in {"read", "write", "both"}
            nd_all_access = menu_permissions.get("nd_all_devices", "none") in {"read", "write", "both"}
            if not nd_categories_access:
                selected_categories = None if nd_all_access else []
            elif not selected_categories and nd_all_access:
                selected_categories = None

        normalized_privileges = [key for key, value in panel_permissions.items() if str(value).strip().lower() in {"read", "write", "both"}]
        menu_access_payload = normalize_menu_access(menu_permissions)

        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            role_value = normalize_role(str(user.get("role", "junior")))
            if role_value == "manager":
                panel_permissions = {key: "read" for key in panel_defaults.keys()}
                menu_permissions = {key: "read" for key in menu_defaults.keys()}
                normalized_privileges = [key for key in panel_permissions.keys()]
                menu_access_payload = normalize_menu_access(menu_permissions)
                selected_categories = None
            user["allowed_categories"] = selected_categories
            user["category_panel_access"] = {
                "panel_permissions": panel_permissions,
                "menu_permissions": menu_permissions,
                "menu_access": menu_access_payload,
                "device_category_permissions": category_permissions,
            }
            user["account_privileges"] = normalized_privileges
            user["admin_permissions"] = []
            save_users(users)
            session["settings_info"] = f"Updated user rights for '{username}'."

    return redirect(url_for("ise_settings_page", modal="users"))
