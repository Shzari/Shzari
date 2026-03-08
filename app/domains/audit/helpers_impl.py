from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "db_conn" not in globals():
    from app.services.db_service import db_conn


def default_sql_server_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "driver": "ODBC Driver 18 for SQL Server",
        "server": "",
        "port": 1433,
        "database_name": "",
        "username": "",
        "password": "",
        "encrypt": True,
        "trust_server_certificate": True,
        "timeout": 5,
        "table_name": "audit_logs",
    }


def normalize_sql_table_name(value: str) -> str:
    candidate = str(value or "").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", candidate):
        return candidate
    return "audit_logs"


def load_sql_server_settings() -> dict[str, Any]:
    defaults = default_sql_server_settings()
    with db_conn() as conn:
        row = conn.execute("""
            SELECT enabled, driver, server, port, database_name, username, password_enc,
                   encrypt, trust_server_certificate, timeout, table_name
            FROM sql_server_settings WHERE id = 1
            """).fetchone()

    if not row:
        return defaults

    defaults.update(
        {
            "enabled": bool(row["enabled"]),
            "driver": str(row["driver"] or "").strip() or "ODBC Driver 18 for SQL Server",
            "server": str(row["server"] or "").strip(),
            "port": int(row["port"] or 1433),
            "database_name": str(row["database_name"] or "").strip(),
            "username": str(row["username"] or "").strip(),
            "password": decrypt_secret(str(row["password_enc"] or "")),
            "encrypt": bool(row["encrypt"]),
            "trust_server_certificate": bool(row["trust_server_certificate"]),
            "timeout": int(row["timeout"] or 5),
            "table_name": normalize_sql_table_name(str(row["table_name"] or "audit_logs")),
        }
    )
    return defaults


def save_sql_server_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO sql_server_settings(
                id, enabled, driver, server, port, database_name, username, password_enc,
                encrypt, trust_server_certificate, timeout, table_name
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1 if bool(settings.get("enabled")) else 0,
                str(settings.get("driver", "ODBC Driver 18 for SQL Server")).strip() or "ODBC Driver 18 for SQL Server",
                str(settings.get("server", "")).strip(),
                int(settings.get("port", 1433) or 1433),
                str(settings.get("database_name", "")).strip(),
                str(settings.get("username", "")).strip(),
                encrypt_secret(str(settings.get("password", ""))),
                1 if bool(settings.get("encrypt", True)) else 0,
                1 if bool(settings.get("trust_server_certificate", True)) else 0,
                int(settings.get("timeout", 5) or 5),
                normalize_sql_table_name(str(settings.get("table_name", "audit_logs"))),
            ),
        )


def _sql_server_conn_string(settings: dict[str, Any]) -> str:
    server = str(settings.get("server", "")).strip()
    port = int(settings.get("port", 1433) or 1433)
    driver = str(settings.get("driver", "ODBC Driver 18 for SQL Server")).strip() or "ODBC Driver 18 for SQL Server"
    database_name = str(settings.get("database_name", "")).strip()
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", ""))
    encrypt = "yes" if bool(settings.get("encrypt", True)) else "no"
    trust_server_certificate = "yes" if bool(settings.get("trust_server_certificate", True)) else "no"
    timeout = int(settings.get("timeout", 5) or 5)
    return (
        f"DRIVER={{{driver}}};"
        f"SERVER={server},{port};"
        f"DATABASE={database_name};"
        f"UID={username};PWD={password};"
        f"Encrypt={encrypt};TrustServerCertificate={trust_server_certificate};"
        f"Connection Timeout={timeout};"
    )


def _connect_sql_server_from_settings(settings: dict[str, Any], autocommit: bool) -> tuple[Any, str]:
    server = str(settings.get("server", "")).strip()
    port = int(settings.get("port", 1433) or 1433)
    database_name = str(settings.get("database_name", "")).strip()
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", ""))
    timeout = int(settings.get("timeout", 5) or 5)

    client = _pick_sql_client()
    if client == "pymssql":
        server_name = server if "\\" in server else f"{server}:{port}"
        conn = pymssql.connect(
            server=server_name,
            user=username,
            password=password,
            database=database_name,
            login_timeout=timeout,
            timeout=timeout,
            autocommit=autocommit,
        )
        return conn, "pymssql"
    if client == "pyodbc":
        conn = pyodbc.connect(_sql_server_conn_string(settings), autocommit=autocommit, timeout=timeout)
        return conn, "pyodbc"
    raise RuntimeError("No SQL Server client available. Install pymssql (recommended, no ODBC) or pyodbc + ODBC Driver.")


def ensure_sql_server_log_table(conn: Any, table_name: str) -> None:
    safe_table = normalize_sql_table_name(table_name)
    sql = f"""
IF OBJECT_ID(N'dbo.[{safe_table}]', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.[{safe_table}] (
        id INT IDENTITY(1,1) PRIMARY KEY,
        action NVARCHAR(128) NOT NULL,
        requester NVARCHAR(255) NOT NULL,
        approver NVARCHAR(255) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END
"""
    cursor = conn.cursor()
    cursor.execute(sql)
    cursor.close()


def test_sql_server_logging_connection(settings: dict[str, Any]) -> tuple[bool, str]:
    try:
        conn, _ = _connect_sql_server_from_settings(settings, autocommit=True)
    except Exception as exc:
        return False, f"SQL Server connection failed: {exc}"

    try:
        ensure_sql_server_log_table(conn, str(settings.get("table_name", "audit_logs")))
        return True, "SQL Server connection successful and logging table is ready."
    except Exception as exc:
        return False, f"Connected but failed to prepare log table: {exc}"
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _write_external_sql_audit_log_sync(
    action: str, requester: str, approver: str, device_name: str, details: dict[str, Any], created_at: str
) -> None:
    settings = load_sql_server_settings()
    if not bool(settings.get("enabled")):
        return
    try:
        timeout_value = int(settings.get("timeout", 5) or 5)
    except Exception:
        timeout_value = 5
    # Keep request paths fast even when SQL Server is unreachable.
    settings["timeout"] = max(1, min(2, timeout_value))

    table_name = normalize_sql_table_name(str(settings.get("table_name", "audit_logs")))
    try:
        conn, backend = _connect_sql_server_from_settings(settings, autocommit=True)
    except Exception:
        return

    try:
        ensure_sql_server_log_table(conn, table_name)
        cursor = conn.cursor()
        insert_sql = (
            f"INSERT INTO dbo.[{table_name}] (action, requester, approver, device_name, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        if backend == "pymssql":
            insert_sql = insert_sql.replace("?", "%s")
        cursor.execute(
            insert_sql,
            (
                str(action),
                str(requester or ""),
                str(approver or ""),
                str(device_name or ""),
                json.dumps(details),
                str(created_at),
            ),
        )
        cursor.close()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def write_external_sql_audit_log(
    action: str, requester: str, approver: str, device_name: str, details: dict[str, Any], created_at: str
) -> None:
    try:
        AUDIT_LOG_EXECUTOR.submit(
            _write_external_sql_audit_log_sync,
            action,
            requester,
            approver,
            device_name,
            details,
            created_at,
        )
    except Exception:
        pass


def _write_primary_audit_log_sync(
    action: str, requester: str, approver: str, device_name: str, details: dict[str, Any], created_at: str
) -> None:
    audit_store_service.write_primary_audit_log(
        db_conn,
        action,
        requester,
        approver,
        device_name,
        details,
        created_at,
    )


def _write_primary_login_audit_log_sync(
    username: str,
    auth_source: str,
    success: bool,
    reason: str,
    client_ip: str,
    user_agent: str,
    created_at: str,
) -> None:
    audit_store_service.write_primary_login_audit_log(
        db_conn,
        username,
        auth_source,
        success,
        reason,
        client_ip,
        user_agent,
        created_at,
    )


def _write_primary_action_log_sync(
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
    audit_store_service.write_primary_action_log(
        db_conn,
        normalize_role,
        username,
        role,
        action,
        device_name,
        interface_name,
        status,
        payload,
        client_ip,
        user_agent,
        created_at,
    )


def _submit_background_log_write(fn: Any, *args: Any) -> None:
    try:
        AUDIT_LOG_EXECUTOR.submit(fn, *args)
    except Exception:
        pass


def write_audit_log(action: str, requester: str, approver: str, device_name: str, details: dict[str, Any]) -> None:
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    _submit_background_log_write(
        _write_primary_audit_log_sync,
        action,
        requester,
        approver,
        device_name,
        details,
        created_at,
    )
    write_external_sql_audit_log(action, requester, approver, device_name, details, created_at)


def write_audit_log_safe(
    action: str,
    device_name: str = "",
    details: dict[str, Any] | None = None,
    *,
    requester: str = "",
    approver: str = "",
) -> None:
    session_actor = ""
    if has_request_context():
        session_actor = str(session.get("creds", {}).get("username", "")).strip()
    actor = str(requester or "").strip() or session_actor or "system"
    reviewer = str(approver or "").strip() or actor
    payload = details if isinstance(details, dict) else {}
    payload_keys = ",".join(sorted([str(k).strip() for k in payload.keys() if str(k).strip()])) or "-"
    try:
        write_audit_log(action, actor, reviewer, str(device_name or ""), payload)
        app.logger.info(
            "audit_event action=%s requester=%s approver=%s device=%s detail_keys=%s",
            str(action or "").strip() or "-",
            actor,
            reviewer,
            str(device_name or "").strip() or "-",
            payload_keys,
        )
    except Exception:
        app.logger.exception("Failed to write audit log for action '%s'.", action)


def write_login_audit_log(username: str, auth_source: str, success: bool, reason: str) -> None:
    client_ip = _resolve_client_ip()
    user_agent = str(request.headers.get("User-Agent", "")).strip()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    details = {
        "auth_source": str(auth_source or "unknown").strip().lower() or "unknown",
        "success": bool(success),
        "reason": str(reason or "").strip(),
        "client_ip": client_ip,
        "user_agent": user_agent[:512],
    }
    action_name = "login_success" if bool(success) else "login_failed"
    _submit_background_log_write(
        _write_primary_login_audit_log_sync,
        str(username or "").strip(),
        str(auth_source or "unknown").strip().lower() or "unknown",
        bool(success),
        str(reason or "").strip(),
        client_ip,
        user_agent,
        created_at,
    )
    _submit_background_log_write(
        _write_primary_audit_log_sync,
        action_name,
        str(username or "").strip(),
        "",
        "",
        details,
        created_at,
    )
    write_external_sql_audit_log(
        action=action_name,
        requester=str(username or "").strip(),
        approver="",
        device_name="",
        details=details,
        created_at=created_at,
    )
    app.logger.info(
        "login_event username=%s auth_source=%s success=%s reason=%s ip=%s",
        str(username or "").strip() or "-",
        str(auth_source or "").strip().lower() or "unknown",
        bool(success),
        str(reason or "").strip() or "-",
        client_ip or "-",
    )


def write_action_log(
    username: str,
    role: str,
    action: str,
    device_name: str,
    interface_name: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> None:
    client_ip = _resolve_client_ip()
    user_agent = str(request.headers.get("User-Agent", "")).strip()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload = details if isinstance(details, dict) else {}
    payload.update(
        {
            "role": normalize_role(str(role or "unknown")),
            "interface_name": str(interface_name or "").strip(),
            "status": str(status or "").strip() or "unknown",
            "client_ip": client_ip,
            "user_agent": user_agent[:512],
        }
    )
    action_name = str(action or "").strip() or "action"
    _submit_background_log_write(
        _write_primary_action_log_sync,
        str(username or "").strip(),
        normalize_role(str(role or "unknown")),
        action_name,
        str(device_name or "").strip(),
        str(interface_name or "").strip(),
        str(status or "").strip() or "unknown",
        dict(payload),
        client_ip,
        user_agent,
        created_at,
    )
    _submit_background_log_write(
        _write_primary_audit_log_sync,
        action_name,
        str(username or "").strip(),
        "",
        str(device_name or "").strip(),
        dict(payload),
        created_at,
    )
    write_external_sql_audit_log(
        action=action_name,
        requester=str(username or "").strip(),
        approver="",
        device_name=str(device_name or "").strip(),
        details=payload,
        created_at=created_at,
    )
    app.logger.info(
        "action_event action=%s username=%s role=%s device=%s interface=%s status=%s ip=%s",
        str(action or "").strip() or "action",
        str(username or "").strip() or "-",
        normalize_role(str(role or "unknown")),
        str(device_name or "").strip() or "-",
        str(interface_name or "").strip() or "-",
        str(status or "").strip() or "unknown",
        client_ip or "-",
    )


def _build_audit_log_summary(action: str, device_name: str, details: dict[str, Any]) -> str:
    return audit_store_service.build_audit_log_summary(action, device_name, details)


def _rows_to_audit_logs(rows: list[Any]) -> list[dict[str, Any]]:
    return audit_store_service.rows_to_audit_logs(rows)


def load_audit_logs_page(limit: int = 100, offset: int = 0) -> tuple[list[dict[str, Any]], bool]:
    return audit_store_service.load_audit_logs_page(db_conn, limit, offset)


def load_audit_logs(limit: int = 500) -> list[dict[str, Any]]:
    logs, _has_more = load_audit_logs_page(limit=max(1, int(limit or 500)), offset=0)
    return logs
