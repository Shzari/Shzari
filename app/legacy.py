#!/usr/bin/env python3
from __future__ import annotations

import csv
import atexit
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from config_settings import (
    DEVICES_FILE,
    EXTERNAL_LOGGING_SETTINGS_FILE,
    IP_BRANCHES_FILE,
    ISE_SETTINGS_FILE,
    MONITORING_SETTINGS_FILE,
    NTP_SETTINGS_FILE,
    PRIMARY_SQL_SERVER_CLIENT,
    PRIMARY_SQL_SERVER_DB,
    PRIMARY_SQL_SERVER_DRIVER,
    PRIMARY_SQL_SERVER_HOST,
    PRIMARY_SQL_SERVER_PASSWORD,
    PRIMARY_SQL_SERVER_PORT,
    PRIMARY_SQL_SERVER_USER,
    SECRET_KEY,
    SESSION_SETTINGS_FILE,
    SUPER_ADMIN_FILE,
    USER_BUTTONS_FILE,
    USERS_FILE,
    DEVICE_CREDS_FILE,
)
from core_models import DBError, DBOperationalError, DBRow, SSHResult
from security_utils import _hash_password, decrypt_secret, encrypt_secret, is_valid_ipv4
try:
    import pyodbc
    PYODBC_AVAILABLE = True
except Exception:
    pyodbc = None
    PYODBC_AVAILABLE = False
try:
    import pymssql
    PYMSSQL_AVAILABLE = True
except Exception:
    pymssql = None
    PYMSSQL_AVAILABLE = False
try:
    from ldap3 import ALL, SUBTREE, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars
    LDAP3_AVAILABLE = True
except Exception:
    ALL = SUBTREE = Connection = Server = Tls = None
    LDAPException = Exception
    escape_filter_chars = None
    LDAP3_AVAILABLE = False
try:
    import pysnmp.hlapi as pysnmp_hlapi
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        getCmd,
        nextCmd,
        usmAesCfb128Protocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
        usmNoPrivProtocol,
    )
    usmHMACMD5AuthProtocol = getattr(pysnmp_hlapi, "usmHMACMD5AuthProtocol", None)
    usmHMAC128SHA224AuthProtocol = getattr(pysnmp_hlapi, "usmHMAC128SHA224AuthProtocol", None)
    usmHMAC192SHA256AuthProtocol = getattr(pysnmp_hlapi, "usmHMAC192SHA256AuthProtocol", None)
    usmHMAC256SHA384AuthProtocol = getattr(pysnmp_hlapi, "usmHMAC256SHA384AuthProtocol", None)
    usmHMAC384SHA512AuthProtocol = getattr(pysnmp_hlapi, "usmHMAC384SHA512AuthProtocol", None)
    usmDESPrivProtocol = getattr(pysnmp_hlapi, "usmDESPrivProtocol", None)
    usm3DESEDEPrivProtocol = getattr(pysnmp_hlapi, "usm3DESEDEPrivProtocol", None)
    usmAesCfb192Protocol = getattr(pysnmp_hlapi, "usmAesCfb192Protocol", None)
    usmAesCfb256Protocol = getattr(pysnmp_hlapi, "usmAesCfb256Protocol", None)
    PYSNMP_AVAILABLE = True
except Exception:
    CommunityData = ContextData = ObjectIdentity = ObjectType = SnmpEngine = UdpTransportTarget = UsmUserData = None
    getCmd = None
    nextCmd = None
    usmAesCfb128Protocol = usmHMACSHAAuthProtocol = usmNoAuthProtocol = usmNoPrivProtocol = None
    usmHMACMD5AuthProtocol = usmHMAC128SHA224AuthProtocol = usmHMAC192SHA256AuthProtocol = None
    usmHMAC256SHA384AuthProtocol = usmHMAC384SHA512AuthProtocol = None
    usmDESPrivProtocol = usm3DESEDEPrivProtocol = usmAesCfb192Protocol = usmAesCfb256Protocol = None
    PYSNMP_AVAILABLE = False
try:
    import winrm
    WINRM_AVAILABLE = True
except Exception:
    winrm = None
    WINRM_AVAILABLE = False

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _env_true(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_web_acl_entries(raw_entries: Any) -> tuple[list[str], list[str]]:
    parts: list[str] = []
    if isinstance(raw_entries, str):
        parts = re.split(r"[,\r\n;]+", raw_entries)
    elif isinstance(raw_entries, (list, tuple, set)):
        for item in raw_entries:
            if isinstance(item, str):
                parts.extend(re.split(r"[,\r\n;]+", item))
            elif item is not None:
                parts.append(str(item))
    elif raw_entries is not None:
        parts = re.split(r"[,\r\n;]+", str(raw_entries))

    normalized: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for token in parts:
        value = str(token or "").strip()
        if not value:
            continue
        try:
            if "/" in value:
                parsed = ipaddress.ip_network(value, strict=False)
                key = str(parsed)
            else:
                parsed = ipaddress.ip_address(value)
                key = str(parsed)
            if key not in seen:
                seen.add(key)
                normalized.append(key)
        except Exception:
            invalid.append(value)
    return normalized, invalid


def _is_client_ip_allowed_by_acl(client_ip: str, acl_entries: list[str]) -> bool:
    ip_text = str(client_ip or "").strip()
    if not ip_text:
        return False
    try:
        parsed_ip = ipaddress.ip_address(ip_text)
    except Exception:
        return False
    for item in acl_entries:
        entry = str(item or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if parsed_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if parsed_ip == ipaddress.ip_address(entry):
                    return True
        except Exception:
            continue
    return False


_AUTO_RESTART_PENDING = threading.Event()


def _schedule_self_restart(delay_seconds: float = 1.0) -> bool:
    """
    Restart current process in-place after response is returned.
    Used to apply HTTP/HTTPS listener changes without manual restart.
    """
    if _env_true("APP_DISABLE_AUTO_RESTART", "0"):
        return False
    if _AUTO_RESTART_PENDING.is_set():
        return False
    _AUTO_RESTART_PENDING.set()

    def _restart() -> None:
        time.sleep(max(0.3, float(delay_seconds)))
        argv = [sys.executable] + list(sys.argv)
        try:
            os.execv(sys.executable, argv)
        except Exception:
            os._exit(0)

    threading.Thread(target=_restart, name="auto-self-restart", daemon=True).start()
    return True


def _session_https_enabled() -> bool:
    try:
        if not SESSION_SETTINGS_FILE.exists():
            return False
        with SESSION_SETTINGS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return False
        https_enabled = bool(data.get("https_enabled", False))
        # Backward compatible with older payloads that only had "https_enabled".
        if "http_enabled" not in data:
            return https_enabled
        http_enabled = bool(data.get("http_enabled", True))
        # Mark cookies as secure only when app is HTTPS-only.
        return https_enabled and not http_enabled
    except Exception:
        return False


app = Flask(
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "static"),
)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = str(os.environ.get("APP_SESSION_SAMESITE", "Lax")).strip() or "Lax"
if _env_true("APP_HTTPS", "0") or _session_https_enabled() or _env_true("APP_FORCE_SECURE_COOKIES", "0"):
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["PREFERRED_URL_SCHEME"] = "https"
if _env_true("APP_TRUST_PROXY", "0"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)  # type: ignore[assignment]

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
SERVICE_TYPE_LOGIN = 1
DEFAULT_CATEGORY = "Uncategorized"
RUNTIME_SSH_SESSIONS: dict[str, dict[str, dict[str, Any]]] = {}
RUNTIME_SSH_LOCK = threading.Lock()
MONITORING_POLLER_LOCK = threading.Lock()
MONITORING_POLLER_THREAD: threading.Thread | None = None
MONITORING_POLLER_STOP = threading.Event()
LOGIN_LOCKOUT_STATE: dict[str, dict[str, Any]] = {}
LOGIN_LOCKOUT_LOCK = threading.Lock()
LOGIN_LOCKOUT_DB_READY = False


def embedded_monitoring_poller_enabled() -> bool:
    raw = str(os.environ.get("MONITORING_EMBEDDED_POLLER", "0")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


SQLSERVER_PRIMARY_KEYS: dict[str, list[str]] = {
    "app_settings": ["setting_key"],
    "login_lockouts": ["lock_key"],
    "users": ["username"],
    "devices": ["hostname"],
    "device_groups": ["hostname", "group_name"],
    "ip_branches": ["branch_name"],
    "ip_branch_details": ["branch_name"],
    "ip_branch_ips": ["branch_name", "ip_address"],
    "device_credentials": ["account_key"],
    "super_admin": ["id"],
    "ise_settings": ["id"],
    "ldap_settings": ["id"],
    "sql_server_settings": ["id"],
    "pending_device_requests": ["id"],
    "pending_command_requests": ["id"],
    "user_notifications": ["id"],
    "audit_logs": ["id"],
    "monitoring_metrics": ["id"],
    "monitoring_device_profiles": ["device_name"],
    "monitoring_interface_metrics": ["id"],
    "monitoring_alerts": ["id"],
}


def _split_sql_list(expr: str) -> list[str]:
    items: list[str] = []
    current = []
    in_quote = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "'" and (i == 0 or expr[i - 1] != "\\"):
            in_quote = not in_quote
            current.append(ch)
        elif ch == "," and not in_quote:
            value = "".join(current).strip()
            if value:
                items.append(value)
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        items.append(tail)
    return items


def _extract_insert_parts(sql: str) -> tuple[str, list[str], list[str]] | None:
    match = re.search(
        r"INSERT\s+OR\s+(?:REPLACE|IGNORE)\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    table = str(match.group(1)).strip()
    columns = _split_sql_list(str(match.group(2)))
    values = _split_sql_list(str(match.group(3)))
    if not table or not columns or len(columns) != len(values):
        return None
    return table, columns, values


def _rewrite_limit_clause(sql: str) -> str:
    normalized = sql.strip().rstrip(";")
    if re.search(r"\bLIMIT\s+\?\s*$", normalized, re.IGNORECASE):
        return re.sub(r"\bLIMIT\s+\?\s*$", "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY", normalized, flags=re.IGNORECASE)
    if re.search(r"\bLIMIT\s+\d+\s*$", normalized, re.IGNORECASE):
        return re.sub(r"\bLIMIT\s+(\d+)\s*$", r"OFFSET 0 ROWS FETCH NEXT \1 ROWS ONLY", normalized, flags=re.IGNORECASE)
    return sql


def _convert_insert_or_ignore(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    parsed = _extract_insert_parts(sql)
    if not parsed:
        return sql.replace("INSERT OR IGNORE", "INSERT"), params
    table, columns, values = parsed
    keys = SQLSERVER_PRIMARY_KEYS.get(table, columns)
    src_items = ", ".join([f"{val} AS {col}" for col, val in zip(columns, values)])
    where_parts = [f"target.{col} = src.{col}" for col in keys]
    where_sql = " AND ".join(where_parts) if where_parts else "1 = 0"
    insert_cols = ", ".join(columns)
    rewritten = (
        f"INSERT INTO {table}({insert_cols}) "
        f"SELECT {', '.join([f'src.{col}' for col in columns])} "
        f"FROM (SELECT {src_items}) AS src "
        f"WHERE NOT EXISTS (SELECT 1 FROM {table} AS target WHERE {where_sql});"
    )
    return rewritten, params


def _convert_insert_or_replace(sql: str, params: tuple[Any, ...] | list[Any] | None) -> str:
    parsed = _extract_insert_parts(sql)
    if not parsed:
        return sql.replace("INSERT OR REPLACE", "INSERT")
    table, columns, values = parsed
    keys = SQLSERVER_PRIMARY_KEYS.get(table, [columns[0]])
    src_items = ", ".join([f"{val} AS {col}" for col, val in zip(columns, values)])
    on_clause = " AND ".join([f"target.{k} = src.{k}" for k in keys if k in columns])
    update_cols = [col for col in columns if col not in keys]
    update_clause = ", ".join([f"target.{col} = src.{col}" for col in update_cols])
    insert_cols = ", ".join(columns)
    insert_vals = ", ".join([f"src.{col}" for col in columns])
    merge_sql = [f"MERGE {table} AS target", f"USING (SELECT {src_items}) AS src", f"ON {on_clause}"]
    if update_clause:
        merge_sql.append(f"WHEN MATCHED THEN UPDATE SET {update_clause}")
    merge_sql.append(f"WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals});")
    return " ".join(merge_sql)


def _transform_sql(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    transformed = _rewrite_limit_clause(sql)
    upper = transformed.upper()
    if "INSERT OR IGNORE INTO" in upper:
        return _convert_insert_or_ignore(transformed, params)
    if "INSERT OR REPLACE INTO" in upper:
        return _convert_insert_or_replace(transformed, params), params
    return transformed, params


def _adapt_param_style(sql: str, backend: str) -> str:
    if backend == "pymssql":
        return sql.replace("?", "%s")
    return sql


class DBCursor:
    def __init__(self, conn: Any, cursor: Any, backend: str, columns: list[str] | None = None):
        self._conn = conn
        self._cursor = cursor
        self._backend = backend
        self._columns = columns
        self.lastrowid = 0

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] | None = None) -> "DBCursor":
        transformed_sql, transformed_params = _transform_sql(sql, params)
        final_sql = _adapt_param_style(transformed_sql, self._backend)
        try:
            if transformed_params is None:
                self._cursor.execute(final_sql)
            else:
                self._cursor.execute(final_sql, tuple(transformed_params))
            self._columns = [str(desc[0]) for desc in self._cursor.description] if self._cursor.description else None
            if final_sql.strip().upper().startswith("INSERT"):
                try:
                    identity_cursor = self._conn.cursor()
                    identity_cursor.execute("SELECT CAST(SCOPE_IDENTITY() AS INT)")
                    row = identity_cursor.fetchone()
                    self.lastrowid = int(row[0]) if row and row[0] is not None else 0
                    identity_cursor.close()
                except Exception:
                    self.lastrowid = 0
            return self
        except Exception as exc:
            raise DBOperationalError(str(exc)) from exc

    def executemany(self, sql: str, params_list: list[tuple[Any, ...]] | list[list[Any]]) -> "DBCursor":
        transformed_sql, _ = _transform_sql(sql, None)
        final_sql = _adapt_param_style(transformed_sql, self._backend)
        try:
            self._cursor.executemany(final_sql, [tuple(p) for p in params_list])
            return self
        except Exception as exc:
            raise DBOperationalError(str(exc)) from exc

    def fetchone(self) -> DBRow | None:
        row = self._cursor.fetchone()
        if row is None:
            return None
        columns = self._columns or [str(desc[0]) for desc in self._cursor.description]
        return DBRow(columns, tuple(row))

    def fetchall(self) -> list[DBRow]:
        rows = self._cursor.fetchall()
        columns = self._columns or [str(desc[0]) for desc in self._cursor.description]
        return [DBRow(columns, tuple(row)) for row in rows]

    def close(self) -> None:
        try:
            self._cursor.close()
        except Exception:
            pass


class DBConnection:
    def __init__(self, conn: Any, backend: str):
        self._conn = conn
        self._backend = backend

    def cursor(self) -> DBCursor:
        return DBCursor(self._conn, self._conn.cursor(), self._backend)

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] | None = None) -> DBCursor:
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql: str, params_list: list[tuple[Any, ...]] | list[list[Any]]) -> DBCursor:
        cur = self.cursor()
        return cur.executemany(sql, params_list)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DBConnection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
        return False


def _primary_sql_server_conn_string() -> str:
    return (
        f"DRIVER={{{PRIMARY_SQL_SERVER_DRIVER}}};"
        f"SERVER={PRIMARY_SQL_SERVER_HOST},{PRIMARY_SQL_SERVER_PORT};"
        f"DATABASE={PRIMARY_SQL_SERVER_DB};"
        f"UID={PRIMARY_SQL_SERVER_USER};PWD={PRIMARY_SQL_SERVER_PASSWORD};"
        "Encrypt=yes;TrustServerCertificate=yes;"
        "Connection Timeout=10;"
    )


def _pick_sql_client() -> str:
    preferred = PRIMARY_SQL_SERVER_CLIENT
    if preferred == "pymssql" and PYMSSQL_AVAILABLE:
        return "pymssql"
    if preferred == "pyodbc" and PYODBC_AVAILABLE:
        return "pyodbc"
    if preferred == "pymssql" and not PYMSSQL_AVAILABLE:
        return ""
    if preferred == "pyodbc" and not PYODBC_AVAILABLE:
        return ""
    if PYMSSQL_AVAILABLE:
        return "pymssql"
    if PYODBC_AVAILABLE:
        return "pyodbc"
    return ""


def _connect_primary_sql_server() -> tuple[Any, str]:
    client = _pick_sql_client()
    if client == "pymssql":
        server_name = PRIMARY_SQL_SERVER_HOST if "\\" in PRIMARY_SQL_SERVER_HOST else f"{PRIMARY_SQL_SERVER_HOST}:{PRIMARY_SQL_SERVER_PORT}"
        conn = pymssql.connect(
            server=server_name,
            user=PRIMARY_SQL_SERVER_USER,
            password=PRIMARY_SQL_SERVER_PASSWORD,
            database=PRIMARY_SQL_SERVER_DB,
            login_timeout=10,
            timeout=10,
            autocommit=False,
        )
        return conn, "pymssql"
    if client == "pyodbc":
        conn = pyodbc.connect(_primary_sql_server_conn_string(), autocommit=False, timeout=10)
        return conn, "pyodbc"
    raise RuntimeError(
        "No SQL Server client available. Install pymssql (recommended, no ODBC) or pyodbc + ODBC Driver."
    )


def db_conn() -> DBConnection:
    try:
        raw, backend = _connect_primary_sql_server()
        return DBConnection(raw, backend)
    except Exception as exc:
        raise RuntimeError(f"Primary SQL Server connection failed: {exc}") from exc


def init_db() -> None:
    with db_conn() as conn:
        conn.execute(
            """
IF OBJECT_ID(N'dbo.app_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.app_settings (
        setting_key NVARCHAR(128) NOT NULL PRIMARY KEY,
        setting_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_app_settings_json DEFAULT '{}',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_app_settings_updated DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.users (
        username NVARCHAR(255) NOT NULL PRIMARY KEY,
        role NVARCHAR(50) NOT NULL CONSTRAINT DF_users_role DEFAULT 'operator',
        auth_source NVARCHAR(32) NOT NULL CONSTRAINT DF_users_auth_source DEFAULT 'ldap',
        salt NVARCHAR(255) NOT NULL CONSTRAINT DF_users_salt DEFAULT '',
        password_hash NVARCHAR(255) NOT NULL CONSTRAINT DF_users_password_hash DEFAULT '',
        must_change_password BIT NOT NULL CONSTRAINT DF_users_mcp DEFAULT 1,
        allowed_categories NVARCHAR(MAX) NULL,
        admin_permissions NVARCHAR(MAX) NULL,
        category_panel_access NVARCHAR(MAX) NULL,
        account_privileges NVARCHAR(MAX) NULL
    );
END
"""
        )
        conn.execute(
            """
IF COL_LENGTH('dbo.users', 'admin_permissions') IS NULL
    ALTER TABLE dbo.users ADD admin_permissions NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'category_panel_access') IS NULL
    ALTER TABLE dbo.users ADD category_panel_access NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'account_privileges') IS NULL
    ALTER TABLE dbo.users ADD account_privileges NVARCHAR(MAX) NULL;
IF COL_LENGTH('dbo.users', 'auth_source') IS NULL
    ALTER TABLE dbo.users ADD auth_source NVARCHAR(32) NOT NULL CONSTRAINT DF_users_auth_source_v2 DEFAULT 'ldap';
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.devices', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.devices (
        hostname NVARCHAR(255) NOT NULL PRIMARY KEY,
        ip_address NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.device_groups', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.device_groups (
        hostname NVARCHAR(255) NOT NULL,
        group_name NVARCHAR(255) NOT NULL,
        CONSTRAINT PK_device_groups PRIMARY KEY(hostname, group_name)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.ip_branches', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branches (
        branch_name NVARCHAR(255) NOT NULL PRIMARY KEY
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.ip_branch_details', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branch_details (
        branch_name NVARCHAR(255) NOT NULL PRIMARY KEY,
        site NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_details_site DEFAULT '',
        network_base NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_network_base DEFAULT '',
        cidr INT NOT NULL CONSTRAINT DF_ip_branch_details_cidr DEFAULT 27,
        subnet_mask NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_subnet_mask DEFAULT '',
        gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_gateway DEFAULT '',
        broadcast NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_broadcast DEFAULT '',
        created_at NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_created DEFAULT '',
        updated_at NVARCHAR(64) NOT NULL CONSTRAINT DF_ip_branch_details_updated DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.ip_branch_ips', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ip_branch_ips (
        branch_name NVARCHAR(255) NOT NULL,
        ip_address NVARCHAR(64) NOT NULL,
        hostname NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_ips_hostname DEFAULT '',
        enduser_name NVARCHAR(255) NOT NULL CONSTRAINT DF_ip_branch_ips_enduser DEFAULT '',
        status NVARCHAR(32) NOT NULL CONSTRAINT DF_ip_branch_ips_status DEFAULT 'FREE',
        CONSTRAINT PK_ip_branch_ips PRIMARY KEY(branch_name, ip_address)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.device_credentials', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.device_credentials (
        account_key NVARCHAR(255) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_device_credentials_username DEFAULT '',
        password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_device_credentials_pwd DEFAULT '',
        enable_password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_device_credentials_enable_pwd DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.super_admin', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.super_admin (
        id INT NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_username DEFAULT '',
        salt NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_salt DEFAULT '',
        password_hash NVARCHAR(255) NOT NULL CONSTRAINT DF_super_admin_password_hash DEFAULT '',
        CONSTRAINT CK_super_admin_id CHECK (id = 1)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.ise_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ise_settings (
        id INT NOT NULL PRIMARY KEY,
        primary_server NVARCHAR(255) NOT NULL CONSTRAINT DF_ise_settings_ps DEFAULT '',
        primary_port INT NOT NULL CONSTRAINT DF_ise_settings_pp DEFAULT 1812,
        primary_shared_secret NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ise_settings_psecret DEFAULT '',
        secondary_server NVARCHAR(255) NOT NULL CONSTRAINT DF_ise_settings_ss DEFAULT '',
        secondary_port INT NOT NULL CONSTRAINT DF_ise_settings_sp DEFAULT 1812,
        secondary_shared_secret NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ise_settings_ssecret DEFAULT '',
        timeout INT NOT NULL CONSTRAINT DF_ise_settings_timeout DEFAULT 5,
        nas_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_ise_settings_nas DEFAULT '127.0.0.1',
        CONSTRAINT CK_ise_settings_id CHECK (id = 1)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.ldap_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ldap_settings (
        id INT NOT NULL PRIMARY KEY,
        server NVARCHAR(255) NOT NULL CONSTRAINT DF_ldap_settings_server DEFAULT '',
        port INT NOT NULL CONSTRAINT DF_ldap_settings_port DEFAULT 389,
        use_ssl BIT NOT NULL CONSTRAINT DF_ldap_settings_use_ssl DEFAULT 0,
        start_tls BIT NOT NULL CONSTRAINT DF_ldap_settings_start_tls DEFAULT 0,
        timeout INT NOT NULL CONSTRAINT DF_ldap_settings_timeout DEFAULT 5,
        base_dn NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_base_dn DEFAULT '',
        user_dn_template NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_user_dn_template DEFAULT '',
        user_search_filter NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_user_filter DEFAULT '(sAMAccountName={username})',
        bind_dn NVARCHAR(512) NOT NULL CONSTRAINT DF_ldap_settings_bind_dn DEFAULT '',
        bind_password NVARCHAR(MAX) NOT NULL CONSTRAINT DF_ldap_settings_bind_password DEFAULT '',
        CONSTRAINT CK_ldap_settings_id CHECK (id = 1)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.sql_server_settings', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.sql_server_settings (
        id INT NOT NULL PRIMARY KEY,
        enabled BIT NOT NULL CONSTRAINT DF_sql_server_settings_enabled DEFAULT 0,
        driver NVARCHAR(128) NOT NULL CONSTRAINT DF_sql_server_settings_driver DEFAULT 'ODBC Driver 18 for SQL Server',
        server NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_server DEFAULT '',
        port INT NOT NULL CONSTRAINT DF_sql_server_settings_port DEFAULT 1433,
        database_name NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_database DEFAULT '',
        username NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_username DEFAULT '',
        password_enc NVARCHAR(MAX) NOT NULL CONSTRAINT DF_sql_server_settings_password DEFAULT '',
        encrypt BIT NOT NULL CONSTRAINT DF_sql_server_settings_encrypt DEFAULT 1,
        trust_server_certificate BIT NOT NULL CONSTRAINT DF_sql_server_settings_trust DEFAULT 1,
        timeout INT NOT NULL CONSTRAINT DF_sql_server_settings_timeout DEFAULT 5,
        table_name NVARCHAR(255) NOT NULL CONSTRAINT DF_sql_server_settings_table DEFAULT 'audit_logs',
        CONSTRAINT CK_sql_server_settings_id CHECK (id = 1)
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.pending_device_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.pending_device_requests (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        requester_username NVARCHAR(255) NOT NULL,
        requester_role NVARCHAR(50) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        original_hostname NVARCHAR(255) NOT NULL,
        original_ip NVARCHAR(64) NOT NULL,
        original_categories NVARCHAR(MAX) NOT NULL,
        proposed_hostname NVARCHAR(255) NOT NULL,
        proposed_ip NVARCHAR(64) NOT NULL,
        proposed_categories NVARCHAR(MAX) NOT NULL,
        status NVARCHAR(50) NOT NULL CONSTRAINT DF_pending_device_requests_status DEFAULT 'pending',
        approver_username NVARCHAR(255) NOT NULL CONSTRAINT DF_pending_device_requests_approver DEFAULT '',
        created_at NVARCHAR(64) NOT NULL,
        decided_at NVARCHAR(64) NOT NULL CONSTRAINT DF_pending_device_requests_decided DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.pending_command_requests', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.pending_command_requests (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        requester_username NVARCHAR(255) NOT NULL,
        requester_role NVARCHAR(50) NOT NULL,
        command_mode NVARCHAR(64) NOT NULL,
        command_text NVARCHAR(MAX) NOT NULL,
        target_devices NVARCHAR(MAX) NOT NULL,
        status NVARCHAR(50) NOT NULL CONSTRAINT DF_pending_command_requests_status DEFAULT 'pending',
        approver_username NVARCHAR(255) NOT NULL CONSTRAINT DF_pending_command_requests_approver DEFAULT '',
        created_at NVARCHAR(64) NOT NULL,
        decided_at NVARCHAR(64) NOT NULL CONSTRAINT DF_pending_command_requests_decided DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.user_notifications', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.user_notifications (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        message NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL,
        is_read BIT NOT NULL CONSTRAINT DF_user_notifications_is_read DEFAULT 0
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.audit_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        action NVARCHAR(128) NOT NULL,
        requester NVARCHAR(255) NOT NULL,
        approver NVARCHAR(255) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.login_audit_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.login_audit_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        auth_source NVARCHAR(32) NOT NULL,
        success BIT NOT NULL,
        reason NVARCHAR(512) NOT NULL,
        client_ip NVARCHAR(128) NOT NULL,
        user_agent NVARCHAR(512) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.login_lockouts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.login_lockouts (
        lock_key NVARCHAR(255) NOT NULL PRIMARY KEY,
        attempts INT NOT NULL CONSTRAINT DF_login_lockouts_attempts DEFAULT 0,
        locked_until_utc NVARCHAR(64) NOT NULL CONSTRAINT DF_login_lockouts_locked_until DEFAULT '',
        updated_at_utc NVARCHAR(64) NOT NULL CONSTRAINT DF_login_lockouts_updated DEFAULT ''
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.action_logs', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.action_logs (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        username NVARCHAR(255) NOT NULL,
        role NVARCHAR(50) NOT NULL CONSTRAINT DF_action_logs_role DEFAULT 'unknown',
        action NVARCHAR(128) NOT NULL,
        device_name NVARCHAR(255) NOT NULL,
        interface_name NVARCHAR(128) NOT NULL,
        status NVARCHAR(64) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        client_ip NVARCHAR(128) NOT NULL,
        user_agent NVARCHAR(512) NOT NULL,
        created_at NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF COL_LENGTH('dbo.action_logs', 'role') IS NULL
    ALTER TABLE dbo.action_logs ADD role NVARCHAR(50) NOT NULL CONSTRAINT DF_action_logs_role_v2 DEFAULT 'unknown';
IF OBJECT_ID(N'dbo.action_logs', N'U') IS NOT NULL AND OBJECT_ID(N'dbo.helpdesk_action_logs', N'U') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM dbo.action_logs)
BEGIN
    SET IDENTITY_INSERT dbo.action_logs ON;
    INSERT INTO dbo.action_logs(id, username, role, action, device_name, interface_name, status, details_json, client_ip, user_agent, created_at)
    SELECT id, username, COALESCE(role, 'unknown'), action, device_name, interface_name, status, details_json, client_ip, user_agent, created_at
    FROM dbo.helpdesk_action_logs;
    SET IDENTITY_INSERT dbo.action_logs OFF;
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.monitoring_metrics', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_metrics (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL,
        collection_mode NVARCHAR(32) NOT NULL,
        status NVARCHAR(32) NOT NULL,
        severity NVARCHAR(32) NOT NULL,
        cpu_percent FLOAT NULL,
        memory_percent FLOAT NULL,
        interfaces_up INT NULL,
        interfaces_down INT NULL,
        sla_ms FLOAT NULL,
        details_json NVARCHAR(MAX) NOT NULL,
        collected_at NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF COL_LENGTH('dbo.monitoring_metrics', 'collected_at_utc') IS NULL
    ALTER TABLE dbo.monitoring_metrics ADD collected_at_utc NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_metrics_collected_at_utc DEFAULT '';
"""
        )
        conn.execute(
            """
IF COL_LENGTH('dbo.monitoring_metrics', 'collected_at_utc') IS NOT NULL
    UPDATE dbo.monitoring_metrics SET collected_at_utc = collected_at WHERE ISNULL(collected_at_utc, '') = '';
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.monitoring_device_profiles', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_device_profiles (
        device_name NVARCHAR(255) NOT NULL PRIMARY KEY,
        host NVARCHAR(64) NOT NULL,
        profile_json NVARCHAR(MAX) NOT NULL,
        created_at NVARCHAR(64) NOT NULL,
        updated_at NVARCHAR(64) NOT NULL
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.monitoring_interface_metrics', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_interface_metrics (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_host DEFAULT '',
        interface_name NVARCHAR(128) NOT NULL,
        interface_description NVARCHAR(255) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_desc DEFAULT '',
        oper_status NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_status DEFAULT 'unknown',
        tx_percent FLOAT NULL,
        rx_percent FLOAT NULL,
        collected_at_utc NVARCHAR(64) NOT NULL,
        details_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_monitoring_interface_metrics_details DEFAULT '{}'
    );
END
"""
        )
        conn.execute(
            """
IF OBJECT_ID(N'dbo.monitoring_alerts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.monitoring_alerts (
        id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        device_name NVARCHAR(255) NOT NULL,
        host NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_host DEFAULT '',
        alert_key NVARCHAR(128) NOT NULL,
        alert_type NVARCHAR(64) NOT NULL,
        severity NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_alerts_severity DEFAULT 'warning',
        status NVARCHAR(32) NOT NULL CONSTRAINT DF_monitoring_alerts_status DEFAULT 'open',
        message NVARCHAR(512) NOT NULL CONSTRAINT DF_monitoring_alerts_message DEFAULT '',
        threshold_value FLOAT NULL,
        last_value FLOAT NULL,
        opened_at NVARCHAR(64) NOT NULL,
        updated_at NVARCHAR(64) NOT NULL,
        sample_collected_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_sample_collected DEFAULT '',
        acked_by NVARCHAR(255) NOT NULL CONSTRAINT DF_monitoring_alerts_acked_by DEFAULT '',
        acked_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_acked_at DEFAULT '',
        cleared_at NVARCHAR(64) NOT NULL CONSTRAINT DF_monitoring_alerts_cleared_at DEFAULT '',
        details_json NVARCHAR(MAX) NOT NULL CONSTRAINT DF_monitoring_alerts_details DEFAULT '{}'
    );
END
"""
        )
        conn.execute(
            """
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_metrics_device_collected_at_utc' AND object_id = OBJECT_ID(N'dbo.monitoring_metrics'))
    CREATE INDEX IX_monitoring_metrics_device_collected_at_utc ON dbo.monitoring_metrics(device_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_collected_at_utc' AND object_id = OBJECT_ID(N'dbo.monitoring_interface_metrics'))
    CREATE INDEX IX_monitoring_interface_metrics_device_collected_at_utc ON dbo.monitoring_interface_metrics(device_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_interface_metrics_device_interface_time' AND object_id = OBJECT_ID(N'dbo.monitoring_interface_metrics'))
    CREATE INDEX IX_monitoring_interface_metrics_device_interface_time ON dbo.monitoring_interface_metrics(device_name, interface_name, collected_at_utc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_alerts_device_status' AND object_id = OBJECT_ID(N'dbo.monitoring_alerts'))
    CREATE INDEX IX_monitoring_alerts_device_status ON dbo.monitoring_alerts(device_name, status, updated_at DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_monitoring_alerts_device_key_status' AND object_id = OBJECT_ID(N'dbo.monitoring_alerts'))
    CREATE INDEX IX_monitoring_alerts_device_key_status ON dbo.monitoring_alerts(device_name, alert_key, status);
"""
        )
    migrate_legacy_json_to_db()


def migrate_legacy_json_to_db() -> None:
    with db_conn() as conn:
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0 and USERS_FILE.exists():
            try:
                data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    username = str(item.get("username", "")).strip()
                    if not username:
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO users(username, role, auth_source, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            username,
                            str(item.get("role", "operator")),
                            normalize_auth_source(item.get("auth_source", "local" if str(item.get("password_hash", "")) else "ldap")),
                            str(item.get("salt", "")),
                            str(item.get("password_hash", "")),
                            1 if bool(item.get("must_change_password", True)) else 0,
                            json.dumps(item.get("allowed_categories")),
                            json.dumps(item.get("admin_permissions", [])),
                            json.dumps(item.get("category_panel_access", {})),
                            json.dumps(item.get("account_privileges", ["ip_addressing", "network_addressing", "net_devices", "monitoring"])),
                        ),
                    )

        device_count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if device_count == 0 and DEVICES_FILE.exists():
            try:
                data = json.loads(DEVICES_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    hostname = str(item.get("name", item.get("hostname", ""))).strip()
                    ip_address = str(item.get("host", item.get("ip_address", ""))).strip()
                    if not hostname or not ip_address:
                        continue
                    conn.execute("INSERT OR REPLACE INTO devices(hostname, ip_address) VALUES (?, ?)", (hostname, ip_address))
                    for group in item.get("groups", []):
                        group_name = str(group).strip()
                        if group_name:
                            conn.execute("INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)", (hostname, group_name))

        creds_count = conn.execute("SELECT COUNT(*) FROM device_credentials").fetchone()[0]
        if creds_count == 0 and DEVICE_CREDS_FILE.exists():
            try:
                data = json.loads(DEVICE_CREDS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                for key, value in data.items():
                    if not isinstance(value, dict):
                        continue
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO device_credentials(account_key, username, password_enc, enable_password_enc)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            str(key),
                            str(value.get("username", "")).strip(),
                            encrypt_secret(str(value.get("password", ""))),
                            encrypt_secret(str(value.get("enable_password", ""))),
                        ),
                    )

        super_admin_count = conn.execute("SELECT COUNT(*) FROM super_admin").fetchone()[0]
        if super_admin_count == 0 and SUPER_ADMIN_FILE.exists():
            try:
                data = json.loads(SUPER_ADMIN_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                username = str(data.get("username", "")).strip()
                salt = str(data.get("salt", ""))
                password_hash = str(data.get("password_hash", ""))
                if username and salt and password_hash:
                    conn.execute(
                        "INSERT OR REPLACE INTO super_admin(id, username, salt, password_hash) VALUES (1, ?, ?, ?)",
                        (username, salt, password_hash),
                    )

        ise_count = conn.execute("SELECT COUNT(*) FROM ise_settings").fetchone()[0]
        if ise_count == 0 and ISE_SETTINGS_FILE.exists():
            try:
                data = json.loads(ISE_SETTINGS_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ise_settings(
                        id, primary_server, primary_port, primary_shared_secret,
                        secondary_server, secondary_port, secondary_shared_secret,
                        timeout, nas_ip
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(data.get("primary_server", "")).strip(),
                        int(data.get("primary_port", 1812) or 1812),
                        encrypt_secret(decrypt_secret(str(data.get("primary_shared_secret", "")))),
                        str(data.get("secondary_server", "")).strip(),
                        int(data.get("secondary_port", 1812) or 1812),
                        encrypt_secret(decrypt_secret(str(data.get("secondary_shared_secret", "")))),
                        int(data.get("timeout", 5) or 5),
                        str(data.get("nas_ip", "127.0.0.1")).strip(),
                    ),
                )


init_db()


def super_admin_exists() -> bool:
    with db_conn() as conn:
        row = conn.execute("SELECT username FROM super_admin WHERE id = 1").fetchone()
    return bool(row and str(row["username"]).strip())


def load_super_admin() -> dict[str, Any]:
    with db_conn() as conn:
        row = conn.execute("SELECT username, salt, password_hash FROM super_admin WHERE id = 1").fetchone()
    if not row:
        return {}
    return {
        "username": str(row["username"] or "").strip(),
        "salt": str(row["salt"] or ""),
        "password_hash": str(row["password_hash"] or ""),
    }


def save_super_admin(username: str, password: str) -> None:
    salt = secrets.token_hex(16)
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO super_admin(id, username, salt, password_hash) VALUES (1, ?, ?, ?)",
            (username.strip(), salt, _hash_password(password, salt)),
        )


def verify_super_admin(username: str, password: str) -> bool:
    data = load_super_admin()
    if not data:
        return False
    if username.strip() != str(data.get("username", "")):
        return False
    salt = str(data.get("salt", ""))
    expected = str(data.get("password_hash", ""))
    if not salt or not expected:
        return False
    actual = _hash_password(password, salt)
    return hmac.compare_digest(actual, expected)


def load_users() -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT username, role, auth_source, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges FROM users ORDER BY username"
        ).fetchall()

    for row in rows:
        allowed_raw = row["allowed_categories"]
        try:
            allowed_categories = json.loads(allowed_raw) if allowed_raw else None
        except Exception:
            allowed_categories = None
        admin_raw = row["admin_permissions"]
        try:
            admin_permissions = json.loads(admin_raw) if admin_raw else []
        except Exception:
            admin_permissions = []
        panel_raw = row["category_panel_access"] if "category_panel_access" in row.keys() else None
        try:
            category_panel_access = json.loads(panel_raw) if panel_raw else {}
        except Exception:
            category_panel_access = {}
        account_raw = row["account_privileges"] if "account_privileges" in row.keys() else None
        try:
            account_privileges = json.loads(account_raw) if account_raw else ["ip_addressing", "network_addressing", "net_devices", "monitoring"]
        except Exception:
            account_privileges = ["ip_addressing", "network_addressing", "net_devices", "monitoring"]
        user: dict[str, Any] = {
            "username": row["username"],
            "role": normalize_role(str(row["role"])),
            "auth_source": normalize_auth_source(row["auth_source"] if "auth_source" in row.keys() else ("local" if str(row["password_hash"] or "") else "ldap")),
            "salt": row["salt"],
            "password_hash": row["password_hash"],
            "must_change_password": bool(row["must_change_password"]),
            "allowed_categories": allowed_categories,
            "admin_permissions": admin_permissions,
            "category_panel_access": category_panel_access,
            "account_privileges": [str(item).strip() for item in account_privileges if str(item).strip()],
        }
        user["role"] = normalize_role(str(user.get("role", "junior")))
        user.setdefault("salt", "")
        user.setdefault("password_hash", "")
        user.setdefault("must_change_password", False)
        user.setdefault("auth_source", "ldap")
        user.setdefault("allowed_categories", None)
        user.setdefault("admin_permissions", [])
        user.setdefault("category_panel_access", {})
        user.setdefault("account_privileges", ["ip_addressing", "network_addressing", "net_devices", "monitoring"])
        normalized.append(user)
    return normalized


def save_users(users: list[dict[str, Any]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM users")
        for user in users:
            conn.execute(
                """
                INSERT INTO users(username, role, auth_source, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(user.get("username", "")).strip(),
                    normalize_role(str(user.get("role", "junior"))),
                    normalize_auth_source(user.get("auth_source", "ldap")),
                    str(user.get("salt", "")),
                    str(user.get("password_hash", "")),
                    1 if bool(user.get("must_change_password", True)) else 0,
                    json.dumps(user.get("allowed_categories")),
                    json.dumps(user.get("admin_permissions", [])),
                    json.dumps(user.get("category_panel_access", {})),
                    json.dumps(user.get("account_privileges", ["ip_addressing", "network_addressing", "net_devices", "monitoring"])),
                ),
            )


def is_provisioned_app_user(username: str) -> bool:
    check = str(username or "").strip().lower()
    if not check:
        return False
    return find_user(load_users(), check) is not None


def load_device_creds_store() -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT account_key, username, password_enc, enable_password_enc FROM device_credentials"
        ).fetchall()

    for row in rows:
        normalized[str(row["account_key"])] = {
            "username": str(row["username"] or "").strip(),
            "password": decrypt_secret(str(row["password_enc"] or "")),
            "enable_password": decrypt_secret(str(row["enable_password_enc"] or "")),
        }
    return normalized


def save_device_creds_store(store: dict[str, dict[str, str]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM device_credentials")
        for account_key, value in store.items():
            conn.execute(
                """
                INSERT INTO device_credentials(account_key, username, password_enc, enable_password_enc)
                VALUES (?, ?, ?, ?)
                """,
                (
                    str(account_key),
                    str(value.get("username", "")).strip(),
                    encrypt_secret(str(value.get("password", ""))),
                    encrypt_secret(str(value.get("enable_password", ""))),
                ),
            )


def device_creds_key(account_username: str, auth_mode: str) -> str:
    return f"{auth_mode.strip().lower()}::{account_username.strip().lower()}"


def load_user_device_creds(account_username: str, auth_mode: str) -> dict[str, str]:
    store = load_device_creds_store()
    return dict(store.get(device_creds_key(account_username, auth_mode), {}))


def save_user_device_creds(account_username: str, auth_mode: str, creds: dict[str, str]) -> None:
    store = load_device_creds_store()
    store[device_creds_key(account_username, auth_mode)] = {
        "username": str(creds.get("username", "")).strip(),
        "password": str(creds.get("password", "")),
        "enable_password": str(creds.get("enable_password", "")),
    }
    save_device_creds_store(store)


def _load_app_setting_json(setting_key: str, default_value: Any, legacy_file: Any | None = None) -> Any:
    with db_conn() as conn:
        row = conn.execute("SELECT setting_json FROM app_settings WHERE setting_key = ?", (setting_key,)).fetchone()
        if row and str(row["setting_json"] or "").strip():
            try:
                return json.loads(str(row["setting_json"]))
            except Exception:
                return default_value

    if legacy_file is not None and getattr(legacy_file, "exists", lambda: False)():
        try:
            legacy_value = json.loads(legacy_file.read_text(encoding="utf-8"))
            _save_app_setting_json(setting_key, legacy_value)
            return legacy_value
        except Exception:
            return default_value
    return default_value


def _save_app_setting_json(setting_key: str, payload: Any) -> None:
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO app_settings(setting_key, setting_json, updated_at) VALUES (?, ?, ?)",
            (setting_key, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )


def load_user_buttons_store() -> dict[str, list[dict[str, Any]]]:
    data = _load_app_setting_json("user_buttons_store", {}, USER_BUTTONS_FILE)
    if not isinstance(data, dict):
        return {}

    normalized: dict[str, list[dict[str, Any]]] = {}
    for key, value in data.items():
        normalized[str(key)] = normalize_buttons(value)
    return normalized


def save_user_buttons_store(store: dict[str, list[dict[str, Any]]]) -> None:
    _save_app_setting_json("user_buttons_store", store)


def load_user_buttons(account_username: str, auth_mode: str) -> list[dict[str, Any]]:
    _ = device_creds_key(account_username, auth_mode)
    global_key = "__global__"
    store = load_user_buttons_store()
    global_buttons = normalize_buttons(store.get(global_key, []))
    if global_buttons:
        return global_buttons
    # One-time migration path: promote first existing non-empty legacy button set to global.
    for legacy_buttons in store.values():
        migrated = normalize_buttons(legacy_buttons)
        if migrated:
            store[global_key] = migrated
            save_user_buttons_store(store)
            return migrated
    # Backward compatibility: if old per-user storage exists, read it.
    legacy_key = device_creds_key(account_username, auth_mode)
    return normalize_buttons(store.get(legacy_key, []))


def save_user_buttons(account_username: str, auth_mode: str, buttons: list[dict[str, Any]]) -> None:
    _ = device_creds_key(account_username, auth_mode)
    global_key = "__global__"
    store = load_user_buttons_store()
    store[global_key] = normalize_buttons(buttons)
    save_user_buttons_store(store)


def default_session_settings() -> dict[str, Any]:
    return {
        "idle_timeout_minutes": 15,
        "http_enabled": True,
        "https_enabled": False,
        "http_port": 8080,
        "https_port": 8443,
        "web_acl_enabled": False,
        "web_acl_entries": [],
        "login_lockout_enabled": False,
        "login_lockout_max_attempts": 5,
        "login_lockout_seconds": 300,
    }


def load_session_settings() -> dict[str, Any]:
    data = _load_app_setting_json("session_settings", {}, SESSION_SETTINGS_FILE)
    defaults = default_session_settings()
    defaults.update(data if isinstance(data, dict) else {})
    defaults["idle_timeout_minutes"] = int(defaults.get("idle_timeout_minutes", 15) or 15)
    raw = data if isinstance(data, dict) else {}
    https_enabled = bool(defaults.get("https_enabled", False))
    if "http_enabled" in raw:
        http_enabled = bool(raw.get("http_enabled", True))
    else:
        # Compatibility mode: if legacy payload has https_enabled only,
        # keep HTTP enabled by default unless explicitly disabled.
        http_enabled = True
    defaults["http_enabled"] = bool(http_enabled)
    defaults["https_enabled"] = bool(https_enabled)
    if not defaults["http_enabled"] and not defaults["https_enabled"]:
        defaults["http_enabled"] = True
    try:
        http_port = int(defaults.get("http_port", 8080) or 8080)
    except Exception:
        http_port = 8080
    try:
        https_port = int(defaults.get("https_port", 8443) or 8443)
    except Exception:
        https_port = 8443
    defaults["http_port"] = max(1, min(65535, http_port))
    defaults["https_port"] = max(1, min(65535, https_port))
    defaults["web_acl_enabled"] = bool(defaults.get("web_acl_enabled", False))
    acl_entries, _ = _normalize_web_acl_entries(defaults.get("web_acl_entries", []))
    defaults["web_acl_entries"] = acl_entries
    defaults["web_acl_text"] = "\n".join(acl_entries)
    defaults["login_lockout_enabled"] = bool(defaults.get("login_lockout_enabled", False))
    try:
        lock_attempts = int(defaults.get("login_lockout_max_attempts", 5) or 5)
    except Exception:
        lock_attempts = 5
    try:
        if "login_lockout_seconds" in defaults:
            lock_seconds = int(defaults.get("login_lockout_seconds", 300) or 300)
        else:
            # Backward compatibility with old minutes setting.
            lock_seconds = int(defaults.get("login_lockout_minutes", 5) or 5) * 60
    except Exception:
        lock_seconds = 300
    defaults["login_lockout_max_attempts"] = max(1, min(20, lock_attempts))
    defaults["login_lockout_seconds"] = max(1, min(86400, lock_seconds))
    return defaults


def save_session_settings(settings: dict[str, Any]) -> None:
    http_enabled = bool(settings.get("http_enabled", True))
    https_enabled = bool(settings.get("https_enabled", False))
    if not http_enabled and not https_enabled:
        http_enabled = True
    acl_entries, _ = _normalize_web_acl_entries(settings.get("web_acl_entries", []))
    lock_attempts = max(1, min(20, int(settings.get("login_lockout_max_attempts", 5) or 5)))
    lock_seconds = max(1, min(86400, int(settings.get("login_lockout_seconds", 300) or 300)))
    payload = {
        "idle_timeout_minutes": max(1, int(settings.get("idle_timeout_minutes", 15) or 15)),
        "http_enabled": http_enabled,
        "https_enabled": https_enabled,
        "http_port": max(1, min(65535, int(settings.get("http_port", 8080) or 8080))),
        "https_port": max(1, min(65535, int(settings.get("https_port", 8443) or 8443))),
        "web_acl_enabled": bool(settings.get("web_acl_enabled", False)),
        "web_acl_entries": acl_entries,
        "login_lockout_enabled": bool(settings.get("login_lockout_enabled", False)),
        "login_lockout_max_attempts": lock_attempts,
        "login_lockout_seconds": lock_seconds,
    }
    _save_app_setting_json("session_settings", payload)


def default_ntp_settings() -> dict[str, Any]:
    return {
        "mode": "ntp",
        "server": "",
        "port": 123,
        "sync_timeout": 3,
        "manual_time": "",
        "last_sync": "",
        "last_status": "Not synchronized yet.",
    }


def load_ntp_settings() -> dict[str, Any]:
    if not NTP_SETTINGS_FILE.exists():
        return default_ntp_settings()
    with NTP_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_ntp_settings()
    if isinstance(data, dict):
        defaults.update(data)
    return defaults


def save_ntp_settings(settings: dict[str, Any]) -> None:
    payload = {
        "mode": str(settings.get("mode", "ntp")).strip().lower() or "ntp",
        "server": str(settings.get("server", "")).strip(),
        "port": int(settings.get("port", 123) or 123),
        "sync_timeout": int(settings.get("sync_timeout", 3) or 3),
        "manual_time": str(settings.get("manual_time", "")),
        "last_sync": str(settings.get("last_sync", "")),
        "last_status": str(settings.get("last_status", "")),
    }
    with NTP_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def default_external_logging_settings() -> dict[str, Any]:
    return {
        "enabled": False,
        "server": "",
        "port": 514,
        "protocol": "udp",
        "source_name": "ndmc-app",
        "notes": "",
    }


def load_external_logging_settings() -> dict[str, Any]:
    if not EXTERNAL_LOGGING_SETTINGS_FILE.exists():
        return default_external_logging_settings()
    with EXTERNAL_LOGGING_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_external_logging_settings()
    if isinstance(data, dict):
        defaults.update(data)
    defaults["enabled"] = bool(defaults.get("enabled", False))
    defaults["server"] = str(defaults.get("server", "")).strip()
    defaults["port"] = int(defaults.get("port", 514) or 514)
    protocol = str(defaults.get("protocol", "udp")).strip().lower() or "udp"
    defaults["protocol"] = protocol if protocol in {"udp", "tcp", "tls"} else "udp"
    defaults["source_name"] = str(defaults.get("source_name", "ndmc-app")).strip() or "ndmc-app"
    defaults["notes"] = str(defaults.get("notes", "")).strip()
    return defaults


def save_external_logging_settings(settings: dict[str, Any]) -> None:
    payload = {
        "enabled": bool(settings.get("enabled", False)),
        "server": str(settings.get("server", "")).strip(),
        "port": int(settings.get("port", 514) or 514),
        "protocol": str(settings.get("protocol", "udp")).strip().lower() or "udp",
        "source_name": str(settings.get("source_name", "ndmc-app")).strip() or "ndmc-app",
        "notes": str(settings.get("notes", "")).strip(),
    }
    if payload["protocol"] not in {"udp", "tcp", "tls"}:
        payload["protocol"] = "udp"
    with EXTERNAL_LOGGING_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def default_monitoring_settings() -> dict[str, Any]:
    return {
        "enabled": True,
        "collection_mode": "telemetry",
        "collector_host": "",
        "collector_port": 57000,
        "transport": "grpc",
        "username": "",
        "password": "",
        "token": "",
        "interval_seconds": 30,
        "metrics": "cpu,memory,interfaces,sla",
        "monitored_devices": [],
        "category_options": ["Router", "Switch", "ATM", "Servers", "Windows Servers", "Firewalls", "Uncategorized"],
        "notes": "",
    }


def load_monitoring_settings() -> dict[str, Any]:
    if not MONITORING_SETTINGS_FILE.exists():
        return default_monitoring_settings()
    with MONITORING_SETTINGS_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    defaults = default_monitoring_settings()
    if isinstance(data, dict):
        defaults.update(data)
    defaults["enabled"] = bool(defaults.get("enabled", False))
    mode = str(defaults.get("collection_mode", "telemetry")).strip().lower() or "telemetry"
    defaults["collection_mode"] = mode if mode in {"telemetry", "snmp", "snmp_v2", "snmp_v3", "ssh", "api", "winrm"} else "telemetry"
    defaults["collector_host"] = str(defaults.get("collector_host", "")).strip()
    defaults["collector_port"] = int(defaults.get("collector_port", 57000) or 57000)
    transport = str(defaults.get("transport", "grpc")).strip().lower() or "grpc"
    defaults["transport"] = transport if transport in {"grpc", "tcp", "udp", "http"} else "grpc"
    defaults["username"] = str(defaults.get("username", "")).strip()
    defaults["password"] = str(defaults.get("password", "")).strip()
    defaults["token"] = str(defaults.get("token", "")).strip()
    defaults["interval_seconds"] = int(defaults.get("interval_seconds", 30) or 30)
    defaults["metrics"] = str(defaults.get("metrics", "cpu,memory,interfaces,sla")).strip() or "cpu,memory,interfaces,sla"
    raw_devices = defaults.get("monitored_devices", [])
    if isinstance(raw_devices, list):
        defaults["monitored_devices"] = [str(item).strip() for item in raw_devices if str(item).strip()]
    else:
        defaults["monitored_devices"] = []
    raw_categories = defaults.get("category_options", [])
    if isinstance(raw_categories, list):
        categories = [str(item).strip() for item in raw_categories if str(item).strip()]
    else:
        categories = []
    required = ["Router", "Switch", "ATM", "Servers", "Windows Servers", "Firewalls", "Uncategorized"]
    for item in required:
        if item not in categories:
            categories.append(item)
    defaults["category_options"] = categories
    defaults["notes"] = str(defaults.get("notes", "")).strip()
    return defaults


def save_monitoring_settings(settings: dict[str, Any]) -> None:
    raw_devices = settings.get("monitored_devices", [])
    if isinstance(raw_devices, list):
        monitored_devices = [str(item).strip() for item in raw_devices if str(item).strip()]
    else:
        monitored_devices = []
    raw_categories = settings.get("category_options", [])
    if isinstance(raw_categories, list):
        category_options = [str(item).strip() for item in raw_categories if str(item).strip()]
    else:
        category_options = []
    required = ["Router", "Switch", "ATM", "Servers", "Windows Servers", "Firewalls", "Uncategorized"]
    for item in required:
        if item not in category_options:
            category_options.append(item)
    payload = {
        "enabled": bool(settings.get("enabled", False)),
        "collection_mode": str(settings.get("collection_mode", "telemetry")).strip().lower() or "telemetry",
        "collector_host": str(settings.get("collector_host", "")).strip(),
        "collector_port": int(settings.get("collector_port", 57000) or 57000),
        "transport": str(settings.get("transport", "grpc")).strip().lower() or "grpc",
        "username": str(settings.get("username", "")).strip(),
        "password": str(settings.get("password", "")).strip(),
        "token": str(settings.get("token", "")).strip(),
        "interval_seconds": int(settings.get("interval_seconds", 30) or 30),
        "metrics": str(settings.get("metrics", "cpu,memory,interfaces,sla")).strip() or "cpu,memory,interfaces,sla",
        "monitored_devices": monitored_devices,
        "category_options": category_options,
        "notes": str(settings.get("notes", "")).strip(),
    }
    if payload["collection_mode"] not in {"telemetry", "snmp", "snmp_v2", "snmp_v3", "ssh", "api", "winrm"}:
        payload["collection_mode"] = "telemetry"
    if payload["transport"] not in {"grpc", "tcp", "udp", "http"}:
        payload["transport"] = "grpc"
    payload["collector_port"] = max(1, min(65535, payload["collector_port"]))
    payload["interval_seconds"] = max(5, min(3600, payload["interval_seconds"]))
    with MONITORING_SETTINGS_FILE.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_monitoring_category_options() -> list[str]:
    settings = load_monitoring_settings()
    raw = settings.get("category_options", [])
    if isinstance(raw, list):
        out = [str(item).strip() for item in raw if str(item).strip()]
    else:
        out = []
    required = ["Router", "Switch", "ATM", "Servers", "Windows Servers", "Firewalls", "Uncategorized"]
    for item in required:
        if item not in out:
            out.append(item)
    return out


def ensure_monitoring_category_exists(category_name: str) -> None:
    name = str(category_name or "").strip()
    if not name:
        return
    settings = load_monitoring_settings()
    raw = settings.get("category_options", [])
    categories = [str(item).strip() for item in raw] if isinstance(raw, list) else []
    if name not in categories:
        categories.append(name)
        settings["category_options"] = categories
        save_monitoring_settings(settings)


def load_monitoring_device_profiles() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT device_name, host, profile_json, created_at, updated_at FROM monitoring_device_profiles"
        ).fetchall()
    for row in rows:
        name = str(row["device_name"]).strip()
        if not name:
            continue
        payload_raw = str(row["profile_json"] or "{}")
        try:
            payload = json.loads(payload_raw)
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        payload["device_name"] = name
        payload["host"] = str(row["host"] or payload.get("host", "")).strip()
        payload["created_at"] = str(row["created_at"] or "")
        payload["updated_at"] = str(row["updated_at"] or "")
        out[name.lower()] = payload
    return out


def save_monitoring_device_profile(device_name: str, host: str, profile: dict[str, Any]) -> None:
    name = str(device_name).strip()
    ip = str(host).strip()
    if not name or not ip:
        return
    now = datetime.now(timezone.utc).isoformat()
    payload = dict(profile or {})
    payload["device_name"] = name
    payload["host"] = ip
    with db_conn() as conn:
        updated = conn.execute(
            "UPDATE monitoring_device_profiles SET host = ?, profile_json = ?, updated_at = ? WHERE device_name = ?",
            (ip, json.dumps(payload), now, name),
        ).rowcount
        if int(updated or 0) <= 0:
            conn.execute(
                """
                INSERT INTO monitoring_device_profiles(device_name, host, profile_json, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?)
                """,
                (name, ip, json.dumps(payload), now, now),
            )


def rename_device_everywhere(old_name: str, new_name: str, new_ip: str) -> None:
    old_key = str(old_name).strip()
    new_key = str(new_name).strip()
    ip = str(new_ip).strip()
    if not old_key or not new_key or not ip:
        return
    with db_conn() as conn:
        conn.execute("UPDATE devices SET hostname = ?, ip_address = ? WHERE hostname = ?", (new_key, ip, old_key))
        conn.execute("UPDATE device_groups SET hostname = ? WHERE hostname = ?", (new_key, old_key))
        conn.execute("UPDATE monitoring_metrics SET device_name = ?, host = ? WHERE device_name = ?", (new_key, ip, old_key))


def delete_device_everywhere(device_name: str) -> None:
    name = str(device_name).strip()
    if not name:
        return
    with db_conn() as conn:
        conn.execute("DELETE FROM monitoring_device_profiles WHERE device_name = ?", (name,))
        conn.execute("DELETE FROM monitoring_metrics WHERE device_name = ?", (name,))
        conn.execute("DELETE FROM device_groups WHERE hostname = ?", (name,))
        conn.execute("DELETE FROM devices WHERE hostname = ?", (name,))


def upsert_device_and_category_for_monitoring(device_name: str, ip_address: str, category: str) -> None:
    name = str(device_name).strip()
    ip = str(ip_address).strip()
    cat = str(category).strip()
    if not name or not ip:
        return
    with db_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO devices(hostname, ip_address) VALUES (?, ?)", (name, ip))
        if cat:
            conn.execute("INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)", (name, cat))


def is_windows_servers_category(category_name: str) -> bool:
    text = re.sub(r"[\s_\-]+", "", str(category_name or "").strip().lower())
    return text in {"windowsservers", "windowsserver", "windowssrv"}


def monitoring_effective_settings(global_settings: dict[str, Any], device_profile: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(global_settings or {})
    profile = dict(device_profile or {})
    method = str(profile.get("polling_method", "")).strip().lower()
    profile_category = str(profile.get("category", "")).strip()
    if is_windows_servers_category(profile_category):
        # Force WinRM collection for Windows Servers, even for legacy profiles.
        method = "winrm_icmp"
        profile["polling_method"] = method
    if method:
        mapping = {
            "status_only": "status_only",
            "snmp_v2": "snmp_v2",
            "snmp_v3": "snmp_v3",
            "winrm_icmp": "winrm",
            "api": "api",
            "ssh": "ssh",
            "telemetry": "telemetry",
        }
        merged["collection_mode"] = mapping.get(method, merged.get("collection_mode", "telemetry"))
    if method == "winrm_icmp":
        merged["collection_mode"] = "winrm"
        merged["winrm_port"] = int(profile.get("winrm_port", 5985) or 5985)
        merged["winrm_auth"] = str(profile.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
        merged["username"] = str(profile.get("winrm_username", "")).strip() or str(merged.get("username", "")).strip()
        merged["password"] = str(profile.get("winrm_password", "")).strip() or str(merged.get("password", "")).strip()
    # Apply SNMP-specific profile fields only when polling method is SNMP-based.
    if method in {"snmp_v2", "snmp_v3", "snmp"}:
        snmp_version = str(profile.get("snmp_version", "")).strip().lower()
        if snmp_version in {"2c", "v2c", "snmpv2c"}:
            merged["collection_mode"] = "snmp_v2"
            if str(profile.get("community", "")).strip():
                merged["token"] = str(profile.get("community", "")).strip()
        elif snmp_version in {"3", "v3", "snmpv3"}:
            merged["collection_mode"] = "snmp_v3"
            merged["username"] = str(profile.get("snmpv3_username", "")).strip() or str(merged.get("username", "")).strip()
            merged["password"] = str(profile.get("snmpv3_auth_password", "")).strip() or str(merged.get("password", "")).strip()
            merged["token"] = str(profile.get("snmpv3_priv_password", "")).strip() or str(merged.get("token", "")).strip()
            merged["snmpv3_auth_protocol"] = str(profile.get("snmpv3_auth_protocol", "")).strip() or str(merged.get("snmpv3_auth_protocol", "sha")).strip()
            merged["snmpv3_priv_protocol"] = str(profile.get("snmpv3_priv_protocol", "")).strip() or str(merged.get("snmpv3_priv_protocol", "aes128")).strip()
    if str(profile.get("interval_seconds", "")).strip().isdigit():
        merged["interval_seconds"] = int(str(profile.get("interval_seconds", "30")).strip() or 30)
    metrics_override = str(profile.get("metrics_override", "")).strip()
    if metrics_override:
        merged["metrics"] = metrics_override
    selected_resources = profile.get("selected_resources", {}) if isinstance(profile.get("selected_resources", {}), dict) else {}
    interfaces_saved = selected_resources.get("interfaces", []) if isinstance(selected_resources.get("interfaces", []), list) else []
    if interfaces_saved:
        merged["selected_interfaces"] = [str(item).strip() for item in interfaces_saved if str(item).strip()]
    else:
        interfaces_watch = str(profile.get("interfaces_watch", "")).strip()
        if interfaces_watch and interfaces_watch.lower() != "all":
            merged["selected_interfaces"] = [str(item).strip() for item in interfaces_watch.split(",") if str(item).strip()]
    return merged


def _monitoring_device_lookup(device_name: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    name = str(device_name or "").strip()
    key = name.lower()
    profiles = load_monitoring_device_profiles()
    profile = dict(profiles.get(key, {}))
    all_devices = load_devices()
    base_device = next((item for item in all_devices if str(item.get("name", "")).strip().lower() == key), {})
    host = str(profile.get("host", "")).strip() or str(base_device.get("host", "")).strip()
    return base_device, profile, host


def _monitoring_effective_category(device_name: str) -> str:
    base_device, profile, _ = _monitoring_device_lookup(device_name)
    profile_category = str(profile.get("category", "")).strip()
    if profile_category:
        return profile_category
    groups = base_device.get("groups", []) if isinstance(base_device, dict) else []
    if isinstance(groups, list) and groups:
        return str(groups[0]).strip()
    return ""


def _monitoring_pull_ssh_creds(profile: dict[str, Any], account_username: str, auth_mode: str) -> dict[str, Any]:
    profile_username = str(profile.get("ssh_username", "")).strip()
    profile_password = str(profile.get("ssh_password", ""))
    profile_enable = str(profile.get("enable_password", ""))
    if profile_username and profile_password:
        return {
            "username": profile_username,
            "password": profile_password,
            "enable_password": profile_enable,
        }
    stored = load_user_device_creds(account_username, auth_mode)
    return {
        "username": str(stored.get("username", "")).strip(),
        "password": str(stored.get("password", "")),
        "enable_password": str(stored.get("enable_password", "")),
    }


def parse_monitoring_metrics(metrics_text: str) -> set[str]:
    allowed = {"cpu", "memory", "interfaces", "sla"}
    items = [str(item).strip().lower() for item in str(metrics_text or "").split(",")]
    selected = {item for item in items if item in allowed}
    return selected or {"cpu", "memory", "interfaces", "sla"}


def _cap_percent(value: Any) -> float | None:
    try:
        number = float(value)
    except Exception:
        return None
    if not (number == number):  # NaN
        return None
    if number == float("inf") or number == float("-inf"):
        return None
    return max(0.0, min(100.0, number))


def ping_host_status(host: str, timeout_seconds: int = 2) -> tuple[str, float | None]:
    addr = str(host or "").strip()
    if not addr:
        return "down", None
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(max(500, timeout_seconds * 1000)), addr]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_seconds)), addr]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return "down", None
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    latency: float | None = None
    match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", output, flags=re.IGNORECASE)
    if match:
        try:
            latency = float(match.group(1))
        except Exception:
            latency = None
    return ("up" if result.returncode == 0 else "down"), latency


def winrm_collect_metrics(host: str, settings: dict[str, Any], timeout_seconds: int = 8) -> tuple[dict[str, Any], list[str]]:
    if not WINRM_AVAILABLE or winrm is None:
        return {}, ["pywinrm_not_installed"]
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    if not username or not password:
        return {}, ["winrm_credentials_missing"]
    try:
        winrm_port = max(1, min(65535, int(settings.get("winrm_port", 5985) or 5985)))
    except Exception:
        winrm_port = 5985
    auth = str(settings.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
    if auth not in {"ntlm", "kerberos", "basic", "credssp"}:
        auth = "ntlm"
    scheme = "https" if winrm_port == 5986 else "http"
    endpoint = f"{scheme}://{host}:{winrm_port}/wsman"
    errors: list[str] = []
    metrics: dict[str, Any] = {
        "cpu_percent": None,
        "memory_percent": None,
        "uptime_seconds": None,
        "last_boot": "",
        "network_rx_mbps": None,
        "network_tx_mbps": None,
        "windows_caption": "",
        "windows_version": "",
        "windows_build": "",
        "windows_arch": "",
        "computer_name": "",
        "computer_model": "",
        "domain": "",
        "total_memory_gb": None,
        "free_memory_gb": None,
        "disk_usage": [],
        "interface_utilization": [],
    }

    ps_preamble = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"

    def _parse_num(text: str) -> float | None:
        raw = str(text or "").strip()
        if not raw:
            return None
        cleaned = raw.replace("%", "").strip()
        candidate = raw.replace(",", ".")
        try:
            return float(candidate)
        except Exception:
            try:
                candidate = cleaned.replace(",", ".")
                return float(candidate)
            except Exception:
                match = re.search(r"[-+]?\d+(?:[.,]\d+)?", cleaned)
                if not match:
                    return None
                token = match.group(0).replace(",", ".")
                try:
                    return float(token)
                except Exception:
                    return None

    def _is_ignorable_ps_stderr(text: str) -> bool:
        raw = str(text or "").strip().lower()
        if not raw:
            return True
        return "preparing modules for first use" in raw and "clixml" in raw

    def _trim_error(text: str, max_len: int = 700) -> str:
        raw = str(text or "").strip()
        if len(raw) <= max_len:
            return raw
        return raw[:max_len] + "..."
    try:
        session = winrm.Session(target=endpoint, auth=(username, password), transport=auth)
    except Exception as exc:
        return metrics, [f"session_init:{exc}"]

    try:
        cpu_cmd = (
            f"{ps_preamble}"
            "$cpu='';"
            "try{$cpu=((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{"
            "try{$cpu=((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{}"
            "};"
            "if($cpu -ne '' -and $cpu -ne $null){[math]::Round([double]$cpu,2)}else{''}"
        )
        cpu_result = session.run_ps(cpu_cmd)
        cpu_status = int(getattr(cpu_result, "status_code", 1) or 1)
        cpu_text = (cpu_result.std_out or b"").decode(errors="ignore").strip()
        if cpu_text:
                cpu_num = _parse_num(cpu_text)
                if cpu_num is not None:
                    metrics["cpu_percent"] = _cap_percent(cpu_num)
        if metrics.get("cpu_percent") is None and cpu_status != 0:
            stderr = (cpu_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"cpu:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"cpu:{exc}")

    try:
        mem_cmd = (
            f"{ps_preamble}"
            "$os=$null;"
            "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
            "if($os -and $os.TotalVisibleMemorySize -gt 0){"
            "$used=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
            "[math]::Round(($used*100)/[double]$os.TotalVisibleMemorySize,2)"
            "}else{''}"
        )
        mem_result = session.run_ps(mem_cmd)
        mem_status = int(getattr(mem_result, "status_code", 1) or 1)
        mem_text = (mem_result.std_out or b"").decode(errors="ignore").strip()
        if mem_text:
            mem_num = _parse_num(mem_text)
            if mem_num is not None:
                metrics["memory_percent"] = mem_num
        if metrics.get("memory_percent") is None and mem_status != 0:
            stderr = (mem_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"memory:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"memory:{exc}")

    try:
        extra_cmd = (
            f"{ps_preamble}"
            "$os=$null;"
            "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
            "$boot='';$uptime=0;"
            "if($os){$boot=$os.LastBootUpTime; if($boot){$uptime=(New-TimeSpan -Start $boot -End (Get-Date)).TotalSeconds}};"
            "$boot_iso=''; if($boot){$boot_iso=([DateTime]$boot).ToString('o')};"
            "$caption='';$version='';$build='';$arch='';$hostn='';$domain='';$model='';$totalMemGb=$null;$freeMemGb=$null;"
            "if($os){"
            "$caption=[string]$os.Caption;"
            "$version=[string]$os.Version;"
            "$build=[string]$os.BuildNumber;"
            "$arch=[string]$os.OSArchitecture;"
            "if($os.TotalVisibleMemorySize -gt 0){$totalMemGb=[Math]::Round(([double]$os.TotalVisibleMemorySize/1024/1024),2)};"
            "if($os.FreePhysicalMemory -ge 0){$freeMemGb=[Math]::Round(([double]$os.FreePhysicalMemory/1024/1024),2)}"
            "};"
            "$hostn=[string]$env:COMPUTERNAME;"
            "$cs=$null; try{$cs=Get-CimInstance Win32_ComputerSystem}catch{try{$cs=Get-WmiObject Win32_ComputerSystem}catch{}};"
            "if($cs){$domain=[string]$cs.Domain; $model=[string]$cs.Model};"
            "$mem=0;"
            "if($os -and $os.TotalVisibleMemorySize -gt 0){"
            "$usedMem=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
            "$mem=[math]::Round(($usedMem*100)/[double]$os.TotalVisibleMemorySize,2)"
            "};"
            "$rx=0;$tx=0;"
            "try{$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{"
            "try{$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{}"
            "};"
            "$d=@();"
            "try{$d=Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object @{N='label';E={$_.DeviceID}}, @{N='size';E={[double]$_.Size}}, @{N='free';E={[double]$_.FreeSpace}}}catch{"
            "try{$d=Get-WmiObject Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object @{N='label';E={$_.DeviceID}}, @{N='size';E={[double]$_.Size}}, @{N='free';E={[double]$_.FreeSpace}}}catch{}"
            "};"
            "$payload=[PSCustomObject]@{"
            "last_boot=$boot_iso;"
            "uptime_seconds=[int][Math]::Round([double]$uptime,0);"
            "windows_caption=$caption;"
            "windows_version=$version;"
            "windows_build=$build;"
            "windows_arch=$arch;"
            "computer_name=$hostn;"
            "computer_model=$model;"
            "domain=$domain;"
            "total_memory_gb=$totalMemGb;"
            "free_memory_gb=$freeMemGb;"
            "memory_percent=[Math]::Round([double]$mem,2);"
            "network_rx_mbps=[Math]::Round(([double]$rx*8/1000000),2);"
            "network_tx_mbps=[Math]::Round(([double]$tx*8/1000000),2);"
            "disks=$d"
            "};"
            "$payload|ConvertTo-Json -Depth 5 -Compress"
        )
        extra_result = session.run_ps(extra_cmd)
        extra_status = int(getattr(extra_result, "status_code", 1) or 1)
        extra_text = (extra_result.std_out or b"").decode(errors="ignore").strip()
        parsed_ok = False
        if extra_text:
            try:
                parsed = json.loads(extra_text)
            except Exception:
                parsed = {}
            if isinstance(parsed, dict):
                parsed_ok = True
                metrics["last_boot"] = str(parsed.get("last_boot", "")).strip()
                metrics["uptime_seconds"] = parsed.get("uptime_seconds")
                metrics["windows_caption"] = str(parsed.get("windows_caption", "")).strip()
                metrics["windows_version"] = str(parsed.get("windows_version", "")).strip()
                metrics["windows_build"] = str(parsed.get("windows_build", "")).strip()
                metrics["windows_arch"] = str(parsed.get("windows_arch", "")).strip()
                metrics["computer_name"] = str(parsed.get("computer_name", "")).strip()
                metrics["computer_model"] = str(parsed.get("computer_model", "")).strip()
                metrics["domain"] = str(parsed.get("domain", "")).strip()
                metrics["total_memory_gb"] = parsed.get("total_memory_gb")
                metrics["free_memory_gb"] = parsed.get("free_memory_gb")
                if metrics.get("memory_percent") is None:
                    mem_extra = _parse_num(str(parsed.get("memory_percent", "")))
                    if mem_extra is not None:
                        metrics["memory_percent"] = mem_extra
                metrics["network_rx_mbps"] = parsed.get("network_rx_mbps")
                metrics["network_tx_mbps"] = parsed.get("network_tx_mbps")
                raw_disks = parsed.get("disks", [])
                disks = raw_disks if isinstance(raw_disks, list) else ([raw_disks] if isinstance(raw_disks, dict) else [])
                out_disks: list[dict[str, Any]] = []
                for d in disks:
                    if not isinstance(d, dict):
                        continue
                    label = str(d.get("label", "")).strip()
                    try:
                        size = float(d.get("size", 0) or 0)
                        free = float(d.get("free", 0) or 0)
                    except Exception:
                        size = 0.0
                        free = 0.0
                    used_pct = None
                    if size > 0:
                        used_pct = max(0.0, min(100.0, ((size - free) * 100.0) / size))
                    out_disks.append(
                        {
                            "label": label or "-",
                            "used_percent": used_pct,
                            "free_gb": round(max(0.0, free) / (1024.0**3), 2),
                        }
                    )
                metrics["disk_usage"] = out_disks
        if not parsed_ok and extra_status != 0:
            stderr = (extra_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"extras:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"extras:{exc}")

    try:
        iface_cmd = (
            f"{ps_preamble}"
            "$rows=@();"
            "try{"
            "$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface;"
            "if(-not $n){$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface};"
            "foreach($i in $n){"
            "$name=[string]$i.Name;"
            "if(-not $name){continue};"
            "$bw=[double]$i.CurrentBandwidth;"
            "$tx=0;$rx=0;"
            "if($bw -gt 0){"
            "$tx=[Math]::Round(([double]$i.BytesSentPersec*8*100)/$bw,2);"
            "$rx=[Math]::Round(([double]$i.BytesReceivedPersec*8*100)/$bw,2)"
            "};"
            "if($tx -lt 0){$tx=0}; if($tx -gt 100){$tx=100};"
            "if($rx -lt 0){$rx=0}; if($rx -gt 100){$rx=100};"
            "$rows += [PSCustomObject]@{interface=$name;status='up';description='';tx_percent=$tx;rx_percent=$rx}"
            "}"
            "}catch{};"
            "$rows|ConvertTo-Json -Depth 4 -Compress"
        )
        iface_result = session.run_ps(iface_cmd)
        iface_status = int(getattr(iface_result, "status_code", 1) or 1)
        iface_text = (iface_result.std_out or b"").decode(errors="ignore").strip()
        parsed_ifaces: list[dict[str, Any]] = []
        if iface_text:
            try:
                iface_obj = json.loads(iface_text)
            except Exception:
                iface_obj = []
            iface_rows = iface_obj if isinstance(iface_obj, list) else ([iface_obj] if isinstance(iface_obj, dict) else [])
            for item in iface_rows:
                if not isinstance(item, dict):
                    continue
                iface_name = str(item.get("interface", "")).strip()
                if not iface_name:
                    continue
                tx_val = _parse_num(str(item.get("tx_percent", "")))
                rx_val = _parse_num(str(item.get("rx_percent", "")))
                tx_pct = max(0.0, min(100.0, float(tx_val))) if tx_val is not None else None
                rx_pct = max(0.0, min(100.0, float(rx_val))) if rx_val is not None else None
                parsed_ifaces.append(
                    {
                        "interface": iface_name,
                        "description": str(item.get("description", "")).strip(),
                        "status": str(item.get("status", "up") or "up").strip().lower(),
                        "tx_percent": tx_pct,
                        "rx_percent": rx_pct,
                    }
                )
        if parsed_ifaces:
            metrics["interface_utilization"] = parsed_ifaces
        elif iface_status != 0:
            stderr = (iface_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"interfaces:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"interfaces:{exc}")

    return metrics, errors


def winrm_collect_live_gauges(host: str, settings: dict[str, Any], timeout_seconds: int = 6) -> tuple[dict[str, Any], list[str]]:
    if not WINRM_AVAILABLE or winrm is None:
        return {}, ["pywinrm_not_installed"]
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    if not username or not password:
        return {}, ["winrm_credentials_missing"]
    try:
        winrm_port = max(1, min(65535, int(settings.get("winrm_port", 5985) or 5985)))
    except Exception:
        winrm_port = 5985
    auth = str(settings.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
    if auth not in {"ntlm", "kerberos", "basic", "credssp"}:
        auth = "ntlm"
    scheme = "https" if winrm_port == 5986 else "http"
    endpoint = f"{scheme}://{host}:{winrm_port}/wsman"
    metrics: dict[str, Any] = {
        "cpu_percent": None,
        "memory_percent": None,
        "uptime_seconds": None,
        "last_boot": "",
        "network_rx_mbps": None,
        "network_tx_mbps": None,
        "windows_caption": "",
        "windows_version": "",
        "windows_build": "",
        "windows_arch": "",
        "computer_name": "",
        "computer_model": "",
        "domain": "",
        "total_memory_gb": None,
        "free_memory_gb": None,
    }
    errors: list[str] = []
    try:
        session = winrm.Session(target=endpoint, auth=(username, password), transport=auth)
    except Exception as exc:
        return metrics, [f"session_init:{exc}"]

    ps_cmd = (
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"
        "$cpu='';"
        "try{$cpu=((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{"
        "try{$cpu=((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{}"
        "};"
        "$os=$null;"
        "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
        "$boot='';$uptime=0;$mem=$null;$caption='';$version='';$build='';$arch='';$totalMemGb=$null;$freeMemGb=$null;"
        "if($os){"
        "$boot=$os.LastBootUpTime;"
        "if($boot){$uptime=(New-TimeSpan -Start $boot -End (Get-Date)).TotalSeconds};"
        "$caption=[string]$os.Caption;$version=[string]$os.Version;$build=[string]$os.BuildNumber;$arch=[string]$os.OSArchitecture;"
        "if($os.TotalVisibleMemorySize -gt 0){"
        "$usedMem=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
        "$mem=[math]::Round(($usedMem*100)/[double]$os.TotalVisibleMemorySize,2);"
        "$totalMemGb=[Math]::Round(([double]$os.TotalVisibleMemorySize/1024/1024),2)"
        "};"
        "if($os.FreePhysicalMemory -ge 0){$freeMemGb=[Math]::Round(([double]$os.FreePhysicalMemory/1024/1024),2)}"
        "};"
        "$boot_iso=''; if($boot){$boot_iso=([DateTime]$boot).ToString('o')};"
        "$hostn=[string]$env:COMPUTERNAME;$domain='';$model='';"
        "$cs=$null; try{$cs=Get-CimInstance Win32_ComputerSystem}catch{try{$cs=Get-WmiObject Win32_ComputerSystem}catch{}};"
        "if($cs){$domain=[string]$cs.Domain; $model=[string]$cs.Model};"
        "$rx=$null;$tx=$null;"
        "try{$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{"
        "try{$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{}"
        "};"
        "$cpuVal=$null; if($cpu -ne '' -and $cpu -ne $null){$cpuVal=[math]::Round([double]$cpu,2)};"
        "$memVal=$null; if($mem -ne '' -and $mem -ne $null){$memVal=[Math]::Round([double]$mem,2)};"
        "$rxVal=$null; if($rx -ne $null){$rxVal=[Math]::Round(([double]$rx*8/1000000),2)};"
        "$txVal=$null; if($tx -ne $null){$txVal=[Math]::Round(([double]$tx*8/1000000),2)};"
        "$payload=[PSCustomObject]@{"
        "cpu_percent=$cpuVal;"
        "memory_percent=$memVal;"
        "last_boot=$boot_iso;"
        "uptime_seconds=[int][Math]::Round([double]$uptime,0);"
        "windows_caption=$caption;windows_version=$version;windows_build=$build;windows_arch=$arch;"
        "computer_name=$hostn;computer_model=$model;domain=$domain;"
        "total_memory_gb=$totalMemGb;free_memory_gb=$freeMemGb;"
        "network_rx_mbps=$rxVal;"
        "network_tx_mbps=$txVal"
        "};"
        "$payload|ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        result = session.run_ps(ps_cmd)
        status = int(getattr(result, "status_code", 1) or 1)
        out_text = (result.std_out or b"").decode(errors="ignore").strip()
        if out_text:
            try:
                parsed = json.loads(out_text)
            except Exception:
                parsed = {}
            if isinstance(parsed, dict):
                metrics["cpu_percent"] = _cap_percent(parsed.get("cpu_percent"))
                metrics["memory_percent"] = _cap_percent(parsed.get("memory_percent"))
                metrics["last_boot"] = str(parsed.get("last_boot", "")).strip()
                metrics["uptime_seconds"] = parsed.get("uptime_seconds")
                metrics["windows_caption"] = str(parsed.get("windows_caption", "")).strip()
                metrics["windows_version"] = str(parsed.get("windows_version", "")).strip()
                metrics["windows_build"] = str(parsed.get("windows_build", "")).strip()
                metrics["windows_arch"] = str(parsed.get("windows_arch", "")).strip()
                metrics["computer_name"] = str(parsed.get("computer_name", "")).strip()
                metrics["computer_model"] = str(parsed.get("computer_model", "")).strip()
                metrics["domain"] = str(parsed.get("domain", "")).strip()
                metrics["total_memory_gb"] = parsed.get("total_memory_gb")
                metrics["free_memory_gb"] = parsed.get("free_memory_gb")
                metrics["network_rx_mbps"] = parsed.get("network_rx_mbps")
                metrics["network_tx_mbps"] = parsed.get("network_tx_mbps")
        if status != 0 and not out_text:
            err_text = (result.std_err or b"").decode(errors="ignore").strip()
            if err_text:
                errors.append(f"live:{err_text[:700]}")
    except Exception as exc:
        errors.append(f"live:{exc}")
    return metrics, errors


def _snmp_auth_data_from_settings(settings: dict[str, Any]) -> tuple[Any | None, str]:
    mode = str(settings.get("collection_mode", "snmp_v2")).strip().lower()
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    token = str(settings.get("token", "")).strip()
    if mode in {"snmp", "snmp_v2"}:
        community = token or password or "public"
        return CommunityData(community, mpModel=1), ""
    if mode == "snmp_v3":
        if not username:
            return None, "snmp_v3_username_missing"
        auth_name = str(settings.get("snmpv3_auth_protocol", "sha")).strip().lower() or "sha"
        priv_name = str(settings.get("snmpv3_priv_protocol", "aes128")).strip().lower() or "aes128"
        auth_proto_map = {
            "none": usmNoAuthProtocol,
            "md5": usmHMACMD5AuthProtocol or usmHMACSHAAuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha1": usmHMACSHAAuthProtocol,
            "sha224": usmHMAC128SHA224AuthProtocol or usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol or usmHMACSHAAuthProtocol,
            "sha384": usmHMAC256SHA384AuthProtocol or usmHMACSHAAuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol or usmHMACSHAAuthProtocol,
        }
        priv_proto_map = {
            "none": usmNoPrivProtocol,
            "des": usmDESPrivProtocol or usmNoPrivProtocol,
            "3des": usm3DESEDEPrivProtocol or usmDESPrivProtocol or usmNoPrivProtocol,
            "aes": usmAesCfb128Protocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol or usmAesCfb128Protocol,
            "aes256": usmAesCfb256Protocol or usmAesCfb128Protocol,
        }
        auth_proto = auth_proto_map.get(auth_name, usmHMACSHAAuthProtocol)
        priv_proto = priv_proto_map.get(priv_name, usmAesCfb128Protocol)
        if not password:
            return UsmUserData(username, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol), ""
        if priv_name != "none" and not token:
            return None, "snmp_v3_priv_password_missing"
        if password and token:
            return (
                UsmUserData(
                    username,
                    password,
                    token,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto,
                ),
                "",
            )
        if password:
            return (
                UsmUserData(
                    username,
                    password,
                    authProtocol=auth_proto,
                    privProtocol=usmNoPrivProtocol,
                ),
                "",
            )
        return UsmUserData(username, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol), ""
    return None, "collection_mode_not_snmp"


def snmp_get_value(host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3) -> tuple[Any | None, str]:
    if not PYSNMP_AVAILABLE:
        return None, "pysnmp_not_installed"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return None, auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    try:
        iterator = getCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication:
            return None, str(error_indication)
        if error_status:
            return None, str(error_status.prettyPrint())
        if not var_binds:
            return None, "empty_response"
        value = None
        try:
            value = var_binds[0][1]
        except Exception:
            try:
                first = tuple(var_binds[0])
                if len(first) >= 2:
                    value = first[1]
            except Exception:
                value = None
        if value is None:
            return None, "empty_response"
        return value, ""
    except Exception as exc:
        return None, str(exc)


def snmp_walk_values(
    host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3, max_rows: int = 1024
) -> tuple[list[Any], str]:
    if not PYSNMP_AVAILABLE:
        return [], "pysnmp_not_installed"
    if nextCmd is None:
        return [], "pysnmp_nextcmd_unavailable"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return [], auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    values: list[Any] = []
    try:
        iterator = nextCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                return values, str(error_indication)
            if error_status:
                return values, str(error_status.prettyPrint())
            for var_bind in var_binds or []:
                value_obj = None
                try:
                    value_obj = var_bind[1]
                except Exception:
                    try:
                        pair = tuple(var_bind)
                        if len(pair) >= 2:
                            value_obj = pair[1]
                    except Exception:
                        value_obj = None
                if value_obj is None:
                    continue
                values.append(value_obj)
                if len(values) >= max(1, int(max_rows)):
                    return values, ""
        return values, ""
    except Exception as exc:
        return values, str(exc)


def snmp_walk_indexed_values(
    host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3, max_rows: int = 4096
) -> tuple[dict[int, Any], str]:
    if not PYSNMP_AVAILABLE:
        return {}, "pysnmp_not_installed"
    if nextCmd is None:
        return {}, "pysnmp_nextcmd_unavailable"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return {}, auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    out: dict[int, Any] = {}
    prefix = f"{str(oid).strip('.')}."
    try:
        iterator = nextCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                return out, str(error_indication)
            if error_status:
                return out, str(error_status.prettyPrint())
            for var_bind in var_binds or []:
                name_obj = None
                value_obj = None
                try:
                    name_obj = var_bind[0]
                    value_obj = var_bind[1]
                except Exception:
                    try:
                        pair = tuple(var_bind)
                        if len(pair) >= 2:
                            name_obj = pair[0]
                            value_obj = pair[1]
                    except Exception:
                        name_obj = None
                        value_obj = None
                if name_obj is None:
                    continue
                oid_text = str(name_obj or "").strip()
                if not oid_text.startswith(prefix):
                    continue
                idx_text = oid_text[len(prefix) :].strip()
                if not idx_text.isdigit():
                    continue
                idx = int(idx_text)
                out[idx] = value_obj
                if len(out) >= max(1, int(max_rows)):
                    return out, ""
        return out, ""
    except Exception as exc:
        return out, str(exc)


def snmp_collect_interface_utilization(
    host: str, settings: dict[str, Any], selected_interfaces: set[str] | None = None, sample_seconds: float = 1.0
) -> list[dict[str, Any]]:
    selected_exact: set[str] = set()
    selected_normalized: set[str] = set()
    for item in (selected_interfaces or set()):
        text = str(item).strip()
        if not text:
            continue
        selected_exact.add(text.lower())
        normalized = _normalize_interface_key(text)
        if normalized:
            selected_normalized.add(normalized)
    names, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.1", max_rows=4096)
    if not names:
        names, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.2", max_rows=4096)
    if not names:
        return []
    alias, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.18", max_rows=4096)
    oper, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
    hi_speed, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.15", max_rows=4096)  # Mbps
    speed, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.5", max_rows=4096)  # bps

    in_oct_1, in_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.6", max_rows=4096)
    out_oct_1, out_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.10", max_rows=4096)
    use_32 = False
    if not in_oct_1 or not out_oct_1 or in_err or out_err:
        in_oct_1, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.10", max_rows=4096)
        out_oct_1, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.16", max_rows=4096)
        use_32 = True
    if not in_oct_1 or not out_oct_1:
        return []

    start_ts = time.time()
    time.sleep(max(0.2, float(sample_seconds)))
    in_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.6", max_rows=4096)[0]
    out_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.10", max_rows=4096)[0]
    if not in_oct_2 or not out_oct_2:
        in_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.10", max_rows=4096)[0]
        out_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.16", max_rows=4096)[0]
        use_32 = True
    end_ts = time.time()
    delta_t = max(0.2, end_ts - start_ts)

    max_counter = float(2**32 if use_32 else 2**64)
    status_map = {1: "up", 2: "down"}
    rows: list[dict[str, Any]] = []
    for idx in sorted(names.keys()):
        if_name = str(names.get(idx, "")).strip()
        if not if_name:
            continue
        if selected_exact or selected_normalized:
            normalized_if_name = _normalize_interface_key(if_name)
            if if_name.lower() not in selected_exact and normalized_if_name not in selected_normalized:
                continue
        if_desc = str(alias.get(idx, "")).strip()
        try:
            oper_code = int(oper.get(idx, 0) or 0)
        except Exception:
            oper_code = 0
        status = status_map.get(oper_code, "unknown")
        try:
            in1 = float(int(in_oct_1.get(idx, 0) or 0))
            in2 = float(int(in_oct_2.get(idx, in1) or in1))
            out1 = float(int(out_oct_1.get(idx, 0) or 0))
            out2 = float(int(out_oct_2.get(idx, out1) or out1))
        except Exception:
            in1 = in2 = out1 = out2 = 0.0
        din = in2 - in1
        dout = out2 - out1
        if din < 0:
            din += max_counter
        if dout < 0:
            dout += max_counter
        in_bps = (din * 8.0) / delta_t
        out_bps = (dout * 8.0) / delta_t
        speed_bps = 0.0
        try:
            hs = float(int(hi_speed.get(idx, 0) or 0))
            if hs > 0:
                speed_bps = hs * 1_000_000.0
            else:
                speed_bps = float(int(speed.get(idx, 0) or 0))
        except Exception:
            speed_bps = 0.0
        tx_pct: float | None = None
        rx_pct: float | None = None
        if speed_bps > 0:
            tx_pct = max(0.0, min(100.0, (out_bps / speed_bps) * 100.0))
            rx_pct = max(0.0, min(100.0, (in_bps / speed_bps) * 100.0))
        rows.append(
            {
                "status": status,
                "interface": if_name,
                "description": if_desc,
                "tx_percent": tx_pct,
                "rx_percent": rx_pct,
            }
        )
    return rows


def snmp_collect_memory_percent(host: str, settings: dict[str, Any]) -> tuple[float | None, list[str]]:
    errors: list[str] = []

    def _to_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            return float(int(value))
        except Exception:
            try:
                return float(str(value).strip())
            except Exception:
                return None

    # Strategy 1: Cisco memory pool MIB (works for many Cisco network devices).
    used_values, used_err = snmp_walk_values(host, settings, "1.3.6.1.4.1.9.9.48.1.1.1.5", max_rows=256)
    free_values, free_err = snmp_walk_values(host, settings, "1.3.6.1.4.1.9.9.48.1.1.1.6", max_rows=256)
    if not used_err and not free_err and used_values and free_values:
        try:
            total_used = float(sum(int(v) for v in used_values))
            total_free = float(sum(int(v) for v in free_values))
            denom = total_used + total_free
            if denom > 0:
                return (total_used * 100.0) / denom, errors
        except Exception as exc:
            errors.append(f"cisco_pool_calc:{exc}")
    else:
        if used_err:
            errors.append(f"cisco_pool_used:{used_err}")
        if free_err:
            errors.append(f"cisco_pool_free:{free_err}")

    # Strategy 2: HOST-RESOURCES-MIB (generic devices/servers).
    type_map, type_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.2", max_rows=1024)
    size_map, size_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.5", max_rows=1024)
    used_map, used_err2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.6", max_rows=1024)
    ram_type_oid = "1.3.6.1.2.1.25.2.1.2"
    if type_map and size_map and used_map and not (type_err or size_err or used_err2):
        ram_ratios: list[tuple[float, float]] = []
        for idx, raw_type in type_map.items():
            type_text = str(raw_type or "").strip()
            if type_text != ram_type_oid:
                continue
            size_val = _to_float(size_map.get(idx))
            used_val = _to_float(used_map.get(idx))
            if size_val is None or used_val is None or size_val <= 0:
                continue
            ratio = max(0.0, min(100.0, (used_val * 100.0) / size_val))
            # Keep size with ratio to prefer the largest RAM entry if multiple exist.
            ram_ratios.append((size_val, ratio))
        if ram_ratios:
            ram_ratios.sort(key=lambda item: item[0], reverse=True)
            return ram_ratios[0][1], errors
    else:
        if type_err:
            errors.append(f"hrStorage_type:{type_err}")
        if size_err:
            errors.append(f"hrStorage_size:{size_err}")
        if used_err2:
            errors.append(f"hrStorage_used:{used_err2}")

    # Strategy 3: UCD-SNMP-MIB memory (common on Linux/Unix SNMP agents).
    total_real, total_err = snmp_get_value(host, settings, "1.3.6.1.4.1.2021.4.5.0")
    avail_real, avail_err = snmp_get_value(host, settings, "1.3.6.1.4.1.2021.4.6.0")
    total_num = _to_float(total_real)
    avail_num = _to_float(avail_real)
    if total_num is not None and avail_num is not None and total_num > 0:
        used_num = max(0.0, total_num - avail_num)
        return max(0.0, min(100.0, (used_num * 100.0) / total_num)), errors
    if total_err:
        errors.append(f"ucd_total:{total_err}")
    if avail_err:
        errors.append(f"ucd_avail:{avail_err}")

    return None, errors


def poll_device_monitoring_sample(
    device: dict[str, Any], settings: dict[str, Any], pre_ping: tuple[str, float | None] | None = None
) -> dict[str, Any]:
    host = str(device.get("host", "")).strip()
    name = str(device.get("name", "")).strip() or host
    mode = str(settings.get("collection_mode", "telemetry")).strip().lower() or "telemetry"
    selected_metrics = parse_monitoring_metrics(str(settings.get("metrics", "")))
    try:
        cpu_warn = max(1, min(100, int(settings.get("cpu_warn", 90) or 90)))
    except Exception:
        cpu_warn = 90
    try:
        memory_warn = max(1, min(100, int(settings.get("memory_warn", 90) or 90)))
    except Exception:
        memory_warn = 90
    if pre_ping is not None:
        ping_state, latency = pre_ping
    else:
        ping_state, latency = ping_host_status(host, 2)
    status = ping_state
    severity = "ok" if status == "up" else "critical"
    details: dict[str, Any] = {"ping_latency_ms": latency}
    cpu_percent: float | None = None
    memory_percent: float | None = None
    interfaces_up: int | None = None
    interfaces_down: int | None = None
    sla_ms: float | None = latency

    if mode in {"snmp", "snmp_v2", "snmp_v3"} and ping_state == "up":
        snmp_errors: list[str] = []
        snmp_attempts = 0
        snmp_success = 0
        if "cpu" in selected_metrics:
            snmp_attempts += 1
            cpu_val, err = snmp_get_value(host, settings, "1.3.6.1.4.1.9.2.1.58.0")
            if err:
                snmp_errors.append(f"cpu:{err}")
            elif cpu_val is not None:
                try:
                    cpu_percent = _cap_percent(float(int(cpu_val)))
                    snmp_success += 1
                except Exception:
                    pass
        if "interfaces" in selected_metrics:
            snmp_attempts += 1
            oper_values, oper_err = snmp_walk_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
            if oper_err:
                snmp_errors.append(f"ifOperStatus:{oper_err}")
                if_num, err = snmp_get_value(host, settings, "1.3.6.1.2.1.2.1.0")
                if err:
                    snmp_errors.append(f"ifNumber:{err}")
                elif if_num is not None:
                    try:
                        interfaces_up = int(if_num)
                        interfaces_down = 0
                        snmp_success += 1
                    except Exception:
                        pass
            else:
                up_count = 0
                down_count = 0
                for raw in oper_values:
                    try:
                        code = int(raw)
                    except Exception:
                        continue
                    if code == 1:
                        up_count += 1
                    elif code == 2:
                        down_count += 1
                interfaces_up = up_count
                interfaces_down = down_count
                snmp_success += 1
        if "memory" in selected_metrics:
            snmp_attempts += 1
            memory_value, memory_errors = snmp_collect_memory_percent(host, settings)
            if memory_value is not None:
                memory_percent = memory_value
                snmp_success += 1
            else:
                for err_text in memory_errors[:6]:
                    if str(err_text).strip():
                        snmp_errors.append(f"memory:{err_text}")
        if snmp_errors:
            details["snmp_errors"] = snmp_errors
        # Store per-interface utilization snapshot so dashboard can render from DB only.
        if "interfaces" in selected_metrics:
            selected_ifaces_raw = settings.get("selected_interfaces", [])
            selected_ifaces = (
                {str(item).strip() for item in selected_ifaces_raw if str(item).strip()}
                if isinstance(selected_ifaces_raw, list)
                else set()
            )
            try:
                util_rows = snmp_collect_interface_utilization(
                    host,
                    settings,
                    selected_interfaces=(selected_ifaces if selected_ifaces else None),
                    sample_seconds=1.0,
                )
                # If selection names don't match SNMP ifName format, retry without filter.
                if selected_ifaces and not util_rows:
                    util_rows = snmp_collect_interface_utilization(
                        host,
                        settings,
                        selected_interfaces=None,
                        sample_seconds=1.0,
                    )
                # If utilization counters are not available, still provide interface/status rows.
                if not util_rows:
                    name_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.1", max_rows=4096)
                    if not name_map:
                        name_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.2", max_rows=4096)
                    oper_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
                    alias_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.18", max_rows=4096)
                    status_map = {1: "up", 2: "down"}
                    fallback_rows: list[dict[str, Any]] = []
                    selected_ifaces_lc = {str(v).strip().lower() for v in selected_ifaces if str(v).strip()}
                    selected_ifaces_norm = {
                        _normalize_interface_key(str(v).strip())
                        for v in selected_ifaces
                        if str(v).strip() and _normalize_interface_key(str(v).strip())
                    }
                    for idx in sorted(name_map.keys()):
                        if_name = str(name_map.get(idx, "")).strip()
                        if not if_name:
                            continue
                        if selected_ifaces_lc or selected_ifaces_norm:
                            if_name_norm = _normalize_interface_key(if_name)
                            if if_name.lower() not in selected_ifaces_lc and if_name_norm not in selected_ifaces_norm:
                                continue
                        try:
                            oper_code = int(oper_map.get(idx, 0) or 0)
                        except Exception:
                            oper_code = 0
                        fallback_rows.append(
                            {
                                "status": status_map.get(oper_code, "unknown"),
                                "interface": if_name,
                                "description": str(alias_map.get(idx, "")).strip(),
                                "tx_percent": None,
                                "rx_percent": None,
                            }
                        )
                    util_rows = fallback_rows
                details["interface_utilization"] = util_rows
            except Exception as exc:
                snmp_errors.append(f"ifUtil:{exc}")
                details["interface_utilization"] = []
        # If SNMP polling fully fails but ping is up, keep operational status as up
        # and set severity warning for visibility.
        if snmp_attempts > 0 and snmp_success <= 0:
            severity = "warning"
            if ping_state == "up":
                status = "up"
            else:
                status = "warning"

    if mode in {"winrm", "winrm_icmp"} and ping_state == "up":
        winrm_attempts = 0
        winrm_success = 0
        winrm_errors: list[str] = []
        metrics, errors = winrm_collect_metrics(host, settings, timeout_seconds=8)
        details["winrm"] = {
            "uptime_seconds": metrics.get("uptime_seconds"),
            "last_boot": metrics.get("last_boot"),
            "network_rx_mbps": metrics.get("network_rx_mbps"),
            "network_tx_mbps": metrics.get("network_tx_mbps"),
            "windows_caption": metrics.get("windows_caption"),
            "windows_version": metrics.get("windows_version"),
            "windows_build": metrics.get("windows_build"),
            "windows_arch": metrics.get("windows_arch"),
            "computer_name": metrics.get("computer_name"),
            "computer_model": metrics.get("computer_model"),
            "domain": metrics.get("domain"),
            "total_memory_gb": metrics.get("total_memory_gb"),
            "free_memory_gb": metrics.get("free_memory_gb"),
            "disk_usage": metrics.get("disk_usage", []),
        }
        if "interfaces" in selected_metrics:
            winrm_attempts += 1
            selected_ifaces_raw = settings.get("selected_interfaces", [])
            selected_ifaces = (
                {str(item).strip() for item in selected_ifaces_raw if str(item).strip()}
                if isinstance(selected_ifaces_raw, list)
                else set()
            )
            selected_ifaces_lc = {str(v).strip().lower() for v in selected_ifaces if str(v).strip()}
            selected_ifaces_norm = {
                _normalize_interface_key(str(v).strip())
                for v in selected_ifaces
                if str(v).strip() and _normalize_interface_key(str(v).strip())
            }
            iface_rows_raw = metrics.get("interface_utilization", [])
            iface_rows = iface_rows_raw if isinstance(iface_rows_raw, list) else []
            normalized_rows: list[dict[str, Any]] = []
            up_count = 0
            down_count = 0
            for row in iface_rows:
                if not isinstance(row, dict):
                    continue
                iface_name = str(row.get("interface", "")).strip()
                if not iface_name:
                    continue
                iface_lc = iface_name.lower()
                iface_norm = _normalize_interface_key(iface_name) or iface_lc
                if selected_ifaces_lc or selected_ifaces_norm:
                    if iface_lc not in selected_ifaces_lc and iface_norm not in selected_ifaces_norm:
                        continue
                status_raw = str(row.get("status", "unknown") or "unknown").strip().lower()
                status_value = status_raw if status_raw in {"up", "down", "unknown"} else "unknown"
                if status_value == "up":
                    up_count += 1
                elif status_value == "down":
                    down_count += 1
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
                normalized_rows.append(
                    {
                        "interface": iface_name,
                        "description": str(row.get("description", "")).strip(),
                        "status": status_value,
                        "tx_percent": tx_percent,
                        "rx_percent": rx_percent,
                    }
                )
            if normalized_rows:
                details["interface_utilization"] = normalized_rows
                interfaces_up = up_count
                interfaces_down = down_count
                winrm_success += 1
            else:
                details["interface_utilization"] = []
                winrm_errors.append("interfaces:unavailable")
        if "cpu" in selected_metrics:
            winrm_attempts += 1
            cpu_val = metrics.get("cpu_percent")
            if cpu_val is not None:
                cpu_percent = _cap_percent(float(cpu_val))
                winrm_success += 1
            else:
                winrm_errors.append("cpu:unavailable")
        if "memory" in selected_metrics:
            winrm_attempts += 1
            mem_val = metrics.get("memory_percent")
            if mem_val is not None:
                memory_percent = float(mem_val)
                winrm_success += 1
            else:
                winrm_errors.append("memory:unavailable")
        if errors:
            winrm_errors.extend(errors)
        if winrm_errors:
            details["winrm_errors"] = winrm_errors
        if winrm_attempts > 0 and winrm_success <= 0:
            severity = "warning"
            status = "up" if ping_state == "up" else "warning"

    if cpu_percent is not None and cpu_percent >= cpu_warn:
        severity = "warning"
        if status == "up":
            status = "warning"
    if memory_percent is not None and memory_percent >= memory_warn:
        severity = "warning"
        if status == "up":
            status = "warning"
    if ping_state != "up":
        status = "down"
        severity = "critical"

    return {
        "device_name": name,
        "host": host,
        "collection_mode": mode,
        "status": status,
        "severity": severity,
        "cpu_percent": _cap_percent(cpu_percent),
        "memory_percent": memory_percent,
        "interfaces_up": interfaces_up,
        "interfaces_down": interfaces_down,
        "sla_ms": sla_ms,
        "cpu_warn": cpu_warn,
        "memory_warn": memory_warn,
        "details_json": json.dumps(details),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def save_monitoring_sample(sample: dict[str, Any]) -> None:
    def _normalized_collected_at(raw_value: Any) -> str:
        text = str(raw_value or "").strip()
        if not text:
            return datetime.now(timezone.utc).isoformat()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    def _safe_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            val = float(value)
        except Exception:
            return None
        if not (val == val):  # NaN check
            return None
        return val

    def _parse_details(raw_json: str) -> dict[str, Any]:
        try:
            obj = json.loads(raw_json)
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _extract_interface_rows(details_obj: dict[str, Any]) -> list[dict[str, Any]]:
        rows_raw = details_obj.get("interface_utilization", [])
        if not isinstance(rows_raw, list):
            return []
        out: list[dict[str, Any]] = []
        for row in rows_raw:
            if not isinstance(row, dict):
                continue
            iface = str(row.get("interface", "")).strip()
            if not iface:
                continue
            status = str(row.get("status", "unknown") or "unknown").strip().lower()
            if status not in {"up", "down", "unknown", "connected", "disable", "notconnected", "err-disable"}:
                status = "unknown"
            out.append(
                {
                    "interface_name": iface,
                    "interface_description": str(row.get("description", "")).strip(),
                    "oper_status": status,
                    "tx_percent": _safe_float(row.get("tx_percent")),
                    "rx_percent": _safe_float(row.get("rx_percent")),
                    "details_json": json.dumps({"source": "poll"}),
                }
            )
        return out

    def _build_active_alerts(sample_obj: dict[str, Any], details_obj: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        status = str(sample_obj.get("status", "unknown")).strip().lower()
        host_name = str(sample_obj.get("host", "")).strip()
        sample_ts = str(sample_obj.get("collected_at", "")).strip()

        cpu_val = _safe_float(sample_obj.get("cpu_percent"))
        mem_val = _safe_float(sample_obj.get("memory_percent"))
        sla_val = _safe_float(sample_obj.get("sla_ms"))
        cpu_warn = _safe_float(sample_obj.get("cpu_warn"))
        mem_warn = _safe_float(sample_obj.get("memory_warn"))
        if_down_raw = sample_obj.get("interfaces_down")
        try:
            interfaces_down = int(if_down_raw) if if_down_raw is not None else None
        except Exception:
            interfaces_down = None

        if status == "down":
            alerts.append(
                {
                    "alert_key": "device_down",
                    "alert_type": "availability",
                    "severity": "critical",
                    "message": f"Device {host_name or sample_obj.get('device_name', '')} is DOWN",
                    "threshold_value": None,
                    "last_value": 0.0,
                    "details_json": json.dumps({"status": status, "sample_collected_at": sample_ts}),
                }
            )
        if cpu_val is not None and cpu_warn is not None and cpu_val >= cpu_warn:
            alerts.append(
                {
                    "alert_key": "cpu_high",
                    "alert_type": "cpu",
                    "severity": "warning",
                    "message": f"CPU high: {cpu_val:.2f}% >= {cpu_warn:.2f}%",
                    "threshold_value": cpu_warn,
                    "last_value": cpu_val,
                    "details_json": json.dumps({"cpu_percent": cpu_val, "threshold": cpu_warn}),
                }
            )
        if mem_val is not None and mem_warn is not None and mem_val >= mem_warn:
            alerts.append(
                {
                    "alert_key": "memory_high",
                    "alert_type": "memory",
                    "severity": "warning",
                    "message": f"Memory high: {mem_val:.2f}% >= {mem_warn:.2f}%",
                    "threshold_value": mem_warn,
                    "last_value": mem_val,
                    "details_json": json.dumps({"memory_percent": mem_val, "threshold": mem_warn}),
                }
            )
        if interfaces_down is not None and interfaces_down > 0:
            alerts.append(
                {
                    "alert_key": "interfaces_down",
                    "alert_type": "interfaces",
                    "severity": "warning",
                    "message": f"{interfaces_down} interface(s) reported DOWN",
                    "threshold_value": 0.0,
                    "last_value": float(interfaces_down),
                    "details_json": json.dumps({"interfaces_down": interfaces_down}),
                }
            )
        # Response-time warning only for very high values to reduce noise.
        if sla_val is not None and sla_val >= 5000.0:
            alerts.append(
                {
                    "alert_key": "response_high",
                    "alert_type": "response",
                    "severity": "warning",
                    "message": f"Response time high: {sla_val:.2f} ms",
                    "threshold_value": 5000.0,
                    "last_value": sla_val,
                    "details_json": json.dumps({"sla_ms": sla_val}),
                }
            )
        return alerts

    def _upsert_monitoring_alerts(conn: Any, sample_obj: dict[str, Any], active_alerts: list[dict[str, Any]]) -> None:
        device_name = str(sample_obj.get("device_name", "")).strip()
        if not device_name:
            return
        host_name = str(sample_obj.get("host", "")).strip()
        now_iso = datetime.now(timezone.utc).isoformat()
        sample_ts = str(sample_obj.get("collected_at", now_iso)).strip() or now_iso
        existing_rows = conn.execute(
            """
            SELECT id, alert_key, status
            FROM monitoring_alerts
            WHERE LOWER(device_name) = LOWER(?) AND status IN ('open', 'acked')
            """,
            (device_name,),
        ).fetchall()
        existing_by_key: dict[str, Any] = {}
        for row in existing_rows:
            key = str(row["alert_key"] or "").strip().lower()
            if key and key not in existing_by_key:
                existing_by_key[key] = row

        active_keys: set[str] = set()
        for alert in active_alerts:
            key = str(alert.get("alert_key", "")).strip().lower()
            if not key:
                continue
            active_keys.add(key)
            existing = existing_by_key.get(key)
            if existing:
                existing_status = str(existing["status"] or "").strip().lower()
                next_status = "acked" if existing_status == "acked" else "open"
                conn.execute(
                    """
                    UPDATE monitoring_alerts
                    SET host = ?, alert_type = ?, severity = ?, status = ?, message = ?,
                        threshold_value = ?, last_value = ?, updated_at = ?, sample_collected_at = ?, details_json = ?
                    WHERE id = ?
                    """,
                    (
                        host_name,
                        str(alert.get("alert_type", "generic")).strip().lower() or "generic",
                        str(alert.get("severity", "warning")).strip().lower() or "warning",
                        next_status,
                        str(alert.get("message", "")).strip(),
                        alert.get("threshold_value"),
                        alert.get("last_value"),
                        now_iso,
                        sample_ts,
                        str(alert.get("details_json", "{}")),
                        existing["id"],
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO monitoring_alerts(
                        device_name, host, alert_key, alert_type, severity, status, message,
                        threshold_value, last_value, opened_at, updated_at, sample_collected_at, details_json
                    ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_name,
                        host_name,
                        key,
                        str(alert.get("alert_type", "generic")).strip().lower() or "generic",
                        str(alert.get("severity", "warning")).strip().lower() or "warning",
                        str(alert.get("message", "")).strip(),
                        alert.get("threshold_value"),
                        alert.get("last_value"),
                        now_iso,
                        now_iso,
                        sample_ts,
                        str(alert.get("details_json", "{}")),
                    ),
                )

        for key, row in existing_by_key.items():
            if key in active_keys:
                continue
            conn.execute(
                """
                UPDATE monitoring_alerts
                SET status = 'cleared', updated_at = ?, cleared_at = ?, sample_collected_at = ?
                WHERE id = ?
                """,
                (now_iso, now_iso, sample_ts, row["id"]),
            )

    collected_at_iso = _normalized_collected_at(sample.get("collected_at"))
    details_json = str(sample.get("details_json", "{}"))
    details_obj = _parse_details(details_json)
    interface_rows = _extract_interface_rows(details_obj)
    sample_payload = dict(sample)
    sample_payload["collected_at"] = collected_at_iso
    active_alerts = _build_active_alerts(sample_payload, details_obj)

    with db_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO monitoring_metrics(
                    device_name, host, collection_mode, status, severity,
                    cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(sample.get("device_name", "")),
                    str(sample.get("host", "")),
                    str(sample.get("collection_mode", "")),
                    str(sample.get("status", "unknown")),
                    str(sample.get("severity", "warning")),
                    sample.get("cpu_percent"),
                    sample.get("memory_percent"),
                    sample.get("interfaces_up"),
                    sample.get("interfaces_down"),
                    sample.get("sla_ms"),
                    details_json,
                    collected_at_iso,
                    collected_at_iso,
                ),
            )
        except Exception:
            conn.execute(
                """
                INSERT INTO monitoring_metrics(
                    device_name, host, collection_mode, status, severity,
                    cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(sample.get("device_name", "")),
                    str(sample.get("host", "")),
                    str(sample.get("collection_mode", "")),
                    str(sample.get("status", "unknown")),
                    str(sample.get("severity", "warning")),
                    sample.get("cpu_percent"),
                    sample.get("memory_percent"),
                    sample.get("interfaces_up"),
                    sample.get("interfaces_down"),
                    sample.get("sla_ms"),
                    details_json,
                    collected_at_iso,
                ),
            )

        if interface_rows:
            for row in interface_rows:
                conn.execute(
                    """
                    INSERT INTO monitoring_interface_metrics(
                        device_name, host, interface_name, interface_description, oper_status,
                        tx_percent, rx_percent, collected_at_utc, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(sample.get("device_name", "")),
                        str(sample.get("host", "")),
                        str(row.get("interface_name", "")),
                        str(row.get("interface_description", "")),
                        str(row.get("oper_status", "unknown")),
                        row.get("tx_percent"),
                        row.get("rx_percent"),
                        collected_at_iso,
                        str(row.get("details_json", "{}")),
                    ),
                )

        _upsert_monitoring_alerts(conn, sample_payload, active_alerts)


def load_latest_monitoring_status_map(max_rows: int = 4000) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    try:
        with db_conn() as conn:
            try:
                rows = conn.execute(
                    "SELECT device_name, status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc FROM monitoring_metrics ORDER BY collected_at_utc DESC LIMIT ?",
                    (int(max(100, max_rows)),),
                ).fetchall()
            except Exception:
                rows = conn.execute(
                    "SELECT device_name, status, severity, cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at FROM monitoring_metrics ORDER BY collected_at DESC LIMIT ?",
                    (int(max(100, max_rows)),),
                ).fetchall()
    except Exception:
        return out
    for row in rows:
        key = str(row["device_name"]).strip().lower()
        if not key or key in out:
            continue
        details_raw = str(row["details_json"] or "{}")
        try:
            details_obj = json.loads(details_raw)
        except Exception:
            details_obj = {}
        out[key] = {
            "status": str(row["status"] or "unknown").strip().lower() or "unknown",
            "severity": str(row["severity"] or "warning").strip().lower() or "warning",
            "cpu_percent": _cap_percent(row["cpu_percent"]),
            "memory_percent": row["memory_percent"],
            "interfaces_up": row["interfaces_up"],
            "interfaces_down": row["interfaces_down"],
            "sla_ms": row["sla_ms"],
            "details": details_obj,
            "collected_at": str((row["collected_at_utc"] if "collected_at_utc" in row.keys() else row["collected_at"]) or ""),
        }
    return out


def load_monitoring_alerts(device_name: str, statuses: list[str] | None = None, limit: int = 100) -> list[dict[str, Any]]:
    name = str(device_name or "").strip()
    if not name:
        return []
    wanted = [str(s).strip().lower() for s in (statuses or ["open", "acked"]) if str(s).strip()]
    if not wanted:
        wanted = ["open", "acked"]
    placeholders = ", ".join(["?"] * len(wanted))
    sql = f"""
        SELECT TOP (?) id, device_name, host, alert_key, alert_type, severity, status, message,
               threshold_value, last_value, opened_at, updated_at, sample_collected_at, acked_by, acked_at, cleared_at, details_json
        FROM monitoring_alerts
        WHERE LOWER(device_name) = LOWER(?) AND LOWER(status) IN ({placeholders})
        ORDER BY updated_at DESC
    """
    params: list[Any] = [max(1, min(1000, int(limit))), name]
    params.extend(wanted)
    try:
        with db_conn() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        details_raw = str(row["details_json"] or "{}")
        try:
            details = json.loads(details_raw)
        except Exception:
            details = {}
        if not isinstance(details, dict):
            details = {}
        out.append(
            {
                "id": int(row["id"]),
                "device_name": str(row["device_name"] or "").strip(),
                "host": str(row["host"] or "").strip(),
                "alert_key": str(row["alert_key"] or "").strip(),
                "alert_type": str(row["alert_type"] or "").strip(),
                "severity": str(row["severity"] or "").strip(),
                "status": str(row["status"] or "").strip(),
                "message": str(row["message"] or "").strip(),
                "threshold_value": row["threshold_value"],
                "last_value": row["last_value"],
                "opened_at": str(row["opened_at"] or "").strip(),
                "updated_at": str(row["updated_at"] or "").strip(),
                "sample_collected_at": str(row["sample_collected_at"] or "").strip(),
                "acked_by": str(row["acked_by"] or "").strip(),
                "acked_at": str(row["acked_at"] or "").strip(),
                "cleared_at": str(row["cleared_at"] or "").strip(),
                "details": details,
            }
        )
    return out


def monitoring_poll_cycle() -> int:
    settings = load_monitoring_settings()
    profiles = load_monitoring_device_profiles()
    selected = {str(item).strip().lower() for item in settings.get("monitored_devices", []) if str(item).strip()}
    polling_enabled = bool(settings.get("enabled", False))
    # Keep polling active when there are monitored devices, even if the profile
    # checkbox was left disabled by mistake.
    if not polling_enabled and selected:
        polling_enabled = True
    if not polling_enabled:
        return max(5, int(settings.get("interval_seconds", 30) or 30))
    all_devices = load_devices()
    by_name = {str(device.get("name", "")).strip().lower(): device for device in all_devices if str(device.get("name", "")).strip()}
    if selected:
        candidate_names = sorted(selected)
    else:
        candidate_names = sorted(set(by_name.keys()) | set(profiles.keys()))
    targets: list[dict[str, Any]] = []
    for name_key in candidate_names:
        base = dict(by_name.get(name_key, {}))
        profile = dict(profiles.get(name_key, {}))
        device_name = str(base.get("name", "")).strip() or str(profile.get("device_name", "")).strip() or name_key
        host = str(base.get("host", "")).strip() or str(profile.get("host", "")).strip()
        if not host:
            continue
        groups = base.get("groups", []) if isinstance(base.get("groups", []), list) else []
        category = str(profile.get("category", "")).strip()
        if not groups:
            if category:
                groups = [category]
            else:
                groups = [DEFAULT_CATEGORY]
        targets.append({
            "name": device_name,
            "host": host,
            "port": int(base.get("port", 22) or 22),
            "groups": groups,
        })
    if not targets:
        return max(5, int(settings.get("interval_seconds", 30) or 30))
    for device in targets:
        try:
            profile = profiles.get(str(device.get("name", "")).strip().lower())
            effective = monitoring_effective_settings(settings, profile)
            ping_state, ping_latency = ping_host_status(str(device.get("host", "")).strip(), 2)
            if ping_state != "up":
                sample = {
                    "device_name": str(device.get("name", "")).strip() or str(device.get("host", "")).strip(),
                    "host": str(device.get("host", "")).strip(),
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
                    "details_json": json.dumps({"ping_latency_ms": ping_latency, "poll_skipped_reason": "icmp_down"}),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                }
            else:
                sample = poll_device_monitoring_sample(device, effective, pre_ping=(ping_state, ping_latency))
            save_monitoring_sample(sample)
        except Exception as exc:
            write_audit_log_safe(
                "monitoring_poll_device_failed",
                details={"device": str(device.get("name", "")), "error": str(exc)},
                requester="system",
            )
    return max(5, int(settings.get("interval_seconds", 30) or 30))


def monitoring_poller_loop() -> None:
    while not MONITORING_POLLER_STOP.is_set():
        wait_seconds = 30
        try:
            wait_seconds = monitoring_poll_cycle()
        except Exception as exc:
            write_audit_log_safe(
                "monitoring_poll_cycle_failed",
                details={"error": str(exc)},
                requester="system",
            )
            wait_seconds = 30
        MONITORING_POLLER_STOP.wait(max(5, int(wait_seconds)))


def ensure_monitoring_poller_started() -> None:
    global MONITORING_POLLER_THREAD
    with MONITORING_POLLER_LOCK:
        if MONITORING_POLLER_THREAD is not None and MONITORING_POLLER_THREAD.is_alive():
            return
        MONITORING_POLLER_STOP.clear()
        MONITORING_POLLER_THREAD = threading.Thread(
            target=monitoring_poller_loop,
            name="monitoring-poller",
            daemon=True,
        )
        MONITORING_POLLER_THREAD.start()


def stop_monitoring_poller(wait_seconds: float = 2.0) -> None:
    global MONITORING_POLLER_THREAD
    with MONITORING_POLLER_LOCK:
        thread = MONITORING_POLLER_THREAD
        MONITORING_POLLER_STOP.set()
    if thread is None:
        return
    if thread is not threading.current_thread() and thread.is_alive():
        try:
            thread.join(timeout=max(0.1, float(wait_seconds)))
        except Exception:
            pass
    with MONITORING_POLLER_LOCK:
        if MONITORING_POLLER_THREAD is thread and not thread.is_alive():
            MONITORING_POLLER_THREAD = None


def _stop_monitoring_poller_on_exit() -> None:
    stop_monitoring_poller(wait_seconds=1.5)


atexit.register(_stop_monitoring_poller_on_exit)


if hasattr(app, "before_serving"):
    @app.before_serving
    def _start_monitoring_poller_before_serving() -> None:
        if embedded_monitoring_poller_enabled():
            ensure_monitoring_poller_started()


if hasattr(app, "after_serving"):
    @app.after_serving
    def _stop_monitoring_poller_after_serving() -> None:
        stop_monitoring_poller(wait_seconds=1.5)


def seed_monitoring_sample_async(device_name: str, ip_address: str, category: str, profile: dict[str, Any], requester: str) -> None:
    def _worker() -> None:
        try:
            effective_settings = monitoring_effective_settings(load_monitoring_settings(), profile)
            seed_sample = poll_device_monitoring_sample(
                {"name": device_name, "host": ip_address, "groups": [category], "port": 22},
                effective_settings,
            )
            save_monitoring_sample(seed_sample)
        except Exception as exc:
            write_audit_log_safe(
                "monitoring_seed_poll_failed",
                details={"device_name": device_name, "ip_address": ip_address, "error": str(exc)},
                requester=requester or "system",
            )

    threading.Thread(target=_worker, name=f"seed-monitor-{device_name}", daemon=True).start()


def sync_ntp_time(server: str, port: int, timeout: int) -> tuple[bool, str, str]:
    if not server:
        return False, "NTP server is required.", ""

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, "Invalid NTP response.", ""

        ntp_seconds = struct.unpack("!I", data[40:44])[0]
        unix_seconds = ntp_seconds - 2208988800
        dt = datetime.fromtimestamp(unix_seconds, timezone.utc)
        return True, f"NTP synchronized with {server}:{port}.", dt.isoformat()
    except OSError as exc:
        return False, f"NTP sync failed: {exc}", ""
    finally:
        sock.close()


def test_ntp_connectivity(server: str, port: int, timeout: int) -> tuple[bool, str]:
    if not server:
        return False, "NTP server is required."

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, f"NTP test failed: invalid response from {server}:{port}."
        return True, f"NTP test success: connected to {server}:{port}."
    except OSError as exc:
        return False, f"NTP test failed: {exc}"
    finally:
        sock.close()


def run_ping_for_host(host: str, count: int = 5) -> str:
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return f"PING {host}\n.....\nPing command error: {exc}\n"

    output = result.stdout or ""
    lines = output.splitlines()
    rendered: list[str] = [f"PING {host}"]
    marks: list[str] = []

    for line in lines:
        lower = line.lower()
        if "ttl=" in lower and ("time=" in lower or "time<" in lower):
            marks.append("!")
            bytes_match = re.search(r"bytes[=< ](\d+)", lower)
            time_match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", lower)
            ttl_match = re.search(r"ttl[=< ](\d+)", lower)
            bytes_val = bytes_match.group(1) if bytes_match else "32"
            ttl_val = ttl_match.group(1) if ttl_match else "64"
            if time_match:
                time_fragment = f"time={time_match.group(1)}ms"
            elif "time<" in lower:
                time_fragment = "time<1ms"
            else:
                time_fragment = "time<1ms"
            rendered.append(f"Reply from {host}: bytes={bytes_val} {time_fragment} TTL={ttl_val}")

    if not marks:
        marks = ["."] * count
    elif len(marks) < count:
        marks.extend(["."] * (count - len(marks)))

    rendered.insert(1, "".join(marks[:count]))
    return "\n".join(rendered) + "\n"


def find_user(users: list[dict[str, Any]], username: str) -> dict[str, Any] | None:
    normalized = username.strip().lower()
    for user in users:
        if str(user.get("username", "")).strip().lower() == normalized:
            return user
    return None


def set_user_password(user: dict[str, Any], password: str) -> None:
    salt = secrets.token_hex(16)
    user["salt"] = salt
    user["password_hash"] = _hash_password(password, salt)


def is_current_session_super_admin() -> bool:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip().lower()
    super_username = str(load_super_admin().get("username", "")).strip().lower()
    return bool(current_username and super_username and current_username == super_username)


def normalize_role(role: str) -> str:
    raw = str(role or "").strip().lower()
    if raw in {"senior", "sysadmin", "junior", "helpdesk", "audit"}:
        return raw
    if raw in {"super_admin", "admin"}:
        return "senior"
    return "junior"


def is_privileged_role(role: str) -> bool:
    return normalize_role(role) in {"senior", "sysadmin"}


def can_manage_monitoring_nodes(role: str) -> bool:
    normalized = normalize_role(role)
    return normalized in {"senior", "sysadmin"}


def sysadmin_monitoring_servers_only(role: str) -> bool:
    return normalize_role(role) == "sysadmin"


def category_allowed_for_monitoring_add(role: str, category: str) -> bool:
    normalized = normalize_role(role)
    if normalized == "senior":
        return True
    if normalized == "sysadmin":
        key = str(category or "").strip().lower()
        return key in {"server", "servers"}
    return False


def monitoring_user_allowed_for_category(username: str, auth_mode: str, category: str) -> bool:
    user = find_user(load_users(), username)
    role = normalize_role(str((user or {}).get("role", "junior")))
    if role in {"senior", "sysadmin"}:
        return True
    allowed = user_allowed_categories_by_panel(username, auth_mode, "monitoring")
    if allowed is None:
        return True
    if not isinstance(allowed, list) or not allowed:
        return True
    category_name = str(category or "").strip() or DEFAULT_CATEGORY
    return category_name in set(allowed)


def normalize_auth_source(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw == "local":
        return "local"
    return "ldap"


def current_user_role() -> str:
    if is_current_session_super_admin():
        return "senior"
    if str(session.get("auth_mode", "local")) != "local":
        return "junior"
    username = str(session.get("creds", {}).get("username", "")).strip()
    users = load_users()
    user = find_user(users, username)
    if not user:
        return "junior"
    return normalize_role(str(user.get("role", "junior")))


def is_senior_user() -> bool:
    return is_privileged_role(current_user_role())


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
    return [
        {"id": int(row["id"]), "message": str(row["message"]), "created_at": str(row["created_at"])}
        for row in rows
    ]


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
        row = conn.execute(
            """
            SELECT enabled, driver, server, port, database_name, username, password_enc,
                   encrypt, trust_server_certificate, timeout, table_name
            FROM sql_server_settings WHERE id = 1
            """
        ).fetchone()

    if not row:
        return defaults

    defaults.update({
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
    })
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
    raise RuntimeError(
        "No SQL Server client available. Install pymssql (recommended, no ODBC) or pyodbc + ODBC Driver."
    )


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


def write_external_sql_audit_log(action: str, requester: str, approver: str, device_name: str, details: dict[str, Any], created_at: str) -> None:
    settings = load_sql_server_settings()
    if not bool(settings.get("enabled")):
        return

    table_name = normalize_sql_table_name(str(settings.get("table_name", "audit_logs")))
    try:
        conn, backend = _connect_sql_server_from_settings(settings, autocommit=True)
    except Exception:
        return

    try:
        ensure_sql_server_log_table(conn, table_name)
        cursor = conn.cursor()
        insert_sql = f"INSERT INTO dbo.[{table_name}] (action, requester, approver, device_name, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)"
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


def write_audit_log(action: str, requester: str, approver: str, device_name: str, details: dict[str, Any]) -> None:
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    write_external_sql_audit_log(action, requester, approver, device_name, details, created_at)




def write_audit_log_safe(
    action: str,
    device_name: str = "",
    details: dict[str, Any] | None = None,
    *,
    requester: str = "",
    approver: str = "",
) -> None:
    actor = str(requester or "").strip() or str(session.get("creds", {}).get("username", "")).strip() or "system"
    reviewer = str(approver or "").strip() or actor
    payload = details if isinstance(details, dict) else {}
    try:
        write_audit_log(action, actor, reviewer, str(device_name or ""), payload)
    except Exception:
        app.logger.exception("Failed to write audit log for action '%s'.", action)


def write_login_audit_log(username: str, auth_source: str, success: bool, reason: str) -> None:
    client_ip = str(
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or ""
    )
    user_agent = str(request.headers.get("User-Agent", "")).strip()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    details = {
        "auth_source": str(auth_source or "unknown").strip().lower() or "unknown",
        "success": bool(success),
        "reason": str(reason or "").strip(),
        "client_ip": client_ip,
        "user_agent": user_agent[:512],
    }
    write_external_sql_audit_log(
        action="login_success" if bool(success) else "login_failed",
        requester=str(username or "").strip(),
        approver="",
        device_name="",
        details=details,
        created_at=created_at,
    )


def _login_client_ip() -> str:
    return str(
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or ""
    )


def _login_lock_key(username: str, client_ip: str) -> str:
    uname = str(username or "").strip().lower() or "__unknown__"
    # Lock by username to avoid bypass when client IP changes behind proxies/NAT.
    _ = str(client_ip or "")
    return uname


def _format_lockout_countdown(seconds_left: int) -> str:
    total = max(1, int(seconds_left or 0))
    return f"{total}s"


def _lockout_epoch_to_iso(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _lockout_iso_to_epoch(value: Any) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return float(parsed.astimezone(timezone.utc).timestamp())
    except Exception:
        return 0.0


def _load_lockout_state_from_db(key: str) -> dict[str, Any] | None:
    global LOGIN_LOCKOUT_DB_READY
    try:
        with db_conn() as conn:
            row = conn.execute(
                "SELECT attempts, locked_until_utc FROM login_lockouts WHERE lock_key = ?",
                (key,),
            ).fetchone()
        LOGIN_LOCKOUT_DB_READY = True
        if not row:
            return None
        return {
            "attempts": int(row["attempts"] or 0),
            "locked_until": _lockout_iso_to_epoch(row["locked_until_utc"]),
        }
    except Exception:
        return None


def _save_lockout_state_to_db(key: str, attempts: int, locked_until: float) -> bool:
    global LOGIN_LOCKOUT_DB_READY
    try:
        with db_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO login_lockouts(lock_key, attempts, locked_until_utc, updated_at_utc) VALUES (?, ?, ?, ?)",
                (
                    key,
                    max(0, int(attempts or 0)),
                    _lockout_epoch_to_iso(locked_until) if float(locked_until or 0) > 0 else "",
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        LOGIN_LOCKOUT_DB_READY = True
        LOGIN_LOCKOUT_STATE.pop(key, None)
        return True
    except Exception:
        return False


def _delete_lockout_state_from_db(key: str) -> bool:
    global LOGIN_LOCKOUT_DB_READY
    try:
        with db_conn() as conn:
            conn.execute("DELETE FROM login_lockouts WHERE lock_key = ?", (key,))
        LOGIN_LOCKOUT_DB_READY = True
        LOGIN_LOCKOUT_STATE.pop(key, None)
        return True
    except Exception:
        return False


def _clear_all_lockout_state_db() -> bool:
    global LOGIN_LOCKOUT_DB_READY
    try:
        with db_conn() as conn:
            conn.execute("DELETE FROM login_lockouts")
        LOGIN_LOCKOUT_DB_READY = True
        LOGIN_LOCKOUT_STATE.clear()
        return True
    except Exception:
        return False


def _is_login_temporarily_locked(username: str, client_ip: str) -> tuple[bool, int]:
    key = _login_lock_key(username, client_ip)
    now = time.time()
    with LOGIN_LOCKOUT_LOCK:
        state = _load_lockout_state_from_db(key)
        if not isinstance(state, dict) and not LOGIN_LOCKOUT_DB_READY:
            state = LOGIN_LOCKOUT_STATE.get(key)
        if not isinstance(state, dict):
            return False, 0
        locked_until = float(state.get("locked_until", 0) or 0)
        if locked_until <= 0:
            return False, 0
        if locked_until <= now:
            if not _delete_lockout_state_from_db(key):
                LOGIN_LOCKOUT_STATE.pop(key, None)
            return False, 0
        return True, max(1, int(locked_until - now))


def _register_login_failure(username: str, client_ip: str, lock_settings: dict[str, Any]) -> tuple[bool, int, int]:
    key = _login_lock_key(username, client_ip)
    now = time.time()
    max_attempts = max(1, int(lock_settings.get("login_lockout_max_attempts", 5) or 5))
    lock_seconds = max(1, int(lock_settings.get("login_lockout_seconds", 300) or 300))
    with LOGIN_LOCKOUT_LOCK:
        state = _load_lockout_state_from_db(key)
        if not isinstance(state, dict) and not LOGIN_LOCKOUT_DB_READY:
            state = LOGIN_LOCKOUT_STATE.get(key, {})
        attempts = int(state.get("attempts", 0) or 0)
        locked_until = float(state.get("locked_until", 0) or 0)
        if locked_until > now:
            return True, max(1, int(locked_until - now)), attempts
        attempts += 1
        if attempts >= max_attempts:
            new_locked_until = now + lock_seconds
            if not _save_lockout_state_to_db(key, 0, new_locked_until):
                LOGIN_LOCKOUT_STATE[key] = {"attempts": 0, "locked_until": new_locked_until}
            return True, max(1, int(new_locked_until - now)), attempts
        if not _save_lockout_state_to_db(key, attempts, 0.0):
            LOGIN_LOCKOUT_STATE[key] = {"attempts": attempts, "locked_until": 0}
        return False, 0, attempts


def _clear_login_failure_state(username: str, client_ip: str) -> None:
    key = _login_lock_key(username, client_ip)
    with LOGIN_LOCKOUT_LOCK:
        if not _delete_lockout_state_from_db(key):
            LOGIN_LOCKOUT_STATE.pop(key, None)


def write_action_log(
    username: str,
    role: str,
    action: str,
    device_name: str,
    interface_name: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> None:
    client_ip = str(
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or ""
    )
    user_agent = str(request.headers.get("User-Agent", "")).strip()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload = details if isinstance(details, dict) else {}
    payload.update({
        "role": normalize_role(str(role or "unknown")),
        "interface_name": str(interface_name or "").strip(),
        "status": str(status or "").strip() or "unknown",
        "client_ip": client_ip,
        "user_agent": user_agent[:512],
    })
    write_external_sql_audit_log(
        action=str(action or "").strip() or "action",
        requester=str(username or "").strip(),
        approver="",
        device_name=str(device_name or "").strip(),
        details=payload,
        created_at=created_at,
    )


def load_audit_logs(limit: int = 500) -> list[dict[str, Any]]:
    rows: list[Any] = []
    settings = load_sql_server_settings()
    if bool(settings.get("enabled")):
        table_name = normalize_sql_table_name(str(settings.get("table_name", "audit_logs")))
        try:
            raw_conn, backend = _connect_sql_server_from_settings(settings, autocommit=True)
            try:
                ensure_sql_server_log_table(raw_conn, table_name)
                query = f"SELECT id, action, requester, approver, device_name, details_json, created_at FROM dbo.[{table_name}] ORDER BY id DESC OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY"
                wrapped = DBConnection(raw_conn, backend)
                rows = wrapped.execute(query, (max(1, int(limit)),)).fetchall()
            finally:
                raw_conn.close()
        except Exception:
            rows = []

    def build_log_summary(action: str, device_name: str, details: dict[str, Any]) -> str:
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
                parts.append(f"IP change: {ip_from or '-'} -> {ip_to or '-' }.")
            if cat_from or cat_to:
                from_txt = ", ".join(str(x) for x in cat_from) if isinstance(cat_from, list) and cat_from else "-"
                to_txt = ", ".join(str(x) for x in cat_to) if isinstance(cat_to, list) and cat_to else "-"
                parts.append(f"Categories: {from_txt} -> {to_txt}.")
            if len(parts) == 1:
                parts.append("No field details.")
            return " ".join(parts)

        return f"{label} for '{target}'."

    logs: list[dict[str, Any]] = []
    for row in rows:
        details_raw = str(row["details_json"] or "")
        try:
            details = json.loads(details_raw) if details_raw else {}
        except Exception:
            details = {"raw": details_raw}

        action = str(row["action"])
        device_name = str(row["device_name"])
        logs.append({
            "id": int(row["id"]),
            "action": action,
            "requester": str(row["requester"]),
            "approver": str(row["approver"]),
            "device_name": device_name,
            "summary": build_log_summary(action, device_name, details),
            "created_at": str(row["created_at"]),
        })
    return logs

def create_pending_device_request(*, requester_username: str, requester_role: str, original_device: dict[str, Any], proposed_hostname: str, proposed_ip: str, proposed_categories: list[str]) -> None:
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
            rows = conn.execute(
                "SELECT * FROM pending_device_requests WHERE status = 'pending' ORDER BY id DESC"
            ).fetchall()
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
        pending.append({
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
        })
    return pending


def load_pending_command_requests(status: str = "pending") -> list[dict[str, Any]]:
    with db_conn() as conn:
        if status == "all":
            rows = conn.execute("SELECT * FROM pending_command_requests ORDER BY id DESC").fetchall()
        elif status == "closed":
            rows = conn.execute("SELECT * FROM pending_command_requests WHERE status IN ('approved','rejected') ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pending_command_requests WHERE status = 'pending' ORDER BY id DESC"
            ).fetchall()

    pending: list[dict[str, Any]] = []
    for row in rows:
        try:
            target_devices = json.loads(str(row["target_devices"] or "[]"))
        except Exception:
            target_devices = []
        pending.append({
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
        })
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
    users.append({
        "username": username.strip(),
        "role": normalize_role(role),
        "auth_source": normalized_auth,
        "salt": "",
        "password_hash": "",
        "must_change_password": True if normalized_auth == "local" else False,
        "allowed_categories": None,
        "admin_permissions": [],
        "category_panel_access": {},
        "account_privileges": ["ip_addressing", "network_addressing", "net_devices", "monitoring"],
    })
    save_users(users)
    if normalized_auth == "local":
        return True, f"User '{username}' created with Local auth. User must set password on first login."
    return True, f"User '{username}' created with LDAP auth."

def default_ip_branches() -> list[str]:
    return ["B701", "B702", "B703", "B704"]


def _ipv4_to_int(ip: str) -> int:
    parts = [int(p) for p in str(ip).split(".")]
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) & 0xFFFFFFFF


def _int_to_ipv4(value: int) -> str:
    n = int(value) & 0xFFFFFFFF
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def _cidr_to_mask(cidr: int) -> str:
    bits = (0xFFFFFFFF << (32 - int(cidr))) & 0xFFFFFFFF
    return _int_to_ipv4(bits)


def _make_ip_rows(network_base: str, cidr: int) -> tuple[str, str, list[dict[str, str]]]:
    base_int = _ipv4_to_int(network_base)
    block_size = 2 ** (32 - int(cidr))
    gateway = _int_to_ipv4(base_int + 1)
    broadcast = _int_to_ipv4(base_int + block_size - 1)
    rows: list[dict[str, str]] = []
    for ip_int in range(base_int + 2, base_int + block_size - 1):
        rows.append({"ip": _int_to_ipv4(ip_int), "hostname": "", "enduser": "", "status": "FREE"})
    return gateway, broadcast, rows


def _seed_branch_state_from_names(branch_names: list[str]) -> list[dict[str, Any]]:
    names = [str(item).strip() for item in branch_names if str(item).strip()]
    if not names:
        names = default_ip_branches()
    base_start = _ipv4_to_int("10.10.10.0")
    cidr = 27
    block_size = 2 ** (32 - cidr)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    seeded: list[dict[str, Any]] = []
    for idx, name in enumerate(names):
        network_base = _int_to_ipv4(base_start + idx * block_size)
        gateway, broadcast, ip_rows = _make_ip_rows(network_base, cidr)
        seeded.append({
            "id": f"b-{idx+1}",
            "name": name,
            "site": "Site",
            "networkBase": network_base,
            "cidr": cidr,
            "subnetMask": _cidr_to_mask(cidr),
            "gateway": gateway,
            "broadcast": broadcast,
            "createdAt": now,
            "updatedAt": now,
            "ipRows": ip_rows,
        })
    return seeded


def load_ip_branch_state() -> list[dict[str, Any]]:
    with db_conn() as conn:
        branch_rows = conn.execute(
            "SELECT branch_name, site, network_base, cidr, subnet_mask, gateway, broadcast, created_at, updated_at FROM ip_branch_details ORDER BY branch_name"
        ).fetchall()
        ip_rows = conn.execute(
            "SELECT branch_name, ip_address, hostname, enduser_name, status FROM ip_branch_ips ORDER BY branch_name, ip_address"
        ).fetchall()

    if not branch_rows:
        seeded = _seed_branch_state_from_names(load_ip_branches())
        save_ip_branch_state(seeded)
        return seeded

    ip_map: dict[str, list[dict[str, str]]] = {}
    for row in ip_rows:
        bname = str(row["branch_name"]).strip()
        ip_map.setdefault(bname, []).append({
            "ip": str(row["ip_address"] or "").strip(),
            "hostname": str(row["hostname"] or "").strip(),
            "enduser": str(row["enduser_name"] or "").strip(),
            "status": str(row["status"] or "FREE").strip() or "FREE",
        })

    state: list[dict[str, Any]] = []
    for idx, row in enumerate(branch_rows, start=1):
        name = str(row["branch_name"] or "").strip()
        cidr = int(row["cidr"] or 27)
        state.append({
            "id": f"b-{idx}",
            "name": name,
            "site": str(row["site"] or "").strip(),
            "networkBase": str(row["network_base"] or "").strip(),
            "cidr": cidr,
            "subnetMask": str(row["subnet_mask"] or "").strip() or _cidr_to_mask(cidr),
            "gateway": str(row["gateway"] or "").strip(),
            "broadcast": str(row["broadcast"] or "").strip(),
            "createdAt": str(row["created_at"] or "").strip(),
            "updatedAt": str(row["updated_at"] or "").strip(),
            "ipRows": ip_map.get(name, []),
        })
    return state


def save_ip_branch_state(branches: list[dict[str, Any]]) -> None:
    normalized_branches: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in branches:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        cidr = int(item.get("cidr", 27) or 27)
        normalized_rows: list[dict[str, str]] = []
        for row in item.get("ipRows", []):
            if not isinstance(row, dict):
                continue
            ip_addr = str(row.get("ip", "")).strip()
            if not ip_addr:
                continue
            normalized_rows.append({
                "ip": ip_addr,
                "hostname": str(row.get("hostname", "")).strip(),
                "enduser": str(row.get("enduser", "")).strip(),
                "status": str(row.get("status", "FREE")).strip() or "FREE",
            })
        normalized_branches.append({
            "name": name,
            "site": str(item.get("site", "")).strip(),
            "networkBase": str(item.get("networkBase", "")).strip(),
            "cidr": cidr,
            "subnetMask": str(item.get("subnetMask", "")).strip() or _cidr_to_mask(cidr),
            "gateway": str(item.get("gateway", "")).strip(),
            "broadcast": str(item.get("broadcast", "")).strip(),
            "createdAt": str(item.get("createdAt", "")).strip(),
            "updatedAt": str(item.get("updatedAt", "")).strip(),
            "ipRows": normalized_rows,
        })

    with db_conn() as conn:
        conn.execute("DELETE FROM ip_branch_ips")
        conn.execute("DELETE FROM ip_branch_details")
        for branch in normalized_branches:
            conn.execute(
                """
                INSERT INTO ip_branch_details(branch_name, site, network_base, cidr, subnet_mask, gateway, broadcast, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    branch["name"],
                    branch["site"],
                    branch["networkBase"],
                    int(branch["cidr"]),
                    branch["subnetMask"],
                    branch["gateway"],
                    branch["broadcast"],
                    branch["createdAt"],
                    branch["updatedAt"],
                ),
            )
            for row in branch["ipRows"]:
                conn.execute(
                    """
                    INSERT INTO ip_branch_ips(branch_name, ip_address, hostname, enduser_name, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        branch["name"],
                        row["ip"],
                        row["hostname"],
                        row["enduser"],
                        row["status"],
                    ),
                )
    save_ip_branches([item["name"] for item in normalized_branches])


def load_ip_branches() -> list[str]:
    with db_conn() as conn:
        rows = conn.execute("SELECT branch_name FROM ip_branches ORDER BY branch_name").fetchall()
        db_branches = [str(row["branch_name"]).strip() for row in rows if str(row["branch_name"]).strip()]
        if db_branches:
            return db_branches

        seeded: list[str] = []
        if IP_BRANCHES_FILE.exists():
            try:
                raw = json.loads(IP_BRANCHES_FILE.read_text(encoding="utf-8"))
            except Exception:
                raw = []
            if isinstance(raw, list):
                seeded = [str(item).strip() for item in raw if str(item).strip()]
        if not seeded:
            seeded = default_ip_branches()

        normalized: list[str] = []
        seen: set[str] = set()
        for item in seeded:
            name = str(item).strip()
            key = name.lower()
            if not name or key in seen:
                continue
            seen.add(key)
            normalized.append(name)
        if not normalized:
            normalized = default_ip_branches()

        for branch_name in normalized:
            conn.execute("INSERT OR IGNORE INTO ip_branches(branch_name) VALUES (?)", (branch_name,))
        return normalized


def save_ip_branches(branches: list[str]) -> None:
    normalized = []
    seen: set[str] = set()
    for item in branches:
        name = str(item).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        normalized.append(name)
    with db_conn() as conn:
        conn.execute("DELETE FROM ip_branches")
        for branch_name in normalized:
            conn.execute("INSERT INTO ip_branches(branch_name) VALUES (?)", (branch_name,))
        if normalized:
            placeholders = ", ".join("?" for _ in normalized)
            conn.execute(
                f"DELETE FROM ip_branch_ips WHERE branch_name NOT IN ({placeholders})",
                tuple(normalized),
            )
            conn.execute(
                f"DELETE FROM ip_branch_details WHERE branch_name NOT IN ({placeholders})",
                tuple(normalized),
            )
        else:
            conn.execute("DELETE FROM ip_branch_ips")
            conn.execute("DELETE FROM ip_branch_details")
    try:
        IP_BRANCHES_FILE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_devices() -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute("SELECT hostname, ip_address FROM devices ORDER BY hostname").fetchall()
        group_rows = conn.execute("SELECT hostname, group_name FROM device_groups").fetchall()

    group_map: dict[str, list[str]] = {}
    for row in group_rows:
        group_map.setdefault(str(row["hostname"]), []).append(str(row["group_name"]))

    for row in rows:
        hostname = str(row["hostname"])
        devices.append({
            "name": hostname,
            "host": str(row["ip_address"]),
            "port": 22,
            "groups": sorted(group_map.get(hostname, [])),
        })
    return devices


def save_devices(devices: list[dict[str, Any]], conn: Any | None = None) -> None:
    def _save(target_conn: Any) -> None:
        target_conn.execute("DELETE FROM device_groups")
        target_conn.execute("DELETE FROM devices")
        for device in devices:
            hostname = str(device.get("name", device.get("hostname", ""))).strip()
            ip_address = str(device.get("host", device.get("ip_address", ""))).strip()
            if not hostname or not ip_address:
                continue
            target_conn.execute("INSERT INTO devices(hostname, ip_address) VALUES (?, ?)", (hostname, ip_address))
            for group in device.get("groups", []):
                group_name = str(group).strip()
                if group_name:
                    target_conn.execute(
                        "INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)",
                        (hostname, group_name),
                    )

    if conn is None:
        with db_conn() as own_conn:
            _save(own_conn)
        return

    _save(conn)


def grouped_devices(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for group in device.get("groups", []):
            groups.setdefault(group, []).append(device)
    return groups




def all_categories(devices: list[dict[str, Any]]) -> list[str]:
    categories: set[str] = set()
    for device in devices:
        groups = [str(group).strip() for group in device.get("groups", []) if str(group).strip()]
        if not groups:
            categories.add(DEFAULT_CATEGORY)
            continue
        for group in groups:
            group_name = str(group).strip()
            if group_name:
                categories.add(group_name)
    return sorted(categories)


def user_allowed_categories(username: str, auth_mode: str) -> list[str] | None:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return None

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return []
    allowed = user.get("allowed_categories")
    if allowed is None:
        return None
    if isinstance(allowed, list):
        return [str(item).strip() for item in allowed if str(item).strip()]
    return []


def filter_devices_for_user(devices: list[dict[str, Any]], username: str, auth_mode: str) -> list[dict[str, Any]]:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return devices

    allowed_set = set(allowed)
    filtered: list[dict[str, Any]] = []
    for device in devices:
        groups = [str(g).strip() for g in device.get("groups", []) if str(g).strip()]
        if not groups:
            if DEFAULT_CATEGORY in allowed_set:
                cloned = dict(device)
                cloned["groups"] = [DEFAULT_CATEGORY]
                filtered.append(cloned)
            continue
        allowed_groups = [group for group in groups if group in allowed_set]
        if allowed_groups:
            cloned = dict(device)
            cloned["groups"] = allowed_groups
            filtered.append(cloned)
    return filtered




def user_has_panel_access(username: str, auth_mode: str, panel_name: str) -> bool:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return True

    user = find_user(load_users(), username)
    if user is None:
        return False

    role = normalize_role(str(user.get("role", "junior")))
    if role == "audit":
        return False

    privileges = user.get("account_privileges")
    if not isinstance(privileges, list):
        privileges = ["ip_addressing", "network_addressing", "net_devices", "monitoring"]

    normalized = {str(item).strip().lower() for item in privileges if str(item).strip()}
    # Backward compatibility with old privilege keys.
    if "devices" in normalized:
        normalized.add("net_devices")
    if "ip_addressing" in normalized and "network_addressing" not in normalized:
        normalized.add("network_addressing")

    panel = str(panel_name or "net_devices").strip().lower()
    if panel in {"devices", "net_devices"}:
        return "net_devices" in normalized
    if panel in {"monitoring", "net_monitoring"}:
        return "monitoring" in normalized
    if panel in {"network_addressing", "network_addresses"}:
        return "network_addressing" in normalized
    if panel == "ip_addressing":
        return "ip_addressing" in normalized
    return panel in normalized


def default_menu_access() -> dict[str, bool]:
    return {
        "ip_branches": True,
        "ip_hq": True,
        "na_servers": True,
        "na_network_devices": True,
        "na_dmvpn": True,
        "na_sim_cards": True,
        "na_site_to_site": True,
        "na_nat": True,
    }


def normalize_menu_access(raw: Any) -> dict[str, bool]:
    defaults = default_menu_access()
    if isinstance(raw, list):
        selected = {str(item).strip() for item in raw if str(item).strip()}
        access = {key: (key in selected) for key in defaults}
    elif isinstance(raw, dict):
        access = {key: bool(raw.get(key, defaults[key])) for key in defaults}
    else:
        access = dict(defaults)

    if not access["na_network_devices"] and not access["na_dmvpn"] and not access["na_sim_cards"] and not access["na_site_to_site"] and not access["na_nat"]:
        access["na_servers"] = access["na_servers"]
    return access


def user_menu_access(username: str, auth_mode: str) -> dict[str, bool]:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return default_menu_access()

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return default_menu_access()

    category_panel_access = user.get("category_panel_access")
    raw = {}
    if isinstance(category_panel_access, dict):
        if isinstance(category_panel_access.get("menu_access"), dict):
            raw = category_panel_access.get("menu_access", {})
        else:
            raw = category_panel_access
    return normalize_menu_access(raw)



def user_allowed_categories_by_panel(username: str, auth_mode: str, panel_name: str) -> list[str] | None:
    if not user_has_panel_access(username, auth_mode, panel_name):
        return []
    return user_allowed_categories(username, auth_mode)

def user_can_access_device(device: dict[str, Any], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return True

    allowed_set = set(allowed)
    groups = {str(g).strip() for g in device.get("groups", []) if str(g).strip()}
    if not groups:
        return DEFAULT_CATEGORY in allowed_set
    return bool(groups & allowed_set)


def user_can_assign_categories(categories: list[str], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories(username, auth_mode)
    if allowed is None:
        return True
    allowed_set = set(allowed)
    return all(category in allowed_set for category in categories)

def default_buttons() -> list[dict[str, Any]]:
    return [
        {"id": "show-version", "label": "Show Version", "command": "show version", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-ip-int-brief", "label": "IP Interface Brief", "command": "show ip interface brief", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-int-status", "label": "Interfaces Status", "command": "show interfaces status", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-logging", "label": "Show Logging", "command": "show logging | tail 50", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-hostname", "label": "Show Hostname", "command": "show running-config | include hostname", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-arp", "label": "Show ARP", "command": "show arp", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-cdp", "label": "CDP Neighbors", "command": "show cdp neighbors", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "show-route", "label": "IP Route", "command": "show ip route", "mode": "show", "categories": [], "audience": "senior"},
        {"id": "config-hostname", "label": "Set Hostname", "command": "configure terminal\nhostname NEW-HOSTNAME", "mode": "config", "categories": [], "audience": "senior"},
        {"id": "config-int-desc", "label": "Interface Description", "command": "configure terminal\ninterface Gi0/1\ndescription UPDATED_BY_TOOL", "mode": "config", "categories": [], "audience": "senior"},
        {"id": "config-save", "label": "Save Config", "command": "write memory", "mode": "config", "categories": [], "audience": "senior"},
    ]


def normalize_buttons(raw_buttons: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_buttons, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_buttons:
        if not isinstance(item, dict):
            continue
        button_id = str(item.get("id", "")).strip()
        label = str(item.get("label", "")).strip()
        command = str(item.get("command", "")).strip()
        if not button_id or not label or not command:
            continue

        mode = str(item.get("mode", "show")).strip().lower()
        if mode not in {"show", "config"}:
            mode = "show"

        categories_raw = item.get("categories", [])
        categories: list[str] = []
        if isinstance(categories_raw, list):
            categories = [str(cat).strip() for cat in categories_raw if str(cat).strip()]
        audience = str(item.get("audience", "senior")).strip().lower()
        if audience not in {"junior", "senior", "both"}:
            audience = "senior"

        if mode == "config":
            command = normalize_config_command_text(command)
        normalized.append({
            "id": button_id,
            "label": label,
            "command": command,
            "mode": mode,
            "categories": categories,
            "audience": audience,
        })
    return normalized


def button_audience_for_role(role: str) -> str:
    normalized = normalize_role(role)
    if normalized in {"junior", "helpdesk"}:
        return "junior"
    return "senior"


def buttons_for_role(role: str) -> list[dict[str, Any]]:
    audience = button_audience_for_role(role)
    return [
        item
        for item in get_buttons()
        if str(item.get("audience", "senior")).strip().lower() in {audience, "both"}
    ]


def get_buttons() -> list[dict[str, Any]]:
    buttons = normalize_buttons(session.get("buttons"))
    if buttons:
        session["buttons"] = buttons
        return buttons
    buttons = default_buttons()
    session["buttons"] = buttons
    return buttons


def persist_current_user_buttons(buttons: list[dict[str, Any]]) -> None:
    account = session.get("creds", {})
    account_username = str(account.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if account_username:
        save_user_buttons(account_username, auth_mode, buttons)


def default_ise_settings() -> dict[str, Any]:
    return {
        "primary_server": "",
        "primary_port": 1812,
        "primary_shared_secret": "",
        "secondary_server": "",
        "secondary_port": 1812,
        "secondary_shared_secret": "",
        "timeout": 5,
        "nas_ip": "127.0.0.1",
    }


def load_ise_settings() -> dict[str, Any]:
    defaults = default_ise_settings()
    with db_conn() as conn:
        row = conn.execute(
            """
            SELECT primary_server, primary_port, primary_shared_secret,
                   secondary_server, secondary_port, secondary_shared_secret,
                   timeout, nas_ip
            FROM ise_settings WHERE id = 1
            """
        ).fetchone()

    if not row:
        return defaults

    defaults.update({
        "primary_server": str(row["primary_server"] or "").strip(),
        "primary_port": int(row["primary_port"] or 1812),
        "primary_shared_secret": decrypt_secret(str(row["primary_shared_secret"] or "")),
        "secondary_server": str(row["secondary_server"] or "").strip(),
        "secondary_port": int(row["secondary_port"] or 1812),
        "secondary_shared_secret": decrypt_secret(str(row["secondary_shared_secret"] or "")),
        "timeout": int(row["timeout"] or 5),
        "nas_ip": str(row["nas_ip"] or "127.0.0.1").strip(),
    })
    return defaults


def save_ise_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ise_settings(
                id, primary_server, primary_port, primary_shared_secret,
                secondary_server, secondary_port, secondary_shared_secret,
                timeout, nas_ip
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(settings.get("primary_server", "")).strip(),
                int(settings.get("primary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("primary_shared_secret", ""))),
                str(settings.get("secondary_server", "")).strip(),
                int(settings.get("secondary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("secondary_shared_secret", ""))),
                int(settings.get("timeout", 5) or 5),
                str(settings.get("nas_ip", "127.0.0.1")).strip(),
            ),
        )


def default_ldap_settings() -> dict[str, Any]:
    return {
        "server": "",
        "port": 389,
        "use_ssl": False,
        "start_tls": False,
        "timeout": 5,
        "base_dn": "",
        "user_dn_template": "",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_dn": "",
        "bind_password": "",
    }


def load_ldap_settings() -> dict[str, Any]:
    defaults = default_ldap_settings()
    with db_conn() as conn:
        row = conn.execute(
            """
            SELECT server, port, use_ssl, start_tls, timeout, base_dn,
                   user_dn_template, user_search_filter, bind_dn, bind_password
            FROM ldap_settings WHERE id = 1
            """
        ).fetchone()

    if not row:
        return defaults

    defaults.update({
        "server": str(row["server"] or "").strip(),
        "port": int(row["port"] or 389),
        "use_ssl": bool(row["use_ssl"]),
        "start_tls": bool(row["start_tls"]),
        "timeout": int(row["timeout"] or 5),
        "base_dn": str(row["base_dn"] or "").strip(),
        "user_dn_template": str(row["user_dn_template"] or "").strip(),
        "user_search_filter": str(row["user_search_filter"] or "(sAMAccountName={username})").strip() or "(sAMAccountName={username})",
        "bind_dn": str(row["bind_dn"] or "").strip(),
        "bind_password": decrypt_secret(str(row["bind_password"] or "")),
    })
    return defaults


def save_ldap_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ldap_settings(
                id, server, port, use_ssl, start_tls, timeout, base_dn,
                user_dn_template, user_search_filter, bind_dn, bind_password
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(settings.get("server", "")).strip(),
                int(settings.get("port", 389) or 389),
                1 if bool(settings.get("use_ssl")) else 0,
                1 if bool(settings.get("start_tls")) else 0,
                int(settings.get("timeout", 5) or 5),
                str(settings.get("base_dn", "")).strip(),
                str(settings.get("user_dn_template", "")).strip(),
                str(settings.get("user_search_filter", "(sAMAccountName={username})")).strip() or "(sAMAccountName={username})",
                str(settings.get("bind_dn", "")).strip(),
                encrypt_secret(str(settings.get("bind_password", ""))),
            ),
        )


def _ldap_connect(
    server_host: str,
    port: int,
    use_ssl: bool,
    start_tls: bool,
    timeout: int,
    user: str | None = None,
    password: str | None = None,
) -> Any:
    tls_config = Tls(validate=ssl.CERT_NONE)
    server = Server(
        server_host,
        port=port,
        use_ssl=use_ssl,
        connect_timeout=timeout,
        get_info=ALL,
        tls=tls_config,
    )
    conn = Connection(
        server,
        user=user,
        password=password,
        auto_bind=False,
        raise_exceptions=True,
        receive_timeout=timeout,
    )
    conn.open()
    if start_tls and not use_ssl:
        conn.start_tls()
    conn.bind()
    return conn


def _ldap_resolve_user_dn(username: str, settings: dict[str, Any]) -> tuple[str, str]:
    template = str(settings.get("user_dn_template", "")).strip()
    if template:
        if "{username}" not in template:
            return "", "LDAP user DN template must include {username}."
        try:
            return template.format(username=username), ""
        except Exception:
            return "", "LDAP user DN template is invalid."

    base_dn = str(settings.get("base_dn", "")).strip()
    if not base_dn:
        return "", "LDAP base DN is required when user DN template is empty."

    raw_filter = str(settings.get("user_search_filter", "(sAMAccountName={username})")).strip()
    search_filter = raw_filter or "(sAMAccountName={username})"
    escaped_username = username
    if escape_filter_chars is not None:
        escaped_username = escape_filter_chars(username)
    try:
        search_filter = search_filter.format(username=escaped_username)
    except Exception:
        return "", "LDAP search filter must include {username} placeholder."

    bind_dn = str(settings.get("bind_dn", "")).strip() or None
    bind_password = str(settings.get("bind_password", "")) if bind_dn else None
    try:
        conn = _ldap_connect(
            str(settings.get("server", "")).strip(),
            int(settings.get("port", 389) or 389),
            bool(settings.get("use_ssl")),
            bool(settings.get("start_tls")),
            int(settings.get("timeout", 5) or 5),
            bind_dn,
            bind_password,
        )
    except Exception as exc:
        return "", f"LDAP bind/search connection failed: {exc}"

    try:
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=["distinguishedName"])
    except LDAPException as exc:
        message = str(exc)
        if "noSuchObject" in message or "NO_SUCH_OBJECT" in message:
            return "", f"LDAP search base was not found: '{base_dn}'. Check Base DN in LDAP settings."
        return "", f"LDAP user search failed: {message}"
    except OSError as exc:
        return "", f"LDAP user search connection failed: {exc}"
    except Exception as exc:
        return "", f"LDAP user search failed: {exc}"
    try:
        if len(conn.entries) == 0:
            return "", "LDAP user not found."
        if len(conn.entries) > 1:
            return "", "LDAP search returned multiple users; refine search filter."
        return str(conn.entries[0].entry_dn), ""
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def authenticate_with_ldap(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    if not LDAP3_AVAILABLE:
        return False, "LDAP login is unavailable because ldap3 is not installed."

    server_host = str(settings.get("server", "")).strip()
    if not server_host:
        return False, "LDAP server is not configured."

    user_dn, dn_error = _ldap_resolve_user_dn(username, settings)
    if dn_error:
        return False, dn_error
    if not user_dn:
        return False, "Failed to resolve LDAP user DN."

    try:
        conn = _ldap_connect(
            server_host,
            int(settings.get("port", 389) or 389),
            bool(settings.get("use_ssl")),
            bool(settings.get("start_tls")),
            int(settings.get("timeout", 5) or 5),
            user_dn,
            password,
        )
        try:
            conn.unbind()
        except Exception:
            pass
        return True, "Authenticated by LDAP."
    except LDAPException as exc:
        message = str(exc)
        if "invalidCredentials" in message or "INVALID_CREDENTIALS" in message:
            return False, "Incorrect username or password."
        return False, "LDAP authentication failed."
    except OSError as exc:
        return False, f"LDAP connection failed: {exc}"


def _radius_attr(attr_type: int, value: bytes) -> bytes:
    length = len(value) + 2
    return bytes([attr_type, length]) + value


def _radius_encrypt_user_password(password: str, secret: bytes, request_authenticator: bytes) -> bytes:
    pwd_bytes = password.encode("utf-8")
    padding = 16 - (len(pwd_bytes) % 16)
    if padding != 16:
        pwd_bytes += b"\x00" * padding

    encrypted = b""
    last = request_authenticator
    for i in range(0, len(pwd_bytes), 16):
        block = pwd_bytes[i : i + 16]
        digest = hashlib.md5(secret + last).digest()
        cipher = bytes(a ^ b for a, b in zip(block, digest))
        encrypted += cipher
        last = cipher
    return encrypted


def _authenticate_radius_server(
    username: str,
    password: str,
    server: str,
    port: int,
    shared_secret: str,
    timeout: int,
    nas_ip: str,
) -> tuple[bool, str]:
    if not server or not shared_secret:
        return False, "Server/secret missing"

    secret = shared_secret.encode("utf-8")
    identifier = random.randint(0, 255)
    request_authenticator = os.urandom(16)

    attrs = b""
    attrs += _radius_attr(ATTR_USER_NAME, username.encode("utf-8"))
    attrs += _radius_attr(ATTR_USER_PASSWORD, _radius_encrypt_user_password(password, secret, request_authenticator))

    try:
        attrs += _radius_attr(ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip))
    except OSError:
        pass

    attrs += _radius_attr(ATTR_NAS_PORT, struct.pack("!I", 0))
    attrs += _radius_attr(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_LOGIN))

    packet_len = 20 + len(attrs)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, packet_len) + request_authenticator + attrs

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        return False, f"Timeout from ISE {server}:{port}"
    except OSError as exc:
        return False, f"Connection error to ISE {server}:{port}: {exc}"
    finally:
        sock.close()

    if len(response) < 20:
        return False, f"Invalid response from ISE {server}:{port}"

    code, recv_identifier, recv_length = struct.unpack("!BBH", response[:4])
    recv_authenticator = response[4:20]
    response_attrs = response[20:recv_length]

    if recv_identifier != identifier:
        return False, f"Identifier mismatch from ISE {server}:{port}"

    expected_auth = hmac.new(secret, response[:4] + request_authenticator + response_attrs, hashlib.md5).digest()
    if expected_auth != recv_authenticator:
        return False, f"Authenticator check failed from ISE {server}:{port}"

    if code == ACCESS_ACCEPT:
        return True, f"Authenticated by ISE {server}:{port}"
    if code == ACCESS_REJECT:
        return False, f"Rejected by ISE {server}:{port}"
    return False, f"Unsupported response code {code} from ISE {server}:{port}"


def authenticate_with_ise(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    timeout = int(settings.get("timeout", 5) or 5)
    nas_ip = str(settings.get("nas_ip", "127.0.0.1")).strip()

    primary_server = str(settings.get("primary_server", "")).strip()
    primary_port = int(settings.get("primary_port", 1812) or 1812)
    primary_secret = str(settings.get("primary_shared_secret", ""))

    secondary_server = str(settings.get("secondary_server", "")).strip()
    secondary_port = int(settings.get("secondary_port", 1812) or 1812)
    secondary_secret = str(settings.get("secondary_shared_secret", ""))

    if not primary_server or not primary_secret:
        return False, "Primary ISE server and primary secret are required."

    ok, message = _authenticate_radius_server(
        username, password, primary_server, primary_port, primary_secret, timeout, nas_ip
    )
    if ok:
        return True, message

    if secondary_server and secondary_secret:
        ok2, msg2 = _authenticate_radius_server(
            username,
            password,
            secondary_server,
            secondary_port,
            secondary_secret,
            timeout,
            nas_ip,
        )
        if ok2:
            return True, msg2
        return False, f"Primary failed: {message}. Secondary failed: {msg2}."

    return False, message


def runtime_session_id() -> str:
    sid = str(session.get("runtime_session_id", "")).strip()
    if sid:
        return sid
    sid = secrets.token_hex(16)
    session["runtime_session_id"] = sid
    return sid


def close_runtime_ssh_sessions(runtime_id: str) -> None:
    if not runtime_id:
        return
    with RUNTIME_SSH_LOCK:
        sessions = RUNTIME_SSH_SESSIONS.pop(runtime_id, {})
    for item in sessions.values():
        client = item.get("client")
        try:
            if client:
                client.close()
        except Exception:
            pass


def get_runtime_device_session(runtime_id: str, device_name: str) -> dict[str, Any] | None:
    with RUNTIME_SSH_LOCK:
        return RUNTIME_SSH_SESSIONS.get(runtime_id, {}).get(device_name)


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


def run_runtime_device_command(runtime_id: str, device: dict[str, Any], creds: dict[str, Any], command: str) -> tuple[str, str]:
    device_name = str(device.get("name", ""))
    ok, message = open_runtime_device_session(runtime_id, device, creds)
    if not ok:
        return "FAIL", message

    runtime = get_runtime_device_session(runtime_id, device_name)
    if runtime is None:
        return "FAIL", "SSH session is not available."

    channel = runtime.get("channel")
    if channel is None:
        return "FAIL", "SSH channel is not available."

    try:
        timeout = max(2, int(creds.get("timeout", 8)))
        commands = split_cli_commands(command)
        if not commands:
            return "FAIL", "No command provided."
        output_parts: list[str] = []
        for cmd in commands:
            channel.send(cmd + "\n")
            text = _read_shell_output(channel, timeout)
            if text:
                output_parts.append(text)
        joined = "\n".join(output_parts).strip()
        return "PASS", joined or "(no output)"
    except Exception as exc:
        with RUNTIME_SSH_LOCK:
            runtime_store = RUNTIME_SSH_SESSIONS.get(runtime_id, {})
            runtime_item = runtime_store.pop(device_name, None)
        client = runtime_item.get("client") if runtime_item else None
        try:
            if client:
                client.close()
        except Exception:
            pass
        return "FAIL", str(exc)


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
    raw = str(command_text or '').strip()
    if raw.startswith('DELETE_BRANCH::'):
        return raw.split('::', 1)[1].strip()
    return ''

def command_requires_senior_approval(command_text: str) -> bool:
    # Command approval flow is disabled: juniors/helpdesk can only run
    # predefined buttons, and manual command entry is blocked.
    _ = command_text
    return False


def notify_seniors_new_pending_command_request(
    request_id: int,
    requester_username: str,
    command_mode: str,
    command_text: str,
    device_names: list[str],
) -> None:
    message = (
        f"New pending request #{request_id} from {requester_username} for DANGEROUS command approval. "
        f"Devices: {', '.join(device_names) or '-'}; Command: '{str(command_text).strip()}'."
    )
    for senior_username in load_senior_notification_targets():
        if senior_username.strip().lower() == str(requester_username).strip().lower():
            continue
        notify_user(senior_username, message)


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
                str(command_mode or 'show').strip().lower(),
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
            command_mode=str(command_mode or 'show').strip().lower(),
            command_text=str(command_text).strip(),
            device_names=normalized_devices,
        )
    return request_id


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


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str, command_mode: str = "show") -> SSHResult:
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


@app.route("/")
def root() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if "auth_mode" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.before_request
def enforce_dashboard_session_timeout() -> Any:
    if _env_true("APP_FORCE_HTTPS", "0"):
        endpoint = request.endpoint or ""
        if endpoint != "static":
            forwarded_proto = str(request.headers.get("X-Forwarded-Proto", request.scheme)).split(",")[0].strip().lower()
            if forwarded_proto != "https" and request.scheme != "https":
                secure_url = request.url.replace("http://", "https://", 1)
                return redirect(secure_url, code=301)
    if embedded_monitoring_poller_enabled():
        ensure_monitoring_poller_started()
    endpoint = request.endpoint or ""
    if endpoint != "static":
        settings = load_session_settings()
        if bool(settings.get("web_acl_enabled", False)):
            client_ip = str(
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.remote_addr
                or ""
            )
            acl_entries = settings.get("web_acl_entries", [])
            if not _is_client_ip_allowed_by_acl(client_ip, acl_entries if isinstance(acl_entries, list) else []):
                if request.path.startswith("/api/") or str(request.accept_mimetypes.best).lower() == "application/json":
                    return jsonify({
                        "ok": False,
                        "error": "Access denied by Web ACL.",
                        "client_ip": client_ip,
                    }), 403
                return (
                    f"Access denied by Web ACL. Your IP {client_ip or 'unknown'} is not allowed.",
                    403,
                )
    # Super-admin verification is scoped only to settings/super-admin pages.
    # As soon as user navigates elsewhere (dashboard/app pages), drop the privileged flag.
    if session.get("super_admin_verified"):
        current_path = str(request.path or "")
        if not (current_path.startswith("/settings/") or current_path.startswith("/super-admin/")):
            session.pop("super_admin_verified", None)
    if "creds" not in session:
        return None

    endpoint = request.endpoint or ""
    if endpoint in {"static", "login", "logout", "setup_super_admin", "change_password"}:
        return None
    passive_endpoints = {"ip_addressing_live_data_api"}

    role = current_user_role()
    if role == "audit":
        allowed_audit_endpoints = {
            "audit_dashboard",
            "mark_notifications_read_route",
            "delete_notification_route",
            "logout",
            "pending_command_decision",
        }
        if endpoint not in allowed_audit_endpoints:
            return redirect(url_for("audit_dashboard"))

    settings = load_session_settings()
    timeout_seconds = max(60, int(settings.get("idle_timeout_minutes", 15)) * 60)
    now = int(time.time())
    last_activity = int(session.get("last_activity_ts", now))

    if now - last_activity > timeout_seconds:
        session.clear()
        session["login_info"] = "Session expired due to inactivity. Please log in again."
        if endpoint in passive_endpoints:
            return jsonify({"ok": False, "error": "Session expired due to inactivity.", "expired": True}), 401
        return redirect(url_for("login", expired=1))

    # Do not treat background auto-refresh APIs as user activity.
    if endpoint not in passive_endpoints:
        session["last_activity_ts"] = now
    return None


@app.after_request
def add_no_cache_headers(response: Any) -> Any:
    endpoint = request.endpoint or ""
    if endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/super-admin/setup", methods=["GET", "POST"])
def setup_super_admin() -> Any:
    if super_admin_exists():
        return redirect(url_for("login"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            error = "Username and password are required."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            save_super_admin(username, password)
            return redirect(url_for("login"))

    return render_template("super_admin_setup.html", error=error)


@app.route("/super-admin/verify", methods=["GET", "POST"])
def verify_super_admin_route() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if request.method == "GET" and request.args.get("exit") == "1":
        session.pop("super_admin_verified", None)
        return redirect(url_for("dashboard"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_super_admin(username, password):
            session["super_admin_verified"] = True
            return redirect(url_for("ise_settings_page"))
        error = "Invalid super admin credentials."

    return render_template("super_admin_verify.html", error=error)


@app.route("/super-admin/exit", methods=["GET"])
def super_admin_exit() -> Any:
    # Exit privileged settings mode and require fresh super-admin verification next time.
    session.pop("super_admin_verified", None)
    return redirect(url_for("dashboard"))


@app.route("/settings/ise", methods=["GET", "POST"])
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


@app.route("/settings/sql-server", methods=["POST"])
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


@app.route("/settings/sql-server/test", methods=["POST"])
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


@app.route("/settings/ldap", methods=["POST"])
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
        save_ldap_settings({
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
        })
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


@app.route("/settings/ntp/test", methods=["POST"])
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


@app.route("/settings/ntp", methods=["POST"])
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





@app.route("/settings/session", methods=["POST"])
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
    lockout_enabled = request.form.get("login_lockout_enabled") == "on"
    lockout_attempts_raw = request.form.get("login_lockout_max_attempts", "5").strip()
    lockout_seconds_raw = request.form.get("login_lockout_seconds", request.form.get("login_lockout_minutes", "300")).strip()
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

    try:
        lockout_attempts = int(lockout_attempts_raw or 5)
        if lockout_attempts < 1 or lockout_attempts > 20:
            raise ValueError
    except ValueError:
        session["settings_error"] = "Lockout failed attempts must be between 1 and 20."
        return redirect(url_for("ise_settings_page", modal="session"))

    try:
        lockout_seconds = int(lockout_seconds_raw or 300)
        if lockout_seconds < 1 or lockout_seconds > 86400:
            raise ValueError
    except ValueError:
        session["settings_error"] = "Lockout countdown must be between 1 and 86400 seconds."
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
        current_ip = str(
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or ""
        )
        if not _is_client_ip_allowed_by_acl(current_ip, acl_entries):
            session["settings_error"] = f"Your current IP {current_ip or 'unknown'} is not in ACL list. Add it before enabling ACL."
            return redirect(url_for("ise_settings_page", modal="session"))

    save_session_settings({
        "idle_timeout_minutes": timeout_minutes,
        "http_enabled": http_enabled,
        "https_enabled": https_enabled,
        "http_port": http_port,
        "https_port": https_port,
        "web_acl_enabled": web_acl_enabled,
        "web_acl_entries": acl_entries,
        "login_lockout_enabled": lockout_enabled,
        "login_lockout_max_attempts": lockout_attempts,
        "login_lockout_seconds": lockout_seconds,
    })
    if not lockout_enabled:
        with LOGIN_LOCKOUT_LOCK:
            LOGIN_LOCKOUT_STATE.clear()
            _clear_all_lockout_state_db()
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


@app.route("/settings/external-logging", methods=["POST"])
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


@app.route("/settings/monitoring", methods=["POST"])
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


@app.route("/monitoring/node/add", methods=["POST"])
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


@app.route("/monitoring/node/delete", methods=["POST"])
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
    settings["monitored_devices"] = [str(item).strip() for item in settings.get("monitored_devices", []) if str(item).strip().lower() != device_name.lower()]
    save_monitoring_settings(settings)
    write_audit_log_safe(
        "monitoring_node_deleted",
        details={"device_name": device_name},
        requester=current_username,
    )
    session["dashboard_info"] = f"Monitoring node '{device_name}' deleted."
    return redirect(url_for("ip_addressing_dashboard"))


@app.route("/monitoring/category/add", methods=["POST"])
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


@app.route("/monitoring/category/delete", methods=["POST"])
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


@app.route("/monitoring/category/rename", methods=["POST"])
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


@app.route("/monitoring/node/test-snmp", methods=["POST"])
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
        return jsonify(
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
        ), 400

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


@app.route("/monitoring/node/resources/pull", methods=["POST"])
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
            return jsonify(
                {
                    "ok": False,
                    "error": "Failed to pull resources via SSH and SNMP. Check SSH credentials or SNMP v2/v3 settings.",
                }
            ), 400

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


@app.route("/monitoring/node/resources/save", methods=["POST"])
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


@app.route("/monitoring/alerts/ack", methods=["POST"])
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


@app.route("/monitoring/node/dashboard-data", methods=["POST"])
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
                    "details_json": json.dumps({"ping_latency_ms": ping_latency, "poll_skipped_reason": "icmp_down", "forced_refresh": True}),
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


@app.route("/monitoring/node/live-gauges", methods=["POST"])
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


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if not super_admin_exists():
        return redirect(url_for("setup_super_admin"))

    error = ""
    info = session.pop("login_info", "")
    if request.args.get("expired") == "1":
        info = "Session expired due to inactivity. Please log in again."
    ldap_settings = load_ldap_settings()
    users = load_users()
    session_settings = load_session_settings()
    lockout_enabled = bool(session_settings.get("login_lockout_enabled", False))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        timeout = int(request.form.get("timeout", "8") or 8)
        client_ip = _login_client_ip()
        auth_source = "unknown"
        failure_reason = ""
        user_role = ""

        if lockout_enabled and username:
            locked, seconds_left = _is_login_temporarily_locked(username, client_ip)
            if locked:
                error = (
                    "Too many failed login attempts. "
                    f"Try again in {_format_lockout_countdown(seconds_left)}."
                )
                failure_reason = "login_locked"
                write_login_audit_log(username, auth_source, False, failure_reason)
                return render_template("login.html", error=error, info=info)

        if not username:
            error = "Username is required."
            failure_reason = "username_missing"
        elif not is_provisioned_app_user(username):
            error = "User is not provisioned in app settings."
            auth_source = "provisioning"
            failure_reason = "user_not_provisioned"
        else:
            user = find_user(users, username)
            auth_source = normalize_auth_source(user.get("auth_source", "ldap") if user else "ldap")
            user_role = normalize_role(str((user or {}).get("role", "")))
            if auth_source == "ldap":
                if not password:
                    error = "Password is required for LDAP users."
                    failure_reason = "password_missing"
                else:
                    ok, message = authenticate_with_ldap(username, password, ldap_settings)
                    if not ok:
                        error = message
                        failure_reason = "invalid_credentials" if message == "Incorrect username or password." else "ldap_auth_failed"
            else:
                ok, local_message, role = validate_local_user(username, password)
                if not ok and local_message == "PASSWORD_SETUP_REQUIRED":
                    session["pending_password_user"] = username
                    session["pending_password_role"] = role or "operator"
                    write_login_audit_log(username, auth_source, False, "password_setup_required")
                    return redirect(url_for("change_password"))
                if not ok:
                    error = local_message
                    failure_reason = (
                        "invalid_credentials"
                        if local_message == "Invalid local username or password."
                        else "local_auth_failed"
                    )

        if not error:
            session["auth_mode"] = "local"
            session["auth_backend"] = auth_source
            session["creds"] = {"username": username, "password": password, "timeout": timeout}
            session["device_creds"] = load_user_device_creds(username, "local")
            session["buttons"] = load_user_buttons(username, "local") or default_buttons()
            session.setdefault("run_history", [])
            session["last_activity_ts"] = int(time.time())
            if lockout_enabled and username:
                _clear_login_failure_state(username, client_ip)
            write_login_audit_log(username, auth_source, True, f"login_success role={user_role or 'unknown'}")
            return redirect(url_for("dashboard"))
        if lockout_enabled and username and failure_reason != "login_locked":
            now_locked, seconds_left, _attempts = _register_login_failure(username, client_ip, session_settings)
            if now_locked:
                error = (
                    "Too many failed login attempts. "
                    f"Account locked for {_format_lockout_countdown(seconds_left)}."
                )
                failure_reason = "login_locked"
        write_login_audit_log(username, auth_source, False, failure_reason or error or "login_failed")

    return render_template("login.html", error=error, info=info)


@app.route("/change-password", methods=["GET", "POST"])
def change_password() -> Any:
    username = session.get("pending_password_user", "")
    if not username:
        return redirect(url_for("login"))

    error = ""
    info = ""
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not new_password:
            error = "New password is required."
        elif new_password != confirm_password:
            error = "Passwords do not match."
        else:
            if verify_super_admin(username, new_password):
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = load_user_device_creds(username, "local")
                session["buttons"] = load_user_buttons(username, "local") or default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

            users = load_users()
            user = find_user(users, username)
            if user is None:
                error = "User no longer exists."
            else:
                set_user_password(user, new_password)
                user["must_change_password"] = False
                save_users(users)
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = load_user_device_creds(username, "local")
                session["buttons"] = load_user_buttons(username, "local") or default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

    return render_template("change_password.html", username=username, error=error, info=info)


@app.route("/settings/users", methods=["POST"])
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
            save_users(users)
            session["settings_info"] = f"Updated role for '{username}' to '{role_value}'."

    elif action == "set_user_rights":
        username = request.form.get("selected_username", "").strip()
        selected_categories = [c.strip() for c in request.form.getlist("allowed_categories") if c.strip()]
        selected_account_privileges = [p.strip() for p in request.form.getlist("account_privileges") if p.strip()]
        allowed_account_privileges = {"ip_addressing", "network_addressing", "net_devices", "devices", "monitoring"}
        selected_account_privileges = [p for p in selected_account_privileges if p in allowed_account_privileges]
        normalized_privileges: list[str] = []
        for privilege in selected_account_privileges:
            normalized_privilege = "net_devices" if privilege == "devices" else privilege
            if normalized_privilege not in normalized_privileges:
                normalized_privileges.append(normalized_privilege)
        selected_menu_access = [m.strip() for m in request.form.getlist("menu_access") if m.strip()]
        allowed_menu_access = set(default_menu_access().keys())
        selected_menu_access = [m for m in selected_menu_access if m in allowed_menu_access]
        menu_access_payload = normalize_menu_access({key: (key in selected_menu_access) for key in allowed_menu_access})

        user = find_user(users, username)
        if user is None:
            session["settings_error"] = "User not found."
        else:
            user["allowed_categories"] = selected_categories
            user["category_panel_access"] = {"menu_access": menu_access_payload}
            user["account_privileges"] = normalized_privileges
            user["admin_permissions"] = []
            save_users(users)
            session["settings_info"] = f"Updated user rights for '{username}'."

    return redirect(url_for("ise_settings_page", modal="users"))


@app.route("/notifications/read", methods=["POST"])
def mark_notifications_read_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    mark_notifications_read(username)
    session["dashboard_info"] = "Notifications marked as read."
    if str(request.form.get("next", "")).strip().lower() == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard", modal="notifications"))
    return redirect(url_for("dashboard"))


@app.route("/notifications/delete", methods=["POST"])
def delete_notification_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    notification_id = int(request.form.get("notification_id", "0") or 0)
    if notification_id > 0:
        delete_notification(username, notification_id)
        session["dashboard_info"] = "Notification deleted."
    if str(request.form.get("next", "")).strip().lower() == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard", modal="notifications"))
    return redirect(url_for("dashboard"))


@app.route("/pending-requests/cleanup", methods=["POST"])
def pending_requests_cleanup() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if not is_senior_user():
        session["dashboard_error"] = "Only Senior/SysAdmin users can delete processed requests."
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "").strip()
    request_id = int(request.form.get("request_id", "0") or 0)
    with db_conn() as conn:
        if action == "delete_one" and request_id > 0:
            conn.execute("DELETE FROM pending_device_requests WHERE id = ? AND status IN ('approved','rejected')", (request_id,))
            session["dashboard_info"] = f"Processed request #{request_id} deleted."
        elif action == "delete_all_closed":
            conn.execute("DELETE FROM pending_device_requests WHERE status IN ('approved','rejected')")
            session["dashboard_info"] = "All processed requests deleted."
    return redirect(url_for("dashboard"))


@app.route("/pending-requests", methods=["POST"])
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
            write_audit_log("request_rejected", requester, approver, device_name, {
                "request_id": request_id,
                "requester": requester,
                "reason": "device_missing",
            })
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
        write_audit_log("request_approved", requester, approver, device_name, {
            "request_id": request_id,
            "requester": requester,
            "fields": {
                "ip": {"from": original_ip, "to": proposed_ip},
                "categories": {"from": original_categories, "to": proposed_categories},
            },
        })
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
    write_audit_log("request_rejected", requester, approver, device_name, {
        "request_id": request_id,
        "requester": requester,
        "fields": {
            "ip": {"from": original_ip, "to": proposed_ip},
            "categories": {"from": original_categories, "to": proposed_categories},
        },
    })

    clear_senior_pending_request_notifications(request_id)
    session["dashboard_info"] = f"Rejected request #{request_id}."
    return redirect(post_action_redirect)


@app.route("/pending-command/decision", methods=["POST"])
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


@app.route("/logout")
def logout() -> Any:
    expired = request.args.get("expired") == "1"
    rid = str(session.get("runtime_session_id", ""))
    close_runtime_ssh_sessions(rid)
    session.clear()
    if expired:
        session["login_info"] = "Session expired due to inactivity. Please log in again."
    return redirect(url_for("login"))


@app.route("/audit-dashboard", methods=["GET"])
def audit_dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    role = current_user_role()
    if role not in {"audit", "senior", "sysadmin"}:
        session["dashboard_error"] = "You do not have access to Audit Dashboard."
        return redirect(url_for("dashboard"))

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    logs = load_audit_logs(500)
    return render_template(
        "audit_dashboard.html",
        logs=logs,
        current_user=current_username,
        current_user_role=role,
        auth_mode=str(session.get("auth_mode", "local")),
        info=session.pop("dashboard_info", ""),
        error=session.pop("dashboard_error", ""),
        unread_notifications_count=len(load_unread_notifications(current_username)),
    )


@app.route("/ip-addressing", methods=["GET"])
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
    if not can_access_ip_panel and not can_access_network_addressing_panel and not can_access_devices_panel and not can_access_monitoring_panel:
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
            if device["monitor_status"] != "up":
                ping_state, ping_latency = ping_host_status(str(device.get("host", "")).strip(), 2)
                if ping_state == "up":
                    device["monitor_status"] = "up"
                    device["status"] = "up"
                    device["monitor_severity"] = "ok"
                    if ping_latency is not None:
                        device["monitor_sla_ms"] = ping_latency
            if device["monitor_status"] != "up":
                ping_state, ping_latency = ping_host_status(str(device.get("host", "")).strip(), 2)
                if ping_state == "up":
                    device["monitor_status"] = "up"
                    device["status"] = "up"
                    if ping_latency is not None:
                        device["monitor_sla_ms"] = ping_latency
    monitoring_settings = load_monitoring_settings()
    monitored_device_names = [str(item).strip() for item in monitoring_settings.get("monitored_devices", []) if str(item).strip()] if can_access_monitoring_panel else []
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
            if node["monitor_status"] != "up":
                ping_state, ping_latency = ping_host_status(host, 2)
                if ping_state == "up":
                    node["monitor_status"] = "up"
                    node["status"] = "up"
                    if ping_latency is not None:
                        node["monitor_sla_ms"] = ping_latency
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
                str(node.get("name", "")).strip()
                for node in monitoring_visible_devices
                if str(node.get("name", "")).strip()
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
        menu_access["na_servers"] = False
        menu_access["na_network_devices"] = False
        menu_access["na_dmvpn"] = False
        menu_access["na_sim_cards"] = False
        menu_access["na_site_to_site"] = False
        menu_access["na_nat"] = False
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
            is_approved_notice = (
                "was approved" in lower_msg
                and ("critical command request" in lower_msg or "command request" in lower_msg)
            )
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


@app.route("/ip-addressing/live-data", methods=["GET"])
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
    if not can_access_ip_panel and not can_access_network_addressing_panel and not can_access_devices_panel and not can_access_monitoring_panel:
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
    monitored_device_names = [str(item).strip() for item in monitoring_settings.get("monitored_devices", []) if str(item).strip()] if can_access_monitoring_panel else []
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
            if node["monitor_status"] != "up":
                ping_state, ping_latency = ping_host_status(host, 2)
                if ping_state == "up":
                    node["monitor_status"] = "up"
                    node["status"] = "up"
                    node["monitor_severity"] = "ok"
                    if ping_latency is not None:
                        node["monitor_sla_ms"] = ping_latency
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
            monitoring_editable_device_names = [str(node.get("name", "")).strip() for node in monitoring_visible_devices if str(node.get("name", "")).strip()]

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


@app.route("/ip-branches", methods=["POST"])
def manage_ip_branches() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = str(request.form.get("action", "")).strip().lower()
    current_username_value = str(session.get("creds", {}).get("username", "")).strip()
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

        if is_senior_user():
            updated = [item for item in branches if item.lower() != branch_name.lower()]
            save_ip_branches(updated)
            write_audit_log("branch_delete_direct", current_username_value, current_username_value, branch_name, {"branch_name": branch_name})
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


@app.route("/ip-branches/request-add", methods=["POST"])
def request_ip_branch_add() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if current_user_role() == "audit":
        return redirect(url_for("audit_dashboard"))

    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403

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


@app.route("/ip-branches/request-delete", methods=["POST"])
def request_ip_branch_delete() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if current_user_role() == "audit":
        return jsonify({"ok": False, "error": "Audit role is read-only."}), 403

    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403

    branch_name = str(request.form.get("branch_name", "")).strip()
    if not branch_name:
        return jsonify({"ok": False, "error": "Select a branch to delete."}), 400

    if is_senior_user():
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

    return jsonify({
        "ok": True,
        "deleted": False,
        "request_id": request_id,
        "message": (
            f"Branch delete request #{request_id} sent to Senior for approval. "
            "After approval, use Notifications to Continue (Execute) or Cancel."
        ),
    })


@app.route("/ip-branches/state", methods=["GET", "POST"])
def ip_branch_state_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Not authenticated."}), 401

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if current_user_role() == "audit":
        return jsonify({"ok": False, "error": "Audit role is read-only."}), 403
    if not user_has_panel_access(current_username, auth_mode, "ip_addressing"):
        return jsonify({"ok": False, "error": "You do not have access to IP Addressing."}), 403

    if request.method == "GET":
        return jsonify({"ok": True, "branches": load_ip_branch_state()})

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


@app.route("/dashboard", methods=["GET"])
def dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    session.pop("super_admin_verified", None)

    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if role == "audit":
        return redirect(url_for("audit_dashboard"))
    return redirect(url_for("ip_addressing_dashboard"))


@app.route("/devices", methods=["POST"])
def manage_devices() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "add").strip()
    devices = load_devices()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")
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
                    mapped_rows.append({
                        "name": str(row.get(name_col, "") or "").strip(),
                        "ip": str(row.get(ip_col, "") or "").strip(),
                        "category": str(row.get(category_col, "") or "").strip() if category_col else "",
                    })

        if not mapped_rows:
            plain = csv.reader(lines)
            for parts in plain:
                if len(parts) < 2:
                    continue
                mapped_rows.append({
                    "name": str(parts[0]).strip(),
                    "ip": str(parts[1]).strip(),
                    "category": str(parts[2]).strip() if len(parts) > 2 else "",
                })

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


@app.route("/categories", methods=["POST"])
def manage_categories() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip()
    devices = load_devices()
    current_username = str(session.get("creds", {}).get("username", "")).strip()
    next_page = str(request.form.get("next", "")).strip().lower()
    dashboard_modal_url = url_for("ip_addressing_dashboard") if next_page == "ip_addressing" else url_for("dashboard", modal="device_settings")

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


@app.route("/buttons", methods=["POST"])
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
            buttons.append({
                "id": button_id,
                "label": label,
                "command": command,
                "mode": mode,
                "categories": selected_categories,
                "audience": audience,
            })
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


@app.route("/device-credentials", methods=["POST"])
def update_device_credentials() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    ssh_username = request.form.get("device_ssh_username", "").strip()
    ssh_password = request.form.get("device_ssh_password", "")
    enable_password = request.form.get("device_enable_password", "")
    current_username = str(session.get("creds", {}).get("username", "")).strip()

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
    auth_mode = str(session.get("auth_mode", "local"))
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


@app.route("/devices/test-connectivity", methods=["POST"])
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
    return jsonify({
        "ok": icmp_ok and ssh_ok,
        "message": " | ".join(status_lines),
        "icmp_ok": icmp_ok,
        "ssh_ok": ssh_ok,
    })


@app.route("/ping-selected", methods=["POST"])
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


def _collect_helpdesk_targets(
    payload: dict[str, Any]
) -> tuple[dict[str, list[str]], dict[str, dict[str, str]], dict[str, dict[str, int]]]:
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

    access_only = [
        row for row in rows.values()
        if str(row.get("mode", "")).strip().lower() == "access"
    ]
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


def allowed_preconfigured_commands(role: str | None = None) -> set[str]:
    source = get_buttons() if role is None else buttons_for_role(role)
    return {str(item.get("command", "")).strip() for item in source if str(item.get("command", "")).strip()}


def is_restricted_command_user(role: str) -> bool:
    return str(role or "").strip().lower() in {"junior", "helpdesk"}


def is_helpdesk_user(role: str) -> bool:
    return str(role or "").strip().lower() == "helpdesk"


def is_helpdesk_action_user(role: str) -> bool:
    return str(role or "").strip().lower() in {"helpdesk", "junior", "senior"}


@app.route("/helpdesk/interfaces", methods=["POST"])
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
        last_show_devices = [str(item).strip() for item in last_show_devices_raw if str(item).strip()] if isinstance(last_show_devices_raw, list) else []
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
            return jsonify({
                "ok": False,
                "error": "Run Show Err-disable on the currently selected device(s) first, then run Remove Err-disable without changing selection.",
            }), 400

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
            action_results.append({
                "device": device_name,
                "status": state,
                "output_preview": str(output or "")[:700],
            })

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
        return jsonify({
            "ok": True,
            "message": "Interface status loaded.",
            "devices": interface_tables,
        })
    return jsonify({
        "ok": True,
        "message": f"Action '{action}' completed on {success_count}/{len(action_results) or 0} device(s).",
        "actions": action_results,
        "devices": interface_tables,
    })


@app.route("/run", methods=["POST"])
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


@app.route("/run-api", methods=["POST"])
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


@app.route("/ssh-session-open", methods=["POST"])
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

    return jsonify({
        "ok": bool(opened),
        "opened": opened,
        "failed": failed,
        "error": "Could not open SSH session for selected devices." if not opened else "",
    })


@app.route("/run-session-api", methods=["POST"])
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


@app.context_processor
def inject_common_context() -> dict[str, Any]:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    can_access_devices = bool(current_username) and user_has_panel_access(current_username, auth_mode, "devices")
    return {
        "current_user": current_username,
        "auth_mode": auth_mode,
        "is_super_admin_session": is_current_session_super_admin(),
        "can_access_devices_panel": can_access_devices,
    }


if __name__ == "__main__":
    if embedded_monitoring_poller_enabled() and (os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug):
        ensure_monitoring_poller_started()
    app.run(host="0.0.0.0", port=8080, debug=True)
