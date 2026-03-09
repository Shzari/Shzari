#!/usr/bin/env python3
from __future__ import annotations

import csv
import atexit
import hashlib
import hmac
import ipaddress
import json
import logging
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
from logging.handlers import RotatingFileHandler

from flask import Flask, g, got_request_exception, has_request_context, jsonify, redirect, render_template, request, session, url_for
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
from app.services import audit_store_service

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

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_LOG_DIR = os.path.join(PROJECT_ROOT, "logs")


def _safe_int(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    from app.services.legacy_logging_helpers import _safe_int as _impl

    return _impl(value, fallback, minimum, maximum)


def _resolve_client_ip() -> str:
    from app.services.legacy_logging_helpers import _resolve_client_ip as _impl

    return _impl()


def _request_actor() -> tuple[str, str]:
    from app.services.legacy_logging_helpers import _request_actor as _impl

    return _impl()


def _configure_app_logging(flask_app: Flask) -> None:
    from app.services.legacy_logging_helpers import _configure_app_logging as _impl

    return _impl(flask_app)


def _env_true(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_web_acl_entries(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import _normalize_web_acl_entries as _impl

    return _impl(*args, **kwargs)


def _is_client_ip_allowed_by_acl(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import _is_client_ip_allowed_by_acl as _impl

    return _impl(*args, **kwargs)


_AUTO_RESTART_PENDING = threading.Event()


def _schedule_self_restart(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import _schedule_self_restart as _impl

    return _impl(*args, **kwargs)


def _session_https_enabled(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import _session_https_enabled as _impl

    return _impl(*args, **kwargs)


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
_configure_app_logging(app)
from app.routes import register_all_routes

register_all_routes(app)

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
AUDIT_LOG_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-log")
NETWORK_ISP_BRANCH_TABLE_LOCK = threading.Lock()
NETWORK_ISP_BRANCH_TABLE_READY = False
NETWORK_ISP_ATM_TABLE_LOCK = threading.Lock()
NETWORK_ISP_ATM_TABLE_READY = False


def embedded_monitoring_poller_enabled() -> bool:
    from app.services.legacy_sql_backend_helpers import embedded_monitoring_poller_enabled as _impl

    return _impl()


SQLSERVER_PRIMARY_KEYS: dict[str, list[str]] = {
    "app_settings": ["setting_key"],
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
    "network_isp_branch_rows": ["id"],
    "network_isp_atm_rows": ["id"],
}


def _split_sql_list(expr: str) -> list[str]:
    from app.services.legacy_sql_backend_helpers import _split_sql_list as _impl

    return _impl(expr)


def _extract_insert_parts(sql: str) -> tuple[str, list[str], list[str]] | None:
    from app.services.legacy_sql_backend_helpers import _extract_insert_parts as _impl

    return _impl(sql)


def _rewrite_limit_clause(sql: str) -> str:
    from app.services.legacy_sql_backend_helpers import _rewrite_limit_clause as _impl

    return _impl(sql)


def _convert_insert_or_ignore(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    from app.services.legacy_sql_backend_helpers import _convert_insert_or_ignore as _impl

    return _impl(sql, params)


def _convert_insert_or_replace(sql: str, params: tuple[Any, ...] | list[Any] | None) -> str:
    from app.services.legacy_sql_backend_helpers import _convert_insert_or_replace as _impl

    return _impl(sql, params)


def _transform_sql(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    from app.services.legacy_sql_backend_helpers import _transform_sql as _impl

    return _impl(sql, params)


def _adapt_param_style(sql: str, backend: str) -> str:
    from app.services.legacy_sql_backend_helpers import _adapt_param_style as _impl

    return _impl(sql, backend)


from app.services.legacy_sql_backend_helpers import DBConnection, DBCursor


def _primary_sql_server_conn_string() -> str:
    from app.services.legacy_sql_backend_helpers import _primary_sql_server_conn_string as _impl

    return _impl()


def _pick_sql_client() -> str:
    from app.services.legacy_sql_backend_helpers import _pick_sql_client as _impl

    return _impl()


def _connect_primary_sql_server() -> tuple[Any, str]:
    from app.services.legacy_sql_backend_helpers import _connect_primary_sql_server as _impl

    return _impl()


def db_conn() -> DBConnection:
    from app.services.legacy_sql_backend_helpers import db_conn as _impl

    return _impl()


def init_db() -> None:
    from app.services.legacy_db_init_handlers import init_db as _impl

    return _impl()


def migrate_legacy_json_to_db() -> None:
    from app.services.legacy_db_init_handlers import migrate_legacy_json_to_db as _impl

    return _impl()


init_db()


def super_admin_exists() -> bool:
    from app.services.legacy_core_helpers import super_admin_exists as _impl

    return _impl()


def load_super_admin() -> dict[str, Any]:
    from app.services.legacy_core_helpers import load_super_admin as _impl

    return _impl()


def save_super_admin(username: str, password: str) -> None:
    from app.services.legacy_core_helpers import save_super_admin as _impl

    return _impl(username, password)


def verify_super_admin(username: str, password: str) -> bool:
    from app.services.legacy_core_helpers import verify_super_admin as _impl

    return _impl(username, password)


def load_users(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import load_users as _impl

    return _impl(*args, **kwargs)


def save_users(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import save_users as _impl

    return _impl(*args, **kwargs)


def is_provisioned_app_user(username: str) -> bool:
    from app.services.legacy_core_helpers import is_provisioned_app_user as _impl

    return _impl(username)


def load_device_creds_store() -> dict[str, dict[str, str]]:
    from app.services.legacy_core_helpers import load_device_creds_store as _impl

    return _impl()


def save_device_creds_store(store: dict[str, dict[str, str]]) -> None:
    from app.services.legacy_core_helpers import save_device_creds_store as _impl

    return _impl(store)


def device_creds_key(account_username: str, auth_mode: str) -> str:
    from app.services.legacy_core_helpers import device_creds_key as _impl

    return _impl(account_username, auth_mode)


def load_user_device_creds(account_username: str, auth_mode: str) -> dict[str, str]:
    from app.services.legacy_core_helpers import load_user_device_creds as _impl

    return _impl(account_username, auth_mode)


def save_user_device_creds(account_username: str, auth_mode: str, creds: dict[str, str]) -> None:
    from app.services.legacy_core_helpers import save_user_device_creds as _impl

    return _impl(account_username, auth_mode, creds)


def _load_app_setting_json(setting_key: str, default_value: Any, legacy_file: Any | None = None) -> Any:
    from app.services.legacy_core_helpers import _load_app_setting_json as _impl

    return _impl(setting_key, default_value, legacy_file)


def _save_app_setting_json(setting_key: str, payload: Any) -> None:
    from app.services.legacy_core_helpers import _save_app_setting_json as _impl

    return _impl(setting_key, payload)


def load_user_buttons_store() -> dict[str, list[dict[str, Any]]]:
    from app.services.legacy_core_helpers import load_user_buttons_store as _impl

    return _impl()


def save_user_buttons_store(store: dict[str, list[dict[str, Any]]]) -> None:
    from app.services.legacy_core_helpers import save_user_buttons_store as _impl

    return _impl(store)


def load_user_buttons(account_username: str, auth_mode: str) -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import load_user_buttons as _impl

    return _impl(account_username, auth_mode)


def save_user_buttons(account_username: str, auth_mode: str, buttons: list[dict[str, Any]]) -> None:
    from app.services.legacy_core_helpers import save_user_buttons as _impl

    return _impl(account_username, auth_mode, buttons)


def default_session_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import default_session_settings as _impl

    return _impl(*args, **kwargs)


def load_session_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import load_session_settings as _impl

    return _impl(*args, **kwargs)


def save_session_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_session_acl_helpers import save_session_settings as _impl

    return _impl(*args, **kwargs)


def default_ntp_settings() -> dict[str, Any]:
    from app.services.legacy_file_settings_helpers import default_ntp_settings as _impl

    return _impl()


def load_ntp_settings() -> dict[str, Any]:
    from app.services.legacy_file_settings_helpers import load_ntp_settings as _impl

    return _impl()


def save_ntp_settings(settings: dict[str, Any]) -> None:
    from app.services.legacy_file_settings_helpers import save_ntp_settings as _impl

    return _impl(settings)


def default_external_logging_settings() -> dict[str, Any]:
    from app.services.legacy_file_settings_helpers import default_external_logging_settings as _impl

    return _impl()


def load_external_logging_settings() -> dict[str, Any]:
    from app.services.legacy_file_settings_helpers import load_external_logging_settings as _impl

    return _impl()


def save_external_logging_settings(settings: dict[str, Any]) -> None:
    from app.services.legacy_file_settings_helpers import save_external_logging_settings as _impl

    return _impl(settings)


def default_monitoring_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import default_monitoring_settings as _impl

    return _impl(*args, **kwargs)


def load_monitoring_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import load_monitoring_settings as _impl

    return _impl(*args, **kwargs)


def save_monitoring_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import save_monitoring_settings as _impl

    return _impl(*args, **kwargs)


def load_monitoring_category_options(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import load_monitoring_category_options as _impl

    return _impl(*args, **kwargs)


def ensure_monitoring_category_exists(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import ensure_monitoring_category_exists as _impl

    return _impl(*args, **kwargs)


def load_monitoring_device_profiles(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import load_monitoring_device_profiles as _impl

    return _impl(*args, **kwargs)


def save_monitoring_device_profile(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_config_helpers import save_monitoring_device_profile as _impl

    return _impl(*args, **kwargs)


def rename_device_everywhere(old_name: str, new_name: str, new_ip: str) -> None:
    from app.services.legacy_monitoring_config_helpers import rename_device_everywhere as _impl

    return _impl(old_name, new_name, new_ip)


def delete_device_everywhere(device_name: str) -> None:
    from app.services.legacy_monitoring_config_helpers import delete_device_everywhere as _impl

    return _impl(device_name)


def upsert_device_and_category_for_monitoring(device_name: str, ip_address: str, category: str) -> None:
    from app.services.legacy_monitoring_config_helpers import upsert_device_and_category_for_monitoring as _impl

    return _impl(device_name, ip_address, category)


def is_windows_servers_category(category_name: str) -> bool:
    from app.services.legacy_monitoring_config_helpers import is_windows_servers_category as _impl

    return _impl(category_name)


def monitoring_effective_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import monitoring_effective_settings as _impl

    return _impl(*args, **kwargs)


def _monitoring_device_lookup(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import _monitoring_device_lookup as _impl

    return _impl(*args, **kwargs)


def _monitoring_effective_category(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import _monitoring_effective_category as _impl

    return _impl(*args, **kwargs)


def _monitoring_pull_ssh_creds(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import _monitoring_pull_ssh_creds as _impl

    return _impl(*args, **kwargs)


def parse_monitoring_metrics(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import parse_monitoring_metrics as _impl

    return _impl(*args, **kwargs)


def _cap_percent(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import _cap_percent as _impl

    return _impl(*args, **kwargs)


def ping_host_status(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import ping_host_status as _impl

    return _impl(*args, **kwargs)


def winrm_collect_metrics(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import winrm_collect_metrics as _impl

    return _impl(*args, **kwargs)


def winrm_collect_live_gauges(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import winrm_collect_live_gauges as _impl

    return _impl(*args, **kwargs)


def _snmp_auth_data_from_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import _snmp_auth_data_from_settings as _impl

    return _impl(*args, **kwargs)


def snmp_get_value(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import snmp_get_value as _impl

    return _impl(*args, **kwargs)


def snmp_walk_values(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import snmp_walk_values as _impl

    return _impl(*args, **kwargs)


def snmp_walk_indexed_values(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import snmp_walk_indexed_values as _impl

    return _impl(*args, **kwargs)


def snmp_collect_interface_utilization(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import snmp_collect_interface_utilization as _impl

    return _impl(*args, **kwargs)


def snmp_collect_memory_percent(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import snmp_collect_memory_percent as _impl

    return _impl(*args, **kwargs)


def poll_device_monitoring_sample(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import poll_device_monitoring_sample as _impl

    return _impl(*args, **kwargs)


def save_monitoring_sample(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_collectors import save_monitoring_sample as _impl

    return _impl(*args, **kwargs)


def load_latest_monitoring_status_map(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import load_latest_monitoring_status_map as _impl

    return _impl(*args, **kwargs)


def load_monitoring_alerts(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import load_monitoring_alerts as _impl

    return _impl(*args, **kwargs)


def monitoring_poll_cycle(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import monitoring_poll_cycle as _impl

    return _impl(*args, **kwargs)


def monitoring_poller_loop(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import monitoring_poller_loop as _impl

    return _impl(*args, **kwargs)


def ensure_monitoring_poller_started(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import ensure_monitoring_poller_started as _impl

    return _impl(*args, **kwargs)


def stop_monitoring_poller(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import stop_monitoring_poller as _impl

    return _impl(*args, **kwargs)


def _stop_monitoring_poller_on_exit(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_monitoring_poller import _stop_monitoring_poller_on_exit as _impl

    return _impl(*args, **kwargs)


atexit.register(_stop_monitoring_poller_on_exit)


def _shutdown_audit_log_executor_on_exit() -> None:
    from app.services.legacy_request_context_helpers import shutdown_audit_log_executor_on_exit as _impl

    return _impl()


atexit.register(_shutdown_audit_log_executor_on_exit)


if hasattr(app, "before_serving"):

    @app.before_serving
    def _start_monitoring_poller_before_serving() -> None:
        if embedded_monitoring_poller_enabled():
            ensure_monitoring_poller_started()


if hasattr(app, "after_serving"):

    @app.after_serving
    def _stop_monitoring_poller_after_serving() -> None:
        stop_monitoring_poller(wait_seconds=1.5)


def seed_monitoring_sample_async(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_checks_helpers import seed_monitoring_sample_async as _impl

    return _impl(*args, **kwargs)


def sync_ntp_time(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_checks_helpers import sync_ntp_time as _impl

    return _impl(*args, **kwargs)


def test_ntp_connectivity(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_checks_helpers import test_ntp_connectivity as _impl

    return _impl(*args, **kwargs)


def run_ping_for_host(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_checks_helpers import run_ping_for_host as _impl

    return _impl(*args, **kwargs)


def find_user(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import find_user as _impl

    return _impl(*args, **kwargs)


def set_user_password(user: dict[str, Any], password: str) -> None:
    from app.services.legacy_core_helpers import set_user_password as _impl

    return _impl(user, password)


def is_current_session_super_admin() -> bool:
    from app.services.legacy_core_helpers import is_current_session_super_admin as _impl

    return _impl()


def normalize_role(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_role as _impl

    return _impl(*args, **kwargs)


def is_privileged_role(role: str) -> bool:
    from app.services.legacy_role_helpers import is_privileged_role as _impl

    return _impl(role)


def can_manage_monitoring_nodes(role: str) -> bool:
    from app.services.legacy_role_helpers import can_manage_monitoring_nodes as _impl

    return _impl(role)


def sysadmin_monitoring_servers_only(role: str) -> bool:
    from app.services.legacy_role_helpers import sysadmin_monitoring_servers_only as _impl

    return _impl(role)


def category_allowed_for_monitoring_add(role: str, category: str) -> bool:
    from app.services.legacy_role_helpers import category_allowed_for_monitoring_add as _impl

    return _impl(role, category)


def monitoring_user_allowed_for_category(username: str, auth_mode: str, category: str) -> bool:
    from app.services.legacy_role_helpers import monitoring_user_allowed_for_category as _impl

    return _impl(username, auth_mode, category)


def normalize_auth_source(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_auth_source as _impl

    return _impl(*args, **kwargs)


def current_user_role(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import current_user_role as _impl

    return _impl(*args, **kwargs)


def is_senior_user() -> bool:
    return is_privileged_role(current_user_role())


def notify_user(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import notify_user as _impl

    return _impl(*args, **kwargs)


def load_senior_notification_targets(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import load_senior_notification_targets as _impl

    return _impl(*args, **kwargs)


def notify_seniors_new_pending_request(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import notify_seniors_new_pending_request as _impl

    return _impl(*args, **kwargs)


def clear_senior_pending_request_notifications(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import clear_senior_pending_request_notifications as _impl

    return _impl(*args, **kwargs)


def load_unread_notifications(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import load_unread_notifications as _impl

    return _impl(*args, **kwargs)


def mark_notifications_read(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import mark_notifications_read as _impl

    return _impl(*args, **kwargs)


def delete_notification(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import delete_notification as _impl

    return _impl(*args, **kwargs)


def default_sql_server_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import default_sql_server_settings as _impl

    return _impl(*args, **kwargs)


def normalize_sql_table_name(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import normalize_sql_table_name as _impl

    return _impl(*args, **kwargs)


def load_sql_server_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import load_sql_server_settings as _impl

    return _impl(*args, **kwargs)


def save_sql_server_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import save_sql_server_settings as _impl

    return _impl(*args, **kwargs)


def _sql_server_conn_string(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _sql_server_conn_string as _impl

    return _impl(*args, **kwargs)


def _connect_sql_server_from_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _connect_sql_server_from_settings as _impl

    return _impl(*args, **kwargs)


def ensure_sql_server_log_table(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import ensure_sql_server_log_table as _impl

    return _impl(*args, **kwargs)


def test_sql_server_logging_connection(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import test_sql_server_logging_connection as _impl

    return _impl(*args, **kwargs)


def _write_external_sql_audit_log_sync(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _write_external_sql_audit_log_sync as _impl

    return _impl(*args, **kwargs)


def write_external_sql_audit_log(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import write_external_sql_audit_log as _impl

    return _impl(*args, **kwargs)


def _write_primary_audit_log_sync(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _write_primary_audit_log_sync as _impl

    return _impl(*args, **kwargs)


def _write_primary_login_audit_log_sync(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _write_primary_login_audit_log_sync as _impl

    return _impl(*args, **kwargs)


def _write_primary_action_log_sync(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _write_primary_action_log_sync as _impl

    return _impl(*args, **kwargs)


def _submit_background_log_write(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _submit_background_log_write as _impl

    return _impl(*args, **kwargs)


def write_audit_log(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import write_audit_log as _impl

    return _impl(*args, **kwargs)


def write_audit_log_safe(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import write_audit_log_safe as _impl

    return _impl(*args, **kwargs)


def write_login_audit_log(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import write_login_audit_log as _impl

    return _impl(*args, **kwargs)


def write_action_log(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import write_action_log as _impl

    return _impl(*args, **kwargs)


def _build_audit_log_summary(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _build_audit_log_summary as _impl

    return _impl(*args, **kwargs)


def _rows_to_audit_logs(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import _rows_to_audit_logs as _impl

    return _impl(*args, **kwargs)


def load_audit_logs_page(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import load_audit_logs_page as _impl

    return _impl(*args, **kwargs)


def load_audit_logs(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_audit_helpers import load_audit_logs as _impl

    return _impl(*args, **kwargs)


def create_pending_device_request(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import create_pending_device_request as _impl

    return _impl(*args, **kwargs)


def load_pending_device_requests(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import load_pending_device_requests as _impl

    return _impl(*args, **kwargs)


def load_pending_command_requests(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import load_pending_command_requests as _impl

    return _impl(*args, **kwargs)


def clear_senior_command_request_notifications(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import clear_senior_command_request_notifications as _impl

    return _impl(*args, **kwargs)


def load_pending_command_request_by_id(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import load_pending_command_request_by_id as _impl

    return _impl(*args, **kwargs)


def validate_local_user(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import validate_local_user as _impl

    return _impl(*args, **kwargs)


def upsert_user(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import upsert_user as _impl

    return _impl(*args, **kwargs)


def default_ip_branches(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import default_ip_branches as _impl

    return _impl(*args, **kwargs)


def _ipv4_to_int(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import _ipv4_to_int as _impl

    return _impl(*args, **kwargs)


def _int_to_ipv4(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import _int_to_ipv4 as _impl

    return _impl(*args, **kwargs)


def _cidr_to_mask(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import _cidr_to_mask as _impl

    return _impl(*args, **kwargs)


def _make_ip_rows(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import _make_ip_rows as _impl

    return _impl(*args, **kwargs)


def _seed_branch_state_from_names(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import _seed_branch_state_from_names as _impl

    return _impl(*args, **kwargs)


def load_ip_branch_state(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import load_ip_branch_state as _impl

    return _impl(*args, **kwargs)


def save_ip_branch_state(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_state_helpers import save_ip_branch_state as _impl

    return _impl(*args, **kwargs)


def _normalize_isp_branch_row(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _normalize_isp_branch_row as _impl

    return _impl(*args, **kwargs)


def _normalize_isp_atm_row(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _normalize_isp_atm_row as _impl

    return _impl(*args, **kwargs)


def _db_bool(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _db_bool as _impl

    return _impl(*args, **kwargs)


def _ensure_network_isp_branch_rows_table(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _ensure_network_isp_branch_rows_table as _impl

    return _impl(*args, **kwargs)


def _load_isp_branch_rows_from_db(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _load_isp_branch_rows_from_db as _impl

    return _impl(*args, **kwargs)


def _save_isp_branch_rows_to_db(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _save_isp_branch_rows_to_db as _impl

    return _impl(*args, **kwargs)


def load_isp_branch_rows(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import load_isp_branch_rows as _impl

    return _impl(*args, **kwargs)


def save_isp_branch_rows(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import save_isp_branch_rows as _impl

    return _impl(*args, **kwargs)


def _ensure_network_isp_atm_rows_table(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _ensure_network_isp_atm_rows_table as _impl

    return _impl(*args, **kwargs)


def _load_isp_atm_rows_from_db(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _load_isp_atm_rows_from_db as _impl

    return _impl(*args, **kwargs)


def _save_isp_atm_rows_to_db(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import _save_isp_atm_rows_to_db as _impl

    return _impl(*args, **kwargs)


def load_isp_atm_rows(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import load_isp_atm_rows as _impl

    return _impl(*args, **kwargs)


def save_isp_atm_rows(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_network_rows_helpers import save_isp_atm_rows as _impl

    return _impl(*args, **kwargs)


def load_ip_branches(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import load_ip_branches as _impl

    return _impl(*args, **kwargs)


def save_ip_branches(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import save_ip_branches as _impl

    return _impl(*args, **kwargs)


def load_devices(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import load_devices as _impl

    return _impl(*args, **kwargs)


def save_devices(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import save_devices as _impl

    return _impl(*args, **kwargs)


def grouped_devices(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import grouped_devices as _impl

    return _impl(*args, **kwargs)


def all_categories(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import all_categories as _impl

    return _impl(*args, **kwargs)


def user_allowed_categories(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_allowed_categories as _impl

    return _impl(*args, **kwargs)


def filter_devices_for_user(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import filter_devices_for_user as _impl

    return _impl(*args, **kwargs)


def user_has_panel_access(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_has_panel_access as _impl

    return _impl(*args, **kwargs)


def user_can_write_panel(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_can_write_panel as _impl

    return _impl(*args, **kwargs)


def default_panel_permissions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_panel_permissions as _impl

    return _impl(*args, **kwargs)


def normalize_panel_permissions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_panel_permissions as _impl

    return _impl(*args, **kwargs)


def default_menu_permissions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_menu_permissions as _impl

    return _impl(*args, **kwargs)


def normalize_menu_permissions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_menu_permissions as _impl

    return _impl(*args, **kwargs)


def default_menu_access(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_menu_access as _impl

    return _impl(*args, **kwargs)


def normalize_menu_access(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_menu_access as _impl

    return _impl(*args, **kwargs)


def user_menu_access(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_menu_access as _impl

    return _impl(*args, **kwargs)


def user_menu_permissions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_menu_permissions as _impl

    return _impl(*args, **kwargs)


def user_can_write_menu(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_can_write_menu as _impl

    return _impl(*args, **kwargs)


def user_allowed_categories_by_panel(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_allowed_categories_by_panel as _impl

    return _impl(*args, **kwargs)


def user_can_access_device(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_can_access_device as _impl

    return _impl(*args, **kwargs)


def user_can_assign_categories(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import user_can_assign_categories as _impl

    return _impl(*args, **kwargs)


def default_buttons(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_buttons as _impl

    return _impl(*args, **kwargs)


def normalize_buttons(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import normalize_buttons as _impl

    return _impl(*args, **kwargs)


def button_audience_for_role(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import button_audience_for_role as _impl

    return _impl(*args, **kwargs)


def buttons_for_role(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import buttons_for_role as _impl

    return _impl(*args, **kwargs)


def get_buttons(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import get_buttons as _impl

    return _impl(*args, **kwargs)


def persist_current_user_buttons(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import persist_current_user_buttons as _impl

    return _impl(*args, **kwargs)


def default_ise_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_ise_settings as _impl

    return _impl(*args, **kwargs)


def load_ise_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import load_ise_settings as _impl

    return _impl(*args, **kwargs)


def save_ise_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import save_ise_settings as _impl

    return _impl(*args, **kwargs)


def default_ldap_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import default_ldap_settings as _impl

    return _impl(*args, **kwargs)


def load_ldap_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import load_ldap_settings as _impl

    return _impl(*args, **kwargs)


def save_ldap_settings(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import save_ldap_settings as _impl

    return _impl(*args, **kwargs)


def _ldap_connect(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import _ldap_connect as _impl

    return _impl(*args, **kwargs)


def _ldap_resolve_user_dn(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import _ldap_resolve_user_dn as _impl

    return _impl(*args, **kwargs)


def authenticate_with_ldap(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import authenticate_with_ldap as _impl

    return _impl(*args, **kwargs)


def _radius_attr(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import _radius_attr as _impl

    return _impl(*args, **kwargs)


def _radius_encrypt_user_password(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import _radius_encrypt_user_password as _impl

    return _impl(*args, **kwargs)


def _authenticate_radius_server(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import _authenticate_radius_server as _impl

    return _impl(*args, **kwargs)


def authenticate_with_ise(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_auth_helpers import authenticate_with_ise as _impl

    return _impl(*args, **kwargs)


def runtime_session_id(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import runtime_session_id as _impl

    return _impl(*args, **kwargs)


def close_runtime_ssh_sessions(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import close_runtime_ssh_sessions as _impl

    return _impl(*args, **kwargs)


def get_runtime_device_session(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import get_runtime_device_session as _impl

    return _impl(*args, **kwargs)


def open_runtime_device_session(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import open_runtime_device_session as _impl

    return _impl(*args, **kwargs)


def run_runtime_device_command(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_core_helpers import run_runtime_device_command as _impl

    return _impl(*args, **kwargs)


def split_cli_commands(command: str) -> list[str]:
    from app.services.legacy_command_utils import split_cli_commands as _impl

    return _impl(command)


def normalize_config_command_text(command: str) -> str:
    from app.services.legacy_command_utils import normalize_config_command_text as _impl

    return _impl(command)


def _read_shell_output(channel: Any, timeout_seconds: int) -> str:
    from app.services.legacy_command_utils import _read_shell_output as _impl

    return _impl(channel, timeout_seconds)


def parse_branch_delete_command(command_text: str) -> str:
    from app.services.legacy_command_utils import parse_branch_delete_command as _impl

    return _impl(command_text)


def command_requires_senior_approval(command_text: str) -> bool:
    from app.services.legacy_command_utils import command_requires_senior_approval as _impl

    return _impl(command_text)


def notify_seniors_new_pending_command_request(
    request_id: int,
    requester_username: str,
    command_mode: str,
    command_text: str,
    device_names: list[str],
) -> None:
    from app.services.legacy_command_utils import notify_seniors_new_pending_command_request as _impl

    return _impl(request_id, requester_username, command_mode, command_text, device_names)


def create_pending_command_request(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_pending_helpers import create_pending_command_request as _impl

    return _impl(*args, **kwargs)


def run_config_commands(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_config_commands as _impl

    return _impl(*args, **kwargs)


def run_errdisable_recovery_sequence(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_errdisable_recovery_sequence as _impl

    return _impl(*args, **kwargs)


def run_ssh_command(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_ssh_command as _impl

    return _impl(*args, **kwargs)


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str, command_mode: str = "show") -> SSHResult:
    from app.services.legacy_command_utils import execute_for_device as _impl

    return _impl(device, creds, command, command_mode)


@app.before_request
def enforce_dashboard_session_timeout(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_timeout_handlers import enforce_dashboard_session_timeout as _impl

    return _impl(*args, **kwargs)


@app.after_request
def add_no_cache_headers(response: Any) -> Any:
    from app.services.legacy_request_context_helpers import add_no_cache_headers as _impl

    return _impl(response)


def ise_settings_page() -> Any:
    from app.services.legacy_settings_handlers import ise_settings_page as _impl

    return _impl()


def sql_server_settings_page() -> Any:
    from app.services.legacy_settings_handlers import sql_server_settings_page as _impl

    return _impl()


def sql_server_test_page() -> Any:
    from app.services.legacy_settings_handlers import sql_server_test_page as _impl

    return _impl()


def ldap_settings_page() -> Any:
    from app.services.legacy_settings_handlers import ldap_settings_page as _impl

    return _impl()


def ntp_test_page() -> Any:
    from app.services.legacy_settings_handlers import ntp_test_page as _impl

    return _impl()


def ntp_settings_page() -> Any:
    from app.services.legacy_settings_handlers import ntp_settings_page as _impl

    return _impl()


def session_settings_page() -> Any:
    from app.services.legacy_settings_handlers import session_settings_page as _impl

    return _impl()


def external_logging_settings_page() -> Any:
    from app.services.legacy_settings_handlers import external_logging_settings_page as _impl

    return _impl()


def monitoring_settings_page() -> Any:
    from app.services.legacy_settings_handlers import monitoring_settings_page as _impl

    return _impl()


def monitoring_node_add_page() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_add_page as _impl

    return _impl()


def monitoring_node_delete_page() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_delete_page as _impl

    return _impl()


def monitoring_category_add_page() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_category_add_page as _impl

    return _impl()


def monitoring_category_delete_page() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_category_delete_page as _impl

    return _impl()


def monitoring_category_rename_page() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_category_rename_page as _impl

    return _impl()


def monitoring_node_test_snmp_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_test_snmp_api as _impl

    return _impl()


def monitoring_node_resources_pull_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_resources_pull_api as _impl

    return _impl()


def monitoring_node_resources_save_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_resources_save_api as _impl

    return _impl()


def monitoring_alert_ack_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_alert_ack_api as _impl

    return _impl()


def monitoring_node_dashboard_data_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_dashboard_data_api as _impl

    return _impl()


def monitoring_node_live_gauges_api() -> Any:
    from app.services.legacy_monitoring_handlers import monitoring_node_live_gauges_api as _impl

    return _impl()


def manage_users() -> Any:
    from app.services.legacy_settings_handlers import manage_users as _impl

    return _impl()


def mark_notifications_read_route(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_dashboard_handlers import mark_notifications_read_route as _impl

    return _impl(*args, **kwargs)


def delete_notification_route(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_dashboard_handlers import delete_notification_route as _impl

    return _impl(*args, **kwargs)


def pending_requests_cleanup(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_dashboard_handlers import pending_requests_cleanup as _impl

    return _impl(*args, **kwargs)


def pending_requests_action() -> Any:
    from app.services.legacy_ipam_handlers import pending_requests_action as _impl

    return _impl()


def pending_command_decision() -> Any:
    from app.services.legacy_ipam_handlers import pending_command_decision as _impl

    return _impl()


def ip_addressing_dashboard() -> Any:
    from app.services.legacy_ipam_handlers import ip_addressing_dashboard as _impl

    return _impl()


def ip_addressing_live_data_api() -> Any:
    from app.services.legacy_ipam_handlers import ip_addressing_live_data_api as _impl

    return _impl()


def manage_ip_branches(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import manage_ip_branches as _impl

    return _impl(*args, **kwargs)


def request_ip_branch_add(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import request_ip_branch_add as _impl

    return _impl(*args, **kwargs)


def request_ip_branch_delete(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import request_ip_branch_delete as _impl

    return _impl(*args, **kwargs)


def ip_branch_state_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import ip_branch_state_api as _impl

    return _impl(*args, **kwargs)


def network_isp_branches_state_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import network_isp_branches_state_api as _impl

    return _impl(*args, **kwargs)


def network_isp_atms_state_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import network_isp_atms_state_api as _impl

    return _impl(*args, **kwargs)


def dashboard(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_dashboard_handlers import dashboard as _impl

    return _impl(*args, **kwargs)


def manage_devices() -> Any:
    from app.services.legacy_ipam_handlers import manage_devices as _impl

    return _impl()


def manage_categories() -> Any:
    from app.services.legacy_ipam_handlers import manage_categories as _impl

    return _impl()


def buttons_menu() -> Any:
    from app.services.legacy_ipam_handlers import buttons_menu as _impl

    return _impl()


def update_device_credentials(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import update_device_credentials as _impl

    return _impl(*args, **kwargs)


def test_device_connectivity(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_ip_branch_handlers import test_device_connectivity as _impl

    return _impl(*args, **kwargs)


def ping_selected_devices(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import ping_selected_devices as _impl

    return _impl(*args, **kwargs)


def _normalize_interface_key(name: str) -> str:
    from app.services.legacy_command_utils import _normalize_interface_key as _impl

    return _impl(name)


def _normalize_interface_status(status_raw: str) -> str:
    from app.services.legacy_command_utils import _normalize_interface_status as _impl

    return _impl(status_raw)


def _parse_show_interfaces_status(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import _parse_show_interfaces_status as _impl

    return _impl(*args, **kwargs)


def _parse_show_mac_table(output: str) -> dict[str, set[str]]:
    from app.services.legacy_command_utils import _parse_show_mac_table as _impl

    return _impl(output)


def _helpdesk_device_creds() -> dict[str, Any]:
    from app.services.legacy_command_utils import _helpdesk_device_creds as _impl

    return _impl()


def _collect_helpdesk_targets(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import _collect_helpdesk_targets as _impl

    return _impl(*args, **kwargs)


def _load_helpdesk_interfaces_for_device(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import _load_helpdesk_interfaces_for_device as _impl

    return _impl(*args, **kwargs)


def allowed_preconfigured_commands(role: str | None = None) -> set[str]:
    from app.services.legacy_role_helpers import allowed_preconfigured_commands as _impl

    return _impl(role)


def is_restricted_command_user(role: str) -> bool:
    from app.services.legacy_role_helpers import is_restricted_command_user as _impl

    return _impl(role)


def is_helpdesk_user(role: str) -> bool:
    from app.services.legacy_role_helpers import is_helpdesk_user as _impl

    return _impl(role)


def is_helpdesk_action_user(role: str) -> bool:
    from app.services.legacy_role_helpers import is_helpdesk_action_user as _impl

    return _impl(role)


def helpdesk_interfaces_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import helpdesk_interfaces_api as _impl

    return _impl(*args, **kwargs)


def run_commands(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_commands as _impl

    return _impl(*args, **kwargs)


def run_commands_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_commands_api as _impl

    return _impl(*args, **kwargs)


def open_ssh_sessions_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import open_ssh_sessions_api as _impl

    return _impl(*args, **kwargs)


def run_session_command_api(*args: Any, **kwargs: Any) -> Any:
    from app.services.legacy_command_handlers import run_session_command_api as _impl

    return _impl(*args, **kwargs)


@app.context_processor
def inject_common_context() -> dict[str, Any]:
    from app.services.legacy_request_context_helpers import inject_common_context as _impl

    return _impl()


if __name__ == "__main__":
    if embedded_monitoring_poller_enabled() and (os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug):
        ensure_monitoring_poller_started()
    app.run(host="0.0.0.0", port=8080, debug=True)
