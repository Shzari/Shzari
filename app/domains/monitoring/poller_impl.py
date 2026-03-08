from __future__ import annotations

from typing import Any


from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
ALL = _legacy.ALL
CommunityData = _legacy.CommunityData
Connection = _legacy.Connection
ContextData = _legacy.ContextData
DBError = _legacy.DBError
DBOperationalError = _legacy.DBOperationalError
DBRow = _legacy.DBRow
DEFAULT_LOG_DIR = _legacy.DEFAULT_LOG_DIR
DEVICES_FILE = _legacy.DEVICES_FILE
DEVICE_CREDS_FILE = _legacy.DEVICE_CREDS_FILE
EXTERNAL_LOGGING_SETTINGS_FILE = _legacy.EXTERNAL_LOGGING_SETTINGS_FILE
Flask = _legacy.Flask
IP_BRANCHES_FILE = _legacy.IP_BRANCHES_FILE
ISE_SETTINGS_FILE = _legacy.ISE_SETTINGS_FILE
LDAP3_AVAILABLE = _legacy.LDAP3_AVAILABLE
LDAPException = _legacy.LDAPException
MONITORING_SETTINGS_FILE = _legacy.MONITORING_SETTINGS_FILE
NTP_SETTINGS_FILE = _legacy.NTP_SETTINGS_FILE
ObjectIdentity = _legacy.ObjectIdentity
ObjectType = _legacy.ObjectType
PRIMARY_SQL_SERVER_CLIENT = _legacy.PRIMARY_SQL_SERVER_CLIENT
PRIMARY_SQL_SERVER_DB = _legacy.PRIMARY_SQL_SERVER_DB
PRIMARY_SQL_SERVER_DRIVER = _legacy.PRIMARY_SQL_SERVER_DRIVER
PRIMARY_SQL_SERVER_HOST = _legacy.PRIMARY_SQL_SERVER_HOST
PRIMARY_SQL_SERVER_PASSWORD = _legacy.PRIMARY_SQL_SERVER_PASSWORD
PRIMARY_SQL_SERVER_PORT = _legacy.PRIMARY_SQL_SERVER_PORT
PRIMARY_SQL_SERVER_USER = _legacy.PRIMARY_SQL_SERVER_USER
PROJECT_ROOT = _legacy.PROJECT_ROOT
PYMSSQL_AVAILABLE = _legacy.PYMSSQL_AVAILABLE
PYODBC_AVAILABLE = _legacy.PYODBC_AVAILABLE
PYSNMP_AVAILABLE = _legacy.PYSNMP_AVAILABLE
ProxyFix = _legacy.ProxyFix
RotatingFileHandler = _legacy.RotatingFileHandler
SECRET_KEY = _legacy.SECRET_KEY
SESSION_SETTINGS_FILE = _legacy.SESSION_SETTINGS_FILE
SSHResult = _legacy.SSHResult
SUBTREE = _legacy.SUBTREE
SUPER_ADMIN_FILE = _legacy.SUPER_ADMIN_FILE
Server = _legacy.Server
SnmpEngine = _legacy.SnmpEngine
ThreadPoolExecutor = _legacy.ThreadPoolExecutor
Tls = _legacy.Tls
USERS_FILE = _legacy.USERS_FILE
USER_BUTTONS_FILE = _legacy.USER_BUTTONS_FILE
UdpTransportTarget = _legacy.UdpTransportTarget
UsmUserData = _legacy.UsmUserData
WINRM_AVAILABLE = _legacy.WINRM_AVAILABLE
_AUTO_RESTART_PENDING = _legacy._AUTO_RESTART_PENDING
_configure_app_logging = _legacy._configure_app_logging
_env_true = _legacy._env_true
_hash_password = _legacy._hash_password
_is_client_ip_allowed_by_acl = _legacy._is_client_ip_allowed_by_acl
_normalize_web_acl_entries = _legacy._normalize_web_acl_entries
_request_actor = _legacy._request_actor
_resolve_client_ip = _legacy._resolve_client_ip
_safe_int = _legacy._safe_int
_schedule_self_restart = _legacy._schedule_self_restart
_session_https_enabled = _legacy._session_https_enabled
annotations = _legacy.annotations
app = _legacy.app
as_completed = _legacy.as_completed
asdict = _legacy.asdict
atexit = _legacy.atexit
audit_store_service = _legacy.audit_store_service
csv = _legacy.csv
datetime = _legacy.datetime
decrypt_secret = _legacy.decrypt_secret
encrypt_secret = _legacy.encrypt_secret
escape_filter_chars = _legacy.escape_filter_chars
g = _legacy.g
getCmd = _legacy.getCmd
got_request_exception = _legacy.got_request_exception
has_request_context = _legacy.has_request_context
hashlib = _legacy.hashlib
hmac = _legacy.hmac
ipaddress = _legacy.ipaddress
is_valid_ipv4 = _legacy.is_valid_ipv4
json = _legacy.json
jsonify = _legacy.jsonify
logging = _legacy.logging
nextCmd = _legacy.nextCmd
os = _legacy.os
pymssql = _legacy.pymssql
pyodbc = _legacy.pyodbc
pysnmp_hlapi = _legacy.pysnmp_hlapi
random = _legacy.random
re = _legacy.re
redirect = _legacy.redirect
render_template = _legacy.render_template
request = _legacy.request
secrets = _legacy.secrets
session = _legacy.session
socket = _legacy.socket
ssl = _legacy.ssl
struct = _legacy.struct
subprocess = _legacy.subprocess
sys = _legacy.sys
threading = _legacy.threading
time = _legacy.time
timedelta = _legacy.timedelta
timezone = _legacy.timezone
url_for = _legacy.url_for
usm3DESEDEPrivProtocol = _legacy.usm3DESEDEPrivProtocol
usmAesCfb128Protocol = _legacy.usmAesCfb128Protocol
usmAesCfb192Protocol = _legacy.usmAesCfb192Protocol
usmAesCfb256Protocol = _legacy.usmAesCfb256Protocol
usmDESPrivProtocol = _legacy.usmDESPrivProtocol
usmHMAC128SHA224AuthProtocol = _legacy.usmHMAC128SHA224AuthProtocol
usmHMAC192SHA256AuthProtocol = _legacy.usmHMAC192SHA256AuthProtocol
usmHMAC256SHA384AuthProtocol = _legacy.usmHMAC256SHA384AuthProtocol
usmHMAC384SHA512AuthProtocol = _legacy.usmHMAC384SHA512AuthProtocol
usmHMACMD5AuthProtocol = _legacy.usmHMACMD5AuthProtocol
usmHMACSHAAuthProtocol = _legacy.usmHMACSHAAuthProtocol
usmNoAuthProtocol = _legacy.usmNoAuthProtocol
usmNoPrivProtocol = _legacy.usmNoPrivProtocol
winrm = _legacy.winrm
# Fallback: keep any remaining legacy symbols available for extracted code paths
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "db_conn" not in globals():
    from app.services.db_service import db_conn
if "_cap_percent" not in globals():
    from app.domains.monitoring.collectors_impl import _cap_percent
if "MONITORING_POLLER_LOCK" not in globals():
    MONITORING_POLLER_LOCK = threading.Lock()
if "MONITORING_POLLER_THREAD" not in globals():
    MONITORING_POLLER_THREAD = None
if "MONITORING_POLLER_STOP" not in globals():
    MONITORING_POLLER_STOP = threading.Event()


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
            merged["snmpv3_auth_protocol"] = (
                str(profile.get("snmpv3_auth_protocol", "")).strip() or str(merged.get("snmpv3_auth_protocol", "sha")).strip()
            )
            merged["snmpv3_priv_protocol"] = (
                str(profile.get("snmpv3_priv_protocol", "")).strip() or str(merged.get("snmpv3_priv_protocol", "aes128")).strip()
            )
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
        targets.append(
            {
                "name": device_name,
                "host": host,
                "port": int(base.get("port", 22) or 22),
                "groups": groups,
            }
        )
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
