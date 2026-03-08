from __future__ import annotations

from typing import Any
from pathlib import Path


from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
ACCESS_ACCEPT = _legacy.ACCESS_ACCEPT
ACCESS_REJECT = _legacy.ACCESS_REJECT
ACCESS_REQUEST = _legacy.ACCESS_REQUEST
ALL = _legacy.ALL
ATTR_NAS_IP_ADDRESS = _legacy.ATTR_NAS_IP_ADDRESS
ATTR_NAS_PORT = _legacy.ATTR_NAS_PORT
ATTR_SERVICE_TYPE = _legacy.ATTR_SERVICE_TYPE
ATTR_USER_NAME = _legacy.ATTR_USER_NAME
ATTR_USER_PASSWORD = _legacy.ATTR_USER_PASSWORD
AUDIT_LOG_EXECUTOR = _legacy.AUDIT_LOG_EXECUTOR
CommunityData = _legacy.CommunityData
Connection = _legacy.Connection
ContextData = _legacy.ContextData
DBConnection = _legacy.DBConnection
DBCursor = _legacy.DBCursor
DBError = _legacy.DBError
DBOperationalError = _legacy.DBOperationalError
DBRow = _legacy.DBRow
DEFAULT_CATEGORY = _legacy.DEFAULT_CATEGORY
DEFAULT_LOG_DIR = _legacy.DEFAULT_LOG_DIR
DEVICES_FILE = _legacy.DEVICES_FILE
DEVICE_CREDS_FILE = _legacy.DEVICE_CREDS_FILE
EXTERNAL_LOGGING_SETTINGS_FILE = _legacy.EXTERNAL_LOGGING_SETTINGS_FILE
Flask = _legacy.Flask
IP_BRANCHES_FILE = _legacy.IP_BRANCHES_FILE
ISE_SETTINGS_FILE = _legacy.ISE_SETTINGS_FILE
LDAP3_AVAILABLE = _legacy.LDAP3_AVAILABLE
LDAPException = _legacy.LDAPException
MONITORING_POLLER_LOCK = _legacy.MONITORING_POLLER_LOCK
MONITORING_POLLER_STOP = _legacy.MONITORING_POLLER_STOP
MONITORING_POLLER_THREAD = _legacy.MONITORING_POLLER_THREAD
MONITORING_SETTINGS_FILE = _legacy.MONITORING_SETTINGS_FILE
NETWORK_ISP_ATM_TABLE_LOCK = _legacy.NETWORK_ISP_ATM_TABLE_LOCK
NETWORK_ISP_ATM_TABLE_READY = _legacy.NETWORK_ISP_ATM_TABLE_READY
NETWORK_ISP_BRANCH_TABLE_LOCK = _legacy.NETWORK_ISP_BRANCH_TABLE_LOCK
NETWORK_ISP_BRANCH_TABLE_READY = _legacy.NETWORK_ISP_BRANCH_TABLE_READY
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
RUNTIME_SSH_LOCK = _legacy.RUNTIME_SSH_LOCK
RUNTIME_SSH_SESSIONS = _legacy.RUNTIME_SSH_SESSIONS
RotatingFileHandler = _legacy.RotatingFileHandler
SECRET_KEY = _legacy.SECRET_KEY
SERVICE_TYPE_LOGIN = _legacy.SERVICE_TYPE_LOGIN
SESSION_SETTINGS_FILE = _legacy.SESSION_SETTINGS_FILE
SQLSERVER_PRIMARY_KEYS = _legacy.SQLSERVER_PRIMARY_KEYS
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
_adapt_param_style = _legacy._adapt_param_style
_configure_app_logging = _legacy._configure_app_logging
_connect_primary_sql_server = _legacy._connect_primary_sql_server
_convert_insert_or_ignore = _legacy._convert_insert_or_ignore
_convert_insert_or_replace = _legacy._convert_insert_or_replace
_env_true = _legacy._env_true
_extract_insert_parts = _legacy._extract_insert_parts
_hash_password = _legacy._hash_password
_is_client_ip_allowed_by_acl = _legacy._is_client_ip_allowed_by_acl
_normalize_web_acl_entries = _legacy._normalize_web_acl_entries
_pick_sql_client = _legacy._pick_sql_client
_primary_sql_server_conn_string = _legacy._primary_sql_server_conn_string
_request_actor = _legacy._request_actor
_resolve_client_ip = _legacy._resolve_client_ip
_rewrite_limit_clause = _legacy._rewrite_limit_clause
_safe_int = _legacy._safe_int
_schedule_self_restart = _legacy._schedule_self_restart
_session_https_enabled = _legacy._session_https_enabled
_split_sql_list = _legacy._split_sql_list
_transform_sql = _legacy._transform_sql
annotations = _legacy.annotations
app = _legacy.app
as_completed = _legacy.as_completed
asdict = _legacy.asdict
atexit = _legacy.atexit
audit_store_service = _legacy.audit_store_service
csv = _legacy.csv
datetime = _legacy.datetime
db_conn = _legacy.db_conn
decrypt_secret = _legacy.decrypt_secret
embedded_monitoring_poller_enabled = _legacy.embedded_monitoring_poller_enabled
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
register_all_routes = _legacy.register_all_routes
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


def _migration_dir() -> Path:
    return Path(PROJECT_ROOT) / "sql" / "migrations"


def _split_sql_batches(sql_text: str) -> list[str]:
    lines = sql_text.splitlines()
    batches: list[list[str]] = [[]]
    for line in lines:
        if str(line).strip().upper() == "GO":
            if batches[-1]:
                batches.append([])
            continue
        batches[-1].append(line)
    merged = ["\n".join(chunk).strip() for chunk in batches]
    return [chunk for chunk in merged if chunk]


def _ensure_schema_migrations_table(conn: Any) -> None:
    conn.execute("""
IF OBJECT_ID(N'dbo.schema_migrations', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.schema_migrations (
        version NVARCHAR(128) NOT NULL PRIMARY KEY,
        applied_at NVARCHAR(64) NOT NULL CONSTRAINT DF_schema_migrations_applied_at DEFAULT ''
    );
END
""")


def _migration_already_applied(conn: Any, version: str) -> bool:
    row = conn.execute(
        "SELECT TOP (1) version FROM schema_migrations WHERE version = ?",
        (str(version),),
    ).fetchone()
    return bool(row)


def _mark_migration_applied(conn: Any, version: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
        (str(version), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
    )


def _apply_sql_migration_file(conn: Any, migration_file: Path) -> None:
    sql_text = migration_file.read_text(encoding="utf-8")
    for statement in _split_sql_batches(sql_text):
        conn.execute(statement)


def _apply_sql_migrations(conn: Any) -> None:
    _ensure_schema_migrations_table(conn)
    migration_dir = _migration_dir()
    if not migration_dir.exists():
        return
    migration_files = sorted(migration_dir.glob("*.sql"))
    for migration_file in migration_files:
        version = migration_file.name
        if _migration_already_applied(conn, version):
            continue
        _apply_sql_migration_file(conn, migration_file)
        _mark_migration_applied(conn, version)


def init_db() -> None:
    with db_conn() as conn:
        _apply_sql_migrations(conn)
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
                            json.dumps(
                                item.get("account_privileges", ["ip_addressing", "network_addressing", "net_devices", "monitoring"])
                            ),
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
