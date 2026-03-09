from __future__ import annotations

import ipaddress
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
if "NETWORK_ISP_INTERNET_TABLE_LOCK" not in globals():
    NETWORK_ISP_INTERNET_TABLE_LOCK = threading.Lock()
if "NETWORK_ISP_INTERNET_TABLE_READY" not in globals():
    NETWORK_ISP_INTERNET_TABLE_READY = False


def _suggest_gateway_from_public_ip(value: Any) -> str:
    text = str(value or "").strip()
    try:
        ip = ipaddress.IPv4Address(text)
    except Exception:
        return ""
    parts = text.split(".")
    if len(parts) != 4:
        return ""
    try:
        last = int(parts[3])
    except Exception:
        return ""
    if last <= 1:
        return ""
    candidate = ipaddress.IPv4Address(int(ip) - 1)
    candidate_text = str(candidate)
    candidate_parts = candidate_text.split(".")
    if len(candidate_parts) != 4:
        return ""
    try:
        if int(candidate_parts[3]) <= 0:
            return ""
    except Exception:
        return ""
    return candidate_text


def _enforce_gateway_prefix_with_public_ip(public_ip: Any, gateway: Any) -> str:
    public_text = str(public_ip or "").strip()
    gateway_text = str(gateway or "").strip()
    try:
        ipaddress.IPv4Address(public_text)
        ipaddress.IPv4Address(gateway_text)
    except Exception:
        return gateway_text
    public_parts = public_text.split(".")
    gateway_parts = gateway_text.split(".")
    if len(public_parts) != 4 or len(gateway_parts) != 4:
        return gateway_text
    if public_parts[:3] == gateway_parts[:3]:
        return gateway_text
    return f"{public_parts[0]}.{public_parts[1]}.{public_parts[2]}.{gateway_parts[3]}"


def _normalize_isp_branch_row(item: Any) -> dict[str, Any]:
    raw = item if isinstance(item, dict) else {}
    row = {
        "branch_code": str(raw.get("branch_code", raw.get("branchCode", "")) or ""),
        "city": str(raw.get("city", "") or ""),
        "primary": str(raw.get("primary", "") or ""),
        "primary_wan": str(raw.get("primary_wan", raw.get("primaryWan", raw.get("wan", ""))) or ""),
        "primary_gateway": str(raw.get("primary_gateway", raw.get("primaryGateway", raw.get("gateway", ""))) or ""),
        "primary_cidr": str(raw.get("primary_cidr", raw.get("primaryCidr", raw.get("cidr", raw.get("subnet", "")))) or ""),
        "primary_bandwidth": str(
            raw.get("primary_bandwidth", raw.get("primaryBandwidth", raw.get("primary_bandwith", raw.get("bandwith", "")))) or ""
        ),
        "secondary": str(raw.get("secondary", "") or ""),
        "secondary_wan": str(raw.get("secondary_wan", raw.get("secondaryWan", "")) or ""),
        "secondary_gateway": str(raw.get("secondary_gateway", raw.get("secondaryGateway", "")) or ""),
        "secondary_cidr": str(raw.get("secondary_cidr", raw.get("secondaryCidr", "")) or ""),
        "secondary_bandwidth": str(raw.get("secondary_bandwidth", raw.get("secondaryBandwidth", raw.get("secondary_bandwith", ""))) or ""),
    }
    required = (
        "branch_code",
        "city",
        "primary",
        "primary_wan",
        "primary_gateway",
        "primary_cidr",
        "primary_bandwidth",
        "secondary",
        "secondary_wan",
        "secondary_gateway",
        "secondary_cidr",
        "secondary_bandwidth",
    )
    completed = all(str(row.get(key, "")).strip() for key in required)
    row["locked"] = bool(raw.get("locked", completed))
    return row


def _normalize_isp_atm_row(item: Any) -> dict[str, Any]:
    raw = item if isinstance(item, dict) else {}
    row = {
        "atm": str(raw.get("atm", raw.get("branch_code", raw.get("branchCode", ""))) or ""),
        "location": str(raw.get("location", raw.get("city", "")) or ""),
        "primary": str(raw.get("primary", "") or ""),
        "primary_wan": str(raw.get("primary_wan", raw.get("primaryWan", raw.get("wan", ""))) or ""),
        "primary_gateway": str(raw.get("primary_gateway", raw.get("primaryGateway", raw.get("gateway", ""))) or ""),
        "primary_cidr": str(raw.get("primary_cidr", raw.get("primaryCidr", raw.get("cidr", raw.get("subnet", "")))) or ""),
        "primary_bandwidth": str(
            raw.get("primary_bandwidth", raw.get("primaryBandwidth", raw.get("primary_bandwith", raw.get("bandwith", "")))) or ""
        ),
        "secondary": str(raw.get("secondary", "") or ""),
        "secondary_wan": str(raw.get("secondary_wan", raw.get("secondaryWan", "")) or ""),
        "secondary_gateway": str(raw.get("secondary_gateway", raw.get("secondaryGateway", "")) or ""),
        "secondary_cidr": str(raw.get("secondary_cidr", raw.get("secondaryCidr", "")) or ""),
        "secondary_bandwidth": str(raw.get("secondary_bandwidth", raw.get("secondaryBandwidth", raw.get("secondary_bandwith", ""))) or ""),
    }
    required = (
        "atm",
        "location",
        "primary",
        "primary_wan",
        "primary_gateway",
        "primary_cidr",
        "primary_bandwidth",
        "secondary",
        "secondary_wan",
        "secondary_gateway",
        "secondary_cidr",
        "secondary_bandwidth",
    )
    completed = all(str(row.get(key, "")).strip() for key in required)
    row["locked"] = bool(raw.get("locked", completed))
    return row


def _normalize_isp_internet_row(item: Any) -> dict[str, Any]:
    raw = item if isinstance(item, dict) else {}
    public_ip = str(raw.get("public_ip", raw.get("publicIp", "")) or "")
    gateway = str(raw.get("gateway", raw.get("public_gateway", raw.get("publicGateway", ""))) or "")
    if not gateway.strip():
        suggested = _suggest_gateway_from_public_ip(public_ip)
        if suggested:
            gateway = suggested
    row = {
        "site": str(raw.get("site", "") or ""),
        "isp": str(raw.get("isp", "") or ""),
        "public_ip": public_ip,
        "gateway": gateway,
        "subnet": str(raw.get("subnet", raw.get("cidr", "")) or ""),
        "bandwidth": str(raw.get("bandwidth", raw.get("bandwith", "")) or ""),
    }
    required = ("site", "isp", "public_ip", "gateway", "subnet", "bandwidth")
    completed = all(str(row.get(key, "")).strip() for key in required)
    requested_locked = bool(raw.get("locked", completed))
    row["locked"] = bool(requested_locked and completed)
    return row


def _db_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "on"}


def _ensure_network_isp_branch_rows_table() -> None:
    global NETWORK_ISP_BRANCH_TABLE_READY
    if NETWORK_ISP_BRANCH_TABLE_READY:
        return
    with NETWORK_ISP_BRANCH_TABLE_LOCK:
        if NETWORK_ISP_BRANCH_TABLE_READY:
            return
        with db_conn() as conn:
            conn.execute("""
IF OBJECT_ID(N'dbo.network_isp_branch_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_branch_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_branch_rows_order_rt DEFAULT 0,
            branch_code NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_branch_code_rt DEFAULT '',
            city NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_city_rt DEFAULT '',
            primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_name_rt DEFAULT '',
            primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_wan_rt DEFAULT '',
            primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_gateway_rt DEFAULT '',
            primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_cidr_rt DEFAULT '',
            primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_bandwidth_rt DEFAULT '',
            secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_name_rt DEFAULT '',
            secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_wan_rt DEFAULT '',
            secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_gateway_rt DEFAULT '',
            secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_cidr_rt DEFAULT '',
            secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_bandwidth_rt DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_branch_rows_locked_rt DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END
""")
            conn.execute("""
IF COL_LENGTH('dbo.network_isp_branch_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_branch_rows_order_rt2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_branch_rows', 'branch_code') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD branch_code NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_branch_code_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'city') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD city NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_city_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_name') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_name_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_wan') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_wan_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_gateway_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_cidr_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'primary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_primary_bandwidth_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_name') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_name_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_wan') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_wan_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_gateway_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_cidr_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'secondary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_branch_rows_secondary_bandwidth_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_branch_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_branch_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_branch_rows_locked_rt2 DEFAULT 0;
""")
            conn.execute("""
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_branch_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_branch_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_branch_rows_order ON dbo.network_isp_branch_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
""")
        NETWORK_ISP_BRANCH_TABLE_READY = True


def _load_isp_branch_rows_from_db() -> list[dict[str, Any]]:
    _ensure_network_isp_branch_rows_table()
    with db_conn() as conn:
        rows = conn.execute("""
            SELECT
                row_order,
                branch_code,
                city,
                primary_name,
                primary_wan,
                primary_gateway,
                primary_cidr,
                primary_bandwidth,
                secondary_name,
                secondary_wan,
                secondary_gateway,
                secondary_cidr,
                secondary_bandwidth,
                locked
            FROM network_isp_branch_rows
            ORDER BY row_order ASC, id ASC
            """).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            _normalize_isp_branch_row(
                {
                    "branch_code": row["branch_code"],
                    "city": row["city"],
                    "primary": row["primary_name"],
                    "primary_wan": row["primary_wan"],
                    "primary_gateway": row["primary_gateway"],
                    "primary_cidr": row["primary_cidr"],
                    "primary_bandwidth": row["primary_bandwidth"],
                    "secondary": row["secondary_name"],
                    "secondary_wan": row["secondary_wan"],
                    "secondary_gateway": row["secondary_gateway"],
                    "secondary_cidr": row["secondary_cidr"],
                    "secondary_bandwidth": row["secondary_bandwidth"],
                    "locked": _db_bool(row["locked"]),
                }
            )
        )
    return out


def _save_isp_branch_rows_to_db(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _ensure_network_isp_branch_rows_table()
    normalized = [_normalize_isp_branch_row(item) for item in (rows if isinstance(rows, list) else [])]
    with db_conn() as conn:
        conn.execute("DELETE FROM network_isp_branch_rows")
        for index, row in enumerate(normalized):
            conn.execute(
                """
                INSERT INTO network_isp_branch_rows(
                    row_order,
                    branch_code,
                    city,
                    primary_name,
                    primary_wan,
                    primary_gateway,
                    primary_cidr,
                    primary_bandwidth,
                    secondary_name,
                    secondary_wan,
                    secondary_gateway,
                    secondary_cidr,
                    secondary_bandwidth,
                    locked
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    index,
                    row["branch_code"],
                    row["city"],
                    row["primary"],
                    row["primary_wan"],
                    row["primary_gateway"],
                    row["primary_cidr"],
                    row["primary_bandwidth"],
                    row["secondary"],
                    row["secondary_wan"],
                    row["secondary_gateway"],
                    row["secondary_cidr"],
                    row["secondary_bandwidth"],
                    1 if bool(row.get("locked")) else 0,
                ),
            )
    return normalized


def load_isp_branch_rows() -> list[dict[str, Any]]:
    try:
        rows = _load_isp_branch_rows_from_db()
        if rows:
            return rows
    except Exception:
        rows = []

    # One-time migration path from previous app_settings storage.
    payload = _load_app_setting_json("network_isp_branch_rows", [], None)
    if isinstance(payload, list) and payload:
        try:
            return _save_isp_branch_rows_to_db(payload)
        except Exception:
            return [_normalize_isp_branch_row(item) for item in payload]
    return []


def save_isp_branch_rows(rows: list[dict[str, Any]]) -> None:
    normalized = _save_isp_branch_rows_to_db(rows)
    # Keep backward-compatible copy for recovery/fallback paths.
    try:
        _save_app_setting_json("network_isp_branch_rows", normalized)
    except Exception:
        pass


def _ensure_network_isp_atm_rows_table() -> None:
    global NETWORK_ISP_ATM_TABLE_READY
    if NETWORK_ISP_ATM_TABLE_READY:
        return
    with NETWORK_ISP_ATM_TABLE_LOCK:
        if NETWORK_ISP_ATM_TABLE_READY:
            return
        with db_conn() as conn:
            conn.execute("""
IF OBJECT_ID(N'dbo.network_isp_atm_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_atm_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_atm_rows_order_rt DEFAULT 0,
            atm NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_atm_rt DEFAULT '',
            location NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_location_rt DEFAULT '',
            primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_name_rt DEFAULT '',
            primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_wan_rt DEFAULT '',
            primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_gateway_rt DEFAULT '',
            primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_cidr_rt DEFAULT '',
            primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_bandwidth_rt DEFAULT '',
            secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_name_rt DEFAULT '',
            secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_wan_rt DEFAULT '',
            secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_gateway_rt DEFAULT '',
            secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_cidr_rt DEFAULT '',
            secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_bandwidth_rt DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_atm_rows_locked_rt DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END
""")
            conn.execute("""
IF COL_LENGTH('dbo.network_isp_atm_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_atm_rows_order_rt2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_atm_rows', 'atm') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD atm NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_atm_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'location') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD location NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_location_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_name') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_name_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_wan') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_wan_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_gateway_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_cidr_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'primary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD primary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_primary_bandwidth_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_name') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_name NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_name_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_wan') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_wan NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_wan_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_gateway') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_gateway_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_cidr') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_cidr NVARCHAR(32) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_cidr_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'secondary_bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD secondary_bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_atm_rows_secondary_bandwidth_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_atm_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_atm_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_atm_rows_locked_rt2 DEFAULT 0;
""")
            conn.execute("""
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_atm_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_atm_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_atm_rows_order ON dbo.network_isp_atm_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
""")
        NETWORK_ISP_ATM_TABLE_READY = True


def _load_isp_atm_rows_from_db() -> list[dict[str, Any]]:
    _ensure_network_isp_atm_rows_table()
    with db_conn() as conn:
        rows = conn.execute("""
            SELECT
                row_order,
                atm,
                location,
                primary_name,
                primary_wan,
                primary_gateway,
                primary_cidr,
                primary_bandwidth,
                secondary_name,
                secondary_wan,
                secondary_gateway,
                secondary_cidr,
                secondary_bandwidth,
                locked
            FROM network_isp_atm_rows
            ORDER BY row_order ASC, id ASC
            """).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            _normalize_isp_atm_row(
                {
                    "atm": row["atm"],
                    "location": row["location"],
                    "primary": row["primary_name"],
                    "primary_wan": row["primary_wan"],
                    "primary_gateway": row["primary_gateway"],
                    "primary_cidr": row["primary_cidr"],
                    "primary_bandwidth": row["primary_bandwidth"],
                    "secondary": row["secondary_name"],
                    "secondary_wan": row["secondary_wan"],
                    "secondary_gateway": row["secondary_gateway"],
                    "secondary_cidr": row["secondary_cidr"],
                    "secondary_bandwidth": row["secondary_bandwidth"],
                    "locked": _db_bool(row["locked"]),
                }
            )
        )
    return out


def _save_isp_atm_rows_to_db(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _ensure_network_isp_atm_rows_table()
    normalized = [_normalize_isp_atm_row(item) for item in (rows if isinstance(rows, list) else [])]
    with db_conn() as conn:
        conn.execute("DELETE FROM network_isp_atm_rows")
        for index, row in enumerate(normalized):
            conn.execute(
                """
                INSERT INTO network_isp_atm_rows(
                    row_order,
                    atm,
                    location,
                    primary_name,
                    primary_wan,
                    primary_gateway,
                    primary_cidr,
                    primary_bandwidth,
                    secondary_name,
                    secondary_wan,
                    secondary_gateway,
                    secondary_cidr,
                    secondary_bandwidth,
                    locked
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    index,
                    row["atm"],
                    row["location"],
                    row["primary"],
                    row["primary_wan"],
                    row["primary_gateway"],
                    row["primary_cidr"],
                    row["primary_bandwidth"],
                    row["secondary"],
                    row["secondary_wan"],
                    row["secondary_gateway"],
                    row["secondary_cidr"],
                    row["secondary_bandwidth"],
                    1 if bool(row.get("locked")) else 0,
                ),
            )
    return normalized


def load_isp_atm_rows() -> list[dict[str, Any]]:
    try:
        rows = _load_isp_atm_rows_from_db()
        if rows:
            return rows
    except Exception:
        rows = []

    payload = _load_app_setting_json("network_isp_atm_rows", [], None)
    if isinstance(payload, list) and payload:
        try:
            return _save_isp_atm_rows_to_db(payload)
        except Exception:
            return [_normalize_isp_atm_row(item) for item in payload]
    return []


def save_isp_atm_rows(rows: list[dict[str, Any]]) -> None:
    normalized = _save_isp_atm_rows_to_db(rows)
    # Keep backward-compatible copy for recovery/fallback paths.
    try:
        _save_app_setting_json("network_isp_atm_rows", normalized)
    except Exception:
        pass


def _ensure_network_isp_internet_rows_table() -> None:
    global NETWORK_ISP_INTERNET_TABLE_READY
    if NETWORK_ISP_INTERNET_TABLE_READY:
        return
    with NETWORK_ISP_INTERNET_TABLE_LOCK:
        if NETWORK_ISP_INTERNET_TABLE_READY:
            return
        with db_conn() as conn:
            conn.execute("""
IF OBJECT_ID(N'dbo.network_isp_internet_rows', N'U') IS NULL
BEGIN
    BEGIN TRY
        CREATE TABLE dbo.network_isp_internet_rows (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order_rt DEFAULT 0,
            site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site_rt DEFAULT '',
            isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp_rt DEFAULT '',
            public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip_rt DEFAULT '',
            gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway_rt DEFAULT '',
            subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet_rt DEFAULT '',
            bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth_rt DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked_rt DEFAULT 0
        );
    END TRY
    BEGIN CATCH
        IF ERROR_NUMBER() <> 2714
            THROW;
    END CATCH
END
""")
            conn.execute("""
IF COL_LENGTH('dbo.network_isp_internet_rows', 'row_order') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order_rt2 DEFAULT 0;
IF COL_LENGTH('dbo.network_isp_internet_rows', 'site') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'isp') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'public_ip') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'gateway') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'subnet') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'bandwidth') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth_rt2 DEFAULT '';
IF COL_LENGTH('dbo.network_isp_internet_rows', 'locked') IS NULL
    ALTER TABLE dbo.network_isp_internet_rows ADD locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked_rt2 DEFAULT 0;
""")
            conn.execute("""
IF EXISTS (
    SELECT 1
    FROM sys.columns gateway_col
    INNER JOIN sys.columns subnet_col ON gateway_col.object_id = subnet_col.object_id
    WHERE gateway_col.object_id = OBJECT_ID(N'dbo.network_isp_internet_rows')
      AND gateway_col.name = 'gateway'
      AND subnet_col.name = 'subnet'
      AND gateway_col.column_id > subnet_col.column_id
)
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION;

        IF OBJECT_ID(N'dbo.network_isp_internet_rows_rebuild', N'U') IS NOT NULL
            DROP TABLE dbo.network_isp_internet_rows_rebuild;

        CREATE TABLE dbo.network_isp_internet_rows_rebuild (
            id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
            row_order INT NOT NULL CONSTRAINT DF_network_isp_internet_rows_order_rt_rebuild DEFAULT 0,
            site NVARCHAR(255) NOT NULL CONSTRAINT DF_network_isp_internet_rows_site_rt_rebuild DEFAULT '',
            isp NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_isp_rt_rebuild DEFAULT '',
            public_ip NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_public_ip_rt_rebuild DEFAULT '',
            gateway NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_gateway_rt_rebuild DEFAULT '',
            subnet NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_subnet_rt_rebuild DEFAULT '',
            bandwidth NVARCHAR(64) NOT NULL CONSTRAINT DF_network_isp_internet_rows_bandwidth_rt_rebuild DEFAULT '',
            locked BIT NOT NULL CONSTRAINT DF_network_isp_internet_rows_locked_rt_rebuild DEFAULT 0
        );

        SET IDENTITY_INSERT dbo.network_isp_internet_rows_rebuild ON;
        INSERT INTO dbo.network_isp_internet_rows_rebuild (
            id, row_order, site, isp, public_ip, gateway, subnet, bandwidth, locked
        )
        SELECT
            id,
            row_order,
            site,
            isp,
            public_ip,
            ISNULL(gateway, ''),
            subnet,
            bandwidth,
            locked
        FROM dbo.network_isp_internet_rows
        ORDER BY id ASC;
        SET IDENTITY_INSERT dbo.network_isp_internet_rows_rebuild OFF;

        DROP TABLE dbo.network_isp_internet_rows;
        EXEC sp_rename N'dbo.network_isp_internet_rows_rebuild', N'network_isp_internet_rows';

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF XACT_STATE() <> 0
            ROLLBACK TRANSACTION;
        THROW;
    END CATCH
END
""")
            conn.execute("""
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_network_isp_internet_rows_order' AND object_id = OBJECT_ID(N'dbo.network_isp_internet_rows'))
BEGIN TRY
    CREATE INDEX IX_network_isp_internet_rows_order ON dbo.network_isp_internet_rows(row_order ASC, id ASC);
END TRY
BEGIN CATCH
    IF ERROR_NUMBER() NOT IN (1913, 2714)
        THROW;
END CATCH
""")
        NETWORK_ISP_INTERNET_TABLE_READY = True


def _load_isp_internet_rows_from_db() -> list[dict[str, Any]]:
    _ensure_network_isp_internet_rows_table()
    with db_conn() as conn:
        rows = conn.execute(
            """
            SELECT
                row_order,
                site,
                isp,
                public_ip,
                gateway,
                subnet,
                bandwidth,
                locked
            FROM network_isp_internet_rows
            ORDER BY row_order ASC, id ASC
            """
        ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            _normalize_isp_internet_row(
                {
                    "site": row["site"],
                    "isp": row["isp"],
                    "public_ip": row["public_ip"],
                    "gateway": row["gateway"],
                    "subnet": row["subnet"],
                    "bandwidth": row["bandwidth"],
                    "locked": _db_bool(row["locked"]),
                }
            )
        )
    return out


def _save_isp_internet_rows_to_db(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    _ensure_network_isp_internet_rows_table()
    normalized = [_normalize_isp_internet_row(item) for item in (rows if isinstance(rows, list) else [])]
    with db_conn() as conn:
        conn.execute("DELETE FROM network_isp_internet_rows")
        for index, row in enumerate(normalized):
            conn.execute(
                """
                INSERT INTO network_isp_internet_rows(
                    row_order,
                    site,
                    isp,
                    public_ip,
                    gateway,
                    subnet,
                    bandwidth,
                    locked
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    index,
                    row["site"],
                    row["isp"],
                    row["public_ip"],
                    row["gateway"],
                    row["subnet"],
                    row["bandwidth"],
                    1 if bool(row.get("locked")) else 0,
                ),
            )
    return normalized


def load_isp_internet_rows() -> list[dict[str, Any]]:
    try:
        rows = _load_isp_internet_rows_from_db()
        if rows:
            return rows
    except Exception:
        rows = []

    payload = _load_app_setting_json("network_isp_internet_rows", [], None)
    if isinstance(payload, list) and payload:
        try:
            return _save_isp_internet_rows_to_db(payload)
        except Exception:
            return [_normalize_isp_internet_row(item) for item in payload]
    return []


def save_isp_internet_rows(rows: list[dict[str, Any]]) -> None:
    normalized = _save_isp_internet_rows_to_db(rows)
    # Keep backward-compatible copy for recovery/fallback paths.
    try:
        _save_app_setting_json("network_isp_internet_rows", normalized)
    except Exception:
        pass
