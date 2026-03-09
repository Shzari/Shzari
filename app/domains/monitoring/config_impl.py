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
        rows = conn.execute("SELECT device_name, host, profile_json, created_at, updated_at FROM monitoring_device_profiles").fetchall()
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
