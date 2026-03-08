from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)


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
