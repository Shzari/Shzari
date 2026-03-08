from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import threading
import time
from typing import Any

from config_settings import SESSION_SETTINGS_FILE
from app.services.legacy_core_helpers import _load_app_setting_json, _save_app_setting_json

_AUTO_RESTART_PENDING = threading.Event()


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


def _schedule_self_restart(delay_seconds: float = 1.0) -> bool:
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
        if "http_enabled" not in data:
            return https_enabled
        http_enabled = bool(data.get("http_enabled", True))
        return https_enabled and not http_enabled
    except Exception:
        return False


def default_session_settings() -> dict[str, Any]:
    return {
        "idle_timeout_minutes": 15,
        "http_enabled": True,
        "https_enabled": True,
        "http_port": 8080,
        "https_port": 8443,
        "web_acl_enabled": False,
        "web_acl_entries": [],
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
    return defaults


def save_session_settings(settings: dict[str, Any]) -> None:
    http_enabled = bool(settings.get("http_enabled", True))
    https_enabled = bool(settings.get("https_enabled", False))
    if not http_enabled and not https_enabled:
        http_enabled = True
    acl_entries, _ = _normalize_web_acl_entries(settings.get("web_acl_entries", []))
    payload = {
        "idle_timeout_minutes": max(1, int(settings.get("idle_timeout_minutes", 15) or 15)),
        "http_enabled": http_enabled,
        "https_enabled": https_enabled,
        "http_port": max(1, min(65535, int(settings.get("http_port", 8080) or 8080))),
        "https_port": max(1, min(65535, int(settings.get("https_port", 8443) or 8443))),
        "web_acl_enabled": bool(settings.get("web_acl_enabled", False)),
        "web_acl_entries": acl_entries,
    }
    _save_app_setting_json("session_settings", payload)
    try:
        SESSION_SETTINGS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass
