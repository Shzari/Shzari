#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import threading
import time
from pathlib import Path
from typing import Any

from app import create_app
from app.legacy import embedded_monitoring_poller_enabled, ensure_monitoring_poller_started
from config_settings import SESSION_SETTINGS_FILE
from werkzeug.serving import make_server

app = create_app()


def _is_true(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_web_runtime_settings() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "http_enabled": True,
        "https_enabled": False,
        "http_port": 8080,
        "https_port": 8443,
    }
    try:
        if not SESSION_SETTINGS_FILE.exists():
            return defaults
        with SESSION_SETTINGS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return defaults
        https_enabled = bool(data.get("https_enabled", False))
        if "http_enabled" in data:
            http_enabled = bool(data.get("http_enabled", True))
        else:
            # Backward compatibility with older settings payload.
            http_enabled = True
        if not http_enabled and not https_enabled:
            http_enabled = True
        defaults["http_enabled"] = http_enabled
        defaults["https_enabled"] = https_enabled
        defaults["http_port"] = max(1, min(65535, int(data.get("http_port", 8080) or 8080)))
        defaults["https_port"] = max(1, min(65535, int(data.get("https_port", 8443) or 8443)))
    except Exception:
        return defaults
    return defaults


def _resolve_ssl_context(use_https: bool) -> Any | None:
    """
    HTTPS modes:
    - APP_HTTPS=0 (default): HTTP only
    - APP_HTTPS=1 + APP_SSL_CERT + APP_SSL_KEY: use provided cert/key
    - APP_HTTPS=1 + APP_SSL_ADHOC=1: use Werkzeug ad-hoc cert (dev only)
    """
    if not use_https:
        return None
    cert_path = str(os.environ.get("APP_SSL_CERT", "")).strip()
    key_path = str(os.environ.get("APP_SSL_KEY", "")).strip()
    if cert_path and key_path:
        cert_file = Path(cert_path).expanduser()
        key_file = Path(key_path).expanduser()
        if not cert_file.exists():
            raise RuntimeError(f"APP_SSL_CERT file not found: {cert_file}")
        if not key_file.exists():
            raise RuntimeError(f"APP_SSL_KEY file not found: {key_file}")
        return (str(cert_file), str(key_file))
    # Default to ad-hoc cert for HTTPS mode when explicit cert/key are not provided.
    if _is_true(os.environ.get("APP_SSL_ADHOC", "1")):
        return "adhoc"
    raise RuntimeError(
        "HTTPS requested but certificate is missing. Set APP_SSL_CERT and APP_SSL_KEY, "
        "or set APP_SSL_ADHOC=1 for development."
    )


def _run_dual_web_servers(host: str, http_port: int, https_port: int, ssl_context: Any, debug_mode: bool) -> None:
    app.debug = debug_mode
    http_server = make_server(host, http_port, app, threaded=True)
    https_server = make_server(host, https_port, app, ssl_context=ssl_context, threaded=True)

    def _serve_http() -> None:
        http_server.serve_forever()

    def _serve_https() -> None:
        https_server.serve_forever()

    http_thread = threading.Thread(target=_serve_http, name="http-server", daemon=True)
    https_thread = threading.Thread(target=_serve_https, name="https-server", daemon=True)
    http_thread.start()
    https_thread.start()

    print(f"Starting web app on http://{host}:{http_port}")
    print(f"Starting web app on https://{host}:{https_port}")
    if debug_mode:
        print("Dual HTTP+HTTPS mode runs without Flask reloader.")
    try:
        while http_thread.is_alive() and https_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping web app...")


if __name__ == "__main__":
    if embedded_monitoring_poller_enabled() and (os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug):
        ensure_monitoring_poller_started()
    settings = _load_web_runtime_settings()
    host = str(os.environ.get("APP_HOST", "0.0.0.0")).strip() or "0.0.0.0"
    http_env_raw = str(os.environ.get("APP_HTTP", "")).strip()
    https_env_raw = str(os.environ.get("APP_HTTPS", "")).strip()
    http_enabled = _is_true(http_env_raw) if http_env_raw else bool(settings.get("http_enabled", True))
    https_enabled = _is_true(https_env_raw) if https_env_raw else bool(settings.get("https_enabled", False))
    if not http_enabled and not https_enabled:
        http_enabled = True
    debug_mode = _is_true(os.environ.get("APP_DEBUG", "1"))
    http_port = int(settings.get("http_port", 8080))
    https_port = int(settings.get("https_port", 8443))
    if str(os.environ.get("APP_PORT", "")).strip():
        try:
            port = int(str(os.environ.get("APP_PORT", "8080")).strip() or "8080")
        except Exception:
            port = 8080
        use_https = https_enabled and not http_enabled
        ssl_context = _resolve_ssl_context(use_https)
        scheme = "https" if ssl_context else "http"
        print(f"Starting web app on {scheme}://{host}:{port}")
        app.run(host=host, port=port, debug=debug_mode, ssl_context=ssl_context)
    elif http_enabled and https_enabled:
        ssl_context = _resolve_ssl_context(True)
        _run_dual_web_servers(host, http_port, https_port, ssl_context, debug_mode)
    elif https_enabled:
        ssl_context = _resolve_ssl_context(True)
        print(f"Starting web app on https://{host}:{https_port}")
        app.run(host=host, port=https_port, debug=debug_mode, ssl_context=ssl_context)
    else:
        print(f"Starting web app on http://{host}:{http_port}")
        app.run(host=host, port=http_port, debug=debug_mode, ssl_context=None)
