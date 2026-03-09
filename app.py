#!/usr/bin/env python3
from __future__ import annotations

import atexit
import errno
import os
import threading
import time
from pathlib import Path
from typing import Any

from app import create_app
from app.legacy import embedded_monitoring_poller_enabled, ensure_monitoring_poller_started, load_session_settings
from werkzeug.serving import make_server

app = create_app()
_APP_LOCK_HANDLE: Any | None = None
_APP_LOCK_PATH = Path(".app_runtime.lock")


def _acquire_single_instance_lock() -> None:
    global _APP_LOCK_HANDLE
    if _APP_LOCK_HANDLE is not None:
        return
    lock_file = _APP_LOCK_PATH.resolve()
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = open(lock_file, "a+")
    try:
        import msvcrt  # Windows file lock used by this deployment.

        lock_handle.seek(0)
        try:
            msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if getattr(exc, "errno", None) in {errno.EACCES, errno.EDEADLK, errno.EAGAIN, 13}:
                lock_handle.close()
                raise RuntimeError(
                    "Another app.py instance is already running. Stop existing process before starting a new one."
                ) from exc
            raise
        lock_handle.write(str(os.getpid()))
        lock_handle.flush()
        _APP_LOCK_HANDLE = lock_handle
    except Exception:
        lock_handle.close()
        raise


def _release_single_instance_lock() -> None:
    global _APP_LOCK_HANDLE
    if _APP_LOCK_HANDLE is None:
        return
    try:
        import msvcrt

        _APP_LOCK_HANDLE.seek(0)
        msvcrt.locking(_APP_LOCK_HANDLE.fileno(), msvcrt.LK_UNLCK, 1)
    except Exception:
        pass
    try:
        _APP_LOCK_HANDLE.close()
    except Exception:
        pass
    _APP_LOCK_HANDLE = None


atexit.register(_release_single_instance_lock)


def _is_true(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _announce(message: str) -> None:
    print(message)
    try:
        app.logger.info(message)
    except Exception:
        pass


def _load_web_runtime_settings() -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "http_enabled": True,
        "https_enabled": True,
        "http_port": 8080,
        "https_port": 8443,
    }
    try:
        data = load_session_settings()
        if not isinstance(data, dict):
            return defaults
        http_enabled = bool(data.get("http_enabled", True))
        https_enabled = bool(data.get("https_enabled", False))
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

    _announce(f"Starting web app on http://{host}:{http_port}")
    _announce(f"Starting web app on https://{host}:{https_port}")
    if debug_mode:
        _announce("Dual HTTP+HTTPS mode runs without Flask reloader.")
    try:
        while http_thread.is_alive() and https_thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _announce("Stopping web app...")


if __name__ == "__main__":
    _acquire_single_instance_lock()
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
        _announce(f"Starting web app on {scheme}://{host}:{port}")
        app.run(host=host, port=port, debug=debug_mode, ssl_context=ssl_context)
    elif http_enabled and https_enabled:
        ssl_context = _resolve_ssl_context(True)
        _run_dual_web_servers(host, http_port, https_port, ssl_context, debug_mode)
    elif https_enabled:
        ssl_context = _resolve_ssl_context(True)
        _announce(f"Starting web app on https://{host}:{https_port}")
        app.run(host=host, port=https_port, debug=debug_mode, ssl_context=ssl_context)
    else:
        _announce(f"Starting web app on http://{host}:{http_port}")
        app.run(host=host, port=http_port, debug=debug_mode, ssl_context=None)
