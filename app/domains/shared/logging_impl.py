from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Any

from flask import Flask, g, got_request_exception, has_request_context, request, session

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DEFAULT_LOG_DIR = os.path.join(PROJECT_ROOT, "logs")


def _safe_int(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = fallback
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


def _resolve_client_ip() -> str:
    if not has_request_context():
        return ""
    return str(request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "")


def _request_actor() -> tuple[str, str]:
    if not has_request_context():
        return "anonymous", ""
    username = str(session.get("creds", {}).get("username", "")).strip() or "anonymous"
    role = str(session.get("creds", {}).get("role", "")).strip().lower()
    return username, role


def _env_true(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def _configure_app_logging(flask_app: Flask) -> None:
    if getattr(flask_app, "_ndmc_logging_configured", False):
        return

    log_dir = str(os.environ.get("APP_LOG_DIR", DEFAULT_LOG_DIR)).strip() or DEFAULT_LOG_DIR
    os.makedirs(log_dir, exist_ok=True)

    level_name = str(os.environ.get("APP_LOG_LEVEL", "INFO")).strip().upper() or "INFO"
    level = getattr(logging, level_name, logging.INFO)
    max_bytes = _safe_int(os.environ.get("APP_LOG_MAX_BYTES", "10485760"), 10485760, 1024, 52428800)
    backup_count = _safe_int(os.environ.get("APP_LOG_BACKUP_COUNT", "10"), 10, 1, 50)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    app_handler = RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    app_handler.setLevel(level)
    app_handler.setFormatter(formatter)

    error_handler = RotatingFileHandler(
        os.path.join(log_dir, "error.log"),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)

    flask_app.logger.setLevel(level)
    flask_app.logger.handlers.clear()
    flask_app.logger.addHandler(app_handler)
    flask_app.logger.addHandler(error_handler)

    if _env_true("APP_LOG_TO_STDOUT", "1"):
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        flask_app.logger.addHandler(stream_handler)

    flask_app.logger.propagate = False
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    flask_app._ndmc_logging_configured = True  # type: ignore[attr-defined]

    def _on_request_exception(_sender: Any, exception: Exception, **_extra: Any) -> None:
        request_id = getattr(g, "request_id", "-")
        endpoint = str(request.endpoint or "-")
        method = str(request.method or "-")
        path = str(request.path or "-")
        username, role = _request_actor()
        flask_app.logger.exception(
            "request_exception id=%s method=%s path=%s endpoint=%s user=%s role=%s ip=%s",
            request_id,
            method,
            path,
            endpoint,
            username,
            role or "-",
            _resolve_client_ip() or "-",
        )

    got_request_exception.connect(_on_request_exception, flask_app)
    flask_app.logger.info("application_logging_initialized log_dir=%s level=%s", log_dir, logging.getLevelName(level))
