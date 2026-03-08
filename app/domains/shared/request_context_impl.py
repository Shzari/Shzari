from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)


def shutdown_audit_log_executor_on_exit() -> None:
    try:
        AUDIT_LOG_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except TypeError:
        AUDIT_LOG_EXECUTOR.shutdown(wait=False)
    except Exception:
        pass


def add_no_cache_headers(response: Any) -> Any:
    endpoint = request.endpoint or ""
    if endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    duration_ms = -1.0
    try:
        started = float(getattr(g, "request_started_at", 0.0) or 0.0)
        if started > 0:
            duration_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
    except Exception:
        duration_ms = -1.0
    username, role = _request_actor()
    app.logger.info(
        "request_finished id=%s method=%s path=%s endpoint=%s status=%s duration_ms=%.2f user=%s role=%s ip=%s",
        str(getattr(g, "request_id", "-")),
        str(request.method or "-"),
        str(request.path or "-"),
        str(endpoint or "-"),
        int(getattr(response, "status_code", 0) or 0),
        duration_ms,
        username,
        role or "-",
        _resolve_client_ip() or "-",
    )
    request_id = str(getattr(g, "request_id", "")).strip()
    if request_id:
        response.headers["X-Request-ID"] = request_id
    return response


def inject_common_context() -> dict[str, Any]:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    can_access_devices = bool(current_username) and user_has_panel_access(current_username, auth_mode, "devices")
    return {
        "current_user": current_username,
        "auth_mode": auth_mode,
        "is_super_admin_session": is_current_session_super_admin(),
        "can_access_devices_panel": can_access_devices,
    }
