from __future__ import annotations

import secrets
import time
from typing import Any

from flask import g, jsonify, redirect, request, session, url_for

from app.domains.settings.session_acl_impl import _env_true, _is_client_ip_allowed_by_acl, load_session_settings
from app.domains.shared.logging_impl import _request_actor, _resolve_client_ip
from app.services.auth_service import current_user_role
from app.services.legacy_monitoring_poller import ensure_monitoring_poller_started
from app.services.legacy_sql_backend_helpers import embedded_monitoring_poller_enabled


def enforce_dashboard_session_timeout() -> Any:
    g.request_started_at = time.perf_counter()
    incoming_request_id = str(request.headers.get("X-Request-ID", "")).strip()
    g.request_id = incoming_request_id or secrets.token_hex(8)
    username, role = _request_actor()
    from flask import current_app

    current_app.logger.info(
        "request_started id=%s method=%s path=%s endpoint=%s user=%s role=%s ip=%s",
        getattr(g, "request_id", "-"),
        str(request.method or "-"),
        str(request.path or "-"),
        str(request.endpoint or "-"),
        username,
        role or "-",
        _resolve_client_ip() or "-",
    )

    if _env_true("APP_FORCE_HTTPS", "0"):
        endpoint = request.endpoint or ""
        if endpoint != "static":
            forwarded_proto = str(request.headers.get("X-Forwarded-Proto", request.scheme)).split(",")[0].strip().lower()
            if forwarded_proto != "https" and request.scheme != "https":
                secure_url = request.url.replace("http://", "https://", 1)
                return redirect(secure_url, code=301)
    if embedded_monitoring_poller_enabled():
        ensure_monitoring_poller_started()
    endpoint = request.endpoint or ""
    if endpoint != "static":
        settings = load_session_settings()
        if bool(settings.get("web_acl_enabled", False)):
            client_ip = str(request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "")
            acl_entries = settings.get("web_acl_entries", [])
            if not _is_client_ip_allowed_by_acl(client_ip, acl_entries if isinstance(acl_entries, list) else []):
                if request.path.startswith("/api/") or str(request.accept_mimetypes.best).lower() == "application/json":
                    return (
                        jsonify(
                            {
                                "ok": False,
                                "error": "Access denied by Web ACL.",
                                "client_ip": client_ip,
                            }
                        ),
                        403,
                    )
                return (
                    f"Access denied by Web ACL. Your IP {client_ip or 'unknown'} is not allowed.",
                    403,
                )
    # Super-admin verification is scoped only to settings/super-admin pages.
    # As soon as user navigates elsewhere (dashboard/app pages), drop the privileged flag.
    if session.get("super_admin_verified"):
        endpoint = request.endpoint or ""
        current_path = str(request.path or "")
        if endpoint != "static" and not (current_path.startswith("/settings/") or current_path.startswith("/super-admin/")):
            session.pop("super_admin_verified", None)
        else:
            # Super-admin settings operations are explicitly re-verified and should not be
            # interrupted by dashboard idle timeout while applying changes.
            if "creds" in session:
                session["last_activity_ts"] = int(time.time())
            return None
    if "creds" not in session:
        return None

    endpoint = request.endpoint or ""
    if endpoint in {"static", "login", "logout", "setup_super_admin", "change_password"}:
        return None
    passive_endpoints = {"ip_addressing_live_data_api"}
    wants_json_response = bool(
        request.path.startswith("/api/")
        or str(endpoint).endswith("_api")
        or request.is_json
        or "application/json" in str(request.headers.get("Accept", "")).lower()
        or str(request.content_type or "").lower().startswith("application/json")
    )

    role = current_user_role()
    if role == "audit":
        allowed_audit_endpoints = {
            "audit_dashboard",
            "audit_dashboard_logs_api",
            "mark_notifications_read_route",
            "delete_notification_route",
            "logout",
            "pending_command_decision",
        }
        if endpoint not in allowed_audit_endpoints:
            return redirect(url_for("audit_dashboard"))

    settings = load_session_settings()
    timeout_seconds = max(60, int(settings.get("idle_timeout_minutes", 15)) * 60)
    now = int(time.time())
    last_activity = int(session.get("last_activity_ts", now))

    if now - last_activity > timeout_seconds:
        session.clear()
        session["login_info"] = "Session expired due to inactivity. Please log in again."
        if endpoint in passive_endpoints or wants_json_response:
            return jsonify({"ok": False, "error": "Session expired due to inactivity.", "expired": True}), 401
        return redirect(url_for("login", expired=1))

    # Do not treat background auto-refresh APIs as user activity.
    if endpoint not in passive_endpoints:
        session["last_activity_ts"] = now
    return None
