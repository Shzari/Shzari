from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from app.services import audit_store_service, auth_service, notifications_service


def audit_dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))

    role = auth_service.current_user_role()
    if role not in {"audit", "senior", "sysadmin"}:
        session["dashboard_error"] = "You do not have access to Audit Dashboard."
        return redirect(url_for("dashboard"))

    current_username = str(session.get("creds", {}).get("username", "")).strip()
    page_size = 100
    logs, has_more = audit_store_service.load_audit_logs_page(page_size, 0)
    return render_template(
        "audit_dashboard.html",
        logs=logs,
        logs_page_size=page_size,
        logs_has_more=has_more,
        current_user=current_username,
        current_user_role=role,
        auth_mode=str(session.get("auth_mode", "local")),
        info=session.pop("dashboard_info", ""),
        error=session.pop("dashboard_error", ""),
        unread_notifications_count=len(notifications_service.load_unread_notifications(current_username)),
    )


def audit_dashboard_logs_api() -> Any:
    if "creds" not in session:
        return jsonify({"ok": False, "error": "Authentication required."}), 401
    role = auth_service.current_user_role()
    if role not in {"audit", "senior", "sysadmin"}:
        return jsonify({"ok": False, "error": "Access denied."}), 403
    try:
        offset = max(0, int(request.args.get("offset", "0") or "0"))
    except Exception:
        offset = 0
    try:
        limit = max(1, min(500, int(request.args.get("limit", "100") or "100")))
    except Exception:
        limit = 100
    logs, has_more = audit_store_service.load_audit_logs_page(limit, offset)
    return jsonify(
        {
            "ok": True,
            "logs": logs,
            "has_more": bool(has_more),
            "next_offset": offset + len(logs),
        }
    )


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/audit-dashboard", endpoint="audit_dashboard", view_func=audit_dashboard, methods=["GET"])
    flask_app.add_url_rule(
        "/audit-dashboard/logs",
        endpoint="audit_dashboard_logs_api",
        view_func=audit_dashboard_logs_api,
        methods=["GET"],
    )
