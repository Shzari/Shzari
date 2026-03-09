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


def mark_notifications_read_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    mark_notifications_read(username)
    session["dashboard_info"] = "Notifications marked as read."
    if str(request.form.get("next", "")).strip().lower() == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard", modal="notifications"))
    return redirect(url_for("dashboard"))


def delete_notification_route() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    username = str(session.get("creds", {}).get("username", "")).strip()
    notification_id = int(request.form.get("notification_id", "0") or 0)
    if notification_id > 0:
        delete_notification(username, notification_id)
        session["dashboard_info"] = "Notification deleted."
    if str(request.form.get("next", "")).strip().lower() == "ip_addressing":
        return redirect(url_for("ip_addressing_dashboard", modal="notifications"))
    return redirect(url_for("dashboard"))


def pending_requests_cleanup() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    if not is_senior_user():
        session["dashboard_error"] = "Only Senior/SysAdmin users can delete processed requests."
        return redirect(url_for("dashboard"))

    action = request.form.get("action", "").strip()
    request_id = int(request.form.get("request_id", "0") or 0)
    with db_conn() as conn:
        if action == "delete_one" and request_id > 0:
            conn.execute("DELETE FROM pending_device_requests WHERE id = ? AND status IN ('approved','rejected')", (request_id,))
            session["dashboard_info"] = f"Processed request #{request_id} deleted."
        elif action == "delete_all_closed":
            conn.execute("DELETE FROM pending_device_requests WHERE status IN ('approved','rejected')")
            session["dashboard_info"] = "All processed requests deleted."
    return redirect(url_for("dashboard"))


def dashboard() -> Any:
    if "creds" not in session:
        return redirect(url_for("login"))
    session.pop("super_admin_verified", None)

    current_username = str(session.get("creds", {}).get("username", ""))
    auth_mode = str(session.get("auth_mode", "local"))
    role = current_user_role()
    if role == "audit":
        return redirect(url_for("audit_dashboard"))
    return redirect(url_for("ip_addressing_dashboard"))
