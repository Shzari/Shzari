from __future__ import annotations

import time
from typing import Any

from flask import Flask, redirect, render_template, request, session, url_for

from app.domains.auth.service import auth_service as auth


def root() -> Any:
    if not auth.super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if "auth_mode" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


def setup_super_admin() -> Any:
    if auth.super_admin_exists():
        return redirect(url_for("login"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            error = "Username and password are required."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            auth.save_super_admin(username, password)
            return redirect(url_for("login"))

    return render_template("super_admin_setup.html", error=error)


def verify_super_admin_route() -> Any:
    if not auth.super_admin_exists():
        return redirect(url_for("setup_super_admin"))
    if request.method == "GET" and request.args.get("exit") == "1":
        session.pop("super_admin_verified", None)
        return redirect(url_for("dashboard"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if auth.verify_super_admin(username, password):
            session["super_admin_verified"] = True
            return redirect(url_for("ise_settings_page"))
        error = "Invalid super admin credentials."

    return render_template("super_admin_verify.html", error=error)


def super_admin_exit() -> Any:
    session.pop("super_admin_verified", None)
    return redirect(url_for("dashboard"))


def login() -> Any:
    if not auth.super_admin_exists():
        return redirect(url_for("setup_super_admin"))

    error = session.pop("login_error", "")
    info = session.pop("login_info", "")
    if request.args.get("expired") == "1":
        info = "Session expired due to inactivity. Please log in again."
    ldap_settings = auth.load_ldap_settings()
    users = auth.load_users()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        timeout = int(request.form.get("timeout", "8") or 8)
        auth_source = "unknown"
        failure_reason = ""
        user_role = ""

        if not username:
            error = "Username is required."
            failure_reason = "username_missing"
        elif not auth.is_provisioned_app_user(username):
            error = "User is not provisioned in app settings."
            auth_source = "provisioning"
            failure_reason = "user_not_provisioned"
        else:
            user = auth.find_user(users, username)
            auth_source = auth.normalize_auth_source(user.get("auth_source", "ldap") if user else "ldap")
            user_role = auth.normalize_role(str((user or {}).get("role", "")))
            if auth_source == "ldap":
                if not password:
                    error = "Password is required for LDAP users."
                    failure_reason = "password_missing"
                else:
                    ok, message = auth.authenticate_with_ldap(username, password, ldap_settings)
                    if not ok:
                        error = message
                        failure_reason = "invalid_credentials" if message == "Incorrect username or password." else "ldap_auth_failed"
            else:
                ok, local_message, role = auth.validate_local_user(username, password)
                if not ok and local_message == "PASSWORD_SETUP_REQUIRED":
                    session["pending_password_user"] = username
                    session["pending_password_role"] = role or "operator"
                    auth.write_login_audit_log(username, auth_source, False, "password_setup_required")
                    return redirect(url_for("change_password"))
                if not ok:
                    error = local_message
                    failure_reason = (
                        "invalid_credentials" if local_message == "Invalid local username or password." else "local_auth_failed"
                    )

        if not error:
            session["auth_mode"] = "local"
            session["auth_backend"] = auth_source
            session["creds"] = {"username": username, "password": password, "timeout": timeout}
            session["device_creds"] = auth.load_user_device_creds(username, "local")
            session["buttons"] = auth.load_user_buttons(username, "local") or auth.default_buttons()
            session.setdefault("run_history", [])
            session["last_activity_ts"] = int(time.time())
            auth.write_login_audit_log(username, auth_source, True, f"login_success role={user_role or 'unknown'}")
            return redirect(url_for("dashboard"))
        auth.write_login_audit_log(username, auth_source, False, failure_reason or error or "login_failed")

    return render_template("login.html", error=error, info=info)


def change_password() -> Any:
    username = session.get("pending_password_user", "")
    if not username:
        return redirect(url_for("login"))

    error = ""
    info = ""
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        timeout = int(request.form.get("timeout", "8") or 8)

        if not new_password:
            error = "New password is required."
        elif new_password != confirm_password:
            error = "Passwords do not match."
        else:
            if auth.verify_super_admin(username, new_password):
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = auth.load_user_device_creds(username, "local")
                session["buttons"] = auth.load_user_buttons(username, "local") or auth.default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

            users = auth.load_users()
            user = auth.find_user(users, username)
            if user is None:
                error = "User no longer exists."
            else:
                auth.set_user_password(user, new_password)
                user["must_change_password"] = False
                auth.save_users(users)
                session.pop("pending_password_user", None)
                session.pop("pending_password_role", None)
                session["auth_mode"] = "local"
                session["creds"] = {"username": username, "password": new_password, "timeout": timeout}
                session["device_creds"] = auth.load_user_device_creds(username, "local")
                session["buttons"] = auth.load_user_buttons(username, "local") or auth.default_buttons()
                session.setdefault("run_history", [])
                session["last_activity_ts"] = int(time.time())
                return redirect(url_for("dashboard"))

    return render_template("change_password.html", username=username, error=error, info=info)


def logout() -> Any:
    expired = request.args.get("expired") == "1"
    rid = str(session.get("runtime_session_id", ""))
    auth.close_runtime_ssh_sessions(rid)
    session.clear()
    if expired:
        session["login_info"] = "Session expired due to inactivity. Please log in again."
    return redirect(url_for("login"))


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/", endpoint="root", view_func=root, methods=["GET"])
    flask_app.add_url_rule("/login", endpoint="login", view_func=login, methods=["GET", "POST"])
    flask_app.add_url_rule("/logout", endpoint="logout", view_func=logout, methods=["GET"])
    flask_app.add_url_rule("/change-password", endpoint="change_password", view_func=change_password, methods=["GET", "POST"])
    flask_app.add_url_rule("/super-admin/setup", endpoint="setup_super_admin", view_func=setup_super_admin, methods=["GET", "POST"])
    flask_app.add_url_rule(
        "/super-admin/verify", endpoint="verify_super_admin_route", view_func=verify_super_admin_route, methods=["GET", "POST"]
    )
    flask_app.add_url_rule("/super-admin/exit", endpoint="super_admin_exit", view_func=super_admin_exit, methods=["GET"])
