from __future__ import annotations

from flask import Flask
import pytest

from app.routes import auth as auth_routes


def _build_app() -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-secret"
    auth_routes.register_routes(app)
    app.add_url_rule("/dashboard", endpoint="dashboard", view_func=lambda: ("dashboard", 200))
    app.add_url_rule("/settings/ise", endpoint="ise_settings_page", view_func=lambda: ("settings", 200))
    return app


def test_login_success_sets_session_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _build_app()
    audit_calls: list[tuple[str, str, bool, str]] = []

    monkeypatch.setattr(auth_routes.auth, "super_admin_exists", lambda: True)
    monkeypatch.setattr(auth_routes.auth, "load_ldap_settings", lambda: {})
    monkeypatch.setattr(auth_routes.auth, "load_users", lambda: [{"username": "alice", "role": "senior", "auth_source": "local"}])
    monkeypatch.setattr(auth_routes.auth, "is_provisioned_app_user", lambda username: username == "alice")
    monkeypatch.setattr(auth_routes.auth, "find_user", lambda users, username: users[0] if username == "alice" else None)
    monkeypatch.setattr(auth_routes.auth, "normalize_auth_source", lambda value: str(value))
    monkeypatch.setattr(auth_routes.auth, "normalize_role", lambda value: str(value or "senior"))
    monkeypatch.setattr(auth_routes.auth, "validate_local_user", lambda username, password: (True, "", "senior"))
    monkeypatch.setattr(auth_routes.auth, "load_user_device_creds", lambda username, auth_mode: {"username": username, "password": ""})
    monkeypatch.setattr(auth_routes.auth, "load_user_buttons", lambda username, auth_mode: [])
    monkeypatch.setattr(auth_routes.auth, "default_buttons", lambda: [{"id": "default"}])
    monkeypatch.setattr(
        auth_routes.auth,
        "write_login_audit_log",
        lambda username, auth_source, success, reason: audit_calls.append((username, auth_source, success, reason)),
    )

    with app.test_client() as client:
        response = client.post(
            "/login",
            data={"username": "alice", "password": "pw", "timeout": "8"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")
        with client.session_transaction() as sess:
            assert sess["auth_mode"] == "local"
            assert sess["creds"]["username"] == "alice"
            assert "buttons" in sess
    assert audit_calls and audit_calls[-1][2] is True


def test_change_password_local_user_path(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _build_app()
    user_row = {"username": "bob", "must_change_password": True}

    monkeypatch.setattr(auth_routes.auth, "verify_super_admin", lambda username, password: False)
    monkeypatch.setattr(auth_routes.auth, "load_users", lambda: [user_row])
    monkeypatch.setattr(auth_routes.auth, "find_user", lambda users, username: user_row)
    monkeypatch.setattr(auth_routes.auth, "set_user_password", lambda user, password: user.update({"password_set": True}))
    monkeypatch.setattr(auth_routes.auth, "save_users", lambda users: None)
    monkeypatch.setattr(auth_routes.auth, "load_user_device_creds", lambda username, auth_mode: {})
    monkeypatch.setattr(auth_routes.auth, "load_user_buttons", lambda username, auth_mode: [])
    monkeypatch.setattr(auth_routes.auth, "default_buttons", lambda: [{"id": "default"}])

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["pending_password_user"] = "bob"
            sess["pending_password_role"] = "operator"
        response = client.post(
            "/change-password",
            data={"new_password": "new-pass", "confirm_password": "new-pass", "timeout": "8"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")
        with client.session_transaction() as sess:
            assert "pending_password_user" not in sess
            assert sess["auth_mode"] == "local"
    assert user_row.get("password_set") is True


def test_logout_expired_sets_login_info(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _build_app()
    closed: list[str] = []
    monkeypatch.setattr(auth_routes.auth, "close_runtime_ssh_sessions", lambda rid: closed.append(rid))

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["runtime_session_id"] = "rid-1"
            sess["creds"] = {"username": "alice"}
        response = client.get("/logout?expired=1", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")
        with client.session_transaction() as sess:
            assert sess.get("login_info")
    assert closed == ["rid-1"]
