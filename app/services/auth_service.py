from __future__ import annotations

from typing import Any


def normalize_role(value: str) -> str:
    from app.services.legacy_core_helpers import normalize_role as _impl

    return str(_impl(value))


def is_privileged_role(role: str) -> bool:
    return normalize_role(role) in {"senior", "sysadmin"}


def current_user_role() -> str:
    from app.services.legacy_core_helpers import current_user_role as _impl

    return str(_impl())


def get_buttons() -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import get_buttons as _impl

    return list(_impl())


def buttons_for_role(role: str) -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import buttons_for_role as _impl

    return list(_impl(role))


def allowed_preconfigured_commands(role: str) -> set[str]:
    source = get_buttons() if not role else buttons_for_role(role)
    return {str(item.get("command", "")).strip() for item in source if str(item.get("command", "")).strip()}


def super_admin_exists() -> bool:
    from app.services.legacy_core_helpers import super_admin_exists as _impl

    return bool(_impl())


def save_super_admin(username: str, password: str) -> None:
    from app.services.legacy_core_helpers import save_super_admin as _impl

    _impl(username, password)


def verify_super_admin(username: str, password: str) -> bool:
    from app.services.legacy_core_helpers import verify_super_admin as _impl

    return bool(_impl(username, password))


def load_ldap_settings() -> dict[str, Any]:
    from app.services.legacy_core_helpers import load_ldap_settings as _impl

    return dict(_impl())


def load_users() -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import load_users as _impl

    return list(_impl())


def save_users(users: list[dict[str, Any]]) -> None:
    from app.services.legacy_core_helpers import save_users as _impl

    _impl(users)


def find_user(users: list[dict[str, Any]], username: str) -> dict[str, Any] | None:
    from app.services.legacy_core_helpers import find_user as _impl

    return _impl(users, username)


def normalize_auth_source(value: str) -> str:
    from app.services.legacy_core_helpers import normalize_auth_source as _impl

    return str(_impl(value))


def is_provisioned_app_user(username: str) -> bool:
    from app.services.legacy_core_helpers import is_provisioned_app_user as _impl

    return bool(_impl(username))


def authenticate_with_ldap(username: str, password: str, ldap_settings: dict[str, Any]) -> tuple[bool, str]:
    from app.services.legacy_auth_helpers import authenticate_with_ldap as _impl

    return _impl(username, password, ldap_settings)


def validate_local_user(username: str, password: str) -> tuple[bool, str, str]:
    from app.services.legacy_pending_helpers import validate_local_user as _impl

    return _impl(username, password)


def write_login_audit_log(username: str, auth_source: str, success: bool, reason: str) -> None:
    from app.services.legacy_audit_helpers import write_login_audit_log as _impl

    _impl(username, auth_source, success, reason)


def load_user_device_creds(username: str, auth_mode: str) -> dict[str, str]:
    from app.services.legacy_core_helpers import load_user_device_creds as _impl

    return dict(_impl(username, auth_mode))


def load_user_buttons(username: str, auth_mode: str) -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import load_user_buttons as _impl

    return list(_impl(username, auth_mode))


def default_buttons() -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import default_buttons as _impl

    return list(_impl())


def set_user_password(user: dict[str, Any], password: str) -> None:
    from app.services.legacy_core_helpers import set_user_password as _impl

    _impl(user, password)


def close_runtime_ssh_sessions(runtime_session_id: str) -> None:
    from app.services.legacy_core_helpers import close_runtime_ssh_sessions as _impl

    _impl(runtime_session_id)
