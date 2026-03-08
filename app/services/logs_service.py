from __future__ import annotations

from typing import Any


def write_audit_log_safe(action: str, details: dict[str, Any], requester: str = "", approver: str = "", device_name: str = "") -> None:
    from app.services.legacy_audit_helpers import write_audit_log_safe as _impl

    _impl(action=action, details=details, requester=requester, approver=approver, device_name=device_name)


def write_action_log(action: str, details: dict[str, Any] | None = None, requester: str = "", approver: str = "", device_name: str = "") -> None:
    from app.services.legacy_audit_helpers import write_action_log as _impl

    _impl(action=action, details=details, requester=requester, approver=approver, device_name=device_name)


def write_login_audit_log(username: str, auth_source: str, success: bool, reason: str) -> None:
    from app.services.legacy_audit_helpers import write_login_audit_log as _impl

    _impl(username, auth_source, success, reason)
