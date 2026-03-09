from __future__ import annotations


def is_privileged_role(role: str) -> bool:
    from app.services.legacy_core_helpers import normalize_role

    return normalize_role(role) in {"senior", "sysadmin"}


def can_manage_monitoring_nodes(role: str) -> bool:
    from app.services.legacy_core_helpers import normalize_role

    return normalize_role(role) in {"senior", "sysadmin"}


def sysadmin_monitoring_servers_only(role: str) -> bool:
    from app.services.legacy_core_helpers import normalize_role

    return normalize_role(role) == "sysadmin"


def category_allowed_for_monitoring_add(role: str, category: str) -> bool:
    from app.services.legacy_core_helpers import normalize_role

    normalized = normalize_role(role)
    if normalized == "senior":
        return True
    if normalized == "sysadmin":
        key = str(category or "").strip().lower()
        return key in {"server", "servers"}
    return False


def monitoring_user_allowed_for_category(username: str, auth_mode: str, category: str) -> bool:
    from app.services.legacy_core_helpers import (
        DEFAULT_CATEGORY,
        find_user,
        load_users,
        normalize_role,
        user_allowed_categories_by_panel,
    )

    user = find_user(load_users(), username)
    role = normalize_role(str((user or {}).get("role", "junior")))
    if role in {"senior", "sysadmin"}:
        return True
    allowed = user_allowed_categories_by_panel(username, auth_mode, "monitoring")
    if allowed is None:
        return True
    if not isinstance(allowed, list) or not allowed:
        return True
    category_name = str(category or "").strip() or DEFAULT_CATEGORY
    return category_name in set(allowed)


def allowed_preconfigured_commands(role: str | None = None) -> set[str]:
    from app.services.legacy_core_helpers import buttons_for_role, get_buttons

    source = get_buttons() if role is None else buttons_for_role(role)
    return {str(item.get("command", "")).strip() for item in source if str(item.get("command", "")).strip()}


def is_restricted_command_user(role: str) -> bool:
    return str(role or "").strip().lower() in {"junior", "helpdesk", "manager"}


def is_helpdesk_user(role: str) -> bool:
    return str(role or "").strip().lower() == "helpdesk"


def is_helpdesk_action_user(role: str) -> bool:
    return str(role or "").strip().lower() in {"helpdesk", "junior", "senior"}
