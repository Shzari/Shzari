from __future__ import annotations

from typing import Any

from flask import Flask


def ise_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.ise_settings_page()


def sql_server_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.sql_server_settings_page()


def sql_server_test_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.sql_server_test_page()


def ldap_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.ldap_settings_page()


def ntp_test_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.ntp_test_page()


def ntp_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.ntp_settings_page()


def session_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.session_settings_page()


def external_logging_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.external_logging_settings_page()


def monitoring_settings_page() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.monitoring_settings_page()


def manage_users() -> Any:
    from app.services import legacy_settings_handlers as settings_handlers

    return settings_handlers.manage_users()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/settings/ise", endpoint="ise_settings_page", view_func=ise_settings_page, methods=["GET", "POST"])
    flask_app.add_url_rule(
        "/settings/sql-server", endpoint="sql_server_settings_page", view_func=sql_server_settings_page, methods=["POST"]
    )
    flask_app.add_url_rule("/settings/sql-server/test", endpoint="sql_server_test_page", view_func=sql_server_test_page, methods=["POST"])
    flask_app.add_url_rule("/settings/ldap", endpoint="ldap_settings_page", view_func=ldap_settings_page, methods=["POST"])
    flask_app.add_url_rule("/settings/ntp/test", endpoint="ntp_test_page", view_func=ntp_test_page, methods=["POST"])
    flask_app.add_url_rule("/settings/ntp", endpoint="ntp_settings_page", view_func=ntp_settings_page, methods=["POST"])
    flask_app.add_url_rule("/settings/session", endpoint="session_settings_page", view_func=session_settings_page, methods=["POST"])
    flask_app.add_url_rule(
        "/settings/external-logging", endpoint="external_logging_settings_page", view_func=external_logging_settings_page, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/settings/monitoring", endpoint="monitoring_settings_page", view_func=monitoring_settings_page, methods=["POST"]
    )
    flask_app.add_url_rule("/settings/users", endpoint="manage_users", view_func=manage_users, methods=["POST"])
