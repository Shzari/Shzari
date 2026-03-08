from __future__ import annotations

from typing import Any


def ise_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import ise_settings_page as _impl

    return _impl()


def sql_server_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import sql_server_settings_page as _impl

    return _impl()


def sql_server_test_page() -> Any:
    from app.services.legacy_settings_handlers_impl import sql_server_test_page as _impl

    return _impl()


def ldap_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import ldap_settings_page as _impl

    return _impl()


def ntp_test_page() -> Any:
    from app.services.legacy_settings_handlers_impl import ntp_test_page as _impl

    return _impl()


def ntp_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import ntp_settings_page as _impl

    return _impl()


def session_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import session_settings_page as _impl

    return _impl()


def external_logging_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import external_logging_settings_page as _impl

    return _impl()


def monitoring_settings_page() -> Any:
    from app.services.legacy_settings_handlers_impl import monitoring_settings_page as _impl

    return _impl()


def manage_users() -> Any:
    from app.services.legacy_settings_handlers_impl import manage_users as _impl

    return _impl()
