from __future__ import annotations

from typing import Any


def pending_requests_action() -> Any:
    from app.services.legacy_ipam_handlers_impl import pending_requests_action as _impl

    return _impl()


def pending_command_decision() -> Any:
    from app.services.legacy_ipam_handlers_impl import pending_command_decision as _impl

    return _impl()


def ip_addressing_dashboard() -> Any:
    from app.services.legacy_ipam_handlers_impl import ip_addressing_dashboard as _impl

    return _impl()


def ip_addressing_live_data_api() -> Any:
    from app.services.legacy_ipam_handlers_impl import ip_addressing_live_data_api as _impl

    return _impl()


def manage_devices() -> Any:
    from app.services.legacy_ipam_handlers_impl import manage_devices as _impl

    return _impl()


def manage_categories() -> Any:
    from app.services.legacy_ipam_handlers_impl import manage_categories as _impl

    return _impl()


def buttons_menu() -> Any:
    from app.services.legacy_ipam_handlers_impl import buttons_menu as _impl

    return _impl()
