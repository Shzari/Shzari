from __future__ import annotations

from typing import Any

from flask import Flask


def manage_devices() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.manage_devices()


def manage_categories() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.manage_categories()


def buttons_menu() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.buttons_menu()


def ping_selected_devices() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.ping_selected_devices()


def update_device_credentials() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.update_device_credentials()


def test_device_connectivity() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.test_device_connectivity()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/devices", endpoint="manage_devices", view_func=manage_devices, methods=["POST"])
    flask_app.add_url_rule("/categories", endpoint="manage_categories", view_func=manage_categories, methods=["POST"])
    flask_app.add_url_rule("/buttons", endpoint="buttons_menu", view_func=buttons_menu, methods=["POST"])
    flask_app.add_url_rule(
        "/device-credentials", endpoint="update_device_credentials", view_func=update_device_credentials, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/devices/test-connectivity",
        endpoint="test_device_connectivity",
        view_func=test_device_connectivity,
        methods=["POST"],
    )
    flask_app.add_url_rule("/ping-selected", endpoint="ping_selected_devices", view_func=ping_selected_devices, methods=["POST"])
