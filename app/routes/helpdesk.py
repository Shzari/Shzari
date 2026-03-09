from __future__ import annotations

from typing import Any

from flask import Flask


def helpdesk_interfaces_api() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.helpdesk_interfaces_api()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/helpdesk/interfaces", endpoint="helpdesk_interfaces_api", view_func=helpdesk_interfaces_api, methods=["POST"])
