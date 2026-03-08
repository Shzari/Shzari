from __future__ import annotations

from typing import Any

from flask import Flask


def run_commands() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.run_commands()


def run_commands_api() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.run_commands_api()


def open_ssh_sessions_api() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.open_ssh_sessions_api()


def run_session_command_api() -> Any:
    from app.services import legacy_command_handlers as command_handlers

    return command_handlers.run_session_command_api()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/run", endpoint="run_commands", view_func=run_commands, methods=["POST"])
    flask_app.add_url_rule("/run-api", endpoint="run_commands_api", view_func=run_commands_api, methods=["POST"])
    flask_app.add_url_rule("/ssh-session-open", endpoint="open_ssh_sessions_api", view_func=open_ssh_sessions_api, methods=["POST"])
    flask_app.add_url_rule("/run-session-api", endpoint="run_session_command_api", view_func=run_session_command_api, methods=["POST"])
