from __future__ import annotations

from typing import Any

from flask import Flask


def dashboard() -> Any:
    from app.services import legacy_dashboard_handlers as dashboard_handlers

    return dashboard_handlers.dashboard()


def mark_notifications_read_route() -> Any:
    from app.services import legacy_dashboard_handlers as dashboard_handlers

    return dashboard_handlers.mark_notifications_read_route()


def delete_notification_route() -> Any:
    from app.services import legacy_dashboard_handlers as dashboard_handlers

    return dashboard_handlers.delete_notification_route()


def pending_requests_cleanup() -> Any:
    from app.services import legacy_dashboard_handlers as dashboard_handlers

    return dashboard_handlers.pending_requests_cleanup()


def pending_requests_action() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.pending_requests_action()


def pending_command_decision() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.pending_command_decision()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/dashboard", endpoint="dashboard", view_func=dashboard, methods=["GET"])
    flask_app.add_url_rule(
        "/notifications/read",
        endpoint="mark_notifications_read_route",
        view_func=mark_notifications_read_route,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/notifications/delete",
        endpoint="delete_notification_route",
        view_func=delete_notification_route,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/pending-requests/cleanup",
        endpoint="pending_requests_cleanup",
        view_func=pending_requests_cleanup,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/pending-requests",
        endpoint="pending_requests_action",
        view_func=pending_requests_action,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/pending-command/decision",
        endpoint="pending_command_decision",
        view_func=pending_command_decision,
        methods=["POST"],
    )
