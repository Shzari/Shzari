from __future__ import annotations

from typing import Any

from flask import Flask


def ip_addressing_dashboard() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.ip_addressing_dashboard()


def ip_addressing_live_data_api() -> Any:
    from app.services import legacy_ipam_handlers as ipam_handlers

    return ipam_handlers.ip_addressing_live_data_api()


def manage_ip_branches() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.manage_ip_branches()


def request_ip_branch_add() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.request_ip_branch_add()


def request_ip_branch_delete() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.request_ip_branch_delete()


def ip_branch_state_api() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.ip_branch_state_api()


def network_isp_branches_state_api() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.network_isp_branches_state_api()


def network_isp_atms_state_api() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.network_isp_atms_state_api()


def network_isp_internet_state_api() -> Any:
    from app.services import legacy_ip_branch_handlers as ip_branch_handlers

    return ip_branch_handlers.network_isp_internet_state_api()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule("/ip-addressing", endpoint="ip_addressing_dashboard", view_func=ip_addressing_dashboard, methods=["GET"])
    flask_app.add_url_rule(
        "/ip-addressing/live-data", endpoint="ip_addressing_live_data_api", view_func=ip_addressing_live_data_api, methods=["GET"]
    )
    flask_app.add_url_rule("/ip-branches", endpoint="manage_ip_branches", view_func=manage_ip_branches, methods=["POST"])
    flask_app.add_url_rule("/ip-branches/request-add", endpoint="request_ip_branch_add", view_func=request_ip_branch_add, methods=["POST"])
    flask_app.add_url_rule(
        "/ip-branches/request-delete", endpoint="request_ip_branch_delete", view_func=request_ip_branch_delete, methods=["POST"]
    )
    flask_app.add_url_rule("/ip-branches/state", endpoint="ip_branch_state_api", view_func=ip_branch_state_api, methods=["GET", "POST"])
    flask_app.add_url_rule(
        "/network-addresses/isp-branches/state",
        endpoint="network_isp_branches_state_api",
        view_func=network_isp_branches_state_api,
        methods=["GET", "POST"],
    )
    flask_app.add_url_rule(
        "/network-addresses/isp-atms/state",
        endpoint="network_isp_atms_state_api",
        view_func=network_isp_atms_state_api,
        methods=["GET", "POST"],
    )
    flask_app.add_url_rule(
        "/network-addresses/isp-internet/state",
        endpoint="network_isp_internet_state_api",
        view_func=network_isp_internet_state_api,
        methods=["GET", "POST"],
    )
