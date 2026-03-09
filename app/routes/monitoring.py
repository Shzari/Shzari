from __future__ import annotations

from typing import Any

from flask import Flask


def monitoring_node_add_page() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_add_page()


def monitoring_node_delete_page() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_delete_page()


def monitoring_category_add_page() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_category_add_page()


def monitoring_category_delete_page() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_category_delete_page()


def monitoring_category_rename_page() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_category_rename_page()


def monitoring_node_test_snmp_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_test_snmp_api()


def monitoring_node_resources_pull_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_resources_pull_api()


def monitoring_node_resources_save_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_resources_save_api()


def monitoring_alert_ack_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_alert_ack_api()


def monitoring_node_dashboard_data_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_dashboard_data_api()


def monitoring_node_live_gauges_api() -> Any:
    from app.services import legacy_monitoring_handlers as monitoring_handlers

    return monitoring_handlers.monitoring_node_live_gauges_api()


def register_routes(flask_app: Flask) -> None:
    flask_app.add_url_rule(
        "/monitoring/node/add", endpoint="monitoring_node_add_page", view_func=monitoring_node_add_page, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/monitoring/node/delete", endpoint="monitoring_node_delete_page", view_func=monitoring_node_delete_page, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/monitoring/category/add", endpoint="monitoring_category_add_page", view_func=monitoring_category_add_page, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/monitoring/category/delete",
        endpoint="monitoring_category_delete_page",
        view_func=monitoring_category_delete_page,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/monitoring/category/rename",
        endpoint="monitoring_category_rename_page",
        view_func=monitoring_category_rename_page,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/monitoring/node/test-snmp", endpoint="monitoring_node_test_snmp_api", view_func=monitoring_node_test_snmp_api, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/monitoring/node/resources/pull",
        endpoint="monitoring_node_resources_pull_api",
        view_func=monitoring_node_resources_pull_api,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/monitoring/node/resources/save",
        endpoint="monitoring_node_resources_save_api",
        view_func=monitoring_node_resources_save_api,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/monitoring/alerts/ack", endpoint="monitoring_alert_ack_api", view_func=monitoring_alert_ack_api, methods=["POST"]
    )
    flask_app.add_url_rule(
        "/monitoring/node/dashboard-data",
        endpoint="monitoring_node_dashboard_data_api",
        view_func=monitoring_node_dashboard_data_api,
        methods=["POST"],
    )
    flask_app.add_url_rule(
        "/monitoring/node/live-gauges",
        endpoint="monitoring_node_live_gauges_api",
        view_func=monitoring_node_live_gauges_api,
        methods=["POST"],
    )
