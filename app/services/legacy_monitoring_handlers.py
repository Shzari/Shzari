from __future__ import annotations

from typing import Any


def monitoring_node_add_page() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_add_page as _impl

    return _impl()


def monitoring_node_delete_page() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_delete_page as _impl

    return _impl()


def monitoring_category_add_page() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_category_add_page as _impl

    return _impl()


def monitoring_category_delete_page() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_category_delete_page as _impl

    return _impl()


def monitoring_category_rename_page() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_category_rename_page as _impl

    return _impl()


def monitoring_node_test_snmp_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_test_snmp_api as _impl

    return _impl()


def monitoring_node_resources_pull_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_resources_pull_api as _impl

    return _impl()


def monitoring_node_resources_save_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_resources_save_api as _impl

    return _impl()


def monitoring_alert_ack_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_alert_ack_api as _impl

    return _impl()


def monitoring_node_dashboard_data_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_dashboard_data_api as _impl

    return _impl()


def monitoring_node_live_gauges_api() -> Any:
    from app.services.legacy_monitoring_handlers_impl import monitoring_node_live_gauges_api as _impl

    return _impl()
