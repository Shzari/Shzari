from __future__ import annotations

from typing import Any


def _monitoring_device_lookup(device_name: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    from app.services.legacy_monitoring_collectors_impl import _monitoring_device_lookup as _impl

    return _impl(device_name)


def _monitoring_effective_category(device_name: str) -> str:
    from app.services.legacy_monitoring_collectors_impl import _monitoring_effective_category as _impl

    return _impl(device_name)


def _monitoring_pull_ssh_creds(profile: dict[str, Any], account_username: str, auth_mode: str) -> dict[str, Any]:
    from app.services.legacy_monitoring_collectors_impl import _monitoring_pull_ssh_creds as _impl

    return _impl(profile, account_username, auth_mode)


def parse_monitoring_metrics(metrics_text: str) -> set[str]:
    from app.services.legacy_monitoring_collectors_impl import parse_monitoring_metrics as _impl

    return _impl(metrics_text)


def _cap_percent(value: Any) -> float | None:
    from app.services.legacy_monitoring_collectors_impl import _cap_percent as _impl

    return _impl(value)


def ping_host_status(host: str, timeout_seconds: int = 2) -> tuple[str, float | None]:
    from app.services.legacy_monitoring_collectors_impl import ping_host_status as _impl

    return _impl(host, timeout_seconds)


def winrm_collect_metrics(host: str, settings: dict[str, Any], timeout_seconds: int = 8) -> tuple[dict[str, Any], list[str]]:
    from app.services.legacy_monitoring_collectors_impl import winrm_collect_metrics as _impl

    return _impl(host, settings, timeout_seconds)


def winrm_collect_live_gauges(host: str, settings: dict[str, Any], timeout_seconds: int = 6) -> tuple[dict[str, Any], list[str]]:
    from app.services.legacy_monitoring_collectors_impl import winrm_collect_live_gauges as _impl

    return _impl(host, settings, timeout_seconds)


def _snmp_auth_data_from_settings(settings: dict[str, Any]) -> tuple[Any | None, str]:
    from app.services.legacy_monitoring_collectors_impl import _snmp_auth_data_from_settings as _impl

    return _impl(settings)


def snmp_get_value(host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3) -> tuple[Any | None, str]:
    from app.services.legacy_monitoring_collectors_impl import snmp_get_value as _impl

    return _impl(host, settings, oid, timeout_seconds)


def snmp_walk_values(
    host: str,
    settings: dict[str, Any],
    oid: str,
    timeout_seconds: int = 3,
    max_rows: int = 2048,
) -> tuple[list[Any], str]:
    from app.services.legacy_monitoring_collectors_impl import snmp_walk_values as _impl

    return _impl(host, settings, oid, timeout_seconds, max_rows)


def snmp_walk_indexed_values(
    host: str,
    settings: dict[str, Any],
    oid: str,
    timeout_seconds: int = 3,
    max_rows: int = 2048,
) -> tuple[dict[str, Any], str]:
    from app.services.legacy_monitoring_collectors_impl import snmp_walk_indexed_values as _impl

    return _impl(host, settings, oid, timeout_seconds, max_rows)


def snmp_collect_interface_utilization(
    host: str, settings: dict[str, Any], timeout_seconds: int = 3
) -> tuple[list[dict[str, Any]], list[str]]:
    from app.services.legacy_monitoring_collectors_impl import snmp_collect_interface_utilization as _impl

    return _impl(host, settings, timeout_seconds)


def snmp_collect_memory_percent(host: str, settings: dict[str, Any]) -> tuple[float | None, list[str]]:
    from app.services.legacy_monitoring_collectors_impl import snmp_collect_memory_percent as _impl

    return _impl(host, settings)


def poll_device_monitoring_sample(
    device: dict[str, Any], settings: dict[str, Any], pre_ping: tuple[str, float | None] | None = None
) -> dict[str, Any]:
    from app.services.legacy_monitoring_collectors_impl import poll_device_monitoring_sample as _impl

    return _impl(device, settings, pre_ping)


def save_monitoring_sample(sample: dict[str, Any]) -> None:
    from app.services.legacy_monitoring_collectors_impl import save_monitoring_sample as _impl

    return _impl(sample)
