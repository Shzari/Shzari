from __future__ import annotations

from typing import Any


def load_monitoring_settings() -> dict[str, Any]:
    from app.services.legacy_monitoring_config_helpers import load_monitoring_settings as _impl

    return dict(_impl())


def save_monitoring_settings(settings: dict[str, Any]) -> None:
    from app.services.legacy_monitoring_config_helpers import save_monitoring_settings as _impl

    _impl(settings)


def poll_monitoring_device_now(
    device: dict[str, Any],
    settings: dict[str, Any],
    pre_ping: tuple[str, float | None] | None = None,
) -> dict[str, Any]:
    from app.services.legacy_monitoring_collectors import poll_device_monitoring_sample as _impl

    return dict(_impl(device, settings, pre_ping=pre_ping))
