from __future__ import annotations

from typing import Any


def load_devices() -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import load_devices as _impl

    return list(_impl())


def filter_devices_for_user(devices: list[dict[str, Any]], username: str, auth_mode: str) -> list[dict[str, Any]]:
    from app.services.legacy_core_helpers import filter_devices_for_user as _impl

    return list(_impl(devices, username, auth_mode))


def execute_for_device(device: dict[str, Any], creds: dict[str, Any], command: str, command_mode: str = "show") -> Any:
    from app.services.legacy_command_handlers import execute_for_device as _impl

    return _impl(device, creds, command, command_mode)
