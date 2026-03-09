from __future__ import annotations

from typing import Any


def open_runtime_device_session(runtime_id: str, device: dict[str, Any], creds: dict[str, Any]) -> tuple[bool, str]:
    from app.services.legacy_command_handlers_impl import open_runtime_device_session as _impl

    return _impl(runtime_id, device, creds)


def run_config_commands(
    command_text: str,
    selected_devices: list[dict[str, Any]],
    creds: dict[str, Any],
    command_mode: str,
    requester_username: str,
    requester_role: str,
) -> tuple[str, str]:
    from app.services.legacy_command_handlers_impl import run_config_commands as _impl

    return _impl(command_text, selected_devices, creds, command_mode, requester_username, requester_role)


def run_errdisable_recovery_sequence(selected_devices: list[dict[str, Any]], creds: dict[str, Any], requester_username: str) -> tuple[str, str]:
    from app.services.legacy_command_handlers_impl import run_errdisable_recovery_sequence as _impl

    return _impl(selected_devices, creds, requester_username)


def run_ssh_command(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
    timeout: int = 8,
    command_mode: str = "show",
    enable_password: str = "",
) -> tuple[str, str]:
    from app.services.legacy_command_handlers_impl import run_ssh_command as _impl

    return _impl(host, port, username, password, command, timeout, command_mode, enable_password)


def ping_selected_devices() -> Any:
    from app.services.legacy_command_handlers_impl import ping_selected_devices as _impl

    return _impl()


def _parse_show_interfaces_status(output: str) -> dict[str, dict[str, str]]:
    from app.services.legacy_command_handlers_impl import _parse_show_interfaces_status as _impl

    return _impl(output)


def _collect_helpdesk_targets(payload: dict[str, Any]) -> tuple[dict[str, list[str]], dict[str, dict[str, str]], dict[str, dict[str, int]]]:
    from app.services.legacy_command_handlers_impl import _collect_helpdesk_targets as _impl

    return _impl(payload)


def _load_helpdesk_interfaces_for_device(device: dict[str, Any], creds: dict[str, Any]) -> dict[str, Any]:
    from app.services.legacy_command_handlers_impl import _load_helpdesk_interfaces_for_device as _impl

    return _impl(device, creds)


def helpdesk_interfaces_api() -> Any:
    from app.services.legacy_command_handlers_impl import helpdesk_interfaces_api as _impl

    return _impl()


def run_commands() -> Any:
    from app.services.legacy_command_handlers_impl import run_commands as _impl

    return _impl()


def run_commands_api() -> Any:
    from app.services.legacy_command_handlers_impl import run_commands_api as _impl

    return _impl()


def open_ssh_sessions_api() -> Any:
    from app.services.legacy_command_handlers_impl import open_ssh_sessions_api as _impl

    return _impl()


def run_session_command_api() -> Any:
    from app.services.legacy_command_handlers_impl import run_session_command_api as _impl

    return _impl()
