from __future__ import annotations


def load_ip_branches() -> list[str]:
    from app.services.legacy_core_helpers import load_ip_branches as _impl

    return list(_impl())


def save_ip_branches(branches: list[str]) -> None:
    from app.services.legacy_core_helpers import save_ip_branches as _impl

    _impl(branches)
