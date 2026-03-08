from __future__ import annotations

from typing import Any


def load_unread_notifications(username: str) -> list[dict[str, Any]]:
    from app.services.legacy_pending_helpers import load_unread_notifications as _impl

    return list(_impl(username))


def mark_notifications_read(username: str) -> None:
    from app.services.legacy_pending_helpers import mark_notifications_read as _impl

    _impl(username)


def delete_notification(username: str, notification_id: int) -> None:
    from app.services.legacy_pending_helpers import delete_notification as _impl

    _impl(username, notification_id)
