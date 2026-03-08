from __future__ import annotations

from typing import Any

from app.routes import api, audit, auth, dashboard, devices, helpdesk, ipam, monitoring, settings


def register_all_routes(flask_app: Any) -> None:
    auth.register_routes(flask_app)
    audit.register_routes(flask_app)
    dashboard.register_routes(flask_app)
    monitoring.register_routes(flask_app)
    devices.register_routes(flask_app)
    helpdesk.register_routes(flask_app)
    ipam.register_routes(flask_app)
    api.register_routes(flask_app)
    settings.register_routes(flask_app)


__all__ = [
    "register_all_routes",
    "audit",
    "auth",
    "dashboard",
    "devices",
    "helpdesk",
    "monitoring",
    "settings",
    "ipam",
    "api",
]
