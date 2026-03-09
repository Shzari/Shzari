from __future__ import annotations

from flask import Flask


def create_app() -> Flask:
    # Transitional app factory while compatibility layer is retained.
    from app.compat import legacy_runtime as legacy

    return legacy.app
