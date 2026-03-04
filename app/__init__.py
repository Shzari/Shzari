from __future__ import annotations

from flask import Flask

from app import legacy


def create_app() -> Flask:
    return legacy.app


app = create_app()
