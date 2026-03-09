from __future__ import annotations

from flask import Flask

from app.factory import create_app


app = create_app()
