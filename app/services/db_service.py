from __future__ import annotations

from core_models import DBError, DBOperationalError, DBRow


def db_conn():
    from app.compat import legacy_runtime as legacy

    return legacy.db_conn()


__all__ = ["DBError", "DBOperationalError", "DBRow", "db_conn"]
