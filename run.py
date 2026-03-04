#!/usr/bin/env python3
from __future__ import annotations

import os

from app import create_app
from app.legacy import ensure_monitoring_poller_started

app = create_app()


if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        ensure_monitoring_poller_started()
    app.run(host="0.0.0.0", port=8080, debug=True)
