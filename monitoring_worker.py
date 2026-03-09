#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

# Keep web process and worker process separated by default.
os.environ.setdefault("MONITORING_EMBEDDED_POLLER", "0")

from app import create_app
from app.legacy import monitoring_poll_cycle


STOP_EVENT = threading.Event()


def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _log(message: str) -> None:
    print(f"[{_now_stamp()}] {message}", flush=True)


class _SingleInstanceLock:
    def __init__(self, lock_path: Path) -> None:
        self._path = lock_path
        self._fh = None

    def acquire(self) -> bool:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a+")
        self._fh.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
            return False
        self._fh.truncate(0)
        self._fh.write(str(os.getpid()))
        self._fh.flush()
        return True

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            self._fh.close()
        except Exception:
            pass
        self._fh = None


def _handle_stop_signal(signum: int, _frame: object) -> None:
    _log(f"Stop signal received ({signum}). Exiting worker loop...")
    STOP_EVENT.set()


def run_worker(run_once: bool = False) -> int:
    app = create_app()
    with app.app_context():
        _log("Monitoring worker started.")
        while not STOP_EVENT.is_set():
            wait_seconds = 30
            try:
                wait_seconds = int(max(5, monitoring_poll_cycle()))
                _log(f"Polling cycle done. Next run in {wait_seconds}s.")
            except Exception as exc:
                wait_seconds = 30
                _log(f"Polling cycle failed: {exc}. Retrying in {wait_seconds}s.")
            if run_once:
                break
            STOP_EVENT.wait(wait_seconds)
    _log("Monitoring worker stopped.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Standalone monitoring poll worker (DB-backed).")
    parser.add_argument("--once", action="store_true", help="Run one polling cycle and exit.")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_stop_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_stop_signal)

    lock_file = Path(__file__).resolve().parent / ".monitoring_worker.lock"
    lock = _SingleInstanceLock(lock_file)
    if not lock.acquire():
        _log("Another monitoring worker instance is already running. Exiting.")
        return 1
    try:
        return run_worker(run_once=args.once)
    finally:
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
