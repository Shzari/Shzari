from __future__ import annotations

# Legacy compatibility shim:
# this module re-exports the old public/private symbols from the
# runtime implementation moved to app.compat.legacy_runtime.

from app.compat import legacy_runtime as _runtime

for _name, _value in _runtime.__dict__.items():
    if _name.startswith("__"):
        continue
    globals()[_name] = _value

__all__ = [name for name in globals() if not name.startswith("__")]
