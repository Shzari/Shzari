from __future__ import annotations

import app.domains.commands.handlers_impl as _impl_mod

for _name, _value in _impl_mod.__dict__.items():
    if _name.startswith("__"):
        continue
    globals()[_name] = _value
