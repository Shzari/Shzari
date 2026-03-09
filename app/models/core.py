from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SSHResult:
    device: str
    host: str
    status: str
    output: str


class DBError(Exception):
    pass


class DBOperationalError(DBError):
    pass


class DBRow:
    def __init__(self, columns: list[str], values: tuple[Any, ...]):
        self._columns = columns
        self._values = values
        self._index = {col.lower(): i for i, col in enumerate(columns)}

    def __getitem__(self, key: int | str) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._index[str(key).lower()]]

    def keys(self) -> list[str]:
        return list(self._columns)
