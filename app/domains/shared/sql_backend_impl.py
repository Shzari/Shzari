from __future__ import annotations

import re
from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)
if "SQLSERVER_PRIMARY_KEYS" not in globals():
    SQLSERVER_PRIMARY_KEYS: dict[str, list[str]] = {}


def embedded_monitoring_poller_enabled() -> bool:
    raw = str(os.environ.get("MONITORING_EMBEDDED_POLLER", "0")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _split_sql_list(expr: str) -> list[str]:
    items: list[str] = []
    current = []
    in_quote = False
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "'" and (i == 0 or expr[i - 1] != "\\"):
            in_quote = not in_quote
            current.append(ch)
        elif ch == "," and not in_quote:
            value = "".join(current).strip()
            if value:
                items.append(value)
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        items.append(tail)
    return items


def _extract_insert_parts(sql: str) -> tuple[str, list[str], list[str]] | None:
    match = re.search(
        r"INSERT\s+OR\s+(?:REPLACE|IGNORE)\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return None
    table = str(match.group(1)).strip()
    columns = _split_sql_list(str(match.group(2)))
    values = _split_sql_list(str(match.group(3)))
    if not table or not columns or len(columns) != len(values):
        return None
    return table, columns, values


def _rewrite_limit_clause(sql: str) -> str:
    normalized = sql.strip().rstrip(";")
    if re.search(r"\bLIMIT\s+\?\s*$", normalized, re.IGNORECASE):
        return re.sub(r"\bLIMIT\s+\?\s*$", "OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY", normalized, flags=re.IGNORECASE)
    if re.search(r"\bLIMIT\s+\d+\s*$", normalized, re.IGNORECASE):
        return re.sub(r"\bLIMIT\s+(\d+)\s*$", r"OFFSET 0 ROWS FETCH NEXT \1 ROWS ONLY", normalized, flags=re.IGNORECASE)
    return sql


def _convert_insert_or_ignore(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    parsed = _extract_insert_parts(sql)
    if not parsed:
        return sql.replace("INSERT OR IGNORE", "INSERT"), params
    table, columns, values = parsed
    keys = SQLSERVER_PRIMARY_KEYS.get(table, [columns[0]])
    src_items = ", ".join([f"{val} AS {col}" for col, val in zip(columns, values)])
    where_parts = [f"target.{col} = src.{col}" for col in keys]
    where_sql = " AND ".join(where_parts) if where_parts else "1 = 0"
    insert_cols = ", ".join(columns)
    rewritten = (
        f"INSERT INTO {table}({insert_cols}) "
        f"SELECT {', '.join([f'src.{col}' for col in columns])} "
        f"FROM (SELECT {src_items}) AS src "
        f"WHERE NOT EXISTS (SELECT 1 FROM {table} AS target WHERE {where_sql});"
    )
    return rewritten, params


def _convert_insert_or_replace(sql: str, params: tuple[Any, ...] | list[Any] | None) -> str:
    parsed = _extract_insert_parts(sql)
    if not parsed:
        return sql.replace("INSERT OR REPLACE", "INSERT")
    table, columns, values = parsed
    keys = SQLSERVER_PRIMARY_KEYS.get(table, [columns[0]])
    src_items = ", ".join([f"{val} AS {col}" for col, val in zip(columns, values)])
    on_clause = " AND ".join([f"target.{k} = src.{k}" for k in keys if k in columns])
    update_cols = [col for col in columns if col not in keys]
    update_clause = ", ".join([f"target.{col} = src.{col}" for col in update_cols])
    insert_cols = ", ".join(columns)
    insert_vals = ", ".join([f"src.{col}" for col in columns])
    merge_sql = [f"MERGE {table} AS target", f"USING (SELECT {src_items}) AS src", f"ON {on_clause}"]
    if update_clause:
        merge_sql.append(f"WHEN MATCHED THEN UPDATE SET {update_clause}")
    merge_sql.append(f"WHEN NOT MATCHED THEN INSERT ({insert_cols}) VALUES ({insert_vals});")
    return " ".join(merge_sql)


def _transform_sql(sql: str, params: tuple[Any, ...] | list[Any] | None) -> tuple[str, tuple[Any, ...] | list[Any] | None]:
    transformed = _rewrite_limit_clause(sql)
    upper = transformed.upper()
    if "INSERT OR IGNORE INTO" in upper:
        return _convert_insert_or_ignore(transformed, params)
    if "INSERT OR REPLACE INTO" in upper:
        return _convert_insert_or_replace(transformed, params), params
    return transformed, params


def _adapt_param_style(sql: str, backend: str) -> str:
    if backend == "pymssql":
        return sql.replace("?", "%s")
    return sql


class DBCursor:
    def __init__(self, conn: Any, cursor: Any, backend: str, columns: list[str] | None = None):
        self._conn = conn
        self._cursor = cursor
        self._backend = backend
        self._columns = columns
        self.lastrowid = 0

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] | None = None) -> "DBCursor":
        transformed_sql, transformed_params = _transform_sql(sql, params)
        final_sql = _adapt_param_style(transformed_sql, self._backend)
        try:
            if transformed_params is None:
                self._cursor.execute(final_sql)
            else:
                self._cursor.execute(final_sql, tuple(transformed_params))
            self._columns = [str(desc[0]) for desc in self._cursor.description] if self._cursor.description else None
            if final_sql.strip().upper().startswith("INSERT"):
                try:
                    identity_cursor = self._conn.cursor()
                    identity_cursor.execute("SELECT CAST(SCOPE_IDENTITY() AS INT)")
                    row = identity_cursor.fetchone()
                    self.lastrowid = int(row[0]) if row and row[0] is not None else 0
                    identity_cursor.close()
                except Exception:
                    self.lastrowid = 0
            return self
        except Exception as exc:
            raise DBOperationalError(str(exc)) from exc

    def executemany(self, sql: str, params_list: list[tuple[Any, ...]] | list[list[Any]]) -> "DBCursor":
        transformed_sql, _ = _transform_sql(sql, None)
        final_sql = _adapt_param_style(transformed_sql, self._backend)
        try:
            self._cursor.executemany(final_sql, [tuple(p) for p in params_list])
            return self
        except Exception as exc:
            raise DBOperationalError(str(exc)) from exc

    def fetchone(self) -> DBRow | None:
        row = self._cursor.fetchone()
        if row is None:
            return None
        columns = self._columns or [str(desc[0]) for desc in self._cursor.description]
        return DBRow(columns, tuple(row))

    def fetchall(self) -> list[DBRow]:
        rows = self._cursor.fetchall()
        columns = self._columns or [str(desc[0]) for desc in self._cursor.description]
        return [DBRow(columns, tuple(row)) for row in rows]

    def close(self) -> None:
        try:
            self._cursor.close()
        except Exception:
            pass


class DBConnection:
    def __init__(self, conn: Any, backend: str):
        self._conn = conn
        self._backend = backend

    def cursor(self) -> DBCursor:
        return DBCursor(self._conn, self._conn.cursor(), self._backend)

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] | None = None) -> DBCursor:
        cur = self.cursor()
        return cur.execute(sql, params)

    def executemany(self, sql: str, params_list: list[tuple[Any, ...]] | list[list[Any]]) -> DBCursor:
        cur = self.cursor()
        return cur.executemany(sql, params_list)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DBConnection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()
        return False


def _primary_sql_server_conn_string() -> str:
    return (
        f"DRIVER={{{PRIMARY_SQL_SERVER_DRIVER}}};"
        f"SERVER={PRIMARY_SQL_SERVER_HOST},{PRIMARY_SQL_SERVER_PORT};"
        f"DATABASE={PRIMARY_SQL_SERVER_DB};"
        f"UID={PRIMARY_SQL_SERVER_USER};PWD={PRIMARY_SQL_SERVER_PASSWORD};"
        "Encrypt=yes;TrustServerCertificate=yes;"
        "Connection Timeout=10;"
    )


def _pick_sql_client() -> str:
    preferred = PRIMARY_SQL_SERVER_CLIENT
    if preferred == "pymssql" and PYMSSQL_AVAILABLE:
        return "pymssql"
    if preferred == "pyodbc" and PYODBC_AVAILABLE:
        return "pyodbc"
    if preferred == "pymssql" and not PYMSSQL_AVAILABLE:
        return ""
    if preferred == "pyodbc" and not PYODBC_AVAILABLE:
        return ""
    if PYMSSQL_AVAILABLE:
        return "pymssql"
    if PYODBC_AVAILABLE:
        return "pyodbc"
    return ""


def _connect_primary_sql_server() -> tuple[Any, str]:
    client = _pick_sql_client()
    if client == "pymssql":
        server_name = PRIMARY_SQL_SERVER_HOST if "\\" in PRIMARY_SQL_SERVER_HOST else f"{PRIMARY_SQL_SERVER_HOST}:{PRIMARY_SQL_SERVER_PORT}"
        conn = pymssql.connect(
            server=server_name,
            user=PRIMARY_SQL_SERVER_USER,
            password=PRIMARY_SQL_SERVER_PASSWORD,
            database=PRIMARY_SQL_SERVER_DB,
            login_timeout=10,
            timeout=10,
            autocommit=False,
        )
        return conn, "pymssql"
    if client == "pyodbc":
        conn = pyodbc.connect(_primary_sql_server_conn_string(), autocommit=False, timeout=10)
        return conn, "pyodbc"
    raise RuntimeError("No SQL Server client available. Install pymssql (recommended, no ODBC) or pyodbc + ODBC Driver.")


def _sql_auto_create_db_enabled() -> bool:
    raw = str(os.environ.get("APP_SQL_AUTO_CREATE_DB", "1")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _looks_like_missing_database_error(exc: Exception) -> bool:
    text = str(exc or "").strip().lower()
    patterns = (
        "cannot open database",
        "unknown database",
        "database does not exist",
        "invalid catalog name",
    )
    return any(pattern in text for pattern in patterns)


def _quoted_db_name() -> str:
    raw = str(PRIMARY_SQL_SERVER_DB or "").strip()
    if not raw:
        raise RuntimeError("APP_SQL_DATABASE is empty.")
    return f"[{raw.replace(']', ']]')}]"


def _create_primary_database() -> None:
    db_name_sql = _quoted_db_name()
    db_name_literal = str(PRIMARY_SQL_SERVER_DB).replace("'", "''")
    client = _pick_sql_client()
    if client == "pymssql":
        server_name = PRIMARY_SQL_SERVER_HOST if "\\" in PRIMARY_SQL_SERVER_HOST else f"{PRIMARY_SQL_SERVER_HOST}:{PRIMARY_SQL_SERVER_PORT}"
        conn = pymssql.connect(
            server=server_name,
            user=PRIMARY_SQL_SERVER_USER,
            password=PRIMARY_SQL_SERVER_PASSWORD,
            database="master",
            login_timeout=10,
            timeout=10,
            autocommit=True,
        )
        try:
            cur = conn.cursor()
            cur.execute(f"IF DB_ID(N'{db_name_literal}') IS NULL CREATE DATABASE {db_name_sql};")
            cur.close()
        finally:
            conn.close()
        return
    if client == "pyodbc":
        master_conn_string = (
            f"DRIVER={{{PRIMARY_SQL_SERVER_DRIVER}}};"
            f"SERVER={PRIMARY_SQL_SERVER_HOST},{PRIMARY_SQL_SERVER_PORT};"
            "DATABASE=master;"
            f"UID={PRIMARY_SQL_SERVER_USER};PWD={PRIMARY_SQL_SERVER_PASSWORD};"
            "Encrypt=yes;TrustServerCertificate=yes;"
            "Connection Timeout=10;"
        )
        conn = pyodbc.connect(master_conn_string, autocommit=True, timeout=10)
        try:
            cur = conn.cursor()
            cur.execute(f"IF DB_ID(N'{db_name_literal}') IS NULL CREATE DATABASE {db_name_sql};")
            cur.close()
        finally:
            conn.close()
        return
    raise RuntimeError("No SQL Server client available to auto-create database.")


def db_conn() -> DBConnection:
    try:
        raw, backend = _connect_primary_sql_server()
        return DBConnection(raw, backend)
    except Exception as exc:
        if _sql_auto_create_db_enabled() and _looks_like_missing_database_error(exc):
            try:
                _create_primary_database()
                raw, backend = _connect_primary_sql_server()
                return DBConnection(raw, backend)
            except Exception as create_exc:
                raise RuntimeError(
                    f"Primary SQL Server connection failed and auto-create DB failed: {create_exc} (original: {exc})"
                ) from create_exc
        raise RuntimeError(f"Primary SQL Server connection failed: {exc}") from exc
