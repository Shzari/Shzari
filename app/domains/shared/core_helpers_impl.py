from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "db_conn" not in globals():
    from app.services.db_service import db_conn
if "normalize_config_command_text" not in globals():
    def normalize_config_command_text(command: str) -> str:
        text = str(command or "").replace("\r", "\n")
        segments: list[str] = []
        for line in text.split("\n"):
            for part in line.split(";"):
                candidate = part.strip()
                if candidate:
                    segments.append(candidate)
        return "\n".join(segments)


def load_users() -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT username, role, auth_source, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges FROM users ORDER BY username"
        ).fetchall()
        panel_rows: list[Any] = []
        menu_rows: list[Any] = []
        category_rows: list[Any] = []
        permissions_tables_available = True
        try:
            panel_rows = conn.execute(
                "SELECT username, panel_key, access_level FROM user_panel_permissions ORDER BY username, panel_key"
            ).fetchall()
            menu_rows = conn.execute(
                "SELECT username, menu_key, access_level FROM user_menu_permissions ORDER BY username, menu_key"
            ).fetchall()
            category_rows = conn.execute(
                "SELECT username, category_name, access_level FROM user_device_category_permissions ORDER BY username, category_name"
            ).fetchall()
        except Exception:
            permissions_tables_available = False

    panel_by_user: dict[str, dict[str, str]] = {}
    menu_by_user: dict[str, dict[str, str]] = {}
    category_by_user: dict[str, dict[str, str]] = {}
    if permissions_tables_available:
        for row in panel_rows:
            username_key = str(row["username"] or "").strip().lower()
            panel_key = str(row["panel_key"] or "").strip()
            if not username_key or not panel_key:
                continue
            panel_by_user.setdefault(username_key, {})[panel_key] = str(row["access_level"] or "")
        for row in menu_rows:
            username_key = str(row["username"] or "").strip().lower()
            menu_key = str(row["menu_key"] or "").strip()
            if not username_key or not menu_key:
                continue
            menu_by_user.setdefault(username_key, {})[menu_key] = str(row["access_level"] or "")
        for row in category_rows:
            username_key = str(row["username"] or "").strip().lower()
            category_name = str(row["category_name"] or "").strip()
            if not username_key or not category_name:
                continue
            category_by_user.setdefault(username_key, {})[category_name] = normalize_binary_access_level(
                row["access_level"], "none"
            )

    for row in rows:
        allowed_raw = row["allowed_categories"]
        try:
            allowed_categories = json.loads(allowed_raw) if allowed_raw else None
        except Exception:
            allowed_categories = None
        admin_raw = row["admin_permissions"]
        try:
            admin_permissions = json.loads(admin_raw) if admin_raw else []
        except Exception:
            admin_permissions = []
        panel_raw = row["category_panel_access"] if "category_panel_access" in row.keys() else None
        try:
            category_panel_access = json.loads(panel_raw) if panel_raw else {}
        except Exception:
            category_panel_access = {}
        account_raw = row["account_privileges"] if "account_privileges" in row.keys() else None
        try:
            account_privileges = (
                json.loads(account_raw) if account_raw else ["ip_addressing", "network_addressing", "net_devices", "monitoring"]
            )
        except Exception:
            account_privileges = ["ip_addressing", "network_addressing", "net_devices", "monitoring"]
        user: dict[str, Any] = {
            "username": row["username"],
            "role": normalize_role(str(row["role"])),
            "auth_source": normalize_auth_source(
                row["auth_source"] if "auth_source" in row.keys() else ("local" if str(row["password_hash"] or "") else "ldap")
            ),
            "salt": row["salt"],
            "password_hash": row["password_hash"],
            "must_change_password": bool(row["must_change_password"]),
            "allowed_categories": allowed_categories,
            "admin_permissions": admin_permissions,
            "category_panel_access": category_panel_access,
            "account_privileges": [str(item).strip() for item in account_privileges if str(item).strip()],
        }
        user["role"] = normalize_role(str(user.get("role", "junior")))
        user.setdefault("salt", "")
        user.setdefault("password_hash", "")
        user.setdefault("must_change_password", False)
        user.setdefault("auth_source", "ldap")
        user.setdefault("allowed_categories", None)
        user.setdefault("admin_permissions", [])
        user.setdefault("category_panel_access", {})
        user.setdefault("account_privileges", ["ip_addressing", "network_addressing", "net_devices", "monitoring"])

        username_key = str(user.get("username", "")).strip().lower()
        table_panel_permissions = panel_by_user.get(username_key, {})
        table_menu_permissions = menu_by_user.get(username_key, {})
        table_category_permissions = category_by_user.get(username_key, {})
        if table_panel_permissions or table_menu_permissions or table_category_permissions:
            resolved_panel_permissions = normalize_panel_permissions(table_panel_permissions)
            resolved_menu_permissions = normalize_menu_permissions(table_menu_permissions)
            resolved_menu_access = normalize_menu_access(resolved_menu_permissions)
            resolved_account_privileges = [
                key for key, value in resolved_panel_permissions.items() if access_level_allows_read(value)
            ]

            if table_category_permissions:
                selected_categories = sorted(
                    [name for name, level in table_category_permissions.items() if access_level_allows_read(level)]
                )
                nd_categories_access = access_level_allows_read(resolved_menu_permissions.get("nd_categories", "none"))
                nd_all_access = access_level_allows_read(resolved_menu_permissions.get("nd_all_devices", "none"))
                if not nd_categories_access:
                    resolved_allowed_categories: list[str] | None = None if nd_all_access else []
                elif not selected_categories and nd_all_access:
                    resolved_allowed_categories = None
                else:
                    resolved_allowed_categories = selected_categories
            else:
                resolved_allowed_categories = user.get("allowed_categories")

            user["allowed_categories"] = resolved_allowed_categories
            user["category_panel_access"] = {
                "panel_permissions": resolved_panel_permissions,
                "menu_permissions": resolved_menu_permissions,
                "menu_access": resolved_menu_access,
                "device_category_permissions": {
                    key: normalize_binary_access_level(value, "none") for key, value in table_category_permissions.items()
                },
            }
            user["account_privileges"] = resolved_account_privileges
        normalized.append(user)
    return normalized


def save_users(users: list[dict[str, Any]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM users")
        try:
            conn.execute("DELETE FROM user_panel_permissions")
            conn.execute("DELETE FROM user_menu_permissions")
            conn.execute("DELETE FROM user_device_category_permissions")
        except Exception:
            # Permission tables may not exist yet before migrations are applied.
            pass
        for user in users:
            panel_permissions = normalize_panel_permissions(
                (
                    user.get("category_panel_access", {}).get("panel_permissions")
                    if isinstance(user.get("category_panel_access"), dict)
                    else user.get("account_privileges")
                )
            )
            menu_permissions = normalize_menu_permissions(
                (
                    user.get("category_panel_access", {}).get("menu_permissions")
                    if isinstance(user.get("category_panel_access"), dict)
                    else user.get("category_panel_access")
                )
            )
            menu_access = normalize_menu_access(menu_permissions)
            category_panel_access_payload = {
                "panel_permissions": panel_permissions,
                "menu_permissions": menu_permissions,
                "menu_access": menu_access,
            }
            account_privileges = [key for key, value in panel_permissions.items() if access_level_allows_read(value)]
            conn.execute(
                """
                INSERT INTO users(username, role, auth_source, salt, password_hash, must_change_password, allowed_categories, admin_permissions, category_panel_access, account_privileges)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(user.get("username", "")).strip(),
                    normalize_role(str(user.get("role", "junior"))),
                    normalize_auth_source(user.get("auth_source", "ldap")),
                    str(user.get("salt", "")),
                    str(user.get("password_hash", "")),
                    1 if bool(user.get("must_change_password", True)) else 0,
                    json.dumps(user.get("allowed_categories")),
                    json.dumps(user.get("admin_permissions", [])),
                    json.dumps(category_panel_access_payload),
                    json.dumps(account_privileges),
                ),
            )
            now_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            username = str(user.get("username", "")).strip()
            if not username:
                continue
            try:
                for panel_key, access_level in panel_permissions.items():
                    conn.execute(
                        """
                        INSERT INTO user_panel_permissions(username, panel_key, access_level, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (username, str(panel_key), normalize_access_level(access_level, "none"), now_stamp),
                    )
                for menu_key, access_level in menu_permissions.items():
                    conn.execute(
                        """
                        INSERT INTO user_menu_permissions(username, menu_key, access_level, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (username, str(menu_key), normalize_access_level(access_level, "none"), now_stamp),
                    )

                category_permissions_payload = {}
                category_panel_access = user.get("category_panel_access")
                if isinstance(category_panel_access, dict):
                    raw_category_permissions = category_panel_access.get("device_category_permissions", {})
                    if isinstance(raw_category_permissions, dict):
                        category_permissions_payload = {
                            str(name).strip(): normalize_binary_access_level(level, "none")
                            for name, level in raw_category_permissions.items()
                            if str(name).strip()
                        }
                if not category_permissions_payload and isinstance(user.get("allowed_categories"), list):
                    category_permissions_payload = {
                        str(name).strip(): "both"
                        for name in user.get("allowed_categories", [])
                        if str(name).strip()
                    }

                for category_name, access_level in category_permissions_payload.items():
                    conn.execute(
                        """
                        INSERT INTO user_device_category_permissions(username, category_name, access_level, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (username, category_name, normalize_binary_access_level(access_level, "none"), now_stamp),
                    )
            except Exception:
                # Keep legacy users row persistence working even if new tables are not yet present.
                pass


def super_admin_exists() -> bool:
    with db_conn() as conn:
        row = conn.execute("SELECT username FROM super_admin WHERE id = 1").fetchone()
    return bool(row and str(row["username"]).strip())


def load_super_admin() -> dict[str, Any]:
    with db_conn() as conn:
        row = conn.execute("SELECT username, salt, password_hash FROM super_admin WHERE id = 1").fetchone()
    if not row:
        return {}
    return {
        "username": str(row["username"] or "").strip(),
        "salt": str(row["salt"] or ""),
        "password_hash": str(row["password_hash"] or ""),
    }


def save_super_admin(username: str, password: str) -> None:
    salt = secrets.token_hex(16)
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO super_admin(id, username, salt, password_hash) VALUES (1, ?, ?, ?)",
            (username.strip(), salt, _hash_password(password, salt)),
        )


def verify_super_admin(username: str, password: str) -> bool:
    data = load_super_admin()
    if not data:
        return False
    if username.strip() != str(data.get("username", "")):
        return False
    salt = str(data.get("salt", ""))
    expected = str(data.get("password_hash", ""))
    if not salt or not expected:
        return False
    actual = _hash_password(password, salt)
    return hmac.compare_digest(actual, expected)


def find_user(users: list[dict[str, Any]], username: str) -> dict[str, Any] | None:
    normalized = username.strip().lower()
    for user in users:
        if str(user.get("username", "")).strip().lower() == normalized:
            return user
    return None


def set_user_password(user: dict[str, Any], password: str) -> None:
    salt = secrets.token_hex(16)
    user["salt"] = salt
    user["password_hash"] = _hash_password(password, salt)


def is_provisioned_app_user(username: str) -> bool:
    check = str(username or "").strip().lower()
    if not check:
        return False
    return find_user(load_users(), check) is not None


def normalize_role(role: str) -> str:
    raw = str(role or "").strip().lower()
    if raw in {"senior", "sysadmin", "junior", "helpdesk", "audit", "manager"}:
        return raw
    if raw in {"super_admin", "admin"}:
        return "senior"
    return "junior"


def normalize_auth_source(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw == "local":
        return "local"
    return "ldap"


def is_current_session_super_admin() -> bool:
    creds = session.get("creds", {})
    current_username = str(creds.get("username", "")).strip().lower()
    super_username = str(load_super_admin().get("username", "")).strip().lower()
    return bool(current_username and super_username and current_username == super_username)


def current_user_role() -> str:
    if is_current_session_super_admin():
        return "senior"
    if str(session.get("auth_mode", "local")) != "local":
        return "junior"
    username = str(session.get("creds", {}).get("username", "")).strip()
    users = load_users()
    user = find_user(users, username)
    if not user:
        return "junior"
    return normalize_role(str(user.get("role", "junior")))


def normalize_access_level(value: Any, default: str = "both") -> str:
    text = str(value if value is not None else "").strip().lower()
    if text in {"none", "no", "off", "deny", "disabled"}:
        return "none"
    if text in {"read", "r", "view", "readonly", "read_only"}:
        return "read"
    if text in {"write", "w", "edit", "modify"}:
        return "write"
    if text in {"both", "all", "rw", "readwrite", "read_write"}:
        return "both"
    if isinstance(value, bool):
        return "both" if value else "none"
    fallback = str(default or "both").strip().lower()
    return fallback if fallback in {"none", "read", "write", "both"} else "both"


def access_level_allows_read(level: Any) -> bool:
    return normalize_access_level(level, "none") in {"read", "write", "both"}


def access_level_allows_write(level: Any) -> bool:
    return normalize_access_level(level, "none") in {"write", "both"}


def normalize_binary_access_level(value: Any, default: str = "none") -> str:
    normalized = normalize_access_level(value, default)
    return "both" if normalized in {"read", "write", "both"} else "none"


def network_address_menu_keys() -> list[str]:
    return [
        "na_system",
        "na_system_ho",
        "na_system_ho_vm",
        "na_system_ho_physical",
        "na_system_ho_storage",
        "na_system_drs",
        "na_system_drs_vm",
        "na_system_drs_physical",
        "na_system_drs_storage",
        "na_network",
        "na_network_devices",
        "na_isp",
        "na_isp_branches",
        "na_isp_atm",
        "na_isp_internet",
        "na_dmvpn",
        "na_dmvpn_branches",
        "na_dmvpn_atms",
        "na_sim_cards",
        "na_site_to_site",
        "na_nat",
    ]


def net_devices_menu_keys() -> list[str]:
    return [
        "nd_all_devices",
        "nd_categories",
    ]


def _legacy_menu_permission_aliases() -> dict[str, list[str]]:
    return {
        "na_servers": [
            "na_system",
            "na_system_ho",
            "na_system_drs",
            "na_system_ho_vm",
            "na_system_ho_physical",
            "na_system_ho_storage",
            "na_system_drs_vm",
            "na_system_drs_physical",
            "na_system_drs_storage",
        ],
        "na_branches_isp": ["na_isp", "na_isp_branches", "na_isp_atm", "na_isp_internet"],
        "na_dmvpn": ["na_dmvpn", "na_dmvpn_branches", "na_dmvpn_atms"],
    }


def default_panel_permissions() -> dict[str, str]:
    return {
        "ip_addressing": "both",
        "network_addressing": "both",
        "net_devices": "both",
        "monitoring": "both",
    }


def normalize_panel_key(panel_name: str) -> str:
    panel = str(panel_name or "net_devices").strip().lower()
    if panel in {"devices", "net_devices"}:
        return "net_devices"
    if panel in {"monitoring", "net_monitoring"}:
        return "monitoring"
    if panel in {"network_addressing", "network_addresses"}:
        return "network_addressing"
    if panel == "ip_addressing":
        return "ip_addressing"
    return panel


def normalize_panel_permissions(raw: Any) -> dict[str, str]:
    defaults = default_panel_permissions()
    if isinstance(raw, list):
        selected: set[str] = set()
        for item in raw:
            key = normalize_panel_key(str(item))
            if key == "devices":
                key = "net_devices"
            if key in defaults:
                selected.add(key)
        if "ip_addressing" in selected:
            selected.add("network_addressing")
        return {key: ("both" if key in selected else "none") for key in defaults}

    if isinstance(raw, dict):
        # When explicit panel permission keys are present, treat missing keys as
        # deny-by-default instead of granting inherited full access.
        has_explicit_keys = any(str(key) in defaults for key in raw.keys())
        normalized: dict[str, str] = {}
        for key in defaults:
            default_level = "none" if has_explicit_keys else defaults[key]
            normalized[key] = normalize_access_level(raw.get(key, default_level), default_level)
        normalized["net_devices"] = normalize_binary_access_level(normalized.get("net_devices", "none"), "none")
        return normalized
    resolved_defaults = dict(defaults)
    resolved_defaults["net_devices"] = normalize_binary_access_level(resolved_defaults.get("net_devices", "none"), "none")
    return resolved_defaults


def default_menu_permissions() -> dict[str, str]:
    network_keys = network_address_menu_keys()
    device_keys = net_devices_menu_keys()
    defaults = {
        "ip_branches": "both",
        "ip_hq": "both",
    }
    defaults.update({key: "both" for key in network_keys})
    defaults.update({key: "both" for key in device_keys})
    return defaults


def _menu_permission_dependencies() -> dict[str, list[str]]:
    return {
        "na_system": [
            "na_system_ho",
            "na_system_ho_vm",
            "na_system_ho_physical",
            "na_system_ho_storage",
            "na_system_drs",
            "na_system_drs_vm",
            "na_system_drs_physical",
            "na_system_drs_storage",
        ],
        "na_system_ho": ["na_system_ho_vm", "na_system_ho_physical", "na_system_ho_storage"],
        "na_system_drs": ["na_system_drs_vm", "na_system_drs_physical", "na_system_drs_storage"],
        "na_network": [
            "na_network_devices",
            "na_isp",
            "na_isp_branches",
            "na_isp_atm",
            "na_isp_internet",
            "na_dmvpn",
            "na_dmvpn_branches",
            "na_dmvpn_atms",
            "na_sim_cards",
            "na_site_to_site",
            "na_nat",
        ],
        "na_isp": ["na_isp_branches", "na_isp_atm", "na_isp_internet"],
        "na_dmvpn": ["na_dmvpn_branches", "na_dmvpn_atms"],
    }


def _apply_menu_permission_dependencies(permissions: dict[str, str]) -> dict[str, str]:
    normalized = dict(permissions)
    for parent, children in _menu_permission_dependencies().items():
        if not access_level_allows_read(normalized.get(parent, "none")):
            for child in children:
                if child in normalized:
                    normalized[child] = "none"
    return normalized


def normalize_menu_permissions(raw: Any) -> dict[str, str]:
    defaults = default_menu_permissions()
    aliases = _legacy_menu_permission_aliases()
    if isinstance(raw, list):
        selected = {str(item).strip() for item in raw if str(item).strip()}
        expanded: set[str] = set()
        for key in selected:
            if key in aliases:
                expanded.update(aliases[key])
                continue
            expanded.add(key)
        normalized = _apply_menu_permission_dependencies({key: ("both" if key in expanded else "none") for key in defaults})
        for key in net_devices_menu_keys():
            normalized[key] = normalize_binary_access_level(normalized.get(key, "none"), "none")
        return normalized
    if isinstance(raw, dict):
        # If any explicit menu/legacy permission key is present, missing keys
        # should not silently escalate to full access.
        has_explicit_keys = any((str(key) in defaults) or (str(key) in aliases) for key in raw.keys())
        normalized: dict[str, str] = {}
        for key in defaults:
            source_value: Any = raw.get(key)
            if source_value is None:
                for legacy_key, mapped_keys in aliases.items():
                    if key in mapped_keys and legacy_key in raw:
                        source_value = raw.get(legacy_key)
                        break
            default_level = "none" if has_explicit_keys else defaults[key]
            normalized[key] = normalize_access_level(
                source_value if source_value is not None else default_level,
                default_level,
            )
        normalized = _apply_menu_permission_dependencies(normalized)
        for key in net_devices_menu_keys():
            normalized[key] = normalize_binary_access_level(normalized.get(key, "none"), "none")
        return normalized
    resolved_defaults = dict(defaults)
    for key in net_devices_menu_keys():
        resolved_defaults[key] = normalize_binary_access_level(resolved_defaults.get(key, "none"), "none")
    return resolved_defaults


def load_ip_branches() -> list[str]:
    with db_conn() as conn:
        rows = conn.execute("SELECT branch_name FROM ip_branches ORDER BY branch_name").fetchall()
        db_branches = [str(row["branch_name"]).strip() for row in rows if str(row["branch_name"]).strip()]
        if db_branches:
            return db_branches

        seeded: list[str] = []
        if IP_BRANCHES_FILE.exists():
            try:
                raw = json.loads(IP_BRANCHES_FILE.read_text(encoding="utf-8"))
            except Exception:
                raw = []
            if isinstance(raw, list):
                seeded = [str(item).strip() for item in raw if str(item).strip()]
        if not seeded:
            seeded = default_ip_branches()

        normalized: list[str] = []
        seen: set[str] = set()
        for item in seeded:
            name = str(item).strip()
            key = name.lower()
            if not name or key in seen:
                continue
            seen.add(key)
            normalized.append(name)
        if not normalized:
            normalized = default_ip_branches()

        for branch_name in normalized:
            conn.execute("INSERT OR IGNORE INTO ip_branches(branch_name) VALUES (?)", (branch_name,))
        return normalized


def save_ip_branches(branches: list[str]) -> None:
    normalized = []
    seen: set[str] = set()
    for item in branches:
        name = str(item).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        normalized.append(name)
    with db_conn() as conn:
        conn.execute("DELETE FROM ip_branches")
        for branch_name in normalized:
            conn.execute("INSERT INTO ip_branches(branch_name) VALUES (?)", (branch_name,))
        if normalized:
            placeholders = ", ".join("?" for _ in normalized)
            conn.execute(
                f"DELETE FROM ip_branch_ips WHERE branch_name NOT IN ({placeholders})",
                tuple(normalized),
            )
            conn.execute(
                f"DELETE FROM ip_branch_details WHERE branch_name NOT IN ({placeholders})",
                tuple(normalized),
            )
        else:
            conn.execute("DELETE FROM ip_branch_ips")
            conn.execute("DELETE FROM ip_branch_details")
    try:
        IP_BRANCHES_FILE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_device_creds_store() -> dict[str, dict[str, str]]:
    normalized: dict[str, dict[str, str]] = {}
    with db_conn() as conn:
        rows = conn.execute("SELECT account_key, username, password_enc, enable_password_enc FROM device_credentials").fetchall()

    for row in rows:
        normalized[str(row["account_key"])] = {
            "username": str(row["username"] or "").strip(),
            "password": decrypt_secret(str(row["password_enc"] or "")),
            "enable_password": decrypt_secret(str(row["enable_password_enc"] or "")),
        }
    return normalized


def save_device_creds_store(store: dict[str, dict[str, str]]) -> None:
    with db_conn() as conn:
        conn.execute("DELETE FROM device_credentials")
        for account_key, value in store.items():
            conn.execute(
                """
                INSERT INTO device_credentials(account_key, username, password_enc, enable_password_enc)
                VALUES (?, ?, ?, ?)
                """,
                (
                    str(account_key),
                    str(value.get("username", "")).strip(),
                    encrypt_secret(str(value.get("password", ""))),
                    encrypt_secret(str(value.get("enable_password", ""))),
                ),
            )


def device_creds_key(account_username: str, auth_mode: str) -> str:
    return f"{auth_mode.strip().lower()}::{account_username.strip().lower()}"


def load_user_device_creds(account_username: str, auth_mode: str) -> dict[str, str]:
    store = load_device_creds_store()
    return dict(store.get(device_creds_key(account_username, auth_mode), {}))


def save_user_device_creds(account_username: str, auth_mode: str, creds: dict[str, str]) -> None:
    store = load_device_creds_store()
    store[device_creds_key(account_username, auth_mode)] = {
        "username": str(creds.get("username", "")).strip(),
        "password": str(creds.get("password", "")),
        "enable_password": str(creds.get("enable_password", "")),
    }
    save_device_creds_store(store)


def _load_app_setting_json(setting_key: str, default_value: Any, legacy_file: Any | None = None) -> Any:
    with db_conn() as conn:
        row = conn.execute("SELECT setting_json FROM app_settings WHERE setting_key = ?", (setting_key,)).fetchone()
        if row and str(row["setting_json"] or "").strip():
            try:
                return json.loads(str(row["setting_json"]))
            except Exception:
                return default_value

    if legacy_file is not None and getattr(legacy_file, "exists", lambda: False)():
        try:
            legacy_value = json.loads(legacy_file.read_text(encoding="utf-8"))
            _save_app_setting_json(setting_key, legacy_value)
            return legacy_value
        except Exception:
            return default_value
    return default_value


def _save_app_setting_json(setting_key: str, payload: Any) -> None:
    with db_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO app_settings(setting_key, setting_json, updated_at) VALUES (?, ?, ?)",
            (setting_key, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
        )


def load_user_buttons_store() -> dict[str, list[dict[str, Any]]]:
    data = _load_app_setting_json("user_buttons_store", {}, USER_BUTTONS_FILE)
    if not isinstance(data, dict):
        return {}

    normalized: dict[str, list[dict[str, Any]]] = {}
    for key, value in data.items():
        normalized[str(key)] = normalize_buttons(value)
    return normalized


def save_user_buttons_store(store: dict[str, list[dict[str, Any]]]) -> None:
    _save_app_setting_json("user_buttons_store", store)


def load_user_buttons(account_username: str, auth_mode: str) -> list[dict[str, Any]]:
    _ = device_creds_key(account_username, auth_mode)
    global_key = "__global__"
    store = load_user_buttons_store()
    global_buttons = normalize_buttons(store.get(global_key, []))
    if global_buttons:
        return global_buttons
    for legacy_buttons in store.values():
        migrated = normalize_buttons(legacy_buttons)
        if migrated:
            store[global_key] = migrated
            save_user_buttons_store(store)
            return migrated
    legacy_key = device_creds_key(account_username, auth_mode)
    return normalize_buttons(store.get(legacy_key, []))


def save_user_buttons(account_username: str, auth_mode: str, buttons: list[dict[str, Any]]) -> None:
    _ = device_creds_key(account_username, auth_mode)
    global_key = "__global__"
    store = load_user_buttons_store()
    store[global_key] = normalize_buttons(buttons)
    save_user_buttons_store(store)


def load_devices() -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    with db_conn() as conn:
        rows = conn.execute("SELECT hostname, ip_address FROM devices ORDER BY hostname").fetchall()
        group_rows = conn.execute("SELECT hostname, group_name FROM device_groups").fetchall()

    group_map: dict[str, list[str]] = {}
    for row in group_rows:
        group_map.setdefault(str(row["hostname"]), []).append(str(row["group_name"]))

    for row in rows:
        hostname = str(row["hostname"])
        devices.append(
            {
                "name": hostname,
                "host": str(row["ip_address"]),
                "port": 22,
                "groups": sorted(group_map.get(hostname, [])),
            }
        )
    return devices


def save_devices(devices: list[dict[str, Any]], conn: Any | None = None) -> None:
    def _save(target_conn: Any) -> None:
        target_conn.execute("DELETE FROM device_groups")
        target_conn.execute("DELETE FROM devices")
        for device in devices:
            hostname = str(device.get("name", device.get("hostname", ""))).strip()
            ip_address = str(device.get("host", device.get("ip_address", ""))).strip()
            if not hostname or not ip_address:
                continue
            target_conn.execute("INSERT INTO devices(hostname, ip_address) VALUES (?, ?)", (hostname, ip_address))
            for group in device.get("groups", []):
                group_name = str(group).strip()
                if group_name:
                    target_conn.execute(
                        "INSERT OR IGNORE INTO device_groups(hostname, group_name) VALUES (?, ?)",
                        (hostname, group_name),
                    )

    if conn is None:
        with db_conn() as own_conn:
            _save(own_conn)
        return

    _save(conn)


def grouped_devices(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for group in device.get("groups", []):
            groups.setdefault(group, []).append(device)
    return groups


def all_categories(devices: list[dict[str, Any]]) -> list[str]:
    categories: set[str] = set()
    for device in devices:
        groups = [str(group).strip() for group in device.get("groups", []) if str(group).strip()]
        if not groups:
            categories.add(DEFAULT_CATEGORY)
            continue
        for group in groups:
            group_name = str(group).strip()
            if group_name:
                categories.add(group_name)
    return sorted(categories)


def user_allowed_categories(username: str, auth_mode: str) -> list[str] | None:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return None

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return []
    role = normalize_role(str(user.get("role", "junior")))
    if role == "manager":
        return None
    allowed = user.get("allowed_categories")
    if allowed is None:
        return None
    if isinstance(allowed, list):
        return [str(item).strip() for item in allowed if str(item).strip()]
    return []


def filter_devices_for_user(devices: list[dict[str, Any]], username: str, auth_mode: str) -> list[dict[str, Any]]:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return devices

    allowed_set = set(allowed)
    filtered: list[dict[str, Any]] = []
    for device in devices:
        groups = [str(g).strip() for g in device.get("groups", []) if str(g).strip()]
        if not groups:
            if DEFAULT_CATEGORY in allowed_set:
                cloned = dict(device)
                cloned["groups"] = [DEFAULT_CATEGORY]
                filtered.append(cloned)
            continue
        allowed_groups = [group for group in groups if group in allowed_set]
        if allowed_groups:
            cloned = dict(device)
            cloned["groups"] = allowed_groups
            filtered.append(cloned)
    return filtered


def user_panel_permissions(username: str, auth_mode: str) -> dict[str, str]:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return default_panel_permissions()

    user = find_user(load_users(), username)
    if user is None:
        return {key: "none" for key in default_panel_permissions()}

    role = normalize_role(str(user.get("role", "junior")))
    if role == "manager":
        return {key: "read" for key in default_panel_permissions()}

    category_panel_access = user.get("category_panel_access")
    if isinstance(category_panel_access, dict) and isinstance(category_panel_access.get("panel_permissions"), dict):
        return normalize_panel_permissions(category_panel_access.get("panel_permissions", {}))

    return normalize_panel_permissions(user.get("account_privileges"))


def user_has_panel_access(username: str, auth_mode: str, panel_name: str) -> bool:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return True
    user = find_user(load_users(), username)
    if user is None:
        return False
    role = normalize_role(str(user.get("role", "junior")))
    if role == "audit":
        return False
    panel = normalize_panel_key(panel_name)
    permissions = user_panel_permissions(username, auth_mode)
    return access_level_allows_read(permissions.get(panel, "none"))


def user_can_write_panel(username: str, auth_mode: str, panel_name: str) -> bool:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return True
    user = find_user(load_users(), username)
    if user is None:
        return False
    role = normalize_role(str(user.get("role", "junior")))
    if role in {"audit", "manager"}:
        return False
    panel = normalize_panel_key(panel_name)
    permissions = user_panel_permissions(username, auth_mode)
    return access_level_allows_write(permissions.get(panel, "none"))


def default_menu_access() -> dict[str, bool]:
    return {key: access_level_allows_read(level) for key, level in default_menu_permissions().items()}


def normalize_menu_access(raw: Any) -> dict[str, bool]:
    menu_permissions = normalize_menu_permissions(raw)
    return {key: access_level_allows_read(level) for key, level in menu_permissions.items()}


def user_menu_permissions(username: str, auth_mode: str) -> dict[str, str]:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return default_menu_permissions()

    users = load_users()
    user = find_user(users, username)
    if user is None:
        return default_menu_permissions()

    role = normalize_role(str(user.get("role", "junior")))
    if role == "manager":
        return {key: "read" for key in default_menu_permissions()}

    category_panel_access = user.get("category_panel_access")
    raw: Any = {}
    if isinstance(category_panel_access, dict):
        if isinstance(category_panel_access.get("menu_permissions"), dict):
            raw = category_panel_access.get("menu_permissions", {})
        elif isinstance(category_panel_access.get("menu_access"), (dict, list)):
            raw = category_panel_access.get("menu_access", {})
        else:
            raw = category_panel_access
    permissions = normalize_menu_permissions(raw)
    panel_permissions = user_panel_permissions(username, auth_mode)
    if not access_level_allows_read(panel_permissions.get("ip_addressing", "none")):
        permissions["ip_branches"] = "none"
        permissions["ip_hq"] = "none"
    if not access_level_allows_read(panel_permissions.get("network_addressing", "none")):
        for key in network_address_menu_keys():
            permissions[key] = "none"
    if not access_level_allows_read(panel_permissions.get("net_devices", "none")):
        for key in net_devices_menu_keys():
            permissions[key] = "none"
    return _apply_menu_permission_dependencies(permissions)


def user_menu_access(username: str, auth_mode: str) -> dict[str, bool]:
    permissions = user_menu_permissions(username, auth_mode)
    return {key: access_level_allows_read(level) for key, level in permissions.items()}


def user_can_write_menu(username: str, auth_mode: str, menu_key: str) -> bool:
    super_admin_username = str(load_super_admin().get("username", "")).strip().lower()
    if username.strip().lower() == super_admin_username:
        return True
    user = find_user(load_users(), username)
    if user is None:
        return False
    role = normalize_role(str(user.get("role", "junior")))
    if role in {"audit", "manager"}:
        return False
    permissions = user_menu_permissions(username, auth_mode)
    return access_level_allows_write(permissions.get(str(menu_key or "").strip(), "none"))


def user_allowed_categories_by_panel(username: str, auth_mode: str, panel_name: str) -> list[str] | None:
    if not user_has_panel_access(username, auth_mode, panel_name):
        return []
    return user_allowed_categories(username, auth_mode)


def user_can_access_device(device: dict[str, Any], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories_by_panel(username, auth_mode, "devices")
    if allowed is None:
        return True

    allowed_set = set(allowed)
    groups = {str(g).strip() for g in device.get("groups", []) if str(g).strip()}
    if not groups:
        return DEFAULT_CATEGORY in allowed_set
    return bool(groups & allowed_set)


def user_can_assign_categories(categories: list[str], username: str, auth_mode: str) -> bool:
    allowed = user_allowed_categories(username, auth_mode)
    if allowed is None:
        return True
    allowed_set = set(allowed)
    return all(category in allowed_set for category in categories)


def default_buttons() -> list[dict[str, Any]]:
    return [
        {"id": "show-version", "label": "Show Version", "command": "show version", "mode": "show", "categories": [], "audience": "senior"},
        {
            "id": "show-ip-int-brief",
            "label": "IP Interface Brief",
            "command": "show ip interface brief",
            "mode": "show",
            "categories": [],
            "audience": "senior",
        },
        {
            "id": "show-int-status",
            "label": "Interfaces Status",
            "command": "show interfaces status",
            "mode": "show",
            "categories": [],
            "audience": "senior",
        },
        {
            "id": "show-logging",
            "label": "Show Logging",
            "command": "show logging | tail 50",
            "mode": "show",
            "categories": [],
            "audience": "senior",
        },
        {
            "id": "show-hostname",
            "label": "Show Hostname",
            "command": "show running-config | include hostname",
            "mode": "show",
            "categories": [],
            "audience": "senior",
        },
        {"id": "show-arp", "label": "Show ARP", "command": "show arp", "mode": "show", "categories": [], "audience": "senior"},
        {
            "id": "show-cdp",
            "label": "CDP Neighbors",
            "command": "show cdp neighbors",
            "mode": "show",
            "categories": [],
            "audience": "senior",
        },
        {"id": "show-route", "label": "IP Route", "command": "show ip route", "mode": "show", "categories": [], "audience": "senior"},
        {
            "id": "config-hostname",
            "label": "Set Hostname",
            "command": "configure terminal\nhostname NEW-HOSTNAME",
            "mode": "config",
            "categories": [],
            "audience": "senior",
        },
        {
            "id": "config-int-desc",
            "label": "Interface Description",
            "command": "configure terminal\ninterface Gi0/1\ndescription UPDATED_BY_TOOL",
            "mode": "config",
            "categories": [],
            "audience": "senior",
        },
        {"id": "config-save", "label": "Save Config", "command": "write memory", "mode": "config", "categories": [], "audience": "senior"},
    ]


def normalize_buttons(raw_buttons: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_buttons, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_buttons:
        if not isinstance(item, dict):
            continue
        button_id = str(item.get("id", "")).strip()
        label = str(item.get("label", "")).strip()
        command = str(item.get("command", "")).strip()
        if not button_id or not label or not command:
            continue

        mode = str(item.get("mode", "show")).strip().lower()
        if mode not in {"show", "config"}:
            mode = "show"

        categories_raw = item.get("categories", [])
        categories: list[str] = []
        if isinstance(categories_raw, list):
            categories = [str(cat).strip() for cat in categories_raw if str(cat).strip()]
        audience = str(item.get("audience", "senior")).strip().lower()
        if audience not in {"junior", "senior", "both"}:
            audience = "senior"

        if mode == "config":
            command = normalize_config_command_text(command)
        normalized.append(
            {
                "id": button_id,
                "label": label,
                "command": command,
                "mode": mode,
                "categories": categories,
                "audience": audience,
            }
        )
    return normalized


def button_audience_for_role(role: str) -> str:
    normalized = normalize_role(role)
    if normalized in {"junior", "helpdesk", "manager"}:
        return "junior"
    return "senior"


def buttons_for_role(role: str) -> list[dict[str, Any]]:
    audience = button_audience_for_role(role)
    return [item for item in get_buttons() if str(item.get("audience", "senior")).strip().lower() in {audience, "both"}]


def get_buttons() -> list[dict[str, Any]]:
    buttons = normalize_buttons(session.get("buttons"))
    if buttons:
        session["buttons"] = buttons
        return buttons
    buttons = default_buttons()
    session["buttons"] = buttons
    return buttons


def persist_current_user_buttons(buttons: list[dict[str, Any]]) -> None:
    account = session.get("creds", {})
    account_username = str(account.get("username", "")).strip()
    auth_mode = str(session.get("auth_mode", "local"))
    if account_username:
        save_user_buttons(account_username, auth_mode, buttons)


def default_ise_settings() -> dict[str, Any]:
    return {
        "primary_server": "",
        "primary_port": 1812,
        "primary_shared_secret": "",
        "secondary_server": "",
        "secondary_port": 1812,
        "secondary_shared_secret": "",
        "timeout": 5,
        "nas_ip": "127.0.0.1",
    }


def load_ise_settings() -> dict[str, Any]:
    defaults = default_ise_settings()
    with db_conn() as conn:
        row = conn.execute("""
            SELECT primary_server, primary_port, primary_shared_secret,
                   secondary_server, secondary_port, secondary_shared_secret,
                   timeout, nas_ip
            FROM ise_settings WHERE id = 1
            """).fetchone()

    if not row:
        return defaults

    defaults.update(
        {
            "primary_server": str(row["primary_server"] or "").strip(),
            "primary_port": int(row["primary_port"] or 1812),
            "primary_shared_secret": decrypt_secret(str(row["primary_shared_secret"] or "")),
            "secondary_server": str(row["secondary_server"] or "").strip(),
            "secondary_port": int(row["secondary_port"] or 1812),
            "secondary_shared_secret": decrypt_secret(str(row["secondary_shared_secret"] or "")),
            "timeout": int(row["timeout"] or 5),
            "nas_ip": str(row["nas_ip"] or "127.0.0.1").strip(),
        }
    )
    return defaults


def save_ise_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ise_settings(
                id, primary_server, primary_port, primary_shared_secret,
                secondary_server, secondary_port, secondary_shared_secret,
                timeout, nas_ip
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(settings.get("primary_server", "")).strip(),
                int(settings.get("primary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("primary_shared_secret", ""))),
                str(settings.get("secondary_server", "")).strip(),
                int(settings.get("secondary_port", 1812) or 1812),
                encrypt_secret(str(settings.get("secondary_shared_secret", ""))),
                int(settings.get("timeout", 5) or 5),
                str(settings.get("nas_ip", "127.0.0.1")).strip(),
            ),
        )


def default_ldap_settings() -> dict[str, Any]:
    return {
        "server": "",
        "port": 389,
        "use_ssl": False,
        "start_tls": False,
        "timeout": 5,
        "base_dn": "",
        "user_dn_template": "",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_dn": "",
        "bind_password": "",
    }


def load_ldap_settings() -> dict[str, Any]:
    defaults = default_ldap_settings()
    with db_conn() as conn:
        row = conn.execute("""
            SELECT server, port, use_ssl, start_tls, timeout, base_dn,
                   user_dn_template, user_search_filter, bind_dn, bind_password
            FROM ldap_settings WHERE id = 1
            """).fetchone()

    if not row:
        return defaults

    defaults.update(
        {
            "server": str(row["server"] or "").strip(),
            "port": int(row["port"] or 389),
            "use_ssl": bool(row["use_ssl"]),
            "start_tls": bool(row["start_tls"]),
            "timeout": int(row["timeout"] or 5),
            "base_dn": str(row["base_dn"] or "").strip(),
            "user_dn_template": str(row["user_dn_template"] or "").strip(),
            "user_search_filter": str(row["user_search_filter"] or "(sAMAccountName={username})").strip() or "(sAMAccountName={username})",
            "bind_dn": str(row["bind_dn"] or "").strip(),
            "bind_password": decrypt_secret(str(row["bind_password"] or "")),
        }
    )
    return defaults


def save_ldap_settings(settings: dict[str, Any]) -> None:
    with db_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO ldap_settings(
                id, server, port, use_ssl, start_tls, timeout, base_dn,
                user_dn_template, user_search_filter, bind_dn, bind_password
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(settings.get("server", "")).strip(),
                int(settings.get("port", 389) or 389),
                1 if bool(settings.get("use_ssl")) else 0,
                1 if bool(settings.get("start_tls")) else 0,
                int(settings.get("timeout", 5) or 5),
                str(settings.get("base_dn", "")).strip(),
                str(settings.get("user_dn_template", "")).strip(),
                str(settings.get("user_search_filter", "(sAMAccountName={username})")).strip() or "(sAMAccountName={username})",
                str(settings.get("bind_dn", "")).strip(),
                encrypt_secret(str(settings.get("bind_password", ""))),
            ),
        )


def runtime_session_id() -> str:
    sid = str(session.get("runtime_session_id", "")).strip()
    if sid:
        return sid
    sid = secrets.token_hex(16)
    session["runtime_session_id"] = sid
    return sid


def close_runtime_ssh_sessions(runtime_id: str) -> None:
    if not runtime_id:
        return
    with RUNTIME_SSH_LOCK:
        sessions = RUNTIME_SSH_SESSIONS.pop(runtime_id, {})
    for item in sessions.values():
        client = item.get("client")
        try:
            if client:
                client.close()
        except Exception:
            pass


def get_runtime_device_session(runtime_id: str, device_name: str) -> dict[str, Any] | None:
    with RUNTIME_SSH_LOCK:
        return RUNTIME_SSH_SESSIONS.get(runtime_id, {}).get(device_name)


def run_runtime_device_command(runtime_id: str, device: dict[str, Any], creds: dict[str, Any], command: str) -> tuple[str, str]:
    device_name = str(device.get("name", ""))
    ok, message = open_runtime_device_session(runtime_id, device, creds)
    if not ok:
        return "FAIL", message

    runtime = get_runtime_device_session(runtime_id, device_name)
    if runtime is None:
        return "FAIL", "SSH session is not available."

    channel = runtime.get("channel")
    if channel is None:
        return "FAIL", "SSH channel is not available."

    try:
        timeout = max(2, int(creds.get("timeout", 8)))
        commands = split_cli_commands(command)
        if not commands:
            return "FAIL", "No command provided."
        output_parts: list[str] = []
        for cmd in commands:
            channel.send(cmd + "\n")
            text = _read_shell_output(channel, timeout)
            if text:
                output_parts.append(text)
        joined = "\n".join(output_parts).strip()
        return "PASS", joined or "(no output)"
    except Exception as exc:
        with RUNTIME_SSH_LOCK:
            runtime_store = RUNTIME_SSH_SESSIONS.get(runtime_id, {})
            runtime_item = runtime_store.pop(device_name, None)
        client = runtime_item.get("client") if runtime_item else None
        try:
            if client:
                client.close()
        except Exception:
            pass
        return "FAIL", str(exc)
