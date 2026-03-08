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


def default_ip_branches() -> list[str]:
    return ["B701", "B702", "B703", "B704"]


def _ipv4_to_int(ip: str) -> int:
    parts = [int(p) for p in str(ip).split(".")]
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) & 0xFFFFFFFF


def _int_to_ipv4(value: int) -> str:
    n = int(value) & 0xFFFFFFFF
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def _cidr_to_mask(cidr: int) -> str:
    bits = (0xFFFFFFFF << (32 - int(cidr))) & 0xFFFFFFFF
    return _int_to_ipv4(bits)


def _make_ip_rows(network_base: str, cidr: int) -> tuple[str, str, list[dict[str, str]]]:
    base_int = _ipv4_to_int(network_base)
    block_size = 2 ** (32 - int(cidr))
    gateway = _int_to_ipv4(base_int + 1)
    broadcast = _int_to_ipv4(base_int + block_size - 1)
    rows: list[dict[str, str]] = []
    for ip_int in range(base_int + 2, base_int + block_size - 1):
        rows.append({"ip": _int_to_ipv4(ip_int), "hostname": "", "enduser": "", "status": "FREE"})
    return gateway, broadcast, rows


def _seed_branch_state_from_names(branch_names: list[str]) -> list[dict[str, Any]]:
    names = [str(item).strip() for item in branch_names if str(item).strip()]
    if not names:
        names = default_ip_branches()
    base_start = _ipv4_to_int("10.10.10.0")
    cidr = 27
    block_size = 2 ** (32 - cidr)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    seeded: list[dict[str, Any]] = []
    for idx, name in enumerate(names):
        network_base = _int_to_ipv4(base_start + idx * block_size)
        gateway, broadcast, ip_rows = _make_ip_rows(network_base, cidr)
        seeded.append(
            {
                "id": f"b-{idx+1}",
                "name": name,
                "site": "Site",
                "networkBase": network_base,
                "cidr": cidr,
                "subnetMask": _cidr_to_mask(cidr),
                "gateway": gateway,
                "broadcast": broadcast,
                "createdAt": now,
                "updatedAt": now,
                "ipRows": ip_rows,
            }
        )
    return seeded


def load_ip_branch_state() -> list[dict[str, Any]]:
    with db_conn() as conn:
        branch_rows = conn.execute(
            "SELECT branch_name, site, network_base, cidr, subnet_mask, gateway, broadcast, created_at, updated_at FROM ip_branch_details ORDER BY branch_name"
        ).fetchall()
        ip_rows = conn.execute(
            "SELECT branch_name, ip_address, hostname, enduser_name, status FROM ip_branch_ips ORDER BY branch_name, ip_address"
        ).fetchall()

    if not branch_rows:
        seeded = _seed_branch_state_from_names(load_ip_branches())
        save_ip_branch_state(seeded)
        return seeded

    ip_map: dict[str, list[dict[str, str]]] = {}
    for row in ip_rows:
        bname = str(row["branch_name"]).strip()
        ip_map.setdefault(bname, []).append(
            {
                "ip": str(row["ip_address"] or "").strip(),
                "hostname": str(row["hostname"] or "").strip(),
                "enduser": str(row["enduser_name"] or "").strip(),
                "status": str(row["status"] or "FREE").strip() or "FREE",
            }
        )

    state: list[dict[str, Any]] = []
    for idx, row in enumerate(branch_rows, start=1):
        name = str(row["branch_name"] or "").strip()
        cidr = int(row["cidr"] or 27)
        state.append(
            {
                "id": f"b-{idx}",
                "name": name,
                "site": str(row["site"] or "").strip(),
                "networkBase": str(row["network_base"] or "").strip(),
                "cidr": cidr,
                "subnetMask": str(row["subnet_mask"] or "").strip() or _cidr_to_mask(cidr),
                "gateway": str(row["gateway"] or "").strip(),
                "broadcast": str(row["broadcast"] or "").strip(),
                "createdAt": str(row["created_at"] or "").strip(),
                "updatedAt": str(row["updated_at"] or "").strip(),
                "ipRows": ip_map.get(name, []),
            }
        )
    return state


def save_ip_branch_state(branches: list[dict[str, Any]]) -> None:
    normalized_branches: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in branches:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        key = name.lower()
        if not name or key in seen:
            continue
        seen.add(key)
        cidr = int(item.get("cidr", 27) or 27)
        normalized_rows: list[dict[str, str]] = []
        for row in item.get("ipRows", []):
            if not isinstance(row, dict):
                continue
            ip_addr = str(row.get("ip", "")).strip()
            if not ip_addr:
                continue
            normalized_rows.append(
                {
                    "ip": ip_addr,
                    "hostname": str(row.get("hostname", "")).strip(),
                    "enduser": str(row.get("enduser", "")).strip(),
                    "status": str(row.get("status", "FREE")).strip() or "FREE",
                }
            )
        normalized_branches.append(
            {
                "name": name,
                "site": str(item.get("site", "")).strip(),
                "networkBase": str(item.get("networkBase", "")).strip(),
                "cidr": cidr,
                "subnetMask": str(item.get("subnetMask", "")).strip() or _cidr_to_mask(cidr),
                "gateway": str(item.get("gateway", "")).strip(),
                "broadcast": str(item.get("broadcast", "")).strip(),
                "createdAt": str(item.get("createdAt", "")).strip(),
                "updatedAt": str(item.get("updatedAt", "")).strip(),
                "ipRows": normalized_rows,
            }
        )

    with db_conn() as conn:
        conn.execute("DELETE FROM ip_branch_ips")
        conn.execute("DELETE FROM ip_branch_details")
        for branch in normalized_branches:
            conn.execute(
                """
                INSERT INTO ip_branch_details(branch_name, site, network_base, cidr, subnet_mask, gateway, broadcast, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    branch["name"],
                    branch["site"],
                    branch["networkBase"],
                    int(branch["cidr"]),
                    branch["subnetMask"],
                    branch["gateway"],
                    branch["broadcast"],
                    branch["createdAt"],
                    branch["updatedAt"],
                ),
            )
            for row in branch["ipRows"]:
                conn.execute(
                    """
                    INSERT INTO ip_branch_ips(branch_name, ip_address, hostname, enduser_name, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        branch["name"],
                        row["ip"],
                        row["hostname"],
                        row["enduser"],
                        row["status"],
                    ),
                )
    save_ip_branches([item["name"] for item in normalized_branches])
