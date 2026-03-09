from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)


def seed_monitoring_sample_async(device_name: str, ip_address: str, category: str, profile: dict[str, Any], requester: str) -> None:
    def _worker() -> None:
        try:
            effective_settings = monitoring_effective_settings(load_monitoring_settings(), profile)
            seed_sample = poll_device_monitoring_sample(
                {"name": device_name, "host": ip_address, "groups": [category], "port": 22},
                effective_settings,
            )
            save_monitoring_sample(seed_sample)
        except Exception as exc:
            write_audit_log_safe(
                "monitoring_seed_poll_failed",
                details={"device_name": device_name, "ip_address": ip_address, "error": str(exc)},
                requester=requester or "system",
            )

    threading.Thread(target=_worker, name=f"seed-monitor-{device_name}", daemon=True).start()


def sync_ntp_time(server: str, port: int, timeout: int) -> tuple[bool, str, str]:
    if not server:
        return False, "NTP server is required.", ""

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, "Invalid NTP response.", ""

        ntp_seconds = struct.unpack("!I", data[40:44])[0]
        unix_seconds = ntp_seconds - 2208988800
        dt = datetime.fromtimestamp(unix_seconds, timezone.utc)
        return True, f"NTP synchronized with {server}:{port}.", dt.isoformat()
    except OSError as exc:
        return False, f"NTP sync failed: {exc}", ""
    finally:
        sock.close()


def test_ntp_connectivity(server: str, port: int, timeout: int) -> tuple[bool, str]:
    if not server:
        return False, "NTP server is required."

    packet = b"\x1b" + 47 * b"\0"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(48)
        if len(data) < 48:
            return False, f"NTP test failed: invalid response from {server}:{port}."
        return True, f"NTP test success: connected to {server}:{port}."
    except OSError as exc:
        return False, f"NTP test failed: {exc}"
    finally:
        sock.close()


def run_ping_for_host(host: str, count: int = 5) -> str:
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return f"PING {host}\n.....\nPing command error: {exc}\n"

    output = result.stdout or ""
    lines = output.splitlines()
    rendered: list[str] = [f"PING {host}"]
    marks: list[str] = []

    for line in lines:
        lower = line.lower()
        if "ttl=" in lower and ("time=" in lower or "time<" in lower):
            marks.append("!")
            bytes_match = re.search(r"bytes[=< ](\d+)", lower)
            time_match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", lower)
            ttl_match = re.search(r"ttl[=< ](\d+)", lower)
            bytes_val = bytes_match.group(1) if bytes_match else "32"
            ttl_val = ttl_match.group(1) if ttl_match else "64"
            if time_match:
                time_fragment = f"time={time_match.group(1)}ms"
            elif "time<" in lower:
                time_fragment = "time<1ms"
            else:
                time_fragment = "time<1ms"
            rendered.append(f"Reply from {host}: bytes={bytes_val} {time_fragment} TTL={ttl_val}")

    if not marks:
        marks = ["."] * count
    elif len(marks) < count:
        marks.extend(["."] * (count - len(marks)))

    rendered.insert(1, "".join(marks[:count]))
    return "\n".join(rendered) + "\n"
