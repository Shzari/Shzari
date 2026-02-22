#!/usr/bin/env python3
"""Daily network-engineering automation utility.

Features
- ICMP reachability checks (ping)
- DNS forward lookup checks
- TCP port reachability checks
- Parallel execution for faster daily runs
- CSV + JSON report output

Usage
  python3 neteng_daily_automation.py --config devices.json --output-dir reports

Config example (JSON)
[
  {
    "name": "core-sw-01",
    "host": "10.0.0.1",
    "dns_name": "core-sw-01.example.com",
    "ports": [22, 443]
  }
]
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class CheckResult:
    device: str
    host: str
    check: str
    status: str
    details: str
    latency_ms: float | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automate common daily network checks for multiple devices."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to JSON config file with device definitions.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON/CSV reports are written (default: reports).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent worker threads (default: 10).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds for ping and socket checks (default: 2.0).",
    )
    return parser.parse_args()


def load_config(config_path: str) -> list[dict[str, Any]]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Config must be a JSON array of device objects.")
    return data


def ping_host(host: str, timeout: float) -> tuple[bool, str, float | None]:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(timeout + 1, 2),
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        latency = extract_latency_ms(output)
        if proc.returncode == 0:
            return True, "ping succeeded", latency
        return False, output.strip()[:250] or "ping failed", latency
    except Exception as exc:
        return False, f"ping error: {exc}", None


def extract_latency_ms(ping_output: str) -> float | None:
    markers = ["time=", "time<", "Average = "]
    for marker in markers:
        idx = ping_output.find(marker)
        if idx == -1:
            continue
        snippet = ping_output[idx : idx + 30]
        digits = []
        for ch in snippet:
            if ch.isdigit() or ch == ".":
                digits.append(ch)
            elif digits:
                break
        if digits:
            try:
                return float("".join(digits))
            except ValueError:
                pass
    return None


def dns_lookup(hostname: str) -> tuple[bool, str]:
    try:
        ip = socket.gethostbyname(hostname)
        return True, f"resolved to {ip}"
    except socket.gaierror as exc:
        return False, f"DNS lookup failed: {exc}"


def check_tcp_port(host: str, port: int, timeout: float) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, int(port)))
        if code == 0:
            return True, f"TCP {port} reachable"
        return False, f"TCP {port} closed/unreachable (code {code})"
    except Exception as exc:
        return False, f"TCP {port} error: {exc}"
    finally:
        sock.close()


def run_checks_for_device(device: dict[str, Any], timeout: float) -> list[CheckResult]:
    name = str(device.get("name") or device.get("host") or "unknown")
    host = str(device.get("host") or "")
    if not host:
        return [
            CheckResult(
                device=name,
                host=host,
                check="input",
                status="FAIL",
                details="missing required field 'host'",
            )
        ]

    results: list[CheckResult] = []

    ping_ok, ping_detail, latency = ping_host(host, timeout)
    results.append(
        CheckResult(
            device=name,
            host=host,
            check="ping",
            status="PASS" if ping_ok else "FAIL",
            details=ping_detail,
            latency_ms=latency,
        )
    )

    dns_name = device.get("dns_name")
    if dns_name:
        dns_ok, dns_detail = dns_lookup(str(dns_name))
        results.append(
            CheckResult(
                device=name,
                host=host,
                check=f"dns:{dns_name}",
                status="PASS" if dns_ok else "FAIL",
                details=dns_detail,
            )
        )

    for port in device.get("ports", []):
        ok, detail = check_tcp_port(host, int(port), timeout)
        results.append(
            CheckResult(
                device=name,
                host=host,
                check=f"tcp:{port}",
                status="PASS" if ok else "FAIL",
                details=detail,
            )
        )

    return results


def write_reports(results: list[CheckResult], output_dir: str) -> tuple[Path, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    json_path = out / f"neteng_report_{stamp}.json"
    csv_path = out / f"neteng_report_{stamp}.csv"

    json_payload = [
        {
            "device": r.device,
            "host": r.host,
            "check": r.check,
            "status": r.status,
            "details": r.details,
            "latency_ms": r.latency_ms,
        }
        for r in results
    ]

    with json_path.open("w", encoding="utf-8") as jf:
        json.dump(json_payload, jf, indent=2)

    with csv_path.open("w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(
            cf,
            fieldnames=["device", "host", "check", "status", "details", "latency_ms"],
        )
        writer.writeheader()
        writer.writerows(json_payload)

    return json_path, csv_path


def summarize(results: list[CheckResult]) -> str:
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    failed = total - passed
    return f"Completed {total} checks: PASS={passed}, FAIL={failed}"


def main() -> int:
    args = parse_args()
    devices = load_config(args.config)
    all_results: list[CheckResult] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [
            executor.submit(run_checks_for_device, device, args.timeout)
            for device in devices
        ]
        for future in as_completed(futures):
            all_results.extend(future.result())

    json_path, csv_path = write_reports(all_results, args.output_dir)
    print(summarize(all_results))
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")

    return 0 if all(r.status == "PASS" for r in all_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
