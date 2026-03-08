from __future__ import annotations
# ruff: noqa: F821

from typing import Any

from app.compat import legacy_runtime as _legacy

for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)

# Fallback for partial legacy initialization paths.
if "db_conn" not in globals():
    from app.services.db_service import db_conn


def _monitoring_device_lookup(device_name: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    name = str(device_name or "").strip()
    key = name.lower()
    profiles = load_monitoring_device_profiles()
    profile = dict(profiles.get(key, {}))
    all_devices = load_devices()
    base_device = next((item for item in all_devices if str(item.get("name", "")).strip().lower() == key), {})
    host = str(profile.get("host", "")).strip() or str(base_device.get("host", "")).strip()
    return base_device, profile, host


def _monitoring_effective_category(device_name: str) -> str:
    base_device, profile, _ = _monitoring_device_lookup(device_name)
    profile_category = str(profile.get("category", "")).strip()
    if profile_category:
        return profile_category
    groups = base_device.get("groups", []) if isinstance(base_device, dict) else []
    if isinstance(groups, list) and groups:
        return str(groups[0]).strip()
    return ""


def _monitoring_pull_ssh_creds(profile: dict[str, Any], account_username: str, auth_mode: str) -> dict[str, Any]:
    profile_username = str(profile.get("ssh_username", "")).strip()
    profile_password = str(profile.get("ssh_password", ""))
    profile_enable = str(profile.get("enable_password", ""))
    if profile_username and profile_password:
        return {
            "username": profile_username,
            "password": profile_password,
            "enable_password": profile_enable,
        }
    stored = load_user_device_creds(account_username, auth_mode)
    return {
        "username": str(stored.get("username", "")).strip(),
        "password": str(stored.get("password", "")),
        "enable_password": str(stored.get("enable_password", "")),
    }


def parse_monitoring_metrics(metrics_text: str) -> set[str]:
    allowed = {"cpu", "memory", "interfaces", "sla"}
    items = [str(item).strip().lower() for item in str(metrics_text or "").split(",")]
    selected = {item for item in items if item in allowed}
    return selected or {"cpu", "memory", "interfaces", "sla"}


def _cap_percent(value: Any) -> float | None:
    try:
        number = float(value)
    except Exception:
        return None
    if not (number == number):  # NaN
        return None
    if number == float("inf") or number == float("-inf"):
        return None
    return max(0.0, min(100.0, number))


def ping_host_status(host: str, timeout_seconds: int = 2) -> tuple[str, float | None]:
    addr = str(host or "").strip()
    if not addr:
        return "down", None
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(max(500, timeout_seconds * 1000)), addr]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_seconds)), addr]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError:
        return "down", None
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    latency: float | None = None
    match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", output, flags=re.IGNORECASE)
    if match:
        try:
            latency = float(match.group(1))
        except Exception:
            latency = None
    return ("up" if result.returncode == 0 else "down"), latency


def winrm_collect_metrics(host: str, settings: dict[str, Any], timeout_seconds: int = 8) -> tuple[dict[str, Any], list[str]]:
    if not WINRM_AVAILABLE or winrm is None:
        return {}, ["pywinrm_not_installed"]
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    if not username or not password:
        return {}, ["winrm_credentials_missing"]
    try:
        winrm_port = max(1, min(65535, int(settings.get("winrm_port", 5985) or 5985)))
    except Exception:
        winrm_port = 5985
    auth = str(settings.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
    if auth not in {"ntlm", "kerberos", "basic", "credssp"}:
        auth = "ntlm"
    scheme = "https" if winrm_port == 5986 else "http"
    endpoint = f"{scheme}://{host}:{winrm_port}/wsman"
    errors: list[str] = []
    metrics: dict[str, Any] = {
        "cpu_percent": None,
        "memory_percent": None,
        "uptime_seconds": None,
        "last_boot": "",
        "network_rx_mbps": None,
        "network_tx_mbps": None,
        "windows_caption": "",
        "windows_version": "",
        "windows_build": "",
        "windows_arch": "",
        "computer_name": "",
        "computer_model": "",
        "domain": "",
        "total_memory_gb": None,
        "free_memory_gb": None,
        "disk_usage": [],
        "interface_utilization": [],
    }

    ps_preamble = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"

    def _parse_num(text: str) -> float | None:
        raw = str(text or "").strip()
        if not raw:
            return None
        cleaned = raw.replace("%", "").strip()
        candidate = raw.replace(",", ".")
        try:
            return float(candidate)
        except Exception:
            try:
                candidate = cleaned.replace(",", ".")
                return float(candidate)
            except Exception:
                match = re.search(r"[-+]?\d+(?:[.,]\d+)?", cleaned)
                if not match:
                    return None
                token = match.group(0).replace(",", ".")
                try:
                    return float(token)
                except Exception:
                    return None

    def _is_ignorable_ps_stderr(text: str) -> bool:
        raw = str(text or "").strip().lower()
        if not raw:
            return True
        return "preparing modules for first use" in raw and "clixml" in raw

    def _trim_error(text: str, max_len: int = 700) -> str:
        raw = str(text or "").strip()
        if len(raw) <= max_len:
            return raw
        return raw[:max_len] + "..."

    try:
        session = winrm.Session(target=endpoint, auth=(username, password), transport=auth)
    except Exception as exc:
        return metrics, [f"session_init:{exc}"]

    try:
        cpu_cmd = (
            f"{ps_preamble}"
            "$cpu='';"
            "try{$cpu=((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{"
            "try{$cpu=((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{}"
            "};"
            "if($cpu -ne '' -and $cpu -ne $null){[math]::Round([double]$cpu,2)}else{''}"
        )
        cpu_result = session.run_ps(cpu_cmd)
        cpu_status = int(getattr(cpu_result, "status_code", 1) or 1)
        cpu_text = (cpu_result.std_out or b"").decode(errors="ignore").strip()
        if cpu_text:
            cpu_num = _parse_num(cpu_text)
            if cpu_num is not None:
                metrics["cpu_percent"] = _cap_percent(cpu_num)
        if metrics.get("cpu_percent") is None and cpu_status != 0:
            stderr = (cpu_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"cpu:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"cpu:{exc}")

    try:
        mem_cmd = (
            f"{ps_preamble}"
            "$os=$null;"
            "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
            "if($os -and $os.TotalVisibleMemorySize -gt 0){"
            "$used=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
            "[math]::Round(($used*100)/[double]$os.TotalVisibleMemorySize,2)"
            "}else{''}"
        )
        mem_result = session.run_ps(mem_cmd)
        mem_status = int(getattr(mem_result, "status_code", 1) or 1)
        mem_text = (mem_result.std_out or b"").decode(errors="ignore").strip()
        if mem_text:
            mem_num = _parse_num(mem_text)
            if mem_num is not None:
                metrics["memory_percent"] = mem_num
        if metrics.get("memory_percent") is None and mem_status != 0:
            stderr = (mem_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"memory:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"memory:{exc}")

    try:
        extra_cmd = (
            f"{ps_preamble}"
            "$os=$null;"
            "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
            "$boot='';$uptime=0;"
            "if($os){$boot=$os.LastBootUpTime; if($boot){$uptime=(New-TimeSpan -Start $boot -End (Get-Date)).TotalSeconds}};"
            "$boot_iso=''; if($boot){$boot_iso=([DateTime]$boot).ToString('o')};"
            "$caption='';$version='';$build='';$arch='';$hostn='';$domain='';$model='';$totalMemGb=$null;$freeMemGb=$null;"
            "if($os){"
            "$caption=[string]$os.Caption;"
            "$version=[string]$os.Version;"
            "$build=[string]$os.BuildNumber;"
            "$arch=[string]$os.OSArchitecture;"
            "if($os.TotalVisibleMemorySize -gt 0){$totalMemGb=[Math]::Round(([double]$os.TotalVisibleMemorySize/1024/1024),2)};"
            "if($os.FreePhysicalMemory -ge 0){$freeMemGb=[Math]::Round(([double]$os.FreePhysicalMemory/1024/1024),2)}"
            "};"
            "$hostn=[string]$env:COMPUTERNAME;"
            "$cs=$null; try{$cs=Get-CimInstance Win32_ComputerSystem}catch{try{$cs=Get-WmiObject Win32_ComputerSystem}catch{}};"
            "if($cs){$domain=[string]$cs.Domain; $model=[string]$cs.Model};"
            "$mem=0;"
            "if($os -and $os.TotalVisibleMemorySize -gt 0){"
            "$usedMem=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
            "$mem=[math]::Round(($usedMem*100)/[double]$os.TotalVisibleMemorySize,2)"
            "};"
            "$rx=0;$tx=0;"
            "try{$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{"
            "try{$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{}"
            "};"
            "$d=@();"
            "try{$d=Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object @{N='label';E={$_.DeviceID}}, @{N='size';E={[double]$_.Size}}, @{N='free';E={[double]$_.FreeSpace}}}catch{"
            "try{$d=Get-WmiObject Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object @{N='label';E={$_.DeviceID}}, @{N='size';E={[double]$_.Size}}, @{N='free';E={[double]$_.FreeSpace}}}catch{}"
            "};"
            "$payload=[PSCustomObject]@{"
            "last_boot=$boot_iso;"
            "uptime_seconds=[int][Math]::Round([double]$uptime,0);"
            "windows_caption=$caption;"
            "windows_version=$version;"
            "windows_build=$build;"
            "windows_arch=$arch;"
            "computer_name=$hostn;"
            "computer_model=$model;"
            "domain=$domain;"
            "total_memory_gb=$totalMemGb;"
            "free_memory_gb=$freeMemGb;"
            "memory_percent=[Math]::Round([double]$mem,2);"
            "network_rx_mbps=[Math]::Round(([double]$rx*8/1000000),2);"
            "network_tx_mbps=[Math]::Round(([double]$tx*8/1000000),2);"
            "disks=$d"
            "};"
            "$payload|ConvertTo-Json -Depth 5 -Compress"
        )
        extra_result = session.run_ps(extra_cmd)
        extra_status = int(getattr(extra_result, "status_code", 1) or 1)
        extra_text = (extra_result.std_out or b"").decode(errors="ignore").strip()
        parsed_ok = False
        if extra_text:
            try:
                parsed = json.loads(extra_text)
            except Exception:
                parsed = {}
            if isinstance(parsed, dict):
                parsed_ok = True
                metrics["last_boot"] = str(parsed.get("last_boot", "")).strip()
                metrics["uptime_seconds"] = parsed.get("uptime_seconds")
                metrics["windows_caption"] = str(parsed.get("windows_caption", "")).strip()
                metrics["windows_version"] = str(parsed.get("windows_version", "")).strip()
                metrics["windows_build"] = str(parsed.get("windows_build", "")).strip()
                metrics["windows_arch"] = str(parsed.get("windows_arch", "")).strip()
                metrics["computer_name"] = str(parsed.get("computer_name", "")).strip()
                metrics["computer_model"] = str(parsed.get("computer_model", "")).strip()
                metrics["domain"] = str(parsed.get("domain", "")).strip()
                metrics["total_memory_gb"] = parsed.get("total_memory_gb")
                metrics["free_memory_gb"] = parsed.get("free_memory_gb")
                if metrics.get("memory_percent") is None:
                    mem_extra = _parse_num(str(parsed.get("memory_percent", "")))
                    if mem_extra is not None:
                        metrics["memory_percent"] = mem_extra
                metrics["network_rx_mbps"] = parsed.get("network_rx_mbps")
                metrics["network_tx_mbps"] = parsed.get("network_tx_mbps")
                raw_disks = parsed.get("disks", [])
                disks = raw_disks if isinstance(raw_disks, list) else ([raw_disks] if isinstance(raw_disks, dict) else [])
                out_disks: list[dict[str, Any]] = []
                for d in disks:
                    if not isinstance(d, dict):
                        continue
                    label = str(d.get("label", "")).strip()
                    try:
                        size = float(d.get("size", 0) or 0)
                        free = float(d.get("free", 0) or 0)
                    except Exception:
                        size = 0.0
                        free = 0.0
                    used_pct = None
                    if size > 0:
                        used_pct = max(0.0, min(100.0, ((size - free) * 100.0) / size))
                    out_disks.append(
                        {
                            "label": label or "-",
                            "used_percent": used_pct,
                            "free_gb": round(max(0.0, free) / (1024.0**3), 2),
                        }
                    )
                metrics["disk_usage"] = out_disks
        if not parsed_ok and extra_status != 0:
            stderr = (extra_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"extras:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"extras:{exc}")

    try:
        iface_cmd = (
            f"{ps_preamble}"
            "$rows=@();"
            "try{"
            "$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface;"
            "if(-not $n){$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface};"
            "foreach($i in $n){"
            "$name=[string]$i.Name;"
            "if(-not $name){continue};"
            "$bw=[double]$i.CurrentBandwidth;"
            "$tx=0;$rx=0;"
            "if($bw -gt 0){"
            "$tx=[Math]::Round(([double]$i.BytesSentPersec*8*100)/$bw,2);"
            "$rx=[Math]::Round(([double]$i.BytesReceivedPersec*8*100)/$bw,2)"
            "};"
            "if($tx -lt 0){$tx=0}; if($tx -gt 100){$tx=100};"
            "if($rx -lt 0){$rx=0}; if($rx -gt 100){$rx=100};"
            "$rows += [PSCustomObject]@{interface=$name;status='up';description='';tx_percent=$tx;rx_percent=$rx}"
            "}"
            "}catch{};"
            "$rows|ConvertTo-Json -Depth 4 -Compress"
        )
        iface_result = session.run_ps(iface_cmd)
        iface_status = int(getattr(iface_result, "status_code", 1) or 1)
        iface_text = (iface_result.std_out or b"").decode(errors="ignore").strip()
        parsed_ifaces: list[dict[str, Any]] = []
        if iface_text:
            try:
                iface_obj = json.loads(iface_text)
            except Exception:
                iface_obj = []
            iface_rows = iface_obj if isinstance(iface_obj, list) else ([iface_obj] if isinstance(iface_obj, dict) else [])
            for item in iface_rows:
                if not isinstance(item, dict):
                    continue
                iface_name = str(item.get("interface", "")).strip()
                if not iface_name:
                    continue
                tx_val = _parse_num(str(item.get("tx_percent", "")))
                rx_val = _parse_num(str(item.get("rx_percent", "")))
                tx_pct = max(0.0, min(100.0, float(tx_val))) if tx_val is not None else None
                rx_pct = max(0.0, min(100.0, float(rx_val))) if rx_val is not None else None
                parsed_ifaces.append(
                    {
                        "interface": iface_name,
                        "description": str(item.get("description", "")).strip(),
                        "status": str(item.get("status", "up") or "up").strip().lower(),
                        "tx_percent": tx_pct,
                        "rx_percent": rx_pct,
                    }
                )
        if parsed_ifaces:
            metrics["interface_utilization"] = parsed_ifaces
        elif iface_status != 0:
            stderr = (iface_result.std_err or b"").decode(errors="ignore").strip()
            if not _is_ignorable_ps_stderr(stderr):
                errors.append(f"interfaces:{_trim_error(stderr or 'command_failed')}")
    except Exception as exc:
        errors.append(f"interfaces:{exc}")

    return metrics, errors


def winrm_collect_live_gauges(host: str, settings: dict[str, Any], timeout_seconds: int = 6) -> tuple[dict[str, Any], list[str]]:
    if not WINRM_AVAILABLE or winrm is None:
        return {}, ["pywinrm_not_installed"]
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    if not username or not password:
        return {}, ["winrm_credentials_missing"]
    try:
        winrm_port = max(1, min(65535, int(settings.get("winrm_port", 5985) or 5985)))
    except Exception:
        winrm_port = 5985
    auth = str(settings.get("winrm_auth", "ntlm")).strip().lower() or "ntlm"
    if auth not in {"ntlm", "kerberos", "basic", "credssp"}:
        auth = "ntlm"
    scheme = "https" if winrm_port == 5986 else "http"
    endpoint = f"{scheme}://{host}:{winrm_port}/wsman"
    metrics: dict[str, Any] = {
        "cpu_percent": None,
        "memory_percent": None,
        "uptime_seconds": None,
        "last_boot": "",
        "network_rx_mbps": None,
        "network_tx_mbps": None,
        "windows_caption": "",
        "windows_version": "",
        "windows_build": "",
        "windows_arch": "",
        "computer_name": "",
        "computer_model": "",
        "domain": "",
        "total_memory_gb": None,
        "free_memory_gb": None,
    }
    errors: list[str] = []
    try:
        session = winrm.Session(target=endpoint, auth=(username, password), transport=auth)
    except Exception as exc:
        return metrics, [f"session_init:{exc}"]

    ps_cmd = (
        "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"
        "$cpu='';"
        "try{$cpu=((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{"
        "try{$cpu=((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)}catch{}"
        "};"
        "$os=$null;"
        "try{$os=Get-CimInstance Win32_OperatingSystem}catch{try{$os=Get-WmiObject Win32_OperatingSystem}catch{}};"
        "$boot='';$uptime=0;$mem=$null;$caption='';$version='';$build='';$arch='';$totalMemGb=$null;$freeMemGb=$null;"
        "if($os){"
        "$boot=$os.LastBootUpTime;"
        "if($boot){$uptime=(New-TimeSpan -Start $boot -End (Get-Date)).TotalSeconds};"
        "$caption=[string]$os.Caption;$version=[string]$os.Version;$build=[string]$os.BuildNumber;$arch=[string]$os.OSArchitecture;"
        "if($os.TotalVisibleMemorySize -gt 0){"
        "$usedMem=([double]$os.TotalVisibleMemorySize-[double]$os.FreePhysicalMemory);"
        "$mem=[math]::Round(($usedMem*100)/[double]$os.TotalVisibleMemorySize,2);"
        "$totalMemGb=[Math]::Round(([double]$os.TotalVisibleMemorySize/1024/1024),2)"
        "};"
        "if($os.FreePhysicalMemory -ge 0){$freeMemGb=[Math]::Round(([double]$os.FreePhysicalMemory/1024/1024),2)}"
        "};"
        "$boot_iso=''; if($boot){$boot_iso=([DateTime]$boot).ToString('o')};"
        "$hostn=[string]$env:COMPUTERNAME;$domain='';$model='';"
        "$cs=$null; try{$cs=Get-CimInstance Win32_ComputerSystem}catch{try{$cs=Get-WmiObject Win32_ComputerSystem}catch{}};"
        "if($cs){$domain=[string]$cs.Domain; $model=[string]$cs.Model};"
        "$rx=$null;$tx=$null;"
        "try{$n=Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{"
        "try{$n=Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkInterface; if($n){$rx=[double](($n | Measure-Object -Property BytesReceivedPersec -Sum).Sum); $tx=[double](($n | Measure-Object -Property BytesSentPersec -Sum).Sum)}}catch{}"
        "};"
        "$cpuVal=$null; if($cpu -ne '' -and $cpu -ne $null){$cpuVal=[math]::Round([double]$cpu,2)};"
        "$memVal=$null; if($mem -ne '' -and $mem -ne $null){$memVal=[Math]::Round([double]$mem,2)};"
        "$rxVal=$null; if($rx -ne $null){$rxVal=[Math]::Round(([double]$rx*8/1000000),2)};"
        "$txVal=$null; if($tx -ne $null){$txVal=[Math]::Round(([double]$tx*8/1000000),2)};"
        "$payload=[PSCustomObject]@{"
        "cpu_percent=$cpuVal;"
        "memory_percent=$memVal;"
        "last_boot=$boot_iso;"
        "uptime_seconds=[int][Math]::Round([double]$uptime,0);"
        "windows_caption=$caption;windows_version=$version;windows_build=$build;windows_arch=$arch;"
        "computer_name=$hostn;computer_model=$model;domain=$domain;"
        "total_memory_gb=$totalMemGb;free_memory_gb=$freeMemGb;"
        "network_rx_mbps=$rxVal;"
        "network_tx_mbps=$txVal"
        "};"
        "$payload|ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        result = session.run_ps(ps_cmd)
        status = int(getattr(result, "status_code", 1) or 1)
        out_text = (result.std_out or b"").decode(errors="ignore").strip()
        if out_text:
            try:
                parsed = json.loads(out_text)
            except Exception:
                parsed = {}
            if isinstance(parsed, dict):
                metrics["cpu_percent"] = _cap_percent(parsed.get("cpu_percent"))
                metrics["memory_percent"] = _cap_percent(parsed.get("memory_percent"))
                metrics["last_boot"] = str(parsed.get("last_boot", "")).strip()
                metrics["uptime_seconds"] = parsed.get("uptime_seconds")
                metrics["windows_caption"] = str(parsed.get("windows_caption", "")).strip()
                metrics["windows_version"] = str(parsed.get("windows_version", "")).strip()
                metrics["windows_build"] = str(parsed.get("windows_build", "")).strip()
                metrics["windows_arch"] = str(parsed.get("windows_arch", "")).strip()
                metrics["computer_name"] = str(parsed.get("computer_name", "")).strip()
                metrics["computer_model"] = str(parsed.get("computer_model", "")).strip()
                metrics["domain"] = str(parsed.get("domain", "")).strip()
                metrics["total_memory_gb"] = parsed.get("total_memory_gb")
                metrics["free_memory_gb"] = parsed.get("free_memory_gb")
                metrics["network_rx_mbps"] = parsed.get("network_rx_mbps")
                metrics["network_tx_mbps"] = parsed.get("network_tx_mbps")
        if status != 0 and not out_text:
            err_text = (result.std_err or b"").decode(errors="ignore").strip()
            if err_text:
                errors.append(f"live:{err_text[:700]}")
    except Exception as exc:
        errors.append(f"live:{exc}")
    return metrics, errors


def _snmp_auth_data_from_settings(settings: dict[str, Any]) -> tuple[Any | None, str]:
    mode = str(settings.get("collection_mode", "snmp_v2")).strip().lower()
    username = str(settings.get("username", "")).strip()
    password = str(settings.get("password", "")).strip()
    token = str(settings.get("token", "")).strip()
    if mode in {"snmp", "snmp_v2"}:
        community = token or password or "public"
        return CommunityData(community, mpModel=1), ""
    if mode == "snmp_v3":
        if not username:
            return None, "snmp_v3_username_missing"
        auth_name = str(settings.get("snmpv3_auth_protocol", "sha")).strip().lower() or "sha"
        priv_name = str(settings.get("snmpv3_priv_protocol", "aes128")).strip().lower() or "aes128"
        auth_proto_map = {
            "none": usmNoAuthProtocol,
            "md5": usmHMACMD5AuthProtocol or usmHMACSHAAuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha1": usmHMACSHAAuthProtocol,
            "sha224": usmHMAC128SHA224AuthProtocol or usmHMACSHAAuthProtocol,
            "sha256": usmHMAC192SHA256AuthProtocol or usmHMACSHAAuthProtocol,
            "sha384": usmHMAC256SHA384AuthProtocol or usmHMACSHAAuthProtocol,
            "sha512": usmHMAC384SHA512AuthProtocol or usmHMACSHAAuthProtocol,
        }
        priv_proto_map = {
            "none": usmNoPrivProtocol,
            "des": usmDESPrivProtocol or usmNoPrivProtocol,
            "3des": usm3DESEDEPrivProtocol or usmDESPrivProtocol or usmNoPrivProtocol,
            "aes": usmAesCfb128Protocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol or usmAesCfb128Protocol,
            "aes256": usmAesCfb256Protocol or usmAesCfb128Protocol,
        }
        auth_proto = auth_proto_map.get(auth_name, usmHMACSHAAuthProtocol)
        priv_proto = priv_proto_map.get(priv_name, usmAesCfb128Protocol)
        if not password:
            return UsmUserData(username, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol), ""
        if priv_name != "none" and not token:
            return None, "snmp_v3_priv_password_missing"
        if password and token:
            return (
                UsmUserData(
                    username,
                    password,
                    token,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto,
                ),
                "",
            )
        if password:
            return (
                UsmUserData(
                    username,
                    password,
                    authProtocol=auth_proto,
                    privProtocol=usmNoPrivProtocol,
                ),
                "",
            )
        return UsmUserData(username, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol), ""
    return None, "collection_mode_not_snmp"


def snmp_get_value(host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3) -> tuple[Any | None, str]:
    if not PYSNMP_AVAILABLE:
        return None, "pysnmp_not_installed"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return None, auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    try:
        iterator = getCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication:
            return None, str(error_indication)
        if error_status:
            return None, str(error_status.prettyPrint())
        if not var_binds:
            return None, "empty_response"
        value = None
        try:
            value = var_binds[0][1]
        except Exception:
            try:
                first = tuple(var_binds[0])
                if len(first) >= 2:
                    value = first[1]
            except Exception:
                value = None
        if value is None:
            return None, "empty_response"
        return value, ""
    except Exception as exc:
        return None, str(exc)


def snmp_walk_values(
    host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3, max_rows: int = 1024
) -> tuple[list[Any], str]:
    if not PYSNMP_AVAILABLE:
        return [], "pysnmp_not_installed"
    if nextCmd is None:
        return [], "pysnmp_nextcmd_unavailable"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return [], auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    values: list[Any] = []
    try:
        iterator = nextCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                return values, str(error_indication)
            if error_status:
                return values, str(error_status.prettyPrint())
            for var_bind in var_binds or []:
                value_obj = None
                try:
                    value_obj = var_bind[1]
                except Exception:
                    try:
                        pair = tuple(var_bind)
                        if len(pair) >= 2:
                            value_obj = pair[1]
                    except Exception:
                        value_obj = None
                if value_obj is None:
                    continue
                values.append(value_obj)
                if len(values) >= max(1, int(max_rows)):
                    return values, ""
        return values, ""
    except Exception as exc:
        return values, str(exc)


def snmp_walk_indexed_values(
    host: str, settings: dict[str, Any], oid: str, timeout_seconds: int = 3, max_rows: int = 4096
) -> tuple[dict[int, Any], str]:
    if not PYSNMP_AVAILABLE:
        return {}, "pysnmp_not_installed"
    if nextCmd is None:
        return {}, "pysnmp_nextcmd_unavailable"
    auth_data, auth_err = _snmp_auth_data_from_settings(settings)
    if auth_err:
        return {}, auth_err

    try:
        snmp_port = max(1, min(65535, int(settings.get("snmp_port", 161) or 161)))
    except Exception:
        snmp_port = 161
    out: dict[int, Any] = {}
    prefix = f"{str(oid).strip('.')}."
    try:
        iterator = nextCmd(
            SnmpEngine(),
            auth_data,
            UdpTransportTarget((str(host), snmp_port), timeout=max(1, timeout_seconds), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        )
        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                return out, str(error_indication)
            if error_status:
                return out, str(error_status.prettyPrint())
            for var_bind in var_binds or []:
                name_obj = None
                value_obj = None
                try:
                    name_obj = var_bind[0]
                    value_obj = var_bind[1]
                except Exception:
                    try:
                        pair = tuple(var_bind)
                        if len(pair) >= 2:
                            name_obj = pair[0]
                            value_obj = pair[1]
                    except Exception:
                        name_obj = None
                        value_obj = None
                if name_obj is None:
                    continue
                oid_text = str(name_obj or "").strip()
                if not oid_text.startswith(prefix):
                    continue
                idx_text = oid_text[len(prefix) :].strip()
                if not idx_text.isdigit():
                    continue
                idx = int(idx_text)
                out[idx] = value_obj
                if len(out) >= max(1, int(max_rows)):
                    return out, ""
        return out, ""
    except Exception as exc:
        return out, str(exc)


def snmp_collect_interface_utilization(
    host: str, settings: dict[str, Any], selected_interfaces: set[str] | None = None, sample_seconds: float = 1.0
) -> list[dict[str, Any]]:
    selected_exact: set[str] = set()
    selected_normalized: set[str] = set()
    for item in selected_interfaces or set():
        text = str(item).strip()
        if not text:
            continue
        selected_exact.add(text.lower())
        normalized = _normalize_interface_key(text)
        if normalized:
            selected_normalized.add(normalized)
    names, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.1", max_rows=4096)
    if not names:
        names, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.2", max_rows=4096)
    if not names:
        return []
    alias, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.18", max_rows=4096)
    oper, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
    hi_speed, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.15", max_rows=4096)  # Mbps
    speed, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.5", max_rows=4096)  # bps

    in_oct_1, in_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.6", max_rows=4096)
    out_oct_1, out_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.10", max_rows=4096)
    use_32 = False
    if not in_oct_1 or not out_oct_1 or in_err or out_err:
        in_oct_1, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.10", max_rows=4096)
        out_oct_1, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.16", max_rows=4096)
        use_32 = True
    if not in_oct_1 or not out_oct_1:
        return []

    start_ts = time.time()
    time.sleep(max(0.2, float(sample_seconds)))
    in_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.6", max_rows=4096)[0]
    out_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.10", max_rows=4096)[0]
    if not in_oct_2 or not out_oct_2:
        in_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.10", max_rows=4096)[0]
        out_oct_2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.16", max_rows=4096)[0]
        use_32 = True
    end_ts = time.time()
    delta_t = max(0.2, end_ts - start_ts)

    max_counter = float(2**32 if use_32 else 2**64)
    status_map = {1: "up", 2: "down"}
    rows: list[dict[str, Any]] = []
    for idx in sorted(names.keys()):
        if_name = str(names.get(idx, "")).strip()
        if not if_name:
            continue
        if selected_exact or selected_normalized:
            normalized_if_name = _normalize_interface_key(if_name)
            if if_name.lower() not in selected_exact and normalized_if_name not in selected_normalized:
                continue
        if_desc = str(alias.get(idx, "")).strip()
        try:
            oper_code = int(oper.get(idx, 0) or 0)
        except Exception:
            oper_code = 0
        status = status_map.get(oper_code, "unknown")
        try:
            in1 = float(int(in_oct_1.get(idx, 0) or 0))
            in2 = float(int(in_oct_2.get(idx, in1) or in1))
            out1 = float(int(out_oct_1.get(idx, 0) or 0))
            out2 = float(int(out_oct_2.get(idx, out1) or out1))
        except Exception:
            in1 = in2 = out1 = out2 = 0.0
        din = in2 - in1
        dout = out2 - out1
        if din < 0:
            din += max_counter
        if dout < 0:
            dout += max_counter
        in_bps = (din * 8.0) / delta_t
        out_bps = (dout * 8.0) / delta_t
        speed_bps = 0.0
        try:
            hs = float(int(hi_speed.get(idx, 0) or 0))
            if hs > 0:
                speed_bps = hs * 1_000_000.0
            else:
                speed_bps = float(int(speed.get(idx, 0) or 0))
        except Exception:
            speed_bps = 0.0
        tx_pct: float | None = None
        rx_pct: float | None = None
        if speed_bps > 0:
            tx_pct = max(0.0, min(100.0, (out_bps / speed_bps) * 100.0))
            rx_pct = max(0.0, min(100.0, (in_bps / speed_bps) * 100.0))
        rows.append(
            {
                "status": status,
                "interface": if_name,
                "description": if_desc,
                "tx_percent": tx_pct,
                "rx_percent": rx_pct,
            }
        )
    return rows


def snmp_collect_memory_percent(host: str, settings: dict[str, Any]) -> tuple[float | None, list[str]]:
    errors: list[str] = []

    def _to_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            return float(int(value))
        except Exception:
            try:
                return float(str(value).strip())
            except Exception:
                return None

    # Strategy 1: Cisco memory pool MIB (works for many Cisco network devices).
    used_values, used_err = snmp_walk_values(host, settings, "1.3.6.1.4.1.9.9.48.1.1.1.5", max_rows=256)
    free_values, free_err = snmp_walk_values(host, settings, "1.3.6.1.4.1.9.9.48.1.1.1.6", max_rows=256)
    if not used_err and not free_err and used_values and free_values:
        try:
            total_used = float(sum(int(v) for v in used_values))
            total_free = float(sum(int(v) for v in free_values))
            denom = total_used + total_free
            if denom > 0:
                return (total_used * 100.0) / denom, errors
        except Exception as exc:
            errors.append(f"cisco_pool_calc:{exc}")
    else:
        if used_err:
            errors.append(f"cisco_pool_used:{used_err}")
        if free_err:
            errors.append(f"cisco_pool_free:{free_err}")

    # Strategy 2: HOST-RESOURCES-MIB (generic devices/servers).
    type_map, type_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.2", max_rows=1024)
    size_map, size_err = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.5", max_rows=1024)
    used_map, used_err2 = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.25.2.3.1.6", max_rows=1024)
    ram_type_oid = "1.3.6.1.2.1.25.2.1.2"
    if type_map and size_map and used_map and not (type_err or size_err or used_err2):
        ram_ratios: list[tuple[float, float]] = []
        for idx, raw_type in type_map.items():
            type_text = str(raw_type or "").strip()
            if type_text != ram_type_oid:
                continue
            size_val = _to_float(size_map.get(idx))
            used_val = _to_float(used_map.get(idx))
            if size_val is None or used_val is None or size_val <= 0:
                continue
            ratio = max(0.0, min(100.0, (used_val * 100.0) / size_val))
            # Keep size with ratio to prefer the largest RAM entry if multiple exist.
            ram_ratios.append((size_val, ratio))
        if ram_ratios:
            ram_ratios.sort(key=lambda item: item[0], reverse=True)
            return ram_ratios[0][1], errors
    else:
        if type_err:
            errors.append(f"hrStorage_type:{type_err}")
        if size_err:
            errors.append(f"hrStorage_size:{size_err}")
        if used_err2:
            errors.append(f"hrStorage_used:{used_err2}")

    # Strategy 3: UCD-SNMP-MIB memory (common on Linux/Unix SNMP agents).
    total_real, total_err = snmp_get_value(host, settings, "1.3.6.1.4.1.2021.4.5.0")
    avail_real, avail_err = snmp_get_value(host, settings, "1.3.6.1.4.1.2021.4.6.0")
    total_num = _to_float(total_real)
    avail_num = _to_float(avail_real)
    if total_num is not None and avail_num is not None and total_num > 0:
        used_num = max(0.0, total_num - avail_num)
        return max(0.0, min(100.0, (used_num * 100.0) / total_num)), errors
    if total_err:
        errors.append(f"ucd_total:{total_err}")
    if avail_err:
        errors.append(f"ucd_avail:{avail_err}")

    return None, errors


def poll_device_monitoring_sample(
    device: dict[str, Any], settings: dict[str, Any], pre_ping: tuple[str, float | None] | None = None
) -> dict[str, Any]:
    host = str(device.get("host", "")).strip()
    name = str(device.get("name", "")).strip() or host
    mode = str(settings.get("collection_mode", "telemetry")).strip().lower() or "telemetry"
    selected_metrics = parse_monitoring_metrics(str(settings.get("metrics", "")))
    try:
        cpu_warn = max(1, min(100, int(settings.get("cpu_warn", 90) or 90)))
    except Exception:
        cpu_warn = 90
    try:
        memory_warn = max(1, min(100, int(settings.get("memory_warn", 90) or 90)))
    except Exception:
        memory_warn = 90
    if pre_ping is not None:
        ping_state, latency = pre_ping
    else:
        ping_state, latency = ping_host_status(host, 2)
    status = ping_state
    severity = "ok" if status == "up" else "critical"
    details: dict[str, Any] = {"ping_latency_ms": latency}
    cpu_percent: float | None = None
    memory_percent: float | None = None
    interfaces_up: int | None = None
    interfaces_down: int | None = None
    sla_ms: float | None = latency

    if mode in {"snmp", "snmp_v2", "snmp_v3"} and ping_state == "up":
        snmp_errors: list[str] = []
        snmp_attempts = 0
        snmp_success = 0
        if "cpu" in selected_metrics:
            snmp_attempts += 1
            cpu_val, err = snmp_get_value(host, settings, "1.3.6.1.4.1.9.2.1.58.0")
            if err:
                snmp_errors.append(f"cpu:{err}")
            elif cpu_val is not None:
                try:
                    cpu_percent = _cap_percent(float(int(cpu_val)))
                    snmp_success += 1
                except Exception:
                    pass
        if "interfaces" in selected_metrics:
            snmp_attempts += 1
            oper_values, oper_err = snmp_walk_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
            if oper_err:
                snmp_errors.append(f"ifOperStatus:{oper_err}")
                if_num, err = snmp_get_value(host, settings, "1.3.6.1.2.1.2.1.0")
                if err:
                    snmp_errors.append(f"ifNumber:{err}")
                elif if_num is not None:
                    try:
                        interfaces_up = int(if_num)
                        interfaces_down = 0
                        snmp_success += 1
                    except Exception:
                        pass
            else:
                up_count = 0
                down_count = 0
                for raw in oper_values:
                    try:
                        code = int(raw)
                    except Exception:
                        continue
                    if code == 1:
                        up_count += 1
                    elif code == 2:
                        down_count += 1
                interfaces_up = up_count
                interfaces_down = down_count
                snmp_success += 1
        if "memory" in selected_metrics:
            snmp_attempts += 1
            memory_value, memory_errors = snmp_collect_memory_percent(host, settings)
            if memory_value is not None:
                memory_percent = memory_value
                snmp_success += 1
            else:
                for err_text in memory_errors[:6]:
                    if str(err_text).strip():
                        snmp_errors.append(f"memory:{err_text}")
        if snmp_errors:
            details["snmp_errors"] = snmp_errors
        # Store per-interface utilization snapshot so dashboard can render from DB only.
        if "interfaces" in selected_metrics:
            selected_ifaces_raw = settings.get("selected_interfaces", [])
            selected_ifaces = (
                {str(item).strip() for item in selected_ifaces_raw if str(item).strip()} if isinstance(selected_ifaces_raw, list) else set()
            )
            try:
                util_rows = snmp_collect_interface_utilization(
                    host,
                    settings,
                    selected_interfaces=(selected_ifaces if selected_ifaces else None),
                    sample_seconds=1.0,
                )
                # If selection names don't match SNMP ifName format, retry without filter.
                if selected_ifaces and not util_rows:
                    util_rows = snmp_collect_interface_utilization(
                        host,
                        settings,
                        selected_interfaces=None,
                        sample_seconds=1.0,
                    )
                # If utilization counters are not available, still provide interface/status rows.
                if not util_rows:
                    name_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.1", max_rows=4096)
                    if not name_map:
                        name_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.2", max_rows=4096)
                    oper_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.2.2.1.8", max_rows=4096)
                    alias_map, _ = snmp_walk_indexed_values(host, settings, "1.3.6.1.2.1.31.1.1.1.18", max_rows=4096)
                    status_map = {1: "up", 2: "down"}
                    fallback_rows: list[dict[str, Any]] = []
                    selected_ifaces_lc = {str(v).strip().lower() for v in selected_ifaces if str(v).strip()}
                    selected_ifaces_norm = {
                        _normalize_interface_key(str(v).strip())
                        for v in selected_ifaces
                        if str(v).strip() and _normalize_interface_key(str(v).strip())
                    }
                    for idx in sorted(name_map.keys()):
                        if_name = str(name_map.get(idx, "")).strip()
                        if not if_name:
                            continue
                        if selected_ifaces_lc or selected_ifaces_norm:
                            if_name_norm = _normalize_interface_key(if_name)
                            if if_name.lower() not in selected_ifaces_lc and if_name_norm not in selected_ifaces_norm:
                                continue
                        try:
                            oper_code = int(oper_map.get(idx, 0) or 0)
                        except Exception:
                            oper_code = 0
                        fallback_rows.append(
                            {
                                "status": status_map.get(oper_code, "unknown"),
                                "interface": if_name,
                                "description": str(alias_map.get(idx, "")).strip(),
                                "tx_percent": None,
                                "rx_percent": None,
                            }
                        )
                    util_rows = fallback_rows
                details["interface_utilization"] = util_rows
            except Exception as exc:
                snmp_errors.append(f"ifUtil:{exc}")
                details["interface_utilization"] = []
        # If SNMP polling fully fails but ping is up, keep operational status as up
        # and set severity warning for visibility.
        if snmp_attempts > 0 and snmp_success <= 0:
            severity = "warning"
            if ping_state == "up":
                status = "up"
            else:
                status = "warning"

    if mode in {"winrm", "winrm_icmp"} and ping_state == "up":
        winrm_attempts = 0
        winrm_success = 0
        winrm_errors: list[str] = []
        metrics, errors = winrm_collect_metrics(host, settings, timeout_seconds=8)
        details["winrm"] = {
            "uptime_seconds": metrics.get("uptime_seconds"),
            "last_boot": metrics.get("last_boot"),
            "network_rx_mbps": metrics.get("network_rx_mbps"),
            "network_tx_mbps": metrics.get("network_tx_mbps"),
            "windows_caption": metrics.get("windows_caption"),
            "windows_version": metrics.get("windows_version"),
            "windows_build": metrics.get("windows_build"),
            "windows_arch": metrics.get("windows_arch"),
            "computer_name": metrics.get("computer_name"),
            "computer_model": metrics.get("computer_model"),
            "domain": metrics.get("domain"),
            "total_memory_gb": metrics.get("total_memory_gb"),
            "free_memory_gb": metrics.get("free_memory_gb"),
            "disk_usage": metrics.get("disk_usage", []),
        }
        if "interfaces" in selected_metrics:
            winrm_attempts += 1
            selected_ifaces_raw = settings.get("selected_interfaces", [])
            selected_ifaces = (
                {str(item).strip() for item in selected_ifaces_raw if str(item).strip()} if isinstance(selected_ifaces_raw, list) else set()
            )
            selected_ifaces_lc = {str(v).strip().lower() for v in selected_ifaces if str(v).strip()}
            selected_ifaces_norm = {
                _normalize_interface_key(str(v).strip())
                for v in selected_ifaces
                if str(v).strip() and _normalize_interface_key(str(v).strip())
            }
            iface_rows_raw = metrics.get("interface_utilization", [])
            iface_rows = iface_rows_raw if isinstance(iface_rows_raw, list) else []
            normalized_rows: list[dict[str, Any]] = []
            up_count = 0
            down_count = 0
            for row in iface_rows:
                if not isinstance(row, dict):
                    continue
                iface_name = str(row.get("interface", "")).strip()
                if not iface_name:
                    continue
                iface_lc = iface_name.lower()
                iface_norm = _normalize_interface_key(iface_name) or iface_lc
                if selected_ifaces_lc or selected_ifaces_norm:
                    if iface_lc not in selected_ifaces_lc and iface_norm not in selected_ifaces_norm:
                        continue
                status_raw = str(row.get("status", "unknown") or "unknown").strip().lower()
                status_value = status_raw if status_raw in {"up", "down", "unknown"} else "unknown"
                if status_value == "up":
                    up_count += 1
                elif status_value == "down":
                    down_count += 1
                try:
                    tx_val = row.get("tx_percent")
                    tx_percent = max(0.0, min(100.0, float(tx_val))) if tx_val is not None else None
                except Exception:
                    tx_percent = None
                try:
                    rx_val = row.get("rx_percent")
                    rx_percent = max(0.0, min(100.0, float(rx_val))) if rx_val is not None else None
                except Exception:
                    rx_percent = None
                normalized_rows.append(
                    {
                        "interface": iface_name,
                        "description": str(row.get("description", "")).strip(),
                        "status": status_value,
                        "tx_percent": tx_percent,
                        "rx_percent": rx_percent,
                    }
                )
            if normalized_rows:
                details["interface_utilization"] = normalized_rows
                interfaces_up = up_count
                interfaces_down = down_count
                winrm_success += 1
            else:
                details["interface_utilization"] = []
                winrm_errors.append("interfaces:unavailable")
        if "cpu" in selected_metrics:
            winrm_attempts += 1
            cpu_val = metrics.get("cpu_percent")
            if cpu_val is not None:
                cpu_percent = _cap_percent(float(cpu_val))
                winrm_success += 1
            else:
                winrm_errors.append("cpu:unavailable")
        if "memory" in selected_metrics:
            winrm_attempts += 1
            mem_val = metrics.get("memory_percent")
            if mem_val is not None:
                memory_percent = float(mem_val)
                winrm_success += 1
            else:
                winrm_errors.append("memory:unavailable")
        if errors:
            winrm_errors.extend(errors)
        if winrm_errors:
            details["winrm_errors"] = winrm_errors
        if winrm_attempts > 0 and winrm_success <= 0:
            severity = "warning"
            status = "up" if ping_state == "up" else "warning"

    if cpu_percent is not None and cpu_percent >= cpu_warn:
        severity = "warning"
        if status == "up":
            status = "warning"
    if memory_percent is not None and memory_percent >= memory_warn:
        severity = "warning"
        if status == "up":
            status = "warning"
    if ping_state != "up":
        status = "down"
        severity = "critical"

    return {
        "device_name": name,
        "host": host,
        "collection_mode": mode,
        "status": status,
        "severity": severity,
        "cpu_percent": _cap_percent(cpu_percent),
        "memory_percent": memory_percent,
        "interfaces_up": interfaces_up,
        "interfaces_down": interfaces_down,
        "sla_ms": sla_ms,
        "cpu_warn": cpu_warn,
        "memory_warn": memory_warn,
        "details_json": json.dumps(details),
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def save_monitoring_sample(sample: dict[str, Any]) -> None:
    def _normalized_collected_at(raw_value: Any) -> str:
        text = str(raw_value or "").strip()
        if not text:
            return datetime.now(timezone.utc).isoformat()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    def _safe_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            val = float(value)
        except Exception:
            return None
        if not (val == val):  # NaN check
            return None
        return val

    def _parse_details(raw_json: str) -> dict[str, Any]:
        try:
            obj = json.loads(raw_json)
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _extract_interface_rows(details_obj: dict[str, Any]) -> list[dict[str, Any]]:
        rows_raw = details_obj.get("interface_utilization", [])
        if not isinstance(rows_raw, list):
            return []
        out: list[dict[str, Any]] = []
        for row in rows_raw:
            if not isinstance(row, dict):
                continue
            iface = str(row.get("interface", "")).strip()
            if not iface:
                continue
            status = str(row.get("status", "unknown") or "unknown").strip().lower()
            if status not in {"up", "down", "unknown", "connected", "disable", "notconnected", "err-disable"}:
                status = "unknown"
            out.append(
                {
                    "interface_name": iface,
                    "interface_description": str(row.get("description", "")).strip(),
                    "oper_status": status,
                    "tx_percent": _safe_float(row.get("tx_percent")),
                    "rx_percent": _safe_float(row.get("rx_percent")),
                    "details_json": json.dumps({"source": "poll"}),
                }
            )
        return out

    def _build_active_alerts(sample_obj: dict[str, Any], details_obj: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        status = str(sample_obj.get("status", "unknown")).strip().lower()
        host_name = str(sample_obj.get("host", "")).strip()
        sample_ts = str(sample_obj.get("collected_at", "")).strip()

        cpu_val = _safe_float(sample_obj.get("cpu_percent"))
        mem_val = _safe_float(sample_obj.get("memory_percent"))
        sla_val = _safe_float(sample_obj.get("sla_ms"))
        cpu_warn = _safe_float(sample_obj.get("cpu_warn"))
        mem_warn = _safe_float(sample_obj.get("memory_warn"))
        if_down_raw = sample_obj.get("interfaces_down")
        try:
            interfaces_down = int(if_down_raw) if if_down_raw is not None else None
        except Exception:
            interfaces_down = None

        if status == "down":
            alerts.append(
                {
                    "alert_key": "device_down",
                    "alert_type": "availability",
                    "severity": "critical",
                    "message": f"Device {host_name or sample_obj.get('device_name', '')} is DOWN",
                    "threshold_value": None,
                    "last_value": 0.0,
                    "details_json": json.dumps({"status": status, "sample_collected_at": sample_ts}),
                }
            )
        if cpu_val is not None and cpu_warn is not None and cpu_val >= cpu_warn:
            alerts.append(
                {
                    "alert_key": "cpu_high",
                    "alert_type": "cpu",
                    "severity": "warning",
                    "message": f"CPU high: {cpu_val:.2f}% >= {cpu_warn:.2f}%",
                    "threshold_value": cpu_warn,
                    "last_value": cpu_val,
                    "details_json": json.dumps({"cpu_percent": cpu_val, "threshold": cpu_warn}),
                }
            )
        if mem_val is not None and mem_warn is not None and mem_val >= mem_warn:
            alerts.append(
                {
                    "alert_key": "memory_high",
                    "alert_type": "memory",
                    "severity": "warning",
                    "message": f"Memory high: {mem_val:.2f}% >= {mem_warn:.2f}%",
                    "threshold_value": mem_warn,
                    "last_value": mem_val,
                    "details_json": json.dumps({"memory_percent": mem_val, "threshold": mem_warn}),
                }
            )
        if interfaces_down is not None and interfaces_down > 0:
            alerts.append(
                {
                    "alert_key": "interfaces_down",
                    "alert_type": "interfaces",
                    "severity": "warning",
                    "message": f"{interfaces_down} interface(s) reported DOWN",
                    "threshold_value": 0.0,
                    "last_value": float(interfaces_down),
                    "details_json": json.dumps({"interfaces_down": interfaces_down}),
                }
            )
        # Response-time warning only for very high values to reduce noise.
        if sla_val is not None and sla_val >= 5000.0:
            alerts.append(
                {
                    "alert_key": "response_high",
                    "alert_type": "response",
                    "severity": "warning",
                    "message": f"Response time high: {sla_val:.2f} ms",
                    "threshold_value": 5000.0,
                    "last_value": sla_val,
                    "details_json": json.dumps({"sla_ms": sla_val}),
                }
            )
        return alerts

    def _upsert_monitoring_alerts(conn: Any, sample_obj: dict[str, Any], active_alerts: list[dict[str, Any]]) -> None:
        device_name = str(sample_obj.get("device_name", "")).strip()
        if not device_name:
            return
        host_name = str(sample_obj.get("host", "")).strip()
        now_iso = datetime.now(timezone.utc).isoformat()
        sample_ts = str(sample_obj.get("collected_at", now_iso)).strip() or now_iso
        existing_rows = conn.execute(
            """
            SELECT id, alert_key, status
            FROM monitoring_alerts
            WHERE LOWER(device_name) = LOWER(?) AND status IN ('open', 'acked')
            """,
            (device_name,),
        ).fetchall()
        existing_by_key: dict[str, Any] = {}
        for row in existing_rows:
            key = str(row["alert_key"] or "").strip().lower()
            if key and key not in existing_by_key:
                existing_by_key[key] = row

        active_keys: set[str] = set()
        for alert in active_alerts:
            key = str(alert.get("alert_key", "")).strip().lower()
            if not key:
                continue
            active_keys.add(key)
            existing = existing_by_key.get(key)
            if existing:
                existing_status = str(existing["status"] or "").strip().lower()
                next_status = "acked" if existing_status == "acked" else "open"
                conn.execute(
                    """
                    UPDATE monitoring_alerts
                    SET host = ?, alert_type = ?, severity = ?, status = ?, message = ?,
                        threshold_value = ?, last_value = ?, updated_at = ?, sample_collected_at = ?, details_json = ?
                    WHERE id = ?
                    """,
                    (
                        host_name,
                        str(alert.get("alert_type", "generic")).strip().lower() or "generic",
                        str(alert.get("severity", "warning")).strip().lower() or "warning",
                        next_status,
                        str(alert.get("message", "")).strip(),
                        alert.get("threshold_value"),
                        alert.get("last_value"),
                        now_iso,
                        sample_ts,
                        str(alert.get("details_json", "{}")),
                        existing["id"],
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO monitoring_alerts(
                        device_name, host, alert_key, alert_type, severity, status, message,
                        threshold_value, last_value, opened_at, updated_at, sample_collected_at, details_json
                    ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_name,
                        host_name,
                        key,
                        str(alert.get("alert_type", "generic")).strip().lower() or "generic",
                        str(alert.get("severity", "warning")).strip().lower() or "warning",
                        str(alert.get("message", "")).strip(),
                        alert.get("threshold_value"),
                        alert.get("last_value"),
                        now_iso,
                        now_iso,
                        sample_ts,
                        str(alert.get("details_json", "{}")),
                    ),
                )

        for key, row in existing_by_key.items():
            if key in active_keys:
                continue
            conn.execute(
                """
                UPDATE monitoring_alerts
                SET status = 'cleared', updated_at = ?, cleared_at = ?, sample_collected_at = ?
                WHERE id = ?
                """,
                (now_iso, now_iso, sample_ts, row["id"]),
            )

    collected_at_iso = _normalized_collected_at(sample.get("collected_at"))
    details_json = str(sample.get("details_json", "{}"))
    details_obj = _parse_details(details_json)
    interface_rows = _extract_interface_rows(details_obj)
    sample_payload = dict(sample)
    sample_payload["collected_at"] = collected_at_iso
    active_alerts = _build_active_alerts(sample_payload, details_obj)

    with db_conn() as conn:
        try:
            conn.execute(
                """
                INSERT INTO monitoring_metrics(
                    device_name, host, collection_mode, status, severity,
                    cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at, collected_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(sample.get("device_name", "")),
                    str(sample.get("host", "")),
                    str(sample.get("collection_mode", "")),
                    str(sample.get("status", "unknown")),
                    str(sample.get("severity", "warning")),
                    sample.get("cpu_percent"),
                    sample.get("memory_percent"),
                    sample.get("interfaces_up"),
                    sample.get("interfaces_down"),
                    sample.get("sla_ms"),
                    details_json,
                    collected_at_iso,
                    collected_at_iso,
                ),
            )
        except Exception:
            conn.execute(
                """
                INSERT INTO monitoring_metrics(
                    device_name, host, collection_mode, status, severity,
                    cpu_percent, memory_percent, interfaces_up, interfaces_down, sla_ms, details_json, collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(sample.get("device_name", "")),
                    str(sample.get("host", "")),
                    str(sample.get("collection_mode", "")),
                    str(sample.get("status", "unknown")),
                    str(sample.get("severity", "warning")),
                    sample.get("cpu_percent"),
                    sample.get("memory_percent"),
                    sample.get("interfaces_up"),
                    sample.get("interfaces_down"),
                    sample.get("sla_ms"),
                    details_json,
                    collected_at_iso,
                ),
            )

        if interface_rows:
            for row in interface_rows:
                conn.execute(
                    """
                    INSERT INTO monitoring_interface_metrics(
                        device_name, host, interface_name, interface_description, oper_status,
                        tx_percent, rx_percent, collected_at_utc, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(sample.get("device_name", "")),
                        str(sample.get("host", "")),
                        str(row.get("interface_name", "")),
                        str(row.get("interface_description", "")),
                        str(row.get("oper_status", "unknown")),
                        row.get("tx_percent"),
                        row.get("rx_percent"),
                        collected_at_iso,
                        str(row.get("details_json", "{}")),
                    ),
                )

        _upsert_monitoring_alerts(conn, sample_payload, active_alerts)
