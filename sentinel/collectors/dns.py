from __future__ import annotations

import json
import platform
import re
import subprocess


def _run(command, timeout=8):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _windows_dns_cache():
    # PowerShell object property names are stable across localized Windows UIs,
    # unlike parsing the localized output of `ipconfig /displaydns`.
    script = (
        "Get-DnsClientCache | "
        "Select-Object Entry,Data,Type,TimeToLive | "
        "ConvertTo-Json -Compress"
    )
    result = _run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=10,
    )
    if not result or result.returncode != 0 or not result.stdout.strip():
        return [], False, (result.stderr.strip() if result else "PowerShell unavailable")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return [], False, f"Unable to parse Windows DNS cache: {exc}"

    if isinstance(payload, dict):
        payload = [payload]

    records = []
    for item in payload:
        domain = str(item.get("Entry") or "").strip().rstrip(".").lower()
        data = str(item.get("Data") or "").strip().rstrip(".")
        record_type = str(item.get("Type") or "?")
        try:
            ttl = int(item.get("TimeToLive")) if item.get("TimeToLive") is not None else None
        except (TypeError, ValueError):
            ttl = None
        if domain:
            records.append(
                {
                    "domain": domain,
                    "record_type": record_type,
                    "data": data,
                    "ttl": ttl,
                }
            )
    return records, True, None


def _linux_dns_cache():
    # Newer systemd-resolved versions may expose `resolvectl show-cache`.
    result = _run(["resolvectl", "show-cache"], timeout=6)
    if not result or result.returncode != 0:
        return [], False, "DNS cache introspection is unavailable on this Linux host"

    records = []
    # Best-effort parser. Unknown lines are ignored rather than guessed.
    pattern = re.compile(r"^\s*(\S+?)\.?\s+IN\s+([A-Z0-9]+)\s+(.+?)\s*$")
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        domain, record_type, data = match.groups()
        records.append(
            {
                "domain": domain.lower(),
                "record_type": record_type,
                "data": data.strip(),
                "ttl": None,
            }
        )
    return records, bool(records), None if records else "DNS cache is empty or not exposed"


def collect_dns_cache():
    system = platform.system().lower()
    if system == "windows":
        return _windows_dns_cache()
    if system == "linux":
        return _linux_dns_cache()
    return [], False, f"DNS cache monitoring is not implemented for {platform.system()}"
