import re
import subprocess


def _linux_proc_arp():
    out = []
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    ip, _, flags, mac, _, iface = parts[:6]
                    if (
                        mac != "00:00:00:00:00:00"
                        and flags != "0x0"
                    ):
                        out.append(
                            {
                                "ip": ip,
                                "mac": mac.lower(),
                                "interface": iface,
                            }
                        )
    except OSError:
        pass
    return out


def _arp_command():
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
            ),
        )
    except (OSError, subprocess.SubprocessError):
        return []

    entries = []
    seen = set()

    win_re = re.compile(
        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+",
        re.MULTILINE,
    )

    unix_re = re.compile(
        r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
        r"(?:\s+on\s+(\S+))?"
    )

    for ip, mac in win_re.findall(result.stdout):
        normalized = mac.replace("-", ":").lower()
        key = (ip, normalized)
        if key not in seen:
            entries.append(
                {
                    "ip": ip,
                    "mac": normalized,
                    "interface": "unknown",
                }
            )
            seen.add(key)

    for match in unix_re.finditer(result.stdout):
        ip, mac, iface = match.groups()
        normalized = mac.lower()
        key = (ip, normalized)
        if key not in seen:
            entries.append(
                {
                    "ip": ip,
                    "mac": normalized,
                    "interface": iface or "unknown",
                }
            )
            seen.add(key)

    return entries


def collect_arp():
    entries = _linux_proc_arp()
    return entries if entries else _arp_command()
