from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import platform
import re
import socket
import subprocess

import psutil

from .arp import collect_arp

try:
    from pymanuf import lookup as manufacturer_lookup
except Exception:
    manufacturer_lookup = None


def _run(command, timeout=4):
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            ),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _mac_for_interface(interface_name):
    addrs = psutil.net_if_addrs().get(interface_name, [])
    af_link = getattr(psutil, "AF_LINK", None)

    for addr in addrs:
        if af_link is not None and addr.family == af_link:
            value = (addr.address or "").replace("-", ":").lower()
            if value and value != "00:00:00:00:00:00":
                return value
    return None


def select_private_interface(max_hosts=254):
    candidates = []

    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue

            try:
                ip = ipaddress.ip_address(addr.address)
            except ValueError:
                continue

            if (
                ip.is_loopback
                or ip.is_link_local
                or not ip.is_private
                or not addr.netmask
            ):
                continue

            try:
                network = ipaddress.ip_network(
                    f"{addr.address}/{addr.netmask}",
                    strict=False,
                )
            except ValueError:
                continue

            candidates.append(
                {
                    "interface": interface_name,
                    "ip": addr.address,
                    "netmask": addr.netmask,
                    "network": network,
                    "mac": _mac_for_interface(interface_name),
                }
            )

    if not candidates:
        return None

    # Prefer interfaces that look like ordinary LANs over virtual/tunnel links.
    def score(item):
        name = item["interface"].lower()
        penalty = sum(
            token in name
            for token in (
                "loopback",
                "docker",
                "veth",
                "hyper-v",
                "virtual",
                "wsl",
                "vpn",
                "tunnel",
                "tailscale",
            )
        )
        return (
            penalty,
            item["network"].num_addresses,
        )

    selected = sorted(candidates, key=score)[0]
    network = selected["network"]

    # Do not sweep more than a /24-sized address set.
    if network.num_addresses - 2 > max_hosts:
        selected["network"] = ipaddress.ip_network(
            f"{selected['ip']}/24",
            strict=False,
        )

    return selected


def detect_default_gateway(local_ip=None):
    system = platform.system().lower()

    if system == "windows":
        result = _run(["route", "print", "-4"])
        if not result:
            return None

        pattern = re.compile(
            r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s*$",
            re.MULTILINE,
        )

        matches = pattern.findall(result.stdout)
        if local_ip:
            for gateway, interface_ip in matches:
                if interface_ip == local_ip:
                    return gateway
        return matches[0][0] if matches else None

    if system == "linux":
        result = _run(["ip", "-4", "route", "show", "default"])
        if result:
            match = re.search(
                r"\bdefault\s+via\s+(\d+\.\d+\.\d+\.\d+)",
                result.stdout,
            )
            if match:
                return match.group(1)

    if system == "darwin":
        result = _run(["route", "-n", "get", "default"])
        if result:
            match = re.search(
                r"gateway:\s*(\d+\.\d+\.\d+\.\d+)",
                result.stdout,
            )
            if match:
                return match.group(1)

    return None


def _ping(ip, timeout_ms):
    system = platform.system().lower()

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout_ms),
            str(ip),
        ]
    else:
        timeout_seconds = max(1, int((timeout_ms + 999) / 1000))
        command = [
            "ping",
            "-c",
            "1",
            "-W",
            str(timeout_seconds),
            str(ip),
        ]

    result = _run(
        command,
        timeout=max(2, timeout_ms / 1000 + 1),
    )
    return bool(result and result.returncode == 0)


def ping_sweep(network, local_ip, timeout_ms=350, max_hosts=254):
    hosts = [
        str(ip)
        for ip in network.hosts()
        if str(ip) != local_ip
    ][:max_hosts]

    active = {local_ip}

    with ThreadPoolExecutor(max_workers=32) as pool:
        future_map = {
            pool.submit(_ping, ip, timeout_ms): ip
            for ip in hosts
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                if future.result():
                    active.add(ip)
            except Exception:
                pass

    return active


def resolve_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def resolve_hostnames(ips):
    result = {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {
            pool.submit(resolve_hostname, ip): ip
            for ip in ips
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                value = future.result()
            except Exception:
                value = None
            result[ip] = value
    return result


def vendor_for_mac(mac):
    if not mac:
        return None

    try:
        first_octet = int(mac.split(":")[0], 16)
        if first_octet & 0x02:
            return "Private / randomized MAC"
    except (ValueError, IndexError):
        pass

    if manufacturer_lookup is None:
        return None

    try:
        value = manufacturer_lookup(mac)
        return str(value) if value else None
    except Exception:
        return None


def discover_network(max_hosts=254, timeout_ms=350):
    interface = select_private_interface(max_hosts=max_hosts)
    if not interface:
        return {
            "network": None,
            "devices": [],
            "error": "No private IPv4 LAN interface found.",
        }

    network = interface["network"]
    local_ip = interface["ip"]
    gateway = detect_default_gateway(local_ip)

    active_ips = ping_sweep(
        network,
        local_ip,
        timeout_ms=timeout_ms,
        max_hosts=max_hosts,
    )

    # Ping populates the ARP cache. Read it after discovery.
    arp_entries = collect_arp()
    arp_by_ip = {
        item["ip"]: item
        for item in arp_entries
    }

    for item in arp_entries:
        try:
            ip = ipaddress.ip_address(item["ip"])
        except ValueError:
            continue
        if ip in network:
            active_ips.add(item["ip"])

    if gateway:
        active_ips.add(gateway)

    hostnames = resolve_hostnames(sorted(active_ips))

    devices = []
    for ip in sorted(
        active_ips,
        key=lambda value: ipaddress.ip_address(value),
    ):
        arp = arp_by_ip.get(ip, {})
        mac = arp.get("mac")

        if ip == local_ip and not mac:
            mac = interface.get("mac")

        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "interface": (
                    interface["interface"]
                    if ip == local_ip
                    else arp.get("interface")
                    or interface["interface"]
                ),
                "hostname": (
                    socket.gethostname()
                    if ip == local_ip
                    else hostnames.get(ip)
                ),
                "vendor": vendor_for_mac(mac),
                "is_gateway": bool(gateway and ip == gateway),
                "is_local": ip == local_ip,
            }
        )

    return {
        "network": {
            "interface": interface["interface"],
            "local_ip": local_ip,
            "local_mac": interface.get("mac"),
            "netmask": interface["netmask"],
            "cidr": str(network),
            "gateway": gateway,
            "host_limit": max_hosts,
        },
        "devices": devices,
        "error": None,
    }
