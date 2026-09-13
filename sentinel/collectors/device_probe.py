from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import platform
import socket
import subprocess
import time


SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    631: "IPP",
    1883: "MQTT",
    3389: "RDP",
    5357: "WSD",
    5900: "VNC",
    8008: "HTTP-alt",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8883: "MQTTS",
    9100: "JetDirect",
}

DEFAULT_PORTS = tuple(SERVICE_NAMES)
LIVENESS_PORTS = (443, 80, 445, 22, 53, 3389, 554, 631, 9100)


def parse_ports(value: str | None) -> tuple[int, ...]:
    if not value:
        return DEFAULT_PORTS
    ports = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return tuple(ports) or DEFAULT_PORTS


def _is_private_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_link_local)


def _ping(ip: str, timeout_ms: int) -> tuple[bool, float | None]:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_seconds = max(1, int((timeout_ms + 999) / 1000))
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]

    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(2.0, timeout_ms / 1000 + 1.0),
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return False, None
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    return result.returncode == 0, elapsed_ms if result.returncode == 0 else None


def _tcp_status(ip: str, port: int, timeout_s: float) -> tuple[bool, bool]:
    """Return (host_responded, port_open) using a normal TCP connect, no payload."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        rc = sock.connect_ex((ip, port))
        # 0=open; connection-refused codes still prove that the host answered.
        responded = rc in {0, 61, 111, 10061}
        return responded, rc == 0
    except OSError:
        return False, False
    finally:
        sock.close()


def probe_device(ip: str, ports: tuple[int, ...], timeout_ms: int = 250) -> dict:
    if not _is_private_ipv4(ip):
        return {
            "ip": ip,
            "online": False,
            "latency_ms": None,
            "services": [],
            "error": "probe limited to private IPv4 addresses",
        }

    ping_ok, latency_ms = _ping(ip, timeout_ms)
    responded = ping_ok
    timeout_s = max(0.08, min(timeout_ms / 1000.0, 1.0))

    # Some phones/IoT devices ignore ICMP. A short TCP liveness pass prevents
    # them from being incorrectly classified as offline.
    if not responded:
        for port in LIVENESS_PORTS:
            host_responded, _ = _tcp_status(ip, port, timeout_s)
            if host_responded:
                responded = True
                break

    services = []
    if responded:
        # Small allow-list only: service exposure inventory, not broad port scanning.
        def check(port: int):
            _, is_open = _tcp_status(ip, port, timeout_s)
            return port, is_open

        with ThreadPoolExecutor(max_workers=min(8, max(1, len(ports)))) as pool:
            futures = [pool.submit(check, port) for port in ports]
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    services.append(
                        {
                            "port": port,
                            "proto": "tcp",
                            "service": SERVICE_NAMES.get(port, f"TCP/{port}"),
                        }
                    )

    services.sort(key=lambda item: item["port"])
    return {
        "ip": ip,
        "online": responded,
        "latency_ms": latency_ms,
        "services": services,
        "error": None,
    }


def probe_devices(
    devices: list[dict],
    ports: tuple[int, ...],
    timeout_ms: int = 250,
    max_workers: int = 8,
) -> list[dict]:
    targets = []
    seen = set()
    for device in devices:
        ip = str(device.get("ip") or "")
        if ip and ip not in seen and _is_private_ipv4(ip):
            seen.add(ip)
            targets.append(ip)

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 24))) as pool:
        future_map = {
            pool.submit(probe_device, ip, ports, timeout_ms): ip
            for ip in targets
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:  # defensive isolation per device
                results.append(
                    {
                        "ip": ip,
                        "online": False,
                        "latency_ms": None,
                        "services": [],
                        "error": str(exc),
                    }
                )
    results.sort(key=lambda item: tuple(int(x) for x in item["ip"].split(".")))
    return results
