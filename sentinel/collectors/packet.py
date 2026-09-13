from __future__ import annotations

import ipaddress
import socket
import time


def _local_ipv4s() -> set[str]:
    values = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            values.add(item[4][0])
    except OSError:
        pass
    return values


def _is_public(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def match_process(flow: dict, connections: list[dict]) -> tuple[str | None, int | None]:
    """Best-effort mapping from a captured host flow to psutil socket data."""
    src_ip = flow.get("src_ip")
    dst_ip = flow.get("dst_ip")
    src_port = flow.get("src_port")
    dst_port = flow.get("dst_port")
    proto = flow.get("proto")

    for item in connections:
        if item.get("proto") != proto:
            continue
        local = item.get("local") or {}
        remote = item.get("remote") or {}
        if (
            local.get("ip") == src_ip
            and local.get("port") == src_port
            and remote.get("ip") == dst_ip
            and remote.get("port") == dst_port
        ):
            return item.get("process"), item.get("pid")
        if (
            local.get("ip") == dst_ip
            and local.get("port") == dst_port
            and remote.get("ip") == src_ip
            and remote.get("port") == src_port
        ):
            return item.get("process"), item.get("pid")
    return None, None


def normalized_packet(packet, local_ips: set[str] | None = None) -> dict | None:
    """Convert a Scapy packet into metadata only. Packet payloads are never stored."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS, DNSQR, DNSRR
    except Exception:
        return None

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    local_ips = local_ips or _local_ipv4s()

    proto = "ip"
    src_port = None
    dst_port = None
    if TCP in packet:
        proto = "tcp"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        proto = "udp"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)

    if src_ip in local_ips:
        direction = "outbound"
        remote_ip = dst_ip
        remote_port = dst_port
        local_ip = src_ip
        local_port = src_port
    elif dst_ip in local_ips:
        direction = "inbound"
        remote_ip = src_ip
        remote_port = src_port
        local_ip = dst_ip
        local_port = dst_port
    else:
        direction = "transit"
        remote_ip = dst_ip
        remote_port = dst_port
        local_ip = src_ip
        local_port = src_port

    dns_events = []
    if DNS in packet:
        dns = packet[DNS]
        if getattr(dns, "qd", None) and DNSQR in packet:
            try:
                name = bytes(dns.qd.qname).decode("utf-8", errors="replace").rstrip(".").lower()
            except Exception:
                name = str(getattr(dns.qd, "qname", "")).rstrip(".").lower()
            if name:
                dns_events.append({"kind": "query", "domain": name, "answer": None})

        count = int(getattr(dns, "ancount", 0) or 0)
        current = getattr(dns, "an", None)
        for _ in range(min(count, 12)):
            if current is None:
                break
            try:
                rrname = bytes(current.rrname).decode("utf-8", errors="replace").rstrip(".").lower()
            except Exception:
                rrname = str(getattr(current, "rrname", "")).rstrip(".").lower()
            answer = getattr(current, "rdata", None)
            if isinstance(answer, bytes):
                answer = answer.decode("utf-8", errors="replace").rstrip(".")
            if rrname:
                dns_events.append({"kind": "answer", "domain": rrname, "answer": str(answer or "")})
            payload = getattr(current, "payload", None)
            current = payload if payload and DNSRR in payload else None

    return {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "local_ip": local_ip,
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "proto": proto,
        "direction": direction,
        "length": int(len(packet)),
        "remote_public": _is_public(remote_ip),
        "dns_events": dns_events,
    }
