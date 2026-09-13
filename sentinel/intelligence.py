from __future__ import annotations

import ipaddress
import time
from collections import defaultdict


def is_public_ip(value: str | None) -> bool:
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


def device_risk(device: dict, now: float | None = None) -> dict:
    """Return an explainable local heuristic, not a compromise probability."""
    now = now or time.time()
    score = 0
    reasons = []

    if device.get("is_gateway"):
        score = 5 if not device.get("trusted") else 0
        reasons.append("default gateway")
    else:
        if device.get("online") and not device.get("trusted"):
            score += 28
            reasons.append("online and not trusted")

        age = max(0, now - float(device.get("first_seen") or now))
        if age < 10 * 60:
            score += 18
            reasons.append("first seen recently")
        elif age < 60 * 60:
            score += 8
            reasons.append("recently learned device")

        mac = str(device.get("mac") or "")
        try:
            first_octet = int(mac.split(":")[0], 16)
            randomized = bool(first_octet & 0x02)
        except (ValueError, IndexError):
            randomized = False
        if randomized:
            score += 12
            reasons.append("private/randomized MAC")

        if not device.get("vendor"):
            score += 6
            reasons.append("vendor unknown")
        if not device.get("hostname"):
            score += 4
            reasons.append("hostname unknown")

    if device.get("trusted"):
        score = max(0, score - 35)
        reasons.append("marked trusted")

    if not device.get("online"):
        score = max(0, score - 8)

    score = max(0, min(100, score))
    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons[:5],
        "kind": "local_heuristic",
    }


def external_connections(connections: list[dict]) -> list[dict]:
    rows = []
    for item in connections:
        remote = item.get("remote") or {}
        remote_ip = remote.get("ip")
        remote_port = remote.get("port")
        if not remote_ip or remote_port is None or not is_public_ip(remote_ip):
            continue
        rows.append(
            {
                "process": item.get("process") or "unknown",
                "pid": item.get("pid"),
                "proto": item.get("proto") or "?",
                "remote_ip": remote_ip,
                "remote_port": int(remote_port),
                "status": item.get("status") or "",
            }
        )
    return rows


def process_communications(
    storage,
    connections: list[dict],
    baseline_ready: bool,
    fanout_threshold: int,
    endpoint_churn_threshold: int,
):
    rows = external_connections(connections)
    fanout = defaultdict(set)
    new_endpoints = defaultdict(int)

    for row in rows:
        result = storage.upsert_communication(row)
        process = row["process"]
        fanout[process].add(row["remote_ip"])
        if result["new_endpoint"]:
            new_endpoints[process] += 1

        if baseline_ready and result["new_process"] and process != "unknown":
            title = f"New network-active process: {process}"
            if not storage.recent_alert("anomaly_new_process", title, 1800):
                storage.add_alert(
                    "medium",
                    "anomaly_new_process",
                    title,
                    (
                        f"First post-baseline external connection to "
                        f"{row['remote_ip']}:{row['remote_port']} ({row['proto'].upper()})"
                    ),
                )

    if not baseline_ready:
        return

    for process, destinations in fanout.items():
        count = len(destinations)
        if count >= fanout_threshold:
            title = f"High destination fan-out: {process}"
            if not storage.recent_alert("anomaly_fanout", title, 300):
                severity = "high" if count >= fanout_threshold * 2 else "medium"
                storage.add_alert(
                    severity,
                    "anomaly_fanout",
                    title,
                    f"{process} currently talks to {count} distinct public IPs",
                )

    for process, count in new_endpoints.items():
        if count >= endpoint_churn_threshold:
            title = f"Endpoint churn: {process}"
            if not storage.recent_alert("anomaly_endpoint_churn", title, 600):
                storage.add_alert(
                    "medium",
                    "anomaly_endpoint_churn",
                    title,
                    f"{count} previously unseen external endpoints appeared in one monitor cycle",
                )


def process_dns_records(storage, records: list[dict], baseline_ready: bool, burst_threshold: int):
    new_domains = set()
    idn_domains = set()

    for record in records:
        is_new = storage.upsert_dns_record(record)
        domain = record.get("domain") or ""
        if is_new:
            new_domains.add(domain)
            if "xn--" in domain:
                idn_domains.add(domain)

    if not baseline_ready:
        return

    if len(new_domains) >= burst_threshold:
        title = "DNS burst detected"
        if not storage.recent_alert("anomaly_dns_burst", title, 300):
            storage.add_alert(
                "medium",
                "anomaly_dns_burst",
                title,
                f"{len(new_domains)} previously unseen DNS names entered the local cache",
            )

    for domain in sorted(idn_domains)[:5]:
        title = f"Internationalized domain observed: {domain}"
        if not storage.recent_alert("anomaly_idn_domain", title, 3600):
            storage.add_alert(
                "low",
                "anomaly_idn_domain",
                title,
                "Punycode can be legitimate, but visual look-alike domains deserve review.",
            )
