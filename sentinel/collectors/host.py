import socket
import time
import psutil


def _addr(addr):
    if not addr:
        return {"ip": None, "port": None}
    try:
        return {"ip": addr.ip, "port": addr.port}
    except AttributeError:
        if isinstance(addr, tuple) and len(addr) >= 2:
            return {"ip": addr[0], "port": addr[1]}
    return {"ip": str(addr), "port": None}


def _proc_name(pid):
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.Error, OSError):
        return None


def collect_connections():
    rows = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        connections = []

    for c in connections:
        proto = (
            "tcp"
            if c.type == socket.SOCK_STREAM
            else "udp"
        )
        rows.append(
            {
                "proto": proto,
                "local": _addr(c.laddr),
                "remote": _addr(c.raddr),
                "status": c.status or "",
                "pid": c.pid,
                "process": _proc_name(c.pid),
            }
        )
    return rows


def collect_listeners(connections):
    result = []
    for c in connections:
        if c["proto"] == "tcp":
            listening = c["status"] == psutil.CONN_LISTEN
        else:
            listening = (
                bool(c["local"]["port"])
                and not c["remote"]["ip"]
            )

        if (
            listening
            and c["local"]["port"] is not None
        ):
            result.append(
                {
                    "proto": c["proto"],
                    "ip": c["local"]["ip"] or "0.0.0.0",
                    "port": int(c["local"]["port"]),
                    "pid": c["pid"],
                    "process": c["process"],
                }
            )
    return result


def network_counters():
    data = psutil.net_io_counters()
    return {
        "timestamp": time.time(),
        "bytes_sent": data.bytes_sent,
        "bytes_recv": data.bytes_recv,
        "packets_sent": data.packets_sent,
        "packets_recv": data.packets_recv,
        "errin": data.errin,
        "errout": data.errout,
        "dropin": data.dropin,
        "dropout": data.dropout,
    }
