import sqlite3
import threading
import time
from contextlib import contextmanager


_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    ip TEXT PRIMARY KEY,
    mac TEXT,
    interface TEXT,
    hostname TEXT,
    vendor TEXT,
    is_gateway INTEGER NOT NULL DEFAULT 0,
    trusted INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS listeners(
    proto TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    pid INTEGER,
    process TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY(proto, ip, port)
);

CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dns_records(
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    data TEXT NOT NULL,
    ttl INTEGER,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(domain, record_type, data)
);

CREATE TABLE IF NOT EXISTS communications(
    process TEXT NOT NULL,
    proto TEXT NOT NULL,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(process, proto, remote_ip, remote_port)
);

CREATE TABLE IF NOT EXISTS processes(
    process TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS flows(
    process TEXT NOT NULL,
    pid INTEGER,
    proto TEXT NOT NULL,
    direction TEXT NOT NULL,
    local_ip TEXT NOT NULL,
    local_port INTEGER NOT NULL DEFAULT 0,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(process, proto, direction, local_ip, local_port, remote_ip, remote_port)
);

CREATE TABLE IF NOT EXISTS security_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    process TEXT,
    remote_ip TEXT,
    domain TEXT,
    incident_id INTEGER
);

CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    process TEXT,
    remote_ip TEXT,
    domain TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    event_count INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0
);


CREATE TABLE IF NOT EXISTS device_samples(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    observed_at REAL NOT NULL,
    online INTEGER NOT NULL,
    latency_ms REAL,
    open_port_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_services(
    ip TEXT NOT NULL,
    proto TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(ip, proto, port)
);

CREATE TABLE IF NOT EXISTS device_traffic(
    ip TEXT PRIMARY KEY,
    packets_from INTEGER NOT NULL DEFAULT 0,
    packets_to INTEGER NOT NULL DEFAULT 0,
    bytes_from INTEGER NOT NULL DEFAULT 0,
    bytes_to INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_samples_ip_time ON device_samples(ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_services_ip_active ON device_services(ip, active);
CREATE INDEX IF NOT EXISTS idx_device_traffic_last_seen ON device_traffic(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_kind_created ON alerts(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_last_seen ON dns_records(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_comm_last_seen ON communications(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_incident ON security_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);
"""

_DEVICE_COLUMNS = {
    "hostname": "TEXT",
    "vendor": "TEXT",
    "is_gateway": "INTEGER NOT NULL DEFAULT 0",
    "trusted": "INTEGER NOT NULL DEFAULT 0",
}


class Storage:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        with self._conn() as con:
            con.executescript(_SCHEMA)
            self._migrate(con)

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def _migrate(self, con):
        cols = {row["name"] for row in con.execute("PRAGMA table_info(devices)").fetchall()}
        for name, definition in _DEVICE_COLUMNS.items():
            if name not in cols:
                con.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")

    def upsert_device(self, ip, mac, interface, hostname=None, vendor=None, is_gateway=False):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            if old is None:
                con.execute(
                    """INSERT INTO devices(
                        ip,mac,interface,hostname,vendor,is_gateway,trusted,first_seen,last_seen
                    ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (ip, mac, interface, hostname, vendor, int(bool(is_gateway)), 0, now, now),
                )
                return {"status": "new", "old_mac": None, "new_mac": mac}

            old_mac = old["mac"]
            mac_changed = bool(old_mac and mac and old_mac.lower() != mac.lower())
            con.execute(
                """UPDATE devices SET
                    mac=COALESCE(?,mac), interface=COALESCE(?,interface),
                    hostname=COALESCE(?,hostname), vendor=COALESCE(?,vendor),
                    is_gateway=?, last_seen=? WHERE ip=?""",
                (mac, interface, hostname, vendor, int(bool(is_gateway)), now, ip),
            )
            return {
                "status": "mac_changed" if mac_changed else "seen",
                "old_mac": old_mac,
                "new_mac": mac,
            }

    def set_device_trusted(self, ip: str, trusted: bool):
        with self.lock, self._conn() as con:
            cur = con.execute("UPDATE devices SET trusted=? WHERE ip=?", (int(bool(trusted)), ip))
            return cur.rowcount > 0

    def upsert_listener(self, proto, ip, port, pid, process):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute(
                "SELECT 1 FROM listeners WHERE proto=? AND ip=? AND port=?", (proto, ip, port)
            ).fetchone()
            if old is None:
                con.execute(
                    """INSERT INTO listeners(proto,ip,port,pid,process,first_seen,last_seen)
                    VALUES(?,?,?,?,?,?,?)""",
                    (proto, ip, port, pid, process, now, now),
                )
                return True
            con.execute(
                """UPDATE listeners SET pid=?,process=?,last_seen=?
                WHERE proto=? AND ip=? AND port=?""",
                (pid, process, now, proto, ip, port),
            )
            return False

    def _insert_event(self, con, category, severity, title, details, process=None, remote_ip=None, domain=None):
        cur = con.execute(
            """INSERT INTO security_events(
                created_at,category,severity,title,details,process,remote_ip,domain
            ) VALUES(?,?,?,?,?,?,?,?)""",
            (time.time(), category, severity, title, details, process, remote_ip, domain),
        )
        return cur.lastrowid

    def add_event(self, category, severity, title, details, process=None, remote_ip=None, domain=None):
        with self.lock, self._conn() as con:
            return self._insert_event(con, category, severity, title, details, process, remote_ip, domain)

    def add_alert(self, severity, kind, title, details, process=None, remote_ip=None, domain=None):
        with self.lock, self._conn() as con:
            cur = con.execute(
                """INSERT INTO alerts(created_at,severity,kind,title,details)
                VALUES(?,?,?,?,?)""",
                (time.time(), severity, kind, title, details),
            )
            self._insert_event(
                con,
                "anomaly" if kind.startswith("anomaly_") else "alert",
                severity,
                title,
                details,
                process,
                remote_ip,
                domain,
            )
            return cur.lastrowid

    def recent_alert(self, kind: str, title: str, cooldown_seconds: int) -> bool:
        cutoff = time.time() - cooldown_seconds
        with self._conn() as con:
            return con.execute(
                "SELECT 1 FROM alerts WHERE kind=? AND title=? AND created_at>=? LIMIT 1",
                (kind, title, cutoff),
            ).fetchone() is not None

    def acknowledge_alert(self, alert_id):
        with self.lock, self._conn() as con:
            con.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def acknowledge_all_alerts(self):
        with self.lock, self._conn() as con:
            return con.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0").rowcount

    def upsert_dns_record(self, record: dict) -> bool:
        now = time.time()
        domain = str(record.get("domain") or "").strip().lower()
        record_type = str(record.get("record_type") or "?")
        data = str(record.get("data") or "")
        ttl = record.get("ttl")
        if not domain:
            return False
        with self.lock, self._conn() as con:
            old = con.execute(
                "SELECT 1 FROM dns_records WHERE domain=? AND record_type=? AND data=?",
                (domain, record_type, data),
            ).fetchone()
            if old is None:
                con.execute(
                    """INSERT INTO dns_records(
                        domain,record_type,data,ttl,first_seen,last_seen,seen_count
                    ) VALUES(?,?,?,?,?,?,1)""",
                    (domain, record_type, data, ttl, now, now),
                )
                return True
            con.execute(
                """UPDATE dns_records SET ttl=?,last_seen=?,seen_count=seen_count+1
                WHERE domain=? AND record_type=? AND data=?""",
                (ttl, now, domain, record_type, data),
            )
            return False

    def record_dns_event(self, domain: str, answer: str | None, source="packet"):
        title = f"DNS {source}: {domain}"
        details = f"answer {answer}" if answer else "query observed"
        return self.add_event("dns", "info", title, details, domain=domain, remote_ip=answer or None)

    def upsert_communication(self, item: dict) -> dict:
        now = time.time()
        process = str(item.get("process") or "unknown")
        proto = str(item.get("proto") or "?")
        remote_ip = str(item.get("remote_ip") or "")
        remote_port = int(item.get("remote_port") or 0)
        with self.lock, self._conn() as con:
            process_old = con.execute("SELECT 1 FROM processes WHERE process=?", (process,)).fetchone()
            if process_old is None:
                con.execute(
                    "INSERT INTO processes(process,first_seen,last_seen,seen_count) VALUES(?,?,?,1)",
                    (process, now, now),
                )
            else:
                con.execute(
                    "UPDATE processes SET last_seen=?,seen_count=seen_count+1 WHERE process=?",
                    (now, process),
                )

            endpoint_old = con.execute(
                """SELECT 1 FROM communications
                WHERE process=? AND proto=? AND remote_ip=? AND remote_port=?""",
                (process, proto, remote_ip, remote_port),
            ).fetchone()
            if endpoint_old is None:
                con.execute(
                    """INSERT INTO communications(
                        process,proto,remote_ip,remote_port,first_seen,last_seen,seen_count
                    ) VALUES(?,?,?,?,?,?,1)""",
                    (process, proto, remote_ip, remote_port, now, now),
                )
            else:
                con.execute(
                    """UPDATE communications SET last_seen=?,seen_count=seen_count+1
                    WHERE process=? AND proto=? AND remote_ip=? AND remote_port=?""",
                    (now, process, proto, remote_ip, remote_port),
                )
            return {"new_process": process_old is None, "new_endpoint": endpoint_old is None}

    def record_flow(self, flow: dict) -> bool:
        now = float(flow.get("timestamp") or time.time())
        process = str(flow.get("process") or "unknown")
        pid = flow.get("pid")
        proto = str(flow.get("proto") or "ip")
        direction = str(flow.get("direction") or "unknown")
        local_ip = str(flow.get("local_ip") or "")
        local_port = int(flow.get("local_port") or 0)
        remote_ip = str(flow.get("remote_ip") or "")
        remote_port = int(flow.get("remote_port") or 0)
        size = max(0, int(flow.get("length") or 0))
        if not local_ip or not remote_ip:
            return False

        with self.lock, self._conn() as con:
            old = con.execute(
                """SELECT 1 FROM flows WHERE process=? AND proto=? AND direction=?
                AND local_ip=? AND local_port=? AND remote_ip=? AND remote_port=?""",
                (process, proto, direction, local_ip, local_port, remote_ip, remote_port),
            ).fetchone()
            if old is None:
                con.execute(
                    """INSERT INTO flows(
                        process,pid,proto,direction,local_ip,local_port,remote_ip,remote_port,
                        first_seen,last_seen,packets,bytes
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)""",
                    (process, pid, proto, direction, local_ip, local_port, remote_ip, remote_port, now, now, size),
                )
                self._insert_event(
                    con,
                    "flow",
                    "info",
                    f"New {direction} flow: {process}",
                    f"{local_ip}:{local_port} -> {remote_ip}:{remote_port} ({proto.upper()})",
                    process=process,
                    remote_ip=remote_ip,
                )
                return True

            con.execute(
                """UPDATE flows SET pid=COALESCE(?,pid),last_seen=?,packets=packets+1,bytes=bytes+?
                WHERE process=? AND proto=? AND direction=? AND local_ip=? AND local_port=?
                AND remote_ip=? AND remote_port=?""",
                (pid, now, size, process, proto, direction, local_ip, local_port, remote_ip, remote_port),
            )
            return False

    def record_device_probe(self, result: dict) -> dict:
        """Persist an agentless reachability/service sample and emit change alerts."""
        now = float(result.get("timestamp") or time.time())
        ip = str(result.get("ip") or "").strip()
        if not ip:
            return {"ip": ip, "changed": False, "added": [], "removed": []}
        online = bool(result.get("online"))
        latency_ms = result.get("latency_ms")
        services = result.get("services") or []
        normalized = {
            (str(item.get("proto") or "tcp"), int(item.get("port") or 0)): str(item.get("service") or "unknown")
            for item in services
            if int(item.get("port") or 0) > 0
        }

        added = []
        removed = []
        state_change = None
        trusted = False
        with self.lock, self._conn() as con:
            device = con.execute("SELECT trusted FROM devices WHERE ip=?", (ip,)).fetchone()
            trusted = bool(device and device["trusted"])
            prev = con.execute(
                "SELECT * FROM device_samples WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)
            ).fetchone()
            prev_online = bool(prev["online"]) if prev is not None else None
            if prev_online is not None and prev_online != online:
                state_change = "online" if online else "offline"

            prev_services = {
                (row["proto"], int(row["port"])): row["service"]
                for row in con.execute(
                    "SELECT proto,port,service FROM device_services WHERE ip=? AND active=1", (ip,)
                ).fetchall()
            }

            con.execute(
                """INSERT INTO device_samples(ip,observed_at,online,latency_ms,open_port_count)
                VALUES(?,?,?,?,?)""",
                (ip, now, int(online), latency_ms, len(normalized)),
            )

            if online:
                con.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now, ip))
                con.execute("UPDATE device_services SET active=0 WHERE ip=?", (ip,))
                for (proto, port), service in normalized.items():
                    old = con.execute(
                        "SELECT 1 FROM device_services WHERE ip=? AND proto=? AND port=?",
                        (ip, proto, port),
                    ).fetchone()
                    if old is None:
                        con.execute(
                            """INSERT INTO device_services(
                                ip,proto,port,service,first_seen,last_seen,active
                            ) VALUES(?,?,?,?,?,?,1)""",
                            (ip, proto, port, service, now, now),
                        )
                    else:
                        con.execute(
                            """UPDATE device_services SET service=?,last_seen=?,active=1
                            WHERE ip=? AND proto=? AND port=?""",
                            (service, now, ip, proto, port),
                        )

                if prev is not None:
                    current_keys = set(normalized)
                    previous_keys = set(prev_services)
                    added = [
                        {"proto": proto, "port": port, "service": normalized[(proto, port)]}
                        for proto, port in sorted(current_keys - previous_keys, key=lambda item: item[1])
                    ]
                    removed = [
                        {"proto": proto, "port": port, "service": prev_services[(proto, port)]}
                        for proto, port in sorted(previous_keys - current_keys, key=lambda item: item[1])
                    ]

        if state_change == "offline":
            title = f"Device offline: {ip}"
            if not self.recent_alert("device_offline", title, 300):
                self.add_alert(
                    "medium" if trusted else "low",
                    "device_offline",
                    title,
                    "Agentless fleet probe no longer receives ICMP/TCP responses.",
                    remote_ip=ip,
                )
        elif state_change == "online":
            title = f"Device back online: {ip}"
            if not self.recent_alert("device_online", title, 300):
                self.add_alert(
                    "low",
                    "device_online",
                    title,
                    "Agentless fleet probe can reach the device again.",
                    remote_ip=ip,
                )

        if added:
            summary = ", ".join(f"{item['service']}:{item['port']}" for item in added[:8])
            title = f"New exposed service on {ip}"
            if not self.recent_alert("device_service_added", title, 600):
                self.add_alert(
                    "low",
                    "device_service_added",
                    title,
                    summary,
                    remote_ip=ip,
                )
        if removed:
            summary = ", ".join(f"{item['service']}:{item['port']}" for item in removed[:8])
            self.add_event(
                "device",
                "info",
                f"Service no longer observed on {ip}",
                summary,
                remote_ip=ip,
            )

        return {
            "ip": ip,
            "changed": bool(state_change or added or removed),
            "state_change": state_change,
            "added": added,
            "removed": removed,
        }

    def known_device_ips(self) -> set[str]:
        with self._conn() as con:
            return {row["ip"] for row in con.execute("SELECT ip FROM devices").fetchall()}

    def record_device_packet(self, ip: str, direction: str, size: int, observed_at=None):
        now = float(observed_at or time.time())
        size = max(0, int(size or 0))
        if direction not in {"from", "to"}:
            return
        with self.lock, self._conn() as con:
            old = con.execute("SELECT 1 FROM device_traffic WHERE ip=?", (ip,)).fetchone()
            if old is None:
                con.execute(
                    """INSERT INTO device_traffic(
                        ip,packets_from,packets_to,bytes_from,bytes_to,first_seen,last_seen
                    ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        ip,
                        1 if direction == "from" else 0,
                        1 if direction == "to" else 0,
                        size if direction == "from" else 0,
                        size if direction == "to" else 0,
                        now,
                        now,
                    ),
                )
            elif direction == "from":
                con.execute(
                    """UPDATE device_traffic SET packets_from=packets_from+1,
                    bytes_from=bytes_from+?,last_seen=? WHERE ip=?""",
                    (size, now, ip),
                )
            else:
                con.execute(
                    """UPDATE device_traffic SET packets_to=packets_to+1,
                    bytes_to=bytes_to+?,last_seen=? WHERE ip=?""",
                    (size, now, ip),
                )

    def device_profiles(self, online_window=130):
        devices = self.devices(online_window)
        with self._conn() as con:
            latest = {
                row["ip"]: dict(row)
                for row in con.execute(
                    """SELECT ds.* FROM device_samples ds
                    JOIN (SELECT ip,MAX(id) AS max_id FROM device_samples GROUP BY ip) x
                    ON ds.id=x.max_id"""
                ).fetchall()
            }
            service_counts = {
                row["ip"]: int(row["n"])
                for row in con.execute(
                    "SELECT ip,COUNT(*) AS n FROM device_services WHERE active=1 GROUP BY ip"
                ).fetchall()
            }
            traffic = {
                row["ip"]: dict(row)
                for row in con.execute("SELECT * FROM device_traffic").fetchall()
            }

        for device in devices:
            sample = latest.get(device["ip"])
            device["monitored"] = sample is not None
            device["probe_online"] = bool(sample["online"]) if sample else None
            device["probe_latency_ms"] = sample["latency_ms"] if sample else None
            device["last_probe"] = sample["observed_at"] if sample else None
            device["open_service_count"] = service_counts.get(device["ip"], 0)
            t = traffic.get(device["ip"])
            device["traffic_seen"] = bool(t)
            device["traffic"] = t or {
                "packets_from": 0, "packets_to": 0,
                "bytes_from": 0, "bytes_to": 0, "last_seen": None,
            }
        return devices

    def device_profile(self, ip: str, online_window=130):
        return next((d for d in self.device_profiles(online_window) if d["ip"] == ip), None)

    def device_history(self, ip: str, limit=120):
        with self._conn() as con:
            return [
                dict(row) for row in con.execute(
                    """SELECT * FROM device_samples WHERE ip=?
                    ORDER BY observed_at DESC LIMIT ?""",
                    (ip, limit),
                ).fetchall()
            ]

    def device_services(self, ip: str, active_only=False):
        with self._conn() as con:
            if active_only:
                rows = con.execute(
                    """SELECT * FROM device_services WHERE ip=? AND active=1
                    ORDER BY port ASC""", (ip,)
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM device_services WHERE ip=? ORDER BY active DESC,port ASC", (ip,)
                ).fetchall()
            return [dict(row) for row in rows]

    def device_traffic(self, ip: str):
        with self._conn() as con:
            row = con.execute("SELECT * FROM device_traffic WHERE ip=?", (ip,)).fetchone()
            return dict(row) if row else {
                "ip": ip, "packets_from": 0, "packets_to": 0,
                "bytes_from": 0, "bytes_to": 0, "first_seen": None, "last_seen": None,
            }

    def fleet_summary(self, online_window=130):
        profiles = self.device_profiles(online_window)
        now = time.time()
        monitored = [d for d in profiles if d.get("monitored")]
        reachable = [d for d in monitored if d.get("probe_online")]
        services = sum(int(d.get("open_service_count") or 0) for d in profiles)
        traffic_seen = [
            d for d in profiles
            if d.get("traffic", {}).get("last_seen")
            and now - float(d["traffic"]["last_seen"]) <= 300
        ]
        return {
            "known": len(profiles),
            "monitored": len(monitored),
            "reachable": len(reachable),
            "unreachable": max(0, len(monitored) - len(reachable)),
            "active_services": services,
            "traffic_seen_recently": len(traffic_seen),
        }

    def correlate_incidents(self, window_seconds=120, min_score=35):
        now = time.time()
        cutoff = now - window_seconds
        with self.lock, self._conn() as con:
            rows = [
                dict(r) for r in con.execute(
                    """SELECT * FROM security_events
                    WHERE incident_id IS NULL AND created_at>=?
                    ORDER BY created_at ASC""",
                    (cutoff,),
                ).fetchall()
            ]
            groups = {}
            for event in rows:
                process = (event.get("process") or "").strip()
                remote_ip = (event.get("remote_ip") or "").strip()
                domain = (event.get("domain") or "").strip()
                if process and process != "unknown":
                    key = f"process:{process.lower()}"
                elif remote_ip:
                    key = f"ip:{remote_ip}"
                elif domain:
                    key = f"domain:{domain.lower()}"
                else:
                    continue
                groups.setdefault(key, []).append(event)

            created_or_updated = []
            severity_weight = {"info": 1, "low": 5, "medium": 22, "high": 45}
            for fingerprint, events in groups.items():
                categories = {e["category"] for e in events}
                weighted = sum(severity_weight.get(e["severity"], 2) for e in events)
                score = min(100, weighted + max(0, len(categories) - 1) * 10 + max(0, len(events) - 2) * 2)
                has_attention = any(e["severity"] in {"medium", "high"} for e in events)
                if score < min_score or (not has_attention and len(categories) < 3):
                    continue

                severity = "high" if score >= 65 else "medium" if score >= 35 else "low"
                process = next((e.get("process") for e in events if e.get("process")), None)
                remote_ip = next((e.get("remote_ip") for e in events if e.get("remote_ip")), None)
                domain = next((e.get("domain") for e in events if e.get("domain")), None)
                subject = process or remote_ip or domain or fingerprint
                title = f"Correlated activity: {subject}"
                summary = f"{len(events)} events across {len(categories)} signal types in {window_seconds}s"

                incident = con.execute(
                    """SELECT * FROM incidents
                    WHERE fingerprint=? AND status='open' AND updated_at>=?
                    ORDER BY id DESC LIMIT 1""",
                    (fingerprint, cutoff),
                ).fetchone()
                if incident is None:
                    cur = con.execute(
                        """INSERT INTO incidents(
                            fingerprint,created_at,updated_at,severity,title,summary,process,
                            remote_ip,domain,status,event_count,score
                        ) VALUES(?,?,?,?,?,?,?,?,?,'open',?,?)""",
                        (fingerprint, now, now, severity, title, summary, process, remote_ip, domain, len(events), score),
                    )
                    incident_id = cur.lastrowid
                else:
                    incident_id = incident["id"]
                    score = max(score, int(incident["score"] or 0))
                    con.execute(
                        """UPDATE incidents SET updated_at=?,severity=?,summary=?,event_count=event_count+?,
                        score=?,process=COALESCE(process,?),remote_ip=COALESCE(remote_ip,?),domain=COALESCE(domain,?)
                        WHERE id=?""",
                        (now, severity, summary, len(events), score, process, remote_ip, domain, incident_id),
                    )

                ids = [e["id"] for e in events]
                placeholders = ",".join("?" for _ in ids)
                con.execute(
                    f"UPDATE security_events SET incident_id=? WHERE id IN ({placeholders})",
                    (incident_id, *ids),
                )
                created_or_updated.append(incident_id)
            return created_or_updated

    def close_incident(self, incident_id: int):
        with self.lock, self._conn() as con:
            return con.execute(
                "UPDATE incidents SET status='closed',updated_at=? WHERE id=?",
                (time.time(), incident_id),
            ).rowcount > 0

    def devices(self, online_window=130):
        now = time.time()
        with self._conn() as con:
            rows = [dict(r) for r in con.execute(
                "SELECT * FROM devices ORDER BY is_gateway DESC,last_seen DESC,ip ASC"
            ).fetchall()]
        for row in rows:
            row["is_gateway"] = bool(row.get("is_gateway"))
            row["trusted"] = bool(row.get("trusted"))
            row["online"] = now - row["last_seen"] <= online_window
        return rows

    def alerts(self, limit=150):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()]

    def anomalies(self, limit=100):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                """SELECT * FROM alerts WHERE kind LIKE 'anomaly_%'
                ORDER BY id DESC LIMIT ?""", (limit,)
            ).fetchall()]

    def dns_records(self, limit=250):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM dns_records ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()]

    def communications(self, limit=300):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM communications ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()]

    def flows(self, limit=300):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM flows ORDER BY last_seen DESC LIMIT ?", (limit,)
            ).fetchall()]

    def timeline(self, limit=250):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM security_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()]

    def incidents(self, limit=100, status=None):
        with self._conn() as con:
            if status:
                rows = con.execute(
                    "SELECT * FROM incidents WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def incident_events(self, incident_id: int):
        with self._conn() as con:
            return [dict(r) for r in con.execute(
                "SELECT * FROM security_events WHERE incident_id=? ORDER BY created_at ASC",
                (incident_id,),
            ).fetchall()]

    def baseline_counts(self):
        with self._conn() as con:
            processes = con.execute("SELECT COUNT(*) AS n FROM processes").fetchone()["n"]
            endpoints = con.execute("SELECT COUNT(*) AS n FROM communications").fetchone()["n"]
            domains = con.execute("SELECT COUNT(DISTINCT domain) AS n FROM dns_records").fetchone()["n"]
            flows = con.execute("SELECT COUNT(*) AS n FROM flows").fetchone()["n"]
        return {"processes": processes, "endpoints": endpoints, "domains": domains, "flows": flows}

    def alert_counts(self):
        with self._conn() as con:
            rows = con.execute(
                "SELECT severity,COUNT(*) AS count FROM alerts WHERE acknowledged=0 GROUP BY severity"
            ).fetchall()
        counts = {"low": 0, "medium": 0, "high": 0}
        for row in rows:
            counts[row["severity"]] = row["count"]
        return counts

    def open_anomaly_count(self):
        with self._conn() as con:
            return con.execute(
                """SELECT COUNT(*) AS n FROM alerts
                WHERE acknowledged=0 AND kind LIKE 'anomaly_%'"""
            ).fetchone()["n"]

    def open_incident_count(self):
        with self._conn() as con:
            return con.execute("SELECT COUNT(*) AS n FROM incidents WHERE status='open'").fetchone()["n"]

    def prune_history(self, retention_days: int):
        cutoff = time.time() - retention_days * 86400
        with self.lock, self._conn() as con:
            dns_deleted = con.execute("DELETE FROM dns_records WHERE last_seen<?", (cutoff,)).rowcount
            comm_deleted = con.execute("DELETE FROM communications WHERE last_seen<?", (cutoff,)).rowcount
            flow_deleted = con.execute("DELETE FROM flows WHERE last_seen<?", (cutoff,)).rowcount
            sample_deleted = con.execute("DELETE FROM device_samples WHERE observed_at<?", (cutoff,)).rowcount
            event_deleted = con.execute(
                "DELETE FROM security_events WHERE created_at<? AND incident_id IS NULL", (cutoff,)
            ).rowcount
        return {
            "dns": dns_deleted,
            "communications": comm_deleted,
            "flows": flow_deleted,
            "device_samples": sample_deleted,
            "events": event_deleted,
        }
