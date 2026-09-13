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

CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_kind_created ON alerts(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_last_seen ON dns_records(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_comm_last_seen ON communications(last_seen DESC);
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
        self.lock = threading.Lock()
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
        cols = {
            row["name"]
            for row in con.execute("PRAGMA table_info(devices)").fetchall()
        }
        for name, definition in _DEVICE_COLUMNS.items():
            if name not in cols:
                con.execute(f"ALTER TABLE devices ADD COLUMN {name} {definition}")

    def upsert_device(
        self,
        ip,
        mac,
        interface,
        hostname=None,
        vendor=None,
        is_gateway=False,
    ):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()

            if old is None:
                con.execute(
                    """
                    INSERT INTO devices(
                        ip,mac,interface,hostname,vendor,is_gateway,trusted,
                        first_seen,last_seen
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ip,
                        mac,
                        interface,
                        hostname,
                        vendor,
                        int(bool(is_gateway)),
                        0,
                        now,
                        now,
                    ),
                )
                return {"status": "new", "old_mac": None, "new_mac": mac}

            old_mac = old["mac"]
            mac_changed = bool(old_mac and mac and old_mac.lower() != mac.lower())
            con.execute(
                """
                UPDATE devices SET
                    mac=COALESCE(?, mac),
                    interface=COALESCE(?, interface),
                    hostname=COALESCE(?, hostname),
                    vendor=COALESCE(?, vendor),
                    is_gateway=?,
                    last_seen=?
                WHERE ip=?
                """,
                (
                    mac,
                    interface,
                    hostname,
                    vendor,
                    int(bool(is_gateway)),
                    now,
                    ip,
                ),
            )
            return {
                "status": "mac_changed" if mac_changed else "seen",
                "old_mac": old_mac,
                "new_mac": mac,
            }

    def set_device_trusted(self, ip: str, trusted: bool):
        with self.lock, self._conn() as con:
            cursor = con.execute(
                "UPDATE devices SET trusted=? WHERE ip=?",
                (int(bool(trusted)), ip),
            )
            return cursor.rowcount > 0

    def upsert_listener(self, proto, ip, port, pid, process):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute(
                "SELECT 1 FROM listeners WHERE proto=? AND ip=? AND port=?",
                (proto, ip, port),
            ).fetchone()
            if old is None:
                con.execute(
                    """
                    INSERT INTO listeners(proto,ip,port,pid,process,first_seen,last_seen)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (proto, ip, port, pid, process, now, now),
                )
                return True
            con.execute(
                """
                UPDATE listeners SET pid=?, process=?, last_seen=?
                WHERE proto=? AND ip=? AND port=?
                """,
                (pid, process, now, proto, ip, port),
            )
            return False

    def add_alert(self, severity, kind, title, details):
        with self.lock, self._conn() as con:
            con.execute(
                """
                INSERT INTO alerts(created_at,severity,kind,title,details)
                VALUES(?,?,?,?,?)
                """,
                (time.time(), severity, kind, title, details),
            )

    def recent_alert(self, kind: str, title: str, cooldown_seconds: int) -> bool:
        cutoff = time.time() - cooldown_seconds
        with self._conn() as con:
            row = con.execute(
                """
                SELECT 1 FROM alerts
                WHERE kind=? AND title=? AND created_at>=?
                LIMIT 1
                """,
                (kind, title, cutoff),
            ).fetchone()
            return row is not None

    def acknowledge_alert(self, alert_id):
        with self.lock, self._conn() as con:
            con.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def acknowledge_all_alerts(self):
        with self.lock, self._conn() as con:
            cursor = con.execute("UPDATE alerts SET acknowledged=1 WHERE acknowledged=0")
            return cursor.rowcount

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
                """
                SELECT 1 FROM dns_records
                WHERE domain=? AND record_type=? AND data=?
                """,
                (domain, record_type, data),
            ).fetchone()
            if old is None:
                con.execute(
                    """
                    INSERT INTO dns_records(
                        domain,record_type,data,ttl,first_seen,last_seen,seen_count
                    ) VALUES(?,?,?,?,?,?,1)
                    """,
                    (domain, record_type, data, ttl, now, now),
                )
                return True

            con.execute(
                """
                UPDATE dns_records
                SET ttl=?, last_seen=?, seen_count=seen_count+1
                WHERE domain=? AND record_type=? AND data=?
                """,
                (ttl, now, domain, record_type, data),
            )
            return False

    def upsert_communication(self, item: dict) -> dict:
        now = time.time()
        process = str(item.get("process") or "unknown")
        proto = str(item.get("proto") or "?")
        remote_ip = str(item.get("remote_ip") or "")
        remote_port = int(item.get("remote_port") or 0)

        with self.lock, self._conn() as con:
            process_old = con.execute(
                "SELECT 1 FROM processes WHERE process=?",
                (process,),
            ).fetchone()
            if process_old is None:
                con.execute(
                    """
                    INSERT INTO processes(process,first_seen,last_seen,seen_count)
                    VALUES(?,?,?,1)
                    """,
                    (process, now, now),
                )
            else:
                con.execute(
                    """
                    UPDATE processes SET last_seen=?, seen_count=seen_count+1
                    WHERE process=?
                    """,
                    (now, process),
                )

            endpoint_old = con.execute(
                """
                SELECT 1 FROM communications
                WHERE process=? AND proto=? AND remote_ip=? AND remote_port=?
                """,
                (process, proto, remote_ip, remote_port),
            ).fetchone()
            if endpoint_old is None:
                con.execute(
                    """
                    INSERT INTO communications(
                        process,proto,remote_ip,remote_port,first_seen,last_seen,seen_count
                    ) VALUES(?,?,?,?,?,?,1)
                    """,
                    (process, proto, remote_ip, remote_port, now, now),
                )
            else:
                con.execute(
                    """
                    UPDATE communications
                    SET last_seen=?, seen_count=seen_count+1
                    WHERE process=? AND proto=? AND remote_ip=? AND remote_port=?
                    """,
                    (now, process, proto, remote_ip, remote_port),
                )

            return {
                "new_process": process_old is None,
                "new_endpoint": endpoint_old is None,
            }

    def devices(self, online_window=130):
        now = time.time()
        with self._conn() as con:
            rows = [
                dict(r)
                for r in con.execute(
                    """
                    SELECT * FROM devices
                    ORDER BY is_gateway DESC, last_seen DESC, ip ASC
                    """
                ).fetchall()
            ]
        for row in rows:
            row["is_gateway"] = bool(row.get("is_gateway"))
            row["trusted"] = bool(row.get("trusted"))
            row["online"] = now - row["last_seen"] <= online_window
        return rows

    def alerts(self, limit=150):
        with self._conn() as con:
            return [
                dict(r)
                for r in con.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]

    def anomalies(self, limit=100):
        with self._conn() as con:
            return [
                dict(r)
                for r in con.execute(
                    """
                    SELECT * FROM alerts
                    WHERE kind LIKE 'anomaly_%'
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]

    def dns_records(self, limit=250):
        with self._conn() as con:
            return [
                dict(r)
                for r in con.execute(
                    """
                    SELECT * FROM dns_records
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]

    def communications(self, limit=300):
        with self._conn() as con:
            return [
                dict(r)
                for r in con.execute(
                    """
                    SELECT * FROM communications
                    ORDER BY last_seen DESC LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]

    def baseline_counts(self):
        with self._conn() as con:
            processes = con.execute("SELECT COUNT(*) AS n FROM processes").fetchone()["n"]
            endpoints = con.execute("SELECT COUNT(*) AS n FROM communications").fetchone()["n"]
            domains = con.execute("SELECT COUNT(DISTINCT domain) AS n FROM dns_records").fetchone()["n"]
        return {
            "processes": processes,
            "endpoints": endpoints,
            "domains": domains,
        }

    def alert_counts(self):
        with self._conn() as con:
            rows = con.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts WHERE acknowledged=0
                GROUP BY severity
                """
            ).fetchall()
        counts = {"low": 0, "medium": 0, "high": 0}
        for row in rows:
            counts[row["severity"]] = row["count"]
        return counts

    def open_anomaly_count(self):
        with self._conn() as con:
            row = con.execute(
                """
                SELECT COUNT(*) AS n FROM alerts
                WHERE acknowledged=0 AND kind LIKE 'anomaly_%'
                """
            ).fetchone()
            return row["n"]

    def prune_history(self, retention_days: int):
        cutoff = time.time() - retention_days * 86400
        with self.lock, self._conn() as con:
            dns_deleted = con.execute(
                "DELETE FROM dns_records WHERE last_seen<?",
                (cutoff,),
            ).rowcount
            comm_deleted = con.execute(
                "DELETE FROM communications WHERE last_seen<?",
                (cutoff,),
            ).rowcount
        return {"dns": dns_deleted, "communications": comm_deleted}
