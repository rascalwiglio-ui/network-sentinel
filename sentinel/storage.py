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
                con.execute(
                    f"ALTER TABLE devices ADD COLUMN {name} {definition}"
                )

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
            old = con.execute(
                "SELECT * FROM devices WHERE ip=?",
                (ip,),
            ).fetchone()

            if old is None:
                con.execute(
                    """
                    INSERT INTO devices(
                        ip,mac,interface,hostname,vendor,is_gateway,trusted,
                        first_seen,last_seen
                    )
                    VALUES(?,?,?,?,?,?,?,?,?)
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
                return {
                    "status": "new",
                    "old_mac": None,
                    "new_mac": mac,
                }

            old_mac = old["mac"]
            mac_changed = bool(
                old_mac
                and mac
                and old_mac.lower() != mac.lower()
            )

            con.execute(
                """
                UPDATE devices
                SET
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
                """
                SELECT * FROM listeners
                WHERE proto=? AND ip=? AND port=?
                """,
                (proto, ip, port),
            ).fetchone()

            if old is None:
                con.execute(
                    """
                    INSERT INTO listeners(
                        proto,ip,port,pid,process,first_seen,last_seen
                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (proto, ip, port, pid, process, now, now),
                )
                return True

            con.execute(
                """
                UPDATE listeners
                SET pid=?, process=?, last_seen=?
                WHERE proto=? AND ip=? AND port=?
                """,
                (pid, process, now, proto, ip, port),
            )
            return False

    def add_alert(self, severity, kind, title, details):
        with self.lock, self._conn() as con:
            con.execute(
                """
                INSERT INTO alerts(
                    created_at,severity,kind,title,details
                )
                VALUES(?,?,?,?,?)
                """,
                (time.time(), severity, kind, title, details),
            )

    def acknowledge_alert(self, alert_id):
        with self.lock, self._conn() as con:
            con.execute(
                "UPDATE alerts SET acknowledged=1 WHERE id=?",
                (alert_id,),
            )

    def acknowledge_all_alerts(self):
        with self.lock, self._conn() as con:
            cursor = con.execute(
                "UPDATE alerts SET acknowledged=1 WHERE acknowledged=0"
            )
            return cursor.rowcount

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

    def alerts(self, limit=100):
        with self._conn() as con:
            return [
                dict(r)
                for r in con.execute(
                    """
                    SELECT * FROM alerts
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            ]

    def alert_counts(self):
        with self._conn() as con:
            rows = con.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts
                WHERE acknowledged=0
                GROUP BY severity
                """
            ).fetchall()
        counts = {"low": 0, "medium": 0, "high": 0}
        for row in rows:
            counts[row["severity"]] = row["count"]
        return counts
