import sqlite3
import threading
import time
from contextlib import contextmanager

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
    ip TEXT PRIMARY KEY,
    mac TEXT,
    interface TEXT,
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

class Storage:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        with self._conn() as con:
            con.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def upsert_device(self, ip, mac, interface):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute(
                "SELECT * FROM devices WHERE ip=?", (ip,)
            ).fetchone()
            if old is None:
                con.execute(
                    "INSERT INTO devices(ip,mac,interface,first_seen,last_seen) VALUES(?,?,?,?,?)",
                    (ip, mac, interface, now, now)
                )
                return True
            con.execute(
                "UPDATE devices SET mac=?, interface=?, last_seen=? WHERE ip=?",
                (mac, interface, now, ip)
            )
            return False

    def upsert_listener(self, proto, ip, port, pid, process):
        now = time.time()
        with self.lock, self._conn() as con:
            old = con.execute(
                "SELECT * FROM listeners WHERE proto=? AND ip=? AND port=?",
                (proto, ip, port)
            ).fetchone()
            if old is None:
                con.execute(
                    """
                    INSERT INTO listeners
                    (proto,ip,port,pid,process,first_seen,last_seen)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (proto, ip, port, pid, process, now, now)
                )
                return True
            con.execute(
                """
                UPDATE listeners
                SET pid=?, process=?, last_seen=?
                WHERE proto=? AND ip=? AND port=?
                """,
                (pid, process, now, proto, ip, port)
            )
            return False

    def add_alert(self, severity, kind, title, details):
        with self.lock, self._conn() as con:
            con.execute(
                """
                INSERT INTO alerts(created_at,severity,kind,title,details)
                VALUES(?,?,?,?,?)
                """,
                (time.time(), severity, kind, title, details)
            )

    def acknowledge_alert(self, alert_id):
        with self.lock, self._conn() as con:
            con.execute(
                "UPDATE alerts SET acknowledged=1 WHERE id=?",
                (alert_id,)
            )

    def devices(self):
        with self._conn() as con:
            return [
                dict(r) for r in con.execute(
                    "SELECT * FROM devices ORDER BY last_seen DESC"
                ).fetchall()
            ]

    def alerts(self, limit=100):
        with self._conn() as con:
            return [
                dict(r) for r in con.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            ]
