from collections import deque
import threading
import time


class RuntimeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.traffic_history = deque(maxlen=300)
        started = time.time()
        self.data = {
            "running": False,
            "started_at": started,
            "last_scan": None,
            "connection_count": 0,
            "listeners": [],
            "connections": [],
            "network": {},
            "network_info": None,
            "rx_bps": 0.0,
            "tx_bps": 0.0,
            "error": None,
            "discovery_running": False,
            "last_discovery": None,
            "discovery_error": None,
            "dns_supported": None,
            "dns_last_scan": None,
            "dns_error": None,
            "dns_records_seen": 0,
            "baseline_ready": False,
            "baseline_remaining": None,
            "intelligence_running": False,
            "last_intelligence": None,
        }

    def update(self, **kwargs):
        with self.lock:
            self.data.update(kwargs)

    def add_traffic(self, point):
        with self.lock:
            self.traffic_history.append(point)

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def traffic(self):
        with self.lock:
            return list(self.traffic_history)

    def baseline_status(self, warmup_seconds: int):
        with self.lock:
            elapsed = max(0.0, time.time() - self.data["started_at"])
            ready = elapsed >= warmup_seconds
            remaining = max(0, int(warmup_seconds - elapsed))
            self.data["baseline_ready"] = ready
            self.data["baseline_remaining"] = remaining
            return ready, remaining


runtime = RuntimeState()
