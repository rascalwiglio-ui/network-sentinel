from collections import deque
import threading


class RuntimeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.traffic_history = deque(maxlen=300)
        self.data = {
            "running": False,
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


runtime = RuntimeState()
