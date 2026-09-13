import threading

class RuntimeState:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {
            "running": False,
            "last_scan": None,
            "connection_count": 0,
            "listeners": [],
            "connections": [],
            "network": {},
            "error": None,
        }

    def update(self, **kwargs):
        with self.lock:
            self.data.update(kwargs)

    def snapshot(self):
        with self.lock:
            return dict(self.data)

runtime = RuntimeState()
