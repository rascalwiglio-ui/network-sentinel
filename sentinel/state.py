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
            "capture_enabled": False,
            "capture_running": False,
            "capture_available": None,
            "capture_error": None,
            "capture_interface": None,
            "capture_packets": 0,
            "capture_bytes": 0,
            "capture_dns_events": 0,
            "last_capture": None,
            "last_correlation": None,
            "fleet_enabled": False,
            "fleet_running": False,
            "last_fleet_scan": None,
            "fleet_error": None,
            "fleet_targets": 0,
            "fleet_reachable": 0,
            "fleet_services": 0,
            "fleet_probe_interval": None,
            "fleet_last_duration_ms": None,
            "fleet_manual_queue": 0,
        }

    def update(self, **kwargs):
        with self.lock:
            self.data.update(kwargs)

    def increment_capture(self, packets=0, bytes_count=0, dns_events=0):
        with self.lock:
            self.data["capture_packets"] += packets
            self.data["capture_bytes"] += bytes_count
            self.data["capture_dns_events"] += dns_events
            self.data["last_capture"] = time.time()

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
