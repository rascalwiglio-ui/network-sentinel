import threading
import time
import traceback

from .collectors.arp import collect_arp
from .collectors.host import collect_connections, collect_listeners, network_counters
from .detectors import process_devices, process_listeners, process_connection_spike
from .state import runtime

class MonitorWorker(threading.Thread):
    daemon = True

    def __init__(self, storage, interval, connection_spike_threshold):
        super().__init__(name="network-sentinel-monitor")
        self.storage = storage
        self.interval = interval
        self.connection_spike_threshold = connection_spike_threshold
        self.stop_event = threading.Event()
        self.previous_connection_count = None

    def stop(self):
        self.stop_event.set()

    def run(self):
        runtime.update(running=True)
        while not self.stop_event.is_set():
            try:
                devices = collect_arp()
                connections = collect_connections()
                listeners = collect_listeners(connections)
                counters = network_counters()

                process_devices(self.storage, devices)
                process_listeners(self.storage, listeners)
                process_connection_spike(
                    self.storage,
                    len(connections),
                    self.previous_connection_count,
                    self.connection_spike_threshold,
                )

                self.previous_connection_count = len(connections)

                runtime.update(
                    running=True,
                    last_scan=time.time(),
                    connection_count=len(connections),
                    listeners=listeners,
                    connections=connections[:1000],
                    network=counters,
                    error=None,
                )

            except Exception:
                runtime.update(error=traceback.format_exc(limit=3))

            self.stop_event.wait(self.interval)

        runtime.update(running=False)
