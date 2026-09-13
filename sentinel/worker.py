import threading
import time
import traceback

from .collectors.arp import collect_arp
from .collectors.dns import collect_dns_cache
from .collectors.host import collect_connections, collect_listeners, network_counters
from .collectors.network import discover_network
from .detectors import process_connection_spike, process_devices, process_listeners
from .intelligence import process_communications, process_dns_records
from .state import runtime


class MonitorWorker(threading.Thread):
    daemon = True

    def __init__(
        self,
        storage,
        interval,
        connection_spike_threshold,
        baseline_warmup_seconds,
        process_fanout_threshold,
        endpoint_churn_threshold,
    ):
        super().__init__(name="network-sentinel-monitor")
        self.storage = storage
        self.interval = interval
        self.connection_spike_threshold = connection_spike_threshold
        self.baseline_warmup_seconds = baseline_warmup_seconds
        self.process_fanout_threshold = process_fanout_threshold
        self.endpoint_churn_threshold = endpoint_churn_threshold
        self.stop_event = threading.Event()
        self.previous_connection_count = None
        self.previous_counters = None

    def stop(self):
        self.stop_event.set()

    def _traffic_rate(self, counters):
        rx_bps = 0.0
        tx_bps = 0.0
        if self.previous_counters:
            elapsed = max(
                counters["timestamp"] - self.previous_counters["timestamp"],
                0.001,
            )
            rx_bps = max(
                (counters["bytes_recv"] - self.previous_counters["bytes_recv"]) / elapsed,
                0.0,
            )
            tx_bps = max(
                (counters["bytes_sent"] - self.previous_counters["bytes_sent"]) / elapsed,
                0.0,
            )
        self.previous_counters = counters
        return rx_bps, tx_bps

    def run(self):
        runtime.update(running=True)
        while not self.stop_event.is_set():
            try:
                connections = collect_connections()
                listeners = collect_listeners(connections)
                counters = network_counters()
                rx_bps, tx_bps = self._traffic_rate(counters)
                baseline_ready, _ = runtime.baseline_status(self.baseline_warmup_seconds)

                process_listeners(self.storage, listeners)
                process_connection_spike(
                    self.storage,
                    len(connections),
                    self.previous_connection_count,
                    self.connection_spike_threshold,
                )
                process_communications(
                    self.storage,
                    connections,
                    baseline_ready=baseline_ready,
                    fanout_threshold=self.process_fanout_threshold,
                    endpoint_churn_threshold=self.endpoint_churn_threshold,
                )
                self.previous_connection_count = len(connections)

                now = time.time()
                runtime.add_traffic(
                    {"timestamp": now, "rx_bps": rx_bps, "tx_bps": tx_bps}
                )
                runtime.update(
                    running=True,
                    last_scan=now,
                    connection_count=len(connections),
                    listeners=listeners,
                    connections=connections[:1000],
                    network=counters,
                    rx_bps=rx_bps,
                    tx_bps=tx_bps,
                    error=None,
                )
            except Exception:
                runtime.update(error=traceback.format_exc(limit=4))

            self.stop_event.wait(self.interval)
        runtime.update(running=False)


class IntelligenceWorker(threading.Thread):
    daemon = True

    def __init__(
        self,
        storage,
        interval,
        baseline_warmup_seconds,
        dns_burst_threshold,
        history_retention_days,
        enabled=True,
    ):
        super().__init__(name="network-sentinel-intelligence")
        self.storage = storage
        self.interval = interval
        self.baseline_warmup_seconds = baseline_warmup_seconds
        self.dns_burst_threshold = dns_burst_threshold
        self.history_retention_days = history_retention_days
        self.enabled = enabled
        self.stop_event = threading.Event()
        self.last_prune = 0.0

    def stop(self):
        self.stop_event.set()

    def run(self):
        runtime.update(intelligence_running=True)
        while not self.stop_event.is_set():
            try:
                baseline_ready, _ = runtime.baseline_status(self.baseline_warmup_seconds)
                now = time.time()

                if self.enabled:
                    records, supported, error = collect_dns_cache()
                    runtime.update(
                        dns_supported=supported,
                        dns_last_scan=now,
                        dns_error=error,
                        dns_records_seen=len(records),
                    )
                    if records:
                        process_dns_records(
                            self.storage,
                            records,
                            baseline_ready=baseline_ready,
                            burst_threshold=self.dns_burst_threshold,
                        )
                else:
                    runtime.update(
                        dns_supported=False,
                        dns_last_scan=now,
                        dns_error="DNS monitoring disabled by configuration",
                        dns_records_seen=0,
                    )

                if now - self.last_prune >= 3600:
                    self.storage.prune_history(self.history_retention_days)
                    self.last_prune = now

                runtime.update(last_intelligence=now, intelligence_running=True)
            except Exception:
                runtime.update(
                    dns_error=traceback.format_exc(limit=4),
                    last_intelligence=time.time(),
                )
            self.stop_event.wait(self.interval)

        runtime.update(intelligence_running=False)


class DiscoveryWorker(threading.Thread):
    daemon = True

    def __init__(self, storage, interval, max_hosts, ping_timeout_ms, active=True):
        super().__init__(name="network-sentinel-discovery")
        self.storage = storage
        self.interval = interval
        self.max_hosts = max_hosts
        self.ping_timeout_ms = ping_timeout_ms
        self.active = active
        self.stop_event = threading.Event()
        self.scan_event = threading.Event()

    def stop(self):
        self.stop_event.set()
        self.scan_event.set()

    def trigger(self):
        self.scan_event.set()

    def _passive_cycle(self):
        devices = []
        for item in collect_arp():
            devices.append(
                {
                    **item,
                    "hostname": None,
                    "vendor": None,
                    "is_gateway": False,
                }
            )
        process_devices(self.storage, devices)

    def _active_cycle(self):
        result = discover_network(
            max_hosts=self.max_hosts,
            timeout_ms=self.ping_timeout_ms,
        )
        if result["error"]:
            runtime.update(
                discovery_error=result["error"],
                network_info=result["network"],
            )
            return
        process_devices(self.storage, result["devices"])
        runtime.update(network_info=result["network"], discovery_error=None)

    def run(self):
        while not self.stop_event.is_set():
            runtime.update(discovery_running=True)
            try:
                if self.active:
                    self._active_cycle()
                else:
                    self._passive_cycle()
                runtime.update(last_discovery=time.time())
            except Exception:
                runtime.update(discovery_error=traceback.format_exc(limit=4))
            finally:
                runtime.update(discovery_running=False)

            self.scan_event.clear()
            self.scan_event.wait(self.interval)
        runtime.update(discovery_running=False)
