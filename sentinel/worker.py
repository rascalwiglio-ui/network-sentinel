import threading
import time
import traceback

from .collectors.arp import collect_arp
from .collectors.dns import collect_dns_cache
from .collectors.device_probe import parse_ports, probe_devices
from .collectors.host import collect_connections, collect_listeners, network_counters
from .collectors.network import discover_network
from .collectors.packet import match_process, normalized_packet
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
            elapsed = max(counters["timestamp"] - self.previous_counters["timestamp"], 0.001)
            rx_bps = max((counters["bytes_recv"] - self.previous_counters["bytes_recv"]) / elapsed, 0.0)
            tx_bps = max((counters["bytes_sent"] - self.previous_counters["bytes_sent"]) / elapsed, 0.0)
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
                runtime.add_traffic({"timestamp": now, "rx_bps": rx_bps, "tx_bps": tx_bps})
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
        incident_window_seconds,
        incident_min_score,
        enabled=True,
    ):
        super().__init__(name="network-sentinel-intelligence")
        self.storage = storage
        self.interval = interval
        self.baseline_warmup_seconds = baseline_warmup_seconds
        self.dns_burst_threshold = dns_burst_threshold
        self.history_retention_days = history_retention_days
        self.incident_window_seconds = incident_window_seconds
        self.incident_min_score = incident_min_score
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

                self.storage.correlate_incidents(
                    window_seconds=self.incident_window_seconds,
                    min_score=self.incident_min_score,
                )
                runtime.update(last_correlation=now)

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


class PacketCaptureWorker(threading.Thread):
    """Optional metadata-only packet sensor. It never stores packet payload bytes."""

    daemon = True

    def __init__(self, storage, enabled=False, interface="", bpf_filter="ip"):
        super().__init__(name="network-sentinel-capture")
        self.storage = storage
        self.enabled = enabled
        self.interface = interface or None
        self.bpf_filter = bpf_filter or "ip"
        self.stop_event = threading.Event()
        self.recent_dns = {}
        self.device_ips = set()
        self.device_ips_refreshed = 0.0

    def stop(self):
        self.stop_event.set()

    def _handle_packet(self, packet):
        state = runtime.snapshot()
        local_ips = set()
        network_info = state.get("network_info") or {}
        if network_info.get("local_ip"):
            local_ips.add(network_info["local_ip"])

        flow = normalized_packet(packet, local_ips=local_ips or None)
        if not flow:
            return

        connections = state.get("connections") or []
        process, pid = match_process(flow, connections)
        flow["process"] = process or "unknown"
        flow["pid"] = pid
        self.storage.record_flow(flow)

        now = time.time()
        if now - self.device_ips_refreshed >= 15:
            self.device_ips = self.storage.known_device_ips()
            self.device_ips_refreshed = now
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        packet_size = flow.get("length") or 0
        if src_ip in self.device_ips:
            self.storage.record_device_packet(src_ip, "from", packet_size, observed_at=now)
        if dst_ip in self.device_ips:
            self.storage.record_device_packet(dst_ip, "to", packet_size, observed_at=now)

        dns_count = 0
        for event in flow.get("dns_events") or []:
            domain = event.get("domain") or ""
            answer = event.get("answer")
            if not domain:
                continue

            # Packet DNS answers enrich the same DNS baseline used by cache telemetry.
            if answer:
                self.storage.upsert_dns_record(
                    {
                        "domain": domain,
                        "record_type": "PACKET",
                        "data": answer,
                        "ttl": None,
                    }
                )

            # Timeline is intentionally rate-limited to avoid logging every DNS packet.
            last = self.recent_dns.get((domain, answer), 0)
            if now - last >= 60:
                self.storage.record_dns_event(domain, answer, source="wire")
                self.recent_dns[(domain, answer)] = now
                dns_count += 1

        runtime.increment_capture(
            packets=1,
            bytes_count=flow.get("length") or 0,
            dns_events=dns_count,
        )

    def run(self):
        runtime.update(
            capture_enabled=self.enabled,
            capture_running=False,
            capture_interface=self.interface,
        )
        if not self.enabled:
            runtime.update(
                capture_available=None,
                capture_error="Packet capture disabled. Use scripts/run-capture.cmd to enable it.",
            )
            return

        try:
            from scapy.all import sniff
        except Exception as exc:
            runtime.update(
                capture_available=False,
                capture_error=f"Scapy unavailable: {exc}. Run scripts/enable-capture.cmd.",
            )
            return

        runtime.update(capture_available=True, capture_running=True, capture_error=None)
        while not self.stop_event.is_set():
            try:
                kwargs = {
                    "store": False,
                    "prn": self._handle_packet,
                    "timeout": 1,
                }
                if self.interface:
                    kwargs["iface"] = self.interface
                if self.bpf_filter:
                    kwargs["filter"] = self.bpf_filter
                sniff(**kwargs)
            except Exception as exc:
                runtime.update(
                    capture_available=False,
                    capture_running=False,
                    capture_error=(
                        f"Packet capture failed: {exc}. On Windows install Npcap; "
                        "on Linux run with capture privileges."
                    ),
                )
                return

        runtime.update(capture_running=False)


class FleetWorker(threading.Thread):
    """Agentless health/service monitoring for known private-LAN devices."""

    daemon = True

    def __init__(
        self,
        storage,
        enabled=True,
        interval=45,
        timeout_ms=250,
        service_ports="",
        max_workers=8,
        online_window=130,
    ):
        super().__init__(name="network-sentinel-fleet")
        self.storage = storage
        self.enabled = enabled
        self.interval = interval
        self.timeout_ms = timeout_ms
        self.ports = parse_ports(service_ports)
        self.max_workers = max_workers
        self.online_window = online_window
        self.stop_event = threading.Event()
        self.scan_event = threading.Event()
        self.queue_lock = threading.Lock()
        self.manual_targets = set()

    def stop(self):
        self.stop_event.set()
        self.scan_event.set()

    def trigger(self, ip=None):
        if ip:
            with self.queue_lock:
                self.manual_targets.add(str(ip))
        self.scan_event.set()

    def _take_targets(self):
        with self.queue_lock:
            targets = set(self.manual_targets)
            self.manual_targets.clear()
        devices = self.storage.devices(self.online_window)
        if targets:
            return [d for d in devices if d.get("ip") in targets]
        return devices

    def run(self):
        runtime.update(
            fleet_enabled=self.enabled,
            fleet_running=False,
            fleet_probe_interval=self.interval,
        )
        if not self.enabled:
            runtime.update(fleet_error="Fleet monitoring disabled by configuration")
            return

        while not self.stop_event.is_set():
            started = time.perf_counter()
            results = []
            runtime.update(fleet_running=True, fleet_error=None)
            try:
                targets = self._take_targets()
                results = probe_devices(
                    targets,
                    self.ports,
                    timeout_ms=self.timeout_ms,
                    max_workers=self.max_workers,
                )
                for result in results:
                    self.storage.record_device_probe(result)

                summary = self.storage.fleet_summary(self.online_window)
                duration_ms = round((time.perf_counter() - started) * 1000, 1)
                runtime.update(
                    last_fleet_scan=time.time(),
                    fleet_targets=len(results),
                    fleet_reachable=sum(1 for r in results if r.get("online")),
                    fleet_services=sum(len(r.get("services") or []) for r in results),
                    fleet_last_duration_ms=duration_ms,
                    fleet_manual_queue=0,
                    fleet_error=None,
                    **{f"fleet_summary_{k}": v for k, v in summary.items()},
                )
            except Exception:
                runtime.update(fleet_error=traceback.format_exc(limit=4))
            finally:
                runtime.update(fleet_running=False)

            self.scan_event.clear()
            self.scan_event.wait(5 if not results else self.interval)

        runtime.update(fleet_running=False)


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
            devices.append({**item, "hostname": None, "vendor": None, "is_gateway": False})
        process_devices(self.storage, devices)

    def _active_cycle(self):
        result = discover_network(max_hosts=self.max_hosts, timeout_ms=self.ping_timeout_ms)
        if result["error"]:
            runtime.update(discovery_error=result["error"], network_info=result["network"])
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
