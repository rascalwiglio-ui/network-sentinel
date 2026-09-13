from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .intelligence import device_risk
from .state import runtime
from .storage import Storage
from .worker import DiscoveryWorker, FleetWorker, IntelligenceWorker, MonitorWorker, PacketCaptureWorker


VERSION = "0.6.0"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
storage = Storage(settings.db_path)

app = FastAPI(
    title="Network Sentinel",
    version=VERSION,
    docs_url="/docs",
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

monitor_worker = MonitorWorker(
    storage=storage,
    interval=settings.interval,
    connection_spike_threshold=settings.connection_spike_threshold,
    baseline_warmup_seconds=settings.baseline_warmup_seconds,
    process_fanout_threshold=settings.process_fanout_threshold,
    endpoint_churn_threshold=settings.endpoint_churn_threshold,
)

discovery_worker = DiscoveryWorker(
    storage=storage,
    interval=settings.discovery_interval,
    max_hosts=settings.max_discovery_hosts,
    ping_timeout_ms=settings.ping_timeout_ms,
    active=settings.active_discovery,
)

fleet_worker = FleetWorker(
    storage=storage,
    enabled=settings.device_monitoring,
    interval=settings.device_probe_interval,
    timeout_ms=settings.device_probe_timeout_ms,
    service_ports=settings.device_service_ports,
    max_workers=settings.device_probe_workers,
    online_window=settings.device_online_window,
)

intelligence_worker = IntelligenceWorker(
    storage=storage,
    interval=settings.dns_interval,
    baseline_warmup_seconds=settings.baseline_warmup_seconds,
    dns_burst_threshold=settings.dns_burst_threshold,
    history_retention_days=settings.history_retention_days,
    incident_window_seconds=settings.incident_window_seconds,
    incident_min_score=settings.incident_min_score,
    enabled=settings.dns_monitoring,
)

capture_worker = PacketCaptureWorker(
    storage=storage,
    enabled=settings.packet_capture,
    interface=settings.capture_interface,
    bpf_filter=settings.capture_bpf,
)


@app.on_event("startup")
def startup():
    if not monitor_worker.is_alive():
        monitor_worker.start()
    if not discovery_worker.is_alive():
        discovery_worker.start()
    if not fleet_worker.is_alive():
        fleet_worker.start()
    if not intelligence_worker.is_alive():
        intelligence_worker.start()
    if not capture_worker.is_alive():
        capture_worker.start()


@app.on_event("shutdown")
def shutdown():
    monitor_worker.stop()
    discovery_worker.stop()
    fleet_worker.stop()
    intelligence_worker.stop()
    capture_worker.stop()


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status():
    runtime.baseline_status(settings.baseline_warmup_seconds)
    data = runtime.snapshot()
    data["active_discovery"] = settings.active_discovery
    data["dns_monitoring"] = settings.dns_monitoring
    data["packet_capture_configured"] = settings.packet_capture
    data["device_monitoring"] = settings.device_monitoring
    data["version"] = VERSION
    return data


def _devices_with_risk():
    devices = storage.device_profiles(settings.device_online_window)
    for device in devices:
        device["risk"] = device_risk(device)
    return devices


@app.get("/api/overview")
def overview():
    devices = _devices_with_risk()
    alerts = storage.alert_counts()
    state = runtime.snapshot()
    baseline = storage.baseline_counts()
    fleet = storage.fleet_summary(settings.device_online_window)

    online = [d for d in devices if d["online"]]
    unknown_online = [d for d in online if not d["trusted"] and not d["is_gateway"]]
    risky_online = [d for d in online if d["risk"]["score"] >= 30]
    anomaly_count = storage.open_anomaly_count()
    incident_count = storage.open_incident_count()
    open_alerts = alerts["low"] + alerts["medium"] + alerts["high"]

    # Transparent attention heuristic; not a probability of compromise.
    score = 100
    score -= alerts["high"] * 18
    score -= alerts["medium"] * 6
    score -= alerts["low"] * 2
    score -= len(unknown_online) * 2
    score -= min(anomaly_count * 4, 20)
    score -= min(incident_count * 8, 28)
    score = max(0, min(100, score))

    return {
        "sentinel_score": score,
        "score_kind": "attention_heuristic",
        "devices_total": len(devices),
        "devices_online": len(online),
        "devices_untrusted_online": len(unknown_online),
        "devices_risky_online": len(risky_online),
        "listeners": len(state["listeners"]),
        "connections": state["connection_count"],
        "alerts_open": open_alerts,
        "alerts_high": alerts["high"],
        "alerts_medium": alerts["medium"],
        "alerts_low": alerts["low"],
        "anomalies_open": anomaly_count,
        "incidents_open": incident_count,
        "known_processes": baseline["processes"],
        "known_endpoints": baseline["endpoints"],
        "known_domains": baseline["domains"],
        "known_flows": baseline["flows"],
        "rx_bps": state["rx_bps"],
        "tx_bps": state["tx_bps"],
        "capture_packets": state["capture_packets"],
        "capture_bytes": state["capture_bytes"],
        "fleet_known": fleet["known"],
        "fleet_monitored": fleet["monitored"],
        "fleet_reachable": fleet["reachable"],
        "fleet_unreachable": fleet["unreachable"],
        "fleet_active_services": fleet["active_services"],
        "fleet_traffic_seen_recently": fleet["traffic_seen_recently"],
    }


@app.get("/api/network")
def network():
    return runtime.snapshot()["network_info"] or {}


@app.get("/api/devices")
def devices():
    return _devices_with_risk()


@app.get("/api/fleet")
def fleet():
    state = runtime.snapshot()
    summary = storage.fleet_summary(settings.device_online_window)
    return {
        **summary,
        "enabled": settings.device_monitoring,
        "running": state["fleet_running"],
        "last_scan": state["last_fleet_scan"],
        "last_duration_ms": state["fleet_last_duration_ms"],
        "probe_interval": settings.device_probe_interval,
        "probe_timeout_ms": settings.device_probe_timeout_ms,
        "service_ports": [int(x) for x in settings.device_service_ports.split(",") if x.strip().isdigit()],
        "error": state["fleet_error"],
        "traffic_visibility": "sensor-observed only; switched LAN traffic may be invisible without router/SPAN telemetry",
    }


@app.post("/api/fleet/scan")
def fleet_scan():
    fleet_worker.trigger()
    return {"ok": True, "queued": True}


@app.get("/api/devices/{ip}/profile")
def device_profile(ip: str):
    device = storage.device_profile(ip, settings.device_online_window)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    device["risk"] = device_risk(device)
    device["services"] = storage.device_services(ip, active_only=False)
    device["traffic"] = storage.device_traffic(ip)
    return device


@app.get("/api/devices/{ip}/history")
def device_history(ip: str, limit: int = Query(120, ge=1, le=1000)):
    if storage.device_profile(ip, settings.device_online_window) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return storage.device_history(ip, limit)


@app.get("/api/devices/{ip}/services")
def device_services(ip: str):
    if storage.device_profile(ip, settings.device_online_window) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return storage.device_services(ip)


@app.get("/api/devices/{ip}/traffic")
def device_traffic(ip: str):
    if storage.device_profile(ip, settings.device_online_window) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return storage.device_traffic(ip)


@app.post("/api/devices/{ip}/probe")
def probe_device_now(ip: str):
    if storage.device_profile(ip, settings.device_online_window) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    fleet_worker.trigger(ip)
    return {"ok": True, "ip": ip, "queued": True}


@app.post("/api/devices/{ip}/trust")
def trust_device(ip: str, trusted: bool = True):
    if not storage.set_device_trusted(ip, trusted):
        raise HTTPException(status_code=404, detail="Device not found")
    return {"ok": True, "ip": ip, "trusted": trusted}


@app.get("/api/listeners")
def listeners():
    return runtime.snapshot()["listeners"]


@app.get("/api/connections")
def connections():
    return runtime.snapshot()["connections"]


@app.get("/api/traffic")
def traffic():
    return runtime.traffic()


@app.get("/api/dns")
def dns_records(limit: int = Query(200, ge=1, le=1000)):
    return storage.dns_records(limit)


@app.get("/api/communications")
def communications(limit: int = Query(250, ge=1, le=1000)):
    return storage.communications(limit)


@app.get("/api/flows")
def flows(limit: int = Query(300, ge=1, le=2000)):
    return storage.flows(limit)


@app.get("/api/timeline")
def timeline(limit: int = Query(250, ge=1, le=1500)):
    return storage.timeline(limit)


@app.get("/api/incidents")
def incidents(
    limit: int = Query(100, ge=1, le=500),
    status: str | None = Query(None, pattern="^(open|closed)$"),
):
    return storage.incidents(limit=limit, status=status)


@app.get("/api/incidents/{incident_id}/events")
def incident_events(incident_id: int):
    return storage.incident_events(incident_id)


@app.post("/api/incidents/{incident_id}/close")
def close_incident(incident_id: int):
    if not storage.close_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"ok": True, "id": incident_id, "status": "closed"}


@app.get("/api/capture")
def capture_status():
    state = runtime.snapshot()
    return {
        "configured": settings.packet_capture,
        "enabled": state["capture_enabled"],
        "running": state["capture_running"],
        "available": state["capture_available"],
        "error": state["capture_error"],
        "interface": state["capture_interface"],
        "packets": state["capture_packets"],
        "bytes": state["capture_bytes"],
        "dns_events": state["capture_dns_events"],
        "last_capture": state["last_capture"],
        "metadata_only": True,
    }


@app.get("/api/anomalies")
def anomalies(limit: int = Query(100, ge=1, le=500)):
    return storage.anomalies(limit)


@app.get("/api/baseline")
def baseline():
    ready, remaining = runtime.baseline_status(settings.baseline_warmup_seconds)
    state = runtime.snapshot()
    return {
        "ready": ready,
        "remaining_seconds": remaining,
        "warmup_seconds": settings.baseline_warmup_seconds,
        "started_at": state["started_at"],
        "counts": storage.baseline_counts(),
        "dns_supported": state["dns_supported"],
        "dns_last_scan": state["dns_last_scan"],
        "dns_error": state["dns_error"],
        "history_retention_days": settings.history_retention_days,
        "process_fanout_threshold": settings.process_fanout_threshold,
        "endpoint_churn_threshold": settings.endpoint_churn_threshold,
        "incident_window_seconds": settings.incident_window_seconds,
        "incident_min_score": settings.incident_min_score,
    }


@app.get("/api/alerts")
def alerts():
    return storage.alerts(150)


@app.post("/api/alerts/{alert_id}/ack")
def ack(alert_id: int):
    storage.acknowledge_alert(alert_id)
    return {"ok": True, "id": alert_id}


@app.post("/api/alerts/ack-all")
def ack_all():
    return {"ok": True, "acknowledged": storage.acknowledge_all_alerts()}


@app.post("/api/discovery/scan")
def scan_now():
    discovery_worker.trigger()
    return {"ok": True, "queued": True}


def main():
    uvicorn.run(
        "sentinel.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
