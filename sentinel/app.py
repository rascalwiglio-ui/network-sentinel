from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .state import runtime
from .storage import Storage
from .worker import DiscoveryWorker, MonitorWorker


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
storage = Storage(settings.db_path)

app = FastAPI(
    title="Network Sentinel",
    version="0.3.0",
    docs_url="/docs",
    redoc_url=None,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

monitor_worker = MonitorWorker(
    storage=storage,
    interval=settings.interval,
    connection_spike_threshold=settings.connection_spike_threshold,
)

discovery_worker = DiscoveryWorker(
    storage=storage,
    interval=settings.discovery_interval,
    max_hosts=settings.max_discovery_hosts,
    ping_timeout_ms=settings.ping_timeout_ms,
    active=settings.active_discovery,
)


@app.on_event("startup")
def startup():
    if not monitor_worker.is_alive():
        monitor_worker.start()
    if not discovery_worker.is_alive():
        discovery_worker.start()


@app.on_event("shutdown")
def shutdown():
    monitor_worker.stop()
    discovery_worker.stop()


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/status")
def status():
    data = runtime.snapshot()
    data["active_discovery"] = settings.active_discovery
    data["version"] = "0.3.0"
    return data


@app.get("/api/overview")
def overview():
    devices = storage.devices(settings.device_online_window)
    alerts = storage.alert_counts()
    state = runtime.snapshot()

    online = [d for d in devices if d["online"]]
    unknown_online = [d for d in online if not d["trusted"] and not d["is_gateway"]]
    open_alerts = alerts["low"] + alerts["medium"] + alerts["high"]

    # A simple attention heuristic, not a probability of compromise.
    score = 100
    score -= alerts["high"] * 18
    score -= alerts["medium"] * 6
    score -= alerts["low"] * 2
    score -= len(unknown_online) * 2
    score = max(0, min(100, score))

    return {
        "sentinel_score": score,
        "score_kind": "attention_heuristic",
        "devices_total": len(devices),
        "devices_online": len(online),
        "devices_untrusted_online": len(unknown_online),
        "listeners": len(state["listeners"]),
        "connections": state["connection_count"],
        "alerts_open": open_alerts,
        "alerts_high": alerts["high"],
        "alerts_medium": alerts["medium"],
        "alerts_low": alerts["low"],
        "rx_bps": state["rx_bps"],
        "tx_bps": state["tx_bps"],
    }


@app.get("/api/network")
def network():
    return runtime.snapshot()["network_info"] or {}


@app.get("/api/devices")
def devices():
    return storage.devices(settings.device_online_window)


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
