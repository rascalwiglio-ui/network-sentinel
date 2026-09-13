from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse

from .config import settings
from .storage import Storage
from .state import runtime
from .worker import MonitorWorker

BASE_DIR = Path(__file__).resolve().parent
storage = Storage(settings.db_path)
worker = MonitorWorker(
    storage=storage,
    interval=settings.interval,
    connection_spike_threshold=settings.connection_spike_threshold,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not worker.is_alive():
        worker.start()
    try:
        yield
    finally:
        worker.stop()

app = FastAPI(
    title="Network Sentinel",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

@app.get("/")
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.get("/api/status")
def status():
    return runtime.snapshot()

@app.get("/api/devices")
def devices():
    return storage.devices()

@app.get("/api/listeners")
def listeners():
    return runtime.snapshot()["listeners"]

@app.get("/api/connections")
def connections():
    return runtime.snapshot()["connections"]

@app.get("/api/alerts")
def alerts():
    return storage.alerts(100)

@app.post("/api/alerts/{alert_id}/ack")
def ack(alert_id: int):
    storage.acknowledge_alert(alert_id)
    return {"ok": True, "id": alert_id}

def main():
    uvicorn.run(
        "sentinel.app:app",
        host=settings.host,
        port=settings.port,
        reload=False,
    )

if __name__ == "__main__":
    main()
