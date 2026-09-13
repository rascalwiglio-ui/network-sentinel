from dataclasses import dataclass
import os

@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.getenv("SENTINEL_PORT", "8765"))
    interval: float = float(os.getenv("SENTINEL_INTERVAL", "5"))
    db_path: str = os.getenv("SENTINEL_DB", "sentinel.db")
    connection_spike_threshold: int = int(os.getenv("SENTINEL_CONN_SPIKE", "80"))

settings = Settings()
