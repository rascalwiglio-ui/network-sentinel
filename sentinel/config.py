from dataclasses import dataclass
import os


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port: int = int(os.getenv("SENTINEL_PORT", "8765"))
    interval: float = float(os.getenv("SENTINEL_INTERVAL", "2"))
    db_path: str = os.getenv("SENTINEL_DB", "sentinel.db")
    connection_spike_threshold: int = int(os.getenv("SENTINEL_CONN_SPIKE", "80"))

    active_discovery: bool = _bool("SENTINEL_ACTIVE_DISCOVERY", True)
    discovery_interval: float = float(os.getenv("SENTINEL_DISCOVERY_INTERVAL", "60"))
    max_discovery_hosts: int = min(
        max(int(os.getenv("SENTINEL_MAX_DISCOVERY_HOSTS", "254")), 1),
        254,
    )
    ping_timeout_ms: int = min(
        max(int(os.getenv("SENTINEL_PING_TIMEOUT_MS", "350")), 100),
        3000,
    )
    device_online_window: int = max(
        int(os.getenv("SENTINEL_DEVICE_ONLINE_WINDOW", "130")),
        10,
    )


settings = Settings()
