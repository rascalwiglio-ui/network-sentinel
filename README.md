# Network Sentinel

Network Sentinel is a local defensive monitoring dashboard for your own computer and LAN.

> Use it only on systems and networks that you own or are explicitly authorized to monitor.

## v0.3.0 — Pulse

Pulse turns the original monitor into a much more usable security console:

- modern responsive dashboard;
- active LAN discovery on private IPv4 networks;
- ARP inventory, reverse-DNS hostnames and offline MAC vendor lookup;
- interactive local network topology;
- realtime host RX/TX traffic graph;
- listening ports and active TCP/UDP connections;
- alerts for new devices, MAC changes, new listeners and connection spikes;
- trusted-device workflow;
- searchable/filterable tables;
- recent security activity feed;
- Sentinel Score, a simple attention heuristic;
- SQLite persistence and automatic schema migration;
- REST API and built-in FastAPI docs.

The Sentinel Score is intentionally labelled as a heuristic. It is not a probability that a machine or network has been compromised.

## Windows quick start

Open PowerShell inside the repository. The easiest Windows path avoids PowerShell execution-policy issues entirely:

```powershell
.\scripts\bootstrap.cmd
.\scripts\run.cmd
```

PowerShell-native `.ps1` wrappers are also included.

Open:

```text
http://127.0.0.1:8765
```

API docs:

```text
http://127.0.0.1:8765/docs
```

## Upgrade with Git

Once your clone tracks `origin/main`, updates are intentionally simple:

```powershell
.\scripts\update.cmd
.\scripts\run.cmd
```

The update script refuses to overwrite uncommitted work, pulls `origin/main` using fast-forward only, then refreshes Python dependencies.

You can also update manually:

```powershell
git pull --ff-only
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m sentinel.app
```

Existing `sentinel.db` data is kept. v0.3 automatically adds the new trusted-device field.

## Configuration

Useful environment variables:

```text
SENTINEL_HOST=127.0.0.1
SENTINEL_PORT=8765
SENTINEL_INTERVAL=2
SENTINEL_DB=sentinel.db
SENTINEL_CONN_SPIKE=80
SENTINEL_ACTIVE_DISCOVERY=1
SENTINEL_DISCOVERY_INTERVAL=60
SENTINEL_MAX_DISCOVERY_HOSTS=254
SENTINEL_PING_TIMEOUT_MS=350
SENTINEL_DEVICE_ONLINE_WINDOW=130
```

Example PowerShell:

```powershell
$env:SENTINEL_DISCOVERY_INTERVAL="120"
.\scripts\run.ps1
```

## Discovery safety boundary

Active discovery is deliberately constrained:

- only a directly connected private IPv4 LAN is considered;
- at most 254 addresses are checked;
- no exploit, brute-force or stealth functionality is included;
- you can disable active discovery with `SENTINEL_ACTIVE_DISCOVERY=0`.

## API

Main endpoints:

```text
GET  /api/status
GET  /api/overview
GET  /api/network
GET  /api/devices
POST /api/devices/{ip}/trust?trusted=true
GET  /api/listeners
GET  /api/connections
GET  /api/traffic
GET  /api/alerts
POST /api/alerts/{id}/ack
POST /api/alerts/ack-all
POST /api/discovery/scan
```

## Repository workflow

Keep `main` stable and build larger features on branches:

```powershell
git switch -c feature/my-feature
# edit / test
git add .
git commit -m "Add my feature"
git push -u origin feature/my-feature
```

Then merge through a pull request.

## Current limitation

The bandwidth chart measures total traffic of the machine running Sentinel. Per-device flow attribution requires packet capture or router telemetry and is not claimed by v0.3.

## Roadmap

Candidate v0.4 work:

- optional packet-capture sensor;
- DNS visibility;
- per-device flow statistics;
- baseline/anomaly engine;
- alert notifications;
- local AI analyst for explaining already-collected events;
- multi-agent deployment.
