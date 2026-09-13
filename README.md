# Network Sentinel

Network Sentinel is a local defensive monitoring dashboard for your own computer and LAN.

> Use it only on systems and networks that you own or are explicitly authorized to monitor.

## v0.4.0 — Watchtower

Watchtower adds a behavioral intelligence layer on top of the Pulse dashboard.

### New in v0.4

- **Behavior baseline**: Sentinel learns processes, external endpoints and DNS names during a configurable warm-up period.
- **Communication history**: external connections are aggregated locally by process, protocol, remote IP and port.
- **Anomaly detection** for:
  - a process that starts making external network connections for the first time after the baseline is ready;
  - unusually high destination fan-out;
  - many previously unseen remote endpoints appearing in one cycle;
  - bursts of previously unseen DNS names;
  - newly observed punycode/IDN domains as a low-severity review signal.
- **DNS visibility**: on Windows, Sentinel reads the local DNS client cache through PowerShell `Get-DnsClientCache`. Other platforms are best-effort and clearly report when cache visibility is unavailable.
- **Per-device risk heuristic**: each device gets an explainable local score based on trust state, age, MAC characteristics and missing identity data.
- **Intelligence UI**: baseline progress, anomaly feed, DNS observations and learned communication endpoints.
- **History retention**: aggregated DNS/endpoint history is pruned automatically.

All risk and Sentinel scores are explicitly heuristics. They are not probabilities of compromise and do not replace an IDS/EDR.

## Windows quick start

From PowerShell inside the repository:

```powershell
.\scripts\bootstrap.cmd
.\scripts\run.cmd
```

Open:

```text
http://127.0.0.1:8765
```

FastAPI docs:

```text
http://127.0.0.1:8765/docs
```

## Upgrade from v0.3 with Git

Stop Sentinel with `CTRL+C`, then:

```powershell
.\scripts\update.cmd
.\scripts\run.cmd
```

The existing `sentinel.db` is migrated automatically. Watchtower creates new local tables for DNS records, communication history and process baselines without deleting previous devices or alerts.

## Configuration

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

SENTINEL_DNS_MONITORING=1
SENTINEL_DNS_INTERVAL=10
SENTINEL_DNS_BURST_THRESHOLD=25
SENTINEL_BASELINE_WARMUP=120
SENTINEL_PROCESS_FANOUT=25
SENTINEL_ENDPOINT_CHURN=12
SENTINEL_HISTORY_RETENTION_DAYS=7
```

For a longer learning phase:

```powershell
$env:SENTINEL_BASELINE_WARMUP="600"
.\scripts\run.cmd
```

To disable DNS cache monitoring:

```powershell
$env:SENTINEL_DNS_MONITORING="0"
.\scripts\run.cmd
```

## What the baseline means

For the first `SENTINEL_BASELINE_WARMUP` seconds, Sentinel records normal observations without generating the new-process, endpoint-churn or DNS-burst anomaly alerts. Once learning is complete, previously unseen behavior can generate review signals.

A short baseline is convenient for development. For long-running home or lab monitoring, 5–15 minutes is more useful than the 120-second default.

## API

```text
GET  /api/status
GET  /api/overview
GET  /api/baseline
GET  /api/network
GET  /api/devices
POST /api/devices/{ip}/trust?trusted=true
GET  /api/listeners
GET  /api/connections
GET  /api/traffic
GET  /api/dns
GET  /api/communications
GET  /api/anomalies
GET  /api/alerts
POST /api/alerts/{id}/ack
POST /api/alerts/ack-all
POST /api/discovery/scan
```

## Scope and safety boundary

Network Sentinel is defensive monitoring software. Active LAN discovery remains deliberately constrained to the directly connected private IPv4 network and at most 254 addresses. Watchtower does not add exploitation, credential attacks, stealth scanning, traffic interception or offensive automation.

DNS visibility reads the local host's cache; it is not a packet sniffer and therefore does not claim to see every DNS request made by every device on the LAN.

Communication history describes the computer running Sentinel. Per-device traffic attribution still requires an authorized router sensor or packet-capture component and is not claimed in v0.4.

## Repository workflow

Keep `main` stable and develop releases on branches:

```powershell
git switch -c feature/my-feature
# edit / test
git add .
git commit -m "Add my feature"
git push -u origin feature/my-feature
```

Then merge through a pull request.
