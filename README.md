# Network Sentinel v0.6.0 — Fleet

Network Sentinel is a defensive, local-first network monitor for computers and private LANs you own or are explicitly authorized to administer.

v0.6 **Fleet** extends the v0.5 Investigator build with agentless monitoring of every device Sentinel discovers on the directly connected private IPv4 LAN.

## What Fleet adds

- Continuous health probes for all discovered private-LAN devices.
- ICMP reachability with TCP fallback for devices that ignore ping.
- Small configurable TCP service-exposure inventory; no banner grabbing and no authentication attempts.
- Per-device reachability history and latency samples.
- Alerts when a known device goes offline or returns online.
- Alerts when a previously unseen monitored TCP service appears.
- Device detail drawer with:
  - identity and vendor;
  - trust state;
  - risk heuristic;
  - probe state and latency;
  - currently observed LAN services;
  - reachability history;
  - packet-sensor traffic counters when available.
- Fleet summary showing known, probed, reachable and unreachable devices.
- Manual probe of one device or the entire known fleet.
- Packet-capture attribution to known LAN IPs when the optional sensor can see those frames.

Everything from earlier versions remains available: active LAN discovery, topology, host socket monitoring, behavior baseline, DNS visibility, packet metadata capture, flow aggregation, anomaly detection, incident correlation and the Investigator timeline.

## Important visibility limitation

Fleet can **monitor** discovered devices, but it does not remotely take control of them.

On ordinary switched Ethernet/Wi-Fi, your PC cannot automatically see every unicast packet exchanged by other devices. Therefore per-device traffic counters include only frames visible to the Sentinel sensor. Full-LAN traffic visibility normally requires router telemetry, a mirror/SPAN port, a supported gateway integration, or a dedicated sensor placed where the traffic actually passes.

Likewise, a device can be online while blocking ICMP and the monitored TCP ports. Fleet uses a TCP fallback to reduce false offline states, but no agentless probe can guarantee perfect liveness detection for every firewall policy.

## Windows quick start

From PowerShell in the repository directory:

```powershell
.\scripts\bootstrap.cmd
.\scripts\run.cmd
```

Open:

```text
http://127.0.0.1:8765
```

API documentation:

```text
http://127.0.0.1:8765/docs
```

## Optional packet metadata sensor

The core Fleet monitor does not require packet capture.

To enable the optional metadata sensor on Windows:

```powershell
.\scripts\enable-capture.cmd
```

Install Npcap, then start with:

```powershell
.\scripts\run-capture.cmd
```

Packet payloads are not persisted by Sentinel. The sensor aggregates metadata such as IPs, ports, protocol, packet count and byte count.

## Fleet configuration

Defaults:

```text
SENTINEL_DEVICE_MONITORING=1
SENTINEL_DEVICE_PROBE_INTERVAL=45
SENTINEL_DEVICE_PROBE_TIMEOUT_MS=250
SENTINEL_DEVICE_PROBE_WORKERS=8
SENTINEL_DEVICE_SERVICE_PORTS=21,22,23,53,80,139,443,445,554,631,1883,3389,5357,5900,8008,8080,8443,8883,9100
```

Example: probe every 90 seconds and only inventory a few common services:

```powershell
$env:SENTINEL_DEVICE_PROBE_INTERVAL="90"
$env:SENTINEL_DEVICE_SERVICE_PORTS="22,80,443,445,3389"
.\scripts\run.cmd
```

The service check is deliberately limited to a configured allow-list. Fleet performs ordinary TCP connects only; it does not brute-force credentials, exploit services or pull private data from devices.

## Fleet API

```text
GET  /api/fleet
POST /api/fleet/scan

GET  /api/devices
GET  /api/devices/{ip}/profile
GET  /api/devices/{ip}/history
GET  /api/devices/{ip}/services
GET  /api/devices/{ip}/traffic
POST /api/devices/{ip}/probe
POST /api/devices/{ip}/trust
```

Existing Investigator endpoints remain available, including `/api/flows`, `/api/timeline`, `/api/incidents`, `/api/dns`, `/api/communications`, `/api/anomalies` and `/api/capture`.

## Upgrade from v0.5

Stop Sentinel, back up the database, then apply the v0.5 → v0.6 patch or copy the overlay files.

```powershell
Copy-Item sentinel.db sentinel-v05-backup.db
```

After the source update:

```powershell
.\scripts\bootstrap.cmd
.\scripts\run.cmd
```

The SQLite schema is extended automatically; the existing database is kept.

## Git workflow

Once the updated source is in your local checkout:

```powershell
git status
git add .
git commit -m "Release Network Sentinel v0.6.0 Fleet"
git push origin main
```

Future remote updates can still be pulled with:

```powershell
.\scripts\update.cmd
```

## Safety model

Network Sentinel is intentionally defensive. Use active discovery and device probing only on networks you own or are authorized to administer. Fleet does not include deauthentication, ARP spoofing, credential attacks, exploitation or covert remote-control functionality.
