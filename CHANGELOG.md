# Changelog

## 0.6.0 — Fleet

- Added agentless health monitoring for every discovered private-LAN device.
- Added ICMP reachability with a limited TCP fallback.
- Added configurable common-service exposure inventory without banner grabbing.
- Added per-device probe history, latency samples and active service tracking.
- Added device online/offline and new-service change alerts.
- Added optional packet-sensor byte/packet attribution to known LAN devices.
- Added Fleet summary and device inspector UI.
- Added manual probe for one device or the full known fleet.
- Added `/api/fleet` and per-device profile/history/services/traffic APIs.
- Extended risk heuristics with monitored service exposure.
- Preserved v0.5 Investigator features and database migration compatibility.

## 0.5.0 — Investigator

- Optional metadata-only packet capture sensor using Scapy.
- Windows helper scripts for installing the optional capture dependency and launching capture mode.
- Packet capture remains disabled by default and never stores packet payload bytes.
- Aggregated network-flow table with direction, process, endpoint, packet and byte counts.
- Best-effort process attribution by correlating captured flows with local psutil sockets.
- Wire DNS visibility for traditional DNS traffic when capture is enabled.
- Security event timeline combining anomalies, alerts, new flows and DNS observations.
- Incident correlation engine that groups related signals by process, IP or domain.
- Incident scoring, severity and close workflow.
- New Investigator dashboard panels for incidents, sensor health, live flows and timeline.
- Sentinel Score now also accounts for open correlated incidents.
- New APIs: `/api/flows`, `/api/timeline`, `/api/incidents`, `/api/capture`.
- New unit tests for flow aggregation, process matching and incident correlation.

## 0.4.0 — Watchtower

- Behavior baseline and communication history.
- DNS cache monitoring.
- Explainable per-device risk scores.
- Behavioral anomaly detection.
- Intelligence dashboard.

## 0.3.0 — Pulse

- Redesigned security-console UI.
- Trust state for devices.
- Search and filters.
- Attention score.
