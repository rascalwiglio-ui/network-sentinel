# Changelog

## 0.4.0 - Watchtower

- Added a local behavior-baseline engine with a configurable learning warm-up.
- Added external communication history aggregated by process, protocol, remote IP and port.
- Added anomaly detection for new network-active processes after baseline learning.
- Added anomaly detection for unusually high destination fan-out and endpoint churn.
- Added best-effort DNS cache visibility, with first-class Windows support through `Get-DnsClientCache`.
- Added DNS burst detection and low-severity visibility for newly observed punycode/IDN domains.
- Added explainable per-device risk heuristics with reasons shown in the UI.
- Added `/api/baseline`, `/api/dns`, `/api/communications` and `/api/anomalies` endpoints.
- Added local history retention and periodic pruning for DNS and communication telemetry.
- Expanded the dashboard with a dedicated Intelligence area, baseline progress, anomaly feed, DNS table and external endpoint history.
- Expanded global search to domains and learned communications.
- Added device filtering by risk level and anomaly-specific alert filtering.
- Improved topology highlighting for medium/high-risk devices.
- Existing SQLite databases migrate in place; no reset is required.

## 0.3.0 - Pulse

- Completely redesigned responsive dashboard with persistent sidebar.
- New Sentinel Score: a transparent attention heuristic based on open alerts and untrusted online devices.
- Trusted-device workflow with one-click trust/untrust actions.
- New overview API with device, connection, listener and alert summaries.
- New activity feed for recent open alerts.
- Global search across devices, listeners, connections and alerts.
- Filters for device state and alert state/severity.
- Improved topology visualization and device labels.
- Refined realtime bandwidth chart.
- Acknowledge-all action for alerts.
- Static UI split into HTML, CSS and JavaScript for easier maintenance.
- Automatic SQLite migration adds the `trusted` field without resetting existing data.

## 0.2.0

- Active LAN discovery on private IPv4 networks.
- Discovery capped at 254 hosts for safety and predictability.
- Reverse-DNS hostname resolution.
- Offline MAC vendor lookup.
- Default gateway detection.
- Device online/offline state.
- MAC-change alerts.
- Realtime RX/TX throughput.
- Traffic history endpoint and graph.
- Interactive network topology map.
- Manual "Scan now" action.
- Safer SQLite schema migration from v0.1.
- GitHub CI workflow.
- PowerShell/Linux bootstrap, run and update scripts.

## 0.1.0

- Initial dashboard.
- ARP inventory.
- Local listeners and active connections.
- SQLite event history.
- New-device/new-listener/connection-spike alerts.
