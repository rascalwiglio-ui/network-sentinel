# Changelog

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
