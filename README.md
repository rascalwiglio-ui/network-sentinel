# Network Sentinel

MVP difensivo per monitorare il proprio PC e la propria LAN.

## Funzioni

- Inventario dei dispositivi osservati tramite cache ARP.
- Snapshot delle connessioni TCP/UDP del computer.
- Porte locali in ascolto con PID e processo, quando disponibile.
- Alert quando:
  - compare un nuovo dispositivo;
  - compare una nuova porta in ascolto;
  - il numero di connessioni cresce rapidamente.
- Storico SQLite.
- Dashboard web locale.
- API JSON.

> Usa Network Sentinel solo su sistemi e reti che possiedi o che sei autorizzato a monitorare.

## Avvio rapido

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Installa:

```bash
pip install -r requirements.txt
```

Avvia:

```bash
python -m sentinel.app
```

Apri:

http://127.0.0.1:8765

## Permessi

Senza privilegi elevati alcune informazioni sui processi possono non essere disponibili.

Linux:

```bash
sudo .venv/bin/python -m sentinel.app
```

## WSL2

Da WSL2 vedrai soprattutto la rete virtuale di WSL e non necessariamente tutta la LAN fisica.

Per monitorare meglio la LAN:
- esegui Sentinel direttamente su Windows;
- oppure su Linux/Raspberry Pi collegato alla rete;
- in futuro puoi integrare API/SNMP del router.

## Configurazione

```bash
SENTINEL_HOST=127.0.0.1
SENTINEL_PORT=8765
SENTINEL_INTERVAL=5
SENTINEL_DB=sentinel.db
SENTINEL_CONN_SPIKE=80
```

Per esporre la dashboard sulla LAN:

```bash
SENTINEL_HOST=0.0.0.0 python -m sentinel.app
```

Fallo solo su una rete fidata.

## API

- `GET /api/status`
- `GET /api/devices`
- `GET /api/listeners`
- `GET /api/connections`
- `GET /api/alerts`
- `POST /api/alerts/{id}/ack`

## Prossime evoluzioni

- discovery ARP/ICMP opzionale;
- cattura passiva con libpcap/Scapy;
- fingerprinting device;
- baseline comportamentale;
- regole IDS;
- integrazione firewall;
- notifiche Telegram/email;
- agent distribuiti;
- analisi AI locale dei log.
