def process_devices(storage, devices):
    for d in devices:
        result = storage.upsert_device(
            d["ip"],
            d.get("mac"),
            d.get("interface"),
            hostname=d.get("hostname"),
            vendor=d.get("vendor"),
            is_gateway=d.get("is_gateway", False),
        )

        if result["status"] == "new":
            label = d.get("hostname") or d["ip"]
            storage.add_alert(
                "medium",
                "new_device",
                f"Nuovo dispositivo: {label}",
                (
                    f"IP {d['ip']} · "
                    f"MAC {d.get('mac') or 'unknown'} · "
                    f"Vendor {d.get('vendor') or 'unknown'}"
                ),
            )

        elif result["status"] == "mac_changed":
            storage.add_alert(
                "high",
                "mac_changed",
                f"MAC cambiato per {d['ip']}",
                (
                    f"{result['old_mac']} -> "
                    f"{result['new_mac']}"
                ),
            )


def process_listeners(storage, listeners):
    for item in listeners:
        is_new = storage.upsert_listener(
            item["proto"],
            item["ip"],
            item["port"],
            item.get("pid"),
            item.get("process"),
        )
        if is_new:
            process = (
                item.get("process")
                or "processo sconosciuto"
            )
            storage.add_alert(
                "medium",
                "new_listener",
                (
                    "Nuova porta in ascolto: "
                    f"{item['proto'].upper()} "
                    f"{item['port']}"
                ),
                (
                    f"{item['ip']}:{item['port']} "
                    f"· {process}"
                ),
            )


def process_connection_spike(
    storage,
    count,
    previous_count,
    threshold,
):
    if previous_count is None:
        return

    delta = count - previous_count
    if delta >= threshold:
        storage.add_alert(
            "high",
            "connection_spike",
            "Picco di connessioni",
            (
                f"Connessioni aumentate di {delta}: "
                f"{previous_count} -> {count}"
            ),
        )
