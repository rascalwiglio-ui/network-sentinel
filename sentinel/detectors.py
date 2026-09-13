def process_devices(storage, devices):
    for d in devices:
        is_new = storage.upsert_device(
            d["ip"], d["mac"], d["interface"]
        )
        if is_new:
            storage.add_alert(
                "medium",
                "new_device",
                f"Nuovo dispositivo: {d['ip']}",
                f"MAC {d['mac']} - interfaccia {d['interface']}",
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
            process = item.get("process") or "processo sconosciuto"
            storage.add_alert(
                "medium",
                "new_listener",
                f"Nuova porta in ascolto: {item['proto'].upper()} {item['port']}",
                f"{item['ip']}:{item['port']} - {process}",
            )

def process_connection_spike(storage, count, previous_count, threshold):
    if previous_count is None:
        return
    delta = count - previous_count
    if delta >= threshold:
        storage.add_alert(
            "high",
            "connection_spike",
            "Picco di connessioni",
            f"Connessioni aumentate di {delta}: {previous_count} -> {count}",
        )
