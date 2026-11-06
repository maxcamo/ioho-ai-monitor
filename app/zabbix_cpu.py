"""Storico CPU Zabbix in sola lettura, fissato all'ora dell'audit HTTP.

Solo host.get, item.get e history.get; nessuna modifica Zabbix e nessuna
richiesta in fase di visualizzazione. TLS e certificati verificati.
"""
import json
import math
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class ZabbixReadError(Exception):
    pass


def _rpc(url, token, method, params):
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params, "id": 1}).encode("utf-8")
    request = Request(url, data=body, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json-rpc",
        "Accept": "application/json",
    })
    # Non disabilitare mai la validazione del certificato.
    with urlopen(request, timeout=8) as response:
        data = json.loads(response.read(1_000_000).decode("utf-8"))
    if not isinstance(data, dict) or "error" in data or not isinstance(data.get("result"), list):
        raise ZabbixReadError("Risposta JSON-RPC non valida o accesso API negato")
    return data["result"]


def _choose_cpu_item(items, preferred=""):
    """Solo item che misurano CPU totale; mai user CPU scambiata per totale."""
    usable = [i for i in items if str(i.get("status", "0")) == "0"
              and str(i.get("value_type", "")) in ("0", "3")]
    if preferred:
        match = next((i for i in usable if i.get("key_") == preferred), None)
        if match:
            # system.cpu.util è totale SOLO se l'item dipendente si chiama
            # CPU utilization; come agent item senza template è CPU user.
            if preferred == "system.cpu.util" and "cpu utilization" not in str(match.get("name", "")).lower():
                return None, False
            return match, preferred.replace(" ", "").lower() in (
                "system.cpu.util[,idle]", "system.cpu.util[all,idle]")
        return None, False
    # Nei template Linux Zabbix "system.cpu.util" e' un item dipendente
    # "CPU utilization" (100 - idle). Un agent item con lo stesso key
    # ma altro nome NON e' equivalente: default agent = modalita' user.
    for item in usable:
        if item.get("key_") == "system.cpu.util" and "cpu utilization" in str(item.get("name", "")).lower():
            return item, False
    for key in ("system.cpu.util[,idle]", "system.cpu.util[all,idle]"):
        for item in usable:
            if item.get("key_") == key:
                return item, True
    return None, False


def _reference_time(payload):
    value = (payload.get("traffic") or {}).get("captured_at") or payload.get("timestamp_utc")
    if value:
        try:
            captured = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return captured.replace(tzinfo=timezone.utc) if captured.tzinfo is None else captured.astimezone(timezone.utc)
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc)


def fetch_cpu_history(zabbix_host, payload, *, rpc=None):
    """Restituisce un piccolo riepilogo JSON serializzabile, senza credenziali."""
    url = os.getenv("ZABBIX_API_URL", "").strip()
    token = os.getenv("ZABBIX_API_TOKEN", "").strip()
    if not url or not token:
        return {"status": "not_configured"}
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        return {"status": "invalid_config", "message": "ZABBIX_API_URL richiede HTTPS e un endpoint valido"}
    if not parsed.path.rstrip("/").endswith("/api_jsonrpc.php"):
        return {"status": "invalid_config", "message": "ZABBIX_API_URL deve terminare con /api_jsonrpc.php"}
    call = rpc or _rpc
    try:
        hosts = call(url, token, "host.get", {
            "output": ["hostid", "host"], "filter": {"host": [zabbix_host]}, "limit": 2})
        if len(hosts) != 1:
            return {"status": "host_missing", "message": "Host tecnico Zabbix assente o non autorizzato"}
        items = call(url, token, "item.get", {
            "hostids": [hosts[0]["hostid"]],
            "output": ["itemid", "name", "key_", "value_type", "status"],
            "search": {"key_": "system.cpu.util"}, "limit": 200})
        item, invert_idle = _choose_cpu_item(items, os.getenv("ZABBIX_CPU_ITEM_KEY", "").strip())
        if item is None:
            return {"status": "item_missing", "message": "Item CPU totale non trovato: verificare template e ZABBIX_CPU_ITEM_KEY"}
        end = _reference_time(payload)
        start = end - timedelta(minutes=10)
        history_type = int(item.get("value_type", 0))
        records = call(url, token, "history.get", {
            "history": history_type, "itemids": [item["itemid"]],
            "time_from": int(start.timestamp()), "time_till": int(end.timestamp()),
            "output": ["clock", "value"], "sortfield": "clock",
            "sortorder": "ASC", "limit": 600})
        valid = []
        per_minute = defaultdict(list)
        for record in records:
            try:
                clock = int(record["clock"])
                value = float(record["value"])
                if not math.isfinite(value):
                    continue
                if invert_idle:
                    value = 100.0 - value
                if value < -0.01 or value > 100.01:
                    continue
                value = min(100.0, max(0.0, value))
                label = datetime.fromtimestamp(clock, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                valid.append((clock, value))
                per_minute[label].append(value)
            except (TypeError, ValueError, KeyError, OverflowError, OSError):
                continue
        if not valid:
            return {"status": "no_history", "item_key": item.get("key_"),
                    "message": "Nessun campione CPU nello stesso intervallo dell'access.log"}
        valid.sort(key=lambda t: t[0])
        return {
            "status": "ok",
            "item_key": str(item.get("key_", ""))[:150],
            "item_name": str(item.get("name", ""))[:120],
            "captured_from": start.isoformat(),
            "captured_to": end.isoformat(),
            "avg_pct": round(sum(value for _, value in valid) / len(valid), 1),
            "peak_pct": round(max(value for _, value in valid), 1),
            "last_pct": round(valid[-1][1], 1),
            "sample_count": len(valid),
            "minutes": [{"minute": minute, "cpu_pct": round(sum(values) / len(values), 1)}
                        for minute, values in sorted(per_minute.items())],
        }
    except Exception:
        # Non includere eccezioni di rete o risposta remota: possono contenere
        # URL e dettagli sensibili. Il monitor HTTP continua senza CPU.
        return {"status": "error", "message": "Zabbix non raggiungibile o accesso API non valido"}
