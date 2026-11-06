"""Statistiche Zabbix dell'ultima rilevazione per la panoramica IOHO.

Sola lettura; host.get + item.get in batch, cache locale 25s.
Non usa gli audit orari come valori correnti, ne' espone credenziali.
"""
import math
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.zabbix_cpu import _choose_cpu_item, _rpc

CACHE_SECONDS = 25
STALE_SECONDS = 300
CPU_YELLOW_AT = 60.0
CPU_RED_AT = 85.0
_CACHE_LOCK = threading.Lock()
_CACHE = {"until": 0.0, "key": None, "data": {}}


def _valid_api_config():
    url = os.getenv("ZABBIX_API_URL", "").strip()
    token = os.getenv("ZABBIX_API_TOKEN", "").strip()
    parsed = urlsplit(url)
    if (not token or parsed.scheme != "https" or not parsed.hostname or
            parsed.username or parsed.password or
            not parsed.path.rstrip("/").endswith("/api_jsonrpc.php")):
        return None
    return url, token


def _item_last(item, now, max_age=STALE_SECONDS):
    """Solo campioni recenti, numerici e finiti; mai convertire -/NaN in 0."""
    if not item or str(item.get("status", "0")) != "0":
        return None
    if str(item.get("state", "0")) != "0":
        return None
    try:
        stamp = int(item["lastclock"])
        value = float(item["lastvalue"])
    except (TypeError, ValueError, KeyError, OverflowError):
        return None
    if not math.isfinite(value) or stamp <= 0 or stamp > now + 60 or now - stamp > max_age:
        return None
    return (value, stamp)


def _choose_item(items, keys, now, lower=0, upper=None):
    for key in keys:
        for item in items:
            if item.get("key_") != key:
                continue
            value = _item_last(item, now)
            if value is None:
                continue
            number, timestamp = value
            if number < lower or (upper is not None and number > upper):
                continue
            return round(number, 2), timestamp
    return None, None


def _choose_cpu(items, now):
    # Riutilizza la stessa validazione della CPU totale del report incidenti.
    candidates = list(items)
    preferred = os.getenv("ZABBIX_CPU_ITEM_KEY", "").strip()
    while candidates:
        item, idle = _choose_cpu_item(candidates, preferred)
        if item is None:
            break
        raw = _item_last(item, now)
        if raw is not None:
            value, stamp = raw
            pct = 100 - value if idle else value
            if 0 <= pct <= 100:
                return round(pct, 2), stamp
        candidates = [candidate for candidate in candidates if candidate is not item]
    return None, None


def _build_host_rows(hostids, cpu_items, process_items, now):
    by_host = {h: [] for h in hostids}
    for item in cpu_items + process_items:
        hostid = str(item.get("hostid", ""))
        if hostid in by_host:
            by_host[hostid].append(item)
    rows = {}
    for hostid in hostids:
        items = by_host[hostid]
        percent, stamp = _choose_cpu(items, now)
        loads = []
        for unit in ("avg1", "avg5", "avg15"):
            value, _ = _choose_item(items, [
                f"system.cpu.load[all,{unit}]",
                f"system.cpu.load[, {unit}]".replace(" ", ""),
                f"system.cpu.load[percpu,{unit}]",
            ], now)
            loads.append(value)
        processes, _ = _choose_item(items, [
            "proc.num[]", "proc.num", "proc.num[,,all]",
        ], now)
        level = ("critical" if percent is not None and percent >= CPU_RED_AT
                 else "warning" if percent is not None and percent >= CPU_YELLOW_AT
                 else "ok" if percent is not None else "unknown")
        rows[hostid] = {
            "cpu_pct": percent,
            "cpu_at": datetime.fromtimestamp(stamp, timezone.utc).strftime("%H:%M:%S UTC") if stamp else None,
            "level": level,
            "load1": loads[0], "load5": loads[1], "load15": loads[2],
            "processes": int(processes) if processes is not None else None,
        }
    return rows


def _fetch(hostnames, call):
    config = _valid_api_config()
    if not config or not hostnames:
        return {}
    url, token = config
    now = int(time.time())
    try:
        # Nessun 'selectItems': l'item.get esplicito applica permessi Zabbix.
        hosts = call(url, token, "host.get", {
            "output": ["hostid", "host"], "filter": {"host": hostnames},
            "limit": max(20, len(hostnames) + 3)})
        host_to_id = {str(h["host"]): str(h["hostid"]) for h in hosts
                      if "host" in h and "hostid" in h}
        if not host_to_id:
            return {}
        ids = sorted(set(host_to_id.values()))
        params = {
            "hostids": ids,
            "output": ["hostid", "itemid", "name", "key_", "status",
                       "state", "lastvalue", "lastclock"],
            "limit": max(1000, len(ids) * 150),
        }
        cpu_items = call(url, token, "item.get",
                         {**params, "search": {"key_": "system.cpu"}})
        process_items = call(url, token, "item.get",
                             {**params, "search": {"key_": "proc.num"}})
        data = _build_host_rows(ids, cpu_items, process_items, now)
        return {name: data[hostid] for name, hostid in host_to_id.items() if hostid in data}
    except Exception:
        # Errore API e token mai mostrati in pagina o log; la home resta operativa.
        return {}


def get_live_metrics(hostnames, *, rpc=None):
    """Una singola lettura batch al massimo ogni 25s per processo API."""
    names = tuple(sorted(set(str(h) for h in hostnames if h)))
    if not names:
        return {}
    call = rpc or _rpc
    # Il test con rpc esplicito bypassa la cache per risultati deterministici.
    if rpc is not None:
        return _fetch(list(names), call)
    now = time.monotonic()
    with _CACHE_LOCK:
        if now < _CACHE["until"] and _CACHE["key"] == names:
            return dict(_CACHE["data"])
        data = _fetch(list(names), call)
        # Errori: nessun dato vecchio spacciato per 'live'.
        _CACHE.update(until=time.monotonic() + CACHE_SECONDS,
                      key=names, data=data)
        return dict(data)
