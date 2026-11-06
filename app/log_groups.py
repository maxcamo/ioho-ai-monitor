"""Vista operativa: una riga per problema, ordinata per occorrenze osservate."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

ROME = ZoneInfo("Europe/Rome")


def _local(ts):
    if not ts:
        return "—"
    try:
        val = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(ROME).strftime("%d/%m/%Y %H:%M:%S")
    except ValueError:
        return "—"


def build_error_groups(data):
    records = {}
    legacy = []
    for name, log in (data.get("logs") or {}).items():
        if not isinstance(log, dict):
            continue
        if not isinstance(log.get("groups"), list):
            if log.get("total", 0):
                legacy.append(name)
            continue
        for g in log["groups"]:
            if not isinstance(g, dict) or not g.get("signature"):
                continue
            signature = str(g["signature"]).strip()
            if name == "nginx_error" and "access forbidden by rule" in signature.lower():
                continue
            key = signature.casefold()
            count = max(0, int(g.get("count", 0) or 0))
            if count <= 0:
                continue
            row = records.setdefault(key, {
                "signature": signature, "count": 0, "count_5m": 0,
                "count_15m": 0, "count_60m": 0, "peak_per_minute": 0,
                "first_seen": None, "last_seen": None, "sources": [], "examples": []
            })
            row["count"] += count
            for k in ("count_5m", "count_15m", "count_60m"):
                row[k] += max(0, int(g.get(k, 0) or 0))
            row["peak_per_minute"] = max(row["peak_per_minute"], max(0, int(g.get("peak_per_minute", 0) or 0)))
            if name not in row["sources"]:
                row["sources"].append(name)
            first = g.get("first_seen")
            last = g.get("last_seen")
            if first and (not row["first_seen"] or first < row["first_seen"]):
                row["first_seen"] = first
            if last and (not row["last_seen"] or last > row["last_seen"]):
                row["last_seen"] = last
            for ex in g.get("examples") or []:
                if isinstance(ex, dict) and len(row["examples"]) < 3:
                    row["examples"].append({"at": _local(ex.get("at")), "message": str(ex.get("message", ""))})
    groups = list(records.values())
    for g in groups:
        g["first_local"] = _local(g["first_seen"])
        g["last_local"] = _local(g["last_seen"])
        if g["count_15m"] >= 150 or g["peak_per_minute"] >= 30:
            g["frequency"] = "Raffica"
            g["frequency_class"] = "critical"
        elif g["count_15m"] >= 15 or g["peak_per_minute"] >= 5:
            g["frequency"] = "Frequente"
            g["frequency_class"] = "warning"
        else:
            g["frequency"] = "Sporadico"
            g["frequency_class"] = "unknown"
    groups.sort(key=lambda g: (-g["count"], -g["count_15m"], g["signature"].lower()))
    return groups, legacy
