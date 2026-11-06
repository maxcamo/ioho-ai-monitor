#!/usr/bin/env python3
"""Collector Python stdlib, senza porte in ingresso e senza comandi remoti."""
import collections
import datetime as dt
import glob
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo
try:
    from .traffic_analysis import TrafficSummary
except ImportError:
    from traffic_analysis import TrafficSummary

# Formati supportati:
# - combined standard: remote_ip - user [date] "GET /path HTTP/1.1" status bytes "referer" "ua"
# - IOHO/proxy: x_forwarded_for (anche piu IP) - user [date] host="domain" "request" status bytes "referer" "ua"
NGINX = re.compile(
    r'^(?P<client>.+?)\s+-\s+\S+\s+\[(?P<date>[^]]+)\]\s+'
    r'(?:host="[^"]*"\s+)?'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+\S+\s+'
    r'"[^"]*"\s+"(?P<ua>[^"]*)"'
)
NGINX_DATE = "%d/%b/%Y:%H:%M:%S %z"
ISO_TIME = re.compile(r'(20\d{2}[-/]\d\d[-/]\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d{2}:?\d{2})?')
SENSITIVE = re.compile(r'(?i)(authorization\s*[:=]\s*(?:bearer\s+)?|\b(?:password|passwd|secret|token|api[_-]?key|session[_-]?id|access[_-]?key)\s*[=:]\s*)[^\s&"\']+')
EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
ERROR = re.compile(r'\b(error|exception|critical|fatal|emerg|alert|timeout|failed|deadlock|warning|warn)\b', re.I)
BOT = re.compile(r'bot|crawler|spider|headless|scrapy|curl|python-requests|facebookexternalhit|meta-external', re.I)
FILTER = re.compile(r'/filter/|/shopby/|[?&](cat|price|color|size|manufacturer|layer|filter|product_list_order)=|%5B', re.I)
# I blocchi intenzionali di Nginx non sono errori applicativi: il traffico HTTP
# (inclusi gli eventuali 403) continua comunque a essere contato in access.log.
NGINX_EXPECTED_BLOCK = re.compile(r'\baccess\s+forbidden\s+by\s+rule\b', re.I)
LOG_PREFIX = re.compile(
    r'^\s*\[?\s*(?:20\d{2}[-/]\d{2}[-/]\d{2})[T ]\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s*\]?\s*'
)
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
MAX_GROUPS_TOTAL = 200
MAX_GROUPS_PER_LOG = 100


def log_signature(line):
    """Firma leggibile per raggruppare messaggi equivalenti senza alterare le prove."""
    value = redact(line.strip())
    value = LOG_PREFIX.sub('', value)
    value = re.sub(r'^(?:[a-z_][a-z0-9_.-]*\.)?(?:critical|error|warning|warn|notice|info|debug|alert):\s*', '', value, flags=re.I)
    # Timestamp Nginx seguiti da prefisso tipo [error] 123#123: *1234
    value = re.sub(r'^\s*\[(?:error|crit|alert|warn|emerg|notice)\]\s*', '', value, flags=re.I)
    value = re.sub(r'^\d+#\d+:\s*\*\d+\s*', '', value)
    # Identificativi HTTP dinamici non definiscono una nuova tipologia di errore.
    value = re.sub(r',\s*(?:client|server|request|host|referrer|upstream):\s*.*$', '', value, flags=re.I)
    value = IPV4.sub('[ip]', value)
    # ID applicativi spesso brevi (quoteId=123, order_id: 4321): non
    # normalizzare invece codici di errore HTTP/SQL che distinguono i problemi.
    value = re.sub(
        r'(?i)\b((?:cart|quote|customer|product|order|entity|request|session|transaction)[_-]?id)'
        r'(\s*[:=]\s*|\s+)[\w-]{1,80}', r'\1\2[id]', value
    )
    value = re.sub(r'(?i)\b[0-9a-f]{24,}\b', '[hex]', value)
    value = re.sub(r'(?<!\w)\d{6,}(?!\w)', '[id]', value)
    value = re.sub(r'(?i)(\bline\s+)\d+', r'\1[line]', value)
    value = re.sub(r'(?i)(\.php:)\d+', r'\1[line]', value)
    value = re.sub(r'\s+', ' ', value).strip(' :\t')
    return (value or 'Errore senza messaggio')[:320]


def add_group(section, line, timestamp, state, reference):
    """Conta tutto, conserva un campione iniziale e uno finale per gruppo."""
    section['total'] += 1
    signature = log_signature(line)
    group_map = section['_group_map']
    key = signature.casefold()
    group = group_map.get(key)
    if group is None:
        if len(group_map) >= MAX_GROUPS_PER_LOG or state['groups'] >= MAX_GROUPS_TOTAL:
            section['ungrouped_occurrences'] += 1
            return
        state['groups'] += 1
        group = {
            'signature': signature,
            'count': 0,
            'count_5m': 0,
            'count_15m': 0,
            'count_60m': 0,
            'peak_per_minute': 0,
            '_minute_counts': collections.Counter(),
            'first_seen': timestamp.isoformat(),
            'last_seen': timestamp.isoformat(),
            'examples': [],
        }
        group_map[key] = group
    group['count'] += 1
    age = (reference - timestamp).total_seconds()
    if -60 <= age <= 300: group['count_5m'] += 1
    if -60 <= age <= 900: group['count_15m'] += 1
    if -60 <= age <= 3600: group['count_60m'] += 1
    minute = timestamp.strftime('%Y-%m-%dT%H:%M')
    group['_minute_counts'][minute] += 1
    group['peak_per_minute'] = max(group['peak_per_minute'], group['_minute_counts'][minute])
    iso = timestamp.isoformat()
    group['first_seen'] = min(group['first_seen'], iso)
    group['last_seen'] = max(group['last_seen'], iso)
    item = {'at': iso, 'message': redact(line.strip())}
    if len(group['examples']) < 3:
        group['examples'].append(item)
    else:
        group['examples'][-1] = item


def redact(value):
    value = EMAIL.sub("[email-redacted]", str(value))
    value = re.sub(r'(?i)\bpi_[A-Za-z0-9]+_secret_[A-Za-z0-9]+', '[payment-secret-redacted]', value)
    value = re.sub(r'(?i)\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]+', '[api-key-redacted]', value)
    value = SENSITIVE.sub(lambda m: m.group(1) + "[redacted]", value)
    value = re.sub(r'\b(?:\d[ -]*?){13,19}\b', '[number-redacted]', value)
    value = re.sub(r'(?i)(?:\?|&)(?:[^=\s&]+=[^\s&]*)+', '[query-redacted]', value)
    return value[:400]


def normalize_uri(uri):
    parsed = urllib.parse.urlsplit(uri)
    path = EMAIL.sub("[email]", urllib.parse.unquote(parsed.path))[:180]
    path = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "[uuid]", path)
    path = re.sub(r"(?<![A-Za-z0-9])\d{8,}(?![A-Za-z0-9])", "[id]", path)
    keys = sorted(set(k[:35] for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))[:12]
    return path + ("?" + "&".join(keys) if keys else "")


def log_time(line, zone):
    """Preserva l'offset dichiarato da Magento (es. +00:00); localizza solo i log senza offset."""
    m = ISO_TIME.search(line[:90])
    if not m:
        return None
    raw = m.group(1).replace('/', '-') + 'T' + m.group(2) + (m.group(3) or '') + (m.group(4) or '')
    if raw.endswith('Z'):
        raw = raw[:-1] + '+00:00'
    try:
        moment = dt.datetime.fromisoformat(raw)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=zone)
        return moment.astimezone(dt.timezone.utc)
    except ValueError:
        return None


def file_lines(path, max_bytes, coverage):
    """Restituisce iterator e flag di troncamento; per gzip campiona la parte iniziale."""
    if path.endswith(".gz"):
        # Le rotazioni compresse richiedono lettura streaming, sempre con budget.
        def gz_lines():
            consumed = 0
            with gzip.open(path, "rb") as f:
                for raw in f:
                    consumed += len(raw)
                    if consumed > max_bytes:
                        coverage["truncated"] = True
                        break
                    yield raw.decode("utf-8", errors="replace")
        return gz_lines(), False
    size = os.path.getsize(path)
    start = max(0, size - max_bytes)
    def lines():
        with open(path, "rb") as f:
            f.seek(start)
            if start:
                f.readline()  # scarta una riga incompleta
            for raw in f:
                yield raw.decode("utf-8", errors="replace")
    return lines(), start > 0


def collect(config, minutes):
    zone = ZoneInfo(config.get("server_timezone", "Europe/Rome"))
    reference = dt.datetime.now(dt.timezone.utc)
    since = reference - dt.timedelta(minutes=minutes)
    per_file_bytes = min(int(config.get("max_bytes_per_file", 12_000_000)), 60_000_000)
    budget = min(int(config.get("max_total_bytes", 90_000_000)), 250_000_000)
    traffic = TrafficSummary(reference) if minutes <= 20 else None
    if traffic is not None:
        budget = max(budget, min(int(config.get("incident_total_bytes", 40_000_000)), 60_000_000))
    max_files = min(int(config.get("max_files", 40)), 80)
    counts = collections.Counter()
    paths = collections.Counter()
    ips = collections.Counter()
    agents = collections.Counter()
    per_minute = collections.Counter()
    filtered = 0
    bot_hits = 0
    total = 0
    access_unparsed = 0
    logs = {}
    group_state = {"groups": 0}
    coverage = {"matched": 0, "truncated": False, "no_access_log": False, "errors": [], "max_total_bytes": budget, "max_bytes_per_file": per_file_bytes}
    types = (("access", config.get("access_logs", [])), ("nginx_error", config.get("nginx_error_logs", [])), ("app", config.get("app_logs", [])))
    used = set()
    spent = 0
    access_found = False
    coverage["access_truncated"] = False
    coverage["access_bytes_read"] = 0
    for group, patterns in types:
        matched = []
        for pattern in patterns:
            for p in glob.glob(pattern):
                if p not in used and os.path.isfile(p) and not os.path.islink(p):
                    matched.append(p)
                    used.add(p)
        matched.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        if len(matched) > max_files:
            coverage["truncated"] = True
            matched = matched[:max_files]
        for path in matched:
            if group == "access":
                access_found = True
            if spent >= budget:
                coverage["truncated"] = True
                break
            try:
                stat = os.stat(path)
                # File con modifiche precedenti alla finestra: saltare (assume data/mtime attendibili).
                if dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc) < since:
                    continue
                file_budget = per_file_bytes
                if group == "access" and traffic is not None:
                    file_budget = max(file_budget, min(int(config.get("incident_access_bytes", 16_000_000)), 24_000_000))
                limit = min(file_budget, budget - spent)
                if limit < 1024:
                    coverage["truncated"] = True
                    break
                stream, truncated = file_lines(path, limit, coverage)
                coverage["truncated"] |= truncated
                if group == "access":
                    coverage["access_truncated"] |= truncated
                    coverage["access_bytes_read"] += min(limit, stat.st_size)
                coverage["matched"] += 1
                spent += limit if path.endswith(".gz") else min(limit, stat.st_size)  # budget conservativo gzip
                key = "nginx_error" if group == "nginx_error" else Path(path).name.split(".log")[0].split(".1")[0]
                if group != "access":
                    section = logs.setdefault(key, {"total": 0, "suppressed": 0, "ungrouped_occurrences": 0, "_group_map": {}})
                for line in stream:
                    if group == "access":
                        m = NGINX.search(line)
                        if not m:
                            access_unparsed += 1
                            continue
                        forwarded = m.group("client")
                        ip = forwarded.split(",", 1)[0].strip() or "-"
                        date = m.group("date")
                        status = m.group("status")
                        ua = m.group("ua")
                        request_parts = m.group("request").split(None, 2)
                        uri = request_parts[1] if len(request_parts) >= 2 else "/[request-unavailable]"
                        try:
                            stamp = dt.datetime.strptime(date, NGINX_DATE).astimezone(dt.timezone.utc)
                        except ValueError:
                            continue
                        if stamp < since:
                            continue
                        if traffic is not None:
                            traffic.add(stamp, ip, normalize_uri(uri), status,
                                        bool(BOT.search(ua)), bool(FILTER.search(uri)))
                        total += 1
                        counts[status] += 1
                        paths[normalize_uri(uri)] += 1
                        ips[ip] += 1
                        agents[redact(ua[:100])] += 1
                        per_minute[stamp.strftime("%Y-%m-%d %H:%M")] += 1
                        if BOT.search(ua):
                            bot_hits += 1
                        if FILTER.search(uri):
                            filtered += 1
                    else:
                        stamp = log_time(line, zone)
                        if stamp is None or stamp < since:
                            continue
                        if group == "nginx_error" and NGINX_EXPECTED_BLOCK.search(line):
                            section["suppressed"] += 1
                            continue
                        if ERROR.search(line):
                            add_group(section, line, stamp, group_state, reference)
            except (OSError, EOFError, UnicodeError) as exc:
                coverage["errors"].append(f"{Path(path).name}: {type(exc).__name__}")
                coverage["truncated"] = True
    for section in logs.values():
        groups = list(section.pop('_group_map').values())
        for group in groups:
            group.pop('_minute_counts', None)
        section['groups'] = sorted(groups, key=lambda g: (-g['count'], g['signature']))
    coverage["no_access_log"] = not access_found
    coverage["access_unparsed_lines"] = access_unparsed
    if access_unparsed and (total == 0 or access_unparsed > total):
        coverage["errors"].append("Formato access.log non riconosciuto su molte righe: adattare il parser.")
    processes = []
    try:
        result = subprocess.run(["ps", "-eo", "pid,comm,pcpu,pmem", "--sort=-pcpu"], capture_output=True, text=True, timeout=4, check=True)
        for line in result.stdout.splitlines()[1:11]:
            cells = line.split()
            if len(cells) == 4:
                processes.append({"pid": int(cells[0]), "command": cells[1][:50], "cpu_percent": cells[2], "mem_percent": cells[3]})
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    system = {}
    try:
        system["loadavg"] = [round(x, 2) for x in os.getloadavg()]
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith(("MemTotal:", "MemAvailable:", "SwapFree:")):
                    k, v = line.split(":", 1)
                    system[k] = v.strip()
    except OSError:
        pass
    return {
        "window_minutes": minutes,
        "timestamp_utc": reference.isoformat(),
        "access": {"total": total, "statuses": dict(counts), "filtered_requests": filtered,
                   "known_bot_user_agent_hits": bot_hits, "top_paths": paths.most_common(15),
                   "top_clients": ips.most_common(12), "top_user_agents": agents.most_common(10),
                   "per_minute": per_minute.most_common(15)},
        "traffic": traffic.snapshot(coverage["access_truncated"]) if traffic else None,
        "logs": logs, "processes": processes, "system": system, "coverage": coverage
    }


def api(config, path, method="GET", payload=None):
    url = config["console_url"].rstrip("/") + path
    if not url.startswith("https://") and not config.get("allow_insecure_http", False):
        raise ValueError("Usare HTTPS: allow_insecure_http solo per test locali")
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method,
        headers={"X-Agent-Token": config["agent_token"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=35) as response:
        return json.loads(response.read().decode("utf-8"))


def run(config):
    print("[agent] IOHO collector pronto; HTTPS in uscita, nessuna esecuzione remota", flush=True)
    while True:
        try:
            reply = api(config, "/api/agent/next")
            job = reply.get("job")
            if job:
                print(f"[agent] job {job['id']}: {job['kind']}", flush=True)
                snapshot = collect(config, int(job["minutes"]))
                api(config, "/api/agent/result", "POST", {"job_id": job["id"], "data": snapshot})
                print(f"[agent] job {job['id']} inviato, richieste={snapshot['access']['total']}", flush=True)
        except Exception as exc:
            print("[agent] errore:", repr(exc), flush=True)
        time.sleep(max(10, int(config.get("poll_seconds", 20))))


if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) >= 2 else "/etc/ioho-ai-agent.json"
    with open(filename) as f:
        conf = json.load(f)
    if "--once" in sys.argv:
        print(json.dumps(collect(conf, 20), indent=2, ensure_ascii=False))
    else:
        run(conf)
