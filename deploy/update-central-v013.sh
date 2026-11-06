#!/usr/bin/env bash
# v0.13 — Widget live CPU Zabbix, load averages, processi e auto-refresh 30s.
# Nessuna modifica a Zabbix, worker, database o agenti. Solo API.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/templates/index.html app/templates/base.html VERSION)

[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || {
    echo "ERRORE: installazione centrale non trovata"; exit 1;
}
[[ "$(cat "$SRC/VERSION")" == "0.13" ]] || {
    echo "ERRORE: repository non aggiornato alla v0.13"; exit 1;
}

for f in "${FILES[@]}" app/zabbix_live.py; do
    [[ -f "$SRC/$f" ]] || { echo "ERRORE: sorgente mancante: $f"; exit 1; }
done
for f in "${FILES[@]}"; do
    [[ -f "$DST/$f" ]] || { echo "ERRORE: destinazione mancante: $f"; exit 1; }
done

python3 -m py_compile "$SRC/app/main.py" "$SRC/app/zabbix_live.py"
BACKUP="/root/ioho-ai-monitor-pre-v013-$(date +%Y%m%d_%H%M%S).tar.gz"
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"

for f in "${FILES[@]}" app/zabbix_live.py; do
    install -o root -g root -m 644 "$SRC/$f" "$DST/$f"
done

cd "$DST"
echo "=== BUILD E RIAVVIO SOLO API ==="
COMPOSE_PARALLEL_LIMIT=1 docker compose build api
docker compose up -d --no-deps --force-recreate api

echo "=== VERIFICA IMPORT WIDGET ==="
docker compose exec -T api python -c 'from app.zabbix_live import get_live_metrics; from app.main import app; print("Widget Zabbix v0.13 disponibile")' </dev/null

echo "=== HEALTH API ==="
for attempt in $(seq 1 20); do
    if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:8088/health; then
        echo
        echo "=== TEST ZABBIX LIVE (NESSUN TOKEN STAMPATO) ==="
        docker compose exec -T api python - <<'PY'
from app.zabbix_live import get_live_metrics
hosts = ["eweki.it", "fluid-hub.net", "polti.com", "originalbrands.store", "prod-www.targetsas.it"]
data = get_live_metrics(hosts)
for name in hosts:
    row = data.get(name)
    if row and row.get("cpu_pct") is not None:
        print(f"{name}: CPU {row['cpu_pct']}% | 1m={row['load1']} 5m={row['load5']} 15m={row['load15']} | processi={row['processes']}")
    else:
        print(f"{name}: nessun campione CPU recente/host non trovato")
PY
        docker compose ps
        echo "=== DASHBOARD V0.13 INSTALLATA; WORKER E DB INVARIATI ==="
        exit 0
    fi
    sleep 2
done
echo "ERRORE: API non raggiungibile" >&2
docker compose ps
docker compose logs --tail=60 api
exit 1
