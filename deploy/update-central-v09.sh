#!/usr/bin/env bash
# v0.9: CPU Zabbix, analisi traffico oraria, UI con link sui badge.
# Non modifica database, token o configurazioni degli agenti.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/traffic_view.py app/templates/index.html app/templates/server.html app/templates/incident.html app/templates/base.html worker.py VERSION)
[[ -f "$DST/compose.yaml" && -f "$DST/.env" ]] || { echo "Console non trovata"; exit 1; }
for f in "${FILES[@]}" app/zabbix_cpu.py; do [[ -f "$SRC/$f" ]] || { echo "Sorgente mancante: $f"; exit 1; }; done
for f in "${FILES[@]}"; do [[ -f "$DST/$f" ]] || { echo "Destinazione mancante: $f"; exit 1; }; done
python3 -m py_compile "$SRC/app/main.py" "$SRC/app/traffic_view.py" "$SRC/app/zabbix_cpu.py" "$SRC/worker.py"
BACKUP="/root/ioho-ai-monitor-pre-v09-$(date +%Y%m%d_%H%M%S).tar.gz"
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"
for f in "${FILES[@]}" app/zabbix_cpu.py; do install -o root -g root -m 644 "$SRC/$f" "$DST/$f"; done
cd "$DST"
echo "=== BUILD API E WORKER (DB invariato) ==="
COMPOSE_PARALLEL_LIMIT=1 docker compose build api worker
docker compose up -d --no-deps --force-recreate api worker
echo "=== IMPORT CODICE ==="
docker compose exec -T api python -c 'from app.main import app; from app.zabbix_cpu import fetch_cpu_history; print("v0.9: import API e Zabbix OK")' </dev/null
echo "=== HEALTH API CON RITENTATIVI ==="
for attempt in $(seq 1 20); do
  if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:8088/health; then
    echo
    echo "=== STATO SERVIZI ==="
    docker compose ps
    echo "=== CONFIGURAZIONE ZABBIX ==="
    if grep -qE '^ZABBIX_API_URL=https://.+' .env && grep -qE '^ZABBIX_API_TOKEN=.+$' .env; then
      echo "API Zabbix configurata (token non mostrato)"
    else
      echo "API Zabbix non ancora configurata: audit log e scheduler funzionano comunque"
    fi
    echo "=== DASHBOARD V0.9 ATTIVA ==="
    exit 0
  fi
  sleep 2
done
echo "ERRORE: API non raggiungibile" >&2
docker compose ps
docker compose logs --tail=60 api
exit 1
