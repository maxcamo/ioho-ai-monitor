#!/usr/bin/env bash
# v0.10 - home compatta, controlli HTTP e applicativi ogni ora.
# Aggiorna solo console e worker, NON DB, agent, Nginx, token o Zabbix.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/templates/index.html app/templates/base.html worker.py VERSION)

[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || {
  echo "ERRORE: installazione centrale non trovata"; exit 1;
}
[[ "$(cat "$SRC/VERSION")" == "0.10" ]] || {
  echo "ERRORE: sorgenti non sono v0.10"; exit 1;
}
for file in "${FILES[@]}"; do
  [[ -f "$SRC/$file" && -f "$DST/$file" ]] || {
    echo "ERRORE: file mancante: $file"; exit 1;
  }
done

python3 -m py_compile "$SRC/app/main.py" "$SRC/worker.py"

BACKUP="/root/ioho-ai-monitor-pre-v010-$(date +%Y%m%d_%H%M%S).tar.gz"
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup configurazioni codice: $BACKUP"

for file in "${FILES[@]}"; do
  install -o root -g root -m 644 "$SRC/$file" "$DST/$file"
done

cd "$DST"
echo "=== BUILD API E WORKER ==="
COMPOSE_PARALLEL_LIMIT=1 docker compose build api worker

echo "=== RESTART API E WORKER (NESSUN INTERVENTO SUL DB) ==="
docker compose up -d --no-deps --force-recreate api worker

echo "=== VERIFICA CODICE E SCHEDULER ==="
docker compose exec -T worker python - <<'PY'
import os
from app.main import DOMAIN_FRESHNESS
from worker import enqueue_hourly_access, enqueue_hourly_app
print("Scheduler traffico attivo:", os.getenv("HOURLY_ACCESS_ENABLED", "true").lower() not in ("false", "0", "no"))
print("Scheduler applicativi attivo:", os.getenv("HOURLY_APP_ENABLED", "true").lower() not in ("false", "0", "no"))
print("Scadenza stato traffico (min):", round(DOMAIN_FRESHNESS["access"].total_seconds()/60))
print("Scadenza stato applicativi (min):", round(DOMAIN_FRESHNESS["app"].total_seconds()/60))
PY

echo "=== HEALTH API (FINO A 20 TENTATIVI) ==="
for attempt in $(seq 1 20); do
  if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:8088/health; then
    echo
    docker compose ps
    echo "=== DASHBOARD V0.10 PRONTA ==="
    exit 0
  fi
  sleep 2
done
echo "ERRORE: API non disponibile dopo il restart" >&2
docker compose ps
docker compose logs --tail=60 api
exit 1
