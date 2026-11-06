#!/usr/bin/env bash
# v0.12: CPU Zabbix ultimo report HTTP nella lista. Nessuna modifica a Zabbix/DB/worker.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/templates/index.html app/templates/base.html VERSION)
[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || {
  echo "ERRORE: installazione centrale non trovata"; exit 1;
}
[[ "$(cat "$SRC/VERSION")" == "0.12" ]] || {
  echo "ERRORE: sorgenti non alla versione 0.12"; exit 1;
}
for file in "${FILES[@]}"; do
  [[ -f "$SRC/$file" && -f "$DST/$file" ]] || {
    echo "ERRORE: file mancante $file"; exit 1;
  }
done

python3 -m py_compile "$SRC/app/main.py"
BACKUP="/root/ioho-ai-monitor-pre-v012-$(date +%Y%m%d_%H%M%S).tar.gz"
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"

for file in "${FILES[@]}"; do
  install -o root -g root -m 644 "$SRC/$file" "$DST/$file"
done

cd "$DST"
echo "=== BUILD E RIAVVIO SOLO API ==="
COMPOSE_PARALLEL_LIMIT=1 docker compose build api
docker compose up -d --no-deps --force-recreate api

echo "=== VERIFICA IMPORT ==="
docker compose exec -T api python -c 'from app.main import display_servers, cpu_from_access_audit; print("v0.12 CPU Zabbix dashboard OK")' </dev/null

echo "=== HEALTH API ==="
for attempt in $(seq 1 20); do
  if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:8088/health; then
    echo
    docker compose ps
    echo "=== V0.12 INSTALLATA: WORKER, DATABASE E AGENTI INVARIATI ==="
    exit 0
  fi
  sleep 2
done
echo "ERRORE: API non disponibile" >&2
docker compose ps
docker compose logs --tail=60 api
exit 1
