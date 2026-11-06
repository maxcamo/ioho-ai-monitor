#!/usr/bin/env bash
# Dashboard IP /24 IPv4 e /64 IPv6; non modifica DB, .env, Nginx o collector.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/traffic_view.py app/templates/incident.html app/templates/base.html VERSION)
[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || { echo "Console non trovata"; exit 1; }
for file in "${FILES[@]}"; do
  [[ -f "$SRC/$file" && -f "$DST/$file" ]] || { echo "File mancante: $file"; exit 1; }
done
python3 -m py_compile "$SRC/app/traffic_view.py"
BACKUP=/root/ioho-ai-monitor-pre-v08-$(date +%Y%m%d_%H%M%S).tar.gz
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"
for file in "${FILES[@]}"; do
  install -o root -g root -m 644 "$SRC/$file" "$DST/$file"
done
cd "$DST"
COMPOSE_PARALLEL_LIMIT=1 docker compose build api
docker compose up -d --no-deps --force-recreate api
docker compose exec -T api python -c 'from app.traffic_view import make_traffic_report; print("Raggruppamento IP v0.8 caricato")' </dev/null
echo "=== HEALTH API (con attesa avvio) ==="
for i in $(seq 1 15); do
  if curl -fsS --connect-timeout 3 --max-time 6 http://127.0.0.1:8088/health; then
    echo
    docker compose ps
    echo "Dashboard v0.8 attiva; DB e segreti invariati"
    exit 0
  fi
  sleep 2
done
echo "ERRORE: API non pronta dopo riavvio" >&2
docker compose ps
docker compose logs --tail=50 api
exit 1
