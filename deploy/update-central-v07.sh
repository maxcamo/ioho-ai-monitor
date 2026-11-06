#!/usr/bin/env bash
# Aggiorna solo la dashboard HTTP; non modifica DB, token, .env, collector o Nginx.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: usare root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/templates/incident.html app/templates/base.html VERSION)
[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || { echo "Console non trovata"; exit 1; }
for f in "${FILES[@]}" app/traffic_view.py; do [[ -f "$SRC/$f" ]] || { echo "Sorgente mancante: $f"; exit 1; }; done
for f in "${FILES[@]}"; do [[ -f "$DST/$f" ]] || { echo "Destinazione mancante: $f"; exit 1; }; done
python3 -m py_compile "$SRC/app/main.py" "$SRC/app/traffic_view.py"
BACKUP=/root/ioho-ai-monitor-pre-v07-$(date +%Y%m%d_%H%M%S).tar.gz
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"
for f in "${FILES[@]}" app/traffic_view.py; do install -o root -g root -m 644 "$SRC/$f" "$DST/$f"; done
cd "$DST"
COMPOSE_PARALLEL_LIMIT=1 docker compose build api
docker compose up -d --no-deps --force-recreate api
docker compose exec -T api python -c 'from app.traffic_view import make_traffic_report; print("Report HTTP v0.7 pronto")' </dev/null
curl -fsS --connect-timeout 5 --max-time 15 http://127.0.0.1:8088/health
echo
printf 'Dashboard HTTP v0.7 attiva: nessuna modifica agli agenti.
'
