#!/usr/bin/env bash
# Solo codice console. DB, .env, Nginx e configurazione collector invariati.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/analysis.py worker.py app/templates/index.html app/templates/server.html app/templates/incident.html app/templates/base.html VERSION)
[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || { echo "Console non trovata"; exit 1; }
for file in "${FILES[@]}"; do [[ -f "$SRC/$file" && -f "$DST/$file" ]] || { echo "File mancante: $file"; exit 1; }; done
python3 -m py_compile "$SRC/app/main.py" "$SRC/app/analysis.py" "$SRC/worker.py"
BACKUP=/root/ioho-ai-monitor-pre-v06-$(date +%Y%m%d_%H%M%S).tar.gz
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"
for file in "${FILES[@]}"; do install -o root -g root -m 644 "$SRC/$file" "$DST/$file"; done
cd "$DST"
COMPOSE_PARALLEL_LIMIT=1 docker compose build api worker
docker compose up -d --no-deps --force-recreate api worker
docker compose exec -T api python -c 'from app.main import app; print("API v0.6 OK")' </dev/null
curl -fsS --connect-timeout 5 --max-time 15 http://127.0.0.1:8088/health
echo
printf 'Dashboard v0.6: stati applicativi / traffico separati, controlli 24h e 10m.\n'
