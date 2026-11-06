#!/usr/bin/env bash
# Aggiorna i soli sorgenti applicativi del monitor centrale; non modifica .env, DB, compose.yaml o Nginx.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="/opt/ioho-ai-monitor"
[[ -f "$SRC/app/main.py" && -f "$SRC/app/templates/incident.html" ]] || { echo "ERRORE: repository sorgente incompleto"; exit 1; }
[[ -f "$DST/compose.yaml" && -f "$DST/.env" ]] || { echo "ERRORE: console non trovata in $DST"; exit 1; }
command -v docker >/dev/null
docker compose version >/dev/null
for path in app/main.py app/analysis.py app/templates/incident.html app/templates/base.html manage.py; do
  [[ -f "$DST/$path" && -f "$SRC/$path" ]] || { echo "ERRORE: file mancante $path"; exit 1; }
done
python3 -m py_compile "$SRC/app/main.py" "$SRC/app/analysis.py" "$SRC/manage.py"

echo "=== BACKUP CONSOLE ==="
BACKUP="/root/ioho-ai-monitor-pre-v04-$(date +%Y%m%d_%H%M%S).tar.gz"
cd "$DST"
tar -czf "$BACKUP" app/main.py app/analysis.py app/templates/incident.html app/templates/base.html manage.py VERSION 2>/dev/null || {
  tar -czf "$BACKUP" app/main.py app/analysis.py app/templates/incident.html app/templates/base.html manage.py
}
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"

echo "=== INSTALLAZIONE SORGENTI ==="
install -o root -g root -m 644 "$SRC/app/main.py" "$DST/app/main.py"
install -o root -g root -m 644 "$SRC/app/analysis.py" "$DST/app/analysis.py"
install -o root -g root -m 644 "$SRC/app/templates/incident.html" "$DST/app/templates/incident.html"
install -o root -g root -m 644 "$SRC/app/templates/base.html" "$DST/app/templates/base.html"
install -o root -g root -m 644 "$SRC/manage.py" "$DST/manage.py"
install -o root -g root -m 644 "$SRC/VERSION" "$DST/VERSION"

echo "=== BUILD SOLO API E WORKER ==="
cd "$DST"
COMPOSE_PARALLEL_LIMIT=1 docker compose build api worker
echo "=== RESTART SOLO API E WORKER ==="
docker compose up -d --no-deps --force-recreate api worker
echo "=== CONTROLLO SERVIZI ==="
docker compose ps
docker compose exec -T api python -c 'from app.main import app; from app.analysis import safe_ai_payload; from pathlib import Path; assert Path("/opt/ioho/app/templates/incident.html").exists(); print("Import console OK")'
curl -fsS --connect-timeout 5 --max-time 15 http://127.0.0.1:8088/health
echo
echo "=== CONSOLE V0.4 AGGIORNATA; DB E SEGRETI INVARIATI ==="
