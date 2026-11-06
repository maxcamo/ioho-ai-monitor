#!/usr/bin/env bash
# v0.11 — solo layout home + ordinamento per gravita', senza toccare Zabbix e worker.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "ERRORE: eseguire come root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ioho-ai-monitor
FILES=(app/main.py app/templates/index.html app/templates/base.html VERSION)
[[ -f "$DST/.env" && -f "$DST/compose.yaml" ]] || {
    echo "ERRORE: console IOHO non trovata"; exit 1;
}
[[ "$(cat "$SRC/VERSION")" == "0.11" ]] || {
    echo "ERRORE: repository non aggiornato alla v0.11"; exit 1;
}
for f in "${FILES[@]}"; do
    [[ -f "$SRC/$f" && -f "$DST/$f" ]] || {
        echo "ERRORE: file non trovato: $f"; exit 1;
    }
done

python3 -m py_compile "$SRC/app/main.py"
BACKUP="/root/ioho-ai-monitor-pre-v011-$(date +%Y%m%d_%H%M%S).tar.gz"
(cd "$DST" && tar -czf "$BACKUP" "${FILES[@]}")
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"

for f in "${FILES[@]}"; do
    install -o root -g root -m 644 "$SRC/$f" "$DST/$f"
done
cd "$DST"
echo "=== BUILD API ==="
COMPOSE_PARALLEL_LIMIT=1 docker compose build api

echo "=== RIAVVIO SOLO API ==="
docker compose up -d --no-deps --force-recreate api
docker compose exec -T api python -c 'from app.main import display_servers; print("Dashboard v0.11 caricata")' </dev/null

echo "=== HEALTH API ==="
for i in $(seq 1 20); do
    if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:8088/health; then
        echo
        docker compose ps
        echo "=== V0.11 ATTIVA (WORKER E DATABASE INVARIATI) ==="
        exit 0
    fi
    sleep 2
done
echo "ERRORE: API non disponibile" >&2
docker compose ps
docker compose logs --tail=60 api
exit 1
